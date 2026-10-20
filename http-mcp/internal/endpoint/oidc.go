package endpoint

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tokenSkew = 10 * time.Second

var errToken = errors.New("invalid token")

type claims struct {
	jwt.RegisteredClaims
	// This resource requires scalar JSON aud, overriding RegisteredClaims' array union.
	Audience string   `json:"aud"`
	Scope    string   `json:"scope"`
	Entities []string `json:"ha_entities"`
	Actions  []string `json:"ha_actions"`
}

func (c *claims) GetAudience() (jwt.ClaimStrings, error) { return jwt.ClaimStrings{c.Audience}, nil }

func (c *claims) Validate() error {
	if !safeText(c.Subject, 256) || c.IssuedAt == nil || c.ExpiresAt == nil ||
		!c.ExpiresAt.After(c.IssuedAt.Time) || c.ExpiresAt.Sub(c.IssuedAt.Time) > 300*time.Second ||
		(c.NotBefore != nil && !c.NotBefore.Before(c.ExpiresAt.Time)) || (c.Audience == "" || len(c.Audience) > 2048) || len(c.Scope) > 256 ||
		len(c.Entities) < 1 || len(c.Entities) > MaxEntities || len(c.Actions) < 1 || len(c.Actions) > 3 {
		return errToken
	}
	scopes := strings.Split(c.Scope, " ")
	if len(scopes) < 1 || len(scopes) > 2 {
		return errToken
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		if (s != "ha.read" && s != "ha.control") || seen[s] {
			return errToken
		}
		seen[s] = true
	}
	seen = map[string]bool{}
	for _, id := range c.Entities {
		if !validID(id) || seen[id] {
			return errToken
		}
		seen[id] = true
	}
	seen = map[string]bool{}
	for _, a := range c.Actions {
		if (a != "state.read" && a != "light.control" && a != "switch.control") || seen[a] {
			return errToken
		}
		seen[a] = true
	}
	return nil
}

type verifier struct {
	cfg                Config
	client             *http.Client
	now                func() time.Time
	mu                 sync.Mutex
	keys               map[string]*rsa.PublicKey
	expires, attempted time.Time
}

func fixedClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") },
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10,
			MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 16, IdleConnTimeout: 30 * time.Second, DisableCompression: true},
	}
}
func newVerifier(cfg Config) *verifier {
	return &verifier{cfg: cfg, client: fixedClient(3 * time.Second), now: time.Now}
}
func (v *verifier) verify(ctx context.Context, raw string) (*claims, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, errToken
	}
	c := new(claims)
	t, e := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if c.Issuer != v.cfg.IssuerURL || c.Validate() != nil || c.Audience != v.cfg.ResourceURL {
			return nil, errToken
		}
		// Token headers never define trust, network locations or algorithms.
		for _, h := range []string{"jku", "jwk", "x5u", "x5c", "crit", "b64"} {
			if _, ok := t.Header[h]; ok {
				return nil, errToken
			}
		}
		kid, ok := t.Header["kid"].(string)
		if !ok || !safeText(kid, 128) {
			return nil, errToken
		}
		return v.key(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(v.cfg.IssuerURL), jwt.WithAudience(v.cfg.ResourceURL),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(tokenSkew), jwt.WithTimeFunc(v.now), jwt.WithStrictDecoding())
	if e != nil || t == nil || !t.Valid {
		return nil, errToken
	}
	return c, nil
}

// At most one fetch, 16 keys, one-minute validity, and a five-second refresh
// floor. Expired keys fail closed on a failed refresh.
func (v *verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if k := v.keys[kid]; k != nil && now.Before(v.expires) {
		return k, nil
	}
	if !v.attempted.IsZero() && now.Sub(v.attempted) < 5*time.Second {
		return nil, errToken
	}
	v.attempted = now
	// The refresh populates a shared public-key cache. One caller disconnecting
	// must not turn it into a failed refresh for every other caller.
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(refreshCtx, http.MethodGet, v.cfg.JWKSURL, nil)
	if e != nil {
		return nil, errToken
	}
	res, e := v.client.Do(req)
	if e != nil {
		return nil, errToken
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, errToken
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, (64<<10)+1))
	if e != nil || len(raw) > 64<<10 {
		return nil, errToken
	}
	keys, e := parseJWKS(raw)
	if e != nil {
		return nil, errToken
	}
	v.keys = keys
	v.expires = v.now().Add(time.Minute)
	if keys[kid] == nil {
		return nil, errToken
	}
	return keys[kid], nil
}

// Decode public RSA JWK integers only. golang-jwt performs all signature work.
func parseJWKS(raw []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string   `json:"kty"`
			Kid string   `json:"kid"`
			Alg string   `json:"alg"`
			Use string   `json:"use"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			D   string   `json:"d"`
			Ops []string `json:"key_ops"`
		} `json:"keys"`
	}
	if json.Unmarshal(raw, &set) != nil || len(set.Keys) < 1 || len(set.Keys) > 16 {
		return nil, errToken
	}
	keys := map[string]*rsa.PublicKey{}
	seen := map[string]bool{}
	for _, j := range set.Keys {
		if !safeText(j.Kid, 128) || seen[j.Kid] || j.D != "" {
			return nil, errToken
		}
		seen[j.Kid] = true
		if j.Kty != "RSA" || (j.Alg != "" && j.Alg != "RS256") || (j.Use != "" && j.Use != "sig") || (len(j.Ops) > 0 && (len(j.Ops) != 1 || j.Ops[0] != "verify")) {
			continue
		}
		n, en := base64.RawURLEncoding.Strict().DecodeString(j.N)
		e, ee := base64.RawURLEncoding.Strict().DecodeString(j.E)
		modulus := new(big.Int).SetBytes(n)
		exponent := new(big.Int).SetBytes(e)
		if en != nil || ee != nil || modulus.BitLen() < 2048 || modulus.BitLen() > 4096 || !exponent.IsInt64() ||
			exponent.Int64() < 3 || exponent.Int64() > 2147483647 || exponent.Int64()%2 == 0 {
			return nil, errToken
		}
		keys[j.Kid] = &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
	}
	if len(keys) == 0 {
		return nil, errToken
	}
	return keys, nil
}
