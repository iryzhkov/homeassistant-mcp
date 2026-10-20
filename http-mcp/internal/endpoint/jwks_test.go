package endpoint

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type observeRoundTrip func(*http.Request) (*http.Response, error)

func (f observeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCanceledHTTPCallerCannotPoisonSharedJWKSRefresh(t *testing.T) {
	f := newFixture(t)
	v := f.srv.verifier
	now := time.Now()
	v.now = func() time.Time { return now }
	valid := f.sign(f.baseClaims())
	if _, err := v.verify(context.Background(), valid); err != nil {
		t.Fatal("cache warmup failed")
	}

	started, release := make(chan struct{}), make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	var fail atomic.Bool
	var fetches atomic.Int32
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if fail.Load() {
			http.Error(w, "synthetic issuer failure", http.StatusInternalServerError)
			return
		}
		close(started)
		select {
		case <-release:
			_, _ = w.Write(f.keyDoc)
		case <-r.Context().Done():
		}
	}))
	defer jwks.Close()
	defer resume()
	seen := make(chan context.Context, 1)
	transport := jwks.Client().Transport
	v.cfg.JWKSURL = jwks.URL
	v.client.Transport = observeRoundTrip(func(r *http.Request) (*http.Response, error) {
		select {
		case seen <- r.Context():
		default:
		}
		return transport.RoundTrip(r)
	})
	// Expire the populated cache without sleeping. The clock then stays fixed
	// through both caller cancellation and the subsequent valid HTTP request.
	now = now.Add(61 * time.Second)
	wrong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	forged := jwt.NewWithClaims(jwt.SigningMethodRS256, f.baseClaims())
	forged.Header["kid"] = "first"
	raw, err := forged.SignedString(wrong)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "http://internal/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)).WithContext(ctx)
	req.Host = "ha.mcp.example"
	req.Header.Set("Authorization", "Bearer "+raw)
	reply := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { defer close(done); f.srv.ServeHTTP(reply, req) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("required JWKS refresh did not start")
	}
	var refreshCtx context.Context
	select {
	case refreshCtx = <-seen:
	case <-time.After(time.Second):
		t.Fatal("missing outbound JWKS request")
	}
	cancel()
	if refreshCtx.Err() != nil {
		t.Fatal("caller cancellation canceled the shared JWKS refresh")
	}
	if _, ok := refreshCtx.Deadline(); !ok {
		t.Fatal("shared JWKS refresh lacks its own deadline")
	}
	resume()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shared JWKS refresh did not complete")
	}
	if reply.Code != http.StatusUnauthorized {
		t.Fatal("forged signature accepted")
	}

	headers := map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-11-25"}
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	if w := f.rawRequest(valid, http.MethodPost, "/mcp", ping, headers); w.Code != http.StatusOK {
		t.Fatalf("valid token denied after canceled caller: status %d", w.Code)
	}
	if fetches.Load() != 1 {
		t.Fatal("valid token did not reuse the successful shared refresh")
	}

	// A real issuer failure after the next expiry must still fail closed and
	// retain the retry floor. Detachment is not permission to use expired keys.
	now = now.Add(61 * time.Second)
	fail.Store(true)
	for i := 0; i < 2; i++ {
		if w := f.rawRequest(valid, http.MethodPost, "/mcp", ping, headers); w.Code != http.StatusUnauthorized {
			t.Fatal("expired cached key accepted after issuer failure")
		}
	}
	if fetches.Load() != 2 {
		t.Fatal("failed refresh retry floor was not retained")
	}
	if len(f.snapshot()) != 0 {
		t.Fatal("authentication-only requests reached HA")
	}
}
