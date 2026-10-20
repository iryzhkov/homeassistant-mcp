package endpoint

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMain(m *testing.M) {
	home, tmp := os.Getenv("HOME"), os.Getenv("TMPDIR")
	if home == "" || tmp == "" || !strings.Contains(home, "/.cache/ha-impl/") || !strings.Contains(tmp, "/.cache/ha-impl/") ||
		!filepath.IsAbs(home) || !filepath.IsAbs(tmp) || !strings.HasPrefix(tmp, filepath.Dir(home)+"/") {
		fmt.Fprintf(os.Stderr, "tests require an asserted scratch HOME and TMPDIR under .cache/ha-impl; HOME=%q TMPDIR=%q\\n", home, tmp)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

type captured struct {
	Method, Path string
	Body         map[string]any
}
type fixture struct {
	t           *testing.T
	cfg         Config
	srv         *Server
	http        *httptest.Server
	ha, jwks    *httptest.Server
	key         *rsa.PrivateKey
	mu          sync.Mutex
	calls       []captured
	changed     map[string]string
	mode        string
	jwksMode    string
	kid         string
	keyDoc      []byte
	jwksFetches int
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, changed: map[string]string{}, kid: "first"}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	f.key = key
	f.keyDoc = jwkDoc(key, "first")
	f.ha = httptest.NewServer(http.HandlerFunc(f.backendHTTP))
	t.Cleanup(f.ha.Close)
	f.jwks = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.jwksFetches++
		mode, doc := f.jwksMode, append([]byte(nil), f.keyDoc...)
		f.mu.Unlock()
		if mode == "error" {
			http.Error(w, "PRIVATE-JWKS-ERROR", 500)
			return
		}
		if mode == "redirect" {
			http.Redirect(w, r, f.ha.URL, 302)
			return
		}
		if mode == "large" {
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxBody+1))
			return
		}
		_, _ = w.Write(doc)
	}))
	t.Cleanup(f.jwks.Close)
	tokenFile := filepath.Join(t.TempDir(), "backend-token")
	if e := os.WriteFile(tokenFile, []byte("synthetic-backend-secret\n"), 0600); e != nil {
		t.Fatal(e)
	}
	f.cfg = Config{Listen: ":8080", ResourceURL: "https://ha.mcp.example/mcp", IssuerURL: "https://issuer.example/application/o/ha/", JWKSURL: f.jwks.URL,
		HAURL: f.ha.URL, BackendTokenFile: tokenFile, Entities: []Entity{
			{ID: "light.a", Name: "Approved lamp", Actions: []string{"state.read", "light.control"}, ControlQualified: true, Brightness: &Brightness{MinPercent: 10, MaxPercent: 90}},
			{ID: "light.b", Name: "Denied sibling", Actions: []string{"state.read", "light.control"}, ControlQualified: true},
			{ID: "switch.a", Name: "Approved switch", Actions: []string{"state.read", "switch.control"}, ControlQualified: true},
			{ID: "sensor.a", Name: "Approved sensor", Actions: []string{"state.read"}},
			{ID: "light.missing", Name: "Missing fixture", Actions: []string{"state.read"}},
		}}
	f.srv, e = New(f.cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.srv.verifier.client.Transport = f.jwks.Client().Transport
	f.http = httptest.NewServer(f.srv)
	t.Cleanup(f.http.Close)
	return f
}
func jwkDoc(key *rsa.PrivateKey, kid string) []byte {
	raw, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	return raw
}
func (f *fixture) backendHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.calls = append(f.calls, captured{r.Method, r.URL.Path, body})
	mode := f.mode
	if r.Method == http.MethodPost {
		if id, ok := body["entity_id"].(string); ok {
			f.changed[id] = r.URL.Path
		}
	}
	f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer synthetic-backend-secret" {
		http.Error(w, "PRIVATE-AUTH-ERROR", 401)
		return
	}
	switch mode {
	case "error":
		http.Error(w, "PRIVATE-ERROR user_id=secret", 500)
		return
	case "missing":
		http.Error(w, "PRIVATE-NOT-FOUND", 404)
		return
	case "redirect":
		http.Redirect(w, r, f.jwks.URL, 302)
		return
	case "large":
		_, _ = w.Write(bytes.Repeat([]byte("PRIVATE-LARGE"), maxBody))
		return
	case "timeout":
		<-r.Context().Done()
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		id := strings.TrimPrefix(r.URL.Path, "/api/states/")
		if id == "light.missing" {
			http.Error(w, "PRIVATE-MISSING", 404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entity_id": id, "state": "on", "attributes": map[string]any{"friendly_name": "PRIVATE-NAME",
			"brightness": 128, "unit_of_measurement": "W", "url": "PRIVATE-URL", "entity_id": []string{"light.b"}, "device_id": "PRIVATE-DEVICE"},
			"context": map[string]any{"user_id": "PRIVATE-USER"}, "last_changed": "2026-10-19T12:00:00Z", "last_updated": "2026-10-19T12:00:01Z"})
	} else {
		_, _ = w.Write([]byte(`[{"entity_id":"light.b","context":{"user_id":"PRIVATE-USER"},"attributes":{"url":"PRIVATE-URL"}}]`))
	}
}
func (f *fixture) baseClaims() jwt.MapClaims {
	now := time.Now().Unix()
	return jwt.MapClaims{"iss": f.cfg.IssuerURL, "aud": f.cfg.ResourceURL, "sub": "same-subject", "iat": now, "exp": now + 300,
		"scope": "ha.read ha.control", "ha_entities": []string{"light.a", "switch.a", "sensor.a", "light.missing"}, "ha_actions": []string{"state.read", "light.control", "switch.control"}}
}
func (f *fixture) sign(c jwt.MapClaims) string {
	f.t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	token.Header["kid"] = f.kid
	raw, e := token.SignedString(f.key)
	if e != nil {
		f.t.Fatal(e)
	}
	return raw
}

type tokenTransport struct {
	base  http.RoundTripper
	token atomic.Value
	host  string
}

func (r *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Host = r.host
	if tok, _ := r.token.Load().(string); tok != "" {
		clone.Header.Set("Authorization", "Bearer "+tok)
	}
	return r.base.RoundTrip(clone)
}
func (f *fixture) session(token string) (*mcp.ClientSession, *tokenTransport) {
	f.t.Helper()
	rt := &tokenTransport{base: http.DefaultTransport, host: "ha.mcp.example"}
	rt.token.Store(token)
	client := mcp.NewClient(&mcp.Implementation{Name: "acceptance", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, e := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: f.http.URL + "/mcp", HTTPClient: &http.Client{Transport: rt}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		f.t.Fatalf("SDK initialize failed: %v", e)
	}
	f.t.Cleanup(func() { _ = session.Close() })
	return session, rt
}
func call(t *testing.T, s *mcp.ClientSession, name string, args any) (*mcp.CallToolResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}
func resultJSON(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	return string(raw)
}
func assertSafe(t *testing.T, raw string) {
	t.Helper()
	for _, secret := range []string{"PRIVATE", "synthetic-backend-secret", "user_id", `"context":`, "device_id", "friendly_name"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("sensitive result marker %q", secret)
		}
	}
	if len(raw) > maxBody {
		t.Fatal("output exceeds bound")
	}
}
func (f *fixture) snapshot() []captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]captured(nil), f.calls...)
}
func toolNames(t *testing.T, s *mcp.ClientSession) []string {
	t.Helper()
	r, e := s.ListTools(context.Background(), nil)
	if e != nil {
		t.Fatal(e)
	}
	names := []string{}
	for _, tool := range r.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}
func TestSDKAllowedReadAndDesiredStateControl(t *testing.T) {
	f := newFixture(t)
	s, _ := f.session(f.sign(f.baseClaims()))
	if got := toolNames(t, s); !reflect.DeepEqual(got, []string{"get_entity", "list_entities", "set_light", "set_switch"}) {
		t.Fatalf("unexpected tools %v", got)
	}
	r, e := call(t, s, "get_entity", map[string]any{"id": "light.a"})
	if e != nil || r.IsError {
		t.Fatalf("read failed: %v", e)
	}
	raw := resultJSON(t, r)
	assertSafe(t, raw)
	if !strings.Contains(raw, "Approved lamp") || !strings.Contains(raw, "brightness_percent") {
		t.Fatal("approved projection missing")
	}
	tests := []struct {
		name, id, power string
		brightness      *int
		path            string
		value           int
	}{
		{"set_light", "light.a", "on", intPtr(50), "/api/services/light/turn_on", 128},
		{"set_light", "light.a", "off", nil, "/api/services/light/turn_off", 0},
		{"set_switch", "switch.a", "on", nil, "/api/services/switch/turn_on", 0},
		{"set_switch", "switch.a", "off", nil, "/api/services/switch/turn_off", 0},
	}
	for _, tc := range tests {
		args := map[string]any{"id": tc.id, "power": tc.power}
		if tc.brightness != nil {
			args["brightness_percent"] = *tc.brightness
		}
		r, e := call(t, s, tc.name, args)
		if e != nil || r.IsError {
			t.Fatalf("set failed: %v", e)
		}
		raw := resultJSON(t, r)
		assertSafe(t, raw)
		if !strings.Contains(raw, `"physical_state_confirmed":false`) || !strings.Contains(raw, "accepted") {
			t.Fatal("write receipt must distinguish acceptance")
		}
		calls := f.snapshot()
		last := calls[len(calls)-1]
		want := map[string]any{"entity_id": tc.id}
		if tc.brightness != nil {
			want["brightness"] = float64(tc.value)
		}
		if last.Method != "POST" || last.Path != tc.path || !reflect.DeepEqual(last.Body, want) {
			t.Fatalf("wrong fixed service request: %v", last)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.changed) != 2 || f.changed["light.a"] == "" || f.changed["switch.a"] == "" {
		t.Fatal("only approved synthetic targets may change")
	}
}
func intPtr(v int) *int { return &v }
func TestRefusalsBeforeBackendAndReadErrorEquivalence(t *testing.T) {
	f := newFixture(t)
	s, _ := f.session(f.sign(f.baseClaims()))
	cases := []struct {
		name string
		args map[string]any
	}{
		{"get_entity", map[string]any{"id": "light.b"}},
		{"get_entity", map[string]any{"id": "light.unknown"}},
		{"get_entity", map[string]any{"id": "../api/config"}},
		{"set_light", map[string]any{"id": "light.b", "power": "on"}},
		{"set_light", map[string]any{"id": "switch.a", "power": "on"}},
		{"set_light", map[string]any{"id": "light.a", "power": "toggle"}},
		{"set_light", map[string]any{"id": "light.a"}},
		{"set_light", map[string]any{"id": "light.a", "power": "off", "brightness_percent": 50}},
		{"set_light", map[string]any{"id": "light.a", "power": "on", "brightness_percent": 9}},
		{"set_light", map[string]any{"id": "light.a", "power": "on", "brightness_percent": 91}},
		{"set_light", map[string]any{"id": "light.a", "power": "on", "brightness_percent": 50.5}},
		{"set_light", map[string]any{"id": "light.a", "power": "on", "area_id": "all"}},
		{"set_light", map[string]any{"id": "light.a", "power": "on", "entity_id": []string{"light.b"}}},
		{"set_switch", map[string]any{"id": "switch.a", "power": "on", "brightness_percent": 30}},
		{"set_switch", map[string]any{"id": "all", "power": "on"}},
		{"set_switch", map[string]any{"id": "switch.a", "power": "on", "service": "toggle"}},
		{"list_entities", map[string]any{"limit": 21}},
		{"list_entities", map[string]any{"offset": -1}},
		{"call_service", map[string]any{"domain": "script", "service": "turn_on"}},
		{"assist", map[string]any{"text": "turn on all lights"}},
	}
	var denied string
	for i, tc := range cases {
		s, _ = f.session(f.sign(f.baseClaims()))
		r, e := call(t, s, tc.name, tc.args)
		if e == nil && !r.IsError {
			t.Fatalf("case %d accepted", i)
		}
		if len(f.snapshot()) != 0 {
			t.Fatalf("case %d reached backend", i)
		}
		if r != nil {
			raw := resultJSON(t, r)
			assertSafe(t, raw)
			if i == 0 {
				denied = raw
			}
			if i == 1 && raw != denied {
				t.Fatal("denied and unknown differ")
			}
		}
	}
	s, _ = f.session(f.sign(f.baseClaims()))
	r, e := call(t, s, "get_entity", map[string]any{"id": "light.missing"})
	if e != nil || !r.IsError || resultJSON(t, r) != denied {
		t.Fatal("missing and denied differ")
	}
	for _, mode := range []string{"error", "missing", "large", "redirect"} {
		f.mu.Lock()
		f.mode = mode
		f.mu.Unlock()
		r, e := call(t, s, "get_entity", map[string]any{"id": "light.a"})
		if e != nil || !r.IsError || resultJSON(t, r) != denied {
			t.Fatalf("%s and denied differ", mode)
		}
	}
}
func TestSeparateScopesAndGrantFilteredPagination(t *testing.T) {
	f := newFixture(t)
	c := f.baseClaims()
	c["scope"] = "ha.read"
	c["ha_entities"] = []string{"light.a", "sensor.a"}
	s, _ := f.session(f.sign(c))
	if got := toolNames(t, s); !reflect.DeepEqual(got, []string{"get_entity", "list_entities"}) {
		t.Fatalf("readonly catalog %v", got)
	}
	r, e := call(t, s, "set_light", map[string]any{"id": "light.a", "power": "on"})
	if e == nil && !r.IsError {
		t.Fatal("readonly write accepted")
	}
	s, _ = f.session(f.sign(c)) // A protocol refusal can close an SDK transport.
	r, e = call(t, s, "list_entities", map[string]any{"limit": 1})
	if e != nil || r.IsError {
		t.Fatalf("page failed: err=%v result=%s", e, resultJSON(t, r))
	}
	raw := resultJSON(t, r)
	assertSafe(t, raw)
	var page pageResult
	b, _ := json.Marshal(r.StructuredContent)
	if json.Unmarshal(b, &page) != nil {
		t.Fatal("page decode")
	}
	if page.Total != 2 || len(page.Entities) != 1 || page.Entities[0].ID != "light.a" || page.NextOffset == nil || *page.NextOffset != 1 {
		t.Fatal("pagination must use permitted IDs first")
	}
	r, e = call(t, s, "list_entities", map[string]any{"offset": 1, "limit": 1})
	if e != nil || r.IsError {
		t.Fatal("second page failed")
	}
	b, _ = json.Marshal(r.StructuredContent)
	_ = json.Unmarshal(b, &page)
	calls := f.snapshot()
	if len(calls) != 2 || calls[0].Path != "/api/states/light.a" || calls[1].Path != "/api/states/sensor.a" {
		t.Fatalf("list used broader backend requests: %v", calls)
	}
	c = f.baseClaims()
	c["scope"] = "ha.control"
	control, _ := f.session(f.sign(c))
	if got := toolNames(t, control); !reflect.DeepEqual(got, []string{"set_light", "set_switch"}) {
		t.Fatalf("control-only catalog %v", got)
	}
	r, e = call(t, control, "get_entity", map[string]any{"id": "light.a"})
	if e == nil && !r.IsError {
		t.Fatal("control-only read accepted")
	}
	control, _ = f.session(f.sign(c))
	r, e = call(t, control, "set_light", map[string]any{"id": "light.a", "power": "on"})
	if e != nil || r.IsError {
		t.Fatal("control-only write refused")
	}
	raw = resultJSON(t, r)
	assertSafe(t, raw)
	if strings.Contains(raw, "Approved") || strings.Contains(raw, "brightness") || strings.Contains(raw, "state\":\"on") {
		t.Fatal("write revealed read projection")
	}
}
func TestSameSubjectGrantChangesAndConcurrency(t *testing.T) {
	f := newFixture(t)
	wide := f.baseClaims()
	narrow := f.baseClaims()
	narrow["scope"] = "ha.read"
	narrow["ha_entities"] = []string{"sensor.a"}
	narrow["ha_actions"] = []string{"state.read"}
	s, rt := f.session(f.sign(wide))
	rt.token.Store(f.sign(narrow))
	r, e := call(t, s, "get_entity", map[string]any{"id": "light.a"})
	if e != nil || !r.IsError {
		t.Fatal("previous same-subject grant retained")
	}
	r, e = call(t, s, "set_light", map[string]any{"id": "light.a", "power": "on"})
	if e == nil && !r.IsError {
		t.Fatal("previous same-subject control retained")
	}
	expired := f.baseClaims()
	expired["iat"] = time.Now().Unix() - 400
	expired["exp"] = time.Now().Unix() - 100
	s, rt = f.session(f.sign(wide))
	rt.token.Store(f.sign(expired))
	before := len(f.snapshot())
	_, expiryErr := call(t, s, "get_entity", map[string]any{"id": "sensor.a"})
	if expiryErr == nil || len(f.snapshot()) != before {
		t.Fatal("retained client bypassed expiry")
	}
	a, _ := f.session(f.sign(wide))
	b, _ := f.session(f.sign(narrow))
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r, e := call(t, a, "get_entity", map[string]any{"id": "light.a"})
			if e != nil || r.IsError {
				t.Error("wide request failed")
			}
		}()
		go func() {
			defer wg.Done()
			r, e := call(t, b, "get_entity", map[string]any{"id": "light.a"})
			if e != nil || !r.IsError {
				t.Error("narrow request escaped grants")
			}
		}()
	}
	wg.Wait()
	for _, c := range f.snapshot() {
		if c.Path != "/api/states/light.a" {
			t.Fatal("unexpected backend target")
		}
	}
}
func (f *fixture) rawRequest(token, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://internal"+path, strings.NewReader(body))
	req.Host = "ha.mcp.example"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)
	return w
}
func TestJWTFailureContract(t *testing.T) {
	f := newFixture(t)
	if _, err := f.srv.verifier.verify(context.Background(), f.sign(f.baseClaims())); err != nil {
		t.Fatal("signed scalar audience refused")
	}
	cases := map[string]func(jwt.MapClaims){
		"issuer":             func(c jwt.MapClaims) { c["iss"] = "https://issuer.example/application/o/ha" },
		"audience":           func(c jwt.MapClaims) { c["aud"] = "https://other.example/mcp" },
		"aud array":          func(c jwt.MapClaims) { c["aud"] = []string{f.cfg.ResourceURL} },
		"multiple audiences": func(c jwt.MapClaims) { c["aud"] = []string{f.cfg.ResourceURL, "https://other.example/mcp"} },
		"scope":              func(c jwt.MapClaims) { c["scope"] = "ha.admin" },
		"empty scope":        func(c jwt.MapClaims) { c["scope"] = "" },
		"missing sub":        func(c jwt.MapClaims) { delete(c, "sub") },
		"missing iat":        func(c jwt.MapClaims) { delete(c, "iat") },
		"missing exp":        func(c jwt.MapClaims) { delete(c, "exp") },
		"expired":            func(c jwt.MapClaims) { c["iat"] = time.Now().Unix() - 400; c["exp"] = time.Now().Unix() - 100 },
		"future iat":         func(c jwt.MapClaims) { c["iat"] = time.Now().Unix() + 30; c["exp"] = time.Now().Unix() + 300 },
		"long lifetime":      func(c jwt.MapClaims) { c["exp"] = time.Now().Unix() + 301 },
		"missing entities":   func(c jwt.MapClaims) { delete(c, "ha_entities") },
		"empty entities":     func(c jwt.MapClaims) { c["ha_entities"] = []string{} },
		"scalar entities":    func(c jwt.MapClaims) { c["ha_entities"] = "light.a" },
		"wildcard":           func(c jwt.MapClaims) { c["ha_entities"] = []string{"light.*"} },
		"selector":           func(c jwt.MapClaims) { c["ha_entities"] = []string{"area.living_room"} },
		"duplicate entity":   func(c jwt.MapClaims) { c["ha_entities"] = []string{"light.a", "light.a"} },
		"missing actions":    func(c jwt.MapClaims) { delete(c, "ha_actions") },
		"empty actions":      func(c jwt.MapClaims) { c["ha_actions"] = []string{} },
		"unknown action":     func(c jwt.MapClaims) { c["ha_actions"] = []string{"script.execute"} },
		"large claims":       func(c jwt.MapClaims) { c["sub"] = strings.Repeat("x", 257) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := f.baseClaims()
			mutate(c)
			w := f.rawRequest(f.sign(c), "POST", "/mcp", "", nil)
			if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata") {
				t.Fatalf("invalid JWT status %d", w.Code)
			}
			assertSafe(t, w.Body.String())
		})
	}
	for name, raw := range map[string]string{"malformed": "abc.def.ghi", "oversize": strings.Repeat("x", 8193)} {
		t.Run(name, func(t *testing.T) {
			if w := f.rawRequest(raw, "POST", "/mcp", "", nil); w.Code != 401 {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
	wrong, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, f.baseClaims())
	tok.Header["kid"] = "first"
	raw, _ := tok.SignedString(wrong)
	if w := f.rawRequest(raw, "POST", "/mcp", "", nil); w.Code != 401 {
		t.Fatal("bad signature accepted")
	}
	tok = jwt.NewWithClaims(jwt.SigningMethodHS256, f.baseClaims())
	tok.Header["kid"] = "first"
	raw, _ = tok.SignedString([]byte("synthetic"))
	if w := f.rawRequest(raw, "POST", "/mcp", "", nil); w.Code != 401 {
		t.Fatal("algorithm confusion accepted")
	}
	tok = jwt.NewWithClaims(jwt.SigningMethodRS256, f.baseClaims())
	tok.Header["kid"] = "first"
	tok.Header["jku"] = f.ha.URL
	raw, _ = tok.SignedString(f.key)
	if w := f.rawRequest(raw, "POST", "/mcp", "", nil); w.Code != 401 {
		t.Fatal("token key URL accepted")
	}
	if len(f.snapshot()) != 0 {
		t.Fatal("JWT refusal reached HA")
	}
}
func TestHTTPBoundaryMetadataLivenessAndBody(t *testing.T) {
	f := newFixture(t)
	token := f.sign(f.baseClaims())
	w := f.rawRequest("", "POST", "/mcp", "", nil)
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "https://ha.mcp.example/.well-known/oauth-protected-resource/mcp") {
		t.Fatal("missing bearer challenge")
	}
	w = f.rawRequest("", "GET", "/.well-known/oauth-protected-resource/mcp", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), f.cfg.ResourceURL) || !strings.Contains(w.Body.String(), "ha.control") {
		t.Fatal("metadata contract")
	}
	for _, path := range []string{"/healthz", "/.well-known/oauth-protected-resource/mcp", "/mcp"} {
		for _, headers := range []map[string]string{{"Origin": "https://evil.example"}, {"Host": "evil.example"}, {"Origin": "null"}, {"Origin": ""}} {
			if headers["Host"] != "" {
				req := httptest.NewRequest("POST", "http://evil.example"+path, nil)
				req.Host = "evil.example"
				w = httptest.NewRecorder()
				f.srv.ServeHTTP(w, req)
			} else {
				w = f.rawRequest(token, "POST", path, "", headers)
			}
			if w.Code != 403 {
				t.Fatal("host/origin check missing")
			}
		}
	}
	w = f.rawRequest("", "GET", "/healthz", "", nil)
	if w.Code != 200 || w.Body.String() != "ok\n" {
		t.Fatal("liveness")
	}
	if len(f.snapshot()) != 0 {
		t.Fatal("liveness/discovery called backend")
	}
	w = f.rawRequest(token, "POST", "/mcp", strings.Repeat("x", maxBody+1), map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream"})
	if w.Code != 413 {
		t.Fatalf("body bound status %d", w.Code)
	}
	w = f.rawRequest(token, "POST", "/mcp", `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"set_light","arguments":{"id":"light.a","power":"on"}}}]`, map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Mcp-Protocol-Version": "2025-03-26"})
	if w.Code != 400 || len(f.snapshot()) != 0 {
		t.Fatal("legacy batch escaped request concurrency limit")
	}
	for _, method := range []string{"GET", "DELETE"} {
		if w = f.rawRequest(token, method, "/mcp", "", nil); w.Code != 405 {
			t.Fatal("stateless endpoint retained session transport")
		}
	}
	if w = f.rawRequest(token, "POST", "/api/services/light/turn_on", "{}", nil); w.Code != 404 {
		t.Fatal("unexpected relay path")
	}
	req := httptest.NewRequest("POST", "http://internal/mcp", nil)
	req.Host = "ha.mcp.example"
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("duplicate bearer accepted")
	}
}
func TestKeyRefreshCacheAndFailure(t *testing.T) {
	f := newFixture(t)
	v := f.srv.verifier
	now := time.Now()
	v.now = func() time.Time { return now }
	if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	fetches := f.jwksFetches
	f.mu.Unlock()
	if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	if f.jwksFetches != fetches {
		t.Error("cache missed")
	}
	f.mu.Unlock()
	f.kid = "rotated"
	f.mu.Lock()
	f.keyDoc = jwkDoc(f.key, f.kid)
	f.mu.Unlock()
	if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e == nil {
		t.Fatal("refresh floor bypass")
	}
	now = now.Add(6 * time.Second)
	if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e != nil {
		t.Fatal("rotation failed")
	}
	f.mu.Lock()
	f.jwksMode = "error"
	f.mu.Unlock()
	now = now.Add(61 * time.Second)
	if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e == nil {
		t.Fatal("expired key used after required refresh failure")
	}
	for _, mode := range []string{"redirect", "large"} {
		now = now.Add(6 * time.Second)
		f.mu.Lock()
		f.jwksMode = mode
		f.mu.Unlock()
		if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e == nil {
			t.Fatalf("JWKS %s accepted", mode)
		}
	}
	f.mu.Lock()
	f.jwksMode = ""
	f.keyDoc = []byte(`{"keys":[]}`)
	f.mu.Unlock()
	now = now.Add(6 * time.Second)
	if _, e := v.verify(context.Background(), f.sign(f.baseClaims())); e == nil {
		t.Fatal("empty key set accepted")
	}
	if len(f.snapshot()) != 0 {
		t.Fatal("JWKS redirect followed")
	}
}
func TestTimeoutUncertainWriteNoRetryAndReadBound(t *testing.T) {
	f := newFixture(t)
	s, _ := f.session(f.sign(f.baseClaims()))
	f.srv.backend.client.Timeout = 60 * time.Millisecond
	f.mu.Lock()
	f.mode = "timeout"
	f.mu.Unlock()
	started := time.Now()
	r, e := call(t, s, "set_light", map[string]any{"id": "light.a", "power": "on"})
	if e != nil || !r.IsError || !strings.Contains(resultJSON(t, r), "uncertain") {
		t.Fatal("timeout must report uncertain outcome")
	}
	if time.Since(started) > time.Second {
		t.Fatal("write timeout unbounded")
	}
	if calls := f.snapshot(); len(calls) != 1 || calls[0].Method != "POST" {
		t.Fatal("write retried or read automatically")
	}
	r, e = call(t, s, "get_entity", map[string]any{"id": "light.a"})
	if e != nil || !r.IsError || !strings.Contains(resultJSON(t, r), "entity unavailable") {
		t.Fatal("read timeout safe error")
	}
	for _, mode := range []string{"large", "error", "redirect"} {
		f.mu.Lock()
		f.mode = mode
		f.mu.Unlock()
		r, e = call(t, s, "set_switch", map[string]any{"id": "switch.a", "power": "off"})
		if e != nil || !r.IsError || !strings.Contains(resultJSON(t, r), "uncertain") {
			t.Fatalf("%s write result", mode)
		}
		assertSafe(t, resultJSON(t, r))
	}
	if len(f.snapshot()) != 5 {
		t.Fatal("backend request count changed")
	}
}
