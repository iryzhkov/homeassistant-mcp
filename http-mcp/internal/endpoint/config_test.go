package endpoint

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigUnknownFieldsBoundsAndSourceQualification(t *testing.T) {
	f := newFixture(t)
	good, _ := json.Marshal(f.cfg)
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(raw []byte) {
		t.Helper()
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(good)
	if _, e := LoadConfig(path); e != nil {
		t.Fatal("valid config refused")
	}
	for name, mutate := range map[string]func(map[string]any){
		"inline credential":  func(c map[string]any) { c["backend_token"] = "secret" },
		"environment secret": func(c map[string]any) { c["backend_token_env"] = "HA_TOKEN" },
		"unknown nested":     func(c map[string]any) { c["entities"].([]any)[0].(map[string]any)["area"] = "all" },
		"wildcard":           func(c map[string]any) { c["entities"].([]any)[0].(map[string]any)["id"] = "light.*" },
		"long id": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["id"] = "light." + strings.Repeat("a", 97)
		},
		"duplicate entity":    func(c map[string]any) { c["entities"] = []any{c["entities"].([]any)[0], c["entities"].([]any)[0]} },
		"unqualified control": func(c map[string]any) { c["entities"].([]any)[0].(map[string]any)["control_qualified"] = false },
		"domain mismatch": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["actions"] = []string{"switch.control"}
		},
		"relay action": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["actions"] = []string{"service.call"}
		},
		"brightness below zero": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["brightness"] = map[string]int{"min_percent": -1, "max_percent": 50}
		},
		"brightness above100": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["brightness"] = map[string]int{"min_percent": 0, "max_percent": 101}
		},
		"reversed bounds": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["brightness"] = map[string]int{"min_percent": 80, "max_percent": 20}
		},
		"missing brightness bounds": func(c map[string]any) {
			c["entities"].([]any)[0].(map[string]any)["brightness"] = map[string]int{"min_percent": 0}
		},
		"empty registry": func(c map[string]any) { c["entities"] = []any{} },
		"too many entities": func(c map[string]any) {
			entities := []any{}
			for i := 0; i < 65; i++ {
				entities = append(entities, map[string]any{"id": "sensor." + strings.Repeat("a", i+1), "name": "n", "actions": []string{"state.read"}})
			}
			c["entities"] = entities
		},
		"nonhttps resource": func(c map[string]any) { c["resource_url"] = "http://ha.mcp.example/mcp" },
		"resource path":     func(c map[string]any) { c["resource_url"] = "https://ha.mcp.example/api" },
		"issuer slash":      func(c map[string]any) { c["issuer_url"] = "https://issuer.example/application/o/ha" },
		"jwks https":        func(c map[string]any) { c["jwks_url"] = "http://issuer.example/jwks" },
		"ha path":           func(c map[string]any) { c["ha_url"] = "https://ha.example/api" },
		"ha userinfo":       func(c map[string]any) { c["ha_url"] = "https://secret@ha.example" },
		"token relative":    func(c map[string]any) { c["backend_token_file"] = "token" },
	} {
		t.Run(name, func(t *testing.T) {
			var c map[string]any
			_ = json.Unmarshal(good, &c)
			mutate(c)
			raw, _ := json.Marshal(c)
			write(raw)
			if _, e := LoadConfig(path); e == nil {
				t.Fatal("bad config accepted")
			}
		})
	}
	for _, raw := range []string{string(good) + "{}", strings.Repeat("x", maxBody+1), "null"} {
		write([]byte(raw))
		if _, e := LoadConfig(path); e == nil {
			t.Fatal("malformed config accepted")
		}
	}
	// Ambient credentials cannot compensate for a missing fixed file.
	t.Setenv("HA_TOKEN", "ambient-secret")
	cfg := f.cfg
	cfg.BackendTokenFile = filepath.Join(t.TempDir(), "absent")
	if _, e := New(cfg); e == nil {
		t.Fatal("ambient fallback accepted")
	}
	cfg = f.cfg
	cfg.Entities[0].Actions = []string{"state.read"}
	cfg.Entities[0].ControlQualified = false
	cfg.Entities[0].Brightness = nil
	if e := cfg.validate(); e != nil {
		t.Fatal("read-only enrollment rejected")
	}
}
func TestBackendCredentialFileBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if e := os.WriteFile(path, []byte("synthetic-token"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := readBackendToken(path); e != nil {
		t.Fatal("private owner file refused")
	}
	if e := os.Chmod(path, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := readBackendToken(path); e == nil {
		t.Fatal("group-readable credential accepted")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readBackendToken(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if _, e := readBackendToken(filepath.Dir(path)); e == nil {
		t.Fatal("directory accepted")
	}
	// Exercise a different runtime UID against the real descriptor owner;
	// Chaldea's single-UID namespace cannot chown to an unmapped UID.
	if _, e := readBackendTokenOwnedBy(path, os.Geteuid()+1); e == nil {
		t.Fatal("foreign owner accepted")
	}
	for _, data := range []string{"", strings.Repeat("x", 4097), "secret\r\n", "secret another", "secret\nsecond"} {
		if e := os.WriteFile(path, []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := readBackendToken(path); e == nil {
			t.Fatal("invalid token file accepted")
		}
	}
}
func TestConfiguredActionsBrightnessAndZeroSemantics(t *testing.T) {
	f := newFixture(t)
	// Same signed grants cannot exceed the operator registry.
	f.srv.entities["light.a"] = Entity{ID: "light.a", Name: "Read only", Actions: []string{"state.read"}}
	s, _ := f.session(f.sign(f.baseClaims()))
	r, e := call(t, s, "set_light", map[string]any{"id": "light.a", "power": "on"})
	if e == nil && !r.IsError {
		t.Fatal("registry ceiling exceeded")
	}
	if len(f.snapshot()) != 0 {
		t.Fatal("registry refusal reached backend")
	}
	f.srv.entities["light.a"] = Entity{ID: "light.a", Name: "Lamp", Actions: []string{"state.read", "light.control"}, ControlQualified: true, Brightness: &Brightness{MinPercent: 0, MaxPercent: 100}}
	s, _ = f.session(f.sign(f.baseClaims()))
	for _, brightness := range []int{0, 100} {
		r, e := call(t, s, "set_light", map[string]any{"id": "light.a", "power": "on", "brightness_percent": brightness})
		if e != nil || r.IsError {
			t.Fatalf("zero/full brightness refused: err=%v result=%s", e, resultJSON(t, r))
		}
		calls := f.snapshot()
		last := calls[len(calls)-1]
		want := float64(0)
		if brightness == 100 {
			want = 255
		}
		if last.Path != "/api/services/light/turn_on" || last.Body["brightness"] != want {
			t.Fatal("brightness conversion")
		}
	}
	for _, brightness := range []int{-1, 101} {
		before := len(f.snapshot())
		r, e := call(t, s, "set_light", map[string]any{"id": "light.a", "power": "on", "brightness_percent": brightness})
		if e == nil && !r.IsError {
			t.Fatal("global brightness bound exceeded")
		}
		if len(f.snapshot()) != before {
			t.Fatal("bad brightness reached HA")
		}
	}
	c := f.baseClaims()
	c["ha_entities"] = []string{"light.b"}
	sibling, _ := f.session(f.sign(c))
	before := len(f.snapshot())
	r, e = call(t, sibling, "set_light", map[string]any{"id": "light.b", "power": "on", "brightness_percent": 50})
	if e == nil && !r.IsError {
		t.Fatal("unenrolled brightness accepted")
	}
	if len(f.snapshot()) != before {
		t.Fatal("unenrolled brightness reached HA")
	}
	c = f.baseClaims()
	c["ha_actions"] = []string{"state.read"}
	read, _ := f.session(f.sign(c))
	if got := toolNames(t, read); len(got) != 2 {
		t.Fatal("signed action ceiling exceeded")
	}
}
func TestNoAmbientProxyOrRedirects(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:1")
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:1")
	c := fixedClient(1)
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil {
		t.Fatal("ambient proxy enabled")
	}
	if c.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirects enabled")
	}
}
