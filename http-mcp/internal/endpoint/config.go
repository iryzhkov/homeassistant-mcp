// Package endpoint implements the bounded Home Assistant MCP resource.
package endpoint

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const MaxEntities = 64
const maxBody = 64 << 10

var entityPattern = regexp.MustCompile(`^(light|switch|sensor|binary_sensor)\.[a-z0-9_]{1,96}$`)
var errConfig = errors.New("invalid endpoint configuration")

type Brightness struct {
	MinPercent int `json:"min_percent"`
	MaxPercent int `json:"max_percent"`
}

// Both bounds must be explicit in the operator JSON.
func (b *Brightness) UnmarshalJSON(raw []byte) error {
	var fields struct {
		Min *int `json:"min_percent"`
		Max *int `json:"max_percent"`
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&fields) != nil || fields.Min == nil || fields.Max == nil {
		return errConfig
	}
	b.MinPercent = *fields.Min
	b.MaxPercent = *fields.Max
	return nil
}

type Entity struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	Actions          []string    `json:"actions"`
	ControlQualified bool        `json:"control_qualified,omitempty"`
	Brightness       *Brightness `json:"brightness,omitempty"`
}
type Config struct {
	Listen           string   `json:"listen"`
	ResourceURL      string   `json:"resource_url"`
	IssuerURL        string   `json:"issuer_url"`
	JWKSURL          string   `json:"jwks_url"`
	HAURL            string   `json:"ha_url"`
	BackendTokenFile string   `json:"backend_token_file"`
	Entities         []Entity `json:"entities"`
}

// LoadConfig accepts only this schema. There are no environment, inline-secret,
// operator CLI, keyring or login fallbacks.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, errConfig
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxBody+1))
	if err != nil || len(raw) > maxBody {
		return cfg, errConfig
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF {
		return cfg, errConfig
	}
	return cfg, cfg.validate()
}
func canonicalURL(raw string, https bool) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" ||
		u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") || u.String() != raw ||
		strings.HasSuffix(u.Host, ":") || (u.Scheme != "https" && (https || u.Scheme != "http")) {
		return nil, errConfig
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || (u.Scheme == "https" && p == "443") || (u.Scheme == "http" && p == "80") {
			return nil, errConfig
		}
	}
	return u, nil
}
func (c Config) validate() error {
	if _, p, e := net.SplitHostPort(c.Listen); e != nil || p == "" {
		return errConfig
	}
	u, e := canonicalURL(c.ResourceURL, true)
	if e != nil || u.Path != "/mcp" {
		return errConfig
	}
	u, e = canonicalURL(c.IssuerURL, true)
	if e != nil || !strings.HasSuffix(u.Path, "/") {
		return errConfig
	}
	if _, e = canonicalURL(c.JWKSURL, true); e != nil {
		return errConfig
	}
	u, e = canonicalURL(c.HAURL, false)
	if e != nil || u.Path != "" {
		return errConfig
	}
	if !filepath.IsAbs(c.BackendTokenFile) || filepath.Clean(c.BackendTokenFile) != c.BackendTokenFile {
		return errConfig
	}
	if len(c.Entities) == 0 || len(c.Entities) > MaxEntities {
		return errConfig
	}
	seen := map[string]bool{}
	for _, v := range c.Entities {
		if !validID(v.ID) || seen[v.ID] || !safeText(v.Name, 128) || len(v.Actions) == 0 || len(v.Actions) > 2 {
			return errConfig
		}
		seen[v.ID] = true
		actions := map[string]bool{}
		control := false
		for _, a := range v.Actions {
			if actions[a] {
				return errConfig
			}
			actions[a] = true
			switch a {
			case "state.read":
			case "light.control", "switch.control":
				if !strings.HasPrefix(v.ID, strings.Split(a, ".")[0]+".") || !v.ControlQualified {
					return errConfig
				}
				control = true
			default:
				return errConfig
			}
		}
		if v.ControlQualified && !control {
			return errConfig
		}
		if v.Brightness != nil && (!actions["light.control"] || v.Brightness.MinPercent < 0 || v.Brightness.MaxPercent > 100 || v.Brightness.MinPercent > v.Brightness.MaxPercent) {
			return errConfig
		}
	}
	return nil
}
func validID(id string) bool { return len(id) <= 112 && entityPattern.MatchString(id) }
func safeText(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// Open the final component without following a symlink, then validate the open
// descriptor. The credential must be a private regular file of the runtime UID.
func readBackendToken(path string) (string, error) {
	return readBackendTokenOwnedBy(path, os.Geteuid())
}
func readBackendTokenOwnedBy(path string, runtimeUID int) (string, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if e != nil {
		return "", errConfig
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Mode()&os.ModeSetuid != 0 {
		return "", errConfig
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(owner.Uid) != runtimeUID {
		return "", errConfig
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return "", errConfig
	}
	token := strings.TrimSuffix(string(b), "\n")
	if len(token) < 1 {
		return "", errConfig
	}
	for _, r := range token {
		if r <= 32 || r >= 127 {
			return "", errConfig
		}
	}
	return token, nil
}
