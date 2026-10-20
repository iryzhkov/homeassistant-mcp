package endpoint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

type Server struct {
	cfg      Config
	verifier *verifier
	backend  *backend
	entities map[string]Entity
	handler  http.Handler
	slots    chan struct{}
}

func New(cfg Config) (*Server, error) {
	if e := cfg.validate(); e != nil {
		return nil, e
	}
	token, e := readBackendToken(cfg.BackendTokenFile)
	if e != nil {
		return nil, e
	}
	s := &Server{cfg: cfg, verifier: newVerifier(cfg), backend: &backend{url: cfg.HAURL, token: token, client: fixedClient(4 * time.Second)}, entities: map[string]Entity{}, slots: make(chan struct{}, 32)}
	// Copy the validated registry so callers cannot mutate the active policy.
	for _, v := range cfg.Entities {
		v.Actions = append([]string(nil), v.Actions...)
		if v.Brightness != nil {
			b := *v.Brightness
			v.Brightness = &b
		}
		s.entities[v.ID] = v
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stream := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server { return s.tools(r.Context(), logger) },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: maxBody, PropagateRequestCancellation: true,
			// Exact configured public Host is enforced outside the SDK, including direct
			// loopback traffic. This supports Traefik preserving that public authority.
			DisableLocalhostProtection: true, Logger: logger})
	u, _ := url.Parse(cfg.ResourceURL)
	metadataURL := u.Scheme + "://" + u.Host + "/.well-known/oauth-protected-resource/mcp"
	s.handler = auth.RequireBearerToken(func(ctx context.Context, raw string, r *http.Request) (*auth.TokenInfo, error) {
		if len(r.Header.Values("Authorization")) != 1 {
			return nil, auth.ErrInvalidToken
		}
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || fields[1] != raw {
			return nil, auth.ErrInvalidToken
		}
		c, e := s.verifier.verify(ctx, raw)
		if e != nil {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: c.Subject, Expiration: c.ExpiresAt.Time, Scopes: strings.Split(c.Scope, " "), Extra: map[string]any{"ha": c}}, nil
	}, &auth.RequireBearerTokenOptions{ResourceMetadataURL: metadataURL, ClockSkew: tokenSkew})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
			if err != nil {
				var tooLarge *http.MaxBytesError
				status := http.StatusBadRequest
				if errors.As(err, &tooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, "request refused", status)
				return
			}
			// Older MCP protocols permit batches. This resource accepts one object per
			// HTTP request, keeping the concurrency ceiling equal to admitted requests.
			if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
				http.Error(w, "single request required", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
		}
		stream.ServeHTTP(w, r)
	}))
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	u, _ := url.Parse(s.cfg.ResourceURL)
	origins := r.Header.Values("Origin")
	if r.Host != u.Host || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || len(origins) > 1 ||
		(len(origins) == 1 && origins[0] != u.Scheme+"://"+u.Host) {
		http.Error(w, "request refused", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("ok\n"))
		}
	case "/.well-known/oauth-protected-resource/mcp":
		auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{Resource: s.cfg.ResourceURL, AuthorizationServers: []string{s.cfg.IssuerURL},
			ScopesSupported: []string{"ha.read", "ha.control"}, BearerMethodsSupported: []string{"header"}, ResourceName: "Bounded Home Assistant entities"}).ServeHTTP(w, r)
	case "/mcp":
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		r = r.WithContext(ctx)
		select {
		case s.slots <- struct{}{}:
			defer func() { <-s.slots }()
		default:
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		// JSON-only stateless replies are buffered to bound even SDK validation
		// errors and reflected JSON-RPC IDs. No partial response is released.
		reply := &boundedReply{header: w.Header().Clone()}
		s.handler.ServeHTTP(reply, r)
		if reply.overflow {
			http.Error(w, "response refused; write outcome may be uncertain", http.StatusInternalServerError)
			return
		}
		for k, vs := range reply.header {
			w.Header()[k] = vs
		}
		w.Header().Set("Cache-Control", "no-store")
		status := reply.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		_, _ = w.Write(reply.body.Bytes())
	default:
		http.NotFound(w, r)
	}
}

type boundedReply struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *boundedReply) Header() http.Header { return w.header }
func (w *boundedReply) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *boundedReply) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if len(p) > maxBody-w.body.Len() {
		w.overflow = true
		return len(p), nil
	}
	if !w.overflow {
		_, _ = w.body.Write(p)
	}
	return len(p), nil
}
func requestClaims(ctx context.Context) *claims {
	ti := auth.TokenInfoFromContext(ctx)
	if ti == nil {
		return nil
	}
	c, _ := ti.Extra["ha"].(*claims)
	return c
}
func (s *Server) allowed(c *claims, id, action string) (Entity, bool) {
	e, ok := s.entities[id]
	if !ok || c == nil || !has(c.Entities, id) || !has(c.Actions, action) || !has(e.Actions, action) {
		return Entity{}, false
	}
	scope := "ha.control"
	if action == "state.read" {
		scope = "ha.read"
	}
	if !has(strings.Split(c.Scope, " "), scope) {
		return Entity{}, false
	}
	return e, true
}
func (s *Server) hasAction(c *claims, action string) bool {
	if c == nil {
		return false
	}
	for _, id := range c.Entities {
		if _, ok := s.allowed(c, id, action); ok {
			return true
		}
	}
	return false
}

type getArgs struct {
	ID string `json:"id"`
}
type pageArgs struct {
	Offset int `json:"offset,omitempty"`
	Limit  int `json:"limit,omitempty"`
}
type pageResult struct {
	Entities   []EntityState `json:"entities"`
	Total      int           `json:"total"`
	NextOffset *int          `json:"next_offset,omitempty"`
}
type lightArgs struct {
	ID                string `json:"id"`
	Power             string `json:"power"`
	BrightnessPercent *int   `json:"brightness_percent,omitempty"`
}
type switchArgs struct {
	ID    string `json:"id"`
	Power string `json:"power"`
}

var errArguments = errors.New("invalid arguments")

// A fresh stateless server advertises only actions allowed by THIS request's
// verified grants. No subject/session cache can retain a previous token's rights.
func (s *Server) tools(httpCtx context.Context, logger *slog.Logger) *mcp.Server {
	c := requestClaims(httpCtx)
	srv := mcp.NewServer(&mcp.Implementation{Name: "ha-mcp", Version: "0.1.0"}, &mcp.ServerOptions{Logger: logger, Capabilities: &mcp.ServerCapabilities{}})
	if s.hasAction(c, "state.read") {
		addTool(srv, httpCtx, "get_entity", "Read one authorized registered entity.", true, func(ctx context.Context, c *claims, a getArgs) (any, error) {
			e, ok := s.allowed(c, a.ID, "state.read")
			if !ok {
				return nil, errUnavailable
			}
			return s.backend.read(ctx, e)
		})
		addTool(srv, httpCtx, "list_entities", "Read permitted registered entities, ordered by ID. Offset applies only to the current token's permitted list; limit defaults to 10, maximum 20.", true,
			func(ctx context.Context, c *claims, a pageArgs) (any, error) {
				if a.Offset < 0 || a.Offset > MaxEntities || a.Limit < 0 || a.Limit > 20 {
					return nil, errArguments
				}
				if a.Limit == 0 {
					a.Limit = 10
				}
				ids := []string{}
				for id := range s.entities {
					if _, ok := s.allowed(c, id, "state.read"); ok {
						ids = append(ids, id)
					}
				}
				sort.Strings(ids)
				out := pageResult{Entities: []EntityState{}, Total: len(ids)}
				start := min(a.Offset, len(ids))
				end := min(start+a.Limit, len(ids))
				for _, id := range ids[start:end] {
					e, ok := s.allowed(c, id, "state.read")
					if !ok {
						return nil, errUnavailable
					}
					state, e2 := s.backend.read(ctx, e)
					if e2 != nil {
						return nil, errUnavailable
					}
					out.Entities = append(out.Entities, state)
				}
				if end < len(ids) {
					out.NextOffset = &end
				}
				return out, nil
			})
	}
	if s.hasAction(c, "light.control") {
		addTool(srv, httpCtx, "set_light", "Set explicit on/off and optional integer brightness_percent. Brightness is allowed only with on and enrolled bounds; zero means HA brightness 0 and can turn a light off. Acceptance does not confirm physical state.", false,
			func(ctx context.Context, c *claims, a lightArgs) (any, error) {
				e, ok := s.allowed(c, a.ID, "light.control")
				if !ok || !strings.HasPrefix(a.ID, "light.") {
					return nil, errUnavailable
				}
				if a.Power != "on" && a.Power != "off" {
					return nil, errArguments
				}
				if a.BrightnessPercent != nil && (a.Power != "on" || e.Brightness == nil || *a.BrightnessPercent < e.Brightness.MinPercent || *a.BrightnessPercent > e.Brightness.MaxPercent) {
					return nil, errArguments
				}
				return s.backend.set(ctx, e, a.Power, a.BrightnessPercent)
			})
	}
	if s.hasAction(c, "switch.control") {
		addTool(srv, httpCtx, "set_switch", "Set explicit on/off. Acceptance does not confirm physical state.", false,
			func(ctx context.Context, c *claims, a switchArgs) (any, error) {
				e, ok := s.allowed(c, a.ID, "switch.control")
				if !ok || !strings.HasPrefix(a.ID, "switch.") {
					return nil, errUnavailable
				}
				if a.Power != "on" && a.Power != "off" {
					return nil, errArguments
				}
				return s.backend.set(ctx, e, a.Power, nil)
			})
	}
	return srv
}
func addTool[In any](srv *mcp.Server, httpCtx context.Context, name, description string, readOnly bool, run func(context.Context, *claims, In) (any, error)) {
	mcp.AddTool(srv, &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: readOnly}},
		func(ctx context.Context, req *mcp.CallToolRequest, a In) (*mcp.CallToolResult, any, error) {
			if req.Extra == nil || req.Extra.TokenInfo == nil {
				return nil, nil, errUnavailable
			}
			c, ok := req.Extra.TokenInfo.Extra["ha"].(*claims)
			if !ok || c == nil {
				return nil, nil, errUnavailable
			}
			ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			// SDK cancellation for older protocol versions is detached; retain the
			// originating HTTP cancellation explicitly for every supported version.
			stop := context.AfterFunc(httpCtx, cancel)
			defer stop()
			out, e := run(ctx, c, a)
			return nil, out, e
		})
}
