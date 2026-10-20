package endpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Exercise the legacy protocol path as well as SDK client calls: the SDK may
// detach the tool context for old protocol versions, but HA must still cancel.
func TestIncomingCancellationReachesBackend(t *testing.T) {
	f := newFixture(t)
	started, canceled := make(chan struct{}), make(chan struct{})
	ha := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer ha.Close()
	f.srv.backend.url = ha.URL
	f.srv.backend.client.Timeout = 2 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest("POST", "http://internal/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_entity","arguments":{"id":"light.a"}}}`)).WithContext(ctx)
	req.Host = "ha.mcp.example"
	req.Header.Set("Authorization", "Bearer "+f.sign(f.baseClaims()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	done := make(chan struct{})
	go func() { defer close(done); f.srv.ServeHTTP(httptest.NewRecorder(), req) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("backend did not start")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("HTTP cancellation did not reach backend")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not finish")
	}
}
