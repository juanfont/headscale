package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	h := rec.Result().Header
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "frame-ancestors 'none'", h.Get("Content-Security-Policy"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))
}

func TestDebugHostGuard(t *testing.T) {
	app := createTestApp(t)
	app.cfg.ServerURL = "https://Control.Example.COM:443/headscale"
	app.cfg.MetricsAddr = "Debug.Internal:9090"
	app.cfg.BaseDomain = "tailnet.invalid"
	handler := app.debugHTTPServer().Handler

	for _, tt := range []struct {
		name   string
		host   string
		path   string
		status int
	}{
		{name: "localhost", host: "localhost:9090", path: "/debug/", status: http.StatusOK},
		{name: "localhost case and dot", host: "LOCALhost.", path: "/debug/", status: http.StatusOK},
		{name: "IPv4", host: "127.0.0.1:9090", path: "/debug/", status: http.StatusOK},
		{name: "IPv6", host: "[::1]", path: "/debug/", status: http.StatusOK},
		{name: "IPv6 port", host: "[::1]:9090", path: "/debug/", status: http.StatusOK},
		{name: "tailnet IP", host: "100.64.0.1:9090", path: "/debug/", status: http.StatusOK},
		{name: "private IP", host: "192.168.0.1:9090", path: "/debug/", status: http.StatusOK},
		{name: "server URL host", host: "CoNtRoL.ExAmPlE.CoM.:9090", path: "/debug/", status: http.StatusOK},
		{name: "metrics listen host", host: "DEBUG.INTERNAL.:9090", path: "/debug/", status: http.StatusOK},
		{name: "unknown host", host: "unknown.example", path: "/debug/", status: http.StatusForbidden},
		{name: "localhost suffix", host: "localhost.remote.example", path: "/debug/", status: http.StatusForbidden},
		{name: "server suffix", host: "control.example.com.remote", path: "/debug/", status: http.StatusForbidden},
		{name: "empty host", host: "", path: "/debug/", status: http.StatusForbidden},
		{name: "base domain", host: "tailnet.invalid", path: "/debug/", status: http.StatusForbidden},
		{name: "base domain child", host: "node.tailnet.invalid", path: "/debug/", status: http.StatusForbidden},
		{name: "custom debug handler", host: "unknown.example", path: "/debug/overview", status: http.StatusForbidden},
		{name: "pprof", host: "unknown.example", path: "/debug/pprof/", status: http.StatusForbidden},
		{name: "statsviz", host: "unknown.example", path: "/debug/statsviz/", status: http.StatusForbidden},
		{name: "statsviz websocket", host: "unknown.example", path: "/debug/statsviz/ws", status: http.StatusForbidden},
		{name: "whole mux", host: "unknown.example", path: "/", status: http.StatusForbidden},
		{name: "metrics any host", host: "unknown.example", path: "/metrics", status: http.StatusOK},
		{name: "metrics empty host", host: "", path: "/metrics", status: http.StatusOK},
		{name: "metrics query", host: "unknown.example", path: "/metrics?x=1", status: http.StatusOK},
		{name: "metrics slash", host: "unknown.example", path: "/metrics/", status: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			req.Host = tt.host
			req.RemoteAddr = "127.0.0.1:1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.status, rec.Code)
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))

			if tt.status == http.StatusForbidden {
				assert.Contains(t, rec.Body.String(), "localhost")
			}
		})
	}
}
