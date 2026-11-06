package hscontrol

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// serveTestConfig returns a config for running Serve on loopback with the
// embedded DERP server enabled on stunAddr.
func serveTestConfig(t *testing.T, stunAddr string) *types.Config {
	t.Helper()

	dir := t.TempDir()

	return &types.Config{
		ServerURL:            "http://127.0.0.1:8080",
		Addr:                 "127.0.0.1:0",
		UnixSocket:           filepath.Join(dir, "hs.sock"),
		UnixSocketPermission: 0o770,
		NoisePrivateKeyPath:  filepath.Join(dir, "noise.key"),
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: filepath.Join(dir, "hs.db")},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			ServerEnabled:                      true,
			AutomaticallyAddEmbeddedDerpRegion: true,
			ServerPrivateKeyPath:               filepath.Join(dir, "derp.key"),
			ServerRegionID:                     999,
			ServerRegionCode:                   "test",
			STUNAddr:                           stunAddr,
		},
		Tuning: types.Tuning{BatchChangeDelay: 100 * time.Millisecond, BatcherWorkers: 1},
	}
}

// A component that cannot start must hand its error back to Serve so the
// deferred shutdown runs; log.Fatal used to exit the process and skip it.
// https://github.com/juanfont/headscale/issues/3499
func TestServeReturnsSTUNBindError(t *testing.T) {
	taken, err := new(net.ListenConfig).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	defer taken.Close()

	app, err := NewHeadscale(serveTestConfig(t, taken.LocalAddr().String()))
	require.NoError(t, err)

	err = app.Serve(t.Context())
	require.ErrorIs(t, err, syscall.EADDRINUSE)

	var bindErr *types.ListenerBindError
	require.ErrorAs(t, err, &bindErr)
}

// Cancelling the context must run the graceful shutdown and return nil, so
// an embedder can stop Serve without sending the process a signal.
func TestServeStopsOnContextCancel(t *testing.T) {
	cfg := serveTestConfig(t, "127.0.0.1:0")

	app, err := NewHeadscale(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	served := make(chan error, 1)

	go func() { served <- app.Serve(ctx) }()

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, "unix", cfg.UnixSocket)
		},
	}}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/api/v1/health", nil)
		require.NoError(c, err)

		res, err := client.Do(req)
		require.NoError(c, err)

		defer res.Body.Close()

		assert.Equal(c, http.StatusOK, res.StatusCode)
	}, 10*time.Second, 50*time.Millisecond)

	cancel()

	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after its context was cancelled")
	}

	assert.NoFileExists(t, cfg.UnixSocket)
}
