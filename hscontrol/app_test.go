package hscontrol

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/cloudflare"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	app.cfg.DNSConfig.BaseDomain = "tailnet.invalid"
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

// TestDebugConfigRedacts: /debug/config is the configuration as
// config.Marshal writes it, without credentials; the running values keep
// theirs.
func TestDebugConfigRedacts(t *testing.T) {
	app := createTestApp(t)
	app.cfg.ServerURL = "https://marker-user:marker-pass@localhost:8080"
	app.cfg.CLI.Address = "https://marker-cli@cli.example.com"
	app.cfg.DNSConfig.Nameservers.Global = []string{"1.1.1.1", "https://marker-dns-user:marker-dns-pass@dns.example.com/q"}
	app.cfg.DNSConfig.Nameservers.Split = map[string][]string{"corp.example.com": {"https://marker-split@dns.example.com/q"}}
	app.cfg.Database.Postgres.Pass = "marker-pg-pass"

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/debug/config", nil)
	req.Host = "localhost"
	req.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	app.debugHTTPServer().Handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.NotContains(t, rec.Body.String(), "marker")
	assert.Contains(t, rec.Body.String(), `"server_url":"https://localhost:8080"`)
	assert.Contains(t, rec.Body.String(), `"global":["1.1.1.1","https://dns.example.com/q"]`)
	assert.Contains(t, app.cfg.ServerURL, "marker-pass")
}

// TestNewHeadscaleDNSProvider pins that startup builds the provider
// dns.challenge.provider names, reading its secrets, unless Go set one, and
// refuses one that cannot keep node certificates apart.
func TestNewHeadscaleDNSProvider(t *testing.T) {
	token := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(token, []byte("from-file\n"), 0o600))

	oneAccount := map[string]any{
		"name": "acmedns", "username": "u", "password": "p",
		"subdomain": "s", "server_url": "https://auth.acme-dns.io",
	}
	goOnly := &cloudflare.Provider{APIToken: "go-only"}
	goOnlyAcmeDNS, err := dns.NewProvider("acmedns", oneAccount,
		func(string) (any, bool) { return nil, false },
		func(_, v string) (string, error) { return v, nil })
	require.NoError(t, err)

	tests := []struct {
		name         string
		challenge    types.DNSChallengeConfig
		certificates bool
		wantToken    string
		wantErr      string
	}{
		{
			name:      "built from settings",
			challenge: types.DNSChallengeConfig{ProviderSettings: map[string]any{"name": "cloudflare", "api_token": "file:" + token}},
			wantToken: "from-file",
		},
		{
			name: "go-only provider wins",
			challenge: types.DNSChallengeConfig{
				ProviderSettings: map[string]any{"name": "cloudflare", "api_token": "settings"},
				Provider:         goOnly,
			},
			wantToken: "go-only",
		},
		{
			name:      "unreadable secret",
			challenge: types.DNSChallengeConfig{ProviderSettings: map[string]any{"name": "cloudflare", "api_token": "file:/nonexistent"}}, //nolint:gosec // a missing file, not a credential
			wantErr:   "dns.challenge.provider.api_token: ",
		},
		{
			name:         "one acme-dns account for node certificates",
			challenge:    types.DNSChallengeConfig{ProviderSettings: oneAccount},
			certificates: true,
			wantErr:      "for acmedns: ",
		},
		{
			name:         "go-only provider named by its type",
			challenge:    types.DNSChallengeConfig{Provider: goOnlyAcmeDNS},
			certificates: true,
			wantErr:      "for *dns.acmeDNS: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.DNSConfig.MagicDNS = true
			cfg.DNSConfig.BaseDomain = "ts.example.com"
			cfg.DNSConfig.Certificates.Enabled = tt.certificates
			cfg.DNSConfig.Challenge = tt.challenge

			app, err := NewHeadscale(&cfg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			t.Cleanup(func() { _ = app.state.Close() })

			provider, ok := cfg.DNSProvider().(*cloudflare.Provider)
			require.True(t, ok, "provider is %T", cfg.DNSProvider())
			assert.Equal(t, tt.wantToken, provider.APIToken)
		})
	}
}

// TestNewHeadscaleSecrets pins that startup reads a file: secret only where
// it is used, and that one it cannot read stops startup, even when OIDC may
// be unavailable.
func TestNewHeadscaleSecrets(t *testing.T) {
	missing := types.Secret("file:" + filepath.Join(t.TempDir(), "missing"))

	tests := []struct {
		name    string
		set     func(*types.Config)
		wantErr string
		noFiles bool // fails before startup writes anything
	}{
		{
			name: "oidc client secret file missing, fallback allowed",
			set: func(c *types.Config) {
				// Unreachable, so discovery would fail and fall back, were the
				// secret read only there.
				c.OIDC.Issuer = "http://127.0.0.1:1"
				c.OIDC.ClientID = "headscale"
				c.OIDC.ClientSecret = missing
				c.OIDC.OnlyStartIfOIDCIsAvailable = false
			},
			wantErr: "oidc.client_secret: ",
			noFiles: true,
		},
		{
			name: "oidc client secret file missing, oidc required",
			set: func(c *types.Config) {
				c.OIDC.Issuer = "http://127.0.0.1:1"
				c.OIDC.ClientID = "headscale"
				c.OIDC.ClientSecret = missing
				c.OIDC.OnlyStartIfOIDCIsAvailable = true
			},
			wantErr: "oidc.client_secret: ",
			noFiles: true,
		},
		{
			name: "postgres pass file missing",
			set: func(c *types.Config) {
				c.Database.Type = types.DatabasePostgres
				c.Database.Postgres = types.PostgresConfig{Host: "127.0.0.1", Port: 1, Name: "headscale", Pass: missing}
			},
			wantErr: "database.postgres.pass: ",
		},
		{
			name: "inactive consumers read nothing",
			set: func(c *types.Config) {
				c.Database.Postgres.Pass = missing
				c.OIDC.ClientSecret = missing
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tmpDir := filepath.Dir(cfg.Noise.PrivateKeyPath)
			tt.set(&cfg)

			app, err := NewHeadscale(&cfg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.ErrorContains(t, err, "readable by the user running headscale")
				// Read before connecting: a connection error would not name the key.
				assert.NotContains(t, err.Error(), "connect")

				if tt.noFiles {
					entries, err := os.ReadDir(tmpDir)
					require.NoError(t, err)
					assert.Empty(t, entries, "no noise key or database before the secret is read")
				}

				return
			}

			require.NoError(t, err)
			t.Cleanup(func() { _ = app.state.Close() })
		})
	}
}

// validConfig is config.Default with a local server URL, its files under a
// fresh temp dir, the policy in the database, DNS off, and the batcher
// quick and single-threaded, and the node store batching briefly, for
// tests.
func validConfig(t *testing.T) types.Config {
	t.Helper()

	dir := t.TempDir()
	v4 := netip.MustParsePrefix("100.64.0.0/10")
	v6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := config.Default()
	cfg.ServerURL = "http://localhost:8080"
	cfg.Noise.PrivateKeyPath = filepath.Join(dir, "noise_private.key")
	cfg.Database.Type = types.DatabaseSqlite
	cfg.Database.Sqlite.Path = filepath.Join(dir, "headscale_test.db")
	cfg.Prefixes.V4 = &v4
	cfg.Prefixes.V6 = &v6
	cfg.Policy.Mode = types.PolicyModeDB
	cfg.DNSConfig.MagicDNS = false
	cfg.DNSConfig.OverrideLocalDNS = false
	cfg.DNSConfig.BaseDomain = ""
	cfg.Tuning.BatchChangeDelay = 100 * time.Millisecond
	cfg.Tuning.BatcherWorkers = 1
	cfg.Tuning.NodeStoreBatchSize = state.TestBatchSize
	cfg.Tuning.NodeStoreBatchTimeout = state.TestBatchTimeout

	return cfg
}

// TestNewHeadscaleRejectsInvalidConfig: a configuration Validate rejects
// stops startup before anything is written.
func TestNewHeadscaleRejectsInvalidConfig(t *testing.T) {
	for _, tt := range []struct {
		name string
		set  func(*types.Config)
		key  string
	}{
		{name: "derp url", set: func(c *types.Config) { c.DERP.URLs = []types.HTTPURL{"ftp://h/map"} }, key: "derp.urls[0]"},
		{name: "zero prefix", set: func(c *types.Config) { c.Prefixes.V4 = &netip.Prefix{} }, key: "prefixes.v4"},
		{name: "zero trusted proxy", set: func(c *types.Config) { c.TrustedProxies = []netip.Prefix{{}} }, key: "trusted_proxies[0]"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.set(&cfg)

			_, err := NewHeadscale(&cfg)
			require.ErrorContains(t, err, tt.key)
			require.ErrorIs(t, err, types.ErrConfig)

			entries, err := os.ReadDir(filepath.Dir(cfg.Noise.PrivateKeyPath))
			require.NoError(t, err)
			assert.Empty(t, entries, "no noise key or database")
		})
	}
}

// TestNewHeadscaleRejectsSharedKey: noise and DERP keys that resolve to
// one file stop startup before anything is written, set from Go or loaded.
func TestNewHeadscaleRejectsSharedKey(t *testing.T) {
	shared := func(t *testing.T) (types.Config, string) {
		t.Helper()

		cfg := validConfig(t)
		dir := filepath.Dir(cfg.Database.Sqlite.Path)
		cfg.ConfigDir = dir
		cfg.Noise.PrivateKeyPath = "shared.key"
		cfg.DERP.Server.Enabled = true
		cfg.DERP.Server.RegionID = 999
		cfg.DERP.Server.STUNAddr = ":3478"
		cfg.DERP.Server.PrivateKeyPath = filepath.Join(dir, "shared.key")

		return cfg, dir
	}

	t.Run("go", func(t *testing.T) {
		cfg, dir := shared(t)

		_, err := NewHeadscale(&cfg)
		require.ErrorContains(t, err, "derp.server.private_key_path must differ from noise.private_key_path")

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries, "no key or database")
	})

	t.Run("go without config dir", func(t *testing.T) {
		cfg, dir := shared(t)
		cfg.ConfigDir = ""

		t.Chdir(dir)

		_, err := NewHeadscale(&cfg)
		require.ErrorContains(t, err, "derp.server.private_key_path must differ from noise.private_key_path")

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries, "no key or database")
	})

	t.Run("loaded", func(t *testing.T) {
		cfg, dir := shared(t)

		out, err := config.Marshal(&cfg, ".yaml")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), out, 0o600))

		l, err := config.Load(filepath.Join(dir, "config.yaml"), true, nil)
		require.NoError(t, err)

		_, err = NewHeadscale(l.Config)
		require.ErrorContains(t, err, "derp.server.private_key_path must differ from noise.private_key_path")

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "no key or database")
		assert.Equal(t, "config.yaml", entries[0].Name())
	})
}

// TestNewHeadscaleWarnsBeforeRejecting: the advisories are logged even when
// the configuration is rejected; one may explain the error.
func TestNewHeadscaleWarnsBeforeRejecting(t *testing.T) {
	buf := captureLog(t, zerolog.WarnLevel)

	cfg := validConfig(t)
	v4 := netip.MustParsePrefix("10.0.0.0/8")
	cfg.Prefixes.V4 = &v4
	cfg.Tuning.BatchChangeDelay = 0

	warnings := config.Warnings(&cfg)
	require.NotEmpty(t, warnings)

	_, err := NewHeadscale(&cfg)
	require.ErrorContains(t, err, "tuning.batch_change_delay must be positive")
	assert.Len(t, buf.entries(t, warnings[0]), 1)
}

// TestNewHeadscaleGoOnlyProvider: an embedder's provider serves node
// certificates without a provider name.
func TestNewHeadscaleGoOnlyProvider(t *testing.T) {
	provider := &cloudflare.Provider{APIToken: "go-only"}

	cfg := validConfig(t)
	cfg.DNSConfig.MagicDNS = true
	cfg.DNSConfig.BaseDomain = "ts.example.com"
	cfg.DNSConfig.Certificates.Enabled = true
	cfg.DNSConfig.Challenge.Provider = provider

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = app.state.Close() })

	assert.Same(t, provider, cfg.DNSProvider())
}

// TestDERPRefreshDoesNotBlockScheduledTasks: a DERP refresh stuck on an
// unreachable source leaves the other scheduled tasks running.
func TestDERPRefreshDoesNotBlockScheduledTasks(t *testing.T) {
	requested := make(chan struct{}, 1)
	release := make(chan struct{})
	stuck := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case requested <- struct{}{}:
		default:
		}

		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(stuck.Close)

	app := createTestApp(t, func(c *types.Config) {
		c.DERP.URLs = []types.HTTPURL{types.HTTPURL(stuck.URL)}
		c.DERP.AutoUpdate = true
		c.DERP.UpdateFrequency = time.Millisecond
	})

	records := filepath.Join(t.TempDir(), "records.json")
	require.NoError(t, os.WriteFile(records, []byte("[]"), 0o600))

	var err error

	app.extraRecordMan, err = dns.NewExtraRecordsManager(records)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())

	// Both log and touch app, so they end before the next test or the
	// state's own cleanup.
	var tasks sync.WaitGroup

	tasks.Go(app.extraRecordMan.Run)
	tasks.Go(func() { app.scheduledTasks(ctx) })

	t.Cleanup(func() {
		cancel()
		close(release)
		app.extraRecordMan.Close()
		tasks.Wait()
	})

	select {
	case <-requested:
	case <-time.After(10 * time.Second):
		t.Fatal("no DERP refresh started")
	}

	require.NoError(t, os.WriteFile(records, []byte(`[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`), 0o600))

	assert.Eventually(t, func() bool { return app.cfg.HasExtraRecord("a.example.com") }, 10*time.Second, 50*time.Millisecond,
		"extra records not reloaded while the DERP refresh is stuck")
}

// serveTestConfig is validConfig serving on loopback and a unix socket, with
// the embedded DERP server and its STUN listener on stunAddr.
func serveTestConfig(t *testing.T, stunAddr string) *types.Config {
	t.Helper()

	cfg := validConfig(t)
	dir := filepath.Dir(cfg.Noise.PrivateKeyPath)
	cfg.Addr = "127.0.0.1:0"
	cfg.UnixSocket = filepath.Join(dir, "hs.sock")
	cfg.DERP.URLs = nil
	cfg.DERP.Server = types.DERPServerConfig{
		Enabled:                            true,
		AutomaticallyAddEmbeddedDerpRegion: true,
		PrivateKeyPath:                     filepath.Join(dir, "derp.key"),
		RegionID:                           999,
		RegionCode:                         "test",
		STUNAddr:                           types.ListenAddr(stunAddr),
	}

	return &cfg
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

// TestServeWaitsForScheduledTasks: shutdown lets a scheduled task in flight
// end before it closes the batcher or the state, and Serve returns after it.
// A log hook holds the task, in its own goroutine, as it stops.
func TestServeWaitsForScheduledTasks(t *testing.T) {
	held, release := make(chan struct{}), make(chan struct{})
	heldOnce, releaseOnce := sync.OnceFunc(func() { close(held) }), sync.OnceFunc(func() { close(release) })

	old, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(io.Discard).Hook(zerolog.HookFunc(func(_ *zerolog.Event, _ zerolog.Level, msg string) {
		if msg == "scheduled task worker is shutting down." {
			heldOnce()
			<-release
		}
	}))

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	t.Cleanup(func() {
		releaseOnce()

		log.Logger = old

		zerolog.SetGlobalLevel(oldLevel)
	})

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
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("the scheduled tasks never saw the cancel")
	}

	batcher := app.MapBatcher()

	// Judge only once shutdown is parked waiting for the task, or has closed
	// the batcher without waiting.
	require.Eventually(t, func() bool {
		select {
		case <-batcher.Done():
			return true
		default:
			return serveParkedInWait()
		}
	}, 10*time.Second, time.Millisecond, "shutdown neither waited for its scheduled tasks nor closed the batcher")

	select {
	case <-batcher.Done():
		t.Fatal("the batcher closed while a scheduled task was running")
	default:
	}

	require.NoError(t, app.state.PingDB(t.Context()), "the database closed while a scheduled task was running")

	releaseOnce()

	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after its scheduled tasks ended")
	}
}

// serveParkedInWait reports whether a goroutine of [Headscale.Serve] is
// blocked in a [sync.WaitGroup.Wait] it calls itself.
func serveParkedInWait() bool {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]

	for g := range strings.SplitSeq(string(buf), "\n\n") {
		_, after, ok := strings.Cut(g, "\nsync.(*WaitGroup).Wait(")
		if !ok {
			continue
		}

		// Skip the rest of the Wait line and its file line.
		frames := strings.SplitN(after, "\n", 3)
		if len(frames) == 3 && strings.HasPrefix(frames[2], "github.com/juanfont/headscale/hscontrol.(*Headscale).Serve.func") {
			return true
		}
	}

	return false
}

// TestServeStopsAHeldDERPRefresh: cancelling Serve ends a DERP refresh
// waiting on a source that does not answer, and the sources after it are not
// read: shutdown waits for the refresh, so it must not wait out each
// source's timeout.
func TestServeStopsAHeldDERPRefresh(t *testing.T) {
	held := make(chan struct{})
	heldOnce := sync.OnceFunc(func() { close(held) })

	var firstRequests, secondRequests atomic.Int32

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The first request is Serve's startup fetch.
		if firstRequests.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)

			return
		}

		heldOnce()
		<-r.Context().Done()
	}))
	t.Cleanup(first.Close)

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondRequests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(second.Close)

	cfg := serveTestConfig(t, "127.0.0.1:0")
	cfg.DERP.URLs = []types.HTTPURL{types.HTTPURL(first.URL), types.HTTPURL(second.URL)}
	cfg.DERP.AutoUpdate = true
	cfg.DERP.UpdateFrequency = time.Millisecond

	app, err := NewHeadscale(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	served := make(chan error, 1)

	go func() { served <- app.Serve(ctx) }()

	select {
	case <-held:
	case <-time.After(10 * time.Second):
		t.Fatal("no DERP refresh started")
	}

	cancel()

	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return promptly while a DERP source held its refresh")
	}

	assert.Equal(t, int32(1), secondRequests.Load(), "the refresh read the source after the held one")
}

// TestServeRefusesADERPPipe: a pipe in derp.paths is refused at every read,
// so neither startup nor a refresh blocks on it, and Serve stops at once.
func TestServeRefusesADERPPipe(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "derp.json")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))

	fetching := make(chan struct{})
	fetchingOnce := sync.OnceFunc(func() { close(fetching) })

	old, oldLevel := log.Logger, zerolog.GlobalLevel()
	log.Logger = zerolog.New(io.Discard).Hook(zerolog.HookFunc(func(_ *zerolog.Event, _ zerolog.Level, msg string) {
		if msg == "fetching DERPMap updates" {
			fetchingOnce()
		}
	}))

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	t.Cleanup(func() {
		log.Logger = old

		zerolog.SetGlobalLevel(oldLevel)
	})

	cfg := serveTestConfig(t, "127.0.0.1:0")
	cfg.DERP.Paths = []string{fifo}
	cfg.DERP.AutoUpdate = true
	cfg.DERP.UpdateFrequency = time.Millisecond

	app, err := NewHeadscale(cfg)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	served := make(chan error, 1)

	go func() { served <- app.Serve(ctx) }()

	select {
	case <-fetching:
	case err := <-served:
		t.Fatalf("Serve returned (err=%v) before a DERP refresh", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no DERP refresh started: startup blocked on the pipe")
	}

	cancel()

	select {
	case err := <-served:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return promptly with a pipe in derp.paths")
	}
}
