package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/dns"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/cloudflare"
	"github.com/rs/zerolog"
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
// quick and single-threaded for tests.
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
	t.Cleanup(func() { close(release) })

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

	go app.extraRecordMan.Run()

	t.Cleanup(app.extraRecordMan.Close)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	go app.scheduledTasks(ctx)

	select {
	case <-requested:
	case <-time.After(10 * time.Second):
		t.Fatal("no DERP refresh started")
	}

	require.NoError(t, os.WriteFile(records, []byte(`[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`), 0o600))

	assert.Eventually(t, func() bool { return app.cfg.HasExtraRecord("a.example.com") }, 10*time.Second, 50*time.Millisecond,
		"extra records not reloaded while the DERP refresh is stuck")
}
