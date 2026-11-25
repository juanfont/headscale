package cli

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol"
	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{
			name:    "bare host defaults to https",
			address: "headscale.example.com:50443",
			want:    "https://headscale.example.com:50443",
		},
		{
			name:    "explicit https scheme is kept",
			address: "https://headscale.example.com",
			want:    "https://headscale.example.com",
		},
		{
			name:    "explicit http scheme is kept",
			address: "http://localhost:8080",
			want:    "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientBaseURL(tt.address); got != tt.want {
				t.Errorf("clientBaseURL(%q) = %q, want %q", tt.address, got, tt.want)
			}
		})
	}
}

// TestCLIAPIKey pins that only a remote CLI reads cli.api_key; over the unix
// socket the key is never read.
func TestCLIAPIKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyFile, []byte("from-file\n"), 0o600))

	missing := "file:" + filepath.Join(dir, "missing")

	tests := []struct {
		name    string
		address string
		apiKey  string
		want    string // the key a remote CLI sends
		wantErr string
	}{
		{name: "remote literal", address: "headscale.example.com:443", apiKey: "literal", want: "literal"},
		{name: "remote reads the file", address: "headscale.example.com:443", apiKey: "file:" + keyFile, want: "from-file"},
		{name: "remote file missing", address: "headscale.example.com:443", apiKey: missing, wantErr: "cli.api_key: "},
		{name: "remote without a key", address: "headscale.example.com:443", wantErr: errAPIKeyNotSet.Error()},
		{name: "socket never reads", apiKey: missing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgDir := t.TempDir()
			cfgPath := filepath.Join(cfgDir, "config.yaml")
			require.NoError(t, os.WriteFile(cfgPath,
				[]byte("unix_socket: "+filepath.Join(cfgDir, "headscale.sock")+"\n"), 0o600))
			t.Setenv("HEADSCALE_CLI_ADDRESS", tt.address)
			t.Setenv("HEADSCALE_CLI_API_KEY", tt.apiKey)
			useLoaded(t, cfgPath)

			if tt.address != "" && tt.wantErr == "" {
				got, err := cliAPIKey(loaded.Config.CLI)
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}

			_, _, cancel, err := newHeadscaleCLIWithConfig()
			_, _, cancelV2, errV2 := newV2Client()

			for _, err := range []error{err, errV2} {
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
				} else {
					require.NoError(t, err)
				}
			}

			if err == nil {
				cancel()
				cancelV2()
			}
		})
	}
}

// TestDialEmptySocket: an empty unix_socket fails at once, naming the key,
// instead of retrying until the CLI timeout.
func TestDialEmptySocket(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	_, err := dialHeadscaleSocket(ctx, "")
	require.ErrorIs(t, err, errUnixSocketNotSet)
}

// TestServerConfigDropsCLIKey: the server never holds the CLI's key, which
// may be a file only the CLI can read.
func TestServerConfigDropsCLIKey(t *testing.T) {
	dir := t.TempDir()
	useLoaded(t, writeServerConfig(t, dir, "cli:\n  api_key: file:"+filepath.Join(dir, "missing")+"\n"))

	assert.Empty(t, serverConfig().CLI.APIKey)
}

// TestBypassDatabaseValidates: the policy commands' --bypass path, which
// starts no server, validates the configuration before opening the
// database.
func TestBypassDatabaseValidates(t *testing.T) {
	dir := t.TempDir()
	useLoaded(t, writeServerConfig(t, dir, "node:\n  ephemeral:\n    inactivity_timeout: 1s\n"))

	_, err := bypassDatabase()
	require.ErrorContains(t, err, "node.ephemeral.inactivity_timeout is below the minimum")
	assert.NoFileExists(t, filepath.Join(dir, "headscale.db"))
}

// serveSocket serves h on a unix socket for the CLI and returns the env that
// points the CLI at it.
func serveSocket(t *testing.T, h http.Handler) []string {
	t.Helper()

	sock := filepath.Join(t.TempDir(), "s")

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}

	go srv.Serve(ln) //nolint:errcheck // closed below

	t.Cleanup(func() { srv.Close() })

	return []string{
		"HOME=" + t.TempDir(),
		"HEADSCALE_UNIX_SOCKET=" + sock,
		"HEADSCALE_CLI_TIMEOUT=5s",
		"HEADSCALE_DISABLE_CHECK_UPDATES=true",
	}
}

// TestCLIWritesThroughV1 runs the old CLI's writes, as a process, against
// the real v1 API over its socket: the bytes the generated client sends are
// the ones a frozen v1 must keep accepting until the CLI goes. Each command
// is checked by what it stored.
func TestCLIWritesThroughV1(t *testing.T) {
	before := nodeStoreWriters()

	var (
		st      *state.State
		started []string
	)

	t.Run("writes", func(t *testing.T) {
		dir := t.TempDir()
		v4, v6 := netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd7a:115c:a1e0::/48")

		cfg := config.Default()
		cfg.ServerURL = "http://localhost:8080"
		cfg.Noise.PrivateKeyPath = filepath.Join(dir, "noise.key")
		cfg.Database.Type = types.DatabaseSqlite
		cfg.Database.Sqlite.Path = filepath.Join(dir, "db.sqlite")
		cfg.Prefixes.V4, cfg.Prefixes.V6 = &v4, &v6
		cfg.Policy.Mode = types.PolicyModeDB

		app, err := hscontrol.NewHeadscale(&cfg)
		require.NoError(t, err)

		st = app.GetState()

		// Registered first, so it runs last: after the batcher stops.
		t.Cleanup(func() { assert.NoError(t, st.Close()) })
		app.StartBatcherForTest(t)

		for id := range nodeStoreWriters() {
			if !before[id] {
				started = append(started, id)
			}
		}

		mux, _ := apiv1.Handler(apiv1.Backend{State: st, Change: app.Change, Cfg: &cfg})

		sock := filepath.Join(dir, "s.sock")
		serveConfig(t, sock, apiv1.WithLocalTrust(mux).ServeHTTP)
		cliConfig := writeFile(t, dir, "cli.yaml", "unix_socket: "+sock+"\n")

		run := func(args ...string) string {
			t.Helper()

			stdout, stderr, err := runHeadscale(t, []string{"HOME=" + t.TempDir()}, append([]string{"-c", cliConfig}, args...)...)
			require.NoError(t, err, "%v: %s", args, stderr)

			return stdout
		}

		run("users", "create", "alice", "--display-name", "Alice", "--email", "alice@example.com")

		users, err := st.ListAllUsers()
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "Alice", users[0].DisplayName)

		run("users", "rename", "--identifier", "1", "--new-name", "bob")

		users, err = st.ListAllUsers()
		require.NoError(t, err)
		assert.Equal(t, "bob", users[0].Name)

		// The tags-only key: the generated client sends "user": "".
		run("preauthkeys", "create", "--tags", "tag:x", "--expiration", "24h")
		run("preauthkeys", "create", "--user", "1", "--reusable", "--expiration", "24h")

		keys, err := st.ListPreAuthKeys()
		require.NoError(t, err)
		require.Len(t, keys, 2)

		tagged := slices.IndexFunc(keys, func(k types.PreAuthKey) bool { return len(k.Tags) > 0 })
		require.NotEqual(t, -1, tagged)

		tagsOnly, owned := keys[tagged], keys[1-tagged]
		assert.Nil(t, tagsOnly.User, "a tags-only key")
		assert.Equal(t, []string{"tag:x"}, tagsOnly.Tags)
		require.NotNil(t, owned.User)
		assert.Equal(t, "bob", owned.User.Name)
		assert.True(t, owned.Reusable)

		// Live before, so expiring it is a change.
		require.NotNil(t, owned.Expiration)
		assert.True(t, owned.Expiration.After(time.Now()), "live before expire")

		run("preauthkeys", "expire", "--id", strconv.FormatUint(owned.ID, 10))
		run("preauthkeys", "delete", "--id", strconv.FormatUint(tagsOnly.ID, 10))

		keys, err = st.ListPreAuthKeys()
		require.NoError(t, err)
		require.Len(t, keys, 1)
		assert.Equal(t, owned.ID, keys[0].ID)
		assert.True(t, keys[0].Expiration.Before(time.Now()), "expired")

		run("apikeys", "create", "--expiration", "24h")

		apiKeys, err := st.ListAPIKeys()
		require.NoError(t, err)
		require.Len(t, apiKeys, 1)

		require.NotNil(t, apiKeys[0].Expiration)
		assert.True(t, apiKeys[0].Expiration.After(time.Now()), "live before expire")

		run("apikeys", "expire", "--prefix", apiKeys[0].Prefix)
		apiKeys, err = st.ListAPIKeys()
		require.NoError(t, err)
		assert.True(t, apiKeys[0].Expiration.Before(time.Now()), "expired")

		run("apikeys", "delete", "--id", strconv.FormatUint(apiKeys[0].ID, 10))
		apiKeys, err = st.ListAPIKeys()
		require.NoError(t, err)
		assert.Empty(t, apiKeys)
	})

	// A -run selector that filters out the subtest leaves nothing to check.
	if st == nil {
		return
	}

	// Nothing of the server runs or answers once the test has ended: the
	// writer it started exits once signalled, and the database is closed.
	require.NotEmpty(t, started)
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		running := nodeStoreWriters()
		for _, id := range started {
			assert.False(c, running[id], "the NodeStore writer must stop")
		}
	}, 5*time.Second, 10*time.Millisecond)
	assert.Error(t, st.PingDB(t.Context()), "the database must be closed")
}

// nodeStoreWriters returns the IDs of the goroutines running a NodeStore
// write loop, from a full goroutine dump. They are found by their creator,
// not their frames: a writer not yet scheduled shows only Start's wrapper.
func nodeStoreWriters() map[string]bool {
	var buf bytes.Buffer

	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)

	ids := map[string]bool{}

	for g := range strings.SplitSeq(buf.String(), "\n\n") {
		if strings.Contains(g, "\ncreated by github.com/juanfont/headscale/hscontrol/state.(*NodeStore).Start in ") {
			id, _, _ := strings.Cut(strings.TrimPrefix(g, "goroutine "), " ")
			ids[id] = true
		}
	}

	return ids
}

// serveConfig serves handler on a unix socket at sock, as the server's
// API would.
func serveConfig(t *testing.T, sock string, handler http.HandlerFunc) {
	t.Helper()

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}
