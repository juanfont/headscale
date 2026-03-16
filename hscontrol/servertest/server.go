// Package servertest provides an in-process test harness for Headscale's
// control plane. It wires a real Headscale server to real Tailscale
// controlclient.Direct instances, enabling fast, deterministic tests
// of the full control protocol without Docker or separate processes.
package servertest

import (
	"net/http/httptest"
	"testing"
	"time"

	hscontrol "github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// TestServer is an in-process Headscale control server suitable for
// use with Tailscale's controlclient.Direct.
type TestServer struct {
	App        *hscontrol.Headscale
	HTTPServer *httptest.Server
	URL        string
	st         *state.State
}

// ServerOption configures a TestServer.
type ServerOption func(*serverConfig)

type serverConfig struct {
	batchDelay       time.Duration
	bufferedChanSize int
	ephemeralTimeout time.Duration
	batcherWorkers   int
}

func defaultServerConfig() *serverConfig {
	return &serverConfig{
		batchDelay:       50 * time.Millisecond,
		batcherWorkers:   1,
		ephemeralTimeout: 30 * time.Second,
	}
}

// WithBatchDelay sets the batcher's change coalescing delay.
func WithBatchDelay(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.batchDelay = d }
}

// WithBufferedChanSize sets the per-node map session channel buffer.
func WithBufferedChanSize(n int) ServerOption {
	return func(c *serverConfig) { c.bufferedChanSize = n }
}

// WithEphemeralTimeout sets the ephemeral node inactivity timeout.
func WithEphemeralTimeout(d time.Duration) ServerOption {
	return func(c *serverConfig) { c.ephemeralTimeout = d }
}

// NewServer creates and starts a Headscale test server.
// The server is fully functional and accepts real Tailscale control
// protocol connections over Noise.
func NewServer(tb testing.TB, opts ...ServerOption) *TestServer {
	tb.Helper()

	sc := defaultServerConfig()
	for _, o := range opts {
		o(sc)
	}

	tmpDir := tb.TempDir()

	cfg := types.Config{
		// Placeholder; updated below once httptest server starts.
		ServerURL:                      "http://localhost:0",
		NoisePrivateKeyPath:            tmpDir + "/noise_private.key",
		EphemeralNodeInactivityTimeout: sc.ephemeralTimeout,
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		Tuning: types.Tuning{
			BatchChangeDelay:               sc.batchDelay,
			BatcherWorkers:                 sc.batcherWorkers,
			NodeMapSessionBufferedChanSize: sc.bufferedChanSize,
		},
	}

	app, err := hscontrol.NewHeadscale(&cfg)
	if err != nil {
		tb.Fatalf("servertest: NewHeadscale: %v", err)
	}

	// Set a minimal DERP map so MapResponse generation works.
	app.GetState().SetDERPMap(&tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			900: {
				RegionID:   900,
				RegionCode: "test",
				RegionName: "Test Region",
				Nodes: []*tailcfg.DERPNode{{
					Name:     "test0",
					RegionID: 900,
					HostName: "127.0.0.1",
					IPv4:     "127.0.0.1",
					DERPPort: -1, // not a real DERP, just needed for MapResponse
				}},
			},
		},
	})

	// Start subsystems.
	app.StartBatcherForTest(tb)
	app.StartEphemeralGCForTest(tb)

	// Start the HTTP server with Headscale's full handler (including
	// /key and /ts2021 Noise upgrade).
	ts := httptest.NewServer(app.HTTPHandler())
	tb.Cleanup(ts.Close)

	// Now update the config to point at the real URL so that
	// MapResponse.ControlURL etc. are correct.
	app.SetServerURLForTest(tb, ts.URL)

	return &TestServer{
		App:        app,
		HTTPServer: ts,
		URL:        ts.URL,
		st:         app.GetState(),
	}
}

// State returns the server's state manager for creating users,
// nodes, and pre-auth keys.
func (s *TestServer) State() *state.State {
	return s.st
}

// CreateUser creates a test user and returns it.
func (s *TestServer) CreateUser(tb testing.TB, name string) *types.User {
	tb.Helper()

	u, _, err := s.st.CreateUser(types.User{Name: name})
	if err != nil {
		tb.Fatalf("servertest: CreateUser(%q): %v", name, err)
	}

	return u
}

// CreatePreAuthKey creates a reusable pre-auth key for the given user.
func (s *TestServer) CreatePreAuthKey(tb testing.TB, userID types.UserID) string {
	tb.Helper()

	uid := userID

	pak, err := s.st.CreatePreAuthKey(&uid, true, false, nil, nil)
	if err != nil {
		tb.Fatalf("servertest: CreatePreAuthKey: %v", err)
	}

	return pak.Key
}

// CreateEphemeralPreAuthKey creates an ephemeral pre-auth key.
func (s *TestServer) CreateEphemeralPreAuthKey(tb testing.TB, userID types.UserID) string {
	tb.Helper()

	uid := userID

	pak, err := s.st.CreatePreAuthKey(&uid, false, true, nil, nil)
	if err != nil {
		tb.Fatalf("servertest: CreateEphemeralPreAuthKey: %v", err)
	}

	return pak.Key
}
