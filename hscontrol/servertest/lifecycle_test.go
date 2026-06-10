package servertest_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// TestConnectionLifecycle exercises the core node lifecycle:
// connecting, seeing peers, joining mid-session, departing, and
// reconnecting.
func TestConnectionLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("single_node", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 1)
		nm := h.Client(0).Netmap()
		assert.NotNil(t, nm, "single node should receive a netmap")
		assert.Empty(t, nm.Peers, "single node should have no peers")
	})

	t.Run("new_node_joins_mesh", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		// Add a 4th client mid-test.
		h.AddClient(t)
		h.WaitForMeshComplete(t, 10*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
		servertest.AssertSymmetricVisibility(t, h.Clients())
	})

	t.Run("node_departs_peer_goes_offline", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		departingName := h.Client(2).Name

		// First verify the departing node is online (may need a moment
		// for Online status to propagate after mesh formation).
		h.Client(0).WaitForCondition(t, "peer initially online", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == departingName {
						isOnline, known := p.Online().GetOk()

						return known && isOnline
					}
				}

				return false
			})

		h.Client(2).Disconnect(t)

		// After the 10-second grace period, the remaining clients
		// should see the departed node as offline. The peer stays
		// in the peer list (non-ephemeral nodes are not removed).
		h.Client(0).WaitForCondition(t, "peer goes offline", 30*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == departingName {
						isOnline, known := p.Online().GetOk()

						return known && !isOnline
					}
				}

				return false
			})
	})

	t.Run("reconnect_restores_mesh", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Disconnect and reconnect.
		h.Client(0).Disconnect(t)
		h.Client(0).Reconnect(t)

		// Mesh should recover.
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("session_replacement", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Reconnect without explicitly waiting for the old session to
		// fully drain. This tests that Headscale correctly replaces
		// the old map session for the same node.
		h.Client(0).Reconnect(t)
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("multiple_nodes_join_sequentially", func(t *testing.T) {
		t.Parallel()

		sizes := []int{2, 5, 10}
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%d_nodes", n), func(t *testing.T) {
				t.Parallel()
				h := servertest.NewHarness(t, n)
				servertest.AssertMeshComplete(t, h.Clients())
				servertest.AssertSymmetricVisibility(t, h.Clients())
			})
		}
	})
}

// TestLogoutReloginAllClientsConverge is an in-process reproduction of the
// flaky integration tests TestAuthKeyLogoutAndReloginSameUser,
// TestAuthWebFlowLogoutAndReloginSameUser and
// TestAuthWebFlowLogoutAndReloginNewUser: a full mesh of clients logs out,
// the server marks every node expired and offline, then all clients log
// back in near-simultaneously with fresh NodeKeys. In the flake, a subset
// of clients never converges — their netmaps stay empty through the whole
// retry window even though the server believes everything is connected.
//
// Each client here is a real [controlclient.Direct], so the client-side
// netmap assembly semantics (full peer list vs. delta, patch handling for
// unknown peers) match the real Tailscale client.
func TestLogoutReloginAllClientsConverge(t *testing.T) {
	if testing.Short() {
		t.Skip("relogin convergence test includes 10s+ disconnect grace per iteration")
	}

	const (
		numClients = 12
		iterations = 4
		// Maximum random delay between the relogins of different
		// clients, so registrations and fresh map streams interleave
		// the way concurrent `tailscale up` invocations do.
		reloginStagger = 500 * time.Millisecond
	)

	// Production tuning: the integration flake happens with the default
	// 800ms batch delay (large coalescing windows) and a multi-worker
	// batcher, so reproduce with the same knobs.
	h := servertest.NewHarness(t, numClients,
		servertest.WithServerOptions(
			servertest.WithBatchDelay(800*time.Millisecond),
			servertest.WithBatcherWorkers(types.DefaultBatcherWorkers()),
		),
		servertest.WithConvergenceTimeout(60*time.Second),
	)

	for iteration := range iterations {
		t.Logf("iteration %d: logging out all clients", iteration)
		logoutAllAndWaitOffline(t, h)

		t.Logf("iteration %d: relogging in all clients", iteration)

		clients := h.Clients()
		errs := make(chan error, len(clients))

		for _, c := range clients {
			go func() {
				time.Sleep(rand.N(reloginStagger)) //nolint:forbidigo,gosec // intentional jitter so relogins interleave; weak random is fine

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				errs <- c.ReloginAndPoll(ctx)
			}()
		}

		for range clients {
			require.NoError(t, <-errs)
		}

		// Every client must converge to the full mesh. A stuck client —
		// the flake — sits at zero peers and fails here.
		deadline := time.Now().Add(30 * time.Second)
		for _, c := range clients {
			waitForMeshOrDump(t, clients, c, numClients-1, time.Until(deadline))
		}
	}
}

// TestLogoutReloginWithPollChurn is the same logout/relogin storm as
// [TestLogoutReloginAllClientsConverge], but each client also restarts its
// map poll once or twice shortly after logging back in — without
// re-registering — the way newer tailscaled versions cycle their map
// session around login state transitions. The integration flake hits the
// head and unstable clients, which churn their sessions far more than
// older releases, so the rapid session replacement is the prime suspect.
func TestLogoutReloginWithPollChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("relogin convergence test includes 10s+ disconnect grace per iteration")
	}

	const (
		numClients     = 12
		iterations     = 4
		reloginStagger = 500 * time.Millisecond
	)

	h := servertest.NewHarness(t, numClients,
		servertest.WithServerOptions(
			servertest.WithBatchDelay(800*time.Millisecond),
			servertest.WithBatcherWorkers(types.DefaultBatcherWorkers()),
		),
		servertest.WithConvergenceTimeout(60*time.Second),
	)

	for iteration := range iterations {
		t.Logf("iteration %d: logging out all clients", iteration)
		logoutAllAndWaitOffline(t, h)

		t.Logf("iteration %d: relogging in all clients with poll churn", iteration)

		clients := h.Clients()
		errs := make(chan error, len(clients))

		for _, c := range clients {
			go func() {
				time.Sleep(rand.N(reloginStagger)) //nolint:forbidigo,gosec // intentional jitter so relogins interleave; weak random is fine

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				err := c.ReloginAndPoll(ctx)
				if err != nil {
					errs <- err
					return
				}

				// Churn the map session like a freshly logged-in
				// tailscaled: restart the poll once or twice with
				// small random gaps.
				for range 1 + rand.IntN(2) { //nolint:gosec // weak random is fine for test jitter
					time.Sleep(rand.N(400 * time.Millisecond)) //nolint:forbidigo,gosec // intentional jitter between poll restarts; weak random is fine

					err = c.RestartPoll(ctx)
					if err != nil {
						errs <- err
						return
					}
				}

				errs <- nil
			}()
		}

		for range clients {
			require.NoError(t, <-errs)
		}

		deadline := time.Now().Add(30 * time.Second)
		for _, c := range clients {
			waitForMeshOrDump(t, clients, c, numClients-1, time.Until(deadline))
		}
	}
}

// logoutAllAndWaitOffline logs every client out concurrently, then blocks
// until the server reports each node expired and offline — the integration
// tests' logout barrier, including the ~10s disconnect grace period.
func logoutAllAndWaitOffline(t *testing.T, h *servertest.TestHarness) {
	t.Helper()

	clients := h.Clients()
	errs := make(chan error, len(clients))

	for _, c := range clients {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			errs <- c.LogoutAndDisconnect(ctx)
		}()
	}

	for range clients {
		require.NoError(t, <-errs)
	}

	st := h.Server.State()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, node := range st.ListNodes().All() {
			assert.True(c, node.IsExpired(), "node %d should be expired after logout", node.ID())
			online := node.IsOnline()
			assert.True(c, online.Valid() && !online.Get(), "node %d should be offline after logout", node.ID())
		}
	}, 30*time.Second, 100*time.Millisecond, "all nodes expired and offline after logout")
}

// waitForMeshOrDump waits until client c reports at least wantPeers peers.
// On timeout it dumps every client's view of the mesh before failing, so a
// reproduced flake shows exactly which clients are stuck and what they see.
func waitForMeshOrDump(t *testing.T, all []*servertest.TestClient, c *servertest.TestClient, wantPeers int, timeout time.Duration) {
	t.Helper()

	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)

	defer ticker.Stop()

	for {
		if nm := c.Netmap(); nm != nil && len(nm.Peers) >= wantPeers {
			return
		}

		select {
		case <-ticker.C:
		case <-deadline:
			for _, other := range all {
				t.Logf("client %s netmap: %s", other.Name, describeNetmap(other))
			}

			nm := c.Netmap()

			got := 0
			if nm != nil {
				got = len(nm.Peers)
			}

			t.Fatalf("client %s did not converge: want %d peers, got %d", c.Name, wantPeers, got)
		}
	}
}

// describeNetmap renders a client's current netmap as a compact string for
// failure dumps: peer names with their expiry/online flags.
func describeNetmap(c *servertest.TestClient) string {
	nm := c.Netmap()
	if nm == nil {
		return "<nil>"
	}

	var out strings.Builder

	fmt.Fprintf(&out, "%d peers:", len(nm.Peers))

	for _, p := range nm.Peers {
		hostname := "<no hostinfo>"
		if hi := p.Hostinfo(); hi.Valid() {
			hostname = hi.Hostname()
		}

		fmt.Fprintf(&out, " %s(id=%d expired=%t online=%v)", hostname, p.ID(), p.KeyExpiry().Before(time.Now()), p.Online())
	}

	return out.String()
}
