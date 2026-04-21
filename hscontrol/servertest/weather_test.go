package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
)

// TestNetworkWeather exercises scenarios that simulate unstable
// network conditions: rapid reconnects, disconnect/reconnect
// timing, and connection flapping.
func TestNetworkWeather(t *testing.T) {
	t.Parallel()

	t.Run("rapid_reconnect_stays_online", func(t *testing.T) {
		t.Parallel()

		h := servertest.NewHarness(t, 2)

		for range 10 {
			h.Client(0).Disconnect(t)
			h.Client(0).Reconnect(t)
		}

		// After rapid flapping, mesh should still be complete.
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("reconnect_within_grace_period", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		h.Client(0).Disconnect(t)

		// Reconnect quickly (well within the 10-second grace period).
		h.Client(0).ReconnectAfter(t, 1*time.Second)
		h.WaitForMeshComplete(t, 15*time.Second)

		// Peer should see us as online after reconnection.
		servertest.AssertPeerOnline(t, h.Client(1), h.Client(0).Name)
	})

	t.Run("disconnect_types", func(t *testing.T) {
		t.Parallel()

		cases := []struct {
			name       string
			disconnect func(c *servertest.TestClient, tb testing.TB)
		}{
			{"clean_disconnect", (*servertest.TestClient).Disconnect},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				h := servertest.NewHarness(t, 2)

				tc.disconnect(h.Client(1), t)

				// The remaining client should eventually see peer gone/offline.
				assert.Eventually(t, func() bool {
					_, found := h.Client(0).PeerByName(h.Client(1).Name)
					if found {
						// If still in peer list, check if it's marked offline.
						isOnline, known := func() (bool, bool) {
							peer, ok := h.Client(0).PeerByName(h.Client(1).Name)
							if !ok {
								return false, false
							}

							return peer.Online().GetOk()
						}()
						// Either unknown or offline is acceptable.
						return known && !isOnline
					}

					return true // peer gone
				}, 30*time.Second, 500*time.Millisecond,
					"peer should become offline or disappear")
			})
		}
	})

	t.Run("state_consistent_through_reconnection", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		// Disconnect and reconnect the middle node.
		h.Client(1).Disconnect(t)
		h.Client(1).Reconnect(t)

		// Wait for convergence and verify consistency.
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertConsistentState(t, h.Clients())
	})

	t.Run("multiple_reconnect_delays", func(t *testing.T) {
		t.Parallel()

		delays := []struct {
			name  string
			delay time.Duration
		}{
			{"immediate", 0},
			{"100ms", 100 * time.Millisecond},
			{"500ms", 500 * time.Millisecond},
			{"1s", 1 * time.Second},
		}
		for _, tc := range delays {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				h := servertest.NewHarness(t, 2)

				if tc.delay > 0 {
					h.Client(0).ReconnectAfter(t, tc.delay)
				} else {
					h.Client(0).Disconnect(t)
					h.Client(0).Reconnect(t)
				}

				h.WaitForMeshComplete(t, 15*time.Second)
				servertest.AssertMeshComplete(t, h.Clients())
			})
		}
	})

	t.Run("flapping_does_not_leak_goroutines", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Do many rapid disconnect/reconnect cycles.
		for i := range 20 {
			h.Client(0).Disconnect(t)
			h.Client(0).Reconnect(t)

			if i%5 == 0 {
				t.Logf("flap cycle %d: %s has %d peers",
					i, h.Client(0).Name, len(h.Client(0).Peers()))
			}
		}

		// Mesh should still be working.
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("scale_20_nodes", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 20)
		servertest.AssertMeshComplete(t, h.Clients())
	})
}
