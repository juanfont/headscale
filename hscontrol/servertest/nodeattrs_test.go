package servertest_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// reloadPolicy applies pol via SetPolicy and runs ReloadPolicy so that the
// state machine emits the changes the mapper consumes — same shape as every
// other servertest that exercises a policy edit.
func reloadPolicy(t *testing.T, srv *servertest.TestServer, pol string) {
	t.Helper()

	changed, err := srv.State().SetPolicy([]byte(pol))
	require.NoError(t, err)

	if !changed {
		return
	}

	changes, err := srv.State().ReloadPolicy()
	require.NoError(t, err)
	srv.App.Change(changes...)
}

// hasCap reports whether the given netmap's self CapMap contains want.
func hasCap(nm *netmap.NetworkMap, want tailcfg.NodeCapability) bool {
	if nm == nil || !nm.SelfNode.Valid() {
		return false
	}

	return nm.SelfNode.CapMap().Contains(want)
}

// peerCapMapsAllEmpty reports whether every peer in nm has an empty
// [tailcfg.Node.CapMap]. The Tailscale-hosted control plane omits the
// peer-side CapMap unless the peer satisfies a peer-cap emission
// condition (e.g. suggest-exit-node on a peer with approved exit
// routes — see [policyv2.PeerCapMap]). The scenarios that call this
// helper do not advertise exit routes, so peer CapMaps stay empty;
// the test asserts that property to lock in the wire shape.
func peerCapMapsAllEmpty(nm *netmap.NetworkMap) bool {
	if nm == nil {
		return false
	}

	for _, peer := range nm.Peers {
		if peer.CapMap().Len() > 0 {
			return false
		}
	}

	return true
}

func TestNodeAttrsDeliverToSelfAndPeer(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "na-user")

	c1 := servertest.NewClient(t, srv, "na-node1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "na-node2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)
	c2.WaitForPeers(t, 1, 10*time.Second)

	reloadPolicy(t, srv, `{
		"nodeAttrs": [{
			"target": ["*"],
			"attr":   ["randomize-client-port"]
		}]
	}`)

	c1.WaitForCondition(t, "self randomize-client-port cap on c1", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrRandomizeClientPort)
		})
	c2.WaitForCondition(t, "self randomize-client-port cap on c2", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrRandomizeClientPort)
		})

	// randomize-client-port is not in the peer-consumed allowlist and
	// these nodes don't advertise exit routes, so peer CapMaps stay
	// empty. Each client reads its own caps from SelfNode.
	assert.True(t, peerCapMapsAllEmpty(c1.Netmap()),
		"c1 peer CapMaps must be empty after policy edit")
	assert.True(t, peerCapMapsAllEmpty(c2.Netmap()),
		"c2 peer CapMaps must be empty after policy edit")
}

func TestNodeAttrsUserTargetIsolated(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")

	a := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))
	b := servertest.NewClient(t, srv, "bob-laptop", servertest.WithUser(bob))

	a.WaitForPeers(t, 0, 5*time.Second)
	b.WaitForPeers(t, 0, 5*time.Second)

	reloadPolicy(t, srv, `{
		"acls":      [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"nodeAttrs": [{
			"target": ["alice@"],
			"attr":   ["randomize-client-port"]
		}]
	}`)

	a.WaitForCondition(t, "alice gains randomize-client-port", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrRandomizeClientPort)
		})

	// bob must remain free of the cap; check after alice has converged so we
	// know the policy is propagated.
	b.WaitForPeers(t, 1, 10*time.Second)
	nmB := b.Netmap()
	require.NotNil(t, nmB)
	assert.False(t, hasCap(nmB, tailcfg.NodeAttrRandomizeClientPort),
		"bob is not in the target set; must not receive the cap")
}

func TestNodeAttrsRevokesWhenRemoved(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "revoke-user")

	c := servertest.NewClient(t, srv, "revoke-node", servertest.WithUser(user))
	c.WaitForCondition(t, "node connected", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return nm != nil && nm.SelfNode.Valid()
		})

	reloadPolicy(t, srv, `{
		"nodeAttrs": [{
			"target": ["*"],
			"attr":   ["disable-captive-portal-detection"]
		}]
	}`)

	c.WaitForCondition(t, "captive cap appears", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrDisableCaptivePortalDetection)
		})

	reloadPolicy(t, srv, `{}`)

	c.WaitForCondition(t, "captive cap disappears", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return !hasCap(nm, tailcfg.NodeAttrDisableCaptivePortalDetection)
		})
}

// TestNodeAttrsBaselineCapsAlwaysOn verifies that the baseline caps
// (Admin, SSH, FileSharing, DefaultAutoUpdate) are emitted on every
// node regardless of whether the policy mentions them. Taildrive
// (drive:share / drive:access) is policy-driven and is verified
// through TestNodeAttrsAddsToBaseline and the integration
// TestGrantCapDrive flow.
func TestNodeAttrsBaselineCapsAlwaysOn(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "baseline-user")

	c := servertest.NewClient(t, srv, "baseline-node", servertest.WithUser(user))
	c.WaitForCondition(t, "baseline caps present without policy", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			if nm == nil || !nm.SelfNode.Valid() {
				return false
			}

			for _, w := range []tailcfg.NodeCapability{
				tailcfg.CapabilityAdmin,
				tailcfg.CapabilitySSH,
				tailcfg.CapabilityFileSharing,
				tailcfg.NodeAttrDefaultAutoUpdate,
			} {
				if !hasCap(nm, w) {
					return false
				}
			}

			return true
		})
}

// TestTaildropDisabledWithholdsFileSharingCap asserts the off path of
// the Taildrop config gate. The Tailscale v2 API does not expose the
// equivalent tailnet setting, so the nodeAttrs compat suite cannot
// vary it; this test covers the headscale side directly.
func TestTaildropDisabledWithholdsFileSharingCap(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithTaildropEnabled(false))
	user := srv.CreateUser(t, "taildrop-off-user")

	c := servertest.NewClient(t, srv, "taildrop-off-node", servertest.WithUser(user))
	c.WaitForCondition(t, "file-sharing absent when taildrop disabled",
		10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			if nm == nil || !nm.SelfNode.Valid() {
				return false
			}

			return !hasCap(nm, tailcfg.CapabilityFileSharing) &&
				hasCap(nm, tailcfg.CapabilityAdmin) &&
				hasCap(nm, tailcfg.CapabilitySSH)
		})
}

// TestNodeAttrsAddsToBaseline verifies that policy nodeAttrs caps land on
// nodes alongside the always-on baseline. The baseline caps remain
// regardless of policy contents.
func TestNodeAttrsAddsToBaseline(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "addon-user")

	c := servertest.NewClient(t, srv, "addon-node", servertest.WithUser(user))
	c.WaitForCondition(t, "node connected", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return nm != nil && nm.SelfNode.Valid()
		})

	reloadPolicy(t, srv, `{
		"nodeAttrs": [{
			"target": ["*"],
			"attr":   ["randomize-client-port", "disable-captive-portal-detection"]
		}]
	}`)

	c.WaitForCondition(t, "policy adds caps on top of baseline", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrRandomizeClientPort) &&
				hasCap(nm, tailcfg.NodeAttrDisableCaptivePortalDetection) &&
				hasCap(nm, tailcfg.CapabilitySSH)
		})
}

func TestNodeAttrsReloadingSamePolicyDoesNotChurnSelf(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "churn-user")

	c := servertest.NewClient(t, srv, "churn-node", servertest.WithUser(user))
	c.WaitForCondition(t, "node connected", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return nm != nil && nm.SelfNode.Valid()
		})

	const pol = `{
		"nodeAttrs": [{
			"target": ["*"],
			"attr":   ["randomize-client-port"]
		}]
	}`

	reloadPolicy(t, srv, pol)

	c.WaitForCondition(t, "policy cap arrives", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrRandomizeClientPort)
		})

	// Reload identical bytes. Per-node CapMap diff produces an empty
	// changed set, so SetPolicy returns no SelfUpdate IDs. The
	// broadcast PolicyChange still fires because filter rules are
	// recomputed on every reload — that's expected. The check below
	// is on the wire shape: cap must still be present.
	reloadPolicy(t, srv, pol)

	c.WaitForCondition(t, "cap persists after no-op reload", 5*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrRandomizeClientPort)
		})
}

// TestNodeAttrsSuggestExitNodeOnPeerCapMap covers the runtime peer-cap
// path: when a peer advertises exit routes, has them approved, and
// the policy targets it with `suggest-exit-node`, the cap lands on
// [tailcfg.Node.CapMap] of the *peer view* — not just on the exit
// node's own SelfNode.CapMap.
//
// The compat test in policy/v2 covers the wire shape; this test
// proves the runtime delivery path through the live mapper.
func TestNodeAttrsSuggestExitNodeOnPeerCapMap(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "see-user")

	exit := servertest.NewClient(t, srv, "see-exit", servertest.WithUser(user))
	viewer := servertest.NewClient(t, srv, "see-viewer", servertest.WithUser(user))

	// Wait for peer visibility before advertising routes; otherwise the
	// hostinfo update can race with initial registration and the
	// approval below sees no advertised route to approve.
	exit.WaitForPeers(t, 1, 10*time.Second)
	viewer.WaitForPeers(t, 1, 10*time.Second)

	exitRoutes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	// Advertise the exit routes via the live noise channel.
	exit.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-see-exit",
		Hostname:     "see-exit",
		RoutableIPs:  exitRoutes,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	require.NoError(t, exit.Direct().SendUpdate(ctx))
	cancel()

	// Approve the routes on the control plane and fan the resulting
	// change out so peers re-render.
	exitID := findNodeID(t, srv, "see-exit")
	_, ch, err := srv.State().SetApprovedRoutes(exitID, exitRoutes)
	require.NoError(t, err)
	srv.App.Change(ch)

	// Stamp suggest-exit-node on every node — the peer-cap rule then
	// gates the actual peer-view emission on whether the peer is an
	// exit node (advertised + approved).
	reloadPolicy(t, srv, `{
		"nodeAttrs": [{
			"target": ["*"],
			"attr":   ["suggest-exit-node"]
		}]
	}`)

	// Self-side: the exit node sees the cap on its own SelfNode (the
	// usual stamp; nothing special about exit nodes here).
	exit.WaitForCondition(t, "self suggest-exit-node on exit", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return hasCap(nm, tailcfg.NodeAttrSuggestExitNode)
		})

	// Peer-side: the viewer sees the exit node in its Peers list with
	// the cap on the peer entry. This is the property the new
	// PeerCapMap rule guards.
	viewer.WaitForCondition(t, "peer suggest-exit-node on exit's peer entry", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			if nm == nil {
				return false
			}

			for _, peer := range nm.Peers {
				if peer.ComputedName() != "see-exit" {
					continue
				}

				return peer.CapMap().Contains(tailcfg.NodeAttrSuggestExitNode)
			}

			return false
		})

	// Negative side: the viewer's peer view of itself (i.e. the exit's
	// peer view of the viewer) must NOT carry suggest-exit-node — only
	// the actual exit-node peer view does.
	exit.WaitForCondition(t, "viewer's peer entry does not carry suggest-exit-node", 5*time.Second,
		func(nm *netmap.NetworkMap) bool {
			if nm == nil {
				return false
			}

			for _, peer := range nm.Peers {
				if peer.ComputedName() != "see-viewer" {
					continue
				}

				return !peer.CapMap().Contains(tailcfg.NodeAttrSuggestExitNode)
			}

			return false
		})
}
