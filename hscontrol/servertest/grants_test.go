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
	"tailscale.com/wgengine/filter/filtertype"
)

// TestGrantPolicies verifies that grant-based policies propagate
// correctly through the full control plane (policy -> state -> mapper)
// and produce the expected packet filter rules in client netmaps.
func TestGrantPolicies(t *testing.T) { //nolint:gocyclo
	t.Parallel()

	t.Run("grant_only_policy", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "grant-user")

		c1 := servertest.NewClient(t, srv, "grant-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "grant-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Record update counts before policy change.
		countC1 := c1.UpdateCount()
		countC2 := c2.UpdateCount()

		// Set a grant-only policy with no ACLs.
		changed, err := srv.State().SetPolicy([]byte(`{
			"grants": [{
				"src": ["*"],
				"dst": ["*"],
				"ip": ["*"]
			}]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		// Wait for both clients to receive an update after the policy change.
		c1.WaitForCondition(t, "update after grant-only policy",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c1.UpdateCount() > countC1
			})
		c2.WaitForCondition(t, "update after grant-only policy",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c2.UpdateCount() > countC2
			})

		// Verify PacketFilter is populated with real rules from the grant.
		nm1 := c1.Netmap()
		require.NotNil(t, nm1)
		assert.NotNil(t, nm1.PacketFilter,
			"c1 PacketFilter should not be nil after grant-only policy")
		assert.NotEmpty(t, nm1.PacketFilter,
			"c1 PacketFilter should have rules from grant-only policy")

		nm2 := c2.Netmap()
		require.NotNil(t, nm2)
		assert.NotNil(t, nm2.PacketFilter,
			"c2 PacketFilter should not be nil after grant-only policy")
		assert.NotEmpty(t, nm2.PacketFilter,
			"c2 PacketFilter should have rules from grant-only policy")

		// Verify both clients still see each other as peers.
		assert.Len(t, nm1.Peers, 1,
			"c1 should still see 1 peer after grant-only policy")
		assert.Len(t, nm2.Peers, 1,
			"c2 should still see 1 peer after grant-only policy")
	})

	t.Run("grant_cap_compilation", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "cap-user")

		c1 := servertest.NewClient(t, srv, "cap-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "cap-node2",
			servertest.WithUser(user))

		// Wait for mesh to form with default allow-all policy.
		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		countC1 := c1.UpdateCount()

		// Set policy with both IP connectivity and cap/drive + cap/relay grants.
		// IP grant is required for peer visibility; cap grant adds capabilities.
		changed, err := srv.State().SetPolicy([]byte(`{
			"grants": [
				{
					"src": ["cap-user@"],
					"dst": ["cap-user@"],
					"ip": ["*"]
				},
				{
					"src": ["cap-user@"],
					"dst": ["cap-user@"],
					"app": {
						"tailscale.com/cap/drive": [{}],
						"tailscale.com/cap/relay": [{}]
					}
				}
			]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		// Wait for PacketFilter with cap match rules to arrive.
		c1.WaitForCondition(t, "packet filter with cap grants",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c1.UpdateCount() > countC1 &&
					hasCapMatches(nm.PacketFilter)
			})

		nm1 := c1.Netmap()
		require.NotNil(t, nm1)

		// Check that the packet filter has CapMatch entries.
		// The main grant produces cap/drive and cap/relay.
		// Companion caps (drive-sharer and relay-target) are
		// generated with reversed direction.
		var (
			foundDrive       bool
			foundDriveSharer bool
			foundRelay       bool
			foundRelayTarget bool
		)

		for _, m := range nm1.PacketFilter {
			for _, cm := range m.Caps {
				switch cm.Cap { //nolint:exhaustive // only checking grant-specific caps
				case tailcfg.PeerCapabilityTaildrive:
					foundDrive = true
				case tailcfg.PeerCapabilityTaildriveSharer:
					foundDriveSharer = true
				case tailcfg.PeerCapabilityRelay:
					foundRelay = true
				case tailcfg.PeerCapabilityRelayTarget:
					foundRelayTarget = true
				}
			}
		}

		assert.True(t, foundDrive || foundDriveSharer,
			"packet filter should contain cap/drive or cap/drive-sharer")
		assert.True(t, foundRelay || foundRelayTarget,
			"packet filter should contain cap/relay or cap/relay-target")

		// Verify c2 also has cap grants. Wait for c2 to receive
		// the policy update with cap matches.
		c2.WaitForCondition(t, "c2 packet filter with cap grants",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return hasCapMatches(nm.PacketFilter)
			})

		nm2 := c2.Netmap()
		require.NotNil(t, nm2)
		assert.True(t, hasCapMatches(nm2.PacketFilter),
			"c2 should also have cap match rules in PacketFilter")
	})

	t.Run("grant_policy_update_propagation", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "propagation-user")

		c1 := servertest.NewClient(t, srv, "prop-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "prop-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Phase 1: Set a grant policy allowing only TCP port 22.
		countC1 := c1.UpdateCount()
		countC2 := c2.UpdateCount()

		changed, err := srv.State().SetPolicy([]byte(`{
			"grants": [{
				"src": ["propagation-user@"],
				"dst": ["propagation-user@"],
				"ip": ["tcp:22"]
			}]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		c1.WaitForCondition(t, "first grant policy update",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c1.UpdateCount() > countC1
			})
		c2.WaitForCondition(t, "first grant policy update",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c2.UpdateCount() > countC2
			})

		// Capture the update count after first policy.
		nm1Before := c1.Netmap()
		require.NotNil(t, nm1Before)
		require.NotEmpty(t, nm1Before.PacketFilter,
			"PacketFilter should have rules from first grant policy")

		updateCountPhase1 := c1.UpdateCount()

		// Phase 2: Change to a grant policy with app capability
		// (structurally different from IP-only grant).
		changed, err = srv.State().SetPolicy([]byte(`{
			"grants": [
				{
					"src": ["propagation-user@"],
					"dst": ["propagation-user@"],
					"ip": ["*"]
				},
				{
					"src": ["propagation-user@"],
					"dst": ["propagation-user@"],
					"app": {
						"tailscale.com/cap/drive": [{}]
					}
				}
			]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		// Wait for the second policy update to arrive.
		c1.WaitForCondition(t, "second grant policy update",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c1.UpdateCount() > updateCountPhase1
			})
		c2.WaitForCondition(t, "second grant policy update",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return c2.UpdateCount() > countC2
			})

		// Verify the second policy added cap grants that weren't
		// in the first (IP-only) policy.
		nm1After := c1.Netmap()
		require.NotNil(t, nm1After)
		require.NotEmpty(t, nm1After.PacketFilter,
			"PacketFilter should have rules from second grant policy")

		hadCapsBefore := hasCapMatches(nm1Before.PacketFilter)
		hasCapsAfter := hasCapMatches(nm1After.PacketFilter)

		assert.False(t, hadCapsBefore,
			"first policy (IP-only) should not have cap matches")
		assert.True(t, hasCapsAfter,
			"second policy (with app grant) should have cap matches")
	})

	t.Run("grant_per_user_isolation", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user1 := srv.CreateUser(t, "iso-user1")
		user2 := srv.CreateUser(t, "iso-user2")

		// Create all nodes first with default allow-all policy.
		u1n1 := servertest.NewClient(t, srv, "u1n1",
			servertest.WithUser(user1))
		u1n2 := servertest.NewClient(t, srv, "u1n2",
			servertest.WithUser(user1))
		u2n1 := servertest.NewClient(t, srv, "u2n1",
			servertest.WithUser(user2))
		u2n2 := servertest.NewClient(t, srv, "u2n2",
			servertest.WithUser(user2))

		// Wait for full mesh with default allow-all.
		u1n1.WaitForPeers(t, 3, 15*time.Second)
		u2n1.WaitForPeers(t, 3, 15*time.Second)

		// Apply per-user grants: user1 can only reach user1,
		// user2 can only reach user2.
		changed, err := srv.State().SetPolicy([]byte(`{
			"grants": [
				{
					"src": ["iso-user1@"],
					"dst": ["iso-user1@"],
					"ip": ["*"]
				},
				{
					"src": ["iso-user2@"],
					"dst": ["iso-user2@"],
					"ip": ["*"]
				}
			]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		// Wait for policy to take effect. Each node should only
		// see the other node from the same user (1 peer each).
		u1n1.WaitForPeerCount(t, 1, 15*time.Second)
		u1n2.WaitForPeerCount(t, 1, 15*time.Second)
		u2n1.WaitForPeerCount(t, 1, 15*time.Second)
		u2n2.WaitForPeerCount(t, 1, 15*time.Second)

		// Verify user1's nodes see each other.
		_, u1n1SeesU1n2 := u1n1.PeerByName("u1n2")
		assert.True(t, u1n1SeesU1n2,
			"u1n1 should see u1n2 (same user)")

		_, u1n2SeesU1n1 := u1n2.PeerByName("u1n1")
		assert.True(t, u1n2SeesU1n1,
			"u1n2 should see u1n1 (same user)")

		// Verify user2's nodes see each other.
		_, u2n1SeesU2n2 := u2n1.PeerByName("u2n2")
		assert.True(t, u2n1SeesU2n2,
			"u2n1 should see u2n2 (same user)")

		_, u2n2SeesU2n1 := u2n2.PeerByName("u2n1")
		assert.True(t, u2n2SeesU2n1,
			"u2n2 should see u2n1 (same user)")

		// Verify cross-user isolation: user1 nodes should NOT
		// see user2 nodes.
		_, u1n1SeesU2n1 := u1n1.PeerByName("u2n1")
		assert.False(t, u1n1SeesU2n1,
			"u1n1 should not see u2n1 (different user)")

		_, u1n1SeesU2n2 := u1n1.PeerByName("u2n2")
		assert.False(t, u1n1SeesU2n2,
			"u1n1 should not see u2n2 (different user)")

		_, u2n1SeesU1n1 := u2n1.PeerByName("u1n1")
		assert.False(t, u2n1SeesU1n1,
			"u2n1 should not see u1n1 (different user)")

		_, u2n1SeesU1n2 := u2n1.PeerByName("u1n2")
		assert.False(t, u2n1SeesU1n2,
			"u2n1 should not see u1n2 (different user)")

		// Verify packet filters exist for each user.
		nm1 := u1n1.Netmap()
		require.NotNil(t, nm1)
		assert.NotNil(t, nm1.PacketFilter,
			"u1n1 should have PacketFilter rules from per-user grant")
		assert.NotEmpty(t, nm1.PacketFilter,
			"u1n1 PacketFilter should not be empty")

		nm2 := u2n1.Netmap()
		require.NotNil(t, nm2)
		assert.NotNil(t, nm2.PacketFilter,
			"u2n1 should have PacketFilter rules from per-user grant")
		assert.NotEmpty(t, nm2.PacketFilter,
			"u2n1 PacketFilter should not be empty")
	})

	t.Run("mixed_grants_and_acls", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		user := srv.CreateUser(t, "mixed-user")

		// Set policy with both ACLs and grants.
		changed, err := srv.State().SetPolicy([]byte(`{
			"acls": [
				{"action": "accept", "src": ["mixed-user@"], "dst": ["mixed-user@:22"]}
			],
			"grants": [{
				"src": ["mixed-user@"],
				"dst": ["mixed-user@"],
				"app": {
					"tailscale.com/cap/drive": [{}]
				}
			}]
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		c1 := servertest.NewClient(t, srv, "mixed-node1",
			servertest.WithUser(user))
		c2 := servertest.NewClient(t, srv, "mixed-node2",
			servertest.WithUser(user))

		c1.WaitForPeers(t, 1, 10*time.Second)
		c2.WaitForPeers(t, 1, 10*time.Second)

		// Wait for the packet filter to contain both Dsts (from ACL)
		// and Caps (from grant) rules.
		c1.WaitForCondition(t, "packet filter with mixed ACL and grant rules",
			10*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return hasDstRules(nm.PacketFilter) &&
					hasCapMatches(nm.PacketFilter)
			})

		nm1 := c1.Netmap()
		require.NotNil(t, nm1)

		// Verify Dsts rules are present (from the ACL for port 22).
		var foundPort22 bool

		for _, m := range nm1.PacketFilter {
			for _, dst := range m.Dsts {
				if dst.Ports.First == 22 && dst.Ports.Last == 22 {
					foundPort22 = true
				}
			}
		}

		assert.True(t, foundPort22,
			"PacketFilter should contain Dsts rule for port 22 from ACL")

		// Verify CapMatch rules are present (from the grant for cap/drive).
		var foundDriveOrSharer bool

		for _, m := range nm1.PacketFilter {
			for _, cm := range m.Caps {
				if cm.Cap == tailcfg.PeerCapabilityTaildrive ||
					cm.Cap == tailcfg.PeerCapabilityTaildriveSharer {
					foundDriveOrSharer = true
				}
			}
		}

		assert.True(t, foundDriveOrSharer,
			"PacketFilter should contain CapMatch with cap/drive or cap/drive-sharer from grant")

		// Verify c2 also has both kinds of rules.
		nm2 := c2.Netmap()
		require.NotNil(t, nm2)
		assert.True(t, hasDstRules(nm2.PacketFilter),
			"c2 should have Dsts rules from ACL")
		assert.True(t, hasCapMatches(nm2.PacketFilter),
			"c2 should have CapMatch rules from grant")
	})

	t.Run("grant_via_subnet_steering", func(t *testing.T) {
		t.Parallel()

		srv := servertest.NewServer(t)
		routerUser := srv.CreateUser(t, "router-user")
		clientUser := srv.CreateUser(t, "client-user")

		route := netip.MustParsePrefix("10.0.0.0/24")

		// Set policy with via grants steering different client groups
		// to different routers for the same subnet.
		changed, err := srv.State().SetPolicy([]byte(`{
			"tagOwners": {
				"tag:router-a": ["router-user@"],
				"tag:router-b": ["router-user@"],
				"tag:group-a":  ["client-user@"],
				"tag:group-b":  ["client-user@"]
			},
			"grants": [
				{
					"src": ["tag:router-a", "tag:router-b", "tag:group-a", "tag:group-b"],
					"dst": ["tag:router-a", "tag:router-b", "tag:group-a", "tag:group-b"],
					"ip": ["*"]
				},
				{
					"src": ["tag:group-a"],
					"dst": ["10.0.0.0/24"],
					"ip": ["*"],
					"via": ["tag:router-a"]
				},
				{
					"src": ["tag:group-b"],
					"dst": ["10.0.0.0/24"],
					"ip": ["*"],
					"via": ["tag:router-b"]
				}
			],
			"autoApprovers": {
				"routes": {
					"10.0.0.0/24": ["tag:router-a", "tag:router-b"]
				}
			}
		}`))
		require.NoError(t, err)

		if changed {
			changes, err := srv.State().ReloadPolicy()
			require.NoError(t, err)
			srv.App.Change(changes...)
		}

		// Create routers and clients with tags.
		routerA := servertest.NewClient(t, srv, "router-a",
			servertest.WithUser(routerUser),
			servertest.WithTags("tag:router-a"))
		routerB := servertest.NewClient(t, srv, "router-b",
			servertest.WithUser(routerUser),
			servertest.WithTags("tag:router-b"))
		clientA := servertest.NewClient(t, srv, "client-a",
			servertest.WithUser(clientUser),
			servertest.WithTags("tag:group-a"))
		clientB := servertest.NewClient(t, srv, "client-b",
			servertest.WithUser(clientUser),
			servertest.WithTags("tag:group-b"))

		// Wait for all nodes to see each other.
		routerA.WaitForPeers(t, 3, 15*time.Second)
		routerB.WaitForPeers(t, 3, 15*time.Second)
		clientA.WaitForPeers(t, 3, 15*time.Second)
		clientB.WaitForPeers(t, 3, 15*time.Second)

		// Advertise route from both routers.
		routerA.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-router-a",
			Hostname:     "router-a",
			RoutableIPs:  []netip.Prefix{route},
		})

		ctxA, cancelA := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelA()

		_ = routerA.Direct().SendUpdate(ctxA)

		routerB.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-router-b",
			Hostname:     "router-b",
			RoutableIPs:  []netip.Prefix{route},
		})

		ctxB, cancelB := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelB()

		_ = routerB.Direct().SendUpdate(ctxB)

		// Approve routes on both routers.
		routerAID := findNodeID(t, srv, "router-a")
		_, routeChangeA, err := srv.State().SetApprovedRoutes(
			routerAID, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChangeA)

		routerBID := findNodeID(t, srv, "router-b")
		_, routeChangeB, err := srv.State().SetApprovedRoutes(
			routerBID, []netip.Prefix{route})
		require.NoError(t, err)
		srv.App.Change(routeChangeB)

		// clientA should see routerA with the route in AllowedIPs.
		clientA.WaitForCondition(t, "clientA sees route via router-a",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "router-a" {
						for i := range p.AllowedIPs().Len() {
							if p.AllowedIPs().At(i) == route {
								return true
							}
						}
					}
				}

				return false
			})

		// clientA should NOT see routerB with the route in AllowedIPs.
		nmA := clientA.Netmap()
		require.NotNil(t, nmA)

		for _, p := range nmA.Peers {
			hi := p.Hostinfo()
			if hi.Valid() && hi.Hostname() == "router-b" {
				for i := range p.AllowedIPs().Len() {
					assert.NotEqual(t, route, p.AllowedIPs().At(i),
						"clientA should NOT see 10.0.0.0/24 via router-b")
				}
			}
		}

		// clientB should see routerB with the route in AllowedIPs.
		clientB.WaitForCondition(t, "clientB sees route via router-b",
			15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == "router-b" {
						for i := range p.AllowedIPs().Len() {
							if p.AllowedIPs().At(i) == route {
								return true
							}
						}
					}
				}

				return false
			})

		// clientB should NOT see routerA with the route in AllowedIPs.
		nmB := clientB.Netmap()
		require.NotNil(t, nmB)

		for _, p := range nmB.Peers {
			hi := p.Hostinfo()
			if hi.Valid() && hi.Hostname() == "router-a" {
				for i := range p.AllowedIPs().Len() {
					assert.NotEqual(t, route, p.AllowedIPs().At(i),
						"clientB should NOT see 10.0.0.0/24 via router-a")
				}
			}
		}
	})
}

// TestGrantViaSubnetFilterRules verifies that routers with via grants
// receive PacketFilter rules that allow the steered subnet traffic.
// This is a regression test: without per-node filter compilation for
// via grants, the router's PacketFilter would lack rules for the
// via-steered subnet destinations, causing traffic to be dropped.
func TestGrantViaSubnetFilterRules(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	routerUser := srv.CreateUser(t, "rt-user")
	clientUser := srv.CreateUser(t, "cl-user")

	route := netip.MustParsePrefix("10.0.0.0/24")

	changed, err := srv.State().SetPolicy([]byte(`{
		"tagOwners": {
			"tag:router-a": ["rt-user@"],
			"tag:group-a":  ["cl-user@"]
		},
		"grants": [
			{
				"src": ["tag:router-a", "tag:group-a"],
				"dst": ["tag:router-a", "tag:group-a"],
				"ip": ["*"]
			},
			{
				"src": ["tag:group-a"],
				"dst": ["10.0.0.0/24"],
				"ip": ["*"],
				"via": ["tag:router-a"]
			}
		],
		"autoApprovers": {
			"routes": {
				"10.0.0.0/24": ["tag:router-a"]
			}
		}
	}`))
	require.NoError(t, err)

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	routerA := servertest.NewClient(t, srv, "router-a",
		servertest.WithUser(routerUser),
		servertest.WithTags("tag:router-a"))
	clientA := servertest.NewClient(t, srv, "client-a",
		servertest.WithUser(clientUser),
		servertest.WithTags("tag:group-a"))

	routerA.WaitForPeers(t, 1, 15*time.Second)
	clientA.WaitForPeers(t, 1, 15*time.Second)

	// Advertise and approve route on router.
	routerA.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-router-a",
		Hostname:     "router-a",
		RoutableIPs:  []netip.Prefix{route},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = routerA.Direct().SendUpdate(ctx)

	routerAID := findNodeID(t, srv, "router-a")
	_, routeChange, err := srv.State().SetApprovedRoutes(
		routerAID, []netip.Prefix{route})
	require.NoError(t, err)
	srv.App.Change(routeChange)

	// Wait for clientA to see the route in AllowedIPs.
	clientA.WaitForCondition(t, "clientA sees route via router-a",
		15*time.Second,
		func(nm *netmap.NetworkMap) bool {
			for _, p := range nm.Peers {
				hi := p.Hostinfo()
				if hi.Valid() && hi.Hostname() == "router-a" {
					for i := range p.AllowedIPs().Len() {
						if p.AllowedIPs().At(i) == route {
							return true
						}
					}
				}
			}

			return false
		})

	// Critical: the router's PacketFilter MUST contain rules with
	// the via-steered subnet (10.0.0.0/24) as a destination.
	// Without this, the router drops traffic forwarded through it.
	routerNM := routerA.Netmap()
	require.NotNil(t, routerNM)
	require.NotNil(t, routerNM.PacketFilter,
		"router PacketFilter should not be nil")

	var foundSubnetDst bool

	for _, m := range routerNM.PacketFilter {
		for _, dst := range m.Dsts {
			dstPrefix := netip.PrefixFrom(dst.Net.Addr(), dst.Net.Bits())
			if route.Contains(dstPrefix.Addr()) && dstPrefix.Bits() >= route.Bits() {
				foundSubnetDst = true
			}
		}
	}

	assert.True(t, foundSubnetDst,
		"router PacketFilter should contain destination rules for via-steered subnet 10.0.0.0/24; "+
			"without per-node filter compilation for via grants, these rules are missing")
}

// TestGrantViaExitNodeNoFilterRules verifies that exit nodes with via grants
// for autogroup:internet do NOT receive PacketFilter rules for exit traffic.
// Tailscale SaaS handles exit traffic forwarding through the client's exit
// node selection mechanism, not through PacketFilter rules. Verified by
// golden captures GRANT-V14 through GRANT-V36.
func TestGrantViaExitNodeNoFilterRules(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	exitUser := srv.CreateUser(t, "exit-user")
	clientUser := srv.CreateUser(t, "cl-user")

	exitRouteV4 := netip.MustParsePrefix("0.0.0.0/0")
	exitRouteV6 := netip.MustParsePrefix("::/0")

	changed, err := srv.State().SetPolicy([]byte(`{
		"tagOwners": {
			"tag:exit-a": ["exit-user@"],
			"tag:group-a":  ["cl-user@"]
		},
		"grants": [
			{
				"src": ["tag:exit-a", "tag:group-a"],
				"dst": ["tag:exit-a", "tag:group-a"],
				"ip": ["*"]
			},
			{
				"src": ["tag:group-a"],
				"dst": ["autogroup:internet"],
				"ip": ["*"],
				"via": ["tag:exit-a"]
			}
		],
		"autoApprovers": {
			"exitNode": ["tag:exit-a"]
		}
	}`))
	require.NoError(t, err)

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	exitA := servertest.NewClient(t, srv, "exit-a",
		servertest.WithUser(exitUser),
		servertest.WithTags("tag:exit-a"))
	clientA := servertest.NewClient(t, srv, "client-a",
		servertest.WithUser(clientUser),
		servertest.WithTags("tag:group-a"))

	exitA.WaitForPeers(t, 1, 15*time.Second)
	clientA.WaitForPeers(t, 1, 15*time.Second)

	// Advertise and approve exit routes.
	exitA.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-exit-a",
		Hostname:     "exit-a",
		RoutableIPs:  []netip.Prefix{exitRouteV4, exitRouteV6},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = exitA.Direct().SendUpdate(ctx)

	exitAID := findNodeID(t, srv, "exit-a")
	_, routeChange, err := srv.State().SetApprovedRoutes(
		exitAID, []netip.Prefix{exitRouteV4, exitRouteV6})
	require.NoError(t, err)
	srv.App.Change(routeChange)

	// Wait for routes to propagate.
	exitA.WaitForCondition(t, "exit-a routes approved",
		15*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return nm != nil
		})

	// The exit node's PacketFilter must NOT contain rules for exit traffic.
	// The only rules should be from the peer connectivity grant (tag:exit-a
	// and tag:group-a can talk to each other at their Tailscale IPs).
	exitNM := exitA.Netmap()
	require.NotNil(t, exitNM)

	for _, m := range exitNM.PacketFilter {
		for _, dst := range m.Dsts {
			dstPrefix := netip.PrefixFrom(dst.Net.Addr(), dst.Net.Bits())
			assert.Falsef(t, dstPrefix == exitRouteV4 || dstPrefix == exitRouteV6,
				"exit node PacketFilter should NOT contain exit route destinations (0.0.0.0/0 or ::/0); "+
					"autogroup:internet via grants do not produce filter rules on exit nodes (verified against Tailscale SaaS)")
		}
	}
}

// hasCapMatches returns true if any Match in the slice contains a
// non-empty Caps (CapMatch) list.
func hasCapMatches(matches []filtertype.Match) bool {
	for _, m := range matches {
		if len(m.Caps) > 0 {
			return true
		}
	}

	return false
}

// hasDstRules returns true if any Match in the slice contains a
// non-empty Dsts list.
func hasDstRules(matches []filtertype.Match) bool {
	for _, m := range matches {
		if len(m.Dsts) > 0 {
			return true
		}
	}

	return false
}
