package integration

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/filter"
)

// hasCapMatchInPacketFilter checks if any Match entry in the packet
// filter contains a CapMatch with the given capability name.
func hasCapMatchInPacketFilter(pf []filter.Match, peerCap tailcfg.PeerCapability) bool {
	for _, m := range pf {
		for _, cm := range m.Caps {
			if cm.Cap == peerCap {
				return true
			}
		}
	}

	return false
}

// hasCapMatchForIP checks if any CapMatch with the given capability
// has a Dst prefix that contains the given IP. This validates that
// the cap is directed at the correct node, not just present.
func hasCapMatchForIP(pf []filter.Match, peerCap tailcfg.PeerCapability, ip netip.Addr) bool {
	for _, m := range pf {
		for _, cm := range m.Caps {
			if cm.Cap == peerCap && cm.Dst.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// parsePeerRelay parses a PeerRelay string of the form "ip:port:vni:N"
// and returns the address and VNI. Returns zero values on parse failure.
func parsePeerRelay(pr string) (netip.AddrPort, string, bool) {
	// Format: "172.18.0.4:58738:vni:1"
	// Split into: host part "172.18.0.4:58738" and vni part "vni:1"
	addrStr, vni, ok := strings.Cut(pr, ":vni:")
	if !ok {
		return netip.AddrPort{}, "", false
	}

	ap, err := netip.ParseAddrPort(addrStr)
	if err != nil {
		return netip.AddrPort{}, "", false
	}

	return ap, vni, true
}

// TestGrantCapRelayAppOnly validates that a grant with only the app
// field (cap/relay, no IP connectivity grant) is sufficient for peer
// visibility and correct cap routing. This is the integration-level
// regression test for the MatchFromFilterRule fix that includes
// CapGrant.Dsts in the peer map.
//
// Without the fix, nodes connected only by a CapGrant would not appear
// in each other's peer lists because CapGrant destinations were not
// included in the matcher's destination set.
//
//  1. Only a relay cap grant exists (no ACL rules, no IP grants)
//  2. All nodes see each other as peers (peer map includes CapGrant.Dsts)
//  3. Cap grants compile correctly (cap/relay on relay, cap/relay-target on clients)
//  4. Wrong caps must NOT be present (negative checks)
func TestGrantCapRelayAppOnly(t *testing.T) {
	IntegrationSkip(t)

	assertTimeout := 120 * time.Second

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{"relay", "client"},
		Networks: map[string]NetworkSpec{
			"usernet1": {Users: []string{"relay", "client"}},
		},
		Versions: []string{"head"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	// Policy has ONLY a relay cap grant — no IP connectivity.
	// Without the CapGrant.Dsts fix, this grant alone would not
	// establish peer visibility between relay and client.
	pol := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:relay"): policyv2.Owners{usernameOwner("relay@")},
		},
		Grants: []policyv2.Grant{
			{
				Sources:      policyv2.Aliases{usernamep("client@")},
				Destinations: policyv2.Aliases{tagp("tag:relay")},
				App: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityRelay: {tailcfg.RawMessage("{}")},
				},
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("grant-cap-relay-app-only"),
		hsic.WithACLPolicy(pol),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrGetHeadscale(t, err)

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)

	_, err = scenario.CreateUser("relay")
	require.NoError(t, err)
	_, err = scenario.CreateUser("client")
	require.NoError(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// --- Create relay node (tagged) ---
	relayR, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)
	defer func() { _, _, _ = relayR.Shutdown() }()

	pakRelay, err := scenario.CreatePreAuthKeyWithTags(
		userMap["relay"].GetId(), false, false, []string{"tag:relay"},
	)
	require.NoError(t, err)
	err = relayR.Login(headscale.GetEndpoint(), pakRelay.GetKey())
	require.NoError(t, err)
	err = relayR.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// --- Create client node (user-owned, no tags) ---
	clientN, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)
	defer func() { _, _, _ = clientN.Shutdown() }()

	pakClient, err := scenario.CreatePreAuthKey(
		userMap["client"].GetId(), false, false,
	)
	require.NoError(t, err)
	err = clientN.Login(headscale.GetEndpoint(), pakClient.GetKey())
	require.NoError(t, err)
	err = clientN.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// ===== Phase 1: Validate peer visibility =====
	// This is the core assertion: with only a CapGrant (no IP grant),
	// both nodes must still appear in each other's peer list.
	t.Log("Phase 1: Validate peer visibility with app-only grant")

	allNodes := []TailscaleClient{relayR, clientN}
	for _, node := range allNodes {
		err = node.WaitForPeers(1, 60*time.Second, 1*time.Second)
		require.NoErrorf(t, err, "node %s failed to see its peer", node.Hostname())
	}

	relayIPv4 := relayR.MustIPv4()
	clientIPv4 := clientN.MustIPv4()

	// ===== Phase 2: Validate cap grants in packet filters =====
	t.Log("Phase 2: Validate cap grants in packet filters")

	// Relay should have cap/relay targeting its own IP.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := relayR.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityRelay, relayIPv4),
			"Relay should have cap/relay with Dst matching relay's IP %s", relayIPv4)
	}, assertTimeout, 500*time.Millisecond, "relay should have cap/relay targeting its own IP")

	// Client should have cap/relay-target targeting client's IP.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := clientN.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityRelayTarget, clientIPv4),
			"Client should have cap/relay-target with Dst matching client's IP %s", clientIPv4)
	}, assertTimeout, 500*time.Millisecond, "client should have cap/relay-target")

	// ===== Phase 3: Negative checks =====
	t.Log("Phase 3: Negative cap checks")

	// Relay should NOT have cap/relay-target.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := relayR.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityRelayTarget),
			"Relay should NOT have cap/relay-target")
	}, 10*time.Second, 500*time.Millisecond, "relay should not have cap/relay-target")

	// Client should NOT have cap/relay.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := clientN.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityRelay),
			"Client should NOT have cap/relay")
	}, 10*time.Second, 500*time.Millisecond, "client should not have cap/relay")
}

// TestGrantCapRelay validates the full peer relay lifecycle:
//  1. No direct connection between isolated clients
//  2. Cap grants compile correctly (relay + relay-target in packet filters)
//     with strict directionality and negative checks
//  3. Peer relay is used instead of DERP (PeerRelay non-empty, valid format)
//  4. Relay goes down -> fallback to DERP (PeerRelay empty, Relay non-empty,
//     DERP ping works)
//  5. Relay comes back up -> peer relay resumes (PeerRelay non-empty again)
func TestGrantCapRelay(t *testing.T) {
	IntegrationSkip(t)

	assertTimeout := 120 * time.Second

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{"relay", "clienta", "clientb"},
		Networks: map[string]NetworkSpec{
			"usernet1": {Users: []string{"clienta"}},
			"usernet2": {Users: []string{"clientb"}},
			"usernet3": {Users: []string{"relay"}},
		},
		Versions: []string{"head"},
	}

	scenario, err := NewScenario(spec)

	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	pol := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:relay"):    policyv2.Owners{usernameOwner("relay@")},
			policyv2.Tag("tag:client-a"): policyv2.Owners{usernameOwner("clienta@")},
			policyv2.Tag("tag:client-b"): policyv2.Owners{usernameOwner("clientb@")},
		},
		Grants: []policyv2.Grant{
			// Grant 1: Basic IP connectivity between all tagged nodes.
			{
				Sources: policyv2.Aliases{
					tagp("tag:relay"), tagp("tag:client-a"), tagp("tag:client-b"),
				},
				Destinations: policyv2.Aliases{
					tagp("tag:relay"), tagp("tag:client-a"), tagp("tag:client-b"),
				},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
			// Grant 2: Relay cap - clients can use relay node for UDP relaying.
			// This generates cap/relay on the relay's filter and cap/relay-target
			// (companion) on the clients' filters.
			{
				Sources:      policyv2.Aliases{tagp("tag:client-a"), tagp("tag:client-b")},
				Destinations: policyv2.Aliases{tagp("tag:relay")},
				App: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityRelay: {tailcfg.RawMessage("{}")},
				},
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("grant-cap-relay"),
		hsic.WithACLPolicy(pol),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrGetHeadscale(t, err)

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)
	usernet2, err := scenario.Network("usernet2")
	require.NoError(t, err)
	usernet3, err := scenario.Network("usernet3")
	require.NoError(t, err)

	// Create users on headscale server.
	_, err = scenario.CreateUser("relay")
	require.NoError(t, err)
	_, err = scenario.CreateUser("clienta")
	require.NoError(t, err)
	_, err = scenario.CreateUser("clientb")
	require.NoError(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// --- Create Relay R on usernet3, dual-homed to usernet1+usernet2 ---
	relayR, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet3),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = relayR.Shutdown() }()

	pakRelay, err := scenario.CreatePreAuthKeyWithTags(
		userMap["relay"].GetId(), false, false, []string{"tag:relay"},
	)
	require.NoError(t, err)
	err = relayR.Login(headscale.GetEndpoint(), pakRelay.GetKey())
	require.NoError(t, err)
	err = relayR.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// Dual-home after registration to avoid duplicate node key generation
	// from Docker network interface changes during tailscaled startup.
	err = relayR.ConnectToNetwork(usernet1)
	require.NoError(t, err)
	err = relayR.ConnectToNetwork(usernet2)
	require.NoError(t, err)

	// Enable the relay server on the relay node. Without this, the
	// relayserver extension loads but RelayServerPort is nil and the
	// server never starts listening for allocation requests.
	// Port 0 = random unused port.
	_, _, err = relayR.Execute([]string{
		"tailscale", "set", "--relay-server-port=0",
	})
	require.NoError(t, err)

	// --- Create Client A on usernet1 only ---
	clientA, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = clientA.Shutdown() }()

	pakClientA, err := scenario.CreatePreAuthKeyWithTags(
		userMap["clienta"].GetId(), false, false, []string{"tag:client-a"},
	)
	require.NoError(t, err)
	err = clientA.Login(headscale.GetEndpoint(), pakClientA.GetKey())
	require.NoError(t, err)
	err = clientA.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// --- Create Client B on usernet2 only ---
	clientB, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet2),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = clientB.Shutdown() }()

	pakClientB, err := scenario.CreatePreAuthKeyWithTags(
		userMap["clientb"].GetId(), false, false, []string{"tag:client-b"},
	)
	require.NoError(t, err)
	err = clientB.Login(headscale.GetEndpoint(), pakClientB.GetKey())
	require.NoError(t, err)
	err = clientB.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// ===== Phase 1: Validate isolation and peer visibility =====
	t.Log("Phase 1: Validate network isolation and peer visibility")

	allNodes := []TailscaleClient{relayR, clientA, clientB}
	for _, node := range allNodes {
		err = node.WaitForPeers(len(allNodes)-1, 60*time.Second, 1*time.Second)
		require.NoErrorf(t, err, "node %s failed to see all peers", node.Hostname())
	}

	// Restart all nodes to ensure fresh wireguard config. When nodes
	// register sequentially, early peers may arrive without DERP info
	// and get permanently skipped in wireguard config.
	for _, node := range allNodes {
		require.NoError(t, node.Restart())
		require.NoError(t, node.WaitForRunning(30*time.Second))
	}

	for _, node := range allNodes {
		err = node.WaitForPeers(len(allNodes)-1, 60*time.Second, 1*time.Second)
		require.NoErrorf(t, err, "node %s failed to see all peers after restart", node.Hostname())
	}

	// Capture keys and IPs for assertions.
	clientBKey := clientB.MustStatus().Self.PublicKey
	clientAKey := clientA.MustStatus().Self.PublicKey
	relayIPv4 := relayR.MustIPv4()
	clientAIPv4 := clientA.MustIPv4()
	clientBIPv4 := clientB.MustIPv4()

	// Verify no direct path between A and B.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := clientA.Status()
		assert.NoError(c, err)

		peerB := status.Peer[clientBKey]
		assert.NotNil(c, peerB, "A should see B as a peer")

		if peerB != nil {
			assert.Empty(c, peerB.CurAddr, "A->B should have no direct path")
		}
	}, assertTimeout, 500*time.Millisecond, "A should have no direct path to B")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := clientB.Status()
		assert.NoError(c, err)

		peerA := status.Peer[clientAKey]
		assert.NotNil(c, peerA, "B should see A as a peer")

		if peerA != nil {
			assert.Empty(c, peerA.CurAddr, "B->A should have no direct path")
		}
	}, assertTimeout, 500*time.Millisecond, "B should have no direct path to A")

	// ===== Phase 2: Validate cap grants in packet filters =====
	t.Log("Phase 2: Validate cap grants in packet filters")

	// --- Positive checks: correct caps on correct nodes ---

	// Relay R should have cap/relay targeting the relay's own IP.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := relayR.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityRelay, relayIPv4),
			"Relay R should have cap/relay with Dst matching relay's IP %s", relayIPv4)
	}, assertTimeout, 500*time.Millisecond, "R should have cap/relay targeting its own IP")

	// Client A should have cap/relay-target targeting client A's IP.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := clientA.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityRelayTarget, clientAIPv4),
			"Client A should have cap/relay-target with Dst matching A's IP %s", clientAIPv4)
	}, assertTimeout, 500*time.Millisecond, "A should have cap/relay-target targeting its own IP")

	// Client B should have cap/relay-target targeting client B's IP.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := clientB.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityRelayTarget, clientBIPv4),
			"Client B should have cap/relay-target with Dst matching B's IP %s", clientBIPv4)
	}, assertTimeout, 500*time.Millisecond, "B should have cap/relay-target targeting its own IP")

	// --- Negative checks: wrong caps must NOT be present ---

	// Relay R should NOT have cap/relay-target (it's a relay server, not a target).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := relayR.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityRelayTarget),
			"Relay R should NOT have cap/relay-target")
	}, 10*time.Second, 500*time.Millisecond, "R should not have cap/relay-target")

	// Client A should NOT have cap/relay (it's a client, not a relay server).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := clientA.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityRelay),
			"Client A should NOT have cap/relay")
	}, 10*time.Second, 500*time.Millisecond, "A should not have cap/relay")

	// Client B should NOT have cap/relay (it's a client, not a relay server).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := clientB.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityRelay),
			"Client B should NOT have cap/relay")
	}, 10*time.Second, 500*time.Millisecond, "B should not have cap/relay")

	// ===== Phase 3: Validate peer relay active (not DERP) =====
	t.Log("Phase 3: Validate peer relay active (not DERP)")

	// Verify PeerRelay is set with valid format and correct relay IPs.
	// Relay endpoint allocation is triggered by traffic between peers,
	// so we send pings in the check loop to initiate relay discovery.
	var peerRelayAtoB, peerRelayBtoA string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// Fire a ping to trigger relay path discovery (ignore output).
		clientA.Execute([]string{"tailscale", "ping", "--c=1", "--timeout=1s", clientBIPv4.String()}) //nolint:errcheck

		status, err := clientA.Status()
		assert.NoError(c, err)

		peerB := status.Peer[clientBKey]
		assert.NotNil(c, peerB, "A should see B as a peer")

		if peerB != nil {
			assert.NotEmpty(c, peerB.PeerRelay,
				"A->B should use peer relay, not DERP")
			assert.Empty(c, peerB.CurAddr,
				"A->B should not have direct connection")

			if peerB.PeerRelay != "" {
				peerRelayAtoB = peerB.PeerRelay

				// Validate PeerRelay format: ip:port:vni:N
				ap, vni, ok := parsePeerRelay(peerB.PeerRelay)
				assert.True(c, ok,
					"PeerRelay %q should be parseable as ip:port:vni:N", peerB.PeerRelay)

				if ok {
					assert.NotZero(c, ap.Port(),
						"PeerRelay port should be non-zero")
					assert.NotEmpty(c, vni,
						"PeerRelay VNI should be non-empty")
				}
			}

			t.Logf("Phase 3 - A->B: PeerRelay=%q Relay=%q CurAddr=%q Active=%v",
				peerB.PeerRelay, peerB.Relay, peerB.CurAddr, peerB.Active)
		}
	}, assertTimeout, 2*time.Second, "A should show peer relay to B")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientB.Execute([]string{"tailscale", "ping", "--c=1", "--timeout=1s", clientAIPv4.String()}) //nolint:errcheck

		status, err := clientB.Status()
		assert.NoError(c, err)

		peerA := status.Peer[clientAKey]
		assert.NotNil(c, peerA, "B should see A as a peer")

		if peerA != nil {
			assert.NotEmpty(c, peerA.PeerRelay,
				"B->A should use peer relay, not DERP")

			if peerA.PeerRelay != "" {
				peerRelayBtoA = peerA.PeerRelay

				ap, vni, ok := parsePeerRelay(peerA.PeerRelay)
				assert.True(c, ok,
					"PeerRelay %q should be parseable as ip:port:vni:N", peerA.PeerRelay)

				if ok {
					assert.NotZero(c, ap.Port(),
						"PeerRelay port should be non-zero")
					assert.NotEmpty(c, vni,
						"PeerRelay VNI should be non-empty")
				}
			}

			t.Logf("Phase 3 - B->A: PeerRelay=%q Relay=%q CurAddr=%q Active=%v",
				peerA.PeerRelay, peerA.Relay, peerA.CurAddr, peerA.Active)
		}
	}, assertTimeout, 2*time.Second, "B should show peer relay to A")

	// Cross-validate: both directions should use the same VNI
	// (same relay allocation) but different IPs (dual-homed relay).
	if peerRelayAtoB != "" && peerRelayBtoA != "" {
		apA, vniA, okA := parsePeerRelay(peerRelayAtoB)

		apB, vniB, okB := parsePeerRelay(peerRelayBtoA)
		if okA && okB {
			assert.Equal(t, vniA, vniB,
				"A->B and B->A should share the same VNI (same relay allocation)")
			assert.Equal(t, apA.Port(), apB.Port(),
				"A->B and B->A should use the same relay port")
			assert.NotEqual(t, apA.Addr(), apB.Addr(),
				"A->B and B->A relay IPs should differ (dual-homed relay)")
		}
	}

	// ===== Phase 4: Bring relay down -> DERP fallback =====
	t.Log("Phase 4: Bring relay down, expect DERP fallback")

	require.NoError(t, relayR.Down())

	// Verify PeerRelay is gone and DERP is used.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := clientA.Status()
		assert.NoError(c, err)

		peerB := status.Peer[clientBKey]
		assert.NotNil(c, peerB, "A should still see B as a peer")

		if peerB != nil {
			assert.Empty(c, peerB.PeerRelay,
				"A->B peer relay should be gone")
			assert.NotEmpty(c, peerB.Relay,
				"A->B should fall back to DERP")
			t.Logf("Phase 4 - A->B: PeerRelay=%q Relay=%q CurAddr=%q Active=%v",
				peerB.PeerRelay, peerB.Relay, peerB.CurAddr, peerB.Active)
		}
	}, assertTimeout, 500*time.Millisecond, "A should fall back to DERP for B")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := clientB.Status()
		assert.NoError(c, err)

		peerA := status.Peer[clientAKey]
		assert.NotNil(c, peerA, "B should still see A as a peer")

		if peerA != nil {
			assert.Empty(c, peerA.PeerRelay,
				"B->A peer relay should be gone")
			t.Logf("Phase 4 - B->A: PeerRelay=%q Relay=%q CurAddr=%q Active=%v",
				peerA.PeerRelay, peerA.Relay, peerA.CurAddr, peerA.Active)
		}
	}, assertTimeout, 500*time.Millisecond, "B should fall back to DERP for A")

	// Verify data plane works via DERP after relay is down.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := clientA.Ping(
			clientBIPv4.String(),
			tsic.WithPingUntilDirect(false),
			tsic.WithPingTimeout(2*time.Second),
			tsic.WithPingCount(1),
		)
		assert.NoError(c, err)
	}, assertTimeout, 1*time.Second, "A should reach B via DERP after relay down")

	// ===== Phase 5: Bring relay back up -> peer relay resumes =====
	t.Log("Phase 5: Bring relay back up, expect peer relay to resume")

	require.NoError(t, relayR.Up())

	err = relayR.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// Verify peer relay resumes. Ping to trigger relay re-discovery.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientA.Execute([]string{"tailscale", "ping", "--c=1", "--timeout=1s", clientBIPv4.String()}) //nolint:errcheck

		status, err := clientA.Status()
		assert.NoError(c, err)

		peerB := status.Peer[clientBKey]
		assert.NotNil(c, peerB, "A should see B as a peer")

		if peerB != nil {
			assert.NotEmpty(c, peerB.PeerRelay,
				"A->B peer relay should resume after R comes back")
			t.Logf("Phase 5 - A->B: PeerRelay=%q Relay=%q CurAddr=%q Active=%v",
				peerB.PeerRelay, peerB.Relay, peerB.CurAddr, peerB.Active)
		}
	}, assertTimeout, 2*time.Second, "A should resume peer relay to B")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		clientB.Execute([]string{"tailscale", "ping", "--c=1", "--timeout=1s", clientAIPv4.String()}) //nolint:errcheck

		status, err := clientB.Status()
		assert.NoError(c, err)

		peerA := status.Peer[clientAKey]
		assert.NotNil(c, peerA, "B should see A as a peer")

		if peerA != nil {
			assert.NotEmpty(c, peerA.PeerRelay,
				"B->A peer relay should resume after R comes back")
			t.Logf("Phase 5 - B->A: PeerRelay=%q Relay=%q CurAddr=%q Active=%v",
				peerA.PeerRelay, peerA.Relay, peerA.CurAddr, peerA.Active)
		}
	}, assertTimeout, 2*time.Second, "B should resume peer relay to A")
}

// driveURL constructs a Taildrive WebDAV URL via the local proxy.
func driveURL(domain, sharerName, path string) string {
	return fmt.Sprintf(
		"http://100.100.100.100:8080/%s/%s/%s",
		domain, sharerName, path,
	)
}

// TestGrantCapDrive validates Taildrive (cap/drive) grant-based access control:
//  1. Node attributes (drive:share, drive:access) are set in all nodes' CapMap
//  2. Cap grants compile correctly (cap/drive + cap/drive-sharer in packet filters)
//  3. RW client can read, write, and delete files on the sharer
//  4. RO client can read but NOT write or delete files on the sharer
//  5. No-access node (no cap/drive grant) cannot read or write files
func TestGrantCapDrive(t *testing.T) {
	IntegrationSkip(t)

	assertTimeout := 120 * time.Second

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{"sharer", "rwclient", "roclient", "noaccess"},
		Networks: map[string]NetworkSpec{
			"usernet1": {Users: []string{"sharer", "rwclient", "roclient", "noaccess"}},
		},
		Versions: []string{"head"},
	}

	scenario, err := NewScenario(spec)

	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	pol := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:sharer"):    policyv2.Owners{usernameOwner("sharer@")},
			policyv2.Tag("tag:rw-client"): policyv2.Owners{usernameOwner("rwclient@")},
			policyv2.Tag("tag:ro-client"): policyv2.Owners{usernameOwner("roclient@")},
			policyv2.Tag("tag:no-access"): policyv2.Owners{usernameOwner("noaccess@")},
		},
		Grants: []policyv2.Grant{
			// Grant 1: IP connectivity between ALL nodes.
			{
				Sources: policyv2.Aliases{
					tagp("tag:sharer"), tagp("tag:rw-client"),
					tagp("tag:ro-client"), tagp("tag:no-access"),
				},
				Destinations: policyv2.Aliases{
					tagp("tag:sharer"), tagp("tag:rw-client"),
					tagp("tag:ro-client"), tagp("tag:no-access"),
				},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
			// Grant 2: cap/drive RW - rw-client can read+write sharer's drives.
			{
				Sources:      policyv2.Aliases{tagp("tag:rw-client")},
				Destinations: policyv2.Aliases{tagp("tag:sharer")},
				App: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityTaildrive: {
						tailcfg.RawMessage(`{"shares":["*"],"access":"rw"}`),
					},
				},
			},
			// Grant 3: cap/drive RO - ro-client can only read sharer's drives.
			{
				Sources:      policyv2.Aliases{tagp("tag:ro-client")},
				Destinations: policyv2.Aliases{tagp("tag:sharer")},
				App: tailcfg.PeerCapMap{
					tailcfg.PeerCapabilityTaildrive: {
						tailcfg.RawMessage(`{"shares":["*"],"access":"ro"}`),
					},
				},
			},
			// NO cap/drive grant for tag:no-access (intentional).
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("grant-cap-drive"),
		hsic.WithACLPolicy(pol),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrGetHeadscale(t, err)

	usernet1, err := scenario.Network("usernet1")
	require.NoError(t, err)

	// Create users on headscale server.
	_, err = scenario.CreateUser("sharer")
	require.NoError(t, err)
	_, err = scenario.CreateUser("rwclient")
	require.NoError(t, err)
	_, err = scenario.CreateUser("roclient")
	require.NoError(t, err)
	_, err = scenario.CreateUser("noaccess")
	require.NoError(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// --- Create Sharer node ---
	sharer, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = sharer.Shutdown() }()

	pakSharer, err := scenario.CreatePreAuthKeyWithTags(
		userMap["sharer"].GetId(), false, false, []string{"tag:sharer"},
	)
	require.NoError(t, err)
	err = sharer.Login(headscale.GetEndpoint(), pakSharer.GetKey())
	require.NoError(t, err)
	err = sharer.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// --- Create RW client node ---
	rwClient, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = rwClient.Shutdown() }()

	pakRW, err := scenario.CreatePreAuthKeyWithTags(
		userMap["rwclient"].GetId(), false, false, []string{"tag:rw-client"},
	)
	require.NoError(t, err)
	err = rwClient.Login(headscale.GetEndpoint(), pakRW.GetKey())
	require.NoError(t, err)
	err = rwClient.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// --- Create RO client node ---
	roClient, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = roClient.Shutdown() }()

	pakRO, err := scenario.CreatePreAuthKeyWithTags(
		userMap["roclient"].GetId(), false, false, []string{"tag:ro-client"},
	)
	require.NoError(t, err)
	err = roClient.Login(headscale.GetEndpoint(), pakRO.GetKey())
	require.NoError(t, err)
	err = roClient.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// --- Create No-access node ---
	noAccess, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(usernet1),
	)
	require.NoError(t, err)

	defer func() { _, _, _ = noAccess.Shutdown() }()

	pakNA, err := scenario.CreatePreAuthKeyWithTags(
		userMap["noaccess"].GetId(), false, false, []string{"tag:no-access"},
	)
	require.NoError(t, err)
	err = noAccess.Login(headscale.GetEndpoint(), pakNA.GetKey())
	require.NoError(t, err)
	err = noAccess.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// ===== Phase 1: Wait for all peers =====
	t.Log("Phase 1: Wait for all peers to be visible")

	allNodes := []TailscaleClient{sharer, rwClient, roClient, noAccess}
	for _, node := range allNodes {
		err = node.WaitForPeers(len(allNodes)-1, 60*time.Second, 1*time.Second)
		require.NoErrorf(t, err, "node %s failed to see all peers", node.Hostname())
	}

	sharerIPv4 := sharer.MustIPv4()

	// ===== Phase 2: Validate node attributes (self CapMap) =====
	t.Log("Phase 2: Validate Taildrive node attributes in CapMap")

	for _, node := range allNodes {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nm, err := node.Netmap()
			assert.NoError(c, err)

			if nm == nil {
				return
			}

			assert.True(c, nm.SelfNode.Valid(),
				"%s: SelfNode should be valid", node.Hostname())

			if nm.SelfNode.Valid() {
				assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeAttrsTaildriveShare),
					"%s: should have drive:share cap", node.Hostname())
				assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeAttrsTaildriveAccess),
					"%s: should have drive:access cap", node.Hostname())
			}
		}, assertTimeout, 500*time.Millisecond,
			"all nodes should have Taildrive node attributes")
	}

	// ===== Phase 3: Validate cap grants in packet filters =====
	t.Log("Phase 3: Validate cap/drive grants in packet filters")

	// --- Positive checks ---

	// Sharer should have cap/drive targeting its own IP (it's the drive destination).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := sharer.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityTaildrive, sharerIPv4),
			"Sharer should have cap/drive with Dst matching sharer's IP %s", sharerIPv4)
	}, assertTimeout, 500*time.Millisecond, "sharer should have cap/drive targeting its own IP")

	// RW client should have cap/drive-sharer (companion) targeting rw-client's IP.
	rwClientIPv4 := rwClient.MustIPv4()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := rwClient.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityTaildriveSharer, rwClientIPv4),
			"RW client should have cap/drive-sharer with Dst matching rw-client's IP %s", rwClientIPv4)
	}, assertTimeout, 500*time.Millisecond, "rw-client should have cap/drive-sharer")

	// RO client should have cap/drive-sharer (companion) targeting ro-client's IP.
	roClientIPv4 := roClient.MustIPv4()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := roClient.PacketFilter()
		assert.NoError(c, err)
		assert.True(c, hasCapMatchForIP(pf, tailcfg.PeerCapabilityTaildriveSharer, roClientIPv4),
			"RO client should have cap/drive-sharer with Dst matching ro-client's IP %s", roClientIPv4)
	}, assertTimeout, 500*time.Millisecond, "ro-client should have cap/drive-sharer")

	// --- Negative checks ---

	// No-access node should NOT have cap/drive or cap/drive-sharer.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := noAccess.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityTaildrive),
			"no-access should NOT have cap/drive")
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityTaildriveSharer),
			"no-access should NOT have cap/drive-sharer")
	}, 10*time.Second, 500*time.Millisecond, "no-access should have no drive caps")

	// Sharer should NOT have cap/drive-sharer (it's a destination, not a source).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := sharer.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityTaildriveSharer),
			"sharer should NOT have cap/drive-sharer")
	}, 10*time.Second, 500*time.Millisecond, "sharer should not have cap/drive-sharer")

	// RW client should NOT have cap/drive (it's a source, not a destination).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := rwClient.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityTaildrive),
			"rw-client should NOT have cap/drive")
	}, 10*time.Second, 500*time.Millisecond, "rw-client should not have cap/drive")

	// RO client should NOT have cap/drive (it's a source, not a destination).
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		pf, err := roClient.PacketFilter()
		assert.NoError(c, err)
		assert.False(c, hasCapMatchInPacketFilter(pf, tailcfg.PeerCapabilityTaildrive),
			"ro-client should NOT have cap/drive")
	}, 10*time.Second, 500*time.Millisecond, "ro-client should not have cap/drive")

	// ===== Phase 4: Create share on sharer =====
	t.Log("Phase 4: Create share on sharer node")

	_, _, err = sharer.Execute([]string{"mkdir", "-p", "/tmp/testshare"})
	require.NoError(t, err)
	_, _, err = sharer.Execute([]string{
		"sh", "-c", `echo "hello-taildrive" > /tmp/testshare/testfile.txt`,
	})
	require.NoError(t, err)
	_, _, err = sharer.Execute([]string{
		"tailscale", "drive", "share", "testshare", "/tmp/testshare",
	})
	require.NoError(t, err)

	// Verify share is listed.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := sharer.Execute([]string{"tailscale", "drive", "list"})
		assert.NoError(c, err)
		assert.Contains(c, result, "testshare",
			"sharer should list 'testshare' in drive list")
	}, 10*time.Second, 500*time.Millisecond, "sharer should have testshare listed")

	// Build the drive URL components from the sharer's FQDN.
	fqdn := strings.TrimSuffix(sharer.MustFQDN(), ".")
	parts := strings.SplitN(fqdn, ".", 2)
	sharerName := parts[0]
	domain := parts[1]

	// ===== Phase 5: RW client - read file (positive) =====
	t.Log("Phase 5: RW client reads file from sharer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := rwClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			driveURL(domain, sharerName, "testshare/testfile.txt"),
		})
		assert.NoError(c, err)
		assert.Equal(c, "hello-taildrive", strings.TrimSpace(result),
			"rw-client should read testfile.txt content")
	}, 60*time.Second, 2*time.Second, "rw-client should read file from sharer")

	// ===== Phase 6: RW client - write file (positive) =====
	t.Log("Phase 6: RW client writes file to sharer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := rwClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "-w", "%{http_code}",
			"-X", "PUT", "--data-binary", "written-by-rw",
			driveURL(domain, sharerName, "testshare/rw-wrote.txt"),
		})
		assert.NoError(c, err)
		assert.Contains(c, result, "20",
			"rw-client PUT should return 2xx status")
	}, 30*time.Second, 2*time.Second, "rw-client should write file to sharer")

	// Verify the file exists on sharer.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		content, err := sharer.ReadFile("/tmp/testshare/rw-wrote.txt")
		assert.NoError(c, err)
		assert.Equal(c, "written-by-rw", strings.TrimSpace(string(content)))
	}, 10*time.Second, 500*time.Millisecond, "rw-wrote.txt should exist on sharer")

	// ===== Phase 7: RO client - read file (positive) =====
	t.Log("Phase 7: RO client reads file from sharer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := roClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			driveURL(domain, sharerName, "testshare/testfile.txt"),
		})
		assert.NoError(c, err)
		assert.Equal(c, "hello-taildrive", strings.TrimSpace(result),
			"ro-client should read testfile.txt content")
	}, 60*time.Second, 2*time.Second, "ro-client should read file from sharer")

	// ===== Phase 8: RO client - write file (NEGATIVE - expect 403) =====
	t.Log("Phase 8: RO client write attempt (should be denied)")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := roClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "-w", "%{http_code}",
			"-X", "PUT", "--data-binary", "should-not-work",
			driveURL(domain, sharerName, "testshare/ro-wrote.txt"),
		})
		assert.NoError(c, err)
		assert.Equal(c, "403", strings.TrimSpace(result),
			"ro-client PUT should return 403 Forbidden")
	}, 30*time.Second, 2*time.Second, "ro-client write should be 403 Forbidden")

	// Verify file was NOT created on sharer.
	_, err = sharer.ReadFile("/tmp/testshare/ro-wrote.txt")
	require.Error(t, err, "ro-wrote.txt should not exist on sharer")

	// ===== Phase 9: No-access node - read file (NEGATIVE) =====
	t.Log("Phase 9: No-access node read attempt (should fail)")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := noAccess.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "-w", "%{http_code}",
			driveURL(domain, sharerName, "testshare/testfile.txt"),
		})
		// Either error (connection refused) or non-200 status.
		if err == nil {
			assert.NotEqual(c, "200", strings.TrimSpace(result),
				"no-access node should NOT get 200 from sharer's drive")
		}
	}, 30*time.Second, 2*time.Second, "no-access node should not read sharer's files")

	// ===== Phase 10: No-access node - write file (NEGATIVE) =====
	t.Log("Phase 10: No-access node write attempt (should fail)")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := noAccess.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "-w", "%{http_code}",
			"-X", "PUT", "--data-binary", "should-not-work",
			driveURL(domain, sharerName, "testshare/no-access-wrote.txt"),
		})
		if err == nil {
			assert.NotEqual(c, "200", strings.TrimSpace(result),
				"no-access node should not get 200 on PUT")
			assert.NotEqual(c, "201", strings.TrimSpace(result),
				"no-access node should not get 201 on PUT")
		}
	}, 30*time.Second, 2*time.Second, "no-access node should not write sharer's files")

	// Verify file NOT created on sharer.
	_, err = sharer.ReadFile("/tmp/testshare/no-access-wrote.txt")
	require.Error(t, err, "no-access-wrote.txt should not exist on sharer")

	// ===== Phase 11: RW client - list directory via PROPFIND (positive) =====
	t.Log("Phase 11: RW client lists directory via PROPFIND")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := rwClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-X", "PROPFIND", "-H", "Depth: 1",
			driveURL(domain, sharerName, "testshare/"),
		})
		assert.NoError(c, err)
		assert.Contains(c, result, "testfile.txt",
			"PROPFIND should list testfile.txt")
		assert.Contains(c, result, "rw-wrote.txt",
			"PROPFIND should list rw-wrote.txt")
	}, 30*time.Second, 2*time.Second, "rw-client PROPFIND should list files")

	// ===== Phase 12: RW client - delete file (positive) =====
	t.Log("Phase 12: RW client deletes file from sharer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := rwClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "-w", "%{http_code}",
			"-X", "DELETE",
			driveURL(domain, sharerName, "testshare/rw-wrote.txt"),
		})
		assert.NoError(c, err)
		assert.Contains(c, result, "20",
			"rw-client DELETE should return 2xx status")
	}, 30*time.Second, 2*time.Second, "rw-client should delete file from sharer")

	// Verify deleted on sharer.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := sharer.ReadFile("/tmp/testshare/rw-wrote.txt")
		assert.Error(c, err, "rw-wrote.txt should be deleted from sharer")
	}, 10*time.Second, 500*time.Millisecond, "rw-wrote.txt should be gone")

	// ===== Phase 13: RO client - delete file (NEGATIVE - expect 403) =====
	t.Log("Phase 13: RO client delete attempt (should be denied)")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, _, err := roClient.Execute([]string{
			"curl", "-s", "--max-time", "5",
			"-o", "/dev/null", "-w", "%{http_code}",
			"-X", "DELETE",
			driveURL(domain, sharerName, "testshare/testfile.txt"),
		})
		assert.NoError(c, err)
		assert.Equal(c, "403", strings.TrimSpace(result),
			"ro-client DELETE should return 403 Forbidden")
	}, 30*time.Second, 2*time.Second, "ro-client delete should be 403 Forbidden")

	// Verify file still exists on sharer.
	content, err := sharer.ReadFile("/tmp/testshare/testfile.txt")
	require.NoError(t, err)
	assert.Equal(t, "hello-taildrive", strings.TrimSpace(string(content)),
		"testfile.txt should still exist after RO delete attempt")
}
