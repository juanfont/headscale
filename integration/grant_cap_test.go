package integration

import (
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
		Networks: map[string][]string{
			"usernet1": {"clienta"},
			"usernet2": {"clientb"},
			"usernet3": {"relay"},
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
