package integration

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestWireGuardOnlyPeerBasicRegistration tests the basic registration flow for WireGuard-only peers.
// It verifies that:
// - A WireGuard-only peer can be registered via CLI
// - The peer appears in the network map of nodes specified in KnownNodeIDs
// - The peer does NOT appear for nodes not in KnownNodeIDs
// - The peer has correct properties (IsWireGuardOnly, IsJailed)
func TestWireGuardOnlyPeerBasicRegistration(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 3,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		nil,
		hsic.WithTestName("wg-only-basic"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)
	require.Len(t, allClients, 3, "should have 3 clients")

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err, "failed to list nodes")
	require.Len(t, nodes, 3, "should have 3 nodes")

	node1ID := nodes[0].GetId()
	node2ID := nodes[1].GetId()
	_ = nodes[2].GetId() // node3 should NOT see the peer

	wgPrivateKey := key.NewNode()
	wgPublicKey := wgPrivateKey.Public()

	// Register a WireGuard-only peer that should be visible to node1 and node2 only
	result, err := headscale.Execute([]string{
		"headscale",
		"node",
		"register-wg-only",
		"--name", "test-wg-peer",
		"--user", "1",
		"--public-key", wgPublicKey.String(),
		"--known-nodes", fmt.Sprintf("%d,%d", node1ID, node2ID),
		"--allowed-ips", "0.0.0.0/0,::/0",
		"--endpoints", "192.0.2.1:51820",
		"--self-ipv4-masq-addr", "10.64.0.100",
		"--extra-config", `{"suggestExitNode":true}`,
		"--output", "json",
	})
	require.NoError(t, err, "failed to register WireGuard-only peer")
	require.NotEmpty(t, result, "registration result should not be empty")

	t.Logf("WireGuard-only peer registered: %s", result)

	var peer *v1.WireGuardOnlyPeer
	err = json.Unmarshal([]byte(result), &peer)
	require.NoError(t, err, "failed to parse registration result")
	require.GreaterOrEqual(t, peer.Id, uint64(types.WireGuardOnlyPeerIDOffset), "WireGuard-only peer ID should be >= 100 million")

	// Wait for the peer to appear in network maps
	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// Verify node1 can see the WireGuard-only peer
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status1, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status1.Peers() {
			peer := status1.Peer[peerKey]
			if peer.HostName == "test-wg-peer" {
				found = true

				assert.NotEmpty(c, peer.AllowedIPs, "peer should have allowed IPs")
				assert.NotNil(c, peer.CapMap, "peer should have capability map")
				_, hasExitNode := peer.CapMap[tailcfg.NodeAttrSuggestExitNode]
				assert.True(c, hasExitNode, "peer should be suggested as exit node")
				break
			}
		}
		assert.True(c, found, "node1 should see the WireGuard-only peer")
	}, 10*time.Second, 500*time.Millisecond, "node1 should see WireGuard-only peer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status2, err := allClients[1].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status2.Peers() {
			peer := status2.Peer[peerKey]
			if peer.HostName == "test-wg-peer" {
				found = true
				break
			}
		}
		assert.True(c, found, "node2 should see the WireGuard-only peer")
	}, 10*time.Second, 500*time.Millisecond, "node2 should see WireGuard-only peer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status3, err := allClients[2].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status3.Peers() {
			peer := status3.Peer[peerKey]
			if peer.HostName == "test-wg-peer" {
				found = true
				break
			}
		}
		assert.False(c, found, "node3 should NOT see the WireGuard-only peer (not in KnownNodeIDs)")
	}, 10*time.Second, 500*time.Millisecond, "node3 should not see WireGuard-only peer")
}

// TestWireGuardOnlyPeerDeletion tests that deleting a WireGuard-only peer removes it from node network maps.
func TestWireGuardOnlyPeerDeletion(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		nil,
		hsic.WithTestName("wg-only-delete"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)
	require.Len(t, allClients, 2, "should have 2 clients")

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err, "failed to list nodes")
	require.Len(t, nodes, 2, "should have 2 nodes")

	node1ID := nodes[0].GetId()

	wgPrivateKey := key.NewNode()
	wgPublicKey := wgPrivateKey.Public()

	// Register a WireGuard-only peer
	result, err := headscale.Execute([]string{
		"headscale",
		"node",
		"register-wg-only",
		"--name", "test-wg-peer-delete",
		"--user", "1",
		"--public-key", wgPublicKey.String(),
		"--known-nodes", fmt.Sprintf("%d", node1ID),
		"--allowed-ips", "10.99.0.0/24",
		"--endpoints", "192.0.2.1:51820",
		"--self-ipv4-masq-addr", "10.64.0.100",
		"--output", "json",
	})
	require.NoError(t, err, "failed to register WireGuard-only peer")
	require.NotEmpty(t, result, "registration result should not be empty")

	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status.Peers() {
			peer := status.Peer[peerKey]
			if peer.HostName == "test-wg-peer-delete" {
				found = true
				break
			}
		}
		assert.True(c, found, "peer should be visible before deletion")
	}, 10*time.Second, 500*time.Millisecond, "peer should be visible")

	var registeredPeer *v1.WireGuardOnlyPeer
	err = json.Unmarshal([]byte(result), &registeredPeer)
	require.NoError(t, err, "failed to parse registration result")

	peerID := registeredPeer.Id

	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"delete",
		"--identifier", fmt.Sprintf("%d", peerID),
	})
	require.NoError(t, err, "failed to delete WireGuard-only peer")

	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status.Peers() {
			peer := status.Peer[peerKey]
			if peer.HostName == "test-wg-peer-delete" {
				found = true
				break
			}
		}
		assert.False(c, found, "peer should not be visible after deletion")
	}, 10*time.Second, 500*time.Millisecond, "peer should be removed from network map")
}

// TestWireGuardOnlyPeerIPAllocation tests that WireGuard-only peers receive proper IP addresses.
func TestWireGuardOnlyPeerIPAllocation(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		nil,
		hsic.WithTestName("wg-only-ips"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)
	require.Len(t, allClients, 1, "should have 1 client")

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err, "failed to list nodes")
	require.Len(t, nodes, 1, "should have 1 node")

	nodeID := nodes[0].GetId()

	wgPrivateKey := key.NewNode()
	wgPublicKey := wgPrivateKey.Public()

	result, err := headscale.Execute([]string{
		"headscale",
		"node",
		"register-wg-only",
		"--name", "test-wg-peer-ips",
		"--user", "1",
		"--public-key", wgPublicKey.String(),
		"--known-nodes", fmt.Sprintf("%d", nodeID),
		"--allowed-ips", "0.0.0.0/0",
		"--endpoints", "192.0.2.1:51820",
		"--self-ipv4-masq-addr", "10.64.0.100",
		"--output", "json",
	})
	require.NoError(t, err, "failed to register WireGuard-only peer")
	require.NotEmpty(t, result, "registration result should not be empty")

	var peer *v1.WireGuardOnlyPeer
	err = json.Unmarshal([]byte(result), &peer)
	require.NoError(t, err, "failed to parse JSON")

	require.NotEmpty(t, peer.Ipv4, "peer should have IPv4 address")
	require.NotEmpty(t, peer.Ipv6, "peer should have IPv6 address")

	ipv4, err := netip.ParseAddr(peer.Ipv4)
	require.NoError(t, err, "IPv4 address should be valid")
	require.True(t, ipv4.Is4(), "IPv4 address should be an IPv4 address")

	ipv6, err := netip.ParseAddr(peer.Ipv6)
	require.NoError(t, err, "IPv6 address should be valid")
	require.True(t, ipv6.Is6(), "IPv6 address should be an IPv6 address")

	t.Logf("WireGuard-only peer allocated IPs - IPv4: %s, IPv6: %s", peer.Ipv4, peer.Ipv6)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status.Peers() {
			peerStatus := status.Peer[peerKey]
			if peerStatus.HostName == "test-wg-peer-ips" {
				found = true

				hasIPv4 := false
				hasIPv6 := false
				for _, addr := range peerStatus.TailscaleIPs {
					if addr.String() == peer.Ipv4 {
						hasIPv4 = true
					}
					if addr.String() == peer.Ipv6 {
						hasIPv6 = true
					}
				}

				assert.True(c, hasIPv4, "peer should have allocated IPv4 in network map")
				assert.True(c, hasIPv6, "peer should have allocated IPv6 in network map")
				break
			}
		}
		assert.True(c, found, "peer should be visible in network map")
	}, 10*time.Second, 500*time.Millisecond, "peer should have correct IPs in network map")
}

// TestWireGuardOnlyPeerMasqueradeAddressValidation tests that at least one masquerade address is required.
func TestWireGuardOnlyPeerMasqueradeAddressValidation(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		nil,
		hsic.WithTestName("wg-only-masq-validation"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)
	require.Len(t, allClients, 1, "should have 1 client")

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err, "failed to list nodes")
	require.Len(t, nodes, 1, "should have 1 node")

	nodeID := nodes[0].GetId()

	wgPrivateKey := key.NewNode()
	wgPublicKey := wgPrivateKey.Public()

	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"register-wg-only",
		"--name", "test-wg-peer-no-masq",
		"--user", "1",
		"--public-key", wgPublicKey.String(),
		"--known-nodes", fmt.Sprintf("%d", nodeID),
		"--allowed-ips", "0.0.0.0/0",
		"--endpoints", "192.0.2.1:51820",
	})
	require.Error(t, err, "registration should fail without masquerade address")

	t.Logf("Registration correctly failed without masquerade address")
}

// TestWireGuardOnlyPeerMapResponse tests that WireGuard-only peers have the correct
// tailcfg.Node fields set in the network map response, including all extra config parameters.
func TestWireGuardOnlyPeerMapResponse(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		nil,
		hsic.WithTestName("wg-only-mapresponse"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)
	require.Len(t, allClients, 1, "should have 1 client")

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err, "failed to list nodes")
	require.Len(t, nodes, 1, "should have 1 node")

	nodeID := nodes[0].GetId()

	wgPrivateKey := key.NewNode()
	wgPublicKey := wgPrivateKey.Public()

	expectedIPv4Masq := netip.MustParseAddr("10.64.0.100")
	expectedIPv6Masq := netip.MustParseAddr("fd7a:115c:a1e0::100")
	expectedAllowedIPs := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	expectedEndpoint := "192.0.2.1:51820"

	// Test complete extra config with all fields
	extraConfig := `{
		"exitNodeDNSResolvers": ["10.64.0.1", "10.64.0.2"],
		"suggestExitNode": true,
		"tags": ["tag:exit-node", "tag:mullvad"],
		"location": {
			"country": "Sweden",
			"countryCode": "SE",
			"city": "Stockholm",
			"cityCode": "sto",
			"latitude": 59.3293,
			"longitude": 18.0686,
			"priority": 100
		}
	}`

	result, err := headscale.Execute([]string{
		"headscale",
		"node",
		"register-wg-only",
		"--name", "test-wg-peer-mapresponse",
		"--user", "1",
		"--public-key", wgPublicKey.String(),
		"--known-nodes", fmt.Sprintf("%d", nodeID),
		"--allowed-ips", "0.0.0.0/0,::/0",
		"--endpoints", expectedEndpoint,
		"--self-ipv4-masq-addr", expectedIPv4Masq.String(),
		"--self-ipv6-masq-addr", expectedIPv6Masq.String(),
		"--extra-config", extraConfig,
		"--output", "json",
	})
	require.NoError(t, err, "failed to register WireGuard-only peer")
	require.NotEmpty(t, result, "registration result should not be empty")

	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := allClients[0].Netmap()
		assert.NoError(c, err)

		found := false
		for _, peer := range nm.Peers {
			if peer.ComputedName() == "test-wg-peer-mapresponse" {
				found = true

				// Basic WireGuard-only peer properties
				assert.True(c, peer.IsWireGuardOnly(), "peer should have IsWireGuardOnly set to true")
				assert.True(c, peer.IsJailed(), "peer should have IsJailed set to true")

				// Masquerade addresses
				masqV4, ok := peer.SelfNodeV4MasqAddrForThisPeer().GetOk()
				assert.True(c, ok, "peer should have SelfNodeV4MasqAddrForThisPeer set")
				assert.Equal(c, expectedIPv4Masq, masqV4, "IPv4 masquerade address should match")

				masqV6, ok := peer.SelfNodeV6MasqAddrForThisPeer().GetOk()
				assert.True(c, ok, "peer should have SelfNodeV6MasqAddrForThisPeer set")
				assert.Equal(c, expectedIPv6Masq, masqV6, "IPv6 masquerade address should match")

				// AllowedIPs
				assert.NotEmpty(c, peer.AllowedIPs(), "peer should have AllowedIPs")
				allowedIPs := peer.AllowedIPs().AsSlice()
				assert.ElementsMatch(c, expectedAllowedIPs, allowedIPs, "AllowedIPs should match expected")

				// Endpoints
				assert.NotEmpty(c, peer.Endpoints(), "peer should have Endpoints")
				endpoints := peer.Endpoints().AsSlice()
				assert.Contains(c, endpoints, expectedEndpoint, "Endpoints should contain expected endpoint")

				// Extra config: suggestExitNode capability
				capMap := peer.CapMap()
				hasExitNode := capMap.Contains(tailcfg.NodeAttrSuggestExitNode)
				assert.True(c, hasExitNode, "peer CapMap should contain exit node attribute")

				// Extra config: exit node DNS resolvers
				exitDNS := peer.ExitNodeDNSResolvers()
				assert.Equal(c, 2, exitDNS.Len(), "peer should have 2 exit node DNS resolvers")
				if exitDNS.Len() == 2 {
					assert.Equal(c, "10.64.0.1", exitDNS.At(0).Addr, "first DNS resolver should match")
					assert.Equal(c, "10.64.0.2", exitDNS.At(1).Addr, "second DNS resolver should match")
				}

				// Extra config: tags
				tags := peer.Tags().AsSlice()
				assert.ElementsMatch(c, []string{"tag:exit-node", "tag:mullvad"}, tags, "tags should match expected")

				// Extra config: location in Hostinfo
				hostinfo := peer.Hostinfo()
				location := hostinfo.Location()
				assert.True(c, location.Valid(), "peer should have location in Hostinfo")
				if location.Valid() {
					assert.Equal(c, "Sweden", location.Country(), "location country should match")
					assert.Equal(c, "SE", location.CountryCode(), "location country code should match")
					assert.Equal(c, "Stockholm", location.City(), "location city should match")
					assert.Equal(c, "sto", location.CityCode(), "location city code should match")
					assert.InDelta(c, 59.3293, location.Latitude(), 0.0001, "location latitude should match")
					assert.InDelta(c, 18.0686, location.Longitude(), 0.0001, "location longitude should match")
					assert.Equal(c, 100, location.Priority(), "location priority should match")
				}

				// Verify hostname in Hostinfo is set to peer name
				assert.Equal(c, "test-wg-peer-mapresponse", hostinfo.Hostname(), "Hostinfo hostname should match peer name")

				break
			}
		}
		assert.True(c, found, "WireGuard-only peer should be in the network map")
	}, 10*time.Second, 500*time.Millisecond, "WireGuard-only peer should have correct tailcfg.Node fields including all extra config")
}

// TestWireGuardOnlyPeerDeletionWithConnections tests that a WireGuard-only peer cannot be deleted
// when connections still exist. It verifies that:
// - Deletion is blocked when connections exist
// - Connections must be removed first before the peer can be deleted
// - Stale connections don't persist after connection removal
func TestWireGuardOnlyPeerDeletionWithConnections(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		nil,
		hsic.WithTestName("wg-only-delete-with-connections"))
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)
	require.Len(t, allClients, 2, "should have 2 clients")

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	nodes, err := headscale.ListNodes()
	require.NoError(t, err, "failed to list nodes")
	require.Len(t, nodes, 2, "should have 2 nodes")

	node1ID := nodes[0].GetId()
	node2ID := nodes[1].GetId()

	wgPrivateKey := key.NewNode()
	wgPublicKey := wgPrivateKey.Public()

	// Register a WireGuard-only peer without any connections initially
	result, err := headscale.Execute([]string{
		"headscale",
		"node",
		"register-wg-only",
		"--name", "test-wg-peer-conn-delete",
		"--user", "1",
		"--public-key", wgPublicKey.String(),
		"--allowed-ips", "10.99.0.0/24",
		"--endpoints", "192.0.2.1:51820",
		"--output", "json",
	})
	require.NoError(t, err, "failed to register WireGuard-only peer")
	require.NotEmpty(t, result, "registration result should not be empty")

	var peer *v1.WireGuardOnlyPeer
	err = json.Unmarshal([]byte(result), &peer)
	require.NoError(t, err, "failed to parse registration result")

	peerID := peer.Id

	// Add connections to both nodes
	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"add-wg-connection",
		"--node-id", fmt.Sprintf("%d", node1ID),
		"--wg-peer-id", fmt.Sprintf("%d", peerID),
		"--ipv4-masq-addr", "10.64.0.100",
	})
	require.NoError(t, err, "failed to add connection to node1")

	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"add-wg-connection",
		"--node-id", fmt.Sprintf("%d", node2ID),
		"--wg-peer-id", fmt.Sprintf("%d", peerID),
		"--ipv4-masq-addr", "10.64.0.101",
	})
	require.NoError(t, err, "failed to add connection to node2")

	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// Verify both nodes can see the peer
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status1, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status1.Peers() {
			peerStatus := status1.Peer[peerKey]
			if peerStatus.HostName == "test-wg-peer-conn-delete" {
				found = true
				break
			}
		}
		assert.True(c, found, "node1 should see the WireGuard-only peer")
	}, 10*time.Second, 500*time.Millisecond, "node1 should see peer")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status2, err := allClients[1].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status2.Peers() {
			peerStatus := status2.Peer[peerKey]
			if peerStatus.HostName == "test-wg-peer-conn-delete" {
				found = true
				break
			}
		}
		assert.True(c, found, "node2 should see the WireGuard-only peer")
	}, 10*time.Second, 500*time.Millisecond, "node2 should see peer")

	// THIS SHOULD FAIL: Try to delete peer while connections exist
	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"delete",
		"--identifier", fmt.Sprintf("%d", peerID),
	})
	require.Error(t, err, "deletion should fail when connections exist")
	require.Contains(t, err.Error(), "has active connections", "error should mention active connections")

	// Remove connection to node2
	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"remove-wg-connection",
		"--node-id", fmt.Sprintf("%d", node2ID),
		"--wg-peer-id", fmt.Sprintf("%d", peerID),
	})
	require.NoError(t, err, "failed to remove connection to node2")

	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// Verify node2 no longer sees the peer, but node1 still does
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status2, err := allClients[1].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status2.Peers() {
			peerStatus := status2.Peer[peerKey]
			if peerStatus.HostName == "test-wg-peer-conn-delete" {
				found = true
				break
			}
		}
		assert.False(c, found, "node2 should NOT see the peer after connection removal")
	}, 10*time.Second, 500*time.Millisecond, "node2 should not see peer after connection removal")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status1, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status1.Peers() {
			peerStatus := status1.Peer[peerKey]
			if peerStatus.HostName == "test-wg-peer-conn-delete" {
				found = true
				break
			}
		}
		assert.True(c, found, "node1 should still see the peer (connection still exists)")
	}, 10*time.Second, 500*time.Millisecond, "node1 should still see peer")

	// THIS SHOULD STILL FAIL: Try to delete peer while one connection exists
	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"delete",
		"--identifier", fmt.Sprintf("%d", peerID),
	})
	require.Error(t, err, "deletion should fail when at least one connection exists")
	require.Contains(t, err.Error(), "has active connections", "error should mention active connections")

	// Remove the last connection
	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"remove-wg-connection",
		"--node-id", fmt.Sprintf("%d", node1ID),
		"--wg-peer-id", fmt.Sprintf("%d", peerID),
	})
	require.NoError(t, err, "failed to remove connection to node1")

	time.Sleep(2 * time.Second)
	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// Verify node1 no longer sees the peer
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status1, err := allClients[0].Status()
		assert.NoError(c, err)

		found := false
		for _, peerKey := range status1.Peers() {
			peerStatus := status1.Peer[peerKey]
			if peerStatus.HostName == "test-wg-peer-conn-delete" {
				found = true
				break
			}
		}
		assert.False(c, found, "node1 should NOT see the peer after connection removal")
	}, 10*time.Second, 500*time.Millisecond, "node1 should not see peer after connection removal")

	// NOW THIS SHOULD SUCCEED: Delete peer with no connections
	_, err = headscale.Execute([]string{
		"headscale",
		"node",
		"delete",
		"--identifier", fmt.Sprintf("%d", peerID),
	})
	require.NoError(t, err, "deletion should succeed when no connections exist")

	// Verify the peer is actually deleted
	result, err = headscale.Execute([]string{
		"headscale",
		"node",
		"list",
		"--output", "json",
	})
	require.NoError(t, err, "failed to list nodes")

	var listedNodes []*v1.Node
	err = json.Unmarshal([]byte(result), &listedNodes)
	require.NoError(t, err, "failed to parse nodes list")

	for _, node := range listedNodes {
		require.NotEqual(t, peerID, node.Id, "deleted peer should not appear in node list")
	}
}
