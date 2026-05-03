package integration

import (
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestNodeAttrsBasic verifies that nodeAttrs are compiled and distributed
// to Tailscale clients via MapResponse in a real Docker environment.
// It validates self-node CapMap and peer CapMap visibility.
func TestNodeAttrsBasic(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	assertTimeout := 60 * time.Second

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"alice", "bob"},
		Versions:     []string{"latest"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	pol := &policyv2.Policy{
		NodeAttrs: []policyv2.NodeAttrGrant{
			{
				Targets: []string{"alice@"},
				Attrs:   []string{"funnel", "custom:abac-allow"},
			},
		},
		Grants: []policyv2.Grant{
			{
				Sources:      policyv2.Aliases{userp("alice@"), userp("bob@")},
				Destinations: policyv2.Aliases{userp("alice@"), userp("bob@")},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
		},
	}

	_, err = scenario.Headscale(
		hsic.WithTestName("nodeattrs-basic"),
		hsic.WithACLPolicy(pol),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrGetHeadscale(t, err)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("nodeattrs-basic"))
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)

	// Wait for all peers to be visible.
	for _, client := range allClients {
		err = client.WaitForPeers(len(allClients)-1, 60*time.Second, 1*time.Second)
		require.NoErrorf(t, err, "client %s failed to see all peers", client.Hostname())
	}

	// Identify clients by user. Each user has NodesPerUser=1 client.
	var aliceClient, bobClient TailscaleClient
	for _, c := range scenario.GetOrCreateUser("alice").Clients {
		aliceClient = c
	}
	for _, c := range scenario.GetOrCreateUser("bob").Clients {
		bobClient = c
	}
	require.NotNil(t, aliceClient, "alice client not found")
	require.NotNil(t, bobClient, "bob client not found")

	// ===== Phase 1: Alice's self node has the capabilities =====
	t.Log("Phase 1: Validate alice's self CapMap")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := aliceClient.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("funnel")),
			"alice self should have funnel")
		assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
			"alice self should have custom:abac-allow")
	}, assertTimeout, 500*time.Millisecond,
		"alice should have nodeAttrs capabilities in self CapMap")

	// ===== Phase 2: Bob's self node does NOT have the capabilities =====
	t.Log("Phase 2: Validate bob's self CapMap lacks the capabilities")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := bobClient.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.False(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("funnel")),
			"bob self should NOT have funnel")
		assert.False(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
			"bob self should NOT have custom:abac-allow")
	}, assertTimeout, 500*time.Millisecond,
		"bob should not have nodeAttrs capabilities in self CapMap")

	// ===== Phase 3: Bob sees alice WITH the capabilities =====
	t.Log("Phase 3: Validate peer CapMap visibility")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := bobClient.Netmap()
		assert.NoError(c, err)
		if nm == nil {
			return
		}

		for _, peer := range nm.Peers {
			hi := peer.Hostinfo()
			if !hi.Valid() || hi.Hostname() != aliceClient.Hostname() {
				continue
			}

			assert.True(c, peer.HasCap(tailcfg.NodeCapability("funnel")),
				"bob should see alice with funnel")
			assert.True(c, peer.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
				"bob should see alice with custom:abac-allow")
		}
	}, assertTimeout, 500*time.Millisecond,
		"bob should see alice's capabilities in peer CapMap")

	// ===== Phase 4: Alice sees bob WITHOUT the custom capability =====
	t.Log("Phase 4: Validate alice sees bob without the capabilities")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := aliceClient.Netmap()
		assert.NoError(c, err)
		if nm == nil {
			return
		}

		for _, peer := range nm.Peers {
			hi := peer.Hostinfo()
			if !hi.Valid() || hi.Hostname() != bobClient.Hostname() {
				continue
			}

			assert.False(c, peer.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
				"alice should see bob without custom:abac-allow")
		}
	}, assertTimeout, 500*time.Millisecond,
		"alice should see bob without capabilities in peer CapMap")
}

// TestNodeAttrsTagTarget verifies that nodeAttrs can target tags
// instead of users, and that only tagged nodes receive capabilities.
func TestNodeAttrsTagTarget(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	assertTimeout := 60 * time.Second

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{"tag-owner"},
		Versions:     []string{"latest"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	pol := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:abac-node"): policyv2.Owners{usernameOwner("tag-owner@")},
		},
		NodeAttrs: []policyv2.NodeAttrGrant{
			{
				Targets: []string{"tag:abac-node"},
				Attrs:   []string{"custom:abac-allow"},
			},
		},
		Grants: []policyv2.Grant{
			{
				Sources:      policyv2.Aliases{tagp("tag:abac-node"), userp("tag-owner@")},
				Destinations: policyv2.Aliases{tagp("tag:abac-node"), userp("tag-owner@")},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("nodeattrs-tag"),
		hsic.WithACLPolicy(pol),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrGetHeadscale(t, err)

	_, err = scenario.CreateUser("tag-owner")
	require.NoError(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// Get the default network for the scenario.
	defaultNet := scenario.Networks()[0]

	// Create tagged node.
	taggedNode, err := scenario.CreateTailscaleNode("latest", tsic.WithNetwork(defaultNet))
	require.NoError(t, err)
	defer func() { _, _, _ = taggedNode.Shutdown() }()

	pakTagged, err := scenario.CreatePreAuthKeyWithTags(
		userMap["tag-owner"].GetId(), false, false, []string{"tag:abac-node"},
	)
	require.NoError(t, err)
	err = taggedNode.Login(headscale.GetEndpoint(), pakTagged.GetKey())
	require.NoError(t, err)
	err = taggedNode.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// Create plain (untagged) node.
	plainNode, err := scenario.CreateTailscaleNode("latest", tsic.WithNetwork(defaultNet))
	require.NoError(t, err)
	defer func() { _, _, _ = plainNode.Shutdown() }()

	pakPlain, err := scenario.CreatePreAuthKeyWithTags(
		userMap["tag-owner"].GetId(), false, false, []string{},
	)
	require.NoError(t, err)
	err = plainNode.Login(headscale.GetEndpoint(), pakPlain.GetKey())
	require.NoError(t, err)
	err = plainNode.WaitForRunning(30 * time.Second)
	require.NoError(t, err)

	// Wait for peers.
	err = taggedNode.WaitForPeers(1, 60*time.Second, 1*time.Second)
	require.NoError(t, err)
	err = plainNode.WaitForPeers(1, 60*time.Second, 1*time.Second)
	require.NoError(t, err)

	// ===== Phase 1: Tagged node has the capability =====
	t.Log("Phase 1: Validate tagged node has custom:abac-allow")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := taggedNode.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
			"tagged node should have custom:abac-allow")
	}, assertTimeout, 500*time.Millisecond,
		"tagged node should have nodeAttrs capability")

	// ===== Phase 2: Plain node does NOT have the capability =====
	t.Log("Phase 2: Validate plain node lacks custom:abac-allow")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := plainNode.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.False(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
			"plain node should NOT have custom:abac-allow")
	}, assertTimeout, 500*time.Millisecond,
		"plain node should not have nodeAttrs capability")

	// ===== Phase 3: Plain node sees tagged node WITH capability =====
	t.Log("Phase 3: Validate peer CapMap visibility for tag target")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := plainNode.Netmap()
		assert.NoError(c, err)
		if nm == nil {
			return
		}

		for _, peer := range nm.Peers {
			hi := peer.Hostinfo()
			if !hi.Valid() {
				continue
			}
			assert.True(c, peer.HasCap(tailcfg.NodeCapability("custom:abac-allow")),
				"plain node should see tagged peer with custom:abac-allow")
		}
	}, assertTimeout, 500*time.Millisecond,
		"plain node should see tagged peer with capability")
}

// TestNodeAttrsDynamicUpdate verifies that CapMap is updated when
// policy is changed at runtime.
func TestNodeAttrsDynamicUpdate(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	assertTimeout := 60 * time.Second

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"dynamic-user"},
		Versions:     []string{"latest"},
	}

	scenario, err := NewScenario(spec)
	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	// Start with a policy that has NO nodeAttrs.
	polInitial := &policyv2.Policy{
		Grants: []policyv2.Grant{
			{
				Sources:      policyv2.Aliases{userp("dynamic-user@")},
				Destinations: policyv2.Aliases{userp("dynamic-user@")},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithTestName("nodeattrs-dynamic"),
		hsic.WithACLPolicy(polInitial),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	requireNoErrGetHeadscale(t, err)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("nodeattrs-dynamic"))
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 1)

	client := allClients[0]

	err = client.WaitForPeers(0, 30*time.Second, 1*time.Second)
	require.NoError(t, err)

	// ===== Phase 1: Initial policy has no nodeAttrs =====
	t.Log("Phase 1: Validate no capabilities before policy update")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := client.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.False(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("funnel")),
			"client should NOT have funnel before policy update")
	}, assertTimeout, 500*time.Millisecond,
		"client should start without capabilities")

	// ===== Phase 2: Update policy to add nodeAttrs =====
	t.Log("Phase 2: Update policy to add nodeAttrs")

	polUpdated := &policyv2.Policy{
		NodeAttrs: []policyv2.NodeAttrGrant{
			{
				Targets: []string{"dynamic-user@"},
				Attrs:   []string{"funnel"},
			},
		},
		Grants: []policyv2.Grant{
			{
				Sources:      policyv2.Aliases{userp("dynamic-user@")},
				Destinations: policyv2.Aliases{userp("dynamic-user@")},
				InternetProtocols: []policyv2.ProtocolPort{
					{Protocol: "*", Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}},
				},
			},
		},
	}

	err = headscale.SetPolicy(polUpdated)
	require.NoError(t, err)

	// ===== Phase 3: Client receives updated CapMap =====
	t.Log("Phase 3: Validate client receives funnel after policy update")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := client.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.True(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("funnel")),
			"client should have funnel after policy update")
	}, assertTimeout, 500*time.Millisecond,
		"client should receive updated CapMap after policy change")

	// ===== Phase 4: Update policy to remove nodeAttrs =====
	t.Log("Phase 4: Update policy to remove nodeAttrs")

	err = headscale.SetPolicy(polInitial)
	require.NoError(t, err)

	// ===== Phase 5: Capability is removed =====
	t.Log("Phase 5: Validate capability is removed after policy revert")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := client.Netmap()
		assert.NoError(c, err)
		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		assert.False(c, nm.SelfNode.HasCap(tailcfg.NodeCapability("funnel")),
			"client should NOT have funnel after policy revert")
	}, assertTimeout, 500*time.Millisecond,
		"client should lose CapMap entry after policy removal")
}

// userp returns a user Alias for policy v2 configurations.
func userp(name string) policyv2.Alias {
	return new(policyv2.Username(name))
}
