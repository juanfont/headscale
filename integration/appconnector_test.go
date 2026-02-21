package integration

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestAppConnectorBasic tests that app connector configuration is properly
// propagated to nodes that advertise as app connectors and match the policy.
func TestAppConnectorBasic(t *testing.T) {
	IntegrationSkip(t)

	// Policy with app connector configuration
	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:connector": policyv2.Owners{usernameOwner("user1@")},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		AppConnectors: []policyv2.AppConnector{
			{
				Name:       "Internal Apps",
				Connectors: []string{"tag:connector"},
				Domains:    []string{"internal.example.com", "*.corp.example.com"},
			},
			{
				Name:       "VPN Apps",
				Connectors: []string{"tag:connector"},
				Domains:    []string{"vpn.example.com"},
				Routes:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 0, // We'll create nodes manually with specific tags
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("appconnector"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// Create a tagged node with tag:connector using PreAuthKey (tags-as-identity)
	taggedKey, err := scenario.CreatePreAuthKeyWithTags(
		userMap["user1"].GetId(), false, false, []string{"tag:connector"},
	)
	require.NoError(t, err)

	connectorNode, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithNetfilter("off"),
	)
	require.NoError(t, err)

	err = connectorNode.Login(headscale.GetEndpoint(), taggedKey.GetKey())
	require.NoError(t, err)

	err = connectorNode.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	// Verify the node has the tag:connector tag
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := connectorNode.Status()
		assert.NoError(c, err)
		assert.NotNil(c, status.Self.Tags, "Node should have tags")

		if status.Self.Tags != nil {
			assert.Contains(c, status.Self.Tags.AsSlice(), "tag:connector", "Node should have tag:connector")
		}
	}, 30*time.Second, 500*time.Millisecond, "Waiting for node to have correct tags")

	// Advertise as an app connector using tailscale set --advertise-connector
	t.Log("Advertising node as app connector")

	_, _, err = connectorNode.Execute([]string{
		"tailscale", "set", "--advertise-connector",
	})
	require.NoError(t, err)

	// Wait for the app connector capability to be propagated
	t.Log("Waiting for app connector capability to be propagated")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := connectorNode.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			assert.Fail(c, "Netmap or SelfNode is invalid")
			return
		}

		capMap := nm.SelfNode.CapMap()
		if capMap.IsNil() {
			assert.Fail(c, "CapMap is nil")
			return
		}

		appConnectorCap := tailcfg.NodeCapability("tailscale.com/app-connectors")
		attrs, hasCapability := capMap.GetOk(appConnectorCap)
		assert.True(c, hasCapability, "Node should have app-connectors capability")

		if hasCapability {
			// Verify we have the expected number of app connector configs
			assert.Equal(c, 2, attrs.Len(), "Should have 2 app connector configs")

			// Verify the content of the configs
			var allDomains []string

			for i := range attrs.Len() {
				var cfg policyv2.AppConnectorAttr

				err := json.Unmarshal([]byte(attrs.At(i)), &cfg)
				assert.NoError(c, err)

				allDomains = append(allDomains, cfg.Domains...)
			}

			assert.Contains(c, allDomains, "internal.example.com")
			assert.Contains(c, allDomains, "*.corp.example.com")
			assert.Contains(c, allDomains, "vpn.example.com")
		}
	}, 60*time.Second, 1*time.Second, "App connector capability should be propagated")
}

// TestAppConnectorNonMatchingTag tests that nodes without matching tags
// do not receive app connector configuration.
func TestAppConnectorNonMatchingTag(t *testing.T) {
	IntegrationSkip(t)

	// Policy with app connector configuration for tag:connector only
	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:connector": policyv2.Owners{usernameOwner("user1@")},
			"tag:other":     policyv2.Owners{usernameOwner("user1@")},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		AppConnectors: []policyv2.AppConnector{
			{
				Name:       "Internal Apps",
				Connectors: []string{"tag:connector"},
				Domains:    []string{"internal.example.com"},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("appconnector-nonmatch"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	// Create a node with tag:other (not tag:connector)
	taggedKey, err := scenario.CreatePreAuthKeyWithTags(
		userMap["user1"].GetId(), false, false, []string{"tag:other"},
	)
	require.NoError(t, err)

	otherNode, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithNetfilter("off"),
	)
	require.NoError(t, err)

	err = otherNode.Login(headscale.GetEndpoint(), taggedKey.GetKey())
	require.NoError(t, err)

	err = otherNode.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	// Verify the node has the tag:other tag
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := otherNode.Status()
		assert.NoError(c, err)
		assert.NotNil(c, status.Self.Tags, "Node should have tags")

		if status.Self.Tags != nil {
			assert.Contains(c, status.Self.Tags.AsSlice(), "tag:other", "Node should have tag:other")
		}
	}, 30*time.Second, 500*time.Millisecond, "Waiting for node to have correct tags")

	// Advertise as an app connector
	t.Log("Advertising node as app connector (should NOT receive config)")

	_, _, err = otherNode.Execute([]string{
		"tailscale", "set", "--advertise-connector",
	})
	require.NoError(t, err)

	// Verify the node does NOT have app connector capability
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := otherNode.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			return
		}

		capMap := nm.SelfNode.CapMap()
		if capMap.IsNil() {
			return
		}

		appConnectorCap := tailcfg.NodeCapability("tailscale.com/app-connectors")
		_, hasCapability := capMap.GetOk(appConnectorCap)
		assert.False(c, hasCapability, "Node with non-matching tag should NOT have app-connectors capability")
	}, 10*time.Second, 1*time.Second, "Verifying node does not receive app connector capability")
}

// TestAppConnectorWildcardConnector tests that a wildcard (*) connector
// matches all nodes that advertise as app connectors.
func TestAppConnectorWildcardConnector(t *testing.T) {
	IntegrationSkip(t)

	// Policy with wildcard connector
	policy := &policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		AppConnectors: []policyv2.AppConnector{
			{
				Name:       "All Connectors",
				Connectors: []string{"*"},
				Domains:    []string{"*.internal.example.com"},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 1, // Create a regular user node
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithNetfilter("off"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("appconnector-wildcard"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)
	require.Len(t, user1Clients, 1)

	regularNode := user1Clients[0]

	// Advertise as an app connector - with wildcard, any node should work
	t.Log("Advertising regular node as app connector with wildcard policy")

	_, _, err = regularNode.Execute([]string{
		"tailscale", "set", "--advertise-connector",
	})
	require.NoError(t, err)

	// Wait for the app connector capability to be propagated
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := regularNode.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			assert.Fail(c, "Netmap or SelfNode is invalid")
			return
		}

		capMap := nm.SelfNode.CapMap()
		if capMap.IsNil() {
			assert.Fail(c, "CapMap is nil")
			return
		}

		appConnectorCap := tailcfg.NodeCapability("tailscale.com/app-connectors")
		attrs, hasCapability := capMap.GetOk(appConnectorCap)
		assert.True(c, hasCapability, "Node should have app-connectors capability with wildcard connector")

		if hasCapability {
			assert.Equal(c, 1, attrs.Len(), "Should have 1 app connector config")

			// Verify the domain
			var cfg policyv2.AppConnectorAttr
			err := json.Unmarshal([]byte(attrs.At(0)), &cfg)
			assert.NoError(c, err)
			assert.Contains(c, cfg.Domains, "*.internal.example.com")
		}
	}, 60*time.Second, 1*time.Second, "App connector capability should be propagated with wildcard")
}
