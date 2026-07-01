package v2

import (
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
)

// appConnectorsCap is the Tailscale capability key under which app connector
// configuration is delivered to a node via the nodeAttrs "app" field. App
// connectors are not a bespoke Headscale policy block: they ride the generic
// valued-capability path, exactly as a Tailscale-hosted control plane delivers
// them.
const appConnectorsCap = tailcfg.NodeCapability("tailscale.com/app-connectors")

// decodeAppConnectorAttrs decodes the app-connectors payloads on a node's
// CapMap into the real Tailscale [appctype.AppConnectorAttr]. Decoding through
// the upstream type (rather than a Headscale duplicate) asserts that the
// values Headscale passes through are wire-compatible with what a Tailscale
// client reads.
func decodeAppConnectorAttrs(t *testing.T, capMap tailcfg.NodeCapMap) []appctype.AppConnectorAttr {
	t.Helper()

	raws, ok := capMap[appConnectorsCap]
	if !ok {
		return nil
	}

	attrs := make([]appctype.AppConnectorAttr, 0, len(raws))

	for _, raw := range raws {
		var attr appctype.AppConnectorAttr

		require.NoError(t, json.Unmarshal([]byte(raw), &attr))
		attrs = append(attrs, attr)
	}

	return attrs
}

// TestAppConnectorViaNodeAttrs verifies that app connector configuration
// declared in nodeAttrs "app" lands in the CapMap of every node the target
// selects, and only those nodes. It reuses the shared nodeAttrs fixtures
// (node 3 = tag:server, node 4 = tag:client, nodes 1-2 = untagged).
func TestAppConnectorViaNodeAttrs(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["tag:server"],
			"app": {
				"tailscale.com/app-connectors": [
					{
						"name": "Internal Apps",
						"connectors": ["tag:server"],
						"domains": ["internal.example.com", "*.corp.example.com"]
					},
					{
						"name": "VPN Apps",
						"connectors": ["tag:server"],
						"domains": ["vpn.example.com"],
						"routes": ["10.0.0.0/8"]
					}
				]
			}
		}]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// The targeted node (tag:server, ID 3) receives both configs.
	attrs := decodeAppConnectorAttrs(t, pm.NodeCapMap(3))
	require.Len(t, attrs, 2)

	domains := make([]string, 0, len(attrs))
	for _, a := range attrs {
		domains = append(domains, a.Domains...)
	}

	assert.ElementsMatch(t,
		[]string{"internal.example.com", "*.corp.example.com", "vpn.example.com"},
		domains,
	)

	// The "routes" field round-trips through the upstream type.
	var withRoutes *appctype.AppConnectorAttr

	for i := range attrs {
		if attrs[i].Name == "VPN Apps" {
			withRoutes = &attrs[i]
		}
	}

	require.NotNil(t, withRoutes)
	assert.Equal(t,
		[]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		withRoutes.Routes,
	)

	// Nodes the target does not select get no app-connectors capability.
	assert.Nil(t, decodeAppConnectorAttrs(t, pm.NodeCapMap(1)), "untagged node")
	assert.Nil(t, decodeAppConnectorAttrs(t, pm.NodeCapMap(4)), "tag:client node")
}

// TestAppConnectorWildcardTarget verifies that a wildcard target delivers the
// app-connectors capability to every node, mirroring Tailscale's "*" target.
func TestAppConnectorWildcardTarget(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	policy := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["*"],
			"app": {
				"tailscale.com/app-connectors": [
					{"name": "All", "connectors": ["*"], "domains": ["*.example.com"]}
				]
			}
		}]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	for _, id := range []types.NodeID{1, 2, 3, 4, 5} {
		attrs := decodeAppConnectorAttrs(t, pm.NodeCapMap(id))
		require.Lenf(t, attrs, 1, "node %d", id)
		assert.Equal(t, []string{"*.example.com"}, attrs[0].Domains)
	}
}

// TestAppConnectorChangeTracking proves that app connector caps delivered via
// nodeAttrs.app participate in NodesWithChangedCapMap — the drain that drives
// per-node change.SelfUpdate on policy reload (hscontrol/state/state.go). This
// is why app connectors no longer need a PolicyChange{IncludeSelf:true}
// broadcast: a node whose app config changes is reported here and gets a
// targeted self-update through the same path as every other nodeAttrs cap.
func TestAppConnectorChangeTracking(t *testing.T) {
	t.Parallel()

	users := nodeAttrsTestUsers()
	nodes := nodeAttrsTestNodes(users)

	// Start with no nodeAttrs at all.
	base := `{"tagOwners": {` + nodeAttrsTagOwners + `}}`

	pm, err := NewPolicyManager([]byte(base), users, nodes.ViewSlice())
	require.NoError(t, err)

	require.Empty(t, pm.NodesWithChangedCapMap(),
		"no nodeAttrs means no node has a CapMap")

	// Add an app connector targeting tag:server (node 3 only).
	withConnector := `{
		"tagOwners": {` + nodeAttrsTagOwners + `},
		"nodeAttrs": [{
			"target": ["tag:server"],
			"app": {
				"tailscale.com/app-connectors": [
					{"name": "Internal", "connectors": ["tag:server"], "domains": ["internal.example.com"]}
				]
			}
		}]
	}`

	changed, err := pm.SetPolicy([]byte(withConnector))
	require.NoError(t, err)
	require.True(t, changed)

	delta := pm.NodesWithChangedCapMap()
	slices.Sort(delta)
	assert.Equal(t, []types.NodeID{3}, delta,
		"only the targeted node's app-connectors cap appeared")

	assert.Empty(t, pm.NodesWithChangedCapMap(),
		"NodesWithChangedCapMap drains on read")
}
