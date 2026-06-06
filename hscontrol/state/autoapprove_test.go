package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestAutoApproveBatchApprovesRoutes verifies the batched autoApproveNodes still
// approves a node's advertised route when policy auto-approvers permit it. The
// batching collapses the per-node SetApprovedRoutes calls into one NodeStore
// update and one policy rebuild; this guards that correctness is preserved.
func TestAutoApproveBatchApprovesRoutes(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")

	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	})
	require.True(t, ok)

	pol := `{
		"autoApprovers": {"routes": {"10.0.0.0/24": ["persist-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err := s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	_, err = s.ReloadPolicy()
	require.NoError(t, err)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Contains(t, nv.ApprovedRoutes().AsSlice(), route,
		"auto-approver should have approved the advertised route")
}
