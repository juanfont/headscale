package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestPersistNodeDoesNotClobberConcurrentAdminWrite ensures that persisting a
// node snapshot captured earlier (as UpdateNodeFromMapRequest does at the top
// of its body) cannot overwrite a concurrent admin write (SetNodeTags) that
// landed in between. NodeStore is the source of truth; the database row must
// converge on it rather than reverting to the stale snapshot.
func TestPersistNodeDoesNotClobberConcurrentAdminWrite(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	pol := `{
		"tagOwners": {"tag:foo": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err := s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	before, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.False(t, before.IsTagged(), "node should start user-owned")
	require.True(t, before.UserID().Valid(), "node should start with a UserID")

	// (1) Map-request captures the node snapshot (the stale view).
	staleView, ok := s.nodeStore.GetNode(nodeID)
	require.True(t, ok)

	staleNode := staleView.AsStruct()
	staleNode.Hostinfo = &tailcfg.Hostinfo{Hostname: "persist-node"}
	staleView = staleNode.View()

	// (2) Concurrent admin SetNodeTags lands in the window: NodeStore + DB
	// become tagged and user ownership is cleared.
	_, _, err = s.SetNodeTags(nodeID, []string{"tag:foo"})
	require.NoError(t, err)

	dbAfterAdmin, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []string{"tag:foo"}, dbAfterAdmin.Tags.List(),
		"precondition: admin SetNodeTags must have written the tag to the DB")

	// (3) Map-request persists its stale snapshot.
	_, _, err = s.persistNodeToDB(staleView)
	require.NoError(t, err)

	// The admin write must survive.
	dbFinal, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Equal(t, []string{"tag:foo"}, dbFinal.Tags.List(),
		"DB tags must reflect the admin SetNodeTags, not the stale persist")
	assert.Nil(t, dbFinal.UserID,
		"DB UserID must stay nil after tagging (tags XOR user ownership)")

	// Restart: the divergence would surface here in production.
	require.NoError(t, s.Close())
	s2 := persistTestReopen(t, dbPath)

	reloaded, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok, "node should reload from DB after restart")
	assert.True(t, reloaded.IsTagged(),
		"after restart the node must still be tagged")
	assert.Equal(t, []string{"tag:foo"}, reloaded.AsStruct().Tags.List(),
		"after restart the node must still carry tag:foo")
}
