package state

import (
	"fmt"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestTaggedReauthKeepsNilExpiry ensures that when an existing tagged node
// re-authenticates through the auth path and re-advertises a tag it is still
// permitted to hold, it stays tagged AND keeps key-expiry disabled (nil).
// Tagged nodes never expire, so applyAuthNodeUpdate must not assign an expiry
// to a node that remains tagged just because the auth used the
// convert-from-tag lookup path.
func TestTaggedReauthKeepsNilExpiry(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("reauth-user")
	node := database.CreateRegisteredNodeForTest(user, "reauth-node")
	machineKey := node.MachineKey
	nodeID := node.ID
	nodeKey := node.NodeKey
	discoKey := node.DiscoKey

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Make the node tagged with tag:foo and Expiry=nil. Leaving UserID nil
	// indexes it under userID 0 so the same-user machine-key lookup misses and
	// HandleNodeFromAuthPath takes the convert-from-tag branch. The User field
	// is retained for created-by tracking, which lets the tag re-advertisement
	// be permitted.
	seeded, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = []string{"tag:foo"}
		n.UserID = nil
		n.User = user
		n.Expiry = nil
	})
	require.True(t, ok)
	require.True(t, seeded.IsTagged(), "precondition: node must be tagged")
	require.True(t, seeded.Valid())

	policy := fmt.Sprintf(`{"tagOwners":{"tag:foo":["%s@"]}}`, user.Name)
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)
	require.True(t, s.NodeCanHaveTag(seeded, "tag:foo"),
		"precondition: tagged node must be permitted to re-advertise tag:foo")

	// Registration that re-advertises tag:foo and carries a non-nil client
	// expiry (the normal tailscale client case).
	clientExpiry := time.Now().Add(180 * 24 * time.Hour)
	regData := &types.RegistrationData{
		MachineKey: machineKey,
		NodeKey:    nodeKey,
		DiscoKey:   discoKey,
		Hostname:   "reauth-node",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "reauth-node",
			RequestTags: []string{"tag:foo"},
		},
		Expiry: &clientExpiry,
	}

	authID := types.MustAuthID()
	s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))

	finalNode, _, err := s.HandleNodeFromAuthPath(
		authID,
		types.UserID(user.ID),
		nil,
		util.RegisterMethodOIDC,
	)
	require.NoError(t, err)
	require.True(t, finalNode.Valid())

	require.True(t, finalNode.IsTagged(),
		"node should remain tagged after re-advertising a permitted tag")

	require.Nil(t, finalNode.AsStruct().Expiry,
		"tagged node must keep nil key expiry (tagged nodes never expire)")
}
