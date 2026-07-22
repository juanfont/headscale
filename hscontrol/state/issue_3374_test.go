package state

import (
	"fmt"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestTaggedReauthValidatesAgainstAuthUser reproduces issue #3374: an already
// tagged node (tag-owned, so neither UserID nor User is set and its IP is not
// in any tag owner's node set) cannot re-advertise a tag through the auth path
// — even a tag it already holds — when the authenticating user owns that tag.
//
// applyAuthNodeUpdate validates RequestTags against the existing tagged node
// instead of the authenticating user, so both NodeCanHaveTag paths (node IP in
// the tag-owner set, node's own user owns the tag) dead-end. The
// fresh-registration path validates against the authenticating user and works,
// so tagged->tagged re-auth is the only rejected case. The fix must still
// reject tags the authenticating user does not own.
//
// https://github.com/juanfont/headscale/issues/3374
func TestTaggedReauthValidatesAgainstAuthUser(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	// tagger owns tag:foo and performs the re-auth. The node is created under a
	// different user and then tag-owned, so its IP is not in tagger's node set —
	// the realistic tag-owned state, unlike a node that is still user-owned.
	tagger := database.CreateUserForTest("tagger")
	other := database.CreateUserForTest("other")
	node := database.CreateRegisteredNodeForTest(other, "tagged-node")
	machineKey := node.MachineKey
	nodeID := node.ID

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Make it genuinely tag-owned: tagged, neither UserID nor User set, as a node
	// registered with a tagged pre-auth key ends up. UserID nil routes the re-auth
	// through the convert-from-tag lookup.
	seeded, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = []string{"tag:foo"}
		n.UserID = nil
		n.User = nil
		n.Expiry = nil
	})
	require.True(t, ok)
	require.True(t, seeded.IsTagged(), "precondition: node must be tagged")

	// tagger owns tag:foo but not tag:bar.
	policy := fmt.Sprintf(`{"tagOwners":{"tag:foo":["%s@"],"tag:bar":["%s@"]}}`, tagger.Name, other.Name)
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)

	reauth := func(t *testing.T, tags []string) (types.NodeView, error) {
		t.Helper()

		regData := &types.RegistrationData{
			MachineKey: machineKey,
			NodeKey:    node.NodeKey,
			DiscoKey:   node.DiscoKey,
			Hostname:   "tagged-node",
			Hostinfo: &tailcfg.Hostinfo{
				Hostname:    "tagged-node",
				RequestTags: tags,
			},
		}

		authID := types.MustAuthID()
		s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))

		n, _, err := s.HandleNodeFromAuthPath(authID, types.UserID(tagger.ID), nil, util.RegisterMethodOIDC)

		return n, err
	}

	// tagger owns tag:foo, so re-advertising it must be permitted.
	finalNode, err := reauth(t, []string{"tag:foo"})
	require.NoError(t, err,
		"tag owner must be allowed to re-auth a tagged node re-advertising a tag they own")
	require.True(t, finalNode.Valid())
	require.True(t, finalNode.IsTagged(),
		"node should remain tagged after re-advertising a permitted tag")
	require.Contains(t, finalNode.Tags().AsSlice(), "tag:foo")

	// tag:bar is owned by other, not tagger, so it must still be rejected — the
	// fix authorises the authenticating user, it does not skip authorisation.
	_, err = reauth(t, []string{"tag:bar"})
	require.Error(t, err,
		"tags the authenticating user does not own must still be rejected")
}
