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
	"tailscale.com/types/key"
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

// TestTaggedReauthWithReusedUserPAK reproduces issue #3312: a containerized
// node registered with a user-owned one-shot pre-auth key, then converted to a
// tagged node (UserID cleared to NULL), is logged out when the container
// restarts and re-registers with the SAME, now-used TS_AUTHKEY.
//
// Root cause: findExistingNodeForPAK (state.go) looks the node up by the PAK's
// owning user (alice). After tagging, the node is indexed under UserID(0), so
// the same-user machine-key lookup misses, the re-registration fast-path is
// skipped, and the already-used one-shot PAK is re-validated and rejected with
// "authkey already used" — logging the node out.
//
// https://github.com/juanfont/headscale/issues/3312
func TestTaggedReauthWithReusedUserPAK(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("authkey-user")

	policy := fmt.Sprintf(`{"tagOwners":{"tag:foo":["%s@"]}}`, user.Name)
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)

	// One-shot, user-owned PAK: `headscale preauthkeys create -u 1`.
	pak, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "authkey-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}

	// First registration: node joins as alice, the one-shot PAK is consumed.
	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, first.Valid())
	nodeID := first.ID()

	// `headscale nodes tag -t tag:foo`: convert to a tagged node. This clears
	// both UserID and User (state.SetNodeTags), diverging the node's ownership
	// from the still-user-owned PAK.
	tagged, _, err := s.SetNodeTags(nodeID, []string{"tag:foo"})
	require.NoError(t, err)
	require.True(t, tagged.IsTagged(), "precondition: node must be tagged")

	// Container restart: the same node re-registers with the SAME, now-used
	// one-shot TS_AUTHKEY. The machine key proves identity, so this must
	// succeed. It currently fails with "authkey already used".
	second, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err,
		"re-registration with a reused user PAK on a tagged node must not be rejected")
	require.True(t, second.Valid())
	require.True(t, second.IsTagged(), "node must remain tagged after re-registration")
	require.Equal(t, nodeID, second.ID(),
		"must update the existing node, not create a new one")
}

// reregisterExpiredUserNodeWithSpentKey registers a user-owned node with a
// one-shot key, forces it into the expired state, and re-registers with the
// same spent key. sameNodeKey distinguishes the two re-auth shapes:
//   - false: the node rotates its node key (normal tailscale client on re-auth)
//   - true:  the node reuses its node key
//
// In both cases an expired node is genuinely re-authenticating and must present
// a valid key; a spent one-shot key must be rejected.
func reregisterExpiredUserNodeWithSpentKey(t *testing.T, sameNodeKey bool) (types.NodeView, error) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("expired-user")

	pak, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "expired-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, first.Valid())
	require.False(t, first.IsTagged(), "precondition: node must be user-owned")

	// Force the node into the expired state.
	past := time.Now().Add(-1 * time.Hour)
	_, ok := s.nodeStore.UpdateNode(first.ID(), func(n *types.Node) {
		n.Expiry = &past
	})
	require.True(t, ok)

	reReg := regReq
	if !sameNodeKey {
		reReg.NodeKey = key.NewNode().Public()
	}

	node, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())

	return node, err
}

// TestExpiredUserNodeReusedOneShotKey_RotatedNodeKey: a node rotating its node
// key on re-auth is already a key rotation, so the key is re-validated.
func TestExpiredUserNodeReusedOneShotKey_RotatedNodeKey(t *testing.T) {
	_, err := reregisterExpiredUserNodeWithSpentKey(t, false)
	require.Error(t, err,
		"expired node re-authenticating with a rotated node key must present a valid key")
	require.Contains(t, err.Error(), "authkey already used")
}

// TestExpiredUserNodeReusedOneShotKey_SameNodeKey: the security boundary must
// not depend on the client rotating its node key. An expired node re-using its
// node key must still re-validate the key, otherwise a spent one-shot key
// silently re-authorises it.
func TestExpiredUserNodeReusedOneShotKey_SameNodeKey(t *testing.T) {
	_, err := reregisterExpiredUserNodeWithSpentKey(t, true)
	require.Error(t, err,
		"expired node re-registering with the same node key must re-validate its key")
	require.Contains(t, err.Error(), "authkey already used")
}

// TestReusableUserPAKReauthOnTaggedNodeNoDuplicate guards against a reusable
// user pre-auth key creating a second node when it is re-presented for a node
// that has since been converted to tagged. The node must be updated in place.
func TestReusableUserPAKReauthOnTaggedNodeNoDuplicate(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("reusable-user")

	policy := fmt.Sprintf(`{"tagOwners":{"tag:foo":["%s@"]}}`, user.Name)
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "reusable-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	_, _, err = s.SetNodeTags(first.ID(), []string{"tag:foo"})
	require.NoError(t, err)

	second, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, second.IsTagged())
	require.Equal(t, first.ID(), second.ID(), "must update in place, not duplicate")
	require.Equal(t, 1, s.ListNodes().Len(), "machine must map to exactly one node")
}

// TestTaggedPAKReauthConvertsUserOwnedNode ensures presenting a tagged pre-auth
// key for a machine that already has a user-owned node converts that node in
// place (same machine, new ownership) rather than creating a duplicate.
func TestTaggedPAKReauthConvertsUserOwnedNode(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("owner")

	userPak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: userPak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "owned-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}

	owned, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.False(t, owned.IsTagged(), "precondition: node is user-owned")

	// A tags-only key re-registers the same machine (same node key).
	taggedPak, err := s.CreatePreAuthKey(nil, true, false, nil, []string{"tag:foo"})
	require.NoError(t, err)

	convReq := regReq
	convReq.Auth = &tailcfg.RegisterResponseAuth{AuthKey: taggedPak.Key}

	converted, _, err := s.HandleNodeFromPreAuthKey(convReq, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, owned.ID(), converted.ID(), "must convert in place, not duplicate")
	require.True(t, converted.IsTagged(), "node must become tagged")
	require.Equal(t, []string{"tag:foo"}, converted.Tags().AsSlice())
	require.Equal(t, 1, s.ListNodes().Len(), "machine must map to exactly one node")
}

// registerTwoUsersOnOneMachine registers two user-owned nodes that share a
// machine key (the "create new, do not transfer" multi-user device state) and
// returns the State and the shared machine key.
func registerTwoUsersOnOneMachine(t *testing.T) (*State, key.MachinePublic, types.NodeID) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	u1 := s.CreateUserForTest("u1")
	u2 := s.CreateUserForTest("u2")
	mk := key.NewMachine()

	reg := func(pakUser *types.User) types.NodeView {
		pak, err := s.CreatePreAuthKey(pakUser.TypedID(), true, false, nil, nil)
		require.NoError(t, err)
		n, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: "multi"},
			Expiry:   time.Now().Add(24 * time.Hour),
		}, mk.Public())
		require.NoError(t, err)

		return n
	}

	n1 := reg(u1)
	n2 := reg(u2)
	require.NotEqual(t, n1.ID(), n2.ID(), "precondition: two distinct nodes share the machine key")
	require.Equal(t, 2, s.ListNodes().Len())

	return s, mk.Public(), n1.ID()
}

// TestTaggedPAKReauthRejectsAmbiguousMultiUserNode: a tagged pre-auth key on a
// machine that has more than one user-owned node cannot know which to convert,
// so the registration is rejected rather than converting an arbitrary one and
// orphaning the rest.
func TestTaggedPAKReauthRejectsAmbiguousMultiUserNode(t *testing.T) {
	s, mk, _ := registerTwoUsersOnOneMachine(t)

	taggedPak, err := s.CreatePreAuthKey(nil, true, false, nil, []string{"tag:foo"})
	require.NoError(t, err)

	_, _, err = s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: taggedPak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "multi"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}, mk)
	require.ErrorIs(t, err, ErrAmbiguousNodeOwnership)
	require.Equal(t, 2, s.ListNodes().Len(), "no node created or converted on rejection")
}

// TestAuthPathRejectsTaggedAndUserCoexistence: if a machine key ends up with
// both a tagged node and a user-owned node (impossible per validateNodeOwnership,
// but reachable by tagging one node of a multi-user device via the admin path),
// an OIDC re-auth must reject rather than silently converting the tagged node
// and orphaning the user-owned one.
func TestAuthPathRejectsTaggedAndUserCoexistence(t *testing.T) {
	s, mk, n1 := registerTwoUsersOnOneMachine(t)

	// Tag one of the two user-owned nodes -> {0: tagged, u2: user-owned} coexist.
	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:foo":["u1@"]}}`))
	require.NoError(t, err)
	tagged, _, err := s.SetNodeTags(n1, []string{"tag:foo"})
	require.NoError(t, err)
	require.True(t, tagged.IsTagged())

	// A third user authenticates the same machine via OIDC.
	u3 := s.CreateUserForTest("u3")
	regData := &types.RegistrationData{
		MachineKey: mk,
		NodeKey:    key.NewNode().Public(),
		Hostname:   "multi",
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "multi"},
	}
	authID := types.MustAuthID()
	s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))

	_, _, err = s.HandleNodeFromAuthPath(authID, types.UserID(u3.ID), nil, util.RegisterMethodOIDC)
	require.ErrorIs(t, err, ErrAmbiguousNodeOwnership)
}

// TestTaggedNodeCanHaveKeyExpiry matches Tailscale: a tagged node has key
// expiry disabled by default, but it can still be set explicitly (e.g. via
// `headscale nodes expire`).
func TestTaggedNodeCanHaveKeyExpiry(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{"tagOwners":{"tag:foo":["tagger@"]}}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(nil, true, false, nil, []string{"tag:foo"})
	require.NoError(t, err)

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "tagged-node"},
	}
	node, _, err := s.HandleNodeFromPreAuthKey(regReq, key.NewMachine().Public())
	require.NoError(t, err)
	require.True(t, node.IsTagged())
	require.Nil(t, node.AsStruct().Expiry, "key expiry is disabled by default for tagged nodes")

	expiry := time.Now().Add(24 * time.Hour)
	after, _, err := s.SetNodeExpiry(node.ID(), &expiry)
	require.NoError(t, err)
	require.True(t, after.IsTagged(), "node stays tagged")
	require.NotNil(t, after.AsStruct().Expiry, "expiry can be set on a tagged node")
	require.Equal(t, expiry.Unix(), after.AsStruct().Expiry.Unix())
}

// TestTaggingPreservesNodeExpiry matches Tailscale: changing a node's tags does
// not alter its key expiry (expiry only changes on re-authentication).
func TestTaggingPreservesNodeExpiry(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("owner")

	_, err = s.SetPolicy(fmt.Appendf(nil, `{"tagOwners":{"tag:foo":["%s@"]}}`, user.Name))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	expiry := time.Now().Add(24 * time.Hour)
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "owned-node"},
		Expiry:   expiry,
	}
	node, _, err := s.HandleNodeFromPreAuthKey(regReq, key.NewMachine().Public())
	require.NoError(t, err)
	require.NotNil(t, node.AsStruct().Expiry, "precondition: user node has an expiry")

	tagged, _, err := s.SetNodeTags(node.ID(), []string{"tag:foo"})
	require.NoError(t, err)
	require.True(t, tagged.IsTagged())
	require.NotNil(t, tagged.AsStruct().Expiry, "tag change must not clear expiry")
	require.Equal(t, expiry.Unix(), tagged.AsStruct().Expiry.Unix())
}
