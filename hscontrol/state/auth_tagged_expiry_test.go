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

// TestIssue3371_TaggedNodeInteractiveReloginAfterLogout reproduces the
// interactive/OIDC arm of https://github.com/juanfont/headscale/issues/3371
// ("With no key (interactive): the register URL is printed and the login never
// completes").
//
// A logout stamps a stale PAST expiry on a tagged node. When the node
// re-authenticates through the auth path (HandleNodeFromAuthPath ->
// applyAuthNodeUpdate), the tagged->tagged branch keeps the existing expiry
// ("Tagged → Tagged: keep existing expiry (nil) - no action needed",
// state.go). That comment assumes the existing expiry is nil; after a logout it
// is a past timestamp, so the node stays expired. The fix must clear a stale
// past expiry on a node that remains tagged (scoped to IsExpired(), so a
// deliberate future expiry is preserved).
func TestIssue3371_TaggedNodeInteractiveReloginAfterLogout(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("interactive-user")
	node := database.CreateRegisteredNodeForTest(user, "interactive-tagged")
	machineKey := node.MachineKey
	nodeID := node.ID
	discoKey := node.DiscoKey

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Make the node tagged with a stale PAST expiry (the state a `tailscale
	// logout` leaves behind). Leaving UserID nil but retaining User routes the
	// re-auth through the convert-from-tag branch and lets the tag
	// re-advertisement be permitted (mirrors TestTaggedReauthKeepsNilExpiry,
	// which seeds Expiry=nil; here the only change is a past expiry).
	past := time.Now().Add(-1 * time.Hour)
	seeded, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = []string{"tag:foo"}
		n.UserID = nil
		n.User = user
		n.Expiry = &past
	})
	require.True(t, ok)
	require.True(t, seeded.IsTagged(), "precondition: node is tagged")
	require.True(t, seeded.IsExpired(), "precondition: logout left the tagged node expired")

	policy := fmt.Sprintf(`{"tagOwners":{"tag:foo":["%s@"]}}`, user.Name)
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)
	require.True(t, s.NodeCanHaveTag(seeded, "tag:foo"),
		"precondition: tagged node is permitted to re-advertise tag:foo")

	// Interactive/OIDC relogin: the client re-advertises the same tag (rotating
	// its node key, as a real client does). The node must come back not-expired.
	regData := &types.RegistrationData{
		MachineKey: machineKey,
		NodeKey:    key.NewNode().Public(),
		DiscoKey:   discoKey,
		Hostname:   "interactive-tagged",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "interactive-tagged",
			RequestTags: []string{"tag:foo"},
		},
	}
	authID := types.MustAuthID()
	s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(regData))

	relogged, _, err := s.HandleNodeFromAuthPath(
		authID, types.UserID(user.ID), nil, util.RegisterMethodOIDC,
	)
	require.NoError(t, err)
	require.True(t, relogged.Valid())

	require.True(t, relogged.IsTagged(), "node stays tagged after interactive relogin")
	require.False(t, relogged.IsExpired(),
		"issue #3371: interactive relogin must clear the stale logout expiry")
	require.Nil(t, relogged.AsStruct().Expiry,
		"issue #3371: tagged node must have key-expiry disabled after interactive relogin")
}

// TestIssue3371_TaggedNodePastExpirySelfHealsOnReregister covers the 0.29.x
// upgrade path: a tagged node broken by an OLDER headscale carries a past
// expiry persisted in its DB row. After a restart (State reloads the row) it
// comes back expired, and its next auth-key re-registration must self-heal it
// by clearing the stale past expiry. This is the "part b" defensive clear.
func TestIssue3371_TaggedNodePastExpirySelfHealsOnReregister(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)

	_, err = s.SetPolicy([]byte(`{"tagOwners":{"tag:foo":["tagger@"]}}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(nil, true, false, nil, []string{"tag:foo"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "broken-tagged"},
	}
	node, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	nodeID := node.ID()

	// A prior (buggy) version persisted a past expiry on this tagged node.
	past := time.Now().Add(-1 * time.Hour)
	err = s.DB().NodeSetExpiry(nodeID, &past)
	require.NoError(t, err)

	// Restart: reload State from the same database file.
	require.NoError(t, s.Close())

	s2, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })

	reloaded, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, reloaded.IsExpired(),
		"precondition: a persisted past expiry survives restart and re-triggers the lockout")

	// Re-register (rotating the node key). The stale past expiry must be cleared.
	reregReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "broken-tagged"},
	}
	healed, _, err := s2.HandleNodeFromPreAuthKey(reregReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, healed.IsTagged(), "node stays tagged")
	require.False(t, healed.IsExpired(),
		"issue #3371: re-registration must self-heal a tagged node broken by an older version")
	require.Nil(t, healed.AsStruct().Expiry,
		"issue #3371: self-healed tagged node must have key-expiry disabled (DB NULL)")
	require.Equal(t, nodeID, healed.ID(), "must be the same node")
}

// TestIssue3371_ExpiredTaggedNodeSameSpentKeyNotRevalidated is the gating test
// for the isExpired-gate exclusion (state.go: `&& !existingNodeSameUser.IsTagged()`).
// A tagged node carrying a stale PAST expiry, re-registering with the SAME
// single-use key and the SAME node key (no rotation), must take the
// skip-validation fast path — otherwise the spent key is re-validated and
// rejected with "authkey already used", the exact lockout #3371 fixes. Without
// the tagged exclusion this fails; with it the node self-heals. The neighbours
// all rotate the node key or use a reusable key, so validation runs regardless
// and none probes this fast-path exclusion.
func TestIssue3371_ExpiredTaggedNodeSameSpentKeyNotRevalidated(t *testing.T) {
	s := newRetagTestState(t)

	// Single-use tagged key.
	pak, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:foo"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "spent-tagged"},
	}
	node, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, node.IsTagged())

	// Stale past (logout) expiry, and the single-use key is now spent.
	past := time.Now().Add(-1 * time.Hour)
	_, ok := s.nodeStore.UpdateNode(node.ID(), func(n *types.Node) {
		n.Expiry = &past
	})
	require.True(t, ok)

	// Re-register with the SAME key and the SAME node key (no rotation). The
	// tagged exclusion from the isExpired gate must let this skip validation, so
	// the spent single-use key is not rejected.
	healed, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err,
		"a tagged node with a stale past expiry must skip re-validation of its spent key")
	require.False(t, healed.IsExpired(), "stale expiry cleared")
	require.Nil(t, healed.AsStruct().Expiry, "tagged node key-expiry disabled")
	require.Equal(t, node.ID(), healed.ID())
}

// TestTaggedPAKReauthRetagsExistingTaggedNode reproduces issue #3370: an
// already-tagged node re-authenticating with a *fresh, valid* tagged pre-auth
// key carrying *different* tags has that key validated and consumed, but its
// tags are silently discarded — the node keeps its old tags.
//
// Root cause: the in-place re-registration path in HandleNodeFromPreAuthKey
// only applies a key's tags when a tagged key converts a user-owned node
// (`pak.IsTagged() && !node.IsTagged()`). An already-tagged node fails
// `!node.IsTagged()`, so a differently-tagged key leaves the tags unchanged —
// while the single-use key is still marked used below (hsdb.UsePreAuthKey).
//
// Tagged-PAK tags are authorised by possession of the key (only syntactic
// `tag:` validation at creation; no tagOwners policy is required — the bug
// reproduces with an empty policy). Re-keying is Tailscale's documented method
// for changing an auth-key device's tags, so a fresh key's tags must be
// applied on re-registration.
//
// https://github.com/juanfont/headscale/issues/3370
func TestTaggedPAKReauthRetagsExistingTaggedNode(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Empty policy: tagged-PAK tags need no tagOwners entry (issue reproduces
	// with a completely empty policy).

	// KEY1: single-use tags-only key carrying tag:tag1.
	key1, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag1"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key1.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "retag-node"},
	}

	// Initial registration: node comes up tagged tag:tag1.
	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, first.IsTagged(), "precondition: node registered tagged")
	require.Equal(t, []string{"tag:tag1"}, first.Tags().AsSlice())
	nodeID := first.ID()
	firstIPv4 := first.IPv4()
	firstIPv6 := first.IPv6()

	// KEY2: fresh single-use tags-only key carrying tag:tag2.
	key2, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag2"})
	require.NoError(t, err)

	// `tailscale up --force-reauth --auth-key KEY2`: same machine, rotated node
	// key, fresh valid key. This validates and consumes KEY2.
	reReg := regReq
	reReg.Auth = &tailcfg.RegisterResponseAuth{AuthKey: key2.Key}
	reReg.NodeKey = key.NewNode().Public()

	second, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, nodeID, second.ID(), "must update in place, not duplicate")
	require.Equal(t, 1, s.ListNodes().Len(), "machine must map to exactly one node")
	require.True(t, second.IsTagged(), "node must remain tagged")

	// KEY2 was validated and consumed regardless of the outcome.
	consumed, err := s.GetPreAuthKeyByID(key2.ID)
	require.NoError(t, err)
	require.True(t, consumed.Used, "single-use key was consumed by the re-auth")

	// The consumed key's tags must be applied: re-keying retags the device
	// (Tailscale's documented behaviour). This is the assertion that fails
	// before the fix — the node keeps ["tag:tag1"].
	require.Equal(t, []string{"tag:tag2"}, second.Tags().AsSlice(),
		"re-authenticating with a differently-tagged key must retag the node, "+
			"not silently discard the tags of the consumed key")

	// Identity continuity: the reporter stresses "same node, same IP". The
	// re-auth updates in place, so the machine key and both Tailscale IPs are
	// preserved while the node key rotates. A retag must not re-allocate IPs or
	// duplicate the node.
	require.Equal(t, machineKey.Public(), second.MachineKey(),
		"machine key is the stable identity across re-auth")
	require.Equal(t, firstIPv4, second.IPv4(), "IPv4 preserved across retag")
	require.Equal(t, firstIPv6, second.IPv6(), "IPv6 preserved across retag")
	require.NotEqual(t, first.NodeKey(), second.NodeKey(),
		"--force-reauth rotates the node key")

	// A retagged node stays a tagged node: user-less and key-expiry disabled.
	require.Nil(t, second.AsStruct().Expiry, "tagged node keeps nil key expiry")
}

// TestTaggedPAKReauthSameKeyPreservesTags is the counterpart constraint to
// #3370: re-authenticating with the *same* tagged key must NOT clobber the
// node's current tags, even after an admin retagged it via
// `headscale nodes tag`. This is the unit-level guard for the integration
// test TestTagsAuthKeyWithTagAdminOverrideReauthPreserves (admin decisions are
// authoritative), and it is why the retag discriminator must key on the
// pre-auth key's *identity* (a different key) rather than on "validation ran"
// (a --force-reauth with the same key also runs validation). This test passes
// today and must keep passing after the #3370 fix.
func TestTaggedPAKReauthSameKeyPreservesTags(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// tag:admin must be permitted for the admin SetNodeTags call.
	_, err = s.SetPolicy([]byte(`{"tagOwners":{"tag:admin":["admin@"]}}`))
	require.NoError(t, err)

	// Reusable tagged key (the shape used by the admin-override integration
	// test) so the same key can be presented twice.
	pak, err := s.CreatePreAuthKey(nil, true, false, nil, []string{"tag:orig"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "sticky-node"},
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, []string{"tag:orig"}, first.Tags().AsSlice())
	nodeID := first.ID()

	// Admin retags the node out-of-band.
	tagged, _, err := s.SetNodeTags(nodeID, []string{"tag:admin"})
	require.NoError(t, err)
	require.Equal(t, []string{"tag:admin"}, tagged.Tags().AsSlice())

	// `--force-reauth` with the SAME key: rotate the node key so validation
	// runs, exactly like the client does.
	reReg := regReq
	reReg.NodeKey = key.NewNode().Public()

	second, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, nodeID, second.ID())
	require.Equal(t, []string{"tag:admin"}, second.Tags().AsSlice(),
		"re-authenticating with the same key must preserve the admin-assigned tags")
}

// TestTaggedPAKReauthSpentKeySameNodeKeyRejected pins the authorization boundary
// the retag must respect: presenting a *spent* single-use tagged key to retag an
// already-tagged node must be rejected, even when the client reuses its node key
// (the skip-validation fast path). Without forcing validation on a retag, a
// used/revoked/expired tagged credential could still apply its tags — replaying
// a dead key to escalate a machine onto a tag, and defeating key revocation. The
// existing isExpired comment already declares the boundary "must not depend on
// the client rotating its key"; retag must honour the same rule.
func TestTaggedPAKReauthSpentKeySameNodeKeyRejected(t *testing.T) {
	s := newRetagTestState(t)

	// KEY1: single-use tag:tag1, used to register.
	key1, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag1"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key1.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "retag-node"},
	}
	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, []string{"tag:tag1"}, first.Tags().AsSlice())

	// KEY2: single-use tag:tag2, spent elsewhere so it is already Used.
	key2, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag2"})
	require.NoError(t, err)
	_, _, err = s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key2.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "other-node"},
	}, key.NewMachine().Public())
	require.NoError(t, err)

	// Re-register the FIRST node with the now-spent KEY2, REUSING its node key
	// (no rotation) so it targets the skip-validation fast path. A spent key must
	// be rejected, and the node's tags must be unchanged.
	reReg := regReq
	reReg.Auth = &tailcfg.RegisterResponseAuth{AuthKey: key2.Key}
	// reReg.NodeKey stays nodeKey (same) -> fast path.

	_, _, err = s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.Error(t, err, "a spent tagged key must not be able to retag on the fast path")
	require.Contains(t, err.Error(), "authkey already used")

	after, ok := s.GetNodeByID(first.ID())
	require.True(t, ok)
	require.Equal(t, []string{"tag:tag1"}, after.Tags().AsSlice(),
		"a rejected spent key must not have applied its tags")
}

// retagReauthCase drives the #3370 retag scenario with configurable key shapes
// so the sibling cases below stay a few lines each. It registers a node with
// key1, then re-registers the same machine with key2, and returns the
// re-registered node. rotateNodeKey mirrors --force-reauth (the client rotates
// its node key); when false the client reuses its node key.
func retagReauthCase(
	t *testing.T,
	s *State,
	key1Tags, key2Tags []string,
	key1User, key2User *types.UserID,
	reusable, rotateNodeKey bool,
) (types.NodeView, types.NodeView) {
	t.Helper()

	key1, err := s.CreatePreAuthKey(key1User, reusable, false, nil, key1Tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key1.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "retag-node"},
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	key2, err := s.CreatePreAuthKey(key2User, reusable, false, nil, key2Tags)
	require.NoError(t, err)

	reReg := regReq

	reReg.Auth = &tailcfg.RegisterResponseAuth{AuthKey: key2.Key}
	if rotateNodeKey {
		reReg.NodeKey = key.NewNode().Public()
	}

	second, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, first.ID(), second.ID(), "must update in place, not duplicate")

	return first, second
}

// TestTaggedPAKReauthReusableKeyRetags: a *reusable* differently-tagged key
// must retag too. The retag must key on key identity, not on the single-use
// `Used` flag, so it cannot be coupled to single-use semantics.
func TestTaggedPAKReauthReusableKeyRetags(t *testing.T) {
	s := newRetagTestState(t)
	_, second := retagReauthCase(t, s,
		[]string{"tag:tag1"}, []string{"tag:tag2"}, nil, nil, true /*reusable*/, true)
	require.Equal(t, []string{"tag:tag2"}, second.Tags().AsSlice())
}

// TestTaggedPAKReauthDifferentKeySameNodeKey: retag must fire even when the
// client reuses its node key (no rotation). The trigger is key identity,
// decoupled from NodeKey rotation.
func TestTaggedPAKReauthDifferentKeySameNodeKey(t *testing.T) {
	s := newRetagTestState(t)
	_, second := retagReauthCase(t, s,
		[]string{"tag:tag1"}, []string{"tag:tag2"}, nil, nil, false, false /*same node key*/)
	require.Equal(t, []string{"tag:tag2"}, second.Tags().AsSlice())
}

// TestTaggedPAKReauthSameSingleUseKeySameNodeKeyPreservesTags guards the #2830
// container-restart permutation for a tags-only single-use key: presenting the
// SAME (already-used) single-use key with the SAME node key must take the
// skip-validation fast path, succeed, and keep the node's tags — not reject
// with "authkey already used" and not spuriously retag. This confirms the
// keyChanged/isRetag additions never fire for a same-key restart, the exact
// property #2830/#3312 depend on. (The existing #3312 test uses a user-owned
// one-shot key; this covers the tags-only single-use key.)
func TestTaggedPAKReauthSameSingleUseKeySameNodeKeyPreservesTags(t *testing.T) {
	s := newRetagTestState(t)

	pak, err := s.CreatePreAuthKey(nil, false /*single-use*/, false, nil, []string{"tag:tag1"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "restart-node"},
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, []string{"tag:tag1"}, first.Tags().AsSlice())

	// Container restart: same key, same node key, same machine. The single-use
	// key is already consumed, so re-validation would reject it.
	second, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err,
		"same-key restart of a tagged node must skip validation, not reject a spent single-use key")
	require.Equal(t, first.ID(), second.ID(), "must update in place")
	require.Equal(t, []string{"tag:tag1"}, second.Tags().AsSlice(),
		"same-key restart must preserve tags (no spurious retag)")
	require.Equal(t, 1, s.ListNodes().Len(), "no duplicate node")
}

// TestTaggedPAKReauthUserScopedKeyRetags: a user-scoped tagged key
// (User != nil, the `headscale preauthkeys create -u <user> --tags` shape)
// exercises the pak.User != nil branch of findExistingNodeForPAK, a different
// lookup path from tags-only keys. It must still retag.
func TestTaggedPAKReauthUserScopedKeyRetags(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("owner")
	uid := user.TypedID()
	_, second := retagReauthCase(t, s,
		[]string{"tag:tag1"}, []string{"tag:tag2"}, uid, uid, false, true)
	require.Equal(t, []string{"tag:tag2"}, second.Tags().AsSlice())
	require.True(t, second.IsTagged())
}

// TestTaggedPAKReauthReplacesNotMerges pins the Tailscale KB 1068 rule that
// re-keying *replaces* the tag set (it does not union). Re-keying a
// {tag1,tag2} node with a {tag1} key must drop tag2.
func TestTaggedPAKReauthReplacesNotMerges(t *testing.T) {
	s := newRetagTestState(t)
	_, second := retagReauthCase(t, s,
		[]string{"tag:tag1", "tag:tag2"}, []string{"tag:tag1"}, nil, nil, false, true)
	require.Equal(t, []string{"tag:tag1"}, second.Tags().AsSlice(),
		"re-keying replaces the tag set; tag:tag2 must be removed, not merged")
}

// TestExpiredTaggedNodeReauthRetags: a tagged node that looks expired (a stale
// logout stamp — see #3371) re-authenticating with a fresh differently-tagged
// key must still retag. Combines the isExpired validation path with the retag.
func TestExpiredTaggedNodeReauthRetags(t *testing.T) {
	s := newRetagTestState(t)

	key1, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag1"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key1.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "retag-node"},
	}
	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	// Force a stale past expiry onto the tagged node.
	past := time.Now().Add(-1 * time.Hour)
	_, ok := s.nodeStore.UpdateNode(first.ID(), func(n *types.Node) {
		n.Expiry = &past
	})
	require.True(t, ok)

	key2, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag2"})
	require.NoError(t, err)

	reReg := regReq
	reReg.Auth = &tailcfg.RegisterResponseAuth{AuthKey: key2.Key}
	reReg.NodeKey = key.NewNode().Public()

	second, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, []string{"tag:tag2"}, second.Tags().AsSlice(),
		"an expired (stale logout stamp) tagged node must retag on fresh-key re-auth")
	require.Nil(t, second.AsStruct().Expiry,
		"retag must clear a stale expiry: the node is tagged and tagged nodes never expire")
	require.False(t, second.IsExpired(),
		"a retagged node must not remain expired")
}

// TestTaggedPAKReauthRetagPreservesFutureAdminExpiry pins the composition
// decision between #3370 (retag) and #3371 (never wrongly expire a tagged
// node): a deliberate FUTURE expiry set by an admin via `headscale nodes expire`
// is a node property, not tied to the auth key, so re-keying an already-tagged
// node with a different key must retag it WITHOUT wiping that future expiry.
// Only a stale PAST expiry is cleared (see TestExpiredTaggedNodeReauthRetags).
// Symmetric with the same-key relogin path.
func TestTaggedPAKReauthRetagPreservesFutureAdminExpiry(t *testing.T) {
	s := newRetagTestState(t)

	key1, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag1"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key1.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "retag-node"},
	}
	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	// Admin sets a deliberate future expiry on the tagged node
	// (`headscale nodes expire`), which SetNodeExpiry permits.
	future := time.Now().Add(30 * 24 * time.Hour)
	_, _, err = s.SetNodeExpiry(first.ID(), &future)
	require.NoError(t, err)

	// Re-key with a different tagged key.
	key2, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:tag2"})
	require.NoError(t, err)

	reReg := regReq
	reReg.Auth = &tailcfg.RegisterResponseAuth{AuthKey: key2.Key}
	reReg.NodeKey = key.NewNode().Public()

	second, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, []string{"tag:tag2"}, second.Tags().AsSlice(), "node retags")
	require.NotNil(t, second.AsStruct().Expiry,
		"a deliberate future admin expiry must survive a different-key retag")
	require.Equal(t, future.Unix(), second.AsStruct().Expiry.Unix(),
		"the admin expiry value must be unchanged")
}

// newRetagTestState builds a State with an empty policy (tagged-PAK tags need
// no tagOwners entry).
func newRetagTestState(t *testing.T) *State {
	t.Helper()

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	return s
}

// TestPreAuthKeyReauthPersistsAuthKeyID pins the root cause behind the
// ephemeral-flag revert bug found while auditing #3370: on re-registration
// with a *different* key, HandleNodeFromPreAuthKey updates node.AuthKeyID in
// the NodeStore (state.go, in the in-place closure) but AuthKeyID is excluded
// from nodeUpdateColumns (added for #2862 to avoid persisting a *deleted* key's
// stale reference on MapRequest). The exclusion is correct for MapRequest, but
// on the re-registration path the presented key is freshly loaded and valid, so
// the new auth_key_id must be persisted. Otherwise a control-plane restart
// reloads the OLD key, and any key-scoped property (notably Ephemeral) silently
// reverts — an ephemeral->non-ephemeral re-auth leaves a node that looks
// persistent in memory but is ephemeral again after restart and can be GC'd.
//
// Drives the real handler twice, then reopens the DB to prove the association
// survives the reload.
func TestPreAuthKeyReauthPersistsAuthKeyID(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)

	user := s.CreateUserForTest("rekey-user")

	// KEY A: ephemeral, single-use.
	keyA, err := s.CreatePreAuthKey(user.TypedID(), false, true /*ephemeral*/, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: keyA.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "rekey-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	nodeID := first.ID()
	require.True(t, first.IsEphemeral(), "precondition: registered with an ephemeral key")

	// KEY B: non-ephemeral, single-use, same user. `--force-reauth` rotates the
	// node key so this is a genuine re-registration that consumes KEY B.
	keyB, err := s.CreatePreAuthKey(user.TypedID(), false, false /*non-ephemeral*/, nil, nil)
	require.NoError(t, err)

	reReg := regReq
	reReg.Auth = &tailcfg.RegisterResponseAuth{AuthKey: keyB.Key}
	reReg.NodeKey = key.NewNode().Public()

	second, _, err := s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, err)
	require.Equal(t, nodeID, second.ID(), "must update in place")

	// In-memory, the node now tracks KEY B (non-ephemeral).
	require.NotNil(t, second.AuthKeyID().Get())
	require.Equal(t, keyB.ID, second.AuthKeyID().Get(),
		"NodeStore must reference the key just used to re-authenticate")
	require.False(t, second.IsEphemeral(),
		"re-auth with a non-ephemeral key must make the node non-ephemeral")

	// Restart the control plane: reload state from the database only.
	require.NoError(t, s.Close())

	s2, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s2.Close() })

	reloaded, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok, "node must reload from DB after restart")

	// This is the assertion that fails today: auth_key_id was never persisted on
	// re-registration, so the reload resurrects KEY A and the node is ephemeral
	// again — at risk of GC on the next disconnect.
	require.NotNil(t, reloaded.AuthKeyID().Get())
	require.Equal(t, keyB.ID, reloaded.AuthKeyID().Get(),
		"auth_key_id must persist across restart, not revert to the old key")
	require.False(t, reloaded.IsEphemeral(),
		"ephemerality must not silently revert after a control-plane restart")
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
