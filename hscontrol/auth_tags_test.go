package hscontrol

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestTaggedPreAuthKeyCreatesTaggedNode tests that a PreAuthKey with tags creates
// a tagged node with:
// - Tags from the PreAuthKey
// - UserID tracking who created the key (informational "created by")
// - IsTagged() returns true.
func TestTaggedPreAuthKeyCreatesTaggedNode(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server", "tag:prod"}

	// Create a tagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)
	require.NotEmpty(t, pak.Tags, "PreAuthKey should have tags")
	require.ElementsMatch(t, tags, pak.Tags, "PreAuthKey should have specified tags")

	// Register a node using the tagged key
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify the node was created with tags
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	// Critical assertions for tags-as-identity model
	assert.True(t, node.IsTagged(), "Node should be tagged")
	assert.ElementsMatch(t, tags, node.Tags().AsSlice(), "Node should have tags from PreAuthKey")
	assert.True(t, node.UserID().Valid(), "Node should have UserID tracking creator")
	assert.Equal(t, user.ID, node.UserID().Get(), "UserID should track PreAuthKey creator")

	// Verify node is identified correctly
	assert.True(t, node.IsTagged(), "Tagged node is not user-owned")
	assert.True(t, node.HasTag("tag:server"), "Node should have tag:server")
	assert.True(t, node.HasTag("tag:prod"), "Node should have tag:prod")
	assert.False(t, node.HasTag("tag:other"), "Node should not have tag:other")
}

// TestReAuthDoesNotReapplyTags tests that when a node re-authenticates using the
// same PreAuthKey, the tags are NOT re-applied. Tags are only set during initial
// authentication. This is critical for the container restart scenario (#2830).
//
// NOTE: This test verifies that re-authentication preserves the node's current tags
// without testing tag modification via SetNodeTags (which requires ACL policy setup).
func TestReAuthDoesNotReapplyTags(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	initialTags := []string{"tag:server", "tag:dev"}

	// Create a tagged PreAuthKey with reusable=true for re-auth
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, initialTags)
	require.NoError(t, err)

	// Initial registration
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reauth-test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify initial tags
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())
	require.ElementsMatch(t, initialTags, node.Tags().AsSlice())

	// Re-authenticate with the SAME PreAuthKey (container restart scenario)
	// Key behavior: Tags should NOT be re-applied during re-auth
	reAuthReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key, // Same key
		},
		NodeKey: nodeKey.Public(), // Same node key
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reauth-test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	reAuthResp, err := app.handleRegisterWithAuthKey(reAuthReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, reAuthResp.MachineAuthorized)

	// CRITICAL: Tags should remain unchanged after re-auth
	// They should match the original tags, proving they weren't re-applied
	nodeAfterReauth, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, nodeAfterReauth.IsTagged(), "Node should still be tagged")
	assert.ElementsMatch(t, initialTags, nodeAfterReauth.Tags().AsSlice(), "Tags should remain unchanged on re-auth")

	// Verify only one node was created (no duplicates)
	nodes := app.state.ListNodesByUser(types.UserID(user.ID))
	assert.Equal(t, 1, nodes.Len(), "Should have exactly one node")
}

// NOTE: TestSetTagsOnUserOwnedNode functionality is covered by gRPC tests in grpcv1_test.go
// which properly handle ACL policy setup. The test verifies that SetTags can convert
// user-owned nodes to tagged nodes while preserving UserID.

// TestCannotRemoveAllTags tests that attempting to remove all tags from a
// tagged node fails with ErrCannotRemoveAllTags. Once a node is tagged,
// it must always have at least one tag (Tailscale requirement).
func TestCannotRemoveAllTags(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server"}

	// Create a tagged node
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify node is tagged
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())

	// Attempt to remove all tags by setting empty array
	_, _, err = app.state.SetNodeTags(node.ID(), []string{})
	require.Error(t, err, "Should not be able to remove all tags")
	require.ErrorIs(t, err, types.ErrCannotRemoveAllTags, "Error should be ErrCannotRemoveAllTags")

	// Verify node still has original tags
	nodeAfter, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, nodeAfter.IsTagged(), "Node should still be tagged")
	assert.ElementsMatch(t, tags, nodeAfter.Tags().AsSlice(), "Tags should be unchanged")
}

// TestUserOwnedNodeCreatedWithUntaggedPreAuthKey tests that using a PreAuthKey
// without tags creates a user-owned node (no tags, UserID is the owner).
func TestUserOwnedNodeCreatedWithUntaggedPreAuthKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("node-owner")

	// Create an untagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)
	require.Empty(t, pak.Tags, "PreAuthKey should not be tagged")
	require.Empty(t, pak.Tags, "PreAuthKey should have no tags")

	// Register a node
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "user-owned-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify node is user-owned
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	// Critical assertions for user-owned node
	assert.False(t, node.IsTagged(), "Node should not be tagged")
	assert.False(t, node.IsTagged(), "Node should be user-owned (not tagged)")
	assert.Empty(t, node.Tags().AsSlice(), "Node should have no tags")
	assert.True(t, node.UserID().Valid(), "Node should have UserID")
	assert.Equal(t, user.ID, node.UserID().Get(), "UserID should be the PreAuthKey owner")
}

// TestMultipleNodesWithSameReusableTaggedPreAuthKey tests that a reusable
// PreAuthKey with tags can be used to register multiple nodes, and all nodes
// receive the same tags from the key.
func TestMultipleNodesWithSameReusableTaggedPreAuthKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server", "tag:prod"}

	// Create a REUSABLE tagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)
	require.ElementsMatch(t, tags, pak.Tags)

	// Register first node
	machineKey1 := key.NewMachine()
	nodeKey1 := key.NewNode()

	regReq1 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey1.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node-1",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp1, err := app.handleRegisterWithAuthKey(regReq1, machineKey1.Public())
	require.NoError(t, err)
	require.True(t, resp1.MachineAuthorized)

	// Register second node with SAME PreAuthKey
	machineKey2 := key.NewMachine()
	nodeKey2 := key.NewNode()

	regReq2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key, // Same key
		},
		NodeKey: nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node-2",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp2, err := app.handleRegisterWithAuthKey(regReq2, machineKey2.Public())
	require.NoError(t, err)
	require.True(t, resp2.MachineAuthorized)

	// Verify both nodes exist and have the same tags
	node1, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
	require.True(t, found)
	node2, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)

	// Both nodes should be tagged with the same tags
	assert.True(t, node1.IsTagged(), "First node should be tagged")
	assert.True(t, node2.IsTagged(), "Second node should be tagged")
	assert.ElementsMatch(t, tags, node1.Tags().AsSlice(), "First node should have PreAuthKey tags")
	assert.ElementsMatch(t, tags, node2.Tags().AsSlice(), "Second node should have PreAuthKey tags")

	// Both nodes should track the same creator
	assert.Equal(t, user.ID, node1.UserID().Get(), "First node should track creator")
	assert.Equal(t, user.ID, node2.UserID().Get(), "Second node should track creator")

	// Verify we have exactly 2 nodes
	nodes := app.state.ListNodesByUser(types.UserID(user.ID))
	assert.Equal(t, 2, nodes.Len(), "Should have exactly two nodes")
}

// TestNonReusableTaggedPreAuthKey tests that a non-reusable PreAuthKey with tags
// can only be used once. The second attempt should fail.
func TestNonReusableTaggedPreAuthKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server"}

	// Create a NON-REUSABLE tagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, tags)
	require.NoError(t, err)
	require.ElementsMatch(t, tags, pak.Tags)

	// Register first node - should succeed
	machineKey1 := key.NewMachine()
	nodeKey1 := key.NewNode()

	regReq1 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey1.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node-1",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp1, err := app.handleRegisterWithAuthKey(regReq1, machineKey1.Public())
	require.NoError(t, err)
	require.True(t, resp1.MachineAuthorized)

	// Verify first node was created with tags
	node1, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
	require.True(t, found)
	assert.True(t, node1.IsTagged())
	assert.ElementsMatch(t, tags, node1.Tags().AsSlice())

	// Attempt to register second node with SAME non-reusable key - should fail
	machineKey2 := key.NewMachine()
	nodeKey2 := key.NewNode()

	regReq2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key, // Same non-reusable key
		},
		NodeKey: nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node-2",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	_, err = app.handleRegisterWithAuthKey(regReq2, machineKey2.Public())
	require.Error(t, err, "Should not be able to reuse non-reusable PreAuthKey")

	// Verify only one node was created
	nodes := app.state.ListNodesByUser(types.UserID(user.ID))
	assert.Equal(t, 1, nodes.Len(), "Should have exactly one node")
}

// TestExpiredTaggedPreAuthKey tests that an expired PreAuthKey with tags
// cannot be used to register a node.
func TestExpiredTaggedPreAuthKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server"}

	// Create a PreAuthKey that expires immediately
	expiration := time.Now().Add(-1 * time.Hour) // Already expired
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, &expiration, tags)
	require.NoError(t, err)
	require.ElementsMatch(t, tags, pak.Tags)

	// Attempt to register with expired key
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.Error(t, err, "Should not be able to use expired PreAuthKey")

	// Verify no node was created
	_, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	assert.False(t, found, "No node should be created with expired key")
}

// TestSingleVsMultipleTags tests that PreAuthKeys work correctly with both
// a single tag and multiple tags.
func TestSingleVsMultipleTags(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")

	// Test with single tag
	singleTag := []string{"tag:server"}
	pak1, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, singleTag)
	require.NoError(t, err)

	machineKey1 := key.NewMachine()
	nodeKey1 := key.NewNode()

	regReq1 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak1.Key,
		},
		NodeKey: nodeKey1.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "single-tag-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp1, err := app.handleRegisterWithAuthKey(regReq1, machineKey1.Public())
	require.NoError(t, err)
	require.True(t, resp1.MachineAuthorized)

	node1, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
	require.True(t, found)
	assert.True(t, node1.IsTagged())
	assert.ElementsMatch(t, singleTag, node1.Tags().AsSlice())

	// Test with multiple tags
	multipleTags := []string{"tag:server", "tag:prod", "tag:database"}
	pak2, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, multipleTags)
	require.NoError(t, err)

	machineKey2 := key.NewMachine()
	nodeKey2 := key.NewNode()

	regReq2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak2.Key,
		},
		NodeKey: nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "multi-tag-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp2, err := app.handleRegisterWithAuthKey(regReq2, machineKey2.Public())
	require.NoError(t, err)
	require.True(t, resp2.MachineAuthorized)

	node2, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)
	assert.True(t, node2.IsTagged())
	assert.ElementsMatch(t, multipleTags, node2.Tags().AsSlice())

	// Verify HasTag works for all tags
	assert.True(t, node2.HasTag("tag:server"))
	assert.True(t, node2.HasTag("tag:prod"))
	assert.True(t, node2.HasTag("tag:database"))
	assert.False(t, node2.HasTag("tag:other"))
}

// TestReAuthWithDifferentMachineKey tests the edge case where a node attempts
// to re-authenticate with the same NodeKey but a DIFFERENT MachineKey.
// This scenario should be handled gracefully (currently creates a new node).
func TestReAuthWithDifferentMachineKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server"}

	// Create a reusable tagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)

	// Initial registration
	machineKey1 := key.NewMachine()
	nodeKey := key.NewNode() // Same NodeKey for both attempts

	regReq1 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp1, err := app.handleRegisterWithAuthKey(regReq1, machineKey1.Public())
	require.NoError(t, err)
	require.True(t, resp1.MachineAuthorized)

	// Verify initial node
	node1, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, node1.IsTagged())

	// Re-authenticate with DIFFERENT MachineKey but SAME NodeKey
	machineKey2 := key.NewMachine() // Different machine key

	regReq2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(), // Same NodeKey
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "test-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp2, err := app.handleRegisterWithAuthKey(regReq2, machineKey2.Public())
	require.NoError(t, err)
	require.True(t, resp2.MachineAuthorized)

	// Verify the node still exists and has tags
	// Note: Depending on implementation, this might be the same node or a new node
	node2, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, node2.IsTagged())
	assert.ElementsMatch(t, tags, node2.Tags().AsSlice())
}
