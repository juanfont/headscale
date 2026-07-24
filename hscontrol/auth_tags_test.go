package hscontrol

import (
	"context"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// createTestAppWithNodeExpiry creates a test app with a specific node.expiry config.
func createTestAppWithNodeExpiry(t *testing.T, nodeExpiry time.Duration) *Headscale {
	t.Helper()

	tmpDir := t.TempDir()

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Node: types.NodeConfig{
			Expiry: nodeExpiry,
		},
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		OIDC: types.OIDCConfig{},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	app.mapBatcher = mapper.NewBatcherAndMapper(&cfg, app.state)
	app.mapBatcher.Start()

	t.Cleanup(func() {
		if app.mapBatcher != nil {
			app.mapBatcher.Close()
		}
	})

	return app
}

// TestTaggedPreAuthKeyCreatesTaggedNode tests that a PreAuthKey with tags creates
// a tagged node with:
// - Tags from the PreAuthKey
// - Nil UserID (tagged nodes are owned by tags, not a user)
// - [types.Node.IsTagged] returns true.
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

	// Tagged nodes are owned by their tags, not a user.
	assert.True(t, node.IsTagged(), "Node should be tagged")
	assert.ElementsMatch(t, tags, node.Tags().AsSlice(), "Node should have tags from PreAuthKey")
	assert.False(t, node.UserID().Valid(), "Tagged node should not have UserID")

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
// without testing tag modification via [state.State.SetNodeTags] (which requires ACL policy setup).
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

	// Verify only one node was created (no duplicates).
	// Tagged nodes are not indexed by user, so check the global list.
	allNodes := app.state.ListNodes()
	assert.Equal(t, 1, allNodes.Len(), "Should have exactly one node")
}

// NOTE: Converting user-owned nodes to tagged nodes while preserving UserID
// is covered by the SetTags API tests, which properly handle ACL policy setup.

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

	// Tagged nodes should not have UserID set.
	assert.False(t, node1.UserID().Valid(), "First node should not have UserID")
	assert.False(t, node2.UserID().Valid(), "Second node should not have UserID")

	// Verify we have exactly 2 nodes.
	allNodes := app.state.ListNodes()
	assert.Equal(t, 2, allNodes.Len(), "Should have exactly two nodes")
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

	// Verify only one node was created.
	allNodes := app.state.ListNodes()
	assert.Equal(t, 1, allNodes.Len(), "Should have exactly one node")
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

// TestTaggedPreAuthKeyDisablesKeyExpiry tests that nodes registered with
// a tagged PreAuthKey have key expiry disabled (expiry is nil).
func TestTaggedPreAuthKeyDisablesKeyExpiry(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server", "tag:prod"}

	// Create a tagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)
	require.ElementsMatch(t, tags, pak.Tags)

	// Register a node using the tagged key
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Client requests an expiry time, but for tagged nodes it should be ignored
	clientRequestedExpiry := time.Now().Add(24 * time.Hour)

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-expiry-test",
		},
		Expiry: clientRequestedExpiry,
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify the node has key expiry DISABLED (expiry is nil/zero)
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	// Critical assertion: Tagged nodes should have expiry disabled
	assert.True(t, node.IsTagged(), "Node should be tagged")
	assert.False(t, node.Expiry().Valid(), "Tagged node should have expiry disabled (nil)")
}

// TestUntaggedPreAuthKeyPreservesKeyExpiry tests that nodes registered with
// an untagged PreAuthKey preserve the client's requested key expiry.
func TestUntaggedPreAuthKeyPreservesKeyExpiry(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("node-owner")

	// Create an untagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)
	require.Empty(t, pak.Tags, "PreAuthKey should not be tagged")

	// Register a node
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Client requests an expiry time
	clientRequestedExpiry := time.Now().Add(24 * time.Hour)

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "untagged-expiry-test",
		},
		Expiry: clientRequestedExpiry,
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify the node has the client's requested expiry
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	// Critical assertion: User-owned nodes should preserve client expiry
	assert.False(t, node.IsTagged(), "Node should not be tagged")
	assert.True(t, node.Expiry().Valid(), "User-owned node should have expiry set")
	// Allow some tolerance for test execution time
	assert.WithinDuration(t, clientRequestedExpiry, node.Expiry().Get(), 5*time.Second,
		"User-owned node should have the client's requested expiry")
}

// TestTaggedNodeReauthPreservesDisabledExpiry tests that when a tagged node
// re-authenticates, the disabled expiry is preserved (not updated from client request).
func TestTaggedNodeReauthPreservesDisabledExpiry(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server"}

	// Create a reusable tagged PreAuthKey
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
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
			Hostname: "tagged-reauth-test",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify initial registration has expiry disabled
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())
	require.False(t, node.Expiry().Valid(), "Initial registration should have expiry disabled")

	// Re-authenticate with a NEW expiry request (should be ignored for tagged nodes)
	newRequestedExpiry := time.Now().Add(48 * time.Hour)
	reAuthReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-reauth-test",
		},
		Expiry: newRequestedExpiry, // Client requests new expiry
	}

	reAuthResp, err := app.handleRegisterWithAuthKey(reAuthReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, reAuthResp.MachineAuthorized)

	// Verify expiry is STILL disabled after re-auth
	nodeAfterReauth, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	// Critical assertion: Tagged node should preserve disabled expiry on re-auth
	assert.True(t, nodeAfterReauth.IsTagged(), "Node should still be tagged")
	assert.False(t, nodeAfterReauth.Expiry().Valid(),
		"Tagged node should have expiry PRESERVED as disabled after re-auth")
}

// TestTaggedNodeRestartPreservesNilExpiry tests that a tagged node whose
// tailscaled restarts (sending Auth=nil, Expiry=zero) keeps its nil expiry.
//
// The handleRegister guard required node.Expiry().Valid(), false for the
// nil expiry tagged nodes are created with. The request fell through to
// handleLogout, which wrote &time.Time{} over the original nil and flipped
// the API representation from null to "0001-01-01T00:00:00Z".
func TestTaggedNodeRestartPreservesNilExpiry(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-restart")
	tags := []string{"tag:agent"}

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
			Hostname: "tagged-restart-test",
		},
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())
	require.False(t, node.Expiry().Valid(), "tagged node should have nil expiry after registration")
	require.False(t, node.IsExpired(), "tagged node with nil expiry should not be expired")

	// tailscaled restart: RegisterRequest with Auth=nil and Expiry=time.Time{}
	// (the Go zero value) is what the client sends when it restarts with
	// persisted state.
	restartReq := tailcfg.RegisterRequest{
		Auth:    nil,
		NodeKey: nodeKey.Public(),
		Expiry:  time.Time{},
	}

	restartResp, err := app.handleRegister(context.Background(), restartReq, machineKey.Public())
	require.NoError(t, err)

	require.True(t, restartResp.MachineAuthorized,
		"restart should not require re-authorization")
	require.False(t, restartResp.NodeKeyExpired,
		"restart should not mark node key as expired")
	require.Equal(t, types.TaggedDevices.View().TailscaleUser(), restartResp.User,
		"response should identify node as tagged device")

	nodeAfterRestart, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	assert.True(t, nodeAfterRestart.IsTagged(), "node should still be tagged")
	assert.False(t, nodeAfterRestart.IsExpired(), "node should not be expired after restart")
	assert.False(t, nodeAfterRestart.Expiry().Valid(),
		"tagged node expiry must remain nil (not zero-time) after restart")

	var dbNode types.Node
	require.NoError(t,
		app.state.DB().DB.First(&dbNode, nodeAfterRestart.ID().Uint64()).Error)
	assert.Nil(t, dbNode.Expiry,
		"database expiry column must be NULL after restart, not a pointer to zero-time")
}

// TestUntaggedNodeRestartPreservesNilExpiry tests that an untagged node
// registered against a preauth key with no default node.expiry keeps its
// nil expiry when tailscaled restarts. Same root cause as the tagged
// variant: the dropped node.Expiry().Valid() check covers any nil-expiry
// node, regardless of ownership.
func TestUntaggedNodeRestartPreservesNilExpiry(t *testing.T) {
	app := createTestAppWithNodeExpiry(t, 0)

	user := app.state.CreateUserForTest("untagged-restart")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "untagged-restart-test",
		},
		Expiry: time.Time{},
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.False(t, node.IsTagged(), "node should be user-owned, not tagged")
	require.False(t, node.Expiry().Valid(),
		"untagged node with no default expiry should have nil expiry after registration")
	require.False(t, node.IsExpired())

	restartReq := tailcfg.RegisterRequest{
		Auth:    nil,
		NodeKey: nodeKey.Public(),
		Expiry:  time.Time{},
	}

	restartResp, err := app.handleRegister(context.Background(), restartReq, machineKey.Public())
	require.NoError(t, err)

	require.True(t, restartResp.MachineAuthorized,
		"restart should not require re-authorization")
	require.False(t, restartResp.NodeKeyExpired,
		"restart should not mark node key as expired")

	nodeAfterRestart, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	assert.False(t, nodeAfterRestart.IsTagged(), "node should still be user-owned")
	assert.False(t, nodeAfterRestart.IsExpired(), "node should not be expired after restart")
	assert.False(t, nodeAfterRestart.Expiry().Valid(),
		"untagged node expiry must remain nil (not zero-time) after restart")

	var dbNode types.Node
	require.NoError(t,
		app.state.DB().DB.First(&dbNode, nodeAfterRestart.ID().Uint64()).Error)
	assert.Nil(t, dbNode.Expiry,
		"database expiry column must be NULL after restart, not a pointer to zero-time "+
			"(this is what `sqlite3 ... 'select expiry from nodes'` sees)")
}

// TestExpiryDuringPersonalToTaggedConversion tests that when a personal node
// is converted to tagged via reauth with RequestTags, the expiry is cleared to nil.
// Previously expiry was NOT cleared because expiry handling ran
// BEFORE [state.State.processReauthTags].
func TestExpiryDuringPersonalToTaggedConversion(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("expiry-test-user")

	// Update policy to allow user to own tags
	err := app.state.UpdatePolicyManagerUsersForTest()
	require.NoError(t, err)

	policy := `{
		"tagOwners": {
			"tag:server": ["expiry-test-user@"]
		},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err = app.state.SetPolicy([]byte(policy))
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey1 := key.NewNode()

	// Step 1: Create user-owned node WITH expiry set
	clientExpiry := time.Now().Add(24 * time.Hour)
	registrationID1 := types.MustAuthID()
	regEntry1 := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey1.Public(),
		Hostname:   "personal-to-tagged",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "personal-to-tagged",
			RequestTags: []string{}, // No tags - user-owned
		},
		Expiry: &clientExpiry,
	})
	app.state.SetAuthCacheEntry(registrationID1, regEntry1)

	node, _, err := app.state.HandleNodeFromAuthPath(
		registrationID1, types.UserID(user.ID), nil, "webauth",
	)
	require.NoError(t, err)
	require.False(t, node.IsTagged(), "Node should be user-owned initially")
	require.True(t, node.Expiry().Valid(), "User-owned node should have expiry set")

	// Step 2: Re-auth with tags (Personal → Tagged conversion)
	nodeKey2 := key.NewNode()
	registrationID2 := types.MustAuthID()
	regEntry2 := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey2.Public(),
		Hostname:   "personal-to-tagged",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "personal-to-tagged",
			RequestTags: []string{"tag:server"}, // Adding tags
		},
		Expiry: &clientExpiry, // Client still sends expiry
	})
	app.state.SetAuthCacheEntry(registrationID2, regEntry2)

	nodeAfter, _, err := app.state.HandleNodeFromAuthPath(
		registrationID2, types.UserID(user.ID), nil, "webauth",
	)
	require.NoError(t, err)
	require.True(t, nodeAfter.IsTagged(), "Node should be tagged after conversion")

	// CRITICAL ASSERTION: Tagged nodes should NOT have expiry
	assert.False(t, nodeAfter.Expiry().Valid(),
		"Tagged node should have expiry cleared to nil")
}

// TestExpiryDuringTaggedToPersonalConversion tests that when a tagged node
// is converted to personal via reauth with empty RequestTags, expiry is set
// from the client request.
// Previously expiry was NOT set because expiry handling ran
// BEFORE [state.State.processReauthTags] (node was still tagged at check time).
func TestExpiryDuringTaggedToPersonalConversion(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("expiry-test-user2")

	// Update policy to allow user to own tags
	err := app.state.UpdatePolicyManagerUsersForTest()
	require.NoError(t, err)

	policy := `{
		"tagOwners": {
			"tag:server": ["expiry-test-user2@"]
		},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err = app.state.SetPolicy([]byte(policy))
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey1 := key.NewNode()

	// Step 1: Create tagged node (expiry should be nil)
	registrationID1 := types.MustAuthID()
	regEntry1 := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey1.Public(),
		Hostname:   "tagged-to-personal",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "tagged-to-personal",
			RequestTags: []string{"tag:server"}, // Tagged node
		},
	})
	app.state.SetAuthCacheEntry(registrationID1, regEntry1)

	node, _, err := app.state.HandleNodeFromAuthPath(
		registrationID1, types.UserID(user.ID), nil, "webauth",
	)
	require.NoError(t, err)
	require.True(t, node.IsTagged(), "Node should be tagged initially")
	require.False(t, node.Expiry().Valid(), "Tagged node should have nil expiry")

	// Step 2: Re-auth with empty tags (Tagged → Personal conversion)
	nodeKey2 := key.NewNode()
	clientExpiry := time.Now().Add(48 * time.Hour)
	registrationID2 := types.MustAuthID()
	regEntry2 := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey.Public(),
		NodeKey:    nodeKey2.Public(),
		Hostname:   "tagged-to-personal",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "tagged-to-personal",
			RequestTags: []string{}, // Empty tags - convert to user-owned
		},
		Expiry: &clientExpiry, // Client requests expiry
	})
	app.state.SetAuthCacheEntry(registrationID2, regEntry2)

	nodeAfter, _, err := app.state.HandleNodeFromAuthPath(
		registrationID2, types.UserID(user.ID), nil, "webauth",
	)
	require.NoError(t, err)
	require.False(t, nodeAfter.IsTagged(), "Node should be user-owned after conversion")

	// CRITICAL ASSERTION: User-owned nodes should have expiry from client
	assert.True(t, nodeAfter.Expiry().Valid(),
		"User-owned node should have expiry set")
	assert.WithinDuration(t, clientExpiry, nodeAfter.Expiry().Get(), 5*time.Second,
		"Expiry should match client request")
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

	// A NodeKey is bound 1:1 to a MachineKey (getAndValidateNode enforces
	// this at poll time). A different machine claiming an existing NodeKey is
	// a hijack: it would poison the NodeStore NodeKey index so the original
	// node fails the poll-time MachineKey check and is denied service.
	// Registration now rejects it (see f8f08cf7). Real Tailscale clients
	// never reuse a NodeKey across machine keys, so no legitimate flow is
	// affected.
	_, err = app.handleRegisterWithAuthKey(regReq2, machineKey2.Public())
	require.Error(t, err,
		"a different machine claiming an existing NodeKey must be rejected")

	// The original node is unaffected: still present, tagged, same identity.
	node2, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, node2.IsTagged())
	assert.ElementsMatch(t, tags, node2.Tags().AsSlice())
	assert.Equal(t, node1.ID(), node2.ID(),
		"original node must survive; the hijacking registration was rejected")
}

// TestUntaggedAuthKeyZeroExpiryGetsDefault tests that when node.expiry is configured
// and a client registers with an untagged auth key without requesting a specific expiry,
// the node gets the configured default expiry.
// This is the core fix for https://github.com/juanfont/headscale/issues/1711
func TestUntaggedAuthKeyZeroExpiryGetsDefault(t *testing.T) {
	t.Parallel()

	nodeExpiry := 180 * 24 * time.Hour // 180 days
	app := createTestAppWithNodeExpiry(t, nodeExpiry)

	user := app.state.CreateUserForTest("node-owner")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Client sends zero expiry (the default behaviour of tailscale up --authkey).
	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "default-expiry-test",
		},
		Expiry: time.Time{}, // zero — no client-requested expiry
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	assert.False(t, node.IsTagged())
	assert.True(t, node.Expiry().Valid(), "node should have expiry set from config default")
	assert.False(t, node.IsExpired(), "node should not be expired yet")

	expectedExpiry := time.Now().Add(nodeExpiry)
	assert.WithinDuration(t, expectedExpiry, node.Expiry().Get(), 10*time.Second,
		"node expiry should be ~180 days from now")
}

// TestTaggedAuthKeyIgnoresNodeExpiry tests that tagged nodes still get nil
// expiry even when node.expiry is configured.
func TestTaggedAuthKeyIgnoresNodeExpiry(t *testing.T) {
	t.Parallel()

	nodeExpiry := 180 * 24 * time.Hour
	app := createTestAppWithNodeExpiry(t, nodeExpiry)

	user := app.state.CreateUserForTest("tag-creator")
	tags := []string{"tag:server"}

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
			Hostname: "tagged-no-expiry",
		},
		Expiry: time.Time{},
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	assert.True(t, node.IsTagged())
	assert.False(t, node.Expiry().Valid(),
		"tagged node should have expiry disabled (nil) even with node.expiry configured")
}

// TestNodeExpiryZeroDisablesDefault tests that setting node.expiry to 0
// preserves the old behaviour where nodes registered without a client-requested
// expiry get no expiry (never expire).
func TestNodeExpiryZeroDisablesDefault(t *testing.T) {
	t.Parallel()

	// node.expiry = 0 means "no default expiry"
	app := createTestAppWithNodeExpiry(t, 0)

	user := app.state.CreateUserForTest("node-owner")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "no-default-expiry",
		},
		Expiry: time.Time{}, // zero
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	assert.False(t, node.IsTagged())
	assert.False(t, node.IsExpired(), "node should not be expired")

	// With node.expiry=0 and zero client expiry, the node gets a zero expiry
	// which [types.Node.IsExpired] treats as "never expires" — backwards compatible.
	if node.Expiry().Valid() {
		assert.True(t, node.Expiry().Get().IsZero(),
			"with node.expiry=0 and zero client expiry, expiry should be zero time")
	}
}

// TestClientNonZeroExpiryTakesPrecedence tests that when a client explicitly
// requests an expiry, that value is used instead of the configured default.
func TestClientNonZeroExpiryTakesPrecedence(t *testing.T) {
	t.Parallel()

	nodeExpiry := 180 * 24 * time.Hour // 180 days
	app := createTestAppWithNodeExpiry(t, nodeExpiry)

	user := app.state.CreateUserForTest("node-owner")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Client explicitly requests 24h expiry
	clientExpiry := time.Now().Add(24 * time.Hour)

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "client-expiry-test",
		},
		Expiry: clientExpiry,
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	assert.True(t, node.Expiry().Valid(), "node should have expiry set")
	assert.WithinDuration(t, clientExpiry, node.Expiry().Get(), 5*time.Second,
		"client-requested expiry should take precedence over node.expiry default")
}

// TestReregistrationAppliesDefaultExpiry tests that when a node re-registers
// with an untagged auth key and the client sends zero expiry, the configured
// default is applied.
func TestReregistrationAppliesDefaultExpiry(t *testing.T) {
	t.Parallel()

	nodeExpiry := 90 * 24 * time.Hour // 90 days
	app := createTestAppWithNodeExpiry(t, nodeExpiry)

	user := app.state.CreateUserForTest("node-owner")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Initial registration with zero expiry
	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reregister-test",
		},
		Expiry: time.Time{},
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, node.Expiry().Valid(), "initial registration should get default expiry")

	firstExpiry := node.Expiry().Get()

	// Re-register with a new node key but same machine key
	nodeKey2 := key.NewNode()
	regReq2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reregister-test",
		},
		Expiry: time.Time{}, // still zero
	}

	resp2, err := app.handleRegisterWithAuthKey(regReq2, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp2.MachineAuthorized)

	node2, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)
	assert.True(t, node2.Expiry().Valid(), "re-registration should also get default expiry")

	// The expiry should be refreshed (new 90d from now), not the old one
	expectedExpiry := time.Now().Add(nodeExpiry)
	assert.WithinDuration(t, expectedExpiry, node2.Expiry().Get(), 10*time.Second,
		"re-registration should refresh the default expiry")
	assert.True(t, node2.Expiry().Get().After(firstExpiry),
		"re-registration expiry should be later than initial registration expiry")
}

// TestReregistrationZeroExpiryStaysNil tests that when a user-owned node
// re-registers with zero client expiry and node.expiry is disabled (0),
// the node's expiry stays nil rather than being set to a pointer to zero
// time. Regression test for the else branch introduced in commit 6337a3db
// which assigned `&regReq.Expiry` (pointer to [time.Time]{}) instead of nil,
// causing the database row to hold `0001-01-01 00:00:00` instead of NULL.
//
// The same !regReq.Expiry.IsZero() gate at state.go:2221-2228 is shared by
// the tags-only PreAuthKey path ([state.State.createAndSaveNewNode] also receives nil
// when the client sends zero expiry), so this regression is covered for
// tagged nodes by inspection.
func TestReregistrationZeroExpiryStaysNil(t *testing.T) {
	t.Parallel()

	// node.expiry = 0 means "no default expiry"
	app := createTestAppWithNodeExpiry(t, 0)

	user := app.state.CreateUserForTest("node-owner")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Initial registration with zero client expiry
	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reregister-zero-expiry",
		},
		Expiry: time.Time{},
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.False(t, node.Expiry().Valid(),
		"initial registration with zero expiry and no default should leave expiry nil")

	// Re-register with a new node key but same machine key + user
	nodeKey2 := key.NewNode()
	regReq2 := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "reregister-zero-expiry",
		},
		Expiry: time.Time{}, // still zero
	}

	resp2, err := app.handleRegisterWithAuthKey(regReq2, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp2.MachineAuthorized)

	node2, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)
	assert.False(t, node2.Expiry().Valid(),
		"re-registration with zero client expiry and no default should leave expiry nil, not pointer to zero time")
}

// tsLogoutSentinelExpiry is the past expiry a real tailscale client sends on
// `tailscale logout`: time.Unix(123, 0) (controlclient/direct.go). The issue
// #3371 trace shows it verbatim as `expiry=123`. Using it here (rather than a
// generic time.Now().Add(-1h)) keeps the reproduction faithful to the wire
// behaviour: handleRegister must classify this as a logout, and handleLogout
// must clamp it to now.
func tsLogoutSentinelExpiry() time.Time {
	return time.Unix(123, 0)
}

// TestIssue3371_TaggedNodeLogoutReloginSingleUseKey reproduces
// https://github.com/juanfont/headscale/issues/3371 through the real
// register/logout HTTP-handler path (handleRegister -> handleLogout ->
// handleRegister), not by poking SetNodeExpiry directly.
//
// Root cause (a): `tailscale logout` sends a past expiry; handleLogout stamps
// it on the node via SetNodeExpiry with no IsTagged guard, so a tagged node —
// which must have key-expiry disabled — becomes Expired.
//
// Root cause (b): on the next `tailscale up --auth-key <fresh key>`,
// HandleNodeFromPreAuthKey sees an expired node, takes the expired-node
// validation path, consumes the fresh single-use key on the in-place
// re-registration, yet leaves the node expired (the expiry-refresh block is
// gated `!node.IsTagged()`). The response carries NodeKeyExpired=true, so the
// client rotates its node key and retries with the now-spent key, which is
// rejected with "authkey already used" forever.
//
// Faithful to the artifacts: the client rotates its NodeKey on relogin, the
// logout carries BOTH a past expiry AND an auth key, and a BRAND NEW key is
// presented for the relogin (the trace shows tag:tag2 keys burned while the
// node kept tag:tag1).
func TestIssue3371_TaggedNodeLogoutReloginSingleUseKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-logout-user")
	tags := []string{"tag:tag1"}

	// `headscale preauthkeys create --tags tag:tag1` (single-use).
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// `tailscale up --auth-key $KEY1`: initial join.
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "headscale-debug"},
	}

	resp, err := app.handleRegister(context.Background(), regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)
	require.False(t, resp.NodeKeyExpired)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged(), "precondition: node is tagged")
	require.False(t, node.Expiry().Valid(), "precondition: tagged node has expiry disabled")

	// `tailscale logout`: client sends a past-expiry register with the auth key
	// still attached (handleRegister must treat past expiry as logout regardless
	// of Auth). Reuse the same node key: logout does not rotate it.
	logoutReq := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: nodeKey.Public(),
		Expiry:  tsLogoutSentinelExpiry(),
	}

	_, err = app.handleRegister(context.Background(), logoutReq, machineKey.Public())
	require.NoError(t, err)

	// A tagged node must NOT be expired by logout — tagged nodes never expire.
	// This is root cause (a); it fails before the fix.
	nodeAfterLogout, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.False(t, nodeAfterLogout.IsExpired(),
		"issue #3371 root cause (a): logout must not expire a tagged node")
	assert.False(t, nodeAfterLogout.Expiry().Valid(),
		"issue #3371 root cause (a): tagged node must keep key-expiry disabled after logout")

	// `tailscale up --auth-key $KEY2`: a BRAND NEW single-use key, and the client
	// rotates its node key (as the real client does on relogin).
	pak2, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, tags)
	require.NoError(t, err)

	nodeKey2 := key.NewNode()
	reloginReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak2.Key},
		NodeKey:  nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "headscale-debug"},
	}

	reloginResp, err := app.handleRegister(context.Background(), reloginReq, machineKey.Public())
	require.NoError(t, err,
		"issue #3371: a fresh valid key must re-authenticate the tagged node after logout")
	require.NotNil(t, reloginResp)

	// The whole point: the node comes back online, not stuck expired.
	assert.False(t, reloginResp.NodeKeyExpired,
		"issue #3371: relogin response must not report the node key as expired")
	assert.True(t, reloginResp.MachineAuthorized)

	relogged, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)
	assert.True(t, relogged.IsTagged(), "node stays tagged after relogin")
	assert.False(t, relogged.IsExpired(),
		"issue #3371: tagged node must be online (not expired) after relogin")
	assert.False(t, relogged.Expiry().Valid(),
		"issue #3371: tagged node must have key-expiry disabled after relogin")
	assert.Equal(t, node.ID(), relogged.ID(), "must re-use the same node, not duplicate")
	assert.Equal(t, 1, app.state.ListNodes().Len(), "machine maps to exactly one node")
}

// TestIssue3371_TaggedNodeLogoutReloginReusableKey is the reusable-key variant
// from the issue ("tailscale up then hangs indefinitely instead of erroring").
// With a reusable key the relogin does not hit "authkey already used", but the
// node still stays expired without the fix — so the client never observes a
// non-expired node and hangs. The observable failure here is the persisted
// expired state after relogin.
func TestIssue3371_TaggedNodeLogoutReloginReusableKey(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-logout-reusable")
	tags := []string{"tag:tag1"}

	// `headscale preauthkeys create --reusable --tags tag:tag1`.
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "reusable-tagged"},
	}

	_, err = app.handleRegister(context.Background(), regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())
	require.False(t, node.Expiry().Valid())

	// Logout.
	logoutReq := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: nodeKey.Public(),
		Expiry:  tsLogoutSentinelExpiry(),
	}
	_, err = app.handleRegister(context.Background(), logoutReq, machineKey.Public())
	require.NoError(t, err)

	// Relogin with the same reusable key, rotating the node key.
	nodeKey2 := key.NewNode()
	reloginReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "reusable-tagged"},
	}
	reloginResp, err := app.handleRegister(context.Background(), reloginReq, machineKey.Public())
	require.NoError(t, err)
	require.NotNil(t, reloginResp)

	assert.False(t, reloginResp.NodeKeyExpired,
		"issue #3371: reusable-key relogin must not report node key expired")

	relogged, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)
	assert.True(t, relogged.IsTagged())
	assert.False(t, relogged.IsExpired(),
		"issue #3371: tagged node must be online (not expired) after reusable-key relogin")
	assert.False(t, relogged.Expiry().Valid(),
		"issue #3371: tagged node must have key-expiry disabled after reusable-key relogin")
}

// TestIssue3371_TaggedNodeLogoutDoesNotSetExpiry pins the deepest root cause
// (a) in isolation: `tailscale logout` on a tagged node must not stamp an
// expiry at all. This is the assertion PR #3372 does not make — it leaves
// handleLogout expiring tagged nodes and only unwinds the damage on the next
// registration. Keeping this separate from the relogin tests means a
// regression that re-introduces logout-sets-expiry is caught even if the
// re-registration cleanup masks it.
func TestIssue3371_TaggedNodeLogoutDoesNotSetExpiry(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-logout-noexpiry")
	tags := []string{"tag:tag1"}

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "noexpiry-tagged"},
	}
	_, err = app.handleRegister(context.Background(), regReq, machineKey.Public())
	require.NoError(t, err)

	logoutReq := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: nodeKey.Public(),
		Expiry:  tsLogoutSentinelExpiry(),
	}
	_, err = app.handleRegister(context.Background(), logoutReq, machineKey.Public())
	require.NoError(t, err)

	nodeAfterLogout, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, nodeAfterLogout.IsTagged(), "node stays tagged through logout")
	assert.False(t, nodeAfterLogout.Expiry().Valid(),
		"issue #3371 root cause (a): logout must not set an expiry on a tagged node")
	assert.False(t, nodeAfterLogout.IsExpired(),
		"issue #3371 root cause (a): tagged node must not be expired by logout")

	// The database column must be NULL, not a clamped 'now' timestamp — a
	// persisted expiry survives restart and re-triggers the lockout.
	var dbNode types.Node
	require.NoError(t,
		app.state.DB().DB.First(&dbNode, nodeAfterLogout.ID().Uint64()).Error)
	assert.Nil(t, dbNode.Expiry,
		"issue #3371 root cause (a): tagged node's DB expiry must remain NULL after logout")
}

// TestIssue3371_UserOwnedNodeLogoutStillExpires is the guard rail: the fix for
// tagged nodes must not change logout for ordinary user-owned nodes. A
// user-owned node that logs out MUST still be expired (that is what logout
// means for it).
func TestIssue3371_UserOwnedNodeLogoutStillExpires(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("user-logout")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "user-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	_, err = app.handleRegister(context.Background(), regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.False(t, node.IsTagged(), "precondition: user-owned node")

	logoutReq := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: nodeKey.Public(),
		Expiry:  tsLogoutSentinelExpiry(),
	}
	logoutResp, err := app.handleRegister(context.Background(), logoutReq, machineKey.Public())
	require.NoError(t, err)
	require.NotNil(t, logoutResp)

	nodeAfterLogout, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, nodeAfterLogout.IsExpired(),
		"user-owned node must still be expired by logout (fix must not regress this)")
	assert.True(t, logoutResp.NodeKeyExpired,
		"logout response for a user-owned node must report the key expired")
}

// TestIssue3371_TaggedNodeFutureExpirySurvivesRelogin is the discriminator
// guard rail for the fix. A tagged node may carry a DELIBERATE future expiry
// set by an admin (`headscale nodes expire`); TestTaggedNodeCanHaveKeyExpiry
// establishes that is legal. The #3371 fix clears only a STALE PAST expiry (the
// logout stamp) on re-registration — it must NOT wipe a future expiry. This
// test locks that boundary: without care, a "tagged => clear expiry" fix would
// silently destroy the admin's setting.
//
// Passes before the fix (re-registration currently never touches a tagged
// node's expiry) and must keep passing after.
func TestIssue3371_TaggedNodeFutureExpirySurvivesRelogin(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-future-expiry")
	tags := []string{"tag:tag1"}

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "future-expiry-tagged"},
	}
	_, err = app.handleRegister(context.Background(), regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())

	// Admin sets a deliberate future expiry (`headscale nodes expire`).
	future := time.Now().Add(24 * time.Hour)
	_, _, err = app.state.SetNodeExpiry(node.ID(), &future)
	require.NoError(t, err)

	withFuture, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, withFuture.Expiry().Valid(), "precondition: future expiry set")
	require.False(t, withFuture.IsExpired(), "precondition: future expiry is not expired")

	// Node re-registers (rotating its node key). The future expiry must survive.
	nodeKey2 := key.NewNode()
	reregReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey2.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "future-expiry-tagged"},
	}
	_, err = app.handleRegister(context.Background(), reregReq, machineKey.Public())
	require.NoError(t, err)

	after, found := app.state.GetNodeByNodeKey(nodeKey2.Public())
	require.True(t, found)
	require.True(t, after.IsTagged(), "node stays tagged")
	assert.True(t, after.Expiry().Valid(),
		"deliberate future expiry must survive re-registration (not cleared by #3371 fix)")
	assert.WithinDuration(t, future, after.Expiry().Get(), 5*time.Second,
		"the surviving expiry must be the admin-set future value, unchanged")
}

// TestIssue3371_EphemeralTaggedNodeLogoutDeletes is a regression guard for the
// ephemeral+tagged combination. A tagged pre-auth key can also be ephemeral.
// handleLogout deletes ephemeral nodes (before any expiry stamp), so the #3371
// fix (which suppresses the expiry stamp for tagged nodes) must not divert an
// ephemeral tagged node away from deletion.
//
// Passes before the fix and must keep passing after.
func TestIssue3371_EphemeralTaggedNodeLogoutDeletes(t *testing.T) {
	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-ephemeral")
	tags := []string{"tag:tag1"}

	// Ephemeral + tagged key.
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, tags)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "ephemeral-tagged"},
	}
	_, err = app.handleRegister(context.Background(), regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged(), "precondition: node is tagged")
	require.True(t, node.IsEphemeral(), "precondition: node is ephemeral")

	// Logout: an ephemeral node is deleted, not expired.
	logoutReq := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: nodeKey.Public(),
		Expiry:  tsLogoutSentinelExpiry(),
	}
	_, err = app.handleRegister(context.Background(), logoutReq, machineKey.Public())
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, stillThere := app.state.GetNodeByNodeKey(nodeKey.Public())
		assert.False(c, stillThere,
			"ephemeral tagged node must be deleted on logout, not expired")
	}, 2*time.Second, 50*time.Millisecond, "waiting for ephemeral node deletion")
}
