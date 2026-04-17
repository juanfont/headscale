package hscontrol

import (
	"context"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func Test_validateTag(t *testing.T) {
	type args struct {
		tag string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "valid tag",
			args:    args{tag: "tag:test"},
			wantErr: false,
		},
		{
			name:    "tag without tag prefix",
			args:    args{tag: "test"},
			wantErr: true,
		},
		{
			name:    "uppercase tag",
			args:    args{tag: "tag:tEST"},
			wantErr: true,
		},
		{
			name:    "tag that contains space",
			args:    args{tag: "tag:this is a spaced tag"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTag(tt.args.tag)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSetTags_Conversion tests the conversion of user-owned nodes to tagged nodes.
// The tags-as-identity model allows one-way conversion from user-owned to tagged.
// Tag authorization is checked via the policy manager - unauthorized tags are rejected.
func TestSetTags_Conversion(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	// Create test user and nodes
	user := app.state.CreateUserForTest("test-user")

	// Create a pre-auth key WITHOUT tags for user-owned node
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey1 := key.NewMachine()
	nodeKey1 := key.NewNode()

	// Register a user-owned node (via untagged PreAuthKey)
	userOwnedReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey1.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "user-owned-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(userOwnedReq, machineKey1.Public())
	require.NoError(t, err)

	// Get the created node
	userOwnedNode, found := app.state.GetNodeByNodeKey(nodeKey1.Public())
	require.True(t, found)

	// Create API server instance
	apiServer := newHeadscaleV1APIServer(app)

	tests := []struct {
		name           string
		nodeID         uint64
		tags           []string
		wantErr        bool
		wantCode       codes.Code
		wantErrMessage string
	}{
		{
			// Conversion is allowed, but tag authorization fails without tagOwners
			name:           "reject unauthorized tags on user-owned node",
			nodeID:         uint64(userOwnedNode.ID()),
			tags:           []string{"tag:server"},
			wantErr:        true,
			wantCode:       codes.InvalidArgument,
			wantErrMessage: "requested tags",
		},
		{
			// Conversion is allowed, but tag authorization fails without tagOwners
			name:           "reject multiple unauthorized tags",
			nodeID:         uint64(userOwnedNode.ID()),
			tags:           []string{"tag:server", "tag:database"},
			wantErr:        true,
			wantCode:       codes.InvalidArgument,
			wantErrMessage: "requested tags",
		},
		{
			name:           "reject non-existent node",
			nodeID:         99999,
			tags:           []string{"tag:server"},
			wantErr:        true,
			wantCode:       codes.NotFound,
			wantErrMessage: "node not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp, err := apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
				NodeId: tt.nodeID,
				Tags:   tt.tags,
			})

			if tt.wantErr {
				require.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok, "error should be a gRPC status error")
				assert.Equal(t, tt.wantCode, st.Code())
				assert.Contains(t, st.Message(), tt.wantErrMessage)
				assert.Nil(t, resp.GetNode())
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotNil(t, resp.GetNode())
			}
		})
	}
}

// TestSetTags_TaggedNode tests that SetTags correctly identifies tagged nodes
// and doesn't reject them with the "user-owned nodes" error.
// Note: This test doesn't validate ACL tag authorization - that's tested elsewhere.
func TestSetTags_TaggedNode(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	// Create test user and tagged pre-auth key
	user := app.state.CreateUserForTest("test-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, []string{"tag:initial"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Register a tagged node (via tagged PreAuthKey)
	taggedReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(taggedReq, machineKey.Public())
	require.NoError(t, err)

	// Get the created node
	taggedNode, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, taggedNode.IsTagged(), "Node should be tagged")
	assert.False(t, taggedNode.UserID().Valid(), "Tagged node should not have UserID")

	// Create API server instance
	apiServer := newHeadscaleV1APIServer(app)

	// Test: SetTags should work on tagged nodes.
	resp, err := apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
		NodeId: uint64(taggedNode.ID()),
		Tags:   []string{"tag:initial"}, // Keep existing tag to avoid ACL validation issues
	})

	// The call should NOT fail with "cannot set tags on user-owned nodes"
	if err != nil {
		st, ok := status.FromError(err)
		require.True(t, ok)
		// If error is about unauthorized tags, that's fine - ACL validation is working
		// If error is about user-owned nodes, that's the bug we're testing for
		assert.NotContains(t, st.Message(), "user-owned nodes", "Should not reject tagged nodes as user-owned")
	} else {
		// Success is also fine
		assert.NotNil(t, resp)
	}
}

// TestSetTags_CannotRemoveAllTags tests that SetTags rejects attempts to remove
// all tags from a tagged node, enforcing Tailscale's requirement that tagged
// nodes must have at least one tag.
func TestSetTags_CannotRemoveAllTags(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	// Create test user and tagged pre-auth key
	user := app.state.CreateUserForTest("test-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, []string{"tag:server"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	// Register a tagged node
	taggedReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "tagged-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(taggedReq, machineKey.Public())
	require.NoError(t, err)

	// Get the created node
	taggedNode, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	assert.True(t, taggedNode.IsTagged())

	// Create API server instance
	apiServer := newHeadscaleV1APIServer(app)

	// Attempt to remove all tags (empty array)
	resp, err := apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
		NodeId: uint64(taggedNode.ID()),
		Tags:   []string{}, // Empty - attempting to remove all tags
	})

	// Should fail with InvalidArgument error
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "cannot remove all tags")
	assert.Nil(t, resp.GetNode())
}

// TestSetTags_ClearsUserIDInDatabase tests that converting a user-owned node
// to a tagged node via SetTags correctly persists user_id = NULL in the
// database, not just in-memory.
// https://github.com/juanfont/headscale/issues/3161
func TestSetTags_ClearsUserIDInDatabase(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("tag-owner")
	err := app.state.UpdatePolicyManagerUsersForTest()
	require.NoError(t, err)

	_, err = app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:server": ["tag-owner@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	// Register a user-owned node (untagged PreAuthKey).
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

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
	}
	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.False(t, node.IsTagged(), "node should start as user-owned")
	require.True(t, node.UserID().Valid(), "user-owned node must have UserID")

	nodeID := node.ID()

	// Convert to tagged via SetTags API.
	apiServer := newHeadscaleV1APIServer(app)
	_, err = apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
		NodeId: uint64(nodeID),
		Tags:   []string{"tag:server"},
	})
	require.NoError(t, err)

	// Verify in-memory state is correct.
	nsNode, found := app.state.GetNodeByID(nodeID)
	require.True(t, found)
	assert.True(t, nsNode.IsTagged(), "NodeStore: node should be tagged")
	assert.False(t, nsNode.UserID().Valid(),
		"NodeStore: UserID should be nil for tagged node")

	// THE CRITICAL CHECK: verify database has user_id = NULL.
	dbNode, err := app.state.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Nil(t, dbNode.UserID,
		"Database: user_id must be NULL after converting to tagged node")
	assert.True(t, dbNode.IsTagged(),
		"Database: tags must be set")
}

// TestSetTags_NodeDisappearsFromUserListing tests issue #3161:
// after converting a user-owned node to tagged, it must no longer appear
// when listing nodes filtered by the original user.
// https://github.com/juanfont/headscale/issues/3161
func TestSetTags_NodeDisappearsFromUserListing(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("list-user")
	err := app.state.UpdatePolicyManagerUsersForTest()
	require.NoError(t, err)

	_, err = app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:web": ["list-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	// Register a user-owned node.
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "web-server",
		},
	}
	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	// Verify node appears under user before tagging.
	apiServer := newHeadscaleV1APIServer(app)
	resp, err := apiServer.ListNodes(context.Background(), &v1.ListNodesRequest{
		User: "list-user",
	})
	require.NoError(t, err)
	assert.Len(t, resp.GetNodes(), 1, "user-owned node should appear under user")

	// Convert to tagged.
	_, err = apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
		NodeId: uint64(node.ID()),
		Tags:   []string{"tag:web"},
	})
	require.NoError(t, err)

	// Node must NOT appear when listing by original user.
	resp, err = apiServer.ListNodes(context.Background(), &v1.ListNodesRequest{
		User: "list-user",
	})
	require.NoError(t, err)
	assert.Empty(t, resp.GetNodes(),
		"tagged node must not appear when listing nodes for original user")

	// Node must still appear in unfiltered listing.
	allResp, err := apiServer.ListNodes(context.Background(), &v1.ListNodesRequest{})
	require.NoError(t, err)
	require.Len(t, allResp.GetNodes(), 1)
	assert.Contains(t, allResp.GetNodes()[0].GetTags(), "tag:web")
}

// TestSetTags_NodeStoreAndDBConsistency verifies that after SetTags, the
// in-memory NodeStore and the database agree on the node's ownership state.
// https://github.com/juanfont/headscale/issues/3161
func TestSetTags_NodeStoreAndDBConsistency(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("consistency-user")
	err := app.state.UpdatePolicyManagerUsersForTest()
	require.NoError(t, err)

	_, err = app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:db": ["consistency-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "db-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	nodeID := node.ID()

	// Convert to tagged.
	apiServer := newHeadscaleV1APIServer(app)
	_, err = apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
		NodeId: uint64(nodeID),
		Tags:   []string{"tag:db"},
	})
	require.NoError(t, err)

	// In-memory state.
	nsNode, found := app.state.GetNodeByID(nodeID)
	require.True(t, found)

	// Database state.
	dbNode, err := app.state.DB().GetNodeByID(nodeID)
	require.NoError(t, err)

	// Both must agree: tagged, no UserID.
	assert.True(t, nsNode.IsTagged(), "NodeStore: should be tagged")
	assert.True(t, dbNode.IsTagged(), "Database: should be tagged")

	assert.False(t, nsNode.UserID().Valid(),
		"NodeStore: UserID should be nil")
	assert.Nil(t, dbNode.UserID,
		"Database: user_id should be NULL")

	assert.Equal(t,
		nsNode.UserID().Valid(),
		dbNode.UserID != nil,
		"NodeStore and database must agree on UserID state")
}

// TestSetTags_UserDeletionDoesNotCascadeToTaggedNode tests that deleting the
// original user does not cascade-delete a node that was converted to tagged
// via SetTags. This catches the real-world consequence of stale user_id:
// ON DELETE CASCADE would destroy the tagged node.
// https://github.com/juanfont/headscale/issues/3161
func TestSetTags_UserDeletionDoesNotCascadeToTaggedNode(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("doomed-user")
	err := app.state.UpdatePolicyManagerUsersForTest()
	require.NoError(t, err)

	_, err = app.state.SetPolicy([]byte(`{
		"tagOwners": {"tag:survivor": ["doomed-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "survivor-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)

	nodeID := node.ID()

	// Convert to tagged.
	apiServer := newHeadscaleV1APIServer(app)
	_, err = apiServer.SetTags(context.Background(), &v1.SetTagsRequest{
		NodeId: uint64(nodeID),
		Tags:   []string{"tag:survivor"},
	})
	require.NoError(t, err)

	// Delete the original user.
	_, err = app.state.DeleteUser(*user.TypedID())
	require.NoError(t, err)

	// The tagged node must survive in both NodeStore and database.
	nsNode, found := app.state.GetNodeByID(nodeID)
	require.True(t, found, "tagged node must survive user deletion in NodeStore")
	assert.True(t, nsNode.IsTagged())

	dbNode, err := app.state.DB().GetNodeByID(nodeID)
	require.NoError(t, err, "tagged node must survive user deletion in database")
	assert.True(t, dbNode.IsTagged())
	assert.Nil(t, dbNode.UserID)
}

// TestGetNodeByNodeKey_Success tests that a registered node can be looked up by its public key.
func TestGetNodeByNodeKey_Success(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("test-user")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "lookup-test-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	apiServer := newHeadscaleV1APIServer(app)

	resp, err := apiServer.GetNodeByNodeKey(context.Background(), &v1.GetNodeByNodeKeyRequest{
		NodeKey: nodeKey.Public().String(),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetNode())
	assert.Equal(t, "lookup-test-node", resp.GetNode().GetName())
	assert.Equal(t, nodeKey.Public().String(), resp.GetNode().GetNodeKey())
}

// TestGetNodeByNodeKey_NotFound tests that looking up a non-existent node key returns NotFound.
func TestGetNodeByNodeKey_NotFound(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	// Use a valid but unregistered node key
	nodeKey := key.NewNode()

	_, err := apiServer.GetNodeByNodeKey(context.Background(), &v1.GetNodeByNodeKeyRequest{
		NodeKey: nodeKey.Public().String(),
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "node not found")
}

// TestGetNodeByNodeKey_InvalidKey tests that a malformed node key returns InvalidArgument.
func TestGetNodeByNodeKey_InvalidKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	tests := []struct {
		name    string
		nodeKey string
	}{
		{name: "empty string", nodeKey: ""},
		{name: "garbage", nodeKey: "not-a-valid-key"},
		{name: "truncated", nodeKey: "nodekey:abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := apiServer.GetNodeByNodeKey(context.Background(), &v1.GetNodeByNodeKeyRequest{
				NodeKey: tt.nodeKey,
			})
			require.Error(t, err)
			st, ok := status.FromError(err)
			require.True(t, ok, "error should be a gRPC status error")
			assert.Equal(t, codes.InvalidArgument, st.Code())
			assert.Contains(t, st.Message(), "invalid node_key")
		})
	}
}

// TestGetNodeByNodeKey_OnlineStatus tests that the online field is populated in the response.
func TestGetNodeByNodeKey_OnlineStatus(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("test-user")

	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	regReq := tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "online-test-node",
		},
	}
	_, err = app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	apiServer := newHeadscaleV1APIServer(app)

	// Freshly registered node without an active poll session should not be online
	resp, err := apiServer.GetNodeByNodeKey(context.Background(), &v1.GetNodeByNodeKeyRequest{
		NodeKey: nodeKey.Public().String(),
	})
	require.NoError(t, err)
	assert.False(t, resp.GetNode().GetOnline(), "node without active poll session should not be online")
}

// TestDeleteUser_ReturnsProperChangeSignal tests issue #2967 fix:
// When a user is deleted, the state should return a non-empty change signal
// to ensure policy manager is updated and clients are notified immediately.
func TestDeleteUser_ReturnsProperChangeSignal(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	// Create a user
	user := app.state.CreateUserForTest("test-user-to-delete")
	require.NotNil(t, user)

	// Delete the user and verify a non-empty change is returned
	// Issue #2967: Without the fix, DeleteUser returned an empty change,
	// causing stale policy state until another user operation triggered an update.
	changeSignal, err := app.state.DeleteUser(*user.TypedID())
	require.NoError(t, err, "DeleteUser should succeed")
	assert.False(t, changeSignal.IsEmpty(), "DeleteUser should return a non-empty change signal (issue #2967)")
}

// TestDeleteUser_TaggedNodeSurvives tests that deleting a user succeeds when
// the user's only nodes are tagged, and that those nodes remain in the
// NodeStore with nil UserID.
// https://github.com/juanfont/headscale/issues/3077
func TestDeleteUser_TaggedNodeSurvives(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)

	user := app.state.CreateUserForTest("legacy-user")

	// Register a tagged node via the full auth flow.
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
			Hostname: "tagged-server",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}

	resp, err := app.handleRegisterWithAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, resp.MachineAuthorized)

	// Verify the registered node has nil UserID (enforced invariant).
	node, found := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, found)
	require.True(t, node.IsTagged())
	assert.False(t, node.UserID().Valid(),
		"tagged node should have nil UserID after registration")

	nodeID := node.ID()

	// NodeStore should not list the tagged node under any user.
	nodesForUser := app.state.ListNodesByUser(types.UserID(user.ID))
	assert.Equal(t, 0, nodesForUser.Len(),
		"tagged nodes should not appear in nodesByUser index")

	// Delete the user.
	changeSignal, err := app.state.DeleteUser(*user.TypedID())
	require.NoError(t, err)
	assert.False(t, changeSignal.IsEmpty())

	// Tagged node survives in the NodeStore.
	nodeAfter, found := app.state.GetNodeByID(nodeID)
	require.True(t, found, "tagged node should survive user deletion")
	assert.True(t, nodeAfter.IsTagged())
	assert.False(t, nodeAfter.UserID().Valid())

	// Tagged node appears in the global list.
	allNodes := app.state.ListNodes()
	foundInAll := false

	for _, n := range allNodes.All() {
		if n.ID() == nodeID {
			foundInAll = true

			break
		}
	}

	assert.True(t, foundInAll, "tagged node should appear in the global node list")
}

// TestExpireApiKey_ByID tests that API keys can be expired by ID.
func TestExpireApiKey_ByID(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	// Create an API key
	createResp, err := apiServer.CreateApiKey(context.Background(), &v1.CreateApiKeyRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.GetApiKey())

	// List keys to get the ID
	listResp, err := apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.GetApiKeys(), 1)

	keyID := listResp.GetApiKeys()[0].GetId()

	// Expire by ID
	_, err = apiServer.ExpireApiKey(context.Background(), &v1.ExpireApiKeyRequest{
		Id: keyID,
	})
	require.NoError(t, err)

	// Verify key is expired (expiration is set to now or in the past)
	listResp, err = apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.GetApiKeys(), 1)
	assert.NotNil(t, listResp.GetApiKeys()[0].GetExpiration(), "expiration should be set")
}

// TestExpireApiKey_ByPrefix tests that API keys can still be expired by prefix.
func TestExpireApiKey_ByPrefix(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	// Create an API key
	createResp, err := apiServer.CreateApiKey(context.Background(), &v1.CreateApiKeyRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.GetApiKey())

	// List keys to get the prefix
	listResp, err := apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.GetApiKeys(), 1)

	keyPrefix := listResp.GetApiKeys()[0].GetPrefix()

	// Expire by prefix
	_, err = apiServer.ExpireApiKey(context.Background(), &v1.ExpireApiKeyRequest{
		Prefix: keyPrefix,
	})
	require.NoError(t, err)
}

// TestDeleteApiKey_ByID tests that API keys can be deleted by ID.
func TestDeleteApiKey_ByID(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	// Create an API key
	createResp, err := apiServer.CreateApiKey(context.Background(), &v1.CreateApiKeyRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.GetApiKey())

	// List keys to get the ID
	listResp, err := apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.GetApiKeys(), 1)

	keyID := listResp.GetApiKeys()[0].GetId()

	// Delete by ID
	_, err = apiServer.DeleteApiKey(context.Background(), &v1.DeleteApiKeyRequest{
		Id: keyID,
	})
	require.NoError(t, err)

	// Verify key is deleted
	listResp, err = apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	assert.Empty(t, listResp.GetApiKeys())
}

// TestDeleteApiKey_ByPrefix tests that API keys can still be deleted by prefix.
func TestDeleteApiKey_ByPrefix(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	// Create an API key
	createResp, err := apiServer.CreateApiKey(context.Background(), &v1.CreateApiKeyRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.GetApiKey())

	// List keys to get the prefix
	listResp, err := apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	require.Len(t, listResp.GetApiKeys(), 1)

	keyPrefix := listResp.GetApiKeys()[0].GetPrefix()

	// Delete by prefix
	_, err = apiServer.DeleteApiKey(context.Background(), &v1.DeleteApiKeyRequest{
		Prefix: keyPrefix,
	})
	require.NoError(t, err)

	// Verify key is deleted
	listResp, err = apiServer.ListApiKeys(context.Background(), &v1.ListApiKeysRequest{})
	require.NoError(t, err)
	assert.Empty(t, listResp.GetApiKeys())
}

// TestExpireApiKey_NoIdentifier tests that an error is returned when neither ID nor prefix is provided.
func TestExpireApiKey_NoIdentifier(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	_, err := apiServer.ExpireApiKey(context.Background(), &v1.ExpireApiKeyRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "must provide id or prefix")
}

// TestDeleteApiKey_NoIdentifier tests that an error is returned when neither ID nor prefix is provided.
func TestDeleteApiKey_NoIdentifier(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	_, err := apiServer.DeleteApiKey(context.Background(), &v1.DeleteApiKeyRequest{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "must provide id or prefix")
}

// TestExpireApiKey_BothIdentifiers tests that an error is returned when both ID and prefix are provided.
func TestExpireApiKey_BothIdentifiers(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	_, err := apiServer.ExpireApiKey(context.Background(), &v1.ExpireApiKeyRequest{
		Id:     1,
		Prefix: "test",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "provide either id or prefix, not both")
}

// TestDeleteApiKey_BothIdentifiers tests that an error is returned when both ID and prefix are provided.
func TestDeleteApiKey_BothIdentifiers(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	apiServer := newHeadscaleV1APIServer(app)

	_, err := apiServer.DeleteApiKey(context.Background(), &v1.DeleteApiKeyRequest{
		Id:     1,
		Prefix: "test",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error should be a gRPC status error")
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "provide either id or prefix, not both")
}
