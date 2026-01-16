package hscontrol

import (
	"context"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
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
			if err := validateTag(tt.args.tag); (err != nil) != tt.wantErr {
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
	assert.True(t, taggedNode.UserID().Valid(), "Tagged node should have UserID for tracking")

	// Create API server instance
	apiServer := newHeadscaleV1APIServer(app)

	// Test: SetTags should NOT reject tagged nodes with "user-owned" error
	// (Even though they have UserID set, IsTagged() identifies them correctly)
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
