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
