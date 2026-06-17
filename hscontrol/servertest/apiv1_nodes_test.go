package servertest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIv1_GetNode(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	user := srv.CreateUser(t, "alice")
	node := srv.CreateNode(t, user, "node1")

	resp, err := client.GetNode(ctx, apiv1.GetNodeParams{NodeID: uint64(node.ID)})
	require.NoError(t, err)
	assert.Equal(t, uint64(node.ID), resp.Node.Value.ID.Value)
	assert.Equal(t, "alice", resp.Node.Value.User.Value.Name.Value)

	_, err = client.GetNode(ctx, apiv1.GetNodeParams{NodeID: 99999})
	requireProblem(t, err, http.StatusNotFound)
}

func TestAPIv1_ListNodes(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	srv.CreateNode(t, alice, "alice1")
	srv.CreateNode(t, alice, "alice2")
	srv.CreateNode(t, bob, "bob1")

	all, err := client.ListNodes(ctx, apiv1.ListNodesParams{})
	require.NoError(t, err)
	require.Len(t, all.Nodes, 3)

	for i := 1; i < len(all.Nodes); i++ {
		assert.Less(t, all.Nodes[i-1].ID.Value, all.Nodes[i].ID.Value)
	}

	byUser, err := client.ListNodes(ctx, apiv1.ListNodesParams{User: apiv1.NewOptString("alice")})
	require.NoError(t, err)
	assert.Len(t, byUser.Nodes, 2)
}

func TestAPIv1_DeleteNode(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	user := srv.CreateUser(t, "alice")
	node := srv.CreateNode(t, user, "node1")

	require.NoError(t, client.DeleteNode(ctx, apiv1.DeleteNodeParams{NodeID: uint64(node.ID)}))

	_, err := client.GetNode(ctx, apiv1.GetNodeParams{NodeID: uint64(node.ID)})
	requireProblem(t, err, http.StatusNotFound)

	err = client.DeleteNode(ctx, apiv1.DeleteNodeParams{NodeID: 99999})
	requireProblem(t, err, http.StatusNotFound)
}

func TestAPIv1_RenameNode(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	user := srv.CreateUser(t, "alice")
	node := srv.CreateNode(t, user, "node1")

	resp, err := client.RenameNode(ctx, apiv1.RenameNodeParams{
		NodeID:  uint64(node.ID),
		NewName: "renamed",
	})
	require.NoError(t, err)
	assert.Equal(t, "renamed", resp.Node.Value.GivenName.Value)
}

func TestAPIv1_ExpireNode(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	user := srv.CreateUser(t, "alice")
	node := srv.CreateNode(t, user, "node1")

	resp, err := client.ExpireNode(ctx, apiv1.ExpireNodeParams{NodeID: uint64(node.ID)})
	require.NoError(t, err)
	assert.True(t, resp.Node.Value.Expiry.Set, "expiry should be set")

	// Disabling expiry clears it.
	resp, err = client.ExpireNode(ctx, apiv1.ExpireNodeParams{
		NodeID:        uint64(node.ID),
		DisableExpiry: apiv1.NewOptBool(true),
	})
	require.NoError(t, err)
	assert.False(t, resp.Node.Value.Expiry.Set, "expiry should be cleared")

	// Setting both expiry and disable_expiry is a 400.
	_, err = client.ExpireNode(ctx, apiv1.ExpireNodeParams{
		NodeID:        uint64(node.ID),
		Expiry:        apiv1.NewOptDateTime(time.Now()),
		DisableExpiry: apiv1.NewOptBool(true),
	})
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_SetApprovedRoutes_ExitNodeExpansion(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	user := srv.CreateUser(t, "alice")
	node := srv.CreateNode(t, user, "node1")

	resp, err := client.SetApprovedRoutes(
		ctx,
		&apiv1.SetApprovedRoutesReq{Routes: []string{"0.0.0.0/0"}},
		apiv1.SetApprovedRoutesParams{NodeID: uint64(node.ID)},
	)
	require.NoError(t, err)
	// An exit route is expanded to both default routes.
	assert.Contains(t, resp.Node.Value.ApprovedRoutes, "0.0.0.0/0")
	assert.Contains(t, resp.Node.Value.ApprovedRoutes, "::/0")
}

func TestAPIv1_SetTags_Validation(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	user := srv.CreateUser(t, "alice")
	node := srv.CreateNode(t, user, "node1")

	// Empty tag list is a 400.
	_, err := client.SetTags(
		ctx,
		&apiv1.SetTagsReq{Tags: []string{}},
		apiv1.SetTagsParams{NodeID: uint64(node.ID)},
	)
	requireProblem(t, err, http.StatusBadRequest)

	// Malformed tag is a 400.
	_, err = client.SetTags(
		ctx,
		&apiv1.SetTagsReq{Tags: []string{"notatag"}},
		apiv1.SetTagsParams{NodeID: uint64(node.ID)},
	)
	requireProblem(t, err, http.StatusBadRequest)

	// Unknown node is a 404.
	_, err = client.SetTags(
		ctx,
		&apiv1.SetTagsReq{Tags: []string{"tag:test"}},
		apiv1.SetTagsParams{NodeID: 99999},
	)
	requireProblem(t, err, http.StatusNotFound)

	// Unauthorized tag (no tagOwners policy) is a 400.
	_, err = client.SetTags(
		ctx,
		&apiv1.SetTagsReq{Tags: []string{"tag:test"}},
		apiv1.SetTagsParams{NodeID: uint64(node.ID)},
	)
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_BackfillNodeIPs(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	// Without confirmation it is a 400.
	_, err := client.BackfillNodeIPs(ctx, apiv1.BackfillNodeIPsParams{})
	requireProblem(t, err, http.StatusBadRequest)

	// Confirmed succeeds.
	_, err = client.BackfillNodeIPs(ctx, apiv1.BackfillNodeIPsParams{
		Confirmed: apiv1.NewOptBool(true),
	})
	require.NoError(t, err)
}

func TestAPIv1_RegisterNode_Errors(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	srv.CreateUser(t, "alice")

	// Malformed registration key is a 400.
	_, err := client.RegisterNode(ctx, apiv1.RegisterNodeParams{
		User: apiv1.NewOptString("alice"),
		Key:  apiv1.NewOptString("not-a-valid-key"),
	})
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_DebugCreateNode(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	srv.CreateUser(t, "alice")

	resp, err := client.DebugCreateNode(ctx, &apiv1.DebugCreateNodeReq{
		User: apiv1.NewOptString("alice"),
		Key:  apiv1.NewOptString(types.MustAuthID().String()),
		Name: apiv1.NewOptString("debug-node"),
	})
	require.NoError(t, err)
	assert.Equal(t, "debug-node", resp.Node.Value.Name.Value)
	assert.Equal(t, "alice", resp.Node.Value.User.Value.Name.Value)
}
