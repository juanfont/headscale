package servertest_test

import (
	"context"
	"net/http"
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIv1_AuthRegister_Errors(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	srv.CreateUser(t, "alice")

	// Malformed auth id is a 400.
	_, err := client.AuthRegister(ctx, &apiv1.AuthRegisterReq{
		User:   apiv1.NewOptString("alice"),
		AuthId: apiv1.NewOptString("not-valid"),
	})
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_AuthApprove(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	srv.CreateUser(t, "alice")

	authID := types.MustAuthID()
	_, err := client.DebugCreateNode(ctx, &apiv1.DebugCreateNodeReq{
		User: apiv1.NewOptString("alice"),
		Key:  apiv1.NewOptString(authID.String()),
		Name: apiv1.NewOptString("pending-node"),
	})
	require.NoError(t, err)

	authReq, ok := srv.State().GetAuthCacheEntry(authID)
	require.True(t, ok)

	// FinishAuth sends on an unbuffered channel; drain it so AuthApprove returns.
	verdict := make(chan types.AuthVerdict, 1)
	go func() { verdict <- <-authReq.WaitForAuth() }()

	require.NoError(t, client.AuthApprove(ctx, &apiv1.AuthApproveReq{
		AuthId: apiv1.NewOptString(authID.String()),
	}))
	assert.NoError(t, (<-verdict).Err, "approval verdict should carry no error")
}

func TestAPIv1_AuthReject(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	srv.CreateUser(t, "alice")

	authID := types.MustAuthID()
	_, err := client.DebugCreateNode(ctx, &apiv1.DebugCreateNodeReq{
		User: apiv1.NewOptString("alice"),
		Key:  apiv1.NewOptString(authID.String()),
		Name: apiv1.NewOptString("pending-node"),
	})
	require.NoError(t, err)

	authReq, ok := srv.State().GetAuthCacheEntry(authID)
	require.True(t, ok)

	verdict := make(chan types.AuthVerdict, 1)
	go func() { verdict <- <-authReq.WaitForAuth() }()

	require.NoError(t, client.AuthReject(ctx, &apiv1.AuthRejectReq{
		AuthId: apiv1.NewOptString(authID.String()),
	}))
	assert.Error(t, (<-verdict).Err, "rejection verdict should carry an error")
}

func TestAPIv1_AuthApprove_Errors(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	// Malformed auth id is a 400.
	requireProblem(t, client.AuthApprove(ctx, &apiv1.AuthApproveReq{
		AuthId: apiv1.NewOptString("not-valid"),
	}), http.StatusBadRequest)

	// Unknown (but well-formed) auth id is a 404.
	requireProblem(t, client.AuthApprove(ctx, &apiv1.AuthApproveReq{
		AuthId: apiv1.NewOptString(types.MustAuthID().String()),
	}), http.StatusNotFound)
}
