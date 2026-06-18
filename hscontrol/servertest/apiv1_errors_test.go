package servertest_test

import (
	"context"
	"net/http"
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
)

// These cases assert the HTTP error translation for paths that the
// per-resource happy-path tests do not already cover; they are the ones that
// caught the RenameNode/ExpireNode 500 and the pre-auth-key silent-success bugs.
// Not-found cases that the per-resource tests already assert (DeleteNode,
// DeleteUser, RenameUser, ExpireApiKey, DeleteApiKey) live there, not here.

func TestAPIv1_Nodes_NotFound(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	const missing = uint64(99999)

	_, err := client.RenameNode(ctx, apiv1.RenameNodeParams{NodeID: missing, NewName: "x"})
	requireProblem(t, err, http.StatusNotFound)

	_, err = client.ExpireNode(ctx, apiv1.ExpireNodeParams{NodeID: missing})
	requireProblem(t, err, http.StatusNotFound)
}

func TestAPIv1_PreAuthKeys_Errors(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	requireProblem(t, client.ExpirePreAuthKey(ctx, &apiv1.ExpirePreAuthKeyReq{
		ID: apiv1.NewOptUint64(99999),
	}), http.StatusNotFound)

	requireProblem(t, client.DeletePreAuthKey(ctx, apiv1.DeletePreAuthKeyParams{
		ID: apiv1.NewOptUint64(99999),
	}), http.StatusNotFound)

	// Creating a key for a user that does not exist is a 404.
	_, err := client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
		User: apiv1.NewOptUint64(99999),
	})
	requireProblem(t, err, http.StatusNotFound)
}

func TestAPIv1_SetApprovedRoutes_InvalidCIDR(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	user := srv.CreateUser(t, "route-user")
	node := srv.CreateNode(t, user, "route-node")

	_, err := client.SetApprovedRoutes(ctx,
		&apiv1.SetApprovedRoutesReq{Routes: []string{"not-a-cidr"}},
		apiv1.SetApprovedRoutesParams{NodeID: uint64(node.ID)},
	)
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_SetPolicy_Invalid(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	_, err := client.SetPolicy(ctx, &apiv1.SetPolicyReq{
		Policy: apiv1.NewOptString("{ this is not valid hujson"),
	})
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_CreatePreAuthKey_InvalidTag(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	user := srv.CreateUser(t, "tag-user")

	_, err := client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
		User:    apiv1.NewOptUint64(uint64(user.ID)),
		AclTags: []string{"not-a-tag"},
	})
	requireProblem(t, err, http.StatusBadRequest)
}
