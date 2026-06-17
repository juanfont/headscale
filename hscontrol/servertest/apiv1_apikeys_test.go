package servertest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIv1_CreateApiKey(t *testing.T) {
	_, client := apiClient(t)
	ctx := context.Background()

	resp, err := client.CreateApiKey(ctx, &apiv1.CreateApiKeyReq{
		Expiration: apiv1.NewOptDateTime(time.Now().Add(time.Hour)),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ApiKey.Value)
}

func TestAPIv1_ListApiKeys(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	before, err := client.ListApiKeys(ctx)
	require.NoError(t, err)

	exp := time.Now().Add(time.Hour)
	_, _, err = srv.State().CreateAPIKey(&exp)
	require.NoError(t, err)

	after, err := client.ListApiKeys(ctx)
	require.NoError(t, err)
	require.Len(t, after.ApiKeys, len(before.ApiKeys)+1)

	for i := 1; i < len(after.ApiKeys); i++ {
		assert.LessOrEqual(t, after.ApiKeys[i-1].ID.Value, after.ApiKeys[i].ID.Value)
	}
}

func TestAPIv1_ExpireApiKey(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	exp := time.Now().Add(time.Hour)
	_, key, err := srv.State().CreateAPIKey(&exp)
	require.NoError(t, err)

	require.NoError(t, client.ExpireApiKey(ctx, &apiv1.ExpireApiKeyReq{
		ID: apiv1.NewOptUint64(key.ID),
	}))

	got, err := srv.State().GetAPIKeyByID(key.ID)
	require.NoError(t, err)
	require.NotNil(t, got.Expiration)
	assert.True(t, got.Expiration.Before(time.Now()), "key should be expired")

	// Both id and prefix is a 400.
	requireProblem(t, client.ExpireApiKey(ctx, &apiv1.ExpireApiKeyReq{
		ID:     apiv1.NewOptUint64(1),
		Prefix: apiv1.NewOptString("abc"),
	}), http.StatusBadRequest)

	// Neither id nor prefix is a 400.
	requireProblem(t, client.ExpireApiKey(ctx, &apiv1.ExpireApiKeyReq{}), http.StatusBadRequest)
}

func TestAPIv1_DeleteApiKey(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	exp := time.Now().Add(time.Hour)
	_, key, err := srv.State().CreateAPIKey(&exp)
	require.NoError(t, err)

	require.NoError(t, client.DeleteApiKey(ctx, apiv1.DeleteApiKeyParams{Prefix: key.Prefix}))

	_, err = srv.State().GetAPIKeyByID(key.ID)
	require.Error(t, err, "key should be gone")

	// Unknown prefix is a 404.
	requireProblem(t, client.DeleteApiKey(ctx, apiv1.DeleteApiKeyParams{Prefix: "nonexistent"}), http.StatusNotFound)
}
