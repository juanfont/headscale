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

func TestAPIv1_CreatePreAuthKey(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	u := srv.CreateUser(t, "alice")

	resp, err := client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
		User:     apiv1.NewOptUint64(uint64(u.ID)),
		Reusable: apiv1.NewOptBool(true),
		AclTags:  []string{"tag:test"},
	})
	require.NoError(t, err)

	pak := resp.PreAuthKey.Value
	assert.NotEmpty(t, pak.Key.Value)
	assert.True(t, pak.Reusable.Value)
	assert.Equal(t, []string{"tag:test"}, pak.AclTags)
	assert.Equal(t, uint64(u.ID), pak.User.Value.ID.Value)

	// Invalid tag format is a 400.
	_, err = client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
		User:    apiv1.NewOptUint64(uint64(u.ID)),
		AclTags: []string{"badtag"},
	})
	requireProblem(t, err, http.StatusBadRequest)
}

func TestAPIv1_ListPreAuthKeys(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	u := srv.CreateUser(t, "alice")

	srv.CreatePreAuthKey(t, types.UserID(u.ID))
	srv.CreatePreAuthKey(t, types.UserID(u.ID))

	resp, err := client.ListPreAuthKeys(ctx)
	require.NoError(t, err)
	require.Len(t, resp.PreAuthKeys, 2)
	assert.LessOrEqual(t, resp.PreAuthKeys[0].ID.Value, resp.PreAuthKeys[1].ID.Value)
}

func TestAPIv1_ExpirePreAuthKey(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	u := srv.CreateUser(t, "alice")

	resp, err := client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
		User:     apiv1.NewOptUint64(uint64(u.ID)),
		Reusable: apiv1.NewOptBool(true),
	})
	require.NoError(t, err)

	id := resp.PreAuthKey.Value.ID.Value

	require.NoError(t, client.ExpirePreAuthKey(ctx, &apiv1.ExpirePreAuthKeyReq{
		ID: apiv1.NewOptUint64(id),
	}))

	keys, err := srv.State().ListPreAuthKeys()
	require.NoError(t, err)

	found := false

	for _, k := range keys {
		if k.ID == id {
			found = true

			require.NotNil(t, k.Expiration)
			assert.True(t, k.Expiration.Before(time.Now()), "key should be expired")
		}
	}

	require.True(t, found, "expired key should still be listed")
}

func TestAPIv1_DeletePreAuthKey(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()
	u := srv.CreateUser(t, "alice")

	resp, err := client.CreatePreAuthKey(ctx, &apiv1.CreatePreAuthKeyReq{
		User:     apiv1.NewOptUint64(uint64(u.ID)),
		Reusable: apiv1.NewOptBool(true),
	})
	require.NoError(t, err)

	id := resp.PreAuthKey.Value.ID.Value

	require.NoError(t, client.DeletePreAuthKey(ctx, apiv1.DeletePreAuthKeyParams{
		ID: apiv1.NewOptUint64(id),
	}))

	keys, err := srv.State().ListPreAuthKeys()
	require.NoError(t, err)

	for _, k := range keys {
		assert.NotEqual(t, id, k.ID)
	}
}
