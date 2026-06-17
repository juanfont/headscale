package servertest_test

import (
	"context"
	"net/http"
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIv1_CreateUser(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	resp, err := client.CreateUser(ctx, &apiv1.CreateUserReq{
		Name:        apiv1.NewOptString("alice"),
		DisplayName: apiv1.NewOptString("Alice"),
		Email:       apiv1.NewOptString("alice@example.com"),
	})
	require.NoError(t, err)

	user := resp.User.Value
	assert.NotZero(t, user.ID.Value)
	assert.Equal(t, "alice", user.Name.Value)
	assert.Equal(t, "Alice", user.DisplayName.Value)
	assert.Equal(t, "alice@example.com", user.Email.Value)

	// Side effect: the user is persisted.
	got, err := srv.State().GetUserByName("alice")
	require.NoError(t, err)
	assert.Equal(t, uint64(got.ID), user.ID.Value)
}

func TestAPIv1_ListUsers(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	srv.CreateUser(t, "alice")
	srv.CreateUser(t, "bob")

	all, err := client.ListUsers(ctx, apiv1.ListUsersParams{})
	require.NoError(t, err)
	require.Len(t, all.Users, 2)
	// Sorted by id ascending.
	assert.Less(t, all.Users[0].ID.Value, all.Users[1].ID.Value)

	byName, err := client.ListUsers(ctx, apiv1.ListUsersParams{Name: apiv1.NewOptString("bob")})
	require.NoError(t, err)
	require.Len(t, byName.Users, 1)
	assert.Equal(t, "bob", byName.Users[0].Name.Value)

	none, err := client.ListUsers(ctx, apiv1.ListUsersParams{Name: apiv1.NewOptString("nobody")})
	require.NoError(t, err)
	assert.Empty(t, none.Users)
}

func TestAPIv1_RenameUser(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	u := srv.CreateUser(t, "alice")

	resp, err := client.RenameUser(ctx, apiv1.RenameUserParams{
		OldID:   uint64(u.ID),
		NewName: "alice2",
	})
	require.NoError(t, err)
	assert.Equal(t, "alice2", resp.User.Value.Name.Value)

	_, err = srv.State().GetUserByName("alice2")
	require.NoError(t, err)

	// Unknown user is a 404 (the previous implementation returned 500 here).
	_, err = client.RenameUser(ctx, apiv1.RenameUserParams{OldID: 99999, NewName: "ghost"})
	requireProblem(t, err, http.StatusNotFound)
}

func TestAPIv1_DeleteUser(t *testing.T) {
	srv, client := apiClient(t)
	ctx := context.Background()

	u := srv.CreateUser(t, "alice")

	require.NoError(t, client.DeleteUser(ctx, apiv1.DeleteUserParams{ID: uint64(u.ID)}))

	_, err := srv.State().GetUserByName("alice")
	require.Error(t, err)

	// Deleting an unknown user is a 404.
	err = client.DeleteUser(ctx, apiv1.DeleteUserParams{ID: 99999})
	requireProblem(t, err, http.StatusNotFound)
}
