package servertest_test

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/require"
)

// TestAPIv0Users runs the user operations through the generated client
// against a real server: create, read, change, and a walk of the list with a
// page size of 2. The subtests change no name and no row another reads.
func TestAPIv0Users(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	apiKey := srv.CreateAPIKey(t, alice)

	c, err := clientv0.NewClientWithResponses(srv.URL,
		clientv0.WithHTTPClient(&http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}),
		clientv0.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+apiKey)

			return nil
		}))
	require.NoError(t, err)

	ctx := t.Context()

	created := make([]string, 0, 4)

	for _, name := range []string{"bob", "carol", "dave", "erin"} {
		resp, err := c.CreateUserWithResponse(ctx, clientv0.CreateUserBody{Name: name, Email: new(name + "@example.com")})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode(), string(resp.Body))
		require.Equal(t, "/api/headscale/v0/users/"+resp.JSON201.Id, resp.HTTPResponse.Header.Get("Location"))
		require.Equal(t, name+"@example.com", resp.JSON201.LoginName)

		created = append(created, resp.JSON201.Id)
	}

	t.Run("walk the list two at a time", func(t *testing.T) {
		t.Parallel()

		var (
			names []string
			pages int
			token *string
		)

		for {
			resp, err := c.ListUsersWithResponse(ctx, &clientv0.ListUsersParams{PageSize: new(int64(2)), PageToken: token})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))

			pages++

			for _, u := range resp.JSON200.Users {
				names = append(names, u.Name)
			}

			token = resp.JSON200.NextPageToken
			if token == nil {
				break
			}

			require.NotEmpty(t, *token)
		}

		require.Equal(t, []string{"alice", "bob", "carol", "dave", "erin"}, names)
		require.Equal(t, 3, pages)
	})

	first, err := c.ListUsersWithResponse(ctx, &clientv0.ListUsersParams{PageSize: new(int64(2))})
	require.NoError(t, err)
	require.NotNil(t, first.JSON200.NextPageToken)

	token := *first.JSON200.NextPageToken

	for _, tt := range []struct {
		name   string
		params clientv0.ListUsersParams
	}{
		{"forged", clientv0.ListUsersParams{PageToken: new(token[:len(token)-2] + "AA")}},
		{"other filters", clientv0.ListUsersParams{PageToken: &token, Name: new("bob")}},
	} {
		t.Run("token "+tt.name, func(t *testing.T) {
			t.Parallel()

			resp, err := c.ListUsersWithResponse(ctx, &tt.params)
			require.NoError(t, err)
			require.Equal(t, clientv0.ProblemCodeInvalidPageToken, resp.ApplicationproblemJSON422.Code, string(resp.Body))
		})
	}

	t.Run("filter by email", func(t *testing.T) {
		t.Parallel()

		resp, err := c.ListUsersWithResponse(ctx, &clientv0.ListUsersParams{Email: new("dave@example.com")})
		require.NoError(t, err)
		require.Len(t, resp.JSON200.Users, 1)
		require.Equal(t, created[2], resp.JSON200.Users[0].Id)
	})

	t.Run("get", func(t *testing.T) {
		t.Parallel()

		resp, err := c.GetUserWithResponse(ctx, created[0])
		require.NoError(t, err)
		require.Equal(t, "bob", resp.JSON200.Name)
		require.Equal(t, clientv0.UserProviderLocal, resp.JSON200.Provider)
		require.Equal(t, []clientv0.NodeReference{}, resp.JSON200.Nodes)

		missing, err := c.GetUserWithResponse(ctx, "9999")
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeNotFound, missing.ApplicationproblemJSON404.Code)
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		resp, err := c.UpdateUserWithResponse(ctx, created[0], clientv0.UpdateUserBody{DisplayName: new("Bob B."), Email: new("")})
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.Equal(t, "Bob B.", resp.JSON200.DisplayName)
		require.Empty(t, resp.JSON200.Email)
		require.Equal(t, "bob", resp.JSON200.LoginName)

		taken, err := c.UpdateUserWithResponse(ctx, created[0], clientv0.UpdateUserBody{Name: new("carol")})
		require.NoError(t, err)

		p := taken.ApplicationproblemJSON409
		require.Equal(t, clientv0.ProblemCodeNameTaken, p.Code)
		require.Equal(t, created[1], p.Object.MustGet().Id)

		empty, err := c.UpdateUserWithResponse(ctx, created[0], clientv0.UpdateUserBody{})
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeEmptyPatch, empty.ApplicationproblemJSON422.Code)
	})

	t.Run("create a taken name", func(t *testing.T) {
		t.Parallel()

		resp, err := c.CreateUserWithResponse(ctx, clientv0.CreateUserBody{Name: "alice"})
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeNameTaken, resp.ApplicationproblemJSON409.Code)
	})

	t.Run("create with a taken email", func(t *testing.T) {
		t.Parallel()

		resp, err := c.CreateUserWithResponse(ctx, clientv0.CreateUserBody{Name: "mallory", Email: new("ERIN@example.com")})
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeEmailTaken, resp.ApplicationproblemJSON409.Code)
		require.Equal(t, created[3], resp.ApplicationproblemJSON409.Object.MustGet().Id)
	})
}

// TestAPIv0DeleteUser runs the delete of a user through the generated
// client against a real server, with real nodes: the refusal while it owns
// nodes, a dry run answered exactly as the real call, a stale expect, a
// token without devices:core, and the peer that sees the nodes go.
func TestAPIv0DeleteUser(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	c := v0Client(t, srv)
	ctx := t.Context()
	id := strconv.FormatUint(uint64(alice.ID), 10)

	servertest.NewClient(t, srv, "laptop", servertest.WithUser(alice))
	servertest.NewClient(t, srv, "phone", servertest.WithUser(alice))

	watcher := servertest.NewClient(t, srv, "watcher", servertest.WithUser(bob))
	watcher.WaitForPeerCount(t, 2, 10*time.Second)

	srv.CreateAPIKey(t, alice)

	// Each client joined with an auth key of alice's.
	keys, err := srv.State().ListPreAuthKeys()
	require.NoError(t, err)

	var aliceKeys int64

	for _, k := range keys {
		if k.UserID != nil && *k.UserID == alice.ID {
			aliceKeys++
		}
	}

	del := func(t *testing.T, params clientv0.DeleteUserParams, edit ...clientv0.RequestEditorFn) *clientv0.DeleteUserResponse {
		t.Helper()

		resp, err := c.DeleteUserWithResponse(ctx, id, &params, edit...)
		require.NoError(t, err)

		return resp
	}

	refused := del(t, clientv0.DeleteUserParams{DryRun: new(true)})
	require.Equal(t, http.StatusConflict, refused.StatusCode(), string(refused.Body))
	require.Equal(t, clientv0.ProblemCodeUserHasNodes, refused.ApplicationproblemJSON409.Code)
	require.Len(t, refused.ApplicationproblemJSON409.Details["nodes"], 2)

	token, err := func() (string, error) {
		_, client, err := srv.State().CreateOAuthClient([]string{"users"}, []string{"tag:ci"}, "", nil)
		if err != nil {
			return "", err
		}

		token, _, err := srv.State().MintAccessToken(client.ClientID, []string{"users"}, []string{"tag:ci"}, new(time.Now().Add(time.Hour)))

		return token, err
	}()
	require.NoError(t, err)

	noCore := del(t, clientv0.DeleteUserParams{WithNodes: new(true)}, bearer(token))
	require.Equal(t, http.StatusForbidden, noCore.StatusCode(), string(noCore.Body))
	require.Equal(t, []any{"devices:core"}, noCore.ApplicationproblemJSON403.Details["scopes"])

	dry := del(t, clientv0.DeleteUserParams{WithNodes: new(true), DryRun: new(true)})
	require.Equal(t, http.StatusOK, dry.StatusCode(), string(dry.Body))
	require.Len(t, dry.JSON200.Nodes, 2)
	require.Equal(t, aliceKeys, dry.JSON200.AuthKeyCount)
	require.Equal(t, int64(1), dry.JSON200.ApiKeyCount)

	t.Run("a node that registers after the dry run", func(t *testing.T) {
		servertest.NewClient(t, srv, "tablet", servertest.WithUser(alice))

		stale := del(t, clientv0.DeleteUserParams{WithNodes: new(true), Expect: &dry.JSON200.Expect})
		require.Equal(t, http.StatusConflict, stale.StatusCode(), string(stale.Body))
		require.Equal(t, clientv0.ProblemCodeUserChanged, stale.ApplicationproblemJSON409.Code)
	})

	again := del(t, clientv0.DeleteUserParams{WithNodes: new(true), DryRun: new(true)})
	require.Len(t, again.JSON200.Nodes, 3)

	gone := del(t, clientv0.DeleteUserParams{WithNodes: new(true), Expect: &again.JSON200.Expect})
	require.Equal(t, http.StatusOK, gone.StatusCode(), string(gone.Body))

	if d := cmp.Diff(again.JSON200, gone.JSON200); d != "" {
		t.Fatalf("the dry run and the delete answer alike (-dry +delete):\n%s", d)
	}

	watcher.WaitForPeerCount(t, 0, 10*time.Second)

	for _, n := range gone.JSON200.Nodes {
		resp, err := c.GetNodeWithResponse(ctx, n.Id)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, resp.StatusCode())
	}

	repeat := del(t, clientv0.DeleteUserParams{})
	require.Equal(t, http.StatusNotFound, repeat.StatusCode(), string(repeat.Body))
}
