package servertest_test

import (
	"context"
	"net/http"
	"testing"

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

	// One digit of the signature changed to one it is not; not the last,
	// whose low bits may carry nothing.
	forged := []byte(token)

	forged[len(forged)-3] = 'A'
	if token[len(token)-3] == 'A' {
		forged[len(forged)-3] = 'B'
	}

	for _, tt := range []struct {
		name   string
		params clientv0.ListUsersParams
	}{
		{"forged", clientv0.ListUsersParams{PageToken: new(string(forged))}},
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
