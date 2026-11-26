package servertest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAPIv0AuthKeys runs the auth key operations through the generated
// client against a real server: a key in every state, real nodes joining
// with them, the walk two at a time, the revoke that holds at once, and the
// secret in the create's answer and nowhere else.
func TestAPIv0AuthKeys(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	srv := servertest.NewServer(t)

	_, _, err := srv.State().UpdatePolicy([]byte(`{
		"tagOwners": {"tag:ci": [], "tag:web": ["tag:ci"], "tag:prod": []},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	alice := srv.CreateUser(t, "alice")
	c := v0Client(t, srv)
	ctx := t.Context()

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	created := map[string]*clientv0.CreatedAuthKey{}

	create := func(t *testing.T, name string, body clientv0.CreateAuthKeyBody) *clientv0.CreatedAuthKey {
		t.Helper()

		body.Expiry = &expiry

		resp, err := c.CreateAuthKeyWithResponse(ctx, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode(), string(resp.Body))
		require.Equal(t, "/api/headscale/v0/auth-keys/"+resp.JSON201.Id, resp.HTTPResponse.Header.Get("Location"))
		require.True(t, strings.HasPrefix(resp.JSON201.Key, "hskey-auth-"+resp.JSON201.Prefix+"-"))

		created[name] = resp.JSON201

		return resp.JSON201
	}

	get := func(t *testing.T, id string) clientv0.AuthKey {
		t.Helper()

		resp, err := c.GetAuthKeyWithResponse(ctx, id)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))

		return *resp.JSON200
	}

	userID := strconv.FormatUint(uint64(alice.ID), 10)

	valid := create(t, "valid", clientv0.CreateAuthKeyBody{Tags: &[]string{"tag:ci"}, Description: new("CI runners")})
	used := create(t, "used", clientv0.CreateAuthKeyBody{UserId: &userID})
	reusable := create(t, "reusable", clientv0.CreateAuthKeyBody{Tags: &[]string{"tag:web"}, Reusable: new(true)})
	revoked := create(t, "revoked", clientv0.CreateAuthKeyBody{Tags: &[]string{"tag:ci"}, Reusable: new(true)})

	past := time.Now().Add(-time.Hour)
	expired, err := srv.State().CreatePreAuthKey(new(types.UserID(alice.ID)), false, false, &past, nil)
	require.NoError(t, err)

	servertest.NewClient(t, srv, "joined-single", servertest.WithUser(alice), servertest.WithAuthKey(used.Key))
	servertest.NewClient(t, srv, "joined-reusable", servertest.WithUser(alice), servertest.WithAuthKey(reusable.Key))
	servertest.NewClient(t, srv, "joined-revoked", servertest.WithUser(alice), servertest.WithAuthKey(revoked.Key))

	del, err := c.DeleteAuthKeyWithResponse(ctx, revoked.Id)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, del.StatusCode())

	t.Run("a revoked key registers no node; its node stays", func(t *testing.T) {
		_, err := servertest.TryNewClient(t, srv, "after-revoke", //nolint:contextcheck // the client has its own
			servertest.WithUser(alice), servertest.WithAuthKey(revoked.Key))
		require.Error(t, err)

		nodes, err := c.ListNodesWithResponse(ctx, &clientv0.ListNodesParams{Tag: new("tag:ci")})
		require.NoError(t, err)
		require.Len(t, nodes.JSON200.Nodes, 1, "the node that joined before the revoke")
		require.Equal(t, revoked.Id, nodes.JSON200.Nodes[0].AuthKeyId.MustGet())
	})

	t.Run("walk the list two at a time; every state", func(t *testing.T) {
		var (
			got   []clientv0.AuthKey
			pages int
			token *string
		)

		for {
			resp, err := c.ListAuthKeysWithResponse(ctx, &clientv0.ListAuthKeysParams{PageSize: new(int64(2)), PageToken: token})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))

			pages++

			got = append(got, resp.JSON200.AuthKeys...)

			token = resp.JSON200.NextPageToken
			if token == nil {
				break
			}
		}

		states := map[string]clientv0.AuthKeyState{}
		for _, k := range got {
			states[k.Id] = k.State
		}

		require.Len(t, got, 5)
		require.Equal(t, 3, pages)
		require.Equal(t, map[string]clientv0.AuthKeyState{
			valid.Id:                           clientv0.AuthKeyStateValid,
			used.Id:                            clientv0.AuthKeyStateUsed,
			reusable.Id:                        clientv0.AuthKeyStateValid,
			revoked.Id:                         clientv0.AuthKeyStateRevoked,
			strconv.FormatUint(expired.ID, 10): clientv0.AuthKeyStateExpired,
		}, states)
	})

	t.Run("the secret is in the create's answer only", func(t *testing.T) {
		list, err := c.ListAuthKeysWithResponse(ctx, &clientv0.ListAuthKeysParams{PageSize: new(int64(1000))})
		require.NoError(t, err)

		for _, k := range created {
			secret := k.Key[len("hskey-auth-"+k.Prefix+"-"):]

			got, err := c.GetAuthKeyWithResponse(ctx, k.Id)
			require.NoError(t, err)

			missing, err := c.GetAuthKeyWithResponse(ctx, k.Key)
			require.NoError(t, err)
			require.Equal(t, clientv0.ProblemCodeNotFound, missing.ApplicationproblemJSON404.Code)

			for _, body := range [][]byte{list.Body, got.Body, missing.Body} {
				require.NotContains(t, string(body), secret)
			}
		}
	})

	t.Run("delete then get: the time of removal", func(t *testing.T) {
		again, err := c.DeleteAuthKeyWithResponse(ctx, revoked.Id)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, again.StatusCode(), "a repeated delete")

		k := get(t, revoked.Id)
		require.Equal(t, clientv0.AuthKeyStateRevoked, k.State)
		require.True(t, k.Removal.IsNull(), "a node still refers to the key")

		del, err := c.DeleteAuthKeyWithResponse(ctx, valid.Id)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, del.StatusCode())

		k = get(t, valid.Id)
		require.Equal(t, k.Revoked.MustGet().Add(7*24*time.Hour), k.Removal.MustGet(), "removed after the retention")
		require.Equal(t, "CI runners", k.Description)
	})

	t.Run("a token makes keys for its own tags only", func(t *testing.T) {
		scopes := []string{"auth_keys"}

		_, client, err := srv.State().CreateOAuthClient(scopes, []string{"tag:ci"}, "ci", nil)
		require.NoError(t, err)

		token, _, err := srv.State().MintAccessToken(client.ClientID, scopes, []string{"tag:ci"}, new(time.Now().Add(time.Hour)))
		require.NoError(t, err)

		bearer := func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)

			return nil
		}

		me, err := c.GetMeWithResponse(ctx, bearer)
		require.NoError(t, err)
		require.Equal(t, []string{"tag:ci", "tag:web"}, me.JSON200.Authorization.Tags.MustGet())

		ok, err := c.CreateAuthKeyWithResponse(ctx, clientv0.CreateAuthKeyBody{Tags: &[]string{"tag:web"}, Expiry: &expiry}, bearer)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, ok.StatusCode(), string(ok.Body))
		require.True(t, ok.JSON201.CreatedBy.IsNull())

		for rule, body := range map[string]clientv0.CreateAuthKeyBody{
			"token_must_own_tags":              {Tags: &[]string{"tag:prod"}, Expiry: &expiry},
			"token_cannot_create_key_for_user": {UserId: &userID, Expiry: &expiry},
		} {
			resp, err := c.CreateAuthKeyWithResponse(ctx, body, bearer)
			require.NoError(t, err)
			require.Equal(t, clientv0.ProblemCodeForbidden, resp.ApplicationproblemJSON403.Code)
			require.Equal(t, rule, resp.ApplicationproblemJSON403.Details["rule"])
		}
	})

	t.Run("createdBy is the maker, where the API that made the key records it", func(t *testing.T) {
		aliceKey := srv.CreateAPIKey(t, alice)
		hc := &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}

		v2Create := func(t *testing.T, body string) string {
			t.Helper()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v2/tailnet/-/keys", strings.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+aliceKey)
			req.Header.Set("Content-Type", "application/json")

			resp, err := hc.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

			var made struct{ ID string }
			require.NoError(t, json.Unmarshal(raw, &made))

			return made.ID
		}

		for name, body := range map[string]string{
			"a tagged key /api/v2 made": `{"capabilities": {"devices": {"create": {"tags": ["tag:ci"], "reusable": false, "ephemeral": false, "preauthorized": true}}}, "expirySeconds": 3600}`,
			"a user's key /api/v2 made": `{"capabilities": {"devices": {"create": {"reusable": false, "ephemeral": false, "preauthorized": true}}}, "expirySeconds": 3600}`,
		} {
			t.Run(name, func(t *testing.T) {
				k := get(t, v2Create(t, body))
				require.Equal(t, "alice", k.CreatedBy.MustGet().LoginName)
			})
		}

		t.Run("a tagged key /api/v1 made for a named user", func(t *testing.T) {
			legacy, err := srv.State().CreatePreAuthKey(new(types.UserID(alice.ID)), false, false, &expiry, []string{"tag:ci"})
			require.NoError(t, err)

			k := get(t, strconv.FormatUint(legacy.ID, 10))
			require.True(t, k.CreatedBy.IsNull(), "the user it names need not be its maker")
			require.Equal(t, []string{"tag:ci"}, k.Owner.MustGet().Tags)
		})
	})
}
