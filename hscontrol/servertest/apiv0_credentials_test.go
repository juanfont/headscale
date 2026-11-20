package servertest_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// bearer sends key as the credential of one call.
func bearer(key string) clientv0.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+key)

		return nil
	}
}

// TestAPIv0ApiKeys runs the API key operations through the generated client
// against a real server: a key in every state walked two at a time, a key
// that revokes itself, the owner, and the rule that no token makes a key.
func TestAPIv0ApiKeys(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	c := v0Client(t, srv)
	ctx := t.Context()

	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	aliceID := strconv.FormatUint(uint64(alice.ID), 10)

	create := func(t *testing.T, body clientv0.CreateApiKeyBody) *clientv0.CreatedApiKey {
		t.Helper()

		body.Expiry = &expiry

		resp, err := c.CreateApiKeyWithResponse(ctx, body)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode(), string(resp.Body))
		require.Equal(t, "/api/headscale/v0/api-keys/"+resp.JSON201.Id, resp.HTTPResponse.Header.Get("Location"))
		require.True(t, strings.HasPrefix(resp.JSON201.Key, "hskey-api-"+resp.JSON201.Prefix+"-"))

		return resp.JSON201
	}

	owned := create(t, clientv0.CreateApiKeyBody{UserId: &aliceID})
	revoked := create(t, clientv0.CreateApiKeyBody{})

	del, err := c.DeleteApiKeyWithResponse(ctx, revoked.Id)
	require.NoError(t, err)
	require.Equal(t, http.StatusNoContent, del.StatusCode())

	_, expired, err := srv.State().CreateAPIKey(new(time.Now().Add(-time.Hour)))
	require.NoError(t, err)

	t.Run("walk the list two at a time; every state", func(t *testing.T) {
		var (
			got   []clientv0.ApiKey
			pages int
			token *string
		)

		for {
			resp, err := c.ListApiKeysWithResponse(ctx, &clientv0.ListApiKeysParams{PageSize: new(int64(2)), PageToken: token})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))

			pages++

			got = append(got, resp.JSON200.ApiKeys...)

			token = resp.JSON200.NextPageToken
			if token == nil {
				break
			}
		}

		states := map[string]clientv0.ApiKeyState{}
		for _, k := range got {
			states[k.Id] = k.State
		}

		// The client's own key comes first, in use.
		require.Len(t, got, 4)
		require.Equal(t, 2, pages)
		require.Equal(t, map[string]clientv0.ApiKeyState{
			got[0].Id:                          clientv0.ApiKeyStateValid,
			owned.Id:                           clientv0.ApiKeyStateValid,
			revoked.Id:                         clientv0.ApiKeyStateRevoked,
			strconv.FormatUint(expired.ID, 10): clientv0.ApiKeyStateExpired,
		}, states)
		require.False(t, got[0].LastSeen.IsNull(), "the key of these calls was seen")
	})

	t.Run("the owner and the user filter", func(t *testing.T) {
		resp, err := c.GetApiKeyWithResponse(ctx, owned.Id)
		require.NoError(t, err)
		require.Equal(t, "alice", resp.JSON200.Owner.MustGet().User.MustGet().LoginName)

		list, err := c.ListApiKeysWithResponse(ctx, &clientv0.ListApiKeysParams{User: &aliceID})
		require.NoError(t, err)
		require.Len(t, list.JSON200.ApiKeys, 1)
		require.Equal(t, owned.Id, list.JSON200.ApiKeys[0].Id)
	})

	t.Run("delete then get: the time of removal", func(t *testing.T) {
		resp, err := c.GetApiKeyWithResponse(ctx, revoked.Id)
		require.NoError(t, err)

		k := resp.JSON200
		require.Equal(t, clientv0.ApiKeyStateRevoked, k.State)
		require.Equal(t, k.Revoked.MustGet().Add(7*24*time.Hour), k.Removal.MustGet())

		me, err := c.GetMeWithResponse(ctx, bearer(revoked.Key))
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeUnauthorized, me.ApplicationproblemJSON401.Code)
	})

	t.Run("a key revokes itself", func(t *testing.T) {
		self := create(t, clientv0.CreateApiKeyBody{})

		del, err := c.DeleteApiKeyWithResponse(ctx, self.Id, bearer(self.Key))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, del.StatusCode())

		me, err := c.GetMeWithResponse(ctx, bearer(self.Key))
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeUnauthorized, me.ApplicationproblemJSON401.Code)
	})

	t.Run("the secret is in the create's answer only", func(t *testing.T) {
		secret := owned.Key[len("hskey-api-"+owned.Prefix+"-"):]

		list, err := c.ListApiKeysWithResponse(ctx, &clientv0.ListApiKeysParams{PageSize: new(int64(1000))})
		require.NoError(t, err)

		got, err := c.GetApiKeyWithResponse(ctx, owned.Id)
		require.NoError(t, err)

		missing, err := c.GetApiKeyWithResponse(ctx, owned.Key)
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeNotFound, missing.ApplicationproblemJSON404.Code)

		for _, body := range [][]byte{list.Body, got.Body, missing.Body} {
			require.NotContains(t, string(body), secret)
		}
	})

	t.Run("no token makes an API key", func(t *testing.T) {
		_, client, err := srv.State().CreateOAuthClient([]string{"all"}, nil, "", nil)
		require.NoError(t, err)

		token, _, err := srv.State().MintAccessToken(client.ClientID, []string{"all"}, nil, new(time.Now().Add(time.Hour)))
		require.NoError(t, err)

		resp, err := c.CreateApiKeyWithResponse(ctx, clientv0.CreateApiKeyBody{Expiry: &expiry}, bearer(token))
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeForbidden, resp.ApplicationproblemJSON403.Code)
		require.Equal(t, "token_cannot_create_api_key", resp.ApplicationproblemJSON403.Details["rule"])
	})
}

// TestAPIv0OAuthClients runs the OAuth client operations through the
// generated client against a real server: a client made in v0 trades its
// secret at /api/v2/oauth/token, its token works in v0, the revoke refuses
// that token at once, and the walk shows every state.
func TestAPIv0OAuthClients(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	srv := servertest.NewServer(t)

	_, _, err := srv.State().UpdatePolicy([]byte(`{
		"tagOwners": {"tag:ci": [], "tag:web": ["tag:ci"], "tag:prod": []},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	bob := srv.CreateUser(t, "bob")
	bobKey := srv.CreateAPIKey(t, bob)
	c := v0Client(t, srv)
	ctx := t.Context()
	hc := &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}

	create := func(t *testing.T, body clientv0.CreateOAuthClientBody, editors ...clientv0.RequestEditorFn) *clientv0.CreatedOAuthClient {
		t.Helper()

		resp, err := c.CreateOAuthClientWithResponse(ctx, body, editors...)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode(), string(resp.Body))
		require.Equal(t, "/api/headscale/v0/oauth-clients/"+resp.JSON201.Id, resp.HTTPResponse.Header.Get("Location"))
		require.True(t, strings.HasPrefix(resp.JSON201.Key, "hskey-client-"+resp.JSON201.Id+"-"))

		return resp.JSON201
	}

	// mint trades a client secret for a token at the endpoint of /api/v2,
	// as the Tailscale tools do.
	mint := func(t *testing.T, secret string) string {
		t.Helper()

		form := url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := hc.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

		var tok struct {
			AccessToken string `json:"access_token"`
		}
		require.NoError(t, json.Unmarshal(raw, &tok))

		return tok.AccessToken
	}

	ops := create(t, clientv0.CreateOAuthClientBody{
		Scopes:      []string{"oauth_keys", "auth_keys"},
		Tags:        &[]string{"tag:ci"},
		Description: new("operator"),
	}, bearer(bobKey))
	require.Equal(t, "bob", ops.CreatedBy.MustGet().LoginName)

	token := mint(t, ops.Key)

	t.Run("its token works in v0 and is held to the token rules", func(t *testing.T) {
		me, err := c.GetMeWithResponse(ctx, bearer(token))
		require.NoError(t, err)
		require.Equal(t, ops.Id, me.JSON200.Credential.MustGet().Client.MustGet().Id)

		made := create(t, clientv0.CreateOAuthClientBody{Scopes: []string{"auth_keys"}, Tags: &[]string{"tag:web"}}, bearer(token))
		require.True(t, made.CreatedBy.IsNull())

		for rule, body := range map[string]clientv0.CreateOAuthClientBody{
			"token_must_hold_scopes": {Scopes: []string{"devices:core"}, Tags: &[]string{"tag:ci"}},
			"token_must_own_tags":    {Scopes: []string{"auth_keys"}, Tags: &[]string{"tag:prod"}},
		} {
			resp, err := c.CreateOAuthClientWithResponse(ctx, body, bearer(token))
			require.NoError(t, err)
			require.Equal(t, clientv0.ProblemCodeForbidden, resp.ApplicationproblemJSON403.Code)
			require.Equal(t, rule, resp.ApplicationproblemJSON403.Details["rule"])
		}

		resp, err := c.CreateOAuthClientWithResponse(ctx, clientv0.CreateOAuthClientBody{Scopes: []string{"auth_keys"}})
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeScopeRequiresTags, resp.ApplicationproblemJSON422.Code)
	})

	t.Run("a revoke refuses its tokens at once", func(t *testing.T) {
		victim := create(t, clientv0.CreateOAuthClientBody{Scopes: []string{"users:read"}})
		held := mint(t, victim.Key)

		users, err := c.ListUsersWithResponse(ctx, nil, bearer(held))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, users.StatusCode())

		del, err := c.DeleteOAuthClientWithResponse(ctx, victim.Id)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, del.StatusCode())

		users, err = c.ListUsersWithResponse(ctx, nil, bearer(held))
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeUnauthorized, users.ApplicationproblemJSON401.Code)

		got, err := c.GetOAuthClientWithResponse(ctx, victim.Id)
		require.NoError(t, err)
		require.Equal(t, clientv0.OAuthClientStateRevoked, got.JSON200.State)
		require.Equal(t, got.JSON200.Revoked.MustGet().Add(7*24*time.Hour), got.JSON200.Removal.MustGet())
	})

	t.Run("a token revokes its own client", func(t *testing.T) {
		self := create(t, clientv0.CreateOAuthClientBody{Scopes: []string{"oauth_keys"}})
		own := mint(t, self.Key)

		del, err := c.DeleteOAuthClientWithResponse(ctx, self.Id, bearer(own))
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, del.StatusCode())

		me, err := c.GetMeWithResponse(ctx, bearer(own))
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeUnauthorized, me.ApplicationproblemJSON401.Code)
	})

	t.Run("walk the list two at a time; every state", func(t *testing.T) {
		var (
			got   []clientv0.OAuthClient
			pages int
			next  *string
		)

		for {
			resp, err := c.ListOAuthClientsWithResponse(ctx, &clientv0.ListOAuthClientsParams{PageSize: new(int64(2)), PageToken: next})
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))

			pages++

			got = append(got, resp.JSON200.OauthClients...)

			next = resp.JSON200.NextPageToken
			if next == nil {
				break
			}
		}

		states := map[clientv0.OAuthClientState]int{}
		for _, oc := range got {
			states[oc.State]++
		}

		require.Len(t, got, 4)
		require.Equal(t, 2, pages)
		require.Equal(t, ops.Id, got[0].Id, "in the order they were made")
		require.Equal(t, map[clientv0.OAuthClientState]int{clientv0.OAuthClientStateValid: 2, clientv0.OAuthClientStateRevoked: 2}, states)
	})

	t.Run("a client whose maker is deleted stays, made by no one", func(t *testing.T) {
		_, err := srv.State().DeleteUser(types.UserID(bob.ID))
		require.NoError(t, err)

		got, err := c.GetOAuthClientWithResponse(ctx, ops.Id)
		require.NoError(t, err)
		require.True(t, got.JSON200.CreatedBy.IsNull())
		require.Equal(t, clientv0.OAuthClientStateValid, got.JSON200.State)
	})

	t.Run("the secret is in the create's answer only", func(t *testing.T) {
		secret := ops.Key[len("hskey-client-"+ops.Id+"-"):]

		list, err := c.ListOAuthClientsWithResponse(ctx, &clientv0.ListOAuthClientsParams{PageSize: new(int64(1000))})
		require.NoError(t, err)

		got, err := c.GetOAuthClientWithResponse(ctx, ops.Id)
		require.NoError(t, err)

		for _, body := range [][]byte{list.Body, got.Body} {
			require.NotContains(t, string(body), secret)
		}
	})
}
