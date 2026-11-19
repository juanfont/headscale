package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func TestGetVersion(t *testing.T) {
	rec := newTestAPI(t, Backend{}).Get(Prefix + "/version")
	require.Equal(t, http.StatusOK, rec.Code)

	var got types.VersionInfo
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.Equal(t, *types.GetVersionInfo(), got)
}

func TestGetMe(t *testing.T) {
	b := newBackend(t)
	api := newTestAPI(t, b)

	_, err := b.State.SetPolicy([]byte(`{
		"tagOwners": {"tag:k8s-operator": [], "tag:k8s": ["tag:k8s-operator"], "tag:other": []},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	bob := b.State.CreateUserForTest("bob")

	expiry := time.Date(2027, 2, 8, 9, 14, 0, 0, time.UTC)

	ownedKey, owned, err := b.State.CreateAPIKey(&expiry)
	require.NoError(t, err)
	require.NoError(t, b.State.SetAPIKeyUser(owned.ID, types.UserID(bob.ID)))

	bareKey, bare, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	scopes := []string{"devices:core", "auth_keys"}
	_, client, err := b.State.CreateOAuthClient(scopes, []string{"tag:k8s-operator"}, "kubernetes operator", nil)
	require.NoError(t, err)

	token, at, err := b.State.MintAccessToken(client.ClientID, scopes, []string{"tag:k8s-operator"}, &expiry)
	require.NoError(t, err)

	id := func(n uint64) string { return strconv.FormatUint(n, 10) }

	for _, tt := range []struct {
		name string
		key  string
		want string
	}{
		{
			name: "api key that bob owns",
			key:  ownedKey,
			want: `{
				"principal": {"kind": "apiKey", "identity": null, "user": null},
				"credential": {
					"kind": "apiKey", "id": "` + id(owned.ID) + `", "prefix": "` + owned.Prefix + `",
					"expiry": "2027-02-08T09:14:00Z",
					"owner": {"user": {"id": "` + id(uint64(bob.ID)) + `", "name": "bob", "loginName": "bob", "displayName": "", "email": ""}, "tags": []},
					"client": null
				},
				"authorization": {"scopes": ["all"], "tags": null, "resources": "all"}
			}`,
		},
		{
			name: "api key with no owner and no expiry",
			key:  bareKey,
			want: `{
				"principal": {"kind": "apiKey", "identity": null, "user": null},
				"credential": {
					"kind": "apiKey", "id": "` + id(bare.ID) + `", "prefix": "` + bare.Prefix + `",
					"expiry": null, "owner": null, "client": null
				},
				"authorization": {"scopes": ["all"], "tags": null, "resources": "all"}
			}`,
		},
		{
			name: "token of an oauth client",
			key:  token,
			want: `{
				"principal": {"kind": "oauthClient", "identity": null, "user": null},
				"credential": {
					"kind": "oauthToken", "id": "` + id(at.ID) + `", "prefix": "` + at.Prefix + `",
					"expiry": "2027-02-08T09:14:00Z", "owner": null,
					"client": {"id": "` + client.ClientID + `", "description": "kubernetes operator"}
				},
				"authorization": {"scopes": ["auth_keys", "devices:core"], "tags": ["tag:k8s", "tag:k8s-operator"], "resources": "all"}
			}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rec := api.Get(Prefix+"/me", "Authorization: Bearer "+tt.key)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.JSONEq(t, tt.want, rec.Body.String())
		})
	}

	t.Run("the socket", func(t *testing.T) {
		me, err := whoAmI(b, allAccess(principal{kind: PrincipalLocal}, nil))
		require.NoError(t, err)

		got, err := json.Marshal(me)
		require.NoError(t, err)
		require.JSONEq(t, `{
			"principal": {"kind": "local", "identity": null, "user": null},
			"credential": null,
			"authorization": {"scopes": ["all"], "tags": null, "resources": "all"}
		}`, string(got))
	})

	t.Run("a token with no tags may give none", func(t *testing.T) {
		_, c, err := b.State.CreateOAuthClient([]string{"users:read"}, nil, "", nil)
		require.NoError(t, err)

		tok, _, err := b.State.MintAccessToken(c.ClientID, []string{"users:read"}, nil, &expiry)
		require.NoError(t, err)

		rec := api.Get(Prefix+"/me", "Authorization: Bearer "+tok)

		var got Me
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		require.Equal(t, []string{}, got.Authorization.Tags)
	})
}

func TestGetHealth(t *testing.T) {
	b := newBackend(t)
	api := newTestAPI(t, b)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	auth := "Authorization: Bearer " + key

	rec := api.Get(Prefix+"/health", auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.JSONEq(t, `{"healthy": true, "databaseConnectivity": true, "warnings": []}`, rec.Body.String())

	user := b.State.CreateUserForTest("user")
	tooLong := strings.Repeat("a", 300)

	for _, n := range []*types.Node{
		{ID: 41, UserID: &user.ID, GivenName: tooLong},
		{ID: 42, UserID: &user.ID, GivenName: tooLong + "b"},
		{ID: 43, UserID: &user.ID, GivenName: "ok", Expiry: new(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))},
	} {
		b.State.PutNodeInStoreForTest(*n)
	}

	rec = api.Get(Prefix+"/health", auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.JSONEq(t, `{"healthy": true, "databaseConnectivity": true, "warnings": [
		{"code": "node_name_invalid", "message": "2 nodes have a name that is not valid.", "details": {"count": 2}},
		{"code": "node_expiry_invalid", "message": "1 node has a key expiry that is not valid.", "details": {"count": 1}}
	]}`, rec.Body.String())

	t.Run("a database that does not answer is unhealthy", func(t *testing.T) {
		down := newBackend(t)
		require.NoError(t, down.State.Close())

		// Over the socket: a key could not be checked either.
		rec := httptest.NewRecorder()
		WithLocalTrust(Handler(down)).ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, Prefix+"/health", nil))

		p := decodeProblem(t, rec, CodeUnhealthy)
		require.Equal(t, map[string]any{"reasons": []any{
			map[string]any{"code": "database_unreachable", "message": "The database does not answer.", "details": map[string]any{}},
		}}, p.Details)
	})
}
