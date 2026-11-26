package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func postClient(api humatest.TestAPI, auth, body string) *httptest.ResponseRecorder {
	return api.Post(
		Prefix+"/oauth-clients",
		auth,
		"Content-Type: application/json",
		strings.NewReader(body),
	)
}

func decodeCreatedClient(
	t *testing.T,
	rec *httptest.ResponseRecorder,
) CreatedOAuthClient {
	t.Helper()

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var c CreatedOAuthClient
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &c), rec.Body.String())

	return c
}

func getClient(t *testing.T, api humatest.TestAPI, auth, id string) OAuthClient {
	t.Helper()

	rec := api.Get(Prefix+"/oauth-clients/"+id, auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var c OAuthClient
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &c))

	return c
}

// clientToken is an access token of the client with secret, minted as the
// token endpoint does.
func clientToken(t *testing.T, b Backend, secret string) string {
	t.Helper()

	client, err := b.State.AuthenticateOAuthClient(secret)
	require.NoError(t, err)

	token, _, err := b.State.MintAccessToken(
		client.ClientID,
		client.Scopes,
		client.Tags,
		new(time.Now().Add(time.Hour)),
	)
	require.NoError(t, err)

	return "Authorization: Bearer " + token
}

// TestScopesAreListed: the document names every scope a client may ask
// for, and still takes one it does not know, which the server answers with
// invalid_scope and the list of unknown scopes.
func TestScopesAreListed(t *testing.T) {
	reg := NewAPI(chi.NewMux(), Backend{}, specVersion).OpenAPI().Components.Schemas

	items := reg.Map()["CreateOAuthClientBody"].Properties["scopes"].Items
	require.Len(t, items.AnyOf, 2)

	known := make([]any, 0, len(scope.Known()))
	for _, s := range scope.Known() {
		known = append(known, string(s))
	}

	require.Equal(t, known, reg.SchemaFromRef(items.AnyOf[0].Ref).Enum)

	// A scope that is not text is still a field the schema refuses.
	//nolint:dogsled // the helper of the auth key tests
	_, api, auth, _, _ := authKeysAPI(t)
	p := decodeProblem(
		t,
		postClient(api, auth, `{"scopes": [5], "tags": ["tag:ci"]}`),
		CodeInvalidField,
	)
	require.Equal(t, []string{"body.scopes[0]"}, locations(p))
}

func TestCreateOAuthClient(t *testing.T) {
	b, api, auth, _, _ := authKeysAPI(t)

	t.Run("a client", func(t *testing.T) {
		rec := postClient(
			api,
			auth,
			`{"scopes": ["devices:core", "auth_keys", "auth_keys"], "tags": ["tag:ci", "tag:build", "tag:ci"], "description": "runners"}`,
		)
		c := decodeCreatedClient(t, rec)

		require.Equal(t, Prefix+"/oauth-clients/"+c.ID, rec.Header().Get("Location"))
		require.Len(t, c.ID, clientIDLength)
		require.True(t, strings.HasPrefix(c.Key, "hskey-client-"+c.ID+"-"))
		require.Equal(t, []string{"auth_keys", "devices:core"}, c.Scopes)
		require.Equal(t, []string{"tag:build", "tag:ci"}, c.Tags)
		require.Equal(
			t,
			"bob",
			c.CreatedBy.LoginName,
			"the owner of the API key that made it",
		)
		require.Equal(t, OAuthClientValid, c.State)
		require.Zero(t, c.Created.Nanosecond()%int(time.Microsecond))
		require.Equal(t, c.OAuthClient, getClient(t, api, auth, c.ID))

		// Its secret mints a token that works.
		rec = api.Get(Prefix+"/me", clientToken(t, b, c.Key))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("a scope that needs no tags", func(t *testing.T) {
		c := decodeCreatedClient(
			t,
			postClient(api, auth, `{"scopes": ["users:read"], "tags": []}`),
		)
		require.Equal(t, []string{}, c.Tags)
	})

	for _, tt := range []struct {
		name, body string
		code       Code
		details    map[string]any
		location   string
	}{
		{"no scopes", `{"tags": ["tag:ci"]}`, CodeInvalidField, nil, "body.scopes"},
		{"an empty scopes", `{"scopes": [], "tags": ["tag:ci"]}`, CodeInvalidField, nil, "body.scopes"},
		{"a scope that does not exist", `{"scopes": ["users", "nope", "devices:nope"], "tags": ["tag:ci"]}`, CodeInvalidScope, map[string]any{"scopes": []any{"devices:nope", "nope"}}, ""},
		{"a scope that needs tags, and none", `{"scopes": ["auth_keys", "users", "devices:core"]}`, CodeScopeRequiresTags, map[string]any{"scopes": []any{"auth_keys", "devices:core"}}, ""},
		{"an empty tags too", `{"scopes": ["auth_keys"], "tags": []}`, CodeScopeRequiresTags, map[string]any{"scopes": []any{"auth_keys"}}, ""},
		{"a tag the policy does not name", `{"scopes": ["auth_keys"], "tags": ["tag:ci", "tag:nope"]}`, CodeTagsNotPermitted, map[string]any{"tags": []any{"tag:nope"}}, ""},
		{"a description with a control character", `{"scopes": ["users"], "description": "a\u0007b"}`, CodeInvalidField, nil, "body.description"},
		{"null tags", `{"scopes": ["users"], "tags": null}`, CodeInvalidField, nil, "body.tags"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeProblem(t, postClient(api, auth, tt.body), tt.code)
			if tt.details != nil {
				require.Equal(t, tt.details, p.Details)
			}

			if tt.location != "" {
				require.Equal(t, tt.location, p.Errors[0].Location)
			}
		})
	}
}

// TestCreateOAuthClientTokenRules: a token gives a client only what it has,
// scopes as tags; the scopes are read from the request, the tags with the
// policy.
func TestCreateOAuthClientTokenRules(t *testing.T) {
	b, api, _, _, _ := authKeysAPI(t) //nolint:dogsled // tokens of its own

	ci := keysToken(t, b, []string{"tag:ci"}, "oauth_keys", "auth_keys")

	t.Run("its scopes and a tag its tag owns", func(t *testing.T) {
		c := decodeCreatedClient(
			t,
			postClient(
				api,
				ci,
				`{"scopes": ["auth_keys", "oauth_keys:read"], "tags": ["tag:web", "tag:ci"]}`,
			),
		)
		require.Nil(t, c.CreatedBy, "a token stands for no user")
	})

	for name, body := range map[string]string{
		"a scope it lacks": `{"scopes": ["auth_keys", "devices:core"], "tags": ["tag:ci"]}`,
		"all":              `{"scopes": ["all"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := decodeProblem(t, postClient(api, ci, body), CodeForbidden)
			require.Equal(t, "token_must_hold_scopes", p.Details["rule"])
		})
	}

	// The rule is checked on a body that is right in itself.
	for name, tc := range map[string]struct {
		body string
		code Code
	}{
		"a scope that does not exist":      {`{"scopes": ["nope"], "tags": ["tag:ci"]}`, CodeInvalidScope},
		"a scope it lacks, needing tags":   {`{"scopes": ["devices:core"]}`, CodeScopeRequiresTags},
		"a scope it lacks, a bad field":    {`{"scopes": ["users"], "description": "a\u0007b"}`, CodeInvalidField},
		"a scope it lacks, a long field":   {`{"scopes": ["users"], "description": "` + strings.Repeat("x", 51) + `"}`, CodeInvalidField},
		"a scope it lacks, an empty scope": {`{"scopes": []}`, CodeInvalidField},
	} {
		t.Run(name, func(t *testing.T) {
			decodeProblem(t, postClient(api, ci, tc.body), tc.code)
		})
	}

	t.Run("a tag it does not own", func(t *testing.T) {
		p := decodeProblem(
			t,
			postClient(
				api,
				ci,
				`{"scopes": ["auth_keys"], "tags": ["tag:ci", "tag:prod"]}`,
			),
			CodeForbidden,
		)
		require.Equal(t, "token_must_own_tags", p.Details["rule"])
	})

	t.Run("the request alone is answered before the policy", func(t *testing.T) {
		decodeProblem(
			t,
			postClient(api, ci, `{"scopes": ["auth_keys"]}`),
			CodeScopeRequiresTags,
		)
	})

	t.Run(
		"a token with all and tags makes a client with all and no tags",
		func(t *testing.T) {
			all := keysToken(t, b, []string{"tag:ci"}, "all")
			decodeCreatedClient(t, postClient(api, all, `{"scopes": ["all"]}`))
		},
	)

	t.Run("the read scope makes no client", func(t *testing.T) {
		p := decodeProblem(
			t,
			postClient(
				api,
				keysToken(t, b, nil, "oauth_keys:read"),
				`{"scopes": ["users"]}`,
			),
			CodeForbidden,
		)
		require.Equal(t, []any{"oauth_keys"}, p.Details["scopes"])
	})
}

func TestListOAuthClients(t *testing.T) {
	b, api, auth, _, _ := authKeysAPI(t)

	made := make([]string, 0, 3)

	for range 3 {
		made = append(
			made,
			decodeCreatedClient(t, postClient(api, auth, `{"scopes": ["users"]}`)).ID,
		)
	}

	require.Equal(
		t,
		http.StatusNoContent,
		api.Delete(Prefix+"/oauth-clients/"+made[1], auth).Code,
	)

	var (
		all   []OAuthClient
		token string
		pages int
	)

	for {
		q := "pageSize=2"
		if token != "" {
			q += "&pageToken=" + url.QueryEscape(token)
		}

		rec := api.Get(Prefix+"/oauth-clients?"+q, auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var l OAuthClientList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

		all = append(all, l.OAuthClients...)
		pages++

		if l.NextPageToken == "" {
			break
		}

		token = l.NextPageToken
	}

	require.Equal(t, 2, pages)
	require.Len(t, all, 3)

	for i, c := range all {
		require.Equal(t, made[i], c.ID, "in the order they were made")
	}

	require.Equal(
		t,
		[]OAuthClientState{OAuthClientValid, OAuthClientRevoked, OAuthClientValid},
		[]OAuthClientState{all[0].State, all[1].State, all[2].State},
	)

	t.Run("a token needs oauth_keys:read", func(t *testing.T) {
		p := decodeProblem(
			t,
			api.Get(Prefix+"/oauth-clients", keysToken(t, b, nil, "auth_keys")),
			CodeForbidden,
		)
		require.Equal(t, []any{"oauth_keys:read"}, p.Details["scopes"])
	})
}

func TestDeleteOAuthClient(t *testing.T) {
	b, api, auth, _, bob := authKeysAPI(t)

	c := decodeCreatedClient(
		t,
		postClient(api, auth, `{"scopes": ["oauth_keys", "users:read"]}`),
	)
	token := clientToken(t, b, c.Key)

	require.Equal(
		t,
		http.StatusOK,
		api.Get(Prefix+"/users", token).Code,
		"the token works before",
	)
	require.Equal(
		t,
		http.StatusNoContent,
		api.Delete(Prefix+"/oauth-clients/"+c.ID, auth).Code,
	)

	got := getClient(t, api, auth, c.ID)
	require.Equal(t, OAuthClientRevoked, got.State)
	require.Equal(t, got.Revoked.Add(7*24*time.Hour), *got.Removal)

	t.Run("a token minted before the revoke is refused", func(t *testing.T) {
		decodeProblem(t, api.Get(Prefix+"/users", token), CodeUnauthorized)
	})

	t.Run("the client mints no token", func(t *testing.T) {
		_, err := b.State.AuthenticateOAuthClient(c.Key)
		require.Error(t, err)
	})

	t.Run("again is 204 and changes nothing", func(t *testing.T) {
		require.Equal(
			t,
			http.StatusNoContent,
			api.Delete(Prefix+"/oauth-clients/"+c.ID, auth).Code,
		)
		require.Equal(t, got, getClient(t, api, auth, c.ID))
	})

	t.Run("a token revokes its own client", func(t *testing.T) {
		self := decodeCreatedClient(
			t,
			postClient(api, auth, `{"scopes": ["oauth_keys"]}`),
		)
		bearer := clientToken(t, b, self.Key)

		rec := api.Delete(Prefix+"/oauth-clients/"+self.ID, bearer)
		require.Equal(t, http.StatusNoContent, rec.Code)
		require.Empty(t, rec.Body.String())
		decodeProblem(t, api.Get(Prefix+"/me", bearer), CodeUnauthorized)
	})

	t.Run("a client whose maker is deleted stays, made by no one", func(t *testing.T) {
		require.Equal(t, "bob", got.CreatedBy.LoginName)

		// bob owns the API key of the request, which goes with him.
		other, _, err := b.State.CreateAPIKey(nil)
		require.NoError(t, err)

		_, err = b.State.DeleteUser(types.UserID(bob.ID))
		require.NoError(t, err)

		decodeProblem(t, api.Get(Prefix+"/me", auth), CodeUnauthorized)

		auth = "Authorization: Bearer " + other

		after := getClient(t, api, auth, c.ID)
		require.Nil(t, after.CreatedBy)
		require.Equal(t, OAuthClientRevoked, after.State)
	})

	for _, id := range []string{"999", "ABCDEF012345", "abcdef01234", c.Key} {
		t.Run("not found "+id[:min(len(id), 12)], func(t *testing.T) {
			decodeProblem(
				t,
				api.Delete(Prefix+"/oauth-clients/"+id, auth),
				CodeNotFound,
			)
			decodeProblem(t, api.Get(Prefix+"/oauth-clients/"+id, auth), CodeNotFound)
		})
	}
}
