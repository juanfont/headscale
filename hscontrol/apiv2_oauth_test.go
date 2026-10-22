package hscontrol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	clientv2 "github.com/juanfont/headscale/gen/client/v2"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	tskey "tailscale.com/types/key"
)

// newOAuthTestServer builds the full v2 API (the auth+scope middleware and the
// OAuth token endpoint, which the humatest harness in apiv2_keys_test.go does
// not mount) over a real httptest server, returning the app, its base URL, and
// an all-access admin API key.
func newOAuthTestServer(t *testing.T) (*Headscale, string, string) {
	t.Helper()

	app := createTestApp(t)

	// Tag creation now requires the tag to exist in policy (matching
	// SetNodeTags), so define the tags these tests assign. Tests needing
	// specific tag ownership (e.g. delegation) override this policy.
	const policy = `{"tagOwners":{"tag:a":[],"tag:b":[],"tag:c":[],"tag:ci":[],"tag:k8s":[],"tag:k8s-operator":[],"tag:other":[],"tag:anything":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

	_, err := app.state.SetPolicy([]byte(policy))
	require.NoError(t, err)
	_, err = app.state.SetPolicyInDB(policy)
	require.NoError(t, err)
	_, err = app.state.ReloadPolicy()
	require.NoError(t, err)

	mux, _ := apiv2.Handler(apiv2.Backend{State: app.state, Change: app.Change, Cfg: app.cfg})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	adminKey, _, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	return app, srv.URL, adminKey
}

// apiPost POSTs a JSON body with an optional bearer token, returning the status
// and raw body. It owns the response body so callers never leak it.
func apiPost(t *testing.T, target, bearer string, body any) (int, []byte) {
	t.Helper()

	b, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, data
}

// apiGet GETs a target with an optional bearer token, returning the status. It
// drains and closes the response body so callers never leak it.
func apiGet(t *testing.T, target, bearer string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	require.NoError(t, err)

	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode
}

// createClient creates an OAuth client through the v2 keys API as the bearer
// credential, returning the client id and the once-shown secret.
func createClient(t *testing.T, baseURL, bearer string, scopes, tags []string) (string, string) {
	t.Helper()

	status, body := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", bearer, apiv2.CreateKeyRequest{
		KeyType: "client",
		Scopes:  scopes,
		Tags:    tags,
	})
	require.Equalf(t, http.StatusOK, status, "create client: %s", body)

	var key apiv2.Key
	require.NoError(t, json.Unmarshal(body, &key))
	assert.Equal(t, "client", key.KeyType)
	require.NotEmpty(t, key.ID, "client id returned")
	require.NotEmpty(t, key.Key, "secret returned once on create")

	return key.ID, key.Key
}

// mintToken runs the client-credentials grant. scope is an optional space-delimited
// narrowing of the client's scopes. credsInBasic sends the secret via HTTP Basic
// instead of the body. Returns the status and decoded JSON body.
func mintToken(t *testing.T, baseURL, clientID, secret, scope string, credsInBasic bool) (int, map[string]any) {
	t.Helper()

	form := url.Values{"grant_type": {"client_credentials"}}
	if scope != "" {
		form.Set("scope", scope)
	}

	if !credsInBasic {
		form.Set("client_secret", secret)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		baseURL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if credsInBasic {
		req.SetBasicAuth(clientID, secret)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	var m map[string]any

	_ = json.Unmarshal(data, &m)

	return resp.StatusCode, m
}

// tokenFor mints and returns a bearer access token for the client.
func tokenFor(t *testing.T, baseURL, secret string) string {
	t.Helper()

	status, m := mintToken(t, baseURL, "", secret, "", false)
	require.Equalf(t, http.StatusOK, status, "mint token: %v", m)

	tok, _ := m["access_token"].(string)
	require.NotEmpty(t, tok)

	return tok
}

// createTaggedKey attempts to create a tagged auth key and returns the HTTP
// status, so allow/deny is asserted by the caller.
func createTaggedKey(t *testing.T, baseURL, bearer string, tags []string) int {
	t.Helper()

	status, _ := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", bearer, apiv2.CreateKeyRequest{
		Capabilities: &apiv2.KeyCapabilities{Devices: apiv2.KeyDeviceCapabilities{
			Create: apiv2.KeyDeviceCreateCapabilities{Reusable: true, Tags: tags},
		}},
	})

	return status
}

func TestAPIv2OAuth_TokenEndpoint(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	clientID, secret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:ci"})

	// The secret embeds the client id (Tailscale's derive-from-secret trick).
	assert.Contains(t, secret, clientID)

	// Mint via the request body.
	status, m := mintToken(t, baseURL, clientID, secret, "", false)
	require.Equalf(t, http.StatusOK, status, "%v", m)
	assert.Equal(t, "Bearer", m["token_type"])
	assert.InDelta(t, 3600, m["expires_in"], 0, "fixed 1h, in seconds")
	tok, _ := m["access_token"].(string)
	assert.Contains(t, tok, "hskey-oauthtok-", "distinct prefix from admin keys")

	// Mint via HTTP Basic (x/oauth2 auto-detect probes Basic first).
	statusBasic, mBasic := mintToken(t, baseURL, clientID, secret, "", true)
	require.Equalf(t, http.StatusOK, statusBasic, "%v", mBasic)
	assert.NotEmpty(t, mBasic["access_token"])

	// The answer names the scopes stored on the token, each once.
	statusDup, mDup := mintToken(t, baseURL, clientID, secret, strings.Repeat("auth_keys ", 2), false)
	require.Equalf(t, http.StatusOK, statusDup, "%v", mDup)
	assert.Equal(t, "auth_keys", mDup["scope"])

	// It names the tags of a token that can assign them; a reader token's
	// answer has no tags field, whatever its client's tags.
	assert.Equal(t, "tag:ci", m["tags"])

	_, readerSecret := createClient(t, baseURL, admin, []string{"auth_keys:read"}, []string{"tag:ci"})
	statusReader, mReader := mintToken(t, baseURL, "", readerSecret, "", false)
	require.Equalf(t, http.StatusOK, statusReader, "%v", mReader)
	assert.NotContains(t, mReader, "tags")

	// Bad credentials → RFC 6749 invalid_client.
	statusBad, mBad := mintToken(t, baseURL, clientID, "hskey-client-deadbeefdead-"+stringOf("0", 64), "", false)
	assert.Equal(t, http.StatusUnauthorized, statusBad)
	assert.Equal(t, "invalid_client", mBad["error"])

	// The token response carries a bearer credential and must not be cached
	// (RFC 6749 §5.1). mintToken consumes the body, so probe the header raw.
	form := url.Values{"grant_type": {"client_credentials"}, "client_secret": {secret}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		baseURL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
}

// TestAPIv2OAuth_RequestBodiesBounded: the token form is parsed before the
// secret is checked, and huma validates a whole body before the handler runs.
func TestAPIv2OAuth_RequestBodiesBounded(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)
	_, secret := createClient(t, baseURL, admin, []string{"users:read"}, nil)

	scopes := strings.TrimSpace(strings.Repeat("users:read ", 2000))
	status, m := mintToken(t, baseURL, "", secret, scopes, false)
	assert.Equalf(t, http.StatusBadRequest, status, "%v", m)
	assert.Equal(t, "invalid_request", m["error"])

	tok := mintScopedToken(t, baseURL, admin, scope.AuthKeys)
	status, _ = apiReq(t, http.MethodPost, baseURL+"/api/v2/tailnet/-/keys", tok,
		map[string]any{"tags": make([]int, 40000)})
	assert.Equal(t, http.StatusRequestEntityTooLarge, status)
}

// TestAPIv2OAuth_ValidationErrorsBounded: huma reports one error per bad
// element of the body, and each carries the element as its value.
func TestAPIv2OAuth_ValidationErrorsBounded(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)
	tok := mintScopedToken(t, baseURL, admin, scope.AuthKeys)

	tags := make([]map[string]string, 1000)
	for i := range tags {
		tags[i] = map[string]string{"pad": fmt.Sprintf("%040d", i)}
	}

	body := map[string]any{"capabilities": map[string]any{"devices": map[string]any{
		"create": map[string]any{"reusable": true, "ephemeral": false, "preauthorized": true, "tags": tags},
	}}}

	status, resp := apiReq(t, http.MethodPost, baseURL+"/api/v2/tailnet/-/keys", tok, body)
	require.Equal(t, http.StatusUnprocessableEntity, status)
	require.Less(t, len(resp), 16<<10, "the error answer grows with the request")
	assert.NotContains(t, string(resp), "map[")

	var out struct {
		Data []struct{ Errors []string }
	}
	require.NoError(t, json.Unmarshal(resp, &out))
	require.Len(t, out.Data, 1)
	require.Len(t, out.Data[0].Errors, 21)
	assert.Equal(t, "and 980 more", out.Data[0].Errors[20])
}

// TestAPIv2OAuth_TaggedKeyCreator: an admin key's user is the creator of the
// tagged keys it makes and shows as their userId; a node joined with such a
// key is tagged. A token's tagged key has no creator.
func TestAPIv2OAuth_TaggedKeyCreator(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	owner := app.state.CreateUserForTest("odin")
	ownerKey, apiKey, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, app.state.SetAPIKeyUser(apiKey.ID, types.UserID(owner.ID)))

	create := func(bearer string) apiv2.Key {
		t.Helper()

		status, body := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", bearer, apiv2.CreateKeyRequest{
			Capabilities: &apiv2.KeyCapabilities{Devices: apiv2.KeyDeviceCapabilities{
				Create: apiv2.KeyDeviceCreateCapabilities{Reusable: true, Tags: []string{"tag:ci"}},
			}},
		})
		require.Equalf(t, http.StatusOK, status, "body: %s", body)

		var key apiv2.Key
		require.NoError(t, json.Unmarshal(body, &key))

		return key
	}

	key := create(ownerKey)
	assert.Equal(t, owner.StringID(), key.UserID)

	status, body := apiReq(t, http.MethodGet, baseURL+"/api/v2/tailnet/-/keys/"+key.ID, admin, nil)
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, string(body), `"userId":"`+owner.StringID()+`"`)

	node, _, err := app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key.Key},
		NodeKey:  tskey.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "made-by-odin"},
	}, tskey.NewMachine().Public())
	require.NoError(t, err)
	assert.True(t, node.IsTagged())
	assert.Equal(t, []string{"tag:ci"}, node.Tags().AsSlice())

	tok := mintScopedToken(t, baseURL, admin, scope.AuthKeys)
	assert.Empty(t, create(tok).UserID)

	// The key and the node's copy of it outlive the creator.
	_, err = app.state.DeleteUser(*owner.TypedID())
	require.NoError(t, err)

	status, body = apiReq(t, http.MethodGet, baseURL+"/api/v2/tailnet/-/keys/"+key.ID, admin, nil)
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
	assert.NotContains(t, string(body), `"userId"`)

	nv, ok := app.state.GetNodeByID(node.ID())
	require.True(t, ok)
	require.True(t, nv.AuthKey().Valid())
	assert.False(t, nv.AuthKey().User().Valid())
}

// TestAPIv2OAuth_TaggedDeviceUser: a tagged device shows the login that made
// the key it joined with, and nothing for a key a token made; it stays owned
// by its tags.
func TestAPIv2OAuth_TaggedDeviceUser(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	owner := app.state.CreateUserForTest("odin")
	ownerKey, apiKey, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, app.state.SetAPIKeyUser(apiKey.ID, types.UserID(owner.ID)))

	tok := mintScopedToken(t, baseURL, admin, scope.AuthKeys)

	for bearer, want := range map[string]string{ownerKey: owner.Username(), tok: ""} {
		status, body := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", bearer, apiv2.CreateKeyRequest{
			Capabilities: &apiv2.KeyCapabilities{Devices: apiv2.KeyDeviceCapabilities{
				Create: apiv2.KeyDeviceCreateCapabilities{Tags: []string{"tag:ci"}},
			}},
		})
		require.Equalf(t, http.StatusOK, status, "body: %s", body)

		var key apiv2.Key
		require.NoError(t, json.Unmarshal(body, &key))

		node, _, err := app.state.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: key.Key},
			NodeKey:  tskey.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: "tagged"},
		}, tskey.NewMachine().Public())
		require.NoError(t, err)
		require.True(t, node.IsTagged())

		status, body = apiReq(t, http.MethodGet, baseURL+"/api/v2/device/"+node.StringID(), admin, nil)
		require.Equalf(t, http.StatusOK, status, "body: %s", body)

		var dev apiv2.Device
		require.NoError(t, json.Unmarshal(body, &dev))
		assert.Equal(t, want, dev.User)
		assert.Equal(t, []string{"tag:ci"}, dev.Tags)

		// oauthClientId names the join key, unless a token made it.
		if bearer == tok {
			assert.Empty(t, dev.OAuthClientID)
		} else {
			assert.Equal(t, key.ID, dev.OAuthClientID)
		}

		if want == "" {
			continue
		}

		// The creator's rename reaches the devices its keys made.
		renamed, _, err := app.state.RenameUser(types.UserID(owner.ID), "thor")
		require.NoError(t, err)

		status, body = apiReq(t, http.MethodGet, baseURL+"/api/v2/device/"+node.StringID(), admin, nil)
		require.Equalf(t, http.StatusOK, status, "body: %s", body)
		require.NoError(t, json.Unmarshal(body, &dev))
		assert.Equal(t, renamed.Username(), dev.User)
	}
}

// TestAPIv2OAuth_KeyListing: a listing never holds an invalid key; without
// all=true a token sees only the auth keys tokens made, whatever their tags.
func TestAPIv2OAuth_KeyListing(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	adminKey := createAdminAuthKey(t, baseURL, admin)

	revoked := createAdminAuthKey(t, baseURL, admin)
	status, _ := apiReq(t, http.MethodDelete, baseURL+"/api/v2/tailnet/-/keys/"+revoked, admin, nil)
	require.Equal(t, http.StatusOK, status)

	maker := mintScopedToken(t, baseURL, admin, scope.AuthKeys)
	require.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, maker, []string{"tag:ci"}))

	keys, err := app.state.ListPreAuthKeys()
	require.NoError(t, err)

	var tokenKey string

	for _, k := range keys {
		if k.CreatedByToken {
			tokenKey = k.StringID()
		}
	}

	require.NotEmpty(t, tokenKey, "the token's key is marked")

	_, readerSecret := createClient(t, baseURL, admin, []string{"auth_keys:read"}, nil)
	reader := tokenFor(t, baseURL, readerSecret)

	listed := func(bearer, query string) []string {
		t.Helper()

		status, body := apiReq(t, http.MethodGet, baseURL+"/api/v2/tailnet/-/keys"+query, bearer, nil)
		require.Equalf(t, http.StatusOK, status, "body: %s", body)

		var out struct{ Keys []apiv2.Key }
		require.NoError(t, json.Unmarshal(body, &out))

		ids := make([]string, 0, len(out.Keys))
		for _, k := range out.Keys {
			if k.KeyType == "auth" {
				ids = append(ids, k.ID)
			}
		}

		slices.Sort(ids)

		return ids
	}

	every := []string{adminKey, tokenKey}
	slices.Sort(every)

	for _, bearer := range []string{reader, maker} {
		assert.Equal(t, []string{tokenKey}, listed(bearer, ""))
		assert.Equal(t, every, listed(bearer, "?all=true"))
	}

	assert.Equal(t, every, listed(admin, ""))
	assert.Equal(t, every, listed(admin, "?all=true"))
}

// TestAPIv2OAuth_UnknownKeyTypeRefused: a keyType other than auth or client
// is refused, not taken as an auth key.
func TestAPIv2OAuth_UnknownKeyTypeRefused(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	status, body := apiReq(t, http.MethodPost, baseURL+"/api/v2/tailnet/-/keys", admin, map[string]any{
		"keyType": "nosuch",
		"capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{
			"reusable": true, "ephemeral": false, "preauthorized": true, "tags": []string{"tag:ci"},
		}}},
	})
	assert.Equal(t, http.StatusBadRequest, status)
	assert.Contains(t, string(body), `invalid key type, \"nosuch\" is not supported`)

	keys, err := app.state.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestAPIv2OAuth_UnknownPropertiesIgnored: a body property the API does not
// define is ignored, at the top and nested, as Tailscale's API does.
func TestAPIv2OAuth_UnknownPropertiesIgnored(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	status, body := apiReq(t, http.MethodPost, baseURL+"/api/v2/tailnet/-/keys", admin, map[string]any{
		"deviceDescription": "x",
		"capabilities": map[string]any{"devices": map[string]any{
			"create": map[string]any{
				"reusable": true, "ephemeral": false, "preauthorized": true,
				"tags": []string{"tag:ci"}, "unknown": true,
			},
		}},
	})
	require.Equalf(t, http.StatusOK, status, "body: %s", body)

	var key apiv2.Key
	require.NoError(t, json.Unmarshal(body, &key))
	assert.Equal(t, []string{"tag:ci"}, key.Capabilities.Devices.Create.Tags)
}

// TestAPIv2OAuth_GeneratedClientNilTags: the generated client's request
// types send a nil tags list as null, which the server takes as no tags.
func TestAPIv2OAuth_GeneratedClientNilTags(t *testing.T) {
	e := newDeviceTestEnv(t)

	resp := e.api.Post("/api/v2/device/"+e.deviceID+"/tags", clientv2.SetTagsRequest{})
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	app, baseURL, _ := newOAuthTestServer(t)
	owner := app.state.CreateUserForTest("odin")
	ownerKey, apiKey, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, app.state.SetAPIKeyUser(apiKey.ID, *owner.TypedID()))

	status, body := apiReq(t, http.MethodPost, baseURL+"/api/v2/tailnet/-/keys", ownerKey,
		clientv2.CreateKeyRequest{Capabilities: &clientv2.KeyCapabilities{}})
	require.Equalf(t, http.StatusOK, status, "body: %s", body)
}

func TestAPIv2OAuth_ScopeEnforcement(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	// A write-scoped token may create an auth key within its tag grant...
	_, writeSecret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:ci"})
	writeTok := tokenFor(t, baseURL, writeSecret)
	assert.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, writeTok, []string{"tag:ci"}),
		"write scope + in-grant tag allowed")

	// ...but not with a tag outside its grant.
	assert.Equal(t, http.StatusBadRequest, createTaggedKey(t, baseURL, writeTok, []string{"tag:other"}),
		"tag outside grant denied")

	// A read-only token is denied the write.
	_, readSecret := createClient(t, baseURL, admin, []string{"auth_keys:read"}, []string{"tag:ci"})
	readTok := tokenFor(t, baseURL, readSecret)
	assert.Equal(t, http.StatusForbidden, createTaggedKey(t, baseURL, readTok, []string{"tag:ci"}),
		"read scope denied write")

	// The wrong write scope (devices:core) cannot create auth keys.
	_, devSecret := createClient(t, baseURL, admin, []string{"devices:core"}, []string{"tag:ci"})
	devTok := tokenFor(t, baseURL, devSecret)
	assert.Equal(t, http.StatusForbidden, createTaggedKey(t, baseURL, devTok, []string{"tag:ci"}),
		"wrong scope denied")

	// The "all" super-scope grants auth_keys.
	_, allSecret := createClient(t, baseURL, admin, []string{"all"}, []string{"tag:ci"})
	allTok := tokenFor(t, baseURL, allSecret)
	assert.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, allTok, []string{"tag:ci"}),
		"all grants auth_keys")

	// A token minted from the all-powerful client but narrowed to read-only is
	// itself denied writes: narrowing is enforced on the minted token.
	statusNarrow, mNarrow := mintToken(t, baseURL, "", allSecret, "auth_keys:read", false)
	require.Equalf(t, http.StatusOK, statusNarrow, "narrow mint: %v", mNarrow)
	narrowed, _ := mNarrow["access_token"].(string)
	assert.Equal(t, http.StatusForbidden, createTaggedKey(t, baseURL, narrowed, []string{"tag:ci"}),
		"token narrowed to :read denied write")
}

func TestAPIv2OAuth_ClientManagementScopes(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	// An oauth_keys token may create a client within its own grant...
	_, okSecret := createClient(t, baseURL, admin, []string{"oauth_keys"}, []string{"tag:ci"})
	okTok := tokenFor(t, baseURL, okSecret)
	status, body := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", okTok, apiv2.CreateKeyRequest{
		KeyType: "client", Scopes: []string{"oauth_keys:read"},
	})
	assert.Equalf(t, http.StatusOK, status, "oauth_keys creates an in-grant client: %s", body)

	// ...but may NOT escalate by granting the new client a scope the token lacks.
	statusEsc, _ := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", okTok, apiv2.CreateKeyRequest{
		KeyType: "client", Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"},
	})
	assert.Equal(t, http.StatusForbidden, statusEsc, "oauth_keys token cannot mint a broader client")

	// A token without oauth_keys cannot manage clients at all.
	_, akSecret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:ci"})
	akTok := tokenFor(t, baseURL, akSecret)
	statusDeny, _ := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", akTok, apiv2.CreateKeyRequest{
		KeyType: "client", Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"},
	})
	assert.Equal(t, http.StatusForbidden, statusDeny, "auth_keys (no oauth_keys) cannot create a client")
}

// TestAPIv2OAuth_TaggedAllClientStaysInTags asserts an all-scope client with
// tags mints tokens only inside its tags, and that a tagged token cannot
// escape them through an untagged all-scope child, whose tokens may take any
// tag.
func TestAPIv2OAuth_TaggedAllClientStaysInTags(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	_, secret := createClient(t, baseURL, admin, []string{"all"}, []string{"tag:a"})

	st, m := mintTokenWithTags(t, baseURL, secret, "tag:b")
	assert.Equalf(t, http.StatusBadRequest, st, "%v", m)
	assert.Equal(t, "requested tags [tag:b] are invalid or not permitted", m["error_description"])

	tok := tokenFor(t, baseURL, secret)
	assert.Equal(t, http.StatusBadRequest,
		createTaggedKey(t, baseURL, tok, []string{"tag:b"}),
		"the token is held to its tags")

	// A tagged child stays inside its tags.
	_, childSecret := createClient(t, baseURL, tok, []string{"all"}, []string{"tag:a"})
	st, m = mintTokenWithTags(t, baseURL, childSecret, "tag:b")
	assert.Equalf(t, http.StatusBadRequest, st, "tagged child: %v", m)

	createClient(t, baseURL, tok, []string{"auth_keys", "oauth_keys"}, []string{"tag:a"})

	st, body := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", tok,
		apiv2.CreateKeyRequest{KeyType: "client", Scopes: []string{"all"}})
	assert.Equalf(t, http.StatusForbidden, st, "untagged all-scope child: %s", body)

	// An admin API key still creates an untagged all-scope client, whose
	// tokens may take any tag.
	_, anySecret := createClient(t, baseURL, admin, []string{"all"}, nil)
	st, m = mintTokenWithTags(t, baseURL, anySecret, "tag:b")
	assert.Equalf(t, http.StatusOK, st, "%v", m)
}

func TestAPIv2OAuth_TagOwnedBy(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	// tag:k8s is owned by tag:k8s-operator: the operator's tag delegation.
	// tag:other exists but is owned by no one, so it tests grant denial (403)
	// rather than tag-not-in-policy (400).
	const policy = `{"tagOwners":{"tag:k8s-operator":[],"tag:k8s":["tag:k8s-operator"],"tag:other":[]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

	_, err := app.state.SetPolicy([]byte(policy))
	require.NoError(t, err)
	_, err = app.state.SetPolicyInDB(policy)
	require.NoError(t, err)
	_, err = app.state.ReloadPolicy()
	require.NoError(t, err)

	_, secret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:k8s-operator"})
	tok := tokenFor(t, baseURL, secret)

	// Exact-match tag: allowed.
	assert.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, tok, []string{"tag:k8s-operator"}),
		"a token may use its own tag")

	// Owned-by tag: allowed (tag:k8s is owned by tag:k8s-operator).
	assert.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, tok, []string{"tag:k8s"}),
		"a token may use a tag owned by its tag")

	// Unrelated tag: denied.
	assert.Equal(t, http.StatusBadRequest, createTaggedKey(t, baseURL, tok, []string{"tag:other"}),
		"a token may not use an unowned tag")
}

// TestAPIv2OAuth_NoClientExistenceOracle asserts a token that cannot read OAuth
// clients gets the same response for a real client id as for a missing key, so
// it cannot enumerate which ids are OAuth clients.
func TestAPIv2OAuth_NoClientExistenceOracle(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	clientID, _ := createClient(t, baseURL, admin, []string{"oauth_keys"}, []string{"tag:ci"})

	// A token holding only auth_keys:read (no oauth_keys:read).
	_, akSecret := createClient(t, baseURL, admin, []string{"auth_keys:read"}, []string{"tag:ci"})
	akTok := tokenFor(t, baseURL, akSecret)

	statusReal := apiGet(t, baseURL+"/api/v2/tailnet/-/keys/"+clientID, akTok)
	statusMissing := apiGet(t, baseURL+"/api/v2/tailnet/-/keys/deadbeefdead", akTok)

	assert.Equal(t, statusMissing, statusReal,
		"a token without oauth_keys:read must not distinguish a real client id from a missing key")
	assert.NotEqual(t, http.StatusOK, statusReal, "the client must not be readable")

	// A token that does hold oauth_keys:read can read the client.
	_, okSecret := createClient(t, baseURL, admin, []string{"oauth_keys:read"}, []string{"tag:ci"})
	okTok := tokenFor(t, baseURL, okSecret)

	statusOK := apiGet(t, baseURL+"/api/v2/tailnet/-/keys/"+clientID, okTok)
	assert.Equal(t, http.StatusOK, statusOK, "oauth_keys:read may read the client")
}

// TestAPIv2OAuth_SetDeviceTagsGrant asserts a devices:core token may only set
// tags within its grant on a device. Without the grant check, the scope alone
// would let a token stamp any existing policy tag (e.g. tag:other) onto any node.
func TestAPIv2OAuth_SetDeviceTagsGrant(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	// A registered, user-owned node to retag.
	user := app.state.CreateUserForTest("dut")
	node := app.state.CreateRegisteredNodeForTest(user, "dut")
	node.User = user
	view := app.state.PutNodeInStoreForTest(*node)
	devURL := baseURL + "/api/v2/device/" + view.StringID() + "/tags"

	// A devices:core token granted only tag:ci.
	_, secret := createClient(t, baseURL, admin, []string{"devices:core"}, []string{"tag:ci"})
	tok := tokenFor(t, baseURL, secret)

	// In-grant tag is allowed.
	st, body := apiPost(t, devURL, tok, map[string]any{"tags": []string{"tag:ci"}})
	assert.Equalf(t, http.StatusOK, st, "in-grant tag: %s", body)

	// The device now carries only tags within the grant.
	st, body = apiPost(t, devURL, tok, map[string]any{"tags": []string{"tag:ci"}})
	assert.Equalf(t, http.StatusOK, st, "in-grant device: %s", body)

	// An existing policy tag outside the token's grant is denied, not silently set.
	st, body = apiPost(t, devURL, tok, map[string]any{"tags": []string{"tag:other"}})
	assert.Equal(t, http.StatusBadRequest, st, "out-of-grant tag must be denied")
	assert.Contains(t, string(body), "requested tags [tag:other] are invalid or not permitted")

	// An admin API key is unrestricted.
	st, body = apiPost(t, devURL, admin, map[string]any{"tags": []string{"tag:other"}})
	assert.Equalf(t, http.StatusOK, st, "admin may set any policy tag: %s", body)

	// SetNodeTags replaces the set, so retagging would remove tag:other.
	st, body = apiPost(t, devURL, tok, map[string]any{"tags": []string{"tag:ci", "tag:other"}})
	assert.Equal(t, http.StatusBadRequest, st, "token must not retag an out-of-grant device")
	assert.Contains(t, string(body),
		"cannot remove current tags: requested tags [tag:other] are invalid or not permitted")

	got, ok := app.state.GetNodeByID(view.ID())
	require.True(t, ok)
	assert.Equal(t, []string{"tag:other"}, got.Tags().AsSlice())
}

// TestAPIv2OAuth_UndefinedTagRejected asserts an OAuth token cannot create a
// client or auth key carrying a tag absent from policy (matching SetNodeTags),
// while an admin key retains the historical syntax-only validation.
func TestAPIv2OAuth_UndefinedTagRejected(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	// A token that may create clients and auth keys, holding tag:ci (in policy).
	_, secret := createClient(t, baseURL, admin, []string{"oauth_keys", "auth_keys"}, []string{"tag:ci"})
	tok := tokenFor(t, baseURL, secret)

	// A token-created auth key with a tag not in policy is rejected.
	assert.Equal(t, http.StatusBadRequest, createTaggedKey(t, baseURL, tok, []string{"tag:undefined"}),
		"token may not create an auth key with an undefined tag")

	// A token-created client with a tag not in policy is rejected.
	st, _ := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", tok, apiv2.CreateKeyRequest{
		KeyType: "client", Scopes: []string{"auth_keys"}, Tags: []string{"tag:undefined"},
	})
	assert.Equal(t, http.StatusBadRequest, st, "token may not create a client with an undefined tag")

	// An admin key keeps the historical behaviour: a syntactically valid but
	// undefined tag is accepted (consistent with the v1/CLI pre-auth-key path).
	assert.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, admin, []string{"tag:adminhistorical"}),
		"admin retains syntax-only tag validation")
}

// TestAPIv2OAuth_DenialBranches covers the token-endpoint and bearer-dispatch
// failure paths: each must fail closed with the right status and no session.
func TestAPIv2OAuth_DenialBranches(t *testing.T) {
	_, baseURL, _ := newOAuthTestServer(t)
	tokenURL := baseURL + "/api/v2/oauth/token"
	keysURL := baseURL + "/api/v2/tailnet/-/keys"

	post := func(form string) (int, map[string]any) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, tokenURL, strings.NewReader(form))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		data, _ := io.ReadAll(resp.Body)

		var m map[string]any

		_ = json.Unmarshal(data, &m)

		return resp.StatusCode, m
	}

	// No credentials → invalid_client.
	st, m := post("grant_type=client_credentials")
	assert.Equal(t, http.StatusUnauthorized, st)
	assert.Equal(t, "invalid_client", m["error"])

	// Wrong grant_type → unsupported_grant_type.
	st, m = post("grant_type=authorization_code&client_secret=x")
	assert.Equal(t, http.StatusBadRequest, st)
	assert.Equal(t, "unsupported_grant_type", m["error"])

	// Unknown secret → invalid_client.
	st, m = post("grant_type=client_credentials&client_secret=not-a-real-secret")
	assert.Equal(t, http.StatusUnauthorized, st)
	assert.Equal(t, "invalid_client", m["error"])

	// Bearer dispatch: every malformed/unknown bearer is unauthorized.
	for _, bearer := range []string{
		"hskey-oauthtok-deadbeefdead-" + stringOf("0", 64), // well-formed prefix, unknown token
		"hskey-oauthtok-garbage",                           // malformed OAuth token
		"hskey-client-deadbeefdead-" + stringOf("0", 64),   // client secret presented as API bearer
		"totally-bogus",
	} {
		assert.Equalf(t, http.StatusUnauthorized, apiGet(t, keysURL, bearer),
			"bearer %q must be unauthorized", bearer)
	}
}

// TestAPIv2OAuth_KeysMultiplexIsolation asserts the multiplexed keys endpoint
// keeps the two kinds isolated by scope: a token cannot list or delete a kind it
// lacks the scope for, and an admin key sees both.
func TestAPIv2OAuth_KeysMultiplexIsolation(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)
	keysURL := baseURL + "/api/v2/tailnet/-/keys"

	clientID, _ := createClient(t, baseURL, admin, []string{"oauth_keys"}, []string{"tag:ci"})
	require.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, admin, []string{"tag:ci"}))

	// all=true, so a token sees the admin's auth key too.
	listKinds := func(bearer string) map[string]int {
		st, body := apiReq(t, http.MethodGet, keysURL+"?all=true", bearer, nil)
		require.Equalf(t, http.StatusOK, st, "%s", body)

		var out struct {
			Keys []apiv2.Key `json:"keys"`
		}

		require.NoError(t, json.Unmarshal(body, &out))

		kinds := map[string]int{}
		for _, k := range out.Keys {
			kinds[k.KeyType]++
		}

		return kinds
	}

	_, akReadSecret := createClient(t, baseURL, admin, []string{"auth_keys:read"}, []string{"tag:ci"})
	akKinds := listKinds(tokenFor(t, baseURL, akReadSecret))
	assert.Zero(t, akKinds["client"], "auth_keys:read must not see OAuth clients")
	assert.Positive(t, akKinds["auth"], "auth_keys:read sees auth keys")

	_, okReadSecret := createClient(t, baseURL, admin, []string{"oauth_keys:read"}, []string{"tag:ci"})
	okKinds := listKinds(tokenFor(t, baseURL, okReadSecret))
	assert.Zero(t, okKinds["auth"], "oauth_keys:read must not see auth keys")
	assert.Positive(t, okKinds["client"], "oauth_keys:read sees OAuth clients")

	adminKinds := listKinds(admin)
	assert.Positive(t, adminKinds["auth"])
	assert.Positive(t, adminKinds["client"])

	// An auth_keys (write) token cannot delete an OAuth client; it survives.
	_, akWriteSecret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:ci"})
	stDel, _ := apiReq(t, http.MethodDelete, keysURL+"/"+clientID, tokenFor(t, baseURL, akWriteSecret), nil)
	assert.NotEqual(t, http.StatusOK, stDel, "auth_keys token must not delete an OAuth client")
	assert.Positive(t, listKinds(admin)["client"], "client survives the denied delete")

	// An oauth_keys (write) token deletes the client.
	_, okWriteSecret := createClient(t, baseURL, admin, []string{"oauth_keys"}, []string{"tag:ci"})
	stDel2, body2 := apiReq(t, http.MethodDelete, keysURL+"/"+clientID, tokenFor(t, baseURL, okWriteSecret), nil)
	assert.Equalf(t, http.StatusOK, stDel2, "oauth_keys deletes the client: %s", body2)
}

func stringOf(s string, n int) string {
	return strings.Repeat(s, n)
}

// TestAPIv2OAuth_SetDeviceRoutesCompat creates the devices:routes client SaaS
// created, replays the route calls its token made on routers announcing the
// tailnet's own addresses, and compares each answer with SaaS.
//
// Test data source:
// policy/v2/testdata/routes_results/routes-t5-oauth-routes-scope.hujson,
// shared with TestRoutesCompat* and TestRoutesTailnetOverlapCompat.
func TestAPIv2OAuth_SetDeviceRoutesCompat(t *testing.T) {
	c := readRoutesCapture(t, "routes-t5-oauth-routes-scope")
	app, baseURL, admin := newOAuthTestServer(t)
	devices := seedCaptureRouters(t, app, c)

	setup := c.Steps[0]
	require.Equal(t, "oauth-client", setup.Name)

	create, mint := setup.Actions[0], setup.Actions[1]
	key := c.TestID + "/" + setup.Name + "/"

	status, body := apiPost(t, baseURL+"/api/v2/tailnet/-/keys", admin, create.Body)
	compatCheck(t, key+"0/status", strconv.Itoa(create.Status), strconv.Itoa(status))

	var client apiv2.Key
	require.NoErrorf(t, json.Unmarshal(body, &client), "body: %s", body)
	require.NotEmpty(t, client.Key, "client secret")

	tokenFields := func(m map[string]any) string {
		return fmt.Sprintf("scope %v type %v expires_in %v", m["scope"], m["token_type"], m["expires_in"])
	}

	var wantToken map[string]any
	require.NoError(t, json.Unmarshal(mint.Response, &wantToken))

	status, token := mintToken(t, baseURL, client.ID, client.Key, *mint.Scope, false)
	compatCheck(t, key+"1/status", strconv.Itoa(mint.Status), strconv.Itoa(status))
	compatCheck(t, key+"1/token", tokenFields(wantToken), tokenFields(token))

	bearer, _ := token["access_token"].(string)
	require.NotEmpty(t, bearer, "access token")

	replayRouteCalls(t, c, "", func(a testcapture.Action, alias string) routeCall {
		require.Equal(t, "token:"+create.Client, a.Principal)

		target := baseURL + "/api/v2/device/" + devices[alias] + "/routes"
		if a.Method == http.MethodPost {
			status, body := apiPost(t, target, bearer, a.Body)

			return v2RouteCall(t, status, body)
		}

		req, err := http.NewRequestWithContext(t.Context(), a.Method, target, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+bearer)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		return v2RouteCall(t, resp.StatusCode, raw)
	})
}
