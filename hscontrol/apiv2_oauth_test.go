package hscontrol

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestAPIv2OAuth_ScopeEnforcement(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	// A write-scoped token may create an auth key within its tag grant...
	_, writeSecret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:ci"})
	writeTok := tokenFor(t, baseURL, writeSecret)
	assert.Equal(t, http.StatusOK, createTaggedKey(t, baseURL, writeTok, []string{"tag:ci"}),
		"write scope + in-grant tag allowed")

	// ...but not with a tag outside its grant.
	assert.Equal(t, http.StatusForbidden, createTaggedKey(t, baseURL, writeTok, []string{"tag:other"}),
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
	assert.Equal(t, http.StatusForbidden, createTaggedKey(t, baseURL, tok, []string{"tag:other"}),
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

	// An existing policy tag outside the token's grant is denied, not silently set.
	st, _ = apiPost(t, devURL, tok, map[string]any{"tags": []string{"tag:other"}})
	assert.Equal(t, http.StatusForbidden, st, "out-of-grant tag must be denied")

	// An admin API key is unrestricted.
	st, body = apiPost(t, devURL, admin, map[string]any{"tags": []string{"tag:other"}})
	assert.Equalf(t, http.StatusOK, st, "admin may set any policy tag: %s", body)
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

	listKinds := func(bearer string) map[string]int {
		st, body := apiReq(t, http.MethodGet, keysURL, bearer, nil)
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
