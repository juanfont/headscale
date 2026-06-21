package hscontrol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiReq issues an arbitrary-method request with an optional bearer token and JSON
// body, returning the status and raw body. It owns the response body.
func apiReq(t *testing.T, method, target, bearer string, body any) (int, []byte) {
	t.Helper()

	var r io.Reader

	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)

		r = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, target, r)
	require.NoError(t, err)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)

	return resp.StatusCode, data
}

// scopeDenied reports whether a response is a scope-enforcement denial. The scope
// gate runs in the middleware before the handler, so a denial is exactly a 403
// carrying this message; any other status (200, or a 400/404 from the handler on
// minimal input) means the request passed the scope gate.
func scopeDenied(status int, body []byte) bool {
	return status == http.StatusForbidden &&
		strings.Contains(string(body), "missing the required scope")
}

// mintScopedToken creates an OAuth client holding exactly scope s (tagged tag:ci so
// tag-requiring scopes are valid) and returns an access token for it.
func mintScopedToken(t *testing.T, baseURL, admin string, s scope.Scope) string {
	t.Helper()

	_, secret := createClient(t, baseURL, admin, []string{string(s)}, []string{"tag:ci"})

	return tokenFor(t, baseURL, secret)
}

// createAdminAuthKey creates a tagged auth key with the admin key and returns its id.
func createAdminAuthKey(t *testing.T, baseURL, admin string) string {
	t.Helper()

	status, body := apiReq(t, http.MethodPost, baseURL+"/api/v2/tailnet/-/keys", admin, apiv2.CreateKeyRequest{
		Capabilities: &apiv2.KeyCapabilities{Devices: apiv2.KeyDeviceCapabilities{
			Create: apiv2.KeyDeviceCreateCapabilities{Reusable: true, Tags: []string{"tag:ci"}},
		}},
	})
	require.Equalf(t, http.StatusOK, status, "create admin auth key: %s", body)

	var key apiv2.Key
	require.NoError(t, json.Unmarshal(body, &key))

	return key.ID
}

type matrixOp struct {
	name   string
	method string
	path   string
	need   scope.Scope
	body   any
	// multiplexed marks the keyType-multiplexed keys ops. They self-enforce in
	// the handler and, to avoid an existence oracle, deny an unauthorized token
	// with a uniform not-found rather than the middleware's scope-403. So denial
	// is "resource not returned" (status != 200), not a specific 403.
	multiplexed bool
}

// TestAPIv2OAuthMatrix_Enforcement is the exhaustive operation×scope cross-product:
// for every scope-gated operation and every scope in the vocabulary, a token
// holding exactly that scope is allowed iff scope.Grants permits it (P3) and denied
// otherwise (P2).
func TestAPIv2OAuthMatrix_Enforcement(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	// Stable ids for the keyType-multiplexed get-by-id operations.
	clientID, _ := createClient(t, baseURL, admin, []string{"oauth_keys:read"}, nil)
	authKeyID := createAdminAuthKey(t, baseURL, admin)
	_ = app

	ops := []matrixOp{
		{"getDevice", http.MethodGet, "/api/v2/device/1", scope.DevicesCoreRead, nil, false},
		{"listDevices", http.MethodGet, "/api/v2/tailnet/-/devices", scope.DevicesCoreRead, nil, false},
		{"deleteDevice", http.MethodDelete, "/api/v2/device/1", scope.DevicesCore, nil, false},
		{"authorizeDevice", http.MethodPost, "/api/v2/device/1/authorized", scope.DevicesCore, map[string]any{}, false},
		{"setDeviceName", http.MethodPost, "/api/v2/device/1/name", scope.DevicesCore, map[string]any{}, false},
		{"setDeviceTags", http.MethodPost, "/api/v2/device/1/tags", scope.DevicesCore, map[string]any{}, false},
		{"setDeviceKey", http.MethodPost, "/api/v2/device/1/key", scope.DevicesCore, map[string]any{}, false},
		{"setDeviceRoutes", http.MethodPost, "/api/v2/device/1/routes", scope.DevicesRoutes, map[string]any{}, false},
		{"getDeviceRoutes", http.MethodGet, "/api/v2/device/1/routes", scope.DevicesRoutesRead, nil, false},
		{"getACL", http.MethodGet, "/api/v2/tailnet/-/acl", scope.PolicyFileRead, nil, false},
		{"setACL", http.MethodPost, "/api/v2/tailnet/-/acl", scope.PolicyFile, map[string]any{}, false},
		{"getSettings", http.MethodGet, "/api/v2/tailnet/-/settings", scope.FeatureSettingsRead, nil, false},
		{"updateSettings", http.MethodPatch, "/api/v2/tailnet/-/settings", scope.FeatureSettings, map[string]any{}, false},
		{"getKeyClient", http.MethodGet, "/api/v2/tailnet/-/keys/" + clientID, scope.OAuthKeysRead, nil, true},
		{"getKeyAuth", http.MethodGet, "/api/v2/tailnet/-/keys/" + authKeyID, scope.AuthKeysRead, nil, true},
	}

	// One token per scope, reused across every operation.
	tokens := make(map[scope.Scope]string, len(scope.Known()))
	for _, s := range scope.Known() {
		tokens[s] = mintScopedToken(t, baseURL, admin, s)
	}

	for _, op := range ops {
		for _, s := range scope.Known() {
			status, body := apiReq(t, op.method, baseURL+op.path, tokens[s], op.body)

			wantDenied := !scope.Grants([]scope.Scope{s}, op.need)

			// A multiplexed keys op denies via uniform not-found (no existence
			// oracle), so denial is "resource not returned"; every other op
			// denies with the middleware's scope-403.
			denied := scopeDenied(status, body)
			if op.multiplexed {
				denied = status != http.StatusOK
			}

			assert.Equalf(t, wantDenied, denied,
				"op %s with scope %q (needs %q): status=%d body=%s",
				op.name, s, op.need, status, body)
		}
	}
}

// TestAPIv2OAuthMatrix_ScopeNarrowing proves P1 for token minting: a client may
// only mint a token for scopes within its own grant. For every held scope X and
// requested scope Y, the mint succeeds iff scope.Grants([X], Y).
func TestAPIv2OAuthMatrix_ScopeNarrowing(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	for _, held := range scope.Known() {
		_, secret := createClient(t, baseURL, admin, []string{string(held)}, []string{"tag:ci"})

		for _, want := range scope.Known() {
			status, m := mintToken(t, baseURL, "", secret, string(want), false)

			wantOK := scope.Grants([]scope.Scope{held}, want)
			if wantOK {
				assert.Equalf(t, http.StatusOK, status, "held %q narrow to %q: %v", held, want, m)
			} else {
				assert.Equalf(t, http.StatusBadRequest, status,
					"held %q must not mint %q: %v", held, want, m)
				assert.Equal(t, "invalid_scope", m["error"])
			}
		}
	}
}

// TestAPIv2OAuthMatrix_TagNarrowing proves P1 for tags at mint time: a client may
// only mint a token for tags within its grant (closing the /oauth/token tags-param
// path). A client with the "all" scope may request any tag.
func TestAPIv2OAuthMatrix_TagNarrowing(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)

	_, secret := createClient(t, baseURL, admin, []string{"auth_keys"}, []string{"tag:a", "tag:b"})

	// In-grant tags mint; an out-of-grant tag is rejected.
	status, m := mintToken(t, baseURL, "", secret, "", false)
	require.Equalf(t, http.StatusOK, status, "%v", m)

	for _, tag := range []string{"tag:a", "tag:b"} {
		st, mm := mintTokenWithTags(t, baseURL, secret, tag)
		assert.Equalf(t, http.StatusOK, st, "in-grant tag %q: %v", tag, mm)
	}

	st, mm := mintTokenWithTags(t, baseURL, secret, "tag:c")
	assert.Equal(t, http.StatusBadRequest, st, mm)
	assert.Equal(t, "invalid_target", mm["error"])

	// An all-scope client may request any tag.
	_, allSecret := createClient(t, baseURL, admin, []string{"all"}, []string{"tag:a"})
	stAll, mAll := mintTokenWithTags(t, baseURL, allSecret, "tag:anything")
	assert.Equalf(t, http.StatusOK, stAll, "all-scope client may assign any tag: %v", mAll)
}

// TestAPIv2OAuthMatrix_Lifecycle proves expired and revoked credentials are denied
// at the HTTP layer, and that an admin API key bypasses scope checks.
func TestAPIv2OAuthMatrix_Lifecycle(t *testing.T) {
	app, baseURL, admin := newOAuthTestServer(t)

	devicesPath := baseURL + "/api/v2/tailnet/-/devices"

	// Expired token → 401.
	_, client, err := app.state.CreateOAuthClient([]string{"devices:core:read"}, []string{"tag:ci"}, "expired", nil)
	require.NoError(t, err)

	past := time.Now().Add(-time.Hour)
	expiredTok, _, err := app.state.MintAccessToken(client.ClientID, []string{"devices:core:read"}, nil, &past)
	require.NoError(t, err)

	status, _ := apiReq(t, http.MethodGet, devicesPath, expiredTok, nil)
	assert.Equal(t, http.StatusUnauthorized, status, "expired token must be rejected")

	// Revoked client → its token is denied.
	_, revClient, err := app.state.CreateOAuthClient([]string{"devices:core:read"}, []string{"tag:ci"}, "revoked", nil)
	require.NoError(t, err)

	future := time.Now().Add(time.Hour)
	revTok, _, err := app.state.MintAccessToken(revClient.ClientID, []string{"devices:core:read"}, nil, &future)
	require.NoError(t, err)

	// Works before revocation.
	okStatus, okBody := apiReq(t, http.MethodGet, devicesPath, revTok, nil)
	assert.Falsef(t, scopeDenied(okStatus, okBody), "token should pass the scope gate before revoke: %d", okStatus)

	require.NoError(t, app.state.RevokeOAuthClient(revClient.ClientID))

	revStatus, _ := apiReq(t, http.MethodGet, devicesPath, revTok, nil)
	assert.Equal(t, http.StatusUnauthorized, revStatus, "token of a revoked client must be rejected")

	// Admin API key bypasses scope checks: it reaches a devices op that a minimal
	// (feature_settings:read) token cannot.
	minimalTok := mintScopedToken(t, baseURL, admin, scope.FeatureSettingsRead)
	minStatus, minBody := apiReq(t, http.MethodGet, devicesPath, minimalTok, nil)
	assert.True(t, scopeDenied(minStatus, minBody), "minimal token must be scope-denied on devices")

	adminStatus, adminBody := apiReq(t, http.MethodGet, devicesPath, admin, nil)
	assert.Falsef(t, scopeDenied(adminStatus, adminBody),
		"admin key is all-access and must not be scope-denied: %d %s", adminStatus, adminBody)
}

// mintTokenWithTags mints with a tags narrowing parameter.
func mintTokenWithTags(t *testing.T, baseURL, secret, tags string) (int, map[string]any) {
	t.Helper()

	form := fmt.Sprintf("grant_type=client_credentials&client_secret=%s&tags=%s", secret, tags)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		baseURL+"/api/v2/oauth/token", strings.NewReader(form))
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
