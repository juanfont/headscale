package hscontrol

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The probe-* recordings cited here are raw captures of the live Tailscale
// API, kept in testdata/tailscale_api (see its README).

// TestAPIv2KeysScopeRefusal: a token without the scope a keys call needs is
// told 404 "not found" when it holds nothing for that kind of key, and 403
// "calling actor does not have enough permissions…" when it may read the
// kind but not write it, as on Tailscale (probe-U U5a-U5n). Listing keys
// with no key read scope at all is 403 there too (U5m), though creating one
// is 404 (U5n). Where the refusal falls through to an unknown auth key
// only the status is compared: Headscale names it "auth key not found".
func TestAPIv2KeysScopeRefusal(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)
	keys := baseURL + "/api/v2/tailnet/-/keys"

	clientID, _ := createClient(t, baseURL, admin, []string{"devices:core:read"}, nil)
	authKeyID := createAdminAuthKey(t, baseURL, admin)

	token := func(scopes ...string) string {
		_, secret := createClient(t, baseURL, admin, scopes, []string{"tag:ci"})

		return tokenFor(t, baseURL, secret)
	}

	authRead := token("auth_keys:read")
	oauthRead := token("oauth_keys:read")
	authWrite := token("auth_keys")
	coreRead := token("devices:core:read")

	const forbidden = `{"message":"calling actor does not have enough permissions to perform this function","status":403}`

	const notFound = `{"message":"not found","status":404}`

	for _, tc := range []struct {
		name, method, target, bearer string
		body                         any
		want                         string
		statusOnly                   bool
	}{
		{"U5a auth_keys:read creates a key", http.MethodPost, keys, authRead, map[string]any{"capabilities": taggedCaps("tag:ci")}, forbidden, false},
		{"U5b auth_keys:read deletes a key", http.MethodDelete, keys + "/" + authKeyID, authRead, nil, forbidden, false},
		{"U5d auth_keys:read reads a client", http.MethodGet, keys + "/" + clientID, authRead, nil, notFound, true},
		{"U5i oauth_keys:read reads an auth key", http.MethodGet, keys + "/" + authKeyID, oauthRead, nil, notFound, false},
		{"U5k oauth_keys:read deletes a client", http.MethodDelete, keys + "/" + clientID, oauthRead, nil, forbidden, false},
		{"U5l auth_keys deletes a client", http.MethodDelete, keys + "/" + clientID, authWrite, nil, notFound, true},
		{"U5m devices:core:read lists keys", http.MethodGet, keys, coreRead, nil, forbidden, false},
		{"U5n devices:core:read creates a key", http.MethodPost, keys, coreRead, map[string]any{"capabilities": taggedCaps("tag:ci")}, notFound, false},
		{"U5o devices:core:read creates a client", http.MethodPost, keys, coreRead, map[string]any{"keyType": "client", "scopes": []string{"devices:core:read"}}, notFound, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, body := apiReq(t, tc.method, tc.target, tc.bearer, tc.body)
			if tc.statusOnly {
				assert.Equalf(t, http.StatusNotFound, st, "%s", body)

				return
			}

			assert.JSONEq(t, tc.want, string(body))
		})
	}
}

// TestAPIv2TokenRuleRefusals: a token that breaks a token rule is refused as
// on Tailscale: 400 for a key without tags (probe-U U2d, U2e, U1k) and 403
// naming the scopes for a client with scopes the token lacks (U3a-U3h).
func TestAPIv2TokenRuleRefusals(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)
	keys := baseURL + "/api/v2/tailnet/-/keys"

	_, secret := createClient(t, baseURL, admin, []string{"all"}, []string{"tag:ci"})
	tok := tokenFor(t, baseURL, secret)

	st, body := apiPost(t, keys, tok, map[string]any{})
	assert.Equal(t, http.StatusBadRequest, st)
	assert.JSONEq(t, `{"message":"tailnet-owned auth key must have tags set","status":400}`, string(body))

	_, secret = createClient(t, baseURL, admin, []string{"oauth_keys"}, nil)
	tok = tokenFor(t, baseURL, secret)

	st, body = apiPost(t, keys, tok, apiv2.CreateKeyRequest{
		KeyType: "client", Scopes: []string{"oauth_keys", "devices:core:read", "all"},
	})
	assert.Equal(t, http.StatusForbidden, st)
	assert.JSONEq(t, `{"message":"actor cannot set scopes: [devices:core:read all]","status":403}`, string(body))
}

// TestAPIv2OAuthClientSoftDelete: DELETE revokes an OAuth client rather than
// removing it, as Tailscale does and as auth keys already do. The client stays
// readable by ID as revoked and invalid, a repeated DELETE succeeds (probe-G
// H6-H8, probe-T H6-H8), and its tokens stop working (probe-Q Q4-Q7). The key
// list never shows a revoked client (probe-T H7b), and shows live clients to
// an admin API key only with all=true (probe-T H5, H5b), while a token that
// may read clients sees them either way (probe-U U6).
func TestAPIv2OAuthClientSoftDelete(t *testing.T) {
	_, baseURL, admin := newOAuthTestServer(t)
	keys := baseURL + "/api/v2/tailnet/-/keys"

	listed := func(bearer, query, id string) bool {
		t.Helper()

		st, body := apiReq(t, http.MethodGet, keys+query, bearer, nil)
		require.Equalf(t, http.StatusOK, st, "%s", body)

		var out struct{ Keys []apiv2.Key }
		require.NoError(t, json.Unmarshal(body, &out))

		for _, k := range out.Keys {
			if k.ID == id {
				return true
			}
		}

		return false
	}

	id, secret := createClient(t, baseURL, admin, []string{"oauth_keys:read"}, nil)
	tok := tokenFor(t, baseURL, secret)

	assert.False(t, listed(admin, "", id), "admin key, default list")
	assert.True(t, listed(admin, "?all=true", id), "admin key, all=true")
	assert.True(t, listed(tok, "", id), "oauth_keys:read token, default list")

	st, body := apiReq(t, http.MethodDelete, keys+"/"+id, admin, nil)
	require.Equalf(t, http.StatusOK, st, "%s", body)

	st, body = apiReq(t, http.MethodGet, keys+"/"+id, admin, nil)
	require.Equalf(t, http.StatusOK, st, "%s", body)

	var got apiv2.Key
	require.NoError(t, json.Unmarshal(body, &got))
	assert.True(t, got.Invalid)
	assert.NotNil(t, got.Revoked)

	st, _ = apiReq(t, http.MethodDelete, keys+"/"+id, admin, nil)
	assert.Equal(t, http.StatusOK, st, "a repeated DELETE succeeds")

	assert.False(t, listed(admin, "?all=true", id), "a revoked client is never listed")

	st, _ = apiReq(t, http.MethodGet, keys, tok, nil)
	assert.Equal(t, http.StatusUnauthorized, st, "the revoked client's token is gone")
}

// TestAPIv2ACLIfMatchConcurrent: writers holding the same ETag race; exactly
// one may win. The ETag is compared under the lock the write takes, so the
// rest see the policy the winner wrote and get 412.
func TestAPIv2ACLIfMatchConcurrent(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	etag := setACL(t, api, allowAllPolicy, "application/json").Header().Get("Etag")

	const writers = 8

	codes := make([]int, writers)

	var wg sync.WaitGroup

	for i := range writers {
		wg.Go(func() {
			body := fmt.Sprintf(`{"hosts":{"h":"100.64.0.%d"},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`, i+1)
			codes[i] = setACL(t, api, body, "application/json", "If-Match: "+etag).Code
		})
	}

	wg.Wait()

	won := 0

	for _, c := range codes {
		if c == http.StatusOK {
			won++
		} else {
			assert.Equal(t, http.StatusPreconditionFailed, c)
		}
	}

	assert.Equal(t, 1, won, "codes: %v", codes)
}

// TestAPIv2DeviceTagsEmptyIsNoChange documents an intentional difference from Tailscale.
//
// Tailscale: POST /device/{id}/tags with "tags":[] on a tagged node answers
// 400 "tagged nodes cannot be untagged without reauth" (probe-J J7).
//
// Headscale: [] and null are accepted with 200 and change nothing. The node
// cannot become untagged either way (tags-as-identity is one-way), but the
// Terraform provider's destroy of tailscale_device_tags sends "tags":null,
// and a 400 there would leave every such resource impossible to destroy.
func TestAPIv2DeviceTagsEmptyIsNoChange(t *testing.T) {
	e := newDeviceTestEnv(t)
	target := "/api/v2/device/" + e.deviceID + "/tags"

	require.Equal(t, http.StatusOK, e.api.Post(target, map[string]any{"tags": []string{"tag:ci"}}).Code)

	for _, body := range []string{`{"tags":[]}`, `{"tags":null}`} {
		resp := e.api.Post(target, "Content-Type: application/json", strings.NewReader(body))
		assert.Equalf(t, http.StatusOK, resp.Code, "%s: %s", body, resp.Body)
		assert.Equal(t, []string{"tag:ci"}, e.srvNode(t).Tags().AsSlice(), body)
	}
}

// TestAPIv2DeviceDeauthorizeRefused documents an intentional difference from Tailscale.
//
// Tailscale: POST /device/{id}/authorized with false answers 200 and the
// device reads back authorized=false (probe-J J17); it is cut off until
// approved again.
//
// Headscale: 400, and the device stays authorized. Headscale has no device
// approval, so there is no state to put it in; answering 200 would let a
// caller believe the device is fenced off when it is not. Device approval is
// juanfont/headscale#2176; when it lands this should follow Tailscale.
func TestAPIv2DeviceDeauthorizeRefused(t *testing.T) {
	e := newDeviceTestEnv(t)

	resp := e.api.Post("/api/v2/device/"+e.deviceID+"/authorized", map[string]any{"authorized": false})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.True(t, getDevice(t, e.api, e.deviceID).Authorized)
}

// TestAPIv2DeviceOneExitPrefix documents an intentional difference from Tailscale.
//
// Tailscale: POST /device/{id}/routes with only "0.0.0.0/0" stores and
// reports exactly that in enabledRoutes, yet the node itself is sent both
// exit routes and offers itself as an exit node; with only "::/0" it is not
// an exit node at all (probe-N N2, N3; probe-P).
//
// Headscale: one exit prefix approves both, and enabledRoutes reports both.
// Headscale approves exit routes as a pair everywhere else (CLI, auto
// approval), and reporting what is actually in effect keeps the API and the
// node in agreement.
func TestAPIv2DeviceOneExitPrefix(t *testing.T) {
	e := newDeviceTestEnv(t)

	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		resp := e.api.Post("/api/v2/device/"+e.deviceID+"/routes", map[string]any{"routes": []string{prefix}})
		require.Equalf(t, http.StatusOK, resp.Code, "%s", resp.Body)

		var dr apiv2.DeviceRoutes
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &dr))
		assert.ElementsMatch(t, []string{"0.0.0.0/0", "::/0"}, dr.Enabled, prefix)
		assert.ElementsMatch(t, []string{"0.0.0.0/0", "::/0"}, approvedRouteStrings(e.srvNode(t)), prefix)
	}
}

// TestAPIv2KeyDescription documents two intentional differences from Tailscale.
//
// Tailscale: a key or OAuth client description over 50 characters is silently
// truncated to 50, on create and on every read (probe-T A11-A13, A21,
// A22). It also refuses many characters, among them . : + , / ' @ ( ) = #
// and any non-ASCII letter, with 400 "keys: description had invalid
// characters" (probe-W D rows).
//
// Headscale: over 50 characters is refused with 422, so a caller never
// stores a text other than the one it sent. Any character is accepted. No
// change was asked for; this test records both.
func TestAPIv2KeyDescription(t *testing.T) {
	_, api := newKeyTestAPI(t)

	resp := api.Post("/api/v2/tailnet/-/keys", apiv2.CreateKeyRequest{
		Description:  strings.Repeat("a", 51),
		Capabilities: taggedCaps("tag:test"),
	})
	assert.Equal(t, http.StatusUnprocessableEntity, resp.Code)

	for _, desc := range []string{"a.b", "a:b", "a@b", "ünï"} {
		key := createKey(t, api, apiv2.CreateKeyRequest{Description: desc, Capabilities: taggedCaps("tag:test")})
		assert.Equal(t, desc, key.Description)
	}
}
