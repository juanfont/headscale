package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// taggedCaps builds capabilities for a tagged auth key.
func taggedCaps(tags ...string) apiv2.KeyCapabilities {
	return apiv2.KeyCapabilities{
		Devices: apiv2.KeyDeviceCapabilities{Create: apiv2.KeyDeviceCreateCapabilities{
			Reusable:      true,
			Preauthorized: true,
			Tags:          tags,
		}},
	}
}

// newKeyTestAPI builds an app + v2 API with NO owner user in context. Without the
// auth middleware ownerUser(ctx) is empty, so only the tagged-key path creates;
// the user-owned path (which needs an owning API key) is covered by TestAPIv2.
func newKeyTestAPI(t *testing.T) (*Headscale, humatest.TestAPI) {
	t.Helper()

	app := createTestApp(t)

	_, api := humatest.New(t, apiv2.Config())
	apiv2.Register(api, apiv2.Backend{State: app.state})

	return app, api
}

// createKey POSTs a key and decodes the create response.
func createKey(t *testing.T, api humatest.TestAPI, req apiv2.CreateKeyRequest) apiv2.Key {
	t.Helper()

	resp := api.Post("/api/v2/tailnet/-/keys", req)
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var key apiv2.Key
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &key))

	return key
}

// getKey GETs a key by id and decodes it.
func getKey(t *testing.T, api humatest.TestAPI, id string) apiv2.Key {
	t.Helper()

	resp := api.Get("/api/v2/tailnet/-/keys/" + id)
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var key apiv2.Key
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &key))

	return key
}

// listKeys GETs the key list and returns the enveloped slice.
func listKeys(t *testing.T, api humatest.TestAPI) []apiv2.Key {
	t.Helper()

	resp := api.Get("/api/v2/tailnet/-/keys")
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var list struct {
		Keys []apiv2.Key `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &list))

	return list.Keys
}

func containsKeyID(keys []apiv2.Key, id string) bool {
	for _, k := range keys {
		if k.ID == id {
			return true
		}
	}

	return false
}

// srvKey is the server-side ground truth: the stored PreAuthKey, found by its
// stringified id through ListPreAuthKeys (User is preloaded).
func srvKey(t *testing.T, app *Headscale, id string) types.PreAuthKey {
	t.Helper()

	want, err := strconv.ParseUint(id, 10, 64)
	require.NoError(t, err)

	keys, err := app.state.ListPreAuthKeys()
	require.NoError(t, err)

	for _, k := range keys {
		if k.ID == want {
			return k
		}
	}

	t.Fatalf("pre-auth key %s not found server-side", id)

	return types.PreAuthKey{}
}

func keyCount(t *testing.T, app *Headscale) int {
	t.Helper()

	keys, err := app.state.ListPreAuthKeys()
	require.NoError(t, err)

	return len(keys)
}

func TestAPIv2Key_Create_Tagged(t *testing.T) {
	app, api := newKeyTestAPI(t)

	created := createKey(t, api, apiv2.CreateKeyRequest{
		Description:   "dev access",
		ExpirySeconds: 86400,
		Capabilities:  taggedCaps("tag:test"),
	})

	// (a) create response — Tailscale Key shape, exact seconds (int64 wire).
	assert.Equal(t, "auth", created.KeyType)
	assert.NotEmpty(t, created.ID)
	assert.NotEmpty(t, created.Key, "secret returned on create")
	assert.Equal(t, "dev access", created.Description)
	assert.Equal(t, int64(86400), created.ExpirySeconds, "seconds, not nanoseconds")
	assert.Empty(t, created.UserID, "tagged key presents no owner")
	assert.Equal(t, []string{"tag:test"}, created.Capabilities.Devices.Create.Tags)
	assert.True(t, created.Capabilities.Devices.Create.Reusable)
	assert.True(t, created.Capabilities.Devices.Create.Preauthorized, "echoed on create")
	assert.NotNil(t, created.Expires)
	assert.False(t, created.Invalid)

	// (c) server-side — the stored key.
	pak := srvKey(t, app, created.ID)
	assert.True(t, pak.Reusable)
	assert.False(t, pak.Ephemeral)
	assert.Equal(t, []string{"tag:test"}, pak.Tags)
	assert.Equal(t, "dev access", pak.Description)
	assert.Nil(t, pak.User, "tagged key has no owning user")
	require.NotNil(t, pak.CreatedAt)
	require.NotNil(t, pak.Expiration)
	assert.InDelta(t, 86400, pak.Expiration.Sub(*pak.CreatedAt).Seconds(), 2)
}

func TestAPIv2Key_Create_Permutations(t *testing.T) {
	tests := []struct {
		name          string
		req           apiv2.CreateKeyRequest
		wantReusable  bool
		wantEphemeral bool
		wantDesc      string
		wantSeconds   float64
	}{
		{
			name: "single-use",
			req: apiv2.CreateKeyRequest{Capabilities: apiv2.KeyCapabilities{
				Devices: apiv2.KeyDeviceCapabilities{Create: apiv2.KeyDeviceCreateCapabilities{Tags: []string{"tag:test"}}},
			}},
			wantSeconds: 7776000,
		},
		{
			name:         "reusable",
			req:          apiv2.CreateKeyRequest{Capabilities: taggedCaps("tag:test")},
			wantReusable: true,
			wantSeconds:  7776000,
		},
		{
			name: "ephemeral",
			req: apiv2.CreateKeyRequest{Capabilities: apiv2.KeyCapabilities{
				Devices: apiv2.KeyDeviceCapabilities{Create: apiv2.KeyDeviceCreateCapabilities{
					Ephemeral: true,
					Tags:      []string{"tag:test"},
				}},
			}},
			wantEphemeral: true,
			wantSeconds:   7776000,
		},
		{
			name:         "with description",
			req:          apiv2.CreateKeyRequest{Description: "ci", Capabilities: taggedCaps("tag:test")},
			wantReusable: true,
			wantDesc:     "ci",
			wantSeconds:  7776000,
		},
		{
			name:         "explicit expiry",
			req:          apiv2.CreateKeyRequest{ExpirySeconds: 3600, Capabilities: taggedCaps("tag:test")},
			wantReusable: true,
			wantSeconds:  3600,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, api := newKeyTestAPI(t)

			created := createKey(t, api, tt.req)
			assert.Equal(t, tt.wantReusable, created.Capabilities.Devices.Create.Reusable)
			assert.Equal(t, tt.wantEphemeral, created.Capabilities.Devices.Create.Ephemeral)
			assert.Equal(t, tt.wantDesc, created.Description)
			assert.InDelta(t, tt.wantSeconds, float64(created.ExpirySeconds), 2)

			pak := srvKey(t, app, created.ID)
			assert.Equal(t, tt.wantReusable, pak.Reusable)
			assert.Equal(t, tt.wantEphemeral, pak.Ephemeral)
			assert.Equal(t, tt.wantDesc, pak.Description)
			require.NotNil(t, pak.CreatedAt)
			require.NotNil(t, pak.Expiration)
			assert.InDelta(t, tt.wantSeconds, pak.Expiration.Sub(*pak.CreatedAt).Seconds(), 2)
		})
	}
}

func TestAPIv2Key_Get(t *testing.T) {
	_, api := newKeyTestAPI(t)

	created := createKey(t, api, apiv2.CreateKeyRequest{
		Description:   "dev access",
		ExpirySeconds: 86400,
		Capabilities:  taggedCaps("tag:test"),
	})

	got := getKey(t, api, created.ID)
	assert.Equal(t, created.ID, got.ID)
	assert.Empty(t, got.Key, "secret omitted on get")
	assert.Equal(t, "dev access", got.Description)
	assert.Equal(t, int64(86400), got.ExpirySeconds, "stable across get")
	assert.True(t, got.Capabilities.Devices.Create.Reusable)
	assert.True(t, got.Capabilities.Devices.Create.Preauthorized, "Headscale always preauthorizes")
	assert.Equal(t, []string{"tag:test"}, got.Capabilities.Devices.Create.Tags)
	assert.False(t, got.Invalid)

	// Unknown id and bad tailnet both 404 with the Tailscale error body.
	assert.Equal(t, http.StatusNotFound, api.Get("/api/v2/tailnet/-/keys/999999").Code)
	bad := api.Get("/api/v2/tailnet/example.com/keys/" + created.ID)
	assert.Equal(t, http.StatusNotFound, bad.Code)
	assert.Contains(t, bad.Body.String(), `"message"`)
}

func TestAPIv2Key_List(t *testing.T) {
	app, api := newKeyTestAPI(t)

	k1 := createKey(t, api, apiv2.CreateKeyRequest{Capabilities: taggedCaps("tag:test")})
	k2 := createKey(t, api, apiv2.CreateKeyRequest{Capabilities: taggedCaps("tag:test")})

	keys := listKeys(t, api)
	assert.True(t, containsKeyID(keys, k1.ID))
	assert.True(t, containsKeyID(keys, k2.ID))

	// Server-side has both too.
	assert.GreaterOrEqual(t, keyCount(t, app), 2)

	bad := api.Get("/api/v2/tailnet/example.com/keys")
	assert.Equal(t, http.StatusNotFound, bad.Code)
	assert.Contains(t, bad.Body.String(), `"message"`)
}

func TestAPIv2Key_Delete(t *testing.T) {
	app, api := newKeyTestAPI(t)

	created := createKey(t, api, apiv2.CreateKeyRequest{Capabilities: taggedCaps("tag:test")})

	require.Equal(t, http.StatusOK, api.Delete("/api/v2/tailnet/-/keys/"+created.ID).Code)

	// DELETE soft-revokes (Tailscale-faithful): the key stays retrievable with
	// invalid set and a revoked timestamp, and is still listed.
	got := getKey(t, api, created.ID)
	assert.True(t, got.Invalid, "revoked key reports invalid")
	assert.NotNil(t, got.Revoked, "revoked timestamp is populated")
	assert.True(t, containsKeyID(listKeys(t, api), created.ID), "revoked key still listed")

	// Server-side: row kept, revoked stamped.
	pak := srvKey(t, app, created.ID)
	require.NotNil(t, pak.Revoked)
	require.Error(t, pak.Validate(), "revoked key is invalid")

	// Delete again -> 404 (already revoked).
	assert.Equal(t, http.StatusNotFound, api.Delete("/api/v2/tailnet/-/keys/"+created.ID).Code)

	// The collector hard-deletes keys revoked before the cutoff.
	reaped, err := app.state.DestroyRevokedPreAuthKeysBefore(time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, reaped, 1)
	assert.False(t, containsKeyID(listKeys(t, api), created.ID), "collector removed the revoked key")
	assert.Equal(t, http.StatusNotFound, api.Get("/api/v2/tailnet/-/keys/"+created.ID).Code)
}

func TestAPIv2Key_Create_NoTags_NoOwner_400(t *testing.T) {
	app, api := newKeyTestAPI(t)

	before := keyCount(t, app)

	resp := api.Post("/api/v2/tailnet/-/keys", apiv2.CreateKeyRequest{Capabilities: apiv2.KeyCapabilities{}})
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), `"message"`)

	// No orphan key was created.
	assert.Equal(t, before, keyCount(t, app))
}
