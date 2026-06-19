package hscontrol

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedAPIKey creates a single API key and returns its database ID and the
// masked display prefix the API exposes, so tests can address it by either.
func seedAPIKey(t *testing.T, app *Headscale) (uint64, string) {
	t.Helper()

	_, key, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	return key.ID, "hskey-api-" + key.Prefix + "-***"
}

func TestAPIV1ApiKeyCreate(t *testing.T) {
	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPost, "/api/v1/apikey", []byte(`{}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			APIKey string `json:"apiKey"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		// The full secret is returned exactly once, on creation.
		assert.NotEmpty(t, got.APIKey)
		assert.Contains(t, got.APIKey, "hskey-api-")
	})

	t.Run("creates secret", func(t *testing.T) {
		// The secret is random, so it can't be captured in a golden; just assert
		// success and that a secret is returned.
		humaApp := createTestApp(t)

		hum := callHandler(newHumaTestHandler(humaApp), http.MethodPost, "/api/v1/apikey", []byte(`{}`))

		assert.Equal(t, http.StatusOK, hum.status)

		var humBody struct {
			APIKey string `json:"apiKey"`
		}
		require.NoError(t, json.Unmarshal(hum.body, &humBody))
		assert.NotEmpty(t, humBody.APIKey)
	})
}

func TestAPIV1ApiKeyList(t *testing.T) {
	t.Run("empty returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodGet, "/api/v1/apikey", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"apiKeys":[]}`, string(res.body))
	})

	t.Run("empty parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.assertParity(t, http.MethodGet, "/api/v1/apikey", nil)
	})

	t.Run("populated parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedAPIKey(t, h.app)
		seedAPIKey(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/apikey", nil)
	})

	t.Run("nil timestamps emitted as null parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedAPIKey(t, h.app)
		// Nil expiration: lastSeen and expiration are unset and must emit as
		// JSON null.
		res := h.assertParity(t, http.MethodGet, "/api/v1/apikey", nil)

		var got struct {
			APIKeys []map[string]any `json:"apiKeys"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		require.Len(t, got.APIKeys, 1)
		assert.Nil(t, got.APIKeys[0]["lastSeen"])
		assert.Nil(t, got.APIKeys[0]["expiration"])
		assert.Contains(t, got.APIKeys[0], "createdAt")
		assert.Contains(t, got.APIKeys[0]["prefix"], "hskey-api-")
	})

	t.Run("zero expiration emitted as zero instant parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		// Non-nil zero expiration (as gRPC CreateApiKey does for a missing one)
		// must render as the zero instant, not null.
		var zero time.Time

		_, _, err := h.app.state.CreateAPIKey(&zero)
		require.NoError(t, err)

		res := h.assertParity(t, http.MethodGet, "/api/v1/apikey", nil)

		var got struct {
			APIKeys []map[string]any `json:"apiKeys"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		require.Len(t, got.APIKeys, 1)
		assert.Equal(t, "0001-01-01T00:00:00Z", got.APIKeys[0]["expiration"])
	})
}

func TestAPIV1ApiKeyExpire(t *testing.T) {
	t.Run("by id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		id, _ := seedAPIKey(t, h.app)
		h.assertParity(t, http.MethodPost, "/api/v1/apikey/expire",
			[]byte(`{"id":"`+strconv.FormatUint(id, 10)+`"}`))
	})

	t.Run("by prefix parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		_, prefix := seedAPIKey(t, h.app)
		h.assertParity(t, http.MethodPost, "/api/v1/apikey/expire",
			[]byte(`{"prefix":"`+prefix+`"}`))
	})

	t.Run("neither id nor prefix parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/apikey/expire", []byte(`{}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("both id and prefix parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/apikey/expire",
			[]byte(`{"id":"1","prefix":"abc"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("not found by id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/apikey/expire", []byte(`{"id":"999"}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("expires the key", func(t *testing.T) {
		h := newAPIV1Harness(t)
		id, _ := seedAPIKey(t, h.app)

		res := h.callHuma(http.MethodPost, "/api/v1/apikey/expire",
			[]byte(`{"id":"`+strconv.FormatUint(id, 10)+`"}`))
		require.Equal(t, http.StatusOK, res.status)

		listRes := h.callHuma(http.MethodGet, "/api/v1/apikey", nil)

		var got struct {
			APIKeys []struct {
				Expiration *time.Time `json:"expiration"`
			} `json:"apiKeys"`
		}
		require.NoError(t, json.Unmarshal(listRes.body, &got))
		require.Len(t, got.APIKeys, 1)
		require.NotNil(t, got.APIKeys[0].Expiration)
		assert.False(t, got.APIKeys[0].Expiration.IsZero(), "expiration should be set")
	})
}

func TestAPIV1ApiKeyDelete(t *testing.T) {
	t.Run("by prefix deletes the key", func(t *testing.T) {
		h := newAPIV1Harness(t)
		_, prefix := seedAPIKey(t, h.app)

		res := h.callHuma(http.MethodDelete, "/api/v1/apikey/"+prefix, nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{}`, string(res.body))

		listRes := h.callHuma(http.MethodGet, "/api/v1/apikey", nil)
		assert.JSONEq(t, `{"apiKeys":[]}`, string(listRes.body))
	})

	t.Run("path prefix with id query is both -> 400 parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		id, prefix := seedAPIKey(t, h.app)
		res := h.assertParity(t, http.MethodDelete,
			"/api/v1/apikey/"+prefix+"?id="+strconv.FormatUint(id, 10), nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("not found by prefix parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/apikey/doesnotexist", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("both id and prefix parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/apikey/abc?id=1", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/apikey/abc?id=notanumber", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}
