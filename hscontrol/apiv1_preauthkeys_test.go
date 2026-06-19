package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedPreAuthKeys creates a user-owned key and a tagged (system-created) key;
// the tagged key exercises the user:null path.
func seedPreAuthKeys() func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		user := app.state.CreateUserForTest("alice")
		uid := types.UserID(user.ID)
		exp := time.Time{}

		_, err := app.state.CreatePreAuthKey(&uid, true, false, &exp, nil)
		require.NoError(t, err)

		// Tagged, system-created: no user.
		_, err = app.state.CreatePreAuthKey(nil, false, true, &exp, []string{"tag:test"})
		require.NoError(t, err)
	}
}

func TestAPIV1CreatePreAuthKey(t *testing.T) {
	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.app.state.CreateUserForTest("alice")

		res := h.callHuma(http.MethodPost, "/api/v1/preauthkey",
			[]byte(`{"user":"1","reusable":true}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			PreAuthKey map[string]any `json:"preAuthKey"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.PreAuthKey["id"])
		assert.Equal(t, true, got.PreAuthKey["reusable"])
		// Zero-value fields are emitted (EmitUnpopulated parity).
		assert.Equal(t, false, got.PreAuthKey["ephemeral"])
		assert.Equal(t, false, got.PreAuthKey["used"])
		assert.Contains(t, got.PreAuthKey, "expiration")
		assert.Contains(t, got.PreAuthKey, "createdAt")
		// Empty tags serialize as [], not null.
		assert.Equal(t, []any{}, got.PreAuthKey["aclTags"])
		// The freshly created key returns its full secret.
		assert.NotEmpty(t, got.PreAuthKey["key"])
		user, ok := got.PreAuthKey["user"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "1", user["id"])
	})

	t.Run("tagged key has null user", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPost, "/api/v1/preauthkey",
			[]byte(`{"aclTags":["tag:test"]}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			PreAuthKey map[string]any `json:"preAuthKey"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Nil(t, got.PreAuthKey["user"])
		assert.Equal(t, []any{"tag:test"}, got.PreAuthKey["aclTags"])
	})

	t.Run("invalid tag parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.app.state.CreateUserForTest("alice")
		res := h.assertParity(t, http.MethodPost, "/api/v1/preauthkey",
			[]byte(`{"user":"1","aclTags":["badtag"]}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("nonexistent user parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/preauthkey", []byte(`{"user":"999"}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid user id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/preauthkey", []byte(`{"user":"abc"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("neither tagged nor owned parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/preauthkey", []byte(`{"reusable":true}`))
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1ExpirePreAuthKey(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		assertParityIsolated(t, seedPreAuthKeys(), http.MethodPost,
			"/api/v1/preauthkey/expire", []byte(`{"id":"1"}`))
	})

	t.Run("nonexistent parity", func(t *testing.T) {
		res := assertParityIsolated(t, seedPreAuthKeys(), http.MethodPost,
			"/api/v1/preauthkey/expire", []byte(`{"id":"99999"}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/preauthkey/expire", []byte(`{"id":"abc"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1DeletePreAuthKey(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		assertParityIsolated(t, seedPreAuthKeys(), http.MethodDelete,
			"/api/v1/preauthkey?id=1", nil)
	})

	t.Run("nonexistent parity", func(t *testing.T) {
		res := assertParityIsolated(t, seedPreAuthKeys(), http.MethodDelete,
			"/api/v1/preauthkey?id=99999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/preauthkey?id=abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1ListPreAuthKeys(t *testing.T) {
	t.Run("empty returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodGet, "/api/v1/preauthkey", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"preAuthKeys":[]}`, string(res.body))
	})

	t.Run("empty parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.assertParity(t, http.MethodGet, "/api/v1/preauthkey", nil)
	})

	t.Run("all parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedPreAuthKeys()(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/preauthkey", nil)
	})
}
