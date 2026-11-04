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

	t.Run("expiration stored and reported as sent", func(t *testing.T) {
		future := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

		for _, tc := range []struct {
			name string
			body string
			want *time.Time
		}{
			{"omitted", `{"aclTags":["tag:test"]}`, nil},
			{"null", `{"aclTags":["tag:test"],"expiration":null}`, nil},
			{
				"future",
				`{"aclTags":["tag:test"],"expiration":"` + future.Format(time.RFC3339) + `"}`,
				&future,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				h := newAPIV1Harness(t)

				res := h.callHuma(http.MethodPost, "/api/v1/preauthkey", []byte(tc.body))
				require.Equal(t, http.StatusOK, res.status)

				var created struct {
					PreAuthKey map[string]any `json:"preAuthKey"`
				}
				require.NoError(t, json.Unmarshal(res.body, &created))

				res = h.callHuma(http.MethodGet, "/api/v1/preauthkey", nil)
				require.Equal(t, http.StatusOK, res.status)

				var listed struct {
					PreAuthKeys []map[string]any `json:"preAuthKeys"`
				}
				require.NoError(t, json.Unmarshal(res.body, &listed))
				require.Len(t, listed.PreAuthKeys, 1)

				keys, err := h.app.state.ListPreAuthKeys()
				require.NoError(t, err)
				require.Len(t, keys, 1)

				// The zero time is already past, so an omitted expiration must
				// stay NULL for the key to be usable.
				require.NoError(t, keys[0].Validate())

				if tc.want == nil {
					assert.Nil(t, keys[0].Expiration)
					assert.Nil(t, created.PreAuthKey["expiration"])
					assert.Nil(t, listed.PreAuthKeys[0]["expiration"])

					return
				}

				require.NotNil(t, keys[0].Expiration)
				assert.True(t, tc.want.Equal(*keys[0].Expiration))
				assert.Equal(t, future.Format(time.RFC3339), created.PreAuthKey["expiration"])
				assert.Equal(t, future.Format(time.RFC3339), listed.PreAuthKeys[0]["expiration"])
			})
		}
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
	t.Run("revoked keys are hidden", func(t *testing.T) {
		h := newAPIV1Harness(t)
		user := h.app.state.CreateUserForTest("revoked-key-user")
		pak, err := h.app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
		require.NoError(t, err)
		require.NoError(t, h.app.state.DB().RevokePreAuthKey(pak.ID))
		res := h.callHuma(http.MethodGet, "/api/v1/preauthkey", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"preAuthKeys":[]}`, string(res.body))
	})

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
