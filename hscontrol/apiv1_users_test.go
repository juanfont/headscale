package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedUsers(names ...string) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		for _, n := range names {
			app.state.CreateUserForTest(n)
		}
	}
}

func TestAPIV1CreateUser(t *testing.T) {
	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPost, "/api/v1/user", []byte(`{"name":"test"}`))
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			User map[string]any `json:"user"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.Equal(t, "1", got.User["id"])
		assert.Equal(t, "test", got.User["name"])
		assert.Contains(t, got.User, "createdAt")
		// Zero-value fields are emitted as empty strings (EmitUnpopulated parity).
		assert.Empty(t, got.User["email"])
		assert.Empty(t, got.User["displayName"])
	})

	t.Run("parity", func(t *testing.T) {
		assertParityIsolated(t, nil, http.MethodPost, "/api/v1/user",
			[]byte(`{"name":"test","displayName":"Test","email":"t@example.com"}`))
	})

	t.Run("duplicate name parity", func(t *testing.T) {
		res := assertParityIsolated(t, seedUsers("dup"), http.MethodPost, "/api/v1/user",
			[]byte(`{"name":"dup"}`))
		assertStatus(t, res, http.StatusConflict)
	})
}

// seedUserWithProfile creates a user whose presentational fields are already
// populated, so a subsequent setUser can be seen to change and to clear them.
func seedUserWithProfile(name string) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		user := app.state.CreateUserForTest(name)

		_, _, err := app.state.SetUserProfile(types.UserID(user.ID), types.UserProfileUpdate{
			DisplayName:   new("Original"),
			Email:         new("original@example.com"),
			ProfilePicURL: new("https://example.com/original.png"),
		})
		require.NoError(t, err)
	}
}

func TestAPIV1SetUser(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		assertParityIsolated(t, seedUsers("vika"), http.MethodPut, "/api/v1/user/1",
			[]byte(`{"displayName":"Vika","pictureUrl":"https://example.com/vika.png"}`))
	})

	t.Run("absent fields are untouched", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUserWithProfile("vika")(t, h.app)

		res := h.callHuma(http.MethodPut, "/api/v1/user/1",
			[]byte(`{"displayName":"Vika"}`))
		require.Equal(t, http.StatusOK, res.status)

		user := decodeUser(t, res.body)
		assert.Equal(t, "Vika", user["displayName"])
		assert.Equal(t, "original@example.com", user["email"])
		assert.Equal(t, "https://example.com/original.png", user["profilePicUrl"])
	})

	// The distinction the pointer fields exist for: an explicit empty string
	// removes the avatar, while omitting the field keeps it.
	t.Run("empty string clears field", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUserWithProfile("vika")(t, h.app)

		res := h.callHuma(http.MethodPut, "/api/v1/user/1", []byte(`{"pictureUrl":""}`))
		require.Equal(t, http.StatusOK, res.status)

		user := decodeUser(t, res.body)
		assert.Empty(t, user["profilePicUrl"])
		assert.Equal(t, "Original", user["displayName"])
	})

	t.Run("empty body rejected", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("vika")(t, h.app)

		res := h.callHuma(http.MethodPut, "/api/v1/user/1", []byte(`{}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	// Headscale hands this URL to every client's user interface, so a scheme
	// that is not http(s) must not be storable.
	t.Run("invalid picture url rejected", func(t *testing.T) {
		for _, bad := range []string{"/avatar.png", "javascript:alert(1)", "example.com/a.png"} {
			h := newAPIV1Harness(t)
			seedUsers("vika")(t, h.app)

			res := h.callHuma(http.MethodPut, "/api/v1/user/1",
				[]byte(`{"pictureUrl":"`+bad+`"}`))
			assertStatus(t, res, http.StatusBadRequest)
		}
	})

	// OIDC re-applies its claims on every login, so a manual edit would be
	// silently reverted; refusing is the honest answer.
	t.Run("oidc user rejected", func(t *testing.T) {
		h := newAPIV1Harness(t)

		user := h.app.state.CreateUserForTest("oidc")
		_, _, err := h.app.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
			u.Provider = util.RegisterMethodOIDC

			return nil
		})
		require.NoError(t, err)

		res := h.callHuma(http.MethodPut, "/api/v1/user/1", []byte(`{"displayName":"Manual"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("nonexistent user", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPut, "/api/v1/user/999", []byte(`{"displayName":"x"}`))
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodPut, "/api/v1/user/abc", []byte(`{"displayName":"x"}`))
		assertStatus(t, res, http.StatusBadRequest)
	})
}

// decodeUser unwraps the {"user": {...}} envelope the user endpoints return.
func decodeUser(t *testing.T, body []byte) map[string]any {
	t.Helper()

	var got struct {
		User map[string]any `json:"user"`
	}

	require.NoError(t, json.Unmarshal(body, &got))

	return got.User
}

func TestAPIV1RenameUser(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		assertParityIsolated(t, seedUsers("alice"), http.MethodPost,
			"/api/v1/user/1/rename/bob", nil)
	})

	t.Run("nonexistent parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/user/999/rename/bob", nil)
		assertStatus(t, res, http.StatusNotFound)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodPost, "/api/v1/user/abc/rename/bob", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}

func TestAPIV1DeleteUser(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		assertParityIsolated(t, seedUsers("alice"), http.MethodDelete, "/api/v1/user/1", nil)
	})

	t.Run("nonexistent parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodDelete, "/api/v1/user/999", nil)
		assertStatus(t, res, http.StatusNotFound)
	})
}

func TestAPIV1ListUsers(t *testing.T) {
	t.Run("empty returns empty array", func(t *testing.T) {
		h := newAPIV1Harness(t)

		res := h.callHuma(http.MethodGet, "/api/v1/user", nil)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{"users":[]}`, string(res.body))
	})

	t.Run("empty parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		h.assertParity(t, http.MethodGet, "/api/v1/user", nil)
	})

	t.Run("all parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice", "bob", "carol")(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/user", nil)
	})

	t.Run("filter by name parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice", "bob")(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/user?name=alice", nil)
	})

	t.Run("filter by id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice", "bob")(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/user?id=2", nil)
	})

	t.Run("invalid id parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedUsers("alice")(t, h.app)
		res := h.assertParity(t, http.MethodGet, "/api/v1/user?id=abc", nil)
		assertStatus(t, res, http.StatusBadRequest)
	})
}
