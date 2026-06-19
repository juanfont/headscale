package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"

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
