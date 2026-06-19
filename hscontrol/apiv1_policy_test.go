package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validPolicy is a minimal policy that passes validation without nodes or users.
const validPolicy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

// invalidPolicy is not valid HuJSON, so policy manager construction fails.
const invalidPolicy = `{"acls": [`

// seedPolicy stores a policy in the database so reads return it.
func seedPolicy(policy string) func(t *testing.T, app *Headscale) {
	return func(t *testing.T, app *Headscale) {
		t.Helper()

		_, err := app.state.SetPolicyInDB(policy)
		require.NoError(t, err)
	}
}

func TestAPIV1PolicyGet(t *testing.T) {
	t.Run("empty parity", func(t *testing.T) {
		// With no policy stored, the DB load fails; this is treated as a server
		// fault (500), matching the legacy contract.
		h := newAPIV1Harness(t)
		res := h.assertParity(t, http.MethodGet, "/api/v1/policy", nil)
		assertStatus(t, res, http.StatusInternalServerError)
	})

	t.Run("set parity", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedPolicy(validPolicy)(t, h.app)
		h.assertParity(t, http.MethodGet, "/api/v1/policy", nil)
	})

	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)
		seedPolicy(validPolicy)(t, h.app)

		res := h.callHuma(http.MethodGet, "/api/v1/policy", nil)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Policy    string `json:"policy"`
			UpdatedAt string `json:"updatedAt"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.JSONEq(t, validPolicy, got.Policy)
		// updatedAt is emitted even though no omitempty is set.
		assert.NotEmpty(t, got.UpdatedAt)
	})
}

func TestAPIV1PolicySet(t *testing.T) {
	t.Run("valid parity", func(t *testing.T) {
		body, err := json.Marshal(map[string]string{"policy": validPolicy})
		require.NoError(t, err)

		assertParityIsolated(t, nil, http.MethodPut, "/api/v1/policy", body)
	})

	t.Run("invalid parity", func(t *testing.T) {
		body, err := json.Marshal(map[string]string{"policy": invalidPolicy})
		require.NoError(t, err)

		res := assertParityIsolated(t, nil, http.MethodPut, "/api/v1/policy", body)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("huma response shape", func(t *testing.T) {
		h := newAPIV1Harness(t)

		body, err := json.Marshal(map[string]string{"policy": validPolicy})
		require.NoError(t, err)

		res := h.callHuma(http.MethodPut, "/api/v1/policy", body)
		require.Equal(t, http.StatusOK, res.status)

		var got struct {
			Policy    string `json:"policy"`
			UpdatedAt string `json:"updatedAt"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))

		assert.JSONEq(t, validPolicy, got.Policy)
		assert.NotEmpty(t, got.UpdatedAt)
	})

	t.Run("not-db mode rejected", func(t *testing.T) {
		// Policy updates are only valid in DB mode; file mode rejects with 400.
		// createTestApp is DB mode, so build a file-mode app here.
		humaApp := createFilePolicyApp(t)

		body, err := json.Marshal(map[string]string{"policy": validPolicy})
		require.NoError(t, err)

		hum := callHandler(newHumaTestHandler(humaApp), http.MethodPut, "/api/v1/policy", body)

		assert.Equal(t, http.StatusBadRequest, hum.status,
			"huma body: %s", hum.body)
	})
}

func TestAPIV1PolicyCheck(t *testing.T) {
	t.Run("valid parity", func(t *testing.T) {
		h := newAPIV1Harness(t)

		body, err := json.Marshal(map[string]string{"policy": validPolicy})
		require.NoError(t, err)

		h.assertParity(t, http.MethodPost, "/api/v1/policy/check", body)
	})

	t.Run("invalid parity", func(t *testing.T) {
		h := newAPIV1Harness(t)

		body, err := json.Marshal(map[string]string{"policy": invalidPolicy})
		require.NoError(t, err)

		res := h.assertParity(t, http.MethodPost, "/api/v1/policy/check", body)
		assertStatus(t, res, http.StatusBadRequest)
	})

	t.Run("valid returns empty object", func(t *testing.T) {
		h := newAPIV1Harness(t)

		body, err := json.Marshal(map[string]string{"policy": validPolicy})
		require.NoError(t, err)

		res := h.callHuma(http.MethodPost, "/api/v1/policy/check", body)
		require.Equal(t, http.StatusOK, res.status)
		assert.JSONEq(t, `{}`, string(res.body))
	})
}

// createFilePolicyApp mirrors createTestApp but with file-based policy mode so
// the policy-update-disabled path can be exercised.
func createFilePolicyApp(t *testing.T) *Headscale {
	t.Helper()

	tmpDir := t.TempDir()

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		OIDC: types.OIDCConfig{},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeFile,
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	app.mapBatcher = mapper.NewBatcherAndMapper(&cfg, app.state)
	app.mapBatcher.Start()

	t.Cleanup(func() {
		if app.mapBatcher != nil {
			app.mapBatcher.Close()
		}
	})

	return app
}
