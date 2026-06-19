package hscontrol

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIV1Health(t *testing.T) {
	h := newAPIV1Harness(t)

	t.Run("huma returns healthy with database connectivity", func(t *testing.T) {
		res := h.callHuma(http.MethodGet, "/api/v1/health", nil)

		assert.Equal(t, http.StatusOK, res.status)
		require.JSONEq(t, `{"databaseConnectivity":true}`, string(res.body))
	})

	t.Run("parity with gateway", func(t *testing.T) {
		h.assertParity(t, http.MethodGet, "/api/v1/health", nil)
	})
}
