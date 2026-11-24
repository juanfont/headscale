package cli

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListOAuthClientsAsksForAll: as on Tailscale, the keys list holds OAuth
// clients only with all=true.
func TestListOAuthClientsAsksForAll(t *testing.T) {
	env := serveSocket(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys := `[]`
		if r.URL.Path == "/api/v2/tailnet/-/keys" && r.URL.Query().Get("all") == "true" {
			keys = `[{"id":"kclient1","keyType":"client","created":"2026-01-01T00:00:00Z"}]`
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":` + keys + `}`))
	}))

	stdout, stderr, err := runHeadscale(t, env, "oauth-clients", "list", "-o", "json")
	require.NoError(t, err, stderr)
	assert.Contains(t, stdout, "kclient1")
}
