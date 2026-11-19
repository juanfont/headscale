package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiv0 "github.com/juanfont/headscale/hscontrol/api/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCORS(t *testing.T) {
	const allowed = "https://admin.example.com"

	// Each API answers 404, so the test sees that an error carries the
	// headers too.
	notFound := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	newRouter := func(origins ...string) http.Handler {
		app := &Headscale{
			cfg:          &types.Config{API: types.APIConfig{CORS: types.CORSConfig{AllowedOrigins: origins}}},
			authProvider: NewAuthProviderWeb(""),
		}

		return app.createRouter(notFound, notFound, notFound)
	}

	do := func(router http.Handler, method, path, origin string, preflight bool) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		if preflight {
			req.Header.Set("Access-Control-Request-Method", http.MethodPatch)
		}

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		return rec
	}

	router := newRouter(allowed)

	for _, path := range []string{"/api/headscale/v0/me", "/api/v2/tailnet/-/devices"} {
		t.Run(path, func(t *testing.T) {
			rec := do(router, http.MethodGet, path, allowed, false)
			assert.Equal(t, http.StatusNotFound, rec.Code)
			assert.Equal(t, allowed, rec.Header().Get("Access-Control-Allow-Origin"))
			assert.Contains(t, rec.Header().Get("Access-Control-Expose-Headers"), "ETag")
			assert.Contains(t, rec.Header().Values("Vary"), "Origin")

			rec = do(router, http.MethodOptions, path, allowed, true)
			assert.Equal(t, http.StatusNoContent, rec.Code)

			if strings.HasPrefix(path, apiv0.Prefix) {
				assert.NotEmpty(t, rec.Header().Get("Headscale-Version"), "the CLI reads it before any body")
			}

			assert.Equal(t, allowed, rec.Header().Get("Access-Control-Allow-Origin"))
			assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "PATCH")
			assert.Equal(t, "Authorization, Content-Type, If-Match", rec.Header().Get("Access-Control-Allow-Headers"))

			rec = do(router, http.MethodGet, path, "https://evil.example.com", false)
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"), "an origin not listed gets nothing")
		})
	}

	t.Run("the legacy API gets no CORS", func(t *testing.T) {
		rec := do(router, http.MethodGet, "/api/v1/node", allowed, false)
		require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("no origins sends nothing", func(t *testing.T) {
		rec := do(newRouter(), http.MethodGet, "/api/headscale/v0/me", allowed, false)
		require.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		require.Empty(t, rec.Header().Values("Vary"))
	})
}
