package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// TestAPIV1Config: GET /api/v1/config is the running configuration as
// YAML, behind an API key like every operation: documented unless
// docs=false, without the client-only cli section, and with no secret.
func TestAPIV1Config(t *testing.T) {
	secrets := []struct {
		name   string
		set    func(*types.Config)
		hidden []string
		shown  []string
	}{
		{
			name:   "postgres password",
			set:    func(c *types.Config) { c.Database.Postgres.Pass = "marker-pg-pass" },
			hidden: []string{"marker-pg-pass"},
		},
		{
			name:   "oidc client secret",
			set:    func(c *types.Config) { c.OIDC.ClientSecret = "marker-oidc-secret" },
			hidden: []string{"marker-oidc-secret"},
		},
		{
			name: "dns provider",
			set: func(c *types.Config) {
				c.DNSConfig.Challenge.ProviderSettings = map[string]any{ //nolint:gosec // test markers, not credentials
					"name":       "cloudflare",
					"api_token":  "marker-api-token",
					"zone":       map[string]any{"id": 987654321},
					"cert_token": "file:/run/credentials/cert",
				}
			},
			hidden: []string{"marker-api-token", "987654321"},
			shown:  []string{"cloudflare", "file:/run/credentials/cert"},
		},
		{
			name:   "url userinfo",
			set:    func(c *types.Config) { c.ServerURL = "https://marker-user:marker-pass@headscale.example.com" }, //nolint:gosec // test markers, not credentials
			hidden: []string{"marker-user", "marker-pass"},
			shown:  []string{"https://headscale.example.com"},
		},
	}

	h := newAPIV1Harness(t)
	for _, s := range secrets {
		s.set(h.app.cfg)
	}

	expiry := time.Now().Add(time.Hour)
	apiKey, _, err := h.app.state.CreateAPIKey(&expiry)
	require.NoError(t, err)

	remote := h.app.HTTPHandler()

	tests := []struct {
		name       string
		handler    http.Handler
		path       string
		auth       string
		wantStatus int
		wantDocs   bool
	}{
		{name: "docs by default", handler: h.huma, path: "/api/v1/config", wantStatus: http.StatusOK, wantDocs: true},
		{name: "docs", handler: h.huma, path: "/api/v1/config?docs=true", wantStatus: http.StatusOK, wantDocs: true},
		{name: "no docs", handler: h.huma, path: "/api/v1/config?docs=false", wantStatus: http.StatusOK},
		{name: "remote with api key", handler: remote, path: "/api/v1/config?docs=false", auth: "Bearer " + apiKey, wantStatus: http.StatusOK},
		{name: "remote without api key", handler: remote, path: "/api/v1/config", wantStatus: http.StatusUnauthorized},
		{name: "remote with bad api key", handler: remote, path: "/api/v1/config", auth: "Bearer hskey-api-invalid", wantStatus: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tt.path, nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, req)

			body := rec.Body.String()
			require.Equal(t, tt.wantStatus, rec.Code, body)

			if tt.wantStatus != http.StatusOK {
				assert.NotContains(t, body, "server_url")

				return
			}

			assert.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))

			var doc map[string]any
			require.NoError(t, yaml.Unmarshal(rec.Body.Bytes(), &doc), body)
			assert.Contains(t, doc, "server_url")
			assert.NotContains(t, doc, "cli")

			hasComment := false
			for l := range strings.SplitSeq(body, "\n") {
				hasComment = hasComment || strings.HasPrefix(strings.TrimSpace(l), "#")
			}

			assert.Equal(t, tt.wantDocs, hasComment)

			for _, s := range secrets {
				for _, hidden := range s.hidden {
					assert.NotContains(t, body, hidden, s.name)
				}

				for _, shown := range s.shown {
					assert.Contains(t, body, shown, s.name)
				}
			}
		})
	}
}
