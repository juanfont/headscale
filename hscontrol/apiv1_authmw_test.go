package hscontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIV1AuthMiddleware proves the v1 API, mounted on the real router, is
// guarded by the Huma security middleware: missing or bad Bearer tokens are
// rejected with 401 before reaching a handler; a valid key passes to 200. The
// per-endpoint harness bypasses auth via WithLocalTrust, so this is the one
// place the middleware itself is exercised.
func TestAPIV1AuthMiddleware(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	expiry := time.Now().Add(time.Hour)
	valid, _, err := app.state.CreateAPIKey(&expiry)
	require.NoError(t, err)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "missing bearer", authHeader: "", wantStatus: http.StatusUnauthorized},
		{name: "no bearer prefix", authHeader: "tskey-invalid", wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer token", authHeader: "Bearer tskey-invalid", wantStatus: http.StatusUnauthorized},
		{name: "valid api key", authHeader: "Bearer " + valid, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, "/api/v1/node", nil,
			)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equalf(t, tt.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestAPIV1RevokedAPIKey: an API key revoked through /api/headscale/v0 is
// refused by /api/v1 from its next request on, and its list no longer shows
// it, since its answer cannot say that a key is revoked.
func TestAPIV1RevokedAPIKey(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	other, _, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	secret, key, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	get := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/apikey", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec
	}

	require.Equal(t, http.StatusOK, get(secret).Code)
	require.NoError(t, app.state.RevokeAPIKey(key.ID))
	require.Equal(t, http.StatusUnauthorized, get(secret).Code)

	rec := get(other)
	require.Equal(t, http.StatusOK, rec.Code)

	var list struct {
		APIKeys []struct {
			ID string `json:"id"`
		} `json:"apiKeys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.APIKeys, 1)
	assert.NotEqual(t, strconv.FormatUint(key.ID, 10), list.APIKeys[0].ID)
}

// TestAPIV1DocsArePublic proves the OpenAPI document and docs UI live under
// /api/v1 and are reachable without an API key, while the operations beside them
// stay key-gated. The docs page points at the versioned spec so a future
// /api/v2 can carry its own.
func TestAPIV1DocsArePublic(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	tests := []struct {
		path     string
		contains string
	}{
		{path: "/api/v1/openapi.yaml", contains: "openapi:"},
		{path: "/api/v1/docs", contains: "/api/v1/openapi.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			// No Authorization header: these must be public.
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, tt.path, nil,
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equalf(t, http.StatusOK, rec.Code, "%s should be public; body: %s", tt.path, rec.Body.String())
			assert.Containsf(t, rec.Body.String(), tt.contains, "%s body", tt.path)
		})
	}
}

// TestAPIV1Unauthorized401 pins the 401 body: RFC 7807 JSON containing
// "Unauthorized", under 100 bytes and leaking no data, as the integration
// auth-bypass tests require.
func TestAPIV1Unauthorized401(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/node", nil,
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)

	body := rec.Body.Bytes()
	assert.Contains(t, string(body), "Unauthorized")
	assert.Lessf(t, len(body), 100, "401 body must stay small (no data leak): %s", body)

	var problem map[string]any
	require.NoError(t, json.Unmarshal(body, &problem), "401 body must be JSON: %s", body)
	assert.NotContains(t, problem, "users")
}
