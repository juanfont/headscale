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

// TestAPIV1Unauthorized401 pins the 401 body: plain "Unauthorized", as 0.29's
// httpAuthenticationMiddleware wrote it before the request reached the
// gateway. headscale-admin matches the text; the integration auth-bypass tests
// require it small and free of data.
func TestAPIV1Unauthorized401(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/node", nil,
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "Unauthorized", rec.Body.String())
}

// TestAPIV1QueryAsGateway: 0.29's grpc-gateway refused a query parameter given
// twice ("too many values", runtime/query.go:159-161 at v2.29.0) and an empty
// value it could not parse as the field's type (:166-170). Huma would read the
// first value, or none, and a write would act on it.
func TestAPIV1QueryAsGateway(t *testing.T) {
	h := newAPIV1Harness(t)
	user := h.app.state.CreateUserForTest("alice")

	_, apiKey, err := h.app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	pak1, err := h.app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)
	pak2, err := h.app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	id1, id2 := strconv.FormatUint(pak1.ID, 10), strconv.FormatUint(pak2.ID, 10)
	apiKeyID := strconv.FormatUint(apiKey.ID, 10)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"pre-auth key id twice", http.MethodDelete, "/api/v1/preauthkey?id=" + id1 + "&id=" + id2, http.StatusBadRequest},
		{"pre-auth key id empty", http.MethodDelete, "/api/v1/preauthkey?id=", http.StatusBadRequest},
		{"api key id twice", http.MethodDelete, "/api/v1/apikey/" + apiKey.Prefix + "?id=" + apiKeyID + "&id=" + apiKeyID, http.StatusBadRequest},
		{"api key id empty", http.MethodDelete, "/api/v1/apikey/" + apiKey.Prefix + "?id=", http.StatusBadRequest},
		{"backfill confirmed twice", http.MethodPost, "/api/v1/node/backfillips?confirmed=true&confirmed=false", http.StatusBadRequest},
		{"backfill confirmed empty", http.MethodPost, "/api/v1/node/backfillips?confirmed=", http.StatusBadRequest},
		{"register user twice", http.MethodPost, "/api/v1/node/register?user=alice&user=bob&key=x", http.StatusBadRequest},
		{"list nodes user twice", http.MethodGet, "/api/v1/node?user=alice&user=bob", http.StatusBadRequest},
		{"pre-auth key id after semicolon", http.MethodDelete, "/api/v1/preauthkey?x;id=" + id1, http.StatusBadRequest},
		// A dotted key into a scalar named no field (query.go:144-146); a
		// bracketed one gave it a second value (query.go:50-53).
		{"pre-auth key id dotted", http.MethodDelete, "/api/v1/preauthkey?id.x=" + id1, http.StatusBadRequest},
		{"pre-auth key id bracketed", http.MethodDelete, "/api/v1/preauthkey?id[x]=" + id1, http.StatusBadRequest},
		{"list users name dotted", http.MethodGet, "/api/v1/user?name.child=value", http.StatusBadRequest},
		{"list users name bracketed", http.MethodGet, "/api/v1/user?name[alice]=", http.StatusBadRequest},
		// Without its closing bracket the key is one unknown name, ignored.
		{"list users name unclosed bracket", http.MethodGet, "/api/v1/user?name[alice=1", http.StatusOK},
		// GetNode had no query parsed at all (no PopulateQueryParameters in
		// its generated handler at v0.29.7): every key is ignored.
		{"get node, path field dotted", http.MethodGet, "/api/v1/node/99999?nodeId.x=1", http.StatusNotFound},
		{"get node, unclosed bracket", http.MethodGet, "/api/v1/node/99999?nodeId[x=1", http.StatusNotFound},
		{"get node, semicolon", http.MethodGet, "/api/v1/node/99999?a;b", http.StatusNotFound},
		{"get node, path field dotted, other name", http.MethodGet, "/api/v1/node/99999?nodeId.child=1", http.StatusNotFound},
		// Health parsed no query either; ListNodes did, so a bad escape is a
		// 400 there and nothing on health.
		{"health, bad escape", http.MethodGet, "/api/v1/health?unrelated=%ZZ", http.StatusOK},
		{"list nodes, bad escape", http.MethodGet, "/api/v1/node?unrelated=%ZZ", http.StatusBadRequest},
		// A string parses from "", so the gateway took it as given.
		{"list users name empty", http.MethodGet, "/api/v1/user?name=", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := h.callHuma(tt.method, tt.path, nil)
			assert.Equal(t, tt.wantStatus, res.status, "body: %s", res.body)
		})
	}

	// A bare key is an empty value, as the gateway read it, not "true"; a
	// user named true tells the two apart.
	h.app.state.CreateUserForTest("true")

	for query, want := range map[string]int{
		"name":         2,
		"name=":        2,
		"name=alice":   1,
		"name=true":    1,
		"unrelated=1":  2,
		"name=&other=": 2,
	} {
		res := h.callHuma(http.MethodGet, "/api/v1/user?"+query, nil)
		require.Equal(t, http.StatusOK, res.status, "%s: %s", query, res.body)

		var got struct {
			Users []map[string]any `json:"users"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		assert.Len(t, got.Users, want, "?%s", query)
	}

	keys, err := h.app.state.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 2, "no pre-auth key may be deleted")

	apiKeys, err := h.app.state.ListAPIKeys()
	require.NoError(t, err)
	assert.Len(t, apiKeys, 1, "no API key may be deleted")
}
