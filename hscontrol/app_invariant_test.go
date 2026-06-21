package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juanfont/headscale/hscontrol"
)

func TestProtectedEndpointsRejectUnauthenticated(t *testing.T) {
	// Initialize the app with minimal config
	app, err := hscontrol.NewHeadscale()
	if err != nil {
		t.Fatalf("failed to create app: %v", err)
	}

	router := app.GetRouter()

	testCases := []struct {
		name           string
		path           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "missing_auth_header",
			path:           "/auth/test-id",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed_bearer_token",
			path:           "/auth/test-id",
			authHeader:     "Bearer invalid-token-format",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "expired_token",
			path:           "/auth/test-id",
			authHeader:     "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2MDAwMDAwMDB9.invalid",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "register_without_auth",
			path:           "/register/test-id",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus && w.Code != http.StatusForbidden {
				t.Errorf("expected status %d or %d, got %d", tc.expectedStatus, http.StatusForbidden, w.Code)
			}
		})
	}
}