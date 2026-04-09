package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConfirmRequest(t *testing.T, authID types.AuthID, formCSRF, cookieCSRF string) *http.Request {
	t.Helper()

	form := strings.NewReader(registerConfirmCSRFCookie + "=" + formCSRF)
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/register/confirm/"+authID.String(),
		form,
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{
		Name:  registerConfirmCSRFCookie,
		Value: cookieCSRF,
	})

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("auth_id", authID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	return req
}

// TestRegisterConfirmHandler_RejectsCSRFMismatch verifies that the
// /register/confirm POST handler refuses to finalise a pending
// registration when the form CSRF token does not match the cookie.
func TestRegisterConfirmHandler_RejectsCSRFMismatch(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	provider := &AuthProviderOIDC{h: app}

	// Mint a pending registration with a stashed pending-confirmation,
	// as the OIDC callback would have done after resolving the user
	// identity but before the user clicked the interstitial form.
	authID := types.MustAuthID()
	regReq := types.NewRegisterAuthRequest(&types.RegistrationData{
		Hostname: "phish-target",
	})
	regReq.SetPendingConfirmation(&types.PendingRegistrationConfirmation{
		UserID: 1,
		CSRF:   "expected-csrf",
	})
	app.state.SetAuthCacheEntry(authID, regReq)

	rec := httptest.NewRecorder()
	provider.RegisterConfirmHandler(rec,
		newConfirmRequest(t, authID, "wrong-csrf", "expected-csrf"),
	)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"CSRF cookie/form mismatch must be rejected with 403")

	// And the registration must still be pending — the rejected POST
	// must not have called handleRegistration.
	cached, ok := app.state.GetAuthCacheEntry(authID)
	require.True(t, ok, "rejected POST must not evict the cached registration")
	require.NotNil(t, cached.PendingConfirmation(),
		"rejected POST must not clear the pending confirmation")
}

// TestRegisterConfirmHandler_RejectsWithoutPending verifies that
// /register/confirm refuses to finalise a registration that did not
// first complete the OIDC interstitial. Without this check an attacker
// who knew an auth_id could POST directly to the confirm endpoint and
// claim the device.
func TestRegisterConfirmHandler_RejectsWithoutPending(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	provider := &AuthProviderOIDC{h: app}

	authID := types.MustAuthID()
	// Cached registration with NO pending confirmation set — i.e. the
	// OIDC callback has not run yet.
	app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(
		&types.RegistrationData{Hostname: "no-oidc-yet"},
	))

	rec := httptest.NewRecorder()
	provider.RegisterConfirmHandler(rec,
		newConfirmRequest(t, authID, "fake", "fake"),
	)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"confirm without prior OIDC pending state must be rejected with 403")
}
