package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoOIDCAuthorization(t *testing.T) {
	testCases := []struct {
		name    string
		cfg     *types.OIDCConfig
		claims  *types.OIDCClaims
		wantErr bool
	}{
		{
			name:    "verified email domain",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{"test.com"},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{},
			},
			claims: &types.OIDCClaims{
				Email:         "user@test.com",
				EmailVerified: true,
			},
		},
		{
			name:    "verified email user",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{},
				AllowedUsers:          []string{"user@test.com"},
				AllowedGroups:         []string{},
			},
			claims: &types.OIDCClaims{
				Email:         "user@test.com",
				EmailVerified: true,
			},
		},
		{
			name:    "unverified email domain",
			wantErr: true,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{"test.com"},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{},
			},
			claims: &types.OIDCClaims{
				Email:         "user@test.com",
				EmailVerified: false,
			},
		},
		{
			name:    "group member",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{"test"},
			},
			claims: &types.OIDCClaims{Groups: []string{"test"}},
		},
		{
			name:    "non group member",
			wantErr: true,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{"nope"},
			},
			claims: &types.OIDCClaims{Groups: []string{"testo"}},
		},
		{
			name:    "group member but bad domain",
			wantErr: true,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{"user@good.com"},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{"test group"},
			},
			claims: &types.OIDCClaims{Groups: []string{"test group"}, Email: "bad@bad.com", EmailVerified: true},
		},
		{
			name:    "all checks pass",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{"test.com"},
				AllowedUsers:          []string{"user@test.com"},
				AllowedGroups:         []string{"test group"},
			},
			claims: &types.OIDCClaims{Groups: []string{"test group"}, Email: "user@test.com", EmailVerified: true},
		},
		{
			name:    "all checks pass with unverified email",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: false,
				AllowedDomains:        []string{"test.com"},
				AllowedUsers:          []string{"user@test.com"},
				AllowedGroups:         []string{"test group"},
			},
			claims: &types.OIDCClaims{Groups: []string{"test group"}, Email: "user@test.com", EmailVerified: false},
		},
		{
			name:    "fail on unverified email",
			wantErr: true,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{"test.com"},
				AllowedUsers:          []string{"user@test.com"},
				AllowedGroups:         []string{"test group"},
			},
			claims: &types.OIDCClaims{Groups: []string{"test group"}, Email: "user@test.com", EmailVerified: false},
		},
		{
			name:    "unverified email user only",
			wantErr: true,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{},
				AllowedUsers:          []string{"user@test.com"},
				AllowedGroups:         []string{},
			},
			claims: &types.OIDCClaims{
				Email:         "user@test.com",
				EmailVerified: false,
			},
		},
		{
			name:    "no filters configured",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{},
			},
			claims: &types.OIDCClaims{
				Email:         "anyone@anywhere.com",
				EmailVerified: false,
			},
		},
		{
			name:    "multiple allowed groups second matches",
			wantErr: false,
			cfg: &types.OIDCConfig{
				EmailVerifiedRequired: true,
				AllowedDomains:        []string{},
				AllowedUsers:          []string{},
				AllowedGroups:         []string{"group1", "group2", "group3"},
			},
			claims: &types.OIDCClaims{Groups: []string{"group2"}},
		},
	}

	for _, tC := range testCases {
		t.Run(tC.name, func(t *testing.T) {
			err := doOIDCAuthorization(tC.cfg, tC.claims)
			if ((err != nil) && !tC.wantErr) || ((err == nil) && tC.wantErr) {
				t.Errorf("bad authorization: %s > want=%v | got=%v", tC.name, tC.wantErr, err)
			}
		})
	}
}

// TestSetCSRFCookieSameSite verifies the OIDC state/nonce CSRF cookies carry an
// explicit SameSite=Lax attribute. Lax (not Strict) is required because the
// OIDC callback is a cross-site top-level GET navigation from the IdP that must
// still carry the cookie — Strict would drop it and break login. The cookie
// previously set no SameSite (despite a comment claiming it did), leaving
// browsers that do not default to Lax sending it on cross-site requests.
func TestSetCSRFCookieSameSite(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/abcdef0123456789", nil)

	setCSRFCookie(w, r, "state", false)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite,
		"OIDC CSRF cookie must explicitly set SameSite=Lax")
}

// TestExtractCodeAndStateParam covers the callback's first trust-boundary
// checks: both params required, and a too-short state is rejected before
// getCookieName can slice out of range.
func TestExtractCodeAndStateParam(t *testing.T) {
	_, _, err := extractCodeAndStateParamFromRequest(
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback", nil))
	require.Error(t, err)

	_, _, err = extractCodeAndStateParamFromRequest(
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback?code=c&state=abc", nil))
	require.ErrorIs(t, err, errOIDCStateTooShort)

	code, state, err := extractCodeAndStateParamFromRequest(
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback?code=c&state=abcdef0123", nil))
	require.NoError(t, err)
	assert.Equal(t, "c", code)
	assert.Equal(t, "abcdef0123", state)
}

// TestGetAuthInfoFromStateSingleUse asserts a consumed OIDC state cannot be
// resolved twice, so a replayed callback cannot re-bind the same session.
func TestGetAuthInfoFromStateSingleUse(t *testing.T) {
	a := &AuthProviderOIDC{
		authCache: expirable.NewLRU[string, AuthInfo](16, nil, time.Minute),
	}
	a.authCache.Add("state-x", AuthInfo{Registration: true})

	got := a.getAuthInfoFromState("state-x")
	require.NotNil(t, got)
	assert.True(t, got.Registration)

	assert.Nil(t, a.getAuthInfoFromState("state-x"), "a consumed state must not resolve again")
}

// TestClearOIDCCallbackCookie asserts the cookie is expired (negative MaxAge) on
// the same path it was set with, so the browser drops it.
func TestClearOIDCCallbackCookie(t *testing.T) {
	w := httptest.NewRecorder()
	clearOIDCCallbackCookie(w, "state_abcdef")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "state_abcdef", cookies[0].Name)
	assert.Negative(t, cookies[0].MaxAge, "deletion cookie must have negative MaxAge")
}

// TestSetCSRFCookieSecure verifies the Secure flag is driven by the secure
// argument (derived from the configured https server_url), not only req.TLS, so
// cookies stay Secure behind a TLS-terminating reverse proxy where req.TLS is
// nil.
func TestSetCSRFCookieSecure(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/abcdef0123456789", nil)

	secureRec := httptest.NewRecorder()
	setCSRFCookie(secureRec, r, "state", true)
	require.Len(t, secureRec.Result().Cookies(), 1)
	assert.True(t, secureRec.Result().Cookies()[0].Secure,
		"https server_url must set Secure even when req.TLS is nil (proxy case)")

	plainRec := httptest.NewRecorder()
	setCSRFCookie(plainRec, r, "state", false)
	require.Len(t, plainRec.Result().Cookies(), 1)
	assert.False(t, plainRec.Result().Cookies()[0].Secure,
		"plain-http server_url without req.TLS must not set Secure")
}
