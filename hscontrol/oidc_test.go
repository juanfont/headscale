package hscontrol

import (
	"net/http"
	"net/http/httptest"
	"testing"

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

	_, err := setCSRFCookie(w, r, "state")
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite,
		"OIDC CSRF cookie must explicitly set SameSite=Lax")
}
