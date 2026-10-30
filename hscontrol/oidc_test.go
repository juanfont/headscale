package hscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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
	a := &AuthProviderOIDC{serverURL: "http://hs.example.com"}
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/abcdef0123456789", nil)

	a.setCSRFCookie(w, r, "state", "state-value")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite,
		"OIDC CSRF cookie must explicitly set SameSite=Lax")
}

// TestExtractCodeAndStateParam covers the callback's first trust-boundary
// checks: a code or provider error is required, and a too-short state is rejected before
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
	t.Cleanup(a.authCache.Close)
	a.authCache.Add("state-x", AuthInfo{Registration: true})

	got := a.getAuthInfoFromState("state-x")
	require.NotNil(t, got)
	assert.True(t, got.Registration)

	assert.Nil(t, a.getAuthInfoFromState("state-x"), "a consumed state must not resolve again")
}

func newOIDCPendingProvider(t *testing.T, capacity int) *AuthProviderOIDC {
	t.Helper()

	a := &AuthProviderOIDC{
		h:         createTestApp(t),
		serverURL: "https://headscale.example",
		cfg:       &types.OIDCConfig{},
		oauth2Config: &oauth2.Config{
			ClientID: "headscale-test",
			Endpoint: oauth2.Endpoint{
				AuthURL:   "https://issuer.example/authorize",
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
	}
	t.Cleanup(func() { require.NoError(t, a.h.state.Close()) })

	a.authCache = expirable.NewLRU[string, AuthInfo](capacity+authCacheSSHReserve, func(_ string, info AuthInfo) {
		if info.Registration {
			a.authCacheRegistrations.Add(-1)
		}
	}, time.Minute)
	t.Cleanup(a.authCache.Close)

	return a
}

func oidcPendingAuthRequest(t *testing.T, authID types.AuthID) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/register/"+authID.String(), nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("auth_id", authID.String())

	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func startOIDCPendingAuth(t *testing.T, a *AuthProviderOIDC, registration bool) (*httptest.ResponseRecorder, types.AuthID) {
	t.Helper()

	authID := types.MustAuthID()

	authReq := types.NewSSHCheckAuthRequest(1, 2)
	if registration {
		authReq = types.NewRegisterAuthRequest(&types.RegistrationData{Hostname: "pending-oidc"})
	}

	require.NoError(t, a.h.state.SetAuthCacheEntry(authID, authReq))

	rec := httptest.NewRecorder()
	a.authHandler(rec, oidcPendingAuthRequest(t, authID), registration)

	return rec, authID
}

func TestOIDCPendingAdmissionPreservesSessions(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	a.cfg.PKCE.Enabled = true
	a.cfg.PKCE.Method = types.PKCEMethodS256

	states := make(map[string]AuthInfo)

	for _, registration := range []bool{true, false} {
		rec, authID := startOIDCPendingAuth(t, a, registration)
		require.Equal(t, http.StatusFound, rec.Code)
		location, err := rec.Result().Location()
		require.NoError(t, err)

		state := location.Query().Get("state")
		info, ok := a.authCache.Peek(state)
		require.True(t, ok)
		require.NotNil(t, info.Verifier)
		assert.Equal(t, authID, info.AuthID)
		assert.Equal(t, registration, info.Registration)
		assert.Equal(t, "S256", location.Query().Get("code_challenge_method"))

		states[state] = info
	}

	rejected, _ := startOIDCPendingAuth(t, a, true)
	assert.Equal(t, http.StatusServiceUnavailable, rejected.Code,
		"a full pending-state cache must reject admission instead of evicting an in-flight login")
	assert.Equal(t, "10", rejected.Header().Get("Retry-After"))
	assert.Empty(t, rejected.Header().Get("Location"))
	assert.Empty(t, rejected.Header().Values("Set-Cookie"))

	for state, want := range states {
		assert.Equal(t, &want, a.getAuthInfoFromState(state), "an admitted session must survive a rejected admission")
	}

	assert.Zero(t, a.authCache.Len())
}

func TestOIDCPendingAdmissionReservesSSHCapacity(t *testing.T) {
	a := newOIDCPendingProvider(t, 2)
	registrations := make(map[string]types.AuthID)

	for range 2 {
		rec, authID := startOIDCPendingAuth(t, a, true)
		require.Equal(t, http.StatusFound, rec.Code)
		location, err := rec.Result().Location()
		require.NoError(t, err)

		registrations[location.Query().Get("state")] = authID
	}

	rejected, _ := startOIDCPendingAuth(t, a, true)
	assert.Equal(t, http.StatusServiceUnavailable, rejected.Code)
	assert.Empty(t, rejected.Header().Values("Set-Cookie"))

	for range 64 {
		rec, authID := startOIDCPendingAuth(t, a, false)
		require.Equal(t, http.StatusFound, rec.Code, "registration load must leave the SSH reserve available")
		location, err := rec.Result().Location()
		require.NoError(t, err)

		info, ok := a.authCache.Peek(location.Query().Get("state"))
		require.True(t, ok)
		assert.Equal(t, authID, info.AuthID)
		assert.False(t, info.Registration)
	}

	full, _ := startOIDCPendingAuth(t, a, false)
	assert.Equal(t, http.StatusServiceUnavailable, full.Code, "the SSH reserve must also be bounded")
	assert.Empty(t, full.Header().Get("Location"))
	assert.Empty(t, full.Header().Values("Set-Cookie"))
	assert.Equal(t, 66, a.authCache.Len())

	for state, authID := range registrations {
		info := a.getAuthInfoFromState(state)
		require.NotNil(t, info, "admission at the total bound must not evict an earlier registration")
		assert.Equal(t, authID, info.AuthID)
	}
}

func TestOIDCPendingAdmissionConcurrent(t *testing.T) {
	a := newOIDCPendingProvider(t, 2)

	type result struct {
		authID types.AuthID
		rec    *httptest.ResponseRecorder
	}

	results := make(chan result, 4)
	start := make(chan struct{})

	var workers sync.WaitGroup

	for range 4 {
		authID := types.MustAuthID()
		require.NoError(t, a.h.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{Hostname: "concurrent-oidc"})))
		req := oidcPendingAuthRequest(t, authID)

		workers.Go(func() {
			<-start

			rec := httptest.NewRecorder()
			a.RegisterHandler(rec, req)

			results <- result{authID: authID, rec: rec}
		})
	}

	close(start)
	workers.Wait()
	close(results)

	accepted := make(map[string]types.AuthID)
	rejected := 0

	for result := range results {
		if result.rec.Code == http.StatusFound {
			location, err := result.rec.Result().Location()
			require.NoError(t, err)

			accepted[location.Query().Get("state")] = result.authID
		} else {
			assert.Equal(t, http.StatusServiceUnavailable, result.rec.Code)
			assert.Empty(t, result.rec.Header().Get("Location"))
			assert.Empty(t, result.rec.Header().Values("Set-Cookie"))

			rejected++
		}
	}

	require.Len(t, accepted, 2, "concurrent admission must respect the pending-state bound")
	assert.Equal(t, 2, rejected)
	assert.Equal(t, 2, a.authCache.Len())

	for state, authID := range accepted {
		info := a.getAuthInfoFromState(state)
		require.NotNil(t, info, "every successful admission must remain usable")
		assert.Equal(t, authID, info.AuthID)
	}
}

func TestOIDCPendingAdmissionDuplicateState(t *testing.T) {
	a := newOIDCPendingProvider(t, 2)
	verifier := "original-verifier"
	info := AuthInfo{AuthID: types.MustAuthID(), Verifier: &verifier, Registration: true}
	require.True(t, a.addAuthInfoToState("same-state", info))
	assert.False(t, a.addAuthInfoToState("same-state", AuthInfo{AuthID: types.MustAuthID()}),
		"a duplicate state must not replace the auth ID, flow type, or PKCE verifier")
	assert.Equal(t, &info, a.getAuthInfoFromState("same-state"))
	assert.Zero(t, a.authCacheRegistrations.Load())
}

func TestOIDCPendingAdmissionSSHUsesNormalSlots(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	for i := range 65 {
		require.True(t, a.addAuthInfoToState(fmt.Sprintf("ssh-state-%d", i), AuthInfo{AuthID: types.MustAuthID()}),
			"SSH checks may use the regular slots as well as their reserve")
	}

	assert.False(t, a.addAuthInfoToState("one-too-many", AuthInfo{AuthID: types.MustAuthID()}))
	assert.Equal(t, 65, a.authCache.Len())
	assert.Zero(t, a.authCacheRegistrations.Load())
}

func TestOIDCPendingAdmissionRequiresAuthRequest(t *testing.T) {
	for _, registration := range []bool{true, false} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("registration=%t/existing=%t", registration, existing), func(t *testing.T) {
				a := newOIDCPendingProvider(t, 1)
				authID := types.MustAuthID()
				wantStatus := http.StatusGone

				if existing {
					// A registration cannot authorize an SSH check, or vice versa.
					authReq := types.NewRegisterAuthRequest(&types.RegistrationData{Hostname: "wrong-flow"})
					if registration {
						authReq = types.NewSSHCheckAuthRequest(1, 2)
					}

					require.NoError(t, a.h.state.SetAuthCacheEntry(authID, authReq))

					wantStatus = http.StatusBadRequest
				}

				rec := httptest.NewRecorder()
				a.authHandler(rec, oidcPendingAuthRequest(t, authID), registration)
				assert.Equal(t, wantStatus, rec.Code)
				assert.Empty(t, rec.Header().Get("Location"))
				assert.Empty(t, rec.Header().Values("Set-Cookie"))
				assert.Zero(t, a.authCache.Len(), "invalid auth requests must not reserve OIDC capacity")
			})
		}
	}
}

func TestOIDCPendingAdmissionInvalidPKCE(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	a.cfg.PKCE.Enabled = true
	a.cfg.PKCE.Method = "invalid"

	rec, _ := startOIDCPendingAuth(t, a, true)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, rec.Header().Get("Location"))
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Zero(t, a.authCache.Len())

	a.cfg.PKCE.Method = types.PKCEMethodPlain
	rec, _ = startOIDCPendingAuth(t, a, true)
	assert.Equal(t, http.StatusFound, rec.Code, "a preparation error must leave capacity available")
}

func TestOIDCPendingAdmissionReclaimsExpired(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		a := newOIDCPendingProvider(t, 2)
		a.authCache.Close()

		a.authCache = expirable.NewLRU[string, AuthInfo](66, func(_ string, info AuthInfo) {
			if info.Registration {
				a.authCacheRegistrations.Add(-1)
			}
		}, time.Second)
		defer a.authCache.Close()

		old, _ := startOIDCPendingAuth(t, a, true)
		require.Equal(t, http.StatusFound, old.Code)
		oldURL, err := old.Result().Location()
		require.NoError(t, err)

		<-time.After(time.Millisecond)

		live, liveID := startOIDCPendingAuth(t, a, true)
		require.Equal(t, http.StatusFound, live.Code)
		liveURL, err := live.Result().Location()
		require.NoError(t, err)

		// Both entries share a cleanup bucket, which waits for the newer expiry.
		<-time.After(time.Second - time.Millisecond + time.Nanosecond)
		require.Equal(t, 2, a.authCache.Len(), "exercise expired entries that the sweeper has not removed")
		_, ok := a.authCache.Peek(oldURL.Query().Get("state"))
		require.False(t, ok)

		next, _ := startOIDCPendingAuth(t, a, true)
		assert.Equal(t, http.StatusFound, next.Code, "expired entries must not cause a false capacity rejection")
		assert.Nil(t, a.getAuthInfoFromState(oldURL.Query().Get("state")))
		info := a.getAuthInfoFromState(liveURL.Query().Get("state"))
		require.NotNil(t, info, "reclaiming expiry must preserve the live session")
		assert.Equal(t, liveID, info.AuthID)
	})
}

func TestOIDCPendingAdmissionReclaimsSweptCapacity(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	a.authCache.Close()

	synctest.Test(t, func(t *testing.T) {
		a.authCache = expirable.NewLRU[string, AuthInfo](65, func(_ string, info AuthInfo) {
			if info.Registration {
				a.authCacheRegistrations.Add(-1)
			}
		}, time.Second)
		defer a.authCache.Close()

		require.True(t, a.addAuthInfoToState("expires", AuthInfo{Registration: true}))

		<-time.After(time.Second + 10*time.Millisecond)
		synctest.Wait()
		assert.Zero(t, a.authCache.Len())
		assert.Zero(t, a.authCacheRegistrations.Load(), "background expiry must return the registration budget")
		assert.True(t, a.addAuthInfoToState("replacement", AuthInfo{Registration: true}))
	})
}

func TestOIDCPendingCallbackReleasesOnError(t *testing.T) {
	for _, pkce := range []bool{false, true} {
		for _, missingToken := range []bool{false, true} {
			t.Run(fmt.Sprintf("pkce=%t/missingToken=%t", pkce, missingToken), func(t *testing.T) {
				a := newOIDCPendingProvider(t, 1)
				a.cfg.PKCE.Enabled = pkce
				a.cfg.PKCE.Method = types.PKCEMethodS256

				var exchanges atomic.Int32

				tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					exchanges.Add(1)
					w.Header().Set("Content-Type", "application/json")

					if missingToken {
						_, _ = io.WriteString(w, `{"access_token":"test-token","token_type":"Bearer"}`)
					} else {
						w.WriteHeader(http.StatusBadRequest)
						_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
					}
				}))
				t.Cleanup(tokenServer.Close)
				a.oauth2Config.Endpoint.TokenURL = tokenServer.URL

				started, authID := startOIDCPendingAuth(t, a, true)
				require.Equal(t, http.StatusFound, started.Code)
				location, err := started.Result().Location()
				require.NoError(t, err)

				state := location.Query().Get("state")
				callbackURL := "/oidc/callback?code=test-code&state=" + state
				callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackURL, nil)
				//nolint:gosec // G124: request cookies carry only name and value on the wire.
				callback.AddCookie(&http.Cookie{Name: getCookieName("state", state), Value: state})

				rec := httptest.NewRecorder()
				a.OIDCCallbackHandler(rec, callback)

				wantStatus := http.StatusForbidden
				if missingToken {
					wantStatus = http.StatusBadRequest
				}

				assert.Equal(t, wantStatus, rec.Code)
				assert.Zero(t, a.authCache.Len(), "a callback error must release its pending-state slot")
				_, pending := a.h.state.GetAuthCacheEntry(authID)
				assert.True(t, pending, "consuming OIDC state must preserve the underlying auth request")

				replay := httptest.NewRecorder()
				a.OIDCCallbackHandler(replay, callback)
				assert.Equal(t, http.StatusGone, replay.Code, "a failed callback must still consume its state")
				assert.EqualValues(t, 1, exchanges.Load(), "a consumed state must not reach token exchange again")

				next := httptest.NewRecorder()
				a.RegisterHandler(next, oidcPendingAuthRequest(t, authID))
				assert.Equal(t, http.StatusFound, next.Code, "the original auth request must support a fresh browser flow")
				nextURL, err := next.Result().Location()
				require.NoError(t, err)
				assert.NotEqual(t, state, nextURL.Query().Get("state"))
			})
		}
	}
}

func TestOIDCPendingCallbackProviderError(t *testing.T) {
	for _, tc := range []struct {
		name          string
		providerError string
		code          string
	}{
		{name: "cancelled", providerError: "access_denied"},
		{name: "error with code", providerError: "access_denied", code: "unused-code"},
		{name: "unknown error", providerError: strings.Repeat("untrusted-provider-error-", 2048)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newOIDCPendingProvider(t, 1)
			a.cfg.PKCE.Enabled = true
			a.cfg.PKCE.Method = types.PKCEMethodS256

			var exchanges atomic.Int32

			tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				exchanges.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			}))
			t.Cleanup(tokenServer.Close)
			a.oauth2Config.Endpoint.TokenURL = tokenServer.URL

			started, authID := startOIDCPendingAuth(t, a, true)
			require.Equal(t, http.StatusFound, started.Code)
			location, err := started.Result().Location()
			require.NoError(t, err)

			state := location.Query().Get("state")

			full := httptest.NewRecorder()
			a.RegisterHandler(full, oidcPendingAuthRequest(t, authID))
			require.Equal(t, http.StatusServiceUnavailable, full.Code)

			query := url.Values{
				"error":             {tc.providerError},
				"error_description": {strings.Repeat("untrusted-provider-description-", 2048)},
				"state":             {state},
				"code":              {tc.code},
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			callback := httptest.NewRequestWithContext(ctx, http.MethodGet, "/oidc/callback?"+query.Encode(), nil)
			//nolint:gosec // G124: request cookies carry only name and value on the wire.
			callback.AddCookie(&http.Cookie{Name: getCookieName("state", state), Value: state})

			rec := httptest.NewRecorder()
			a.OIDCCallbackHandler(rec, callback)
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.NotContains(t, rec.Body.String(), "untrusted-provider-description")
			assert.NotContains(t, rec.Body.String(), "untrusted-provider-error")
			assert.Less(t, rec.Body.Len(), 16*1024, "provider input must not inflate the error response")
			assert.Zero(t, a.authCache.Len(), "provider cancellation must release its pending-state slot")
			assert.Zero(t, a.authCacheRegistrations.Load())
			_, pending := a.h.state.GetAuthCacheEntry(authID)
			assert.True(t, pending, "provider cancellation must preserve the underlying auth request")

			replay := httptest.NewRecorder()
			a.OIDCCallbackHandler(replay, callback)
			assert.Equal(t, http.StatusGone, replay.Code, "a provider-error callback must consume its state exactly once")
			assert.Zero(t, exchanges.Load(), "provider-error callbacks must never exchange a code")

			next := httptest.NewRecorder()
			a.RegisterHandler(next, oidcPendingAuthRequest(t, authID))
			require.Equal(t, http.StatusFound, next.Code, "cancellation must free capacity for a fresh login")
			nextURL, err := next.Result().Location()
			require.NoError(t, err)
			assert.NotEqual(t, state, nextURL.Query().Get("state"))
		})
	}
}

func TestOIDCPendingCallbackProviderErrorValidation(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	started, authID := startOIDCPendingAuth(t, a, true)
	require.Equal(t, http.StatusFound, started.Code)
	location, err := started.Result().Location()
	require.NoError(t, err)

	state := location.Query().Get("state")
	cookieName := getCookieName("state", state)
	cookie := cookieName + "=" + state
	providerError := "error=access_denied&state=" + state

	for _, tc := range []struct {
		name   string
		query  string
		cookie string
		status int
	}{
		{name: "missing state", query: "error=access_denied", cookie: cookie, status: http.StatusBadRequest},
		{name: "short state", query: "error=access_denied&state=abc", cookie: "state_abc=abc", status: http.StatusBadRequest},
		{name: "missing code and error", query: "state=" + state, cookie: cookie, status: http.StatusBadRequest},
		{name: "empty error", query: "error=&state=" + state, cookie: cookie, status: http.StatusBadRequest},
		{name: "description only", query: "error_description=cancelled&state=" + state, cookie: cookie, status: http.StatusBadRequest},
		{name: "missing cookie", query: providerError, status: http.StatusBadRequest},
		{name: "invalid cookie", query: providerError, cookie: cookieName + "=\"unterminated", status: http.StatusBadRequest},
		{name: "empty cookie", query: providerError, cookie: cookieName + "=", status: http.StatusForbidden},
		{name: "wrong cookie value", query: providerError, cookie: cookieName + "=different-state", status: http.StatusForbidden},
		{name: "wrong cookie name", query: providerError, cookie: "state_other=" + state, status: http.StatusBadRequest},
		{name: "unknown state", query: "error=access_denied&state=unknown-state", cookie: "state_unknow=unknown-state", status: http.StatusGone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback?"+tc.query, nil)
			callback.Header.Set("Cookie", tc.cookie)

			rec := httptest.NewRecorder()
			a.OIDCCallbackHandler(rec, callback)
			assert.Equal(t, tc.status, rec.Code)

			info, ok := a.authCache.Peek(state)
			require.True(t, ok, "invalid callbacks must preserve the pending state")
			assert.Equal(t, authID, info.AuthID)

			full := httptest.NewRecorder()
			a.RegisterHandler(full, oidcPendingAuthRequest(t, authID))
			assert.Equal(t, http.StatusServiceUnavailable, full.Code, "invalid callbacks must not free another browser's slot")
		})
	}
}

func TestOIDCPendingCallbackRequiresState(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)

	var exchanges atomic.Int32

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exchanges.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(tokenServer.Close)
	a.oauth2Config.Endpoint.TokenURL = tokenServer.URL

	const state = "unknown-oidc-state"

	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback?code=test-code&state="+state, nil)
	//nolint:gosec // G124: request cookies carry only name and value on the wire.
	callback.AddCookie(&http.Cookie{Name: getCookieName("state", state), Value: state})

	rec := httptest.NewRecorder()
	a.OIDCCallbackHandler(rec, callback)
	assert.Equal(t, http.StatusGone, rec.Code)
	assert.Zero(t, exchanges.Load(), "unknown state must be rejected before token exchange even without PKCE")
}

func TestOIDCPendingCallbackConcurrent(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	a.cfg.PKCE.Enabled = true
	a.cfg.PKCE.Method = types.PKCEMethodS256
	entered := make(chan struct{}, 2)
	release := make(chan struct{})

	var releaseOnce sync.Once

	unblock := func() { releaseOnce.Do(func() { close(release) }) }

	var exchanges atomic.Int32

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exchanges.Add(1)

		entered <- struct{}{}

		<-release
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}))
	t.Cleanup(tokenServer.Close)
	t.Cleanup(unblock)

	a.oauth2Config.Endpoint.TokenURL = tokenServer.URL

	started, _ := startOIDCPendingAuth(t, a, true)
	require.Equal(t, http.StatusFound, started.Code)
	location, err := started.Result().Location()
	require.NoError(t, err)

	state := location.Query().Get("state")
	callbackURL := "/oidc/callback?code=test-code&state=" + state
	first := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackURL, nil)
	//nolint:gosec // G124: request cookies carry only name and value on the wire.
	first.AddCookie(&http.Cookie{Name: getCookieName("state", state), Value: state})
	second := first.Clone(t.Context())
	firstRec, secondRec := httptest.NewRecorder(), httptest.NewRecorder()
	firstDone, secondDone := make(chan struct{}), make(chan struct{})

	go func() {
		a.OIDCCallbackHandler(firstRec, first)
		close(firstDone)
	}()

	select {
	case <-entered:
	case <-firstDone:
		t.Fatal("the first callback must reach token exchange")
	case <-time.After(5 * time.Second):
		t.Fatal("the first callback did not reach token exchange")
	}

	go func() {
		a.OIDCCallbackHandler(secondRec, second)
		close(secondDone)
	}()

	select {
	case <-secondDone:
	case <-entered:
		// Release both requests before asserting the single-exchange invariant.
	case <-time.After(5 * time.Second):
		t.Fatal("the duplicate callback did not finish or reach token exchange")
	}

	unblock()
	<-firstDone
	<-secondDone
	assert.Equal(t, http.StatusForbidden, firstRec.Code)
	assert.Equal(t, http.StatusGone, secondRec.Code)
	assert.EqualValues(t, 1, exchanges.Load(), "only one callback may claim a pending state")
	assert.Zero(t, a.authCache.Len())
}

func TestOIDCPendingCallbackCookieBinding(t *testing.T) {
	a := newOIDCPendingProvider(t, 1)
	started, _ := startOIDCPendingAuth(t, a, true)
	require.Equal(t, http.StatusFound, started.Code)
	location, err := started.Result().Location()
	require.NoError(t, err)

	state := location.Query().Get("state")

	for _, value := range []string{"", "different-state"} {
		callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback?code=test-code&state="+state, nil)
		wantStatus := http.StatusBadRequest

		if value != "" {
			//nolint:gosec // G124: request cookies carry only name and value on the wire.
			callback.AddCookie(&http.Cookie{Name: getCookieName("state", state), Value: value})

			wantStatus = http.StatusForbidden
		}

		rec := httptest.NewRecorder()
		a.OIDCCallbackHandler(rec, callback)
		assert.Equal(t, wantStatus, rec.Code)

		_, ok := a.authCache.Peek(state)
		assert.True(t, ok, "an unbound callback must not consume another browser's pending state")
	}
}

func TestOIDCPendingCallbackPKCEFlow(t *testing.T) {
	for _, method := range []string{"", types.PKCEMethodPlain, types.PKCEMethodS256} {
		t.Run("method="+method, func(t *testing.T) {
			b := newOIDCBrowser(t)
			a, ok := b.app.authProvider.(*AuthProviderOIDC)
			require.True(t, ok)

			a.cfg.PKCE.Enabled = method != ""
			a.cfg.PKCE.Method = method
			a.authCache.Resize(65)

			authID, registerURL := b.pendingNode(t)

			status, _, body := b.get(t, registerURL)
			require.Equal(t, http.StatusOK, status)
			assert.Contains(t, body, "Confirm node registration")
			assert.Zero(t, a.authCache.Len(), "successful callbacks must release pending OIDC capacity")

			authReq, ok := b.app.state.GetAuthCacheEntry(authID)
			require.True(t, ok, "consuming OIDC state must preserve the registration for confirmation")
			assert.NotNil(t, authReq.PendingConfirmation())
		})
	}
}

func TestOIDCPendingCallbackPreservesSSHVerdict(t *testing.T) {
	b := newOIDCBrowser(t)
	a, ok := b.app.authProvider.(*AuthProviderOIDC)
	require.True(t, ok)

	principal := mockoidc.DefaultUser()
	user, err := a.createOrUpdateUserFromClaim(&types.OIDCClaims{
		Iss:           b.idp.Issuer(),
		Sub:           principal.Subject,
		Username:      principal.PreferredUsername,
		Email:         principal.Email,
		EmailVerified: true,
	})
	require.NoError(t, err)

	src := b.app.state.CreateNodeForTest(user, "oidc-ssh-source")
	b.app.state.PutNodeInStoreForTest(*src)

	authID := types.MustAuthID()
	authReq := types.NewSSHCheckAuthRequest(src.ID, 2)
	require.NoError(t, b.app.state.SetAuthCacheEntry(authID, authReq))

	status, _, body := b.get(t, a.AuthURL(authID))
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, body, "You may return to your terminal.")
	assert.Zero(t, a.authCache.Len())

	cached, ok := b.app.state.GetAuthCacheEntry(authID)
	require.True(t, ok, "completing OIDC must preserve the SSH verdict for its polling client")
	assert.Same(t, authReq, cached)

	select {
	case verdict := <-cached.WaitForAuth():
		assert.True(t, verdict.Accept())
	default:
		t.Fatal("successful SSH authentication must make its verdict available")
	}
}

func TestOIDCPendingCallbackNonceBinding(t *testing.T) {
	b := newOIDCBrowser(t)
	a, ok := b.app.authProvider.(*AuthProviderOIDC)
	require.True(t, ok)

	b.client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Path == "/oidc/callback" {
			return http.ErrUseLastResponse
		}

		return nil
	}
	_, registerURL := b.pendingNode(t)
	//nolint:noctx,bodyclose // local test browser; closed below
	response, err := b.client.Get(registerURL)
	require.NoError(t, err)

	defer response.Body.Close()

	callbackURL, err := response.Location()
	require.NoError(t, err)
	require.Equal(t, "/oidc/callback", callbackURL.Path)

	callback := httptest.NewRequestWithContext(t.Context(), http.MethodGet, callbackURL.String(), nil)
	for _, cookie := range b.client.Jar.Cookies(callbackURL) {
		if strings.HasPrefix(cookie.Name, "nonce_") {
			cookie.Value = "wrong-nonce"
		}

		callback.AddCookie(cookie)
	}

	rec := httptest.NewRecorder()
	a.OIDCCallbackHandler(rec, callback)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, a.authCache.Len(), "nonce rejection must release the consumed pending state")
}

// TestClearOIDCCallbackCookie asserts the cookie is expired (negative MaxAge) on
// the same path it was set with, so the browser drops it.
func TestClearOIDCCallbackCookie(t *testing.T) {
	a := &AuthProviderOIDC{serverURL: "https://hs.example.com/prefix"}
	w := httptest.NewRecorder()
	a.clearOIDCCallbackCookie(w, "state_abcdef")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, "state_abcdef", cookies[0].Name)
	assert.Equal(t, "/prefix/oidc/callback", cookies[0].Path)
	assert.Negative(t, cookies[0].MaxAge, "deletion cookie must have negative MaxAge")
}

// TestSetCSRFCookieSecure verifies the Secure flag is driven by the secure
// argument (derived from the configured https server_url), not only req.TLS, so
// cookies stay Secure behind a TLS-terminating reverse proxy where req.TLS is
// nil.
func TestSetCSRFCookieSecure(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/abcdef0123456789", nil)

	secureRec := httptest.NewRecorder()
	secureProvider := &AuthProviderOIDC{serverURL: "https://hs.example.com"}
	secureProvider.setCSRFCookie(secureRec, r, "state", "state-value")
	require.Len(t, secureRec.Result().Cookies(), 1)
	assert.True(t, secureRec.Result().Cookies()[0].Secure,
		"https server_url must set Secure even when req.TLS is nil (proxy case)")

	plainRec := httptest.NewRecorder()
	plainProvider := &AuthProviderOIDC{serverURL: "http://hs.example.com"}
	plainProvider.setCSRFCookie(plainRec, r, "state", "state-value")
	require.Len(t, plainRec.Result().Cookies(), 1)
	assert.False(t, plainRec.Result().Cookies()[0].Secure,
		"plain-http server_url without req.TLS must not set Secure")
}

// oidcBrowser drives the interactive OIDC registration flow the way a
// browser does: over real HTTP against the real route table, through a
// cookie jar that honours Path and expiry, following redirects.
//
// Both halves matter for this bug. The route table is where the
// confirmation page's missing GET route lives, and cookie Path decides
// whether the state cookie the callback deletes is actually gone on the
// next hit.
type oidcBrowser struct {
	app       *Headscale
	idp       *mockoidc.MockOIDC
	srv       *httptest.Server
	publicURL string
	client    *http.Client
}

func newOIDCBrowser(t *testing.T) *oidcBrowser {
	t.Helper()

	return newOIDCBrowserWithPrefix(t, "")
}

func newOIDCBrowserWithPrefix(t *testing.T, prefix string) *oidcBrowser {
	t.Helper()

	return newOIDCBrowserWith(t, prefix, nil)
}

// newOIDCBrowserWith is [newOIDCBrowserWithPrefix] with a hook to adjust the
// OIDC configuration before the provider is created.
func newOIDCBrowserWith(t *testing.T, prefix string, configure func(*types.OIDCConfig)) *oidcBrowser {
	t.Helper()

	idp, err := mockoidc.Run()
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = idp.Shutdown()
	})

	app := createTestApp(t)

	// The provider derives its OIDC redirect_uri from the server URL, and
	// the server serves the router the provider is registered on, so bind
	// the router late to break the cycle.
	var router http.Handler

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if prefix == "" {
			router.ServeHTTP(w, r)
			return
		}

		http.StripPrefix(prefix, router).ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	publicURL := srv.URL + prefix

	cfg := &types.OIDCConfig{
		Issuer:       idp.Issuer(),
		ClientID:     idp.ClientID,
		ClientSecret: idp.ClientSecret,
		Scope:        []string{"openid", "profile", "email"},
	}
	if configure != nil {
		configure(cfg)
	}

	provider, err := NewAuthProviderOIDC(
		context.Background(),
		app,
		publicURL,
		cfg,
	)
	require.NoError(t, err)
	t.Cleanup(provider.authCache.Close)

	app.authProvider = provider
	router = app.createRouter(nil, nil)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	return &oidcBrowser{
		app:       app,
		idp:       idp,
		srv:       srv,
		publicURL: publicURL,
		client:    &http.Client{Jar: jar},
	}
}

// get fetches a URL, follows redirects, and returns the status, the URL
// the browser ended up on, and the page body.
func (b *oidcBrowser) get(t *testing.T, rawURL string) (int, *url.URL, string) {
	t.Helper()

	resp, err := b.client.Get(rawURL) //nolint:noctx,bodyclose // test client; closed below
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, resp.Request.URL, string(body)
}

// pendingNode mints a pending node registration and returns the URL the
// tailscale client would print for the user to open.
func (b *oidcBrowser) pendingNode(t *testing.T) (types.AuthID, string) {
	t.Helper()

	authID := types.MustAuthID()
	require.NoError(t, b.app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "reload-victim",
	})))

	return authID, b.publicURL + "/register/" + authID.String()
}

var (
	csrfInputRe = regexp.MustCompile(
		`name="` + registerConfirmCSRFCookie + `"[^>]*value="([^"]+)"`,
	)
	formActionRe = regexp.MustCompile(`action="([^"]+)"`)
)

// TestOIDCLoginDoesNotParkTheBrowserOnTheCodeURL reproduces
// https://github.com/juanfont/headscale/issues/3365.
//
// Before this regression was fixed, the interactive OIDC flow wrote the
// confirmation interstitial as the body of the /oidc/callback response.
// The browser was therefore parked on the URL carrying the single-use
// OAuth authorization code. Reloading it re-entered the callback, which
// had already spent the code and deleted the state cookie, and the error
// page painted over the interstitial. The node was never registered.
//
// Adblock Plus is only the loudest trigger — it calls
// window.location.reload() to apply element-hiding filters. The back
// button, mobile pull-to-refresh and browser prerendering all aim at the
// same URL.
//
// The property asserted here is the one that fixes the whole class,
// stated without naming an implementation: wherever the flow leaves the
// browser, that URL must be free of the authorization code and safe to
// load again.
func TestOIDCLoginDoesNotParkTheBrowserOnTheCodeURL(t *testing.T) {
	b := newOIDCBrowser(t)

	_, registerURL := b.pendingNode(t)

	status, landed, body := b.get(t, registerURL)
	require.Equal(t, http.StatusOK, status, "the login flow must reach a page")
	require.Contains(t, body, "Confirm node registration",
		"the flow must end on the confirmation interstitial")

	assert.Empty(t, landed.Query().Get("code"),
		"the browser must not be left parked on the URL carrying the one-time "+
			"OAuth code; any reload of it re-enters the spent callback")

	reloadedStatus, _, reloadedBody := b.get(t, landed.String())

	require.Equal(t, http.StatusOK, reloadedStatus,
		"reloading the page the flow left the browser on must re-render it")
	assert.Contains(t, reloadedBody, "Confirm node registration",
		"the reload must show the confirmation interstitial, not an error page")
}

// TestOIDCLoginCompletesAfterReload is the reporters' scenario end to
// end: the confirmation page is reloaded before the user clicks, and the
// registration must still complete. One deployment measured login
// completion falling from 100% to 61-73% across this exact step.
func TestOIDCLoginCompletesAfterReload(t *testing.T) {
	b := newOIDCBrowser(t)

	authID, registerURL := b.pendingNode(t)

	status, landed, _ := b.get(t, registerURL)
	require.Equal(t, http.StatusOK, status)

	// The spurious reload, on whatever URL the flow parked the browser on.
	reloadedStatus, reloadedURL, body := b.get(t, landed.String())
	require.Equal(t, http.StatusOK, reloadedStatus,
		"the page the user is sitting on must survive a reload")

	csrf := csrfInputRe.FindStringSubmatch(body)
	require.Len(t, csrf, 2, "the reloaded page must still carry a usable confirm form")

	action := formActionRe.FindStringSubmatch(body)
	require.Len(t, action, 2, "the reloaded page must still carry a form action")

	confirmURL, err := reloadedURL.Parse(action[1])
	require.NoError(t, err)

	//nolint:noctx,bodyclose // test client; closed below
	confirmed, err := b.client.PostForm(confirmURL.String(), url.Values{
		registerConfirmCSRFCookie: {csrf[1]},
	})
	require.NoError(t, err)

	defer confirmed.Body.Close()

	confirmedBody, err := io.ReadAll(confirmed.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, confirmed.StatusCode,
		"confirming after a reload must register the node")
	assert.Contains(t, string(confirmedBody), "Node registered",
		"the user must get the registration success page")

	_, cached := b.app.state.GetAuthCacheEntry(authID)
	assert.False(t, cached, "a completed registration must consume the auth session")
	assert.True(t, b.app.state.ListNodes().ContainsFunc(func(node types.NodeView) bool {
		return node.Hostname() == "reload-victim"
	}), "the pending node must be persisted after confirmation")
}

// TestRegisterConfirmGETIsNotADeadEnd covers the second, independent way
// a registration is lost, reported with no ad blocker involved: the
// confirmation endpoint used to be POST-only in the route table, so a
// user who refreshed or navigated back to it got a bare 405 from the
// router with no way to recover, while the pending registration sat in
// the cache unreachable until it expired.
//
// This is a route-table gap, so it can only be observed through the real
// router — calling the handler directly cannot see it.
func TestRegisterConfirmGETIsNotADeadEnd(t *testing.T) {
	b := newOIDCBrowser(t)

	authID, registerURL := b.pendingNode(t)

	// Complete the OIDC leg so there is a pending confirmation to render.
	status, _, _ := b.get(t, registerURL)
	require.Equal(t, http.StatusOK, status)

	confirmStatus, _, body := b.get(t, b.srv.URL+"/register/confirm/"+authID.String())

	require.NotEqual(t, http.StatusMethodNotAllowed, confirmStatus,
		"GET on the confirmation URL must not be a dead end for a user who "+
			"refreshes or goes back")
	require.Equal(t, http.StatusOK, confirmStatus,
		"the confirmation page must be reachable by GET")
	assert.Contains(t, body, "Confirm node registration")
}

// TestRegisterConfirmNeedsTheCallbackCookie locks the reason the
// confirmation step exists. The node being registered knows its own auth
// ID, so the auth ID alone must never be enough to view the device
// details or to finalise the registration — only the browser that
// completed the OIDC login holds the cookie the callback set, and holding
// it is what authorises the confirm.
//
// Without this, an attacker could hand a victim a /register/{auth_id}
// link for the attacker's own node, let the victim's IdP silently sign
// in, and then confirm the registration themselves under the victim's
// identity.
func TestRegisterConfirmNeedsTheCallbackCookie(t *testing.T) {
	b := newOIDCBrowser(t)

	authID, registerURL := b.pendingNode(t)

	status, _, body := b.get(t, registerURL)
	require.Equal(t, http.StatusOK, status)

	csrf := csrfInputRe.FindStringSubmatch(body)
	require.Len(t, csrf, 2)

	// A second browser that knows the auth ID, and even the token from the
	// rendered page, but never completed the OIDC login.
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	attacker := &http.Client{Jar: jar}
	confirmURL := b.srv.URL + "/register/confirm/" + authID.String()

	//nolint:noctx,bodyclose // test client; closed below
	viewed, err := attacker.Get(confirmURL)
	require.NoError(t, err)

	defer viewed.Body.Close()

	assert.Equal(t, http.StatusForbidden, viewed.StatusCode,
		"the confirmation page must not render without the callback cookie")

	//nolint:noctx,bodyclose // test client; closed below
	submitted, err := attacker.PostForm(confirmURL, url.Values{
		registerConfirmCSRFCookie: {csrf[1]},
	})
	require.NoError(t, err)

	defer submitted.Body.Close()

	assert.Equal(t, http.StatusForbidden, submitted.StatusCode,
		"the registration must not finalise without the callback cookie")

	cached, ok := b.app.state.GetAuthCacheEntry(authID)
	require.True(t, ok, "the pending registration must survive the attempt")
	assert.NotNil(t, cached.PendingConfirmation(),
		"the pending registration must still be waiting for the real user")
}

// TestSetRegisterConfirmCookieSameSite pins SameSite=Lax. Strict is
// withheld by browsers that evaluate the whole redirect chain, and this
// cookie now has to survive the callback's redirect to the confirmation
// page — a chain that begins cross-site at the identity provider. Lax is
// still never attached to a cross-site POST, so the confirm submission
// keeps its protection.
func TestSetRegisterConfirmCookieSameSite(t *testing.T) {
	a := &AuthProviderOIDC{serverURL: "https://hs.example.com"}
	authID := types.MustAuthID()

	rec := httptest.NewRecorder()
	a.setRegisterConfirmCookie(rec,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback", nil),
		authID, "token", 900)

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite,
		"the confirm cookie must survive the callback redirect")
	assert.True(t, cookies[0].Secure, "https server_url must set Secure")
	assert.Equal(t, "/register/confirm/"+authID.String(), cookies[0].Path)
}

// TestRegisterConfirmURLFollowsServerURLPrefix covers the deployment
// where a reverse proxy serves Headscale under a path prefix. The
// redirect target, the form action and the cookie scope are all seen by
// the browser, so they carry the prefix even though the routed path does
// not.
func TestRegisterConfirmURLFollowsServerURLPrefix(t *testing.T) {
	b := newOIDCBrowserWithPrefix(t, "/hs")
	authID, registerURL := b.pendingNode(t)

	status, landed, body := b.get(t, registerURL)
	require.Equal(t, http.StatusOK, status,
		"the prefixed callback must receive its state and nonce cookies")
	assert.Equal(t, "/hs/register/confirm/"+authID.String(), landed.Path)
	assert.Contains(t, body, "Confirm node registration")
}

func TestRouterMethodNotAllowedIncludesAllow(t *testing.T) {
	b := newOIDCBrowser(t)

	//nolint:noctx,bodyclose // test client; closed below
	resp, err := b.client.PostForm(b.srv.URL+"/health", nil)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, []string{http.MethodGet}, resp.Header.Values("Allow"))
}

type oidcUserWithInfo struct {
	mockoidc.MockUser

	info types.OIDCUserInfo
}

func (u *oidcUserWithInfo) Userinfo(_ []string) ([]byte, error) {
	return json.Marshal(u.info)
}

func TestOIDCEmailClaims(t *testing.T) {
	for _, tt := range []struct {
		name          string
		tokenEmail    string
		tokenVerified bool
		infoEmail     string
		infoVerified  bool
		wantStatus    int
	}{
		{"different address", "guest@other.example", true, "boss@corp.example", false, http.StatusUnauthorized},
		{"flag without address", "boss@corp.example", false, "", true, http.StatusUnauthorized},
		{"same address token flag", "boss@corp.example", true, "boss@corp.example", false, http.StatusOK},
		{"same address userinfo flag", "boss@corp.example", false, "boss@corp.example", true, http.StatusOK},
		{"no userinfo email", "boss@corp.example", true, "", false, http.StatusOK},
		{"different verified address", "guest@other.example", false, "boss@corp.example", true, http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := newOIDCBrowser(t)
			provider, ok := b.app.authProvider.(*AuthProviderOIDC)
			require.True(t, ok)

			provider.cfg.EmailVerifiedRequired = true
			provider.cfg.AllowedDomains = []string{"corp.example"}

			b.idp.QueueUser(&oidcUserWithInfo{
				Subject:       "email-pair",
				Email:         tt.tokenEmail,
				EmailVerified: tt.tokenVerified,
				info: types.OIDCUserInfo{
					Sub:           "email-pair",
					Email:         tt.infoEmail,
					EmailVerified: types.FlexibleBoolean(tt.infoVerified),
				},
			})
			_, registerURL := b.pendingNode(t)
			status, _, _ := b.get(t, registerURL)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}

func TestMergeEmailClaims(t *testing.T) {
	for _, tt := range []struct {
		name     string
		token    types.OIDCClaims
		info     types.OIDCUserInfo
		email    string
		verified types.FlexibleBoolean
	}{
		{"different address", types.OIDCClaims{Email: "old@example.com", EmailVerified: true}, types.OIDCUserInfo{Email: "new@example.com"}, "new@example.com", false},
		{"flag without address", types.OIDCClaims{Email: "old@example.com"}, types.OIDCUserInfo{EmailVerified: true}, "old@example.com", false},
		{"same address token flag", types.OIDCClaims{Email: "same@example.com", EmailVerified: true}, types.OIDCUserInfo{Email: "same@example.com"}, "same@example.com", true},
		{"same address userinfo flag", types.OIDCClaims{Email: "same@example.com"}, types.OIDCUserInfo{Email: "same@example.com", EmailVerified: true}, "same@example.com", true},
		{"no userinfo email", types.OIDCClaims{Email: "old@example.com", EmailVerified: true}, types.OIDCUserInfo{}, "old@example.com", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			email, verified := mergeEmailClaims(&tt.token, &tt.info)
			assert.Equal(t, tt.email, email)
			assert.Equal(t, tt.verified, verified)
		})
	}
}

func TestOIDCRegistrationRejectsOversizedMergedHostinfo(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("oidc-report-user")
	node := app.state.CreateNodeForTest(user, "oidc-report-node")
	node.Hostinfo = &tailcfg.Hostinfo{Hostname: node.Hostname, OSVersion: "v"}
	encoded, err := json.Marshal(node.Hostinfo)
	require.NoError(t, err)

	node.Hostinfo.OSVersion = strings.Repeat("v", types.MaxHostinfoSize-len(encoded))
	require.NoError(t, types.ValidateHostinfo(node.Hostinfo))
	before := app.state.PutNodeInStoreForTest(*node)

	hostname := strings.Repeat("h", types.MaxHostnameLength)
	authID := types.MustAuthID()
	require.NoError(t, app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: node.MachineKey, NodeKey: key.NewNode().Public(),
		Hostname: hostname, Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	})))

	provider := &AuthProviderOIDC{h: app}
	changed, err := provider.handleRegistration(user, authID, nil)
	require.ErrorIs(t, err, types.ErrHostinfoTooLarge)

	var httpErr HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
	assert.Contains(t, strings.ToLower(httpErr.UserMsg), "reduce")
	assert.Contains(t, httpErr.UserMsg, "metadata")
	assert.Contains(t, httpErr.UserMsg, "sign")
	assert.False(t, changed)

	after, ok := app.state.GetNodeByID(node.ID)
	require.True(t, ok)
	assert.Equal(t, before.NodeKey(), after.NodeKey())
	assert.Equal(t, before.Hostname(), after.Hostname())
	assert.True(t, before.Hostinfo().AsStruct().Equal(after.Hostinfo().AsStruct()))
}
