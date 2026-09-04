package hscontrol

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	a.setCSRFCookie(w, r, "state")

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
	secureProvider.setCSRFCookie(secureRec, r, "state")
	require.Len(t, secureRec.Result().Cookies(), 1)
	assert.True(t, secureRec.Result().Cookies()[0].Secure,
		"https server_url must set Secure even when req.TLS is nil (proxy case)")

	plainRec := httptest.NewRecorder()
	plainProvider := &AuthProviderOIDC{serverURL: "http://hs.example.com"}
	plainProvider.setCSRFCookie(plainRec, r, "state")
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

	provider, err := NewAuthProviderOIDC(
		context.Background(),
		app,
		publicURL,
		&types.OIDCConfig{
			Issuer:       idp.Issuer(),
			ClientID:     idp.ClientID,
			ClientSecret: idp.ClientSecret,
			Scope:        []string{"openid", "profile", "email"},
		},
	)
	require.NoError(t, err)

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
	b.app.state.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "reload-victim",
	}))

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
