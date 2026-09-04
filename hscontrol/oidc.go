package hscontrol

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"tailscale.com/util/rands"
)

const (
	randomByteSize           = 16
	defaultOAuthOptionsCount = 3
	authCacheExpiration      = time.Minute * 15

	// authCacheMaxEntries bounds each OIDC state pool so active callback state
	// has a predictable footprint.
	authCacheMaxEntries = 1024

	// cookieNamePrefixLen is the number of leading characters from a
	// state/nonce value that [getCookieName] splices into the cookie name.
	// State and nonce values that are shorter than this are rejected at
	// the callback boundary so [getCookieName] cannot panic on a slice
	// out-of-range.
	cookieNamePrefixLen = 6
)

var errOIDCStateTooShort = errors.New("oidc state parameter is too short")

var (
	errOIDCStateCapacity    = errors.New("pending OIDC authentication capacity reached")
	errOIDCStateExists      = errors.New("OIDC authentication already started")
	errOIDCAuthTypeMismatch = errors.New("OIDC authentication request type does not match route")
)

var (
	errEmptyOIDCCallbackParams = errors.New("empty OIDC callback params")
	errNoOIDCIDToken           = errors.New("extracting ID token")
	errOIDCAllowedDomains      = errors.New(
		"authenticated principal does not match any allowed domain",
	)
	errOIDCAllowedGroups = errors.New("authenticated principal is not in any allowed group")
	errOIDCAllowedUsers  = errors.New(
		"authenticated principal does not match any allowed user",
	)
	errOIDCUnverifiedEmail = errors.New("authenticated principal has an unverified email")
	errInvalidPKCEMethod   = errors.New("invalid pkce.method")
)

// AuthInfo contains both auth ID and verifier information for OIDC validation.
type AuthInfo struct {
	AuthID       types.AuthID
	Verifier     *string
	Registration bool
}

type oidcAuthState struct {
	state        string
	registration bool
}

type AuthProviderOIDC struct {
	h         *Headscale
	serverURL string
	cfg       *types.OIDCConfig

	// Registration and SSH state have independent capacity so one request class
	// cannot displace active sessions from the other.
	authCache            *expirable.LRU[string, AuthInfo]
	sshAuthCache         *expirable.LRU[string, AuthInfo]
	authCacheMaxEntries  int
	authCacheMu          sync.Mutex
	authStateByRequestID map[types.AuthID]oidcAuthState

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(
	ctx context.Context,
	h *Headscale,
	serverURL string,
	cfg *types.OIDCConfig,
) (*AuthProviderOIDC, error) {
	// Use the caller's context (bounded, see app.go) so a slow or unreachable
	// issuer fails discovery within the timeout instead of hanging startup.
	oidcProvider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider from issuer config: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  oidcCallbackURL(serverURL),
		Scopes:       cfg.Scope,
	}

	authCache := expirable.NewLRU[string, AuthInfo](
		0,
		nil,
		authCacheExpiration,
	)
	sshAuthCache := expirable.NewLRU[string, AuthInfo](
		0,
		nil,
		authCacheExpiration,
	)

	return &AuthProviderOIDC{
		h:                    h,
		serverURL:            serverURL,
		cfg:                  cfg,
		authCache:            authCache,
		sshAuthCache:         sshAuthCache,
		authCacheMaxEntries:  authCacheMaxEntries,
		authStateByRequestID: make(map[types.AuthID]oidcAuthState),

		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
	}, nil
}

// cookiesSecure reports whether the OIDC cookies should carry the Secure flag.
// It keys off the configured server_url scheme, not req.TLS, so cookies stay
// Secure behind a TLS-terminating reverse proxy (where the proxy→Headscale hop
// is plain HTTP and req.TLS is nil). Deriving it from config avoids trusting a
// spoofable X-Forwarded-Proto header.
func (a *AuthProviderOIDC) cookiesSecure() bool {
	return strings.HasPrefix(a.serverURL, "https://")
}

func oidcCallbackURL(serverURL string) string {
	return strings.TrimSuffix(serverURL, "/") + "/oidc/callback"
}

func (a *AuthProviderOIDC) oidcCallbackPath() string {
	if u, err := url.Parse(oidcCallbackURL(a.serverURL)); err == nil { //nolint:noinlineerr
		return u.Path
	}

	return "/oidc/callback"
}

func (a *AuthProviderOIDC) AuthURL(authID types.AuthID) string {
	return authPathURL(a.serverURL, "auth", authID)
}

func (a *AuthProviderOIDC) AuthHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	a.authHandler(writer, req, false)
}

func (a *AuthProviderOIDC) RegisterURL(authID types.AuthID) string {
	return authPathURL(a.serverURL, "register", authID)
}

// RegisterHandler registers the OIDC callback handler with the given router.
// It puts NodeKey in cache so the callback can retrieve it using the oidc state param.
// Listens in /register/:auth_id.
func (a *AuthProviderOIDC) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	a.authHandler(writer, req, true)
}

// authHandler takes an incoming request that needs to be authenticated and
// validates and prepares it for the OIDC flow.
func (a *AuthProviderOIDC) authHandler(
	writer http.ResponseWriter,
	req *http.Request,
	registration bool,
) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	err = a.validateOIDCAuthRequest(authID, registration)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	state := rands.HexString(64)
	nonce := rands.HexString(64)

	registrationInfo := AuthInfo{
		AuthID:       authID,
		Registration: registration,
	}

	extras := make([]oauth2.AuthCodeOption, 0, len(a.cfg.ExtraParams)+defaultOAuthOptionsCount)
	// Add PKCE verification if enabled
	if a.cfg.PKCE.Enabled {
		verifier := oauth2.GenerateVerifier()
		registrationInfo.Verifier = &verifier

		extras = append(extras, oauth2.AccessTypeOffline)

		switch a.cfg.PKCE.Method {
		case types.PKCEMethodS256:
			extras = append(extras, oauth2.S256ChallengeOption(verifier))
		case types.PKCEMethodPlain:
			// oauth2 does not have a plain challenge option, so we add it manually
			extras = append(extras, oauth2.SetAuthURLParam("code_challenge_method", "plain"), oauth2.SetAuthURLParam("code_challenge", verifier))
		default:
			// An unknown method must not silently emit no challenge: a
			// verifier was generated and is sent at token exchange, so a
			// missing challenge degrades to no-PKCE without anyone noticing.
			httpError(writer, NewHTTPError(http.StatusInternalServerError, "internal server error", fmt.Errorf("%w: %q", errInvalidPKCEMethod, a.cfg.PKCE.Method)))
			return
		}
	}

	// Add any extra parameters from configuration
	for k, v := range a.cfg.ExtraParams {
		extras = append(extras, oauth2.SetAuthURLParam(k, v))
	}

	extras = append(extras, oidc.Nonce(nonce))

	// Cache the registration info before redirecting. Admission refusal leaves
	// every active callback state available.
	err = a.addOIDCAuthState(state, registrationInfo)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	a.setCSRFCookieValue(writer, req, "state", state)
	a.setCSRFCookieValue(writer, req, "nonce", nonce)

	authURL := a.oauth2Config.AuthCodeURL(state, extras...)
	log.Debug().Caller().Msgf("redirecting to %s for authentication", authURL)

	http.Redirect(writer, req, authURL, http.StatusFound)
}

func (a *AuthProviderOIDC) validateOIDCAuthRequest(
	authID types.AuthID,
	registration bool,
) error {
	authRequest, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		return NewHTTPError(http.StatusNotFound, "authentication request not found", ErrNoAuthSession)
	}

	if _, complete := authRequest.AuthResult(); complete {
		return NewHTTPError(http.StatusGone, "authentication request already completed", nil)
	}

	if authRequest.PendingConfirmation() != nil {
		return NewHTTPError(http.StatusConflict, "authentication confirmation already pending", errOIDCStateExists)
	}

	typeMatches := registration && authRequest.IsRegistration() ||
		!registration && authRequest.IsSSHCheck()
	if !typeMatches {
		return NewHTTPError(http.StatusBadRequest, "authentication request type does not match route", errOIDCAuthTypeMismatch)
	}

	return nil
}

func (a *AuthProviderOIDC) claimOIDCAuthRequest(
	authInfo AuthInfo,
) (*types.AuthRequest, error) {
	authRequest, ok := a.h.state.GetAuthCacheEntry(authInfo.AuthID)
	if !ok {
		return nil, NewHTTPError(http.StatusGone, "authentication request expired", ErrNoAuthSession)
	}

	typeMatches := authInfo.Registration && authRequest.IsRegistration() ||
		!authInfo.Registration && authRequest.IsSSHCheck()
	if !typeMatches {
		return nil, NewHTTPError(http.StatusBadRequest, "authentication request type changed", errOIDCAuthTypeMismatch)
	}

	if !authRequest.TryBeginAuth() {
		return nil, NewHTTPError(http.StatusGone, "authentication request already completed", nil)
	}

	return authRequest, nil
}

func (a *AuthProviderOIDC) addOIDCAuthState(state string, info AuthInfo) error {
	a.authCacheMu.Lock()
	defer a.authCacheMu.Unlock()

	a.pruneExpiredOIDCAuthStatesLocked()

	if _, exists := a.authStateByRequestID[info.AuthID]; exists {
		return NewHTTPError(http.StatusConflict, "authentication already started", errOIDCStateExists)
	}

	if _, exists := a.peekOIDCAuthStateLocked(state); exists {
		return NewHTTPError(http.StatusConflict, "authentication state already exists", errOIDCStateExists)
	}

	cache := a.oidcAuthStateCache(info.Registration)
	if cache.Len() >= a.authCacheMaxEntries {
		return NewHTTPError(
			http.StatusServiceUnavailable,
			"too many pending authentication requests; try again later",
			errOIDCStateCapacity,
		)
	}

	cache.Add(state, info)
	a.authStateByRequestID[info.AuthID] = oidcAuthState{
		state:        state,
		registration: info.Registration,
	}

	return nil
}

func (a *AuthProviderOIDC) peekOIDCAuthState(state string) (AuthInfo, bool) {
	a.authCacheMu.Lock()
	defer a.authCacheMu.Unlock()

	return a.peekOIDCAuthStateLocked(state)
}

func (a *AuthProviderOIDC) peekOIDCAuthStateLocked(state string) (AuthInfo, bool) {
	if info, ok := a.authCache.Peek(state); ok {
		return info, true
	}

	if a.sshAuthCache != nil {
		return a.sshAuthCache.Peek(state)
	}

	return AuthInfo{}, false
}

func (a *AuthProviderOIDC) takeOIDCAuthState(state string) (AuthInfo, bool) {
	a.authCacheMu.Lock()
	defer a.authCacheMu.Unlock()

	info, ok := a.authCache.Peek(state)

	cache := a.authCache
	if !ok && a.sshAuthCache != nil {
		info, ok = a.sshAuthCache.Peek(state)
		cache = a.sshAuthCache
	}

	if !ok || !cache.Remove(state) {
		return AuthInfo{}, false
	}

	if ref, exists := a.authStateByRequestID[info.AuthID]; exists && ref.state == state {
		ref.state = ""
		a.authStateByRequestID[info.AuthID] = ref
	}

	return info, true
}

func (a *AuthProviderOIDC) pruneExpiredOIDCAuthStatesLocked() {
	for authID, ref := range a.authStateByRequestID {
		if a.h != nil {
			authRequest, ok := a.h.state.GetAuthCacheEntry(authID)
			typeMatches := ok && (ref.registration && authRequest.IsRegistration() ||
				!ref.registration && authRequest.IsSSHCheck())

			complete := false
			if ok {
				_, complete = authRequest.AuthResult()
			}

			if !typeMatches || complete {
				if ref.state != "" {
					a.oidcAuthStateCache(ref.registration).Remove(ref.state)
				}

				delete(a.authStateByRequestID, authID)

				continue
			}
		}

		if ref.state == "" {
			continue
		}

		cache := a.oidcAuthStateCache(ref.registration)
		if _, ok := cache.Peek(ref.state); ok {
			continue
		}

		cache.Remove(ref.state)
		delete(a.authStateByRequestID, authID)
	}
}

func (a *AuthProviderOIDC) releaseOIDCAuthReservation(authID types.AuthID) {
	a.authCacheMu.Lock()
	defer a.authCacheMu.Unlock()

	delete(a.authStateByRequestID, authID)
}

func (a *AuthProviderOIDC) oidcAuthStateCache(
	registration bool,
) *expirable.LRU[string, AuthInfo] {
	if registration {
		return a.authCache
	}

	return a.sshAuthCache
}

// OIDCCallbackHandler handles the callback from the OIDC endpoint
// Retrieves the nkey from the state cache and adds the node to the users email user
// TODO: A confirmation page for new nodes should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into node HostInfo
// Listens in /oidc/callback.
//
//nolint:gocyclo // callback validation stages share reservation cleanup state
func (a *AuthProviderOIDC) OIDCCallbackHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, err := extractCodeAndStateParamFromRequest(req)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	stateCookieName := getCookieName("state", state)

	cookieState, err := req.Cookie(stateCookieName)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "state not found", err))
		return
	}

	if state != cookieState.Value {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "state did not match", nil))
		return
	}

	authInfo := a.getAuthInfoFromState(state)
	if authInfo == nil {
		log.Debug().Caller().Str("state", state).Msg("state not found in cache, login session may have expired")
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	releaseReservation := true
	defer func() {
		if releaseReservation {
			a.releaseOIDCAuthReservation(authInfo.AuthID)
		}
	}()

	authReq, err := a.claimOIDCAuthRequest(*authInfo)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	authClaimed := true
	defer func() {
		if authClaimed {
			authReq.AbortAuth()
		}
	}()

	oauth2Token, err := a.getOauth2Token(req.Context(), code, *authInfo)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	idToken, err := a.extractIDToken(req.Context(), oauth2Token)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	if idToken.Nonce == "" {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "nonce not found in IDToken", err))
		return
	}

	nonceCookieName := getCookieName("nonce", idToken.Nonce)

	nonce, err := req.Cookie(nonceCookieName)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "nonce not found", err))
		return
	}

	if idToken.Nonce != nonce.Value {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "nonce did not match", nil))
		return
	}

	// The state/nonce cookies have served their CSRF purpose; clear them so a
	// single-use pair does not linger in the browser until MaxAge.
	a.clearOIDCCallbackCookie(writer, stateCookieName)
	a.clearOIDCCallbackCookie(writer, nonceCookieName)

	nodeExpiry := a.determineNodeExpiry(idToken.Expiry)

	var claims types.OIDCClaims
	if err := idToken.Claims(&claims); err != nil { //nolint:noinlineerr
		httpUserError(writer, fmt.Errorf("decoding ID token claims: %w", err))
		return
	}

	// Fetch user information (email, groups, name, etc) from the userinfo endpoint
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	var userinfo *oidc.UserInfo

	userinfo, err = a.oidcProvider.UserInfo(req.Context(), oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		util.LogErr(err, "could not get userinfo; only using claims from id token")
	}

	// The [oidc.UserInfo] type only decodes some fields (Subject, Profile, Email, EmailVerified).
	// We are interested in other fields too (e.g. groups are required for allowedGroups) so we
	// decode into our own [types.OIDCUserInfo] type using the underlying claims struct.
	var userinfo2 types.OIDCUserInfo
	if userinfo != nil && userinfo.Claims(&userinfo2) == nil && userinfo2.Sub == claims.Sub {
		// Update the user with the userinfo claims (with id token claims as fallback).
		// TODO(kradalby): there might be more interesting fields here that we have not found yet.
		claims.Email = cmp.Or(userinfo2.Email, claims.Email)
		claims.EmailVerified = cmp.Or(userinfo2.EmailVerified, claims.EmailVerified)
		claims.Username = cmp.Or(userinfo2.PreferredUsername, claims.Username)
		claims.Name = cmp.Or(userinfo2.Name, claims.Name)

		claims.ProfilePictureURL = cmp.Or(userinfo2.Picture, claims.ProfilePictureURL)
		if userinfo2.Groups != nil {
			claims.Groups = userinfo2.Groups
		}
	}

	// The user claims are now updated from the userinfo endpoint so we can verify the user
	// against allowed emails, email domains, and groups.
	err = doOIDCAuthorization(a.cfg, &claims)
	if err != nil {
		httpUserError(writer, err)
		return
	}

	user, _, err := a.createOrUpdateUserFromClaim(&claims)
	if err != nil {
		httpUserError(writer, NewHTTPError(
			http.StatusInternalServerError,
			"could not create or update user",
			err,
		))

		return
	}

	// If this is a registration flow, render the confirmation
	// interstitial instead of finalising the registration immediately.
	// Without an explicit user click, a single GET to
	// /register/{auth_id} could silently complete a registration when
	// the IdP allows silent SSO.
	if authInfo.Registration {
		err = a.beginRegistrationConfirmation(
			writer,
			req,
			authInfo.AuthID,
			authReq,
			user,
			nodeExpiry,
		)
		if err != nil {
			httpUserError(writer, err)

			return
		}

		authReq.AbortAuth()

		authClaimed = false
		releaseReservation = false

		return
	}

	// If this is not a registration callback, then it is an SSH
	// check-mode auth callback. Confirm the OIDC identity is the owner
	// of the SSH source node before recording approval; without this
	// check any tailnet user could approve a check-mode prompt for any
	// other user's node, defeating the stolen-key protection that
	// check-mode is meant to provide.

	binding := authReq.SSHCheckBinding()

	srcNode, ok := a.h.state.GetNodeByID(binding.SrcNodeID)
	if !ok {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Uint64("src_node_id", binding.SrcNodeID.Uint64()).
			Msg("SSH check src node no longer exists")
		httpUserError(writer, NewHTTPError(http.StatusGone, "src node no longer exists", nil))

		return
	}

	// Strict identity binding: only the user that owns the src node
	// may approve an SSH check for that node. Tagged source nodes are
	// rejected because they have no user owner to compare against.
	if srcNode.IsTagged() || !srcNode.UserID().Valid() {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Uint64("src_node_id", binding.SrcNodeID.Uint64()).
			Bool("src_is_tagged", srcNode.IsTagged()).
			Str("oidc_user", user.Username()).
			Msg("SSH check rejected: src node has no user owner")
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "src node has no user owner", nil))

		return
	}

	if srcNode.UserID().Get() != user.ID {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Uint64("src_node_id", binding.SrcNodeID.Uint64()).
			Uint("src_owner_id", srcNode.UserID().Get()).
			Uint("oidc_user_id", user.ID).
			Str("oidc_user", user.Username()).
			Msg("SSH check rejected: OIDC user is not the owner of src node")
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "OIDC user is not the owner of the SSH source node", nil))

		return
	}

	currentAuthReq, ok := a.h.state.GetAuthCacheEntry(authInfo.AuthID)
	if !ok || currentAuthReq != authReq || !authReq.FinishClaimedAuth(types.AuthVerdict{}) {
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	authClaimed = false

	content := renderAuthSuccessTemplate(user)

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if _, err := writer.Write(content.Bytes()); err != nil { //nolint:noinlineerr
		util.LogErr(err, "Failed to write HTTP response")
	}
}

func (a *AuthProviderOIDC) determineNodeExpiry(idTokenExpiration time.Time) *time.Time {
	if a.cfg.UseExpiryFromToken {
		return &idTokenExpiration
	}

	return nil
}

func extractCodeAndStateParamFromRequest(
	req *http.Request,
) (string, string, error) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" || state == "" {
		return "", "", NewHTTPError(http.StatusBadRequest, "missing code or state parameter", errEmptyOIDCCallbackParams)
	}

	// Reject states that are too short for [getCookieName] to splice
	// into a cookie name. Without this guard a request with
	// ?state=abc panics on the slice out-of-range and is recovered by
	// chi's [middleware.Recoverer], amplifying small-DoS log noise.
	if len(state) < cookieNamePrefixLen {
		return "", "", NewHTTPError(http.StatusBadRequest, "invalid state parameter", errOIDCStateTooShort)
	}

	return code, state, nil
}

// getOauth2Token exchanges the code from the callback for an oauth2 token.
func (a *AuthProviderOIDC) getOauth2Token(
	ctx context.Context,
	code string,
	authInfo AuthInfo,
) (*oauth2.Token, error) {
	var exchangeOpts []oauth2.AuthCodeOption

	if a.cfg.PKCE.Enabled && authInfo.Verifier != nil {
		exchangeOpts = []oauth2.AuthCodeOption{oauth2.VerifierOption(*authInfo.Verifier)}
	}

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "invalid code", fmt.Errorf("exchanging code for token: %w", err))
	}

	return oauth2Token, nil
}

// extractIDToken extracts the ID token from the oauth2 token.
func (a *AuthProviderOIDC) extractIDToken(
	ctx context.Context,
	oauth2Token *oauth2.Token,
) (*oidc.IDToken, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, NewHTTPError(http.StatusBadRequest, "no id_token", errNoOIDCIDToken)
	}

	verifier := a.oidcProvider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "failed to verify id_token", fmt.Errorf("verifying ID token: %w", err))
	}

	return idToken, nil
}

// validateOIDCAllowedDomains checks that if AllowedDomains is provided,
// that the authenticated principal ends with @<alloweddomain>.
func validateOIDCAllowedDomains(
	allowedDomains []string,
	claims *types.OIDCClaims,
) error {
	if len(allowedDomains) > 0 {
		if _, domain, found := strings.CutLast(claims.Email, "@"); !found ||
			!slices.Contains(allowedDomains, domain) {
			return NewHTTPError(http.StatusUnauthorized, "unauthorised domain", errOIDCAllowedDomains)
		}
	}

	return nil
}

// validateOIDCAllowedGroups checks if AllowedGroups is provided,
// and that the user has one group in the list.
// claims.Groups can be populated by adding a client scope named
// 'groups' that contains group membership.
func validateOIDCAllowedGroups(
	allowedGroups []string,
	claims *types.OIDCClaims,
) error {
	for _, group := range allowedGroups {
		if slices.Contains(claims.Groups, group) {
			return nil
		}
	}

	return NewHTTPError(http.StatusUnauthorized, "unauthorised group", errOIDCAllowedGroups)
}

// validateOIDCAllowedUsers checks that if AllowedUsers is provided,
// that the authenticated principal is part of that list.
func validateOIDCAllowedUsers(
	allowedUsers []string,
	claims *types.OIDCClaims,
) error {
	if !slices.Contains(allowedUsers, claims.Email) {
		return NewHTTPError(http.StatusUnauthorized, "unauthorised user", errOIDCAllowedUsers)
	}

	return nil
}

// doOIDCAuthorization applies authorization tests to claims.
//
// The following tests are always applied:
//
// - [validateOIDCAllowedGroups]
//
// The following tests are applied if cfg.EmailVerifiedRequired=false
// or claims.email_verified=true:
//
// - [validateOIDCAllowedDomains]
// - [validateOIDCAllowedUsers]
//
// NOTE that, contrary to the function name, [validateOIDCAllowedUsers]
// only checks the email address -- not the username.
func doOIDCAuthorization(
	cfg *types.OIDCConfig,
	claims *types.OIDCClaims,
) error {
	if len(cfg.AllowedGroups) > 0 {
		err := validateOIDCAllowedGroups(cfg.AllowedGroups, claims)
		if err != nil {
			return err
		}
	}

	trustEmail := !cfg.EmailVerifiedRequired || bool(claims.EmailVerified)

	hasEmailTests := len(cfg.AllowedDomains) > 0 || len(cfg.AllowedUsers) > 0
	if !trustEmail && hasEmailTests {
		return NewHTTPError(http.StatusUnauthorized, "unverified email", errOIDCUnverifiedEmail)
	}

	if len(cfg.AllowedDomains) > 0 {
		err := validateOIDCAllowedDomains(cfg.AllowedDomains, claims)
		if err != nil {
			return err
		}
	}

	if len(cfg.AllowedUsers) > 0 {
		err := validateOIDCAllowedUsers(cfg.AllowedUsers, claims)
		if err != nil {
			return err
		}
	}

	return nil
}

// getAuthInfoFromState retrieves and consumes the auth info for a state. The
// entry is removed on read so a state is single-use: a replayed callback cannot
// resolve the same auth session twice, even within the cache TTL.
func (a *AuthProviderOIDC) getAuthInfoFromState(state string) *AuthInfo {
	authInfo, ok := a.takeOIDCAuthState(state)
	if !ok {
		return nil
	}

	return &authInfo
}

func (a *AuthProviderOIDC) createOrUpdateUserFromClaim(
	claims *types.OIDCClaims,
) (*types.User, change.Change, error) {
	var (
		user    *types.User
		err     error
		newUser bool
		c       change.Change
	)

	user, err = a.h.state.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, change.Change{}, fmt.Errorf("creating or updating user: %w", err)
	}

	// if the user is still not found, create a new empty user.
	// TODO(kradalby): This context is not inherited from the request, which is probably not ideal.
	// However, we need a context to use the OIDC provider.
	if user == nil {
		newUser = true
		user = &types.User{}
	}

	user.FromClaim(claims, a.cfg.EmailVerifiedRequired)

	if newUser {
		user, c, err = a.h.state.CreateUser(*user)
		if err != nil {
			return nil, change.Change{}, fmt.Errorf("creating user: %w", err)
		}
	} else {
		_, c, err = a.h.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
			*u = *user
			return nil
		})
		if err != nil {
			return nil, change.Change{}, fmt.Errorf("updating user: %w", err)
		}
	}

	return user, c, nil
}

// registerConfirmCSRFCookie is the cookie name used to bind the
// /register/confirm POST handler's CSRF token to the OIDC callback that
// rendered the interstitial. It includes a per-session prefix derived
// from the auth ID so cookies for unrelated registrations on the same
// browser do not collide.
const registerConfirmCSRFCookie = "headscale_register_confirm"

// registrationLinkSpentMsg is logged when a user returns to a
// registration link whose session is gone, which is usually a reload or a
// back button after they already confirmed. The page the user sees comes
// from [userMessageForStatusCode].
const registrationLinkSpentMsg = "registration link already used or expired"

const registrationLinkSpentUserMsg = "This link has already been used or has expired. " +
	"If your device is connected you are done; otherwise start the login again."

var errRegistrationLinkSpent = newHTTPUserError(
	http.StatusGone,
	registrationLinkSpentMsg,
	registrationLinkSpentUserMsg,
	nil,
)

// registerConfirmURL is the browser-facing URL of the confirmation page.
// It is built from server_url, like [AuthProviderOIDC.RegisterURL] and the
// OIDC redirect URI, so a Headscale that a reverse proxy serves under a
// path prefix hands the browser a URL that resolves.
func (a *AuthProviderOIDC) registerConfirmURL(authID types.AuthID) string {
	return authPathURL(a.serverURL, "register/confirm", authID)
}

// setRegisterConfirmCookie writes the per-session register-confirm CSRF
// cookie. Pass the CSRF token and authCacheExpiration seconds to set it;
// pass ("", -1) to clear it after the registration is finalised.
func (a *AuthProviderOIDC) setRegisterConfirmCookie(
	writer http.ResponseWriter,
	req *http.Request,
	authID types.AuthID,
	value string,
	maxAge int,
) {
	// Scope the cookie to the browser-facing path, which carries the
	// reverse proxy's prefix; the routed path does not.
	path := "/register/confirm/" + authID.String()
	if u, err := url.Parse(a.registerConfirmURL(authID)); err == nil { //nolint:noinlineerr
		path = u.Path
	}

	//nolint:gosec // G124: Secure from server_url scheme or req.TLS; HttpOnly + SameSite already set
	http.SetCookie(writer, &http.Cookie{
		Name:     registerConfirmCSRFCookie,
		Value:    value,
		Path:     path,
		MaxAge:   maxAge,
		Secure:   a.cookiesSecure() || req.TLS != nil,
		HttpOnly: true,
		// Lax, not Strict: the callback sets this cookie and immediately
		// redirects to the confirmation page. That hop ends a redirect
		// chain which began cross-site at the IdP, and Firefox evaluates
		// the whole chain, so a Strict cookie is withheld and the
		// confirmation page 403s. Lax still never rides a cross-site
		// POST, so the confirm submission stays protected.
		SameSite: http.SameSiteLaxMode,
	})
}

// beginRegistrationConfirmation captures the resolved OIDC identity and
// node expiry into the cached [types.AuthRequest], sets the CSRF cookie, and
// redirects the browser to the confirmation page.
//
// The interstitial is served from its own URL rather than written inline
// here, because this request carries the single-use OAuth authorization
// code. A page rendered on this response leaves the browser parked on the
// code-bearing URL, and anything that reloads it — an extension calling
// window.location.reload(), the back button, pull-to-refresh, a prerender
// — re-enters the callback with a spent code and paints an error over the
// interstitial. Redirecting keeps the code exchange one-shot and makes the
// page the user waits on safe to reload.
func (a *AuthProviderOIDC) beginRegistrationConfirmation(
	writer http.ResponseWriter,
	req *http.Request,
	authID types.AuthID,
	authReq *types.AuthRequest,
	user *types.User,
	nodeExpiry *time.Time,
) error {
	currentAuthReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok || currentAuthReq != authReq {
		log.Debug().Caller().Str("auth_id", authID.String()).Msg("registration session expired before authorization completed")

		return NewHTTPError(http.StatusGone, "login session expired, try again", nil)
	}

	if !authReq.IsRegistration() {
		log.Warn().Caller().
			Str("auth_id", authID.String()).
			Msg("OIDC callback hit registration path with auth request that is not a node registration")

		return NewHTTPError(http.StatusBadRequest, "auth session is not for node registration", nil)
	}

	csrf := rands.HexString(32)

	if !authReq.SetPendingConfirmation(&types.PendingRegistrationConfirmation{
		UserID:     user.ID,
		NodeExpiry: nodeExpiry,
		CSRF:       csrf,
	}) {
		return NewHTTPError(http.StatusConflict, "registration confirmation already pending", errOIDCStateExists)
	}

	a.setRegisterConfirmCookie(writer, req, authID, csrf, int(authCacheExpiration.Seconds()))

	// 303 See Other so the browser issues a fresh GET for the
	// confirmation page and leaves the code-bearing URL behind as a
	// transient hop rather than a history entry it can return to.
	http.Redirect(writer, req, a.registerConfirmURL(authID), http.StatusSeeOther)

	return nil
}

// RegisterConfirmGetHandler renders the OIDC registration confirmation
// interstitial. It is reached via the redirect that
// [AuthProviderOIDC.beginRegistrationConfirmation] issues from the OIDC
// callback, and it is safe to reload: it only reads the pending
// confirmation captured on the cached [types.AuthRequest] and never touches
// the one-time code exchange.
//
// Listens in GET /register/confirm/:auth_id.
func (a *AuthProviderOIDC) RegisterConfirmGetHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		a.releaseOIDCAuthReservation(authID)
		httpUserError(writer, errRegistrationLinkSpent)

		return
	}

	if _, complete := authReq.AuthResult(); complete {
		a.releaseOIDCAuthReservation(authID)
		httpUserError(writer, errRegistrationLinkSpent)

		return
	}

	pending := authReq.PendingConfirmation()
	if pending == nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "registration not OIDC-authorized", nil))

		return
	}

	// Only the browser that completed the OIDC flow holds this cookie, and
	// holding it is what authorises the confirm POST. Requiring it here too
	// keeps the device details, and the token that finalises the
	// registration, away from anyone who merely knows the auth ID — which
	// the node being registered does.
	cookie, err := req.Cookie(registerConfirmCSRFCookie)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "missing csrf cookie", err))

		return
	}

	if cookie.Value != pending.CSRF {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "csrf token mismatch", nil))

		return
	}

	user, err := a.h.state.GetUserByID(types.UserID(pending.UserID))
	if err != nil {
		httpUserError(writer, fmt.Errorf("looking up user: %w", err))

		return
	}

	regData := authReq.RegistrationData()

	info := templates.RegisterConfirmInfo{
		FormAction:    a.registerConfirmURL(authID),
		CSRFTokenName: registerConfirmCSRFCookie,
		CSRFToken:     pending.CSRF,
		User:          user.Display(),
		Hostname:      regData.Hostname,
		MachineKey:    regData.MachineKey.ShortString(),
	}
	if regData.Hostinfo != nil {
		info.OS = regData.Hostinfo.OS
	}

	// The page carries the token that finalises the registration, so no
	// shared cache or history restore may serve it back.
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if _, err := writer.Write([]byte(templates.RegisterConfirm(info).Render())); err != nil { //nolint:noinlineerr
		util.LogErr(err, "Failed to write HTTP response")
	}
}

// RegisterConfirmHandler is the POST endpoint behind the OIDC
// registration confirmation interstitial. It validates the CSRF cookie
// against the form-submitted token, finalises the registration via
// [AuthProviderOIDC.handleRegistration], and renders the success page.
func (a *AuthProviderOIDC) RegisterConfirmHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	authID, err := authIDFromRequest(req)
	if err != nil {
		httpUserError(writer, err)

		return
	}

	// Cap the form body. The confirmation form is a single CSRF token,
	// so 4 KiB is generous and prevents an unauthenticated client from
	// submitting an arbitrarily large body to ParseForm.
	req.Body = http.MaxBytesReader(writer, req.Body, 4*1024)

	if err := req.ParseForm(); err != nil { //nolint:noinlineerr,gosec // body is bounded above
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "invalid form", err))

		return
	}

	formCSRF := req.PostFormValue(registerConfirmCSRFCookie) //nolint:gosec // body is bounded above
	if formCSRF == "" {
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "missing csrf token", nil))

		return
	}

	cookie, err := req.Cookie(registerConfirmCSRFCookie)
	if err != nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "missing csrf cookie", err))

		return
	}

	if cookie.Value != formCSRF {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "csrf token mismatch", nil))

		return
	}

	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		a.releaseOIDCAuthReservation(authID)
		httpUserError(writer, errRegistrationLinkSpent)

		return
	}

	if _, complete := authReq.AuthResult(); complete {
		a.releaseOIDCAuthReservation(authID)
		httpUserError(writer, errRegistrationLinkSpent)

		return
	}

	pending := authReq.PendingConfirmation()
	if pending == nil {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "registration not OIDC-authorized", nil))

		return
	}

	if pending.CSRF != cookie.Value {
		httpUserError(writer, NewHTTPError(http.StatusForbidden, "csrf token does not match cached registration", nil))

		return
	}

	user, err := a.h.state.GetUserByID(types.UserID(pending.UserID))
	if err != nil {
		httpUserError(writer, fmt.Errorf("looking up user: %w", err))

		return
	}

	newNode, err := a.handleRegistration(user, authID, pending.NodeExpiry)
	if err != nil {
		if errors.Is(err, db.ErrNodeNotFoundRegistrationCache) {
			a.releaseOIDCAuthReservation(authID)
			httpUserError(writer, newHTTPUserError(
				http.StatusGone,
				registrationLinkSpentMsg,
				registrationLinkSpentUserMsg,
				err,
			))

			return
		}

		httpUserError(writer, err)

		return
	}

	a.releaseOIDCAuthReservation(authID)

	// Clear the CSRF cookie now that the registration is final.
	a.setRegisterConfirmCookie(writer, req, authID, "", -1)

	content := renderRegistrationSuccessTemplate(user, newNode)

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	// [renderRegistrationSuccessTemplate]'s output only embeds
	// HTML-escaped values from a server-side template, so the gosec
	// XSS warning is a false positive here.
	if _, err := writer.Write(content.Bytes()); err != nil { //nolint:noinlineerr,gosec
		util.LogErr(err, "Failed to write HTTP response")
	}
}

func (a *AuthProviderOIDC) handleRegistration(
	user *types.User,
	registrationID types.AuthID,
	expiry *time.Time,
) (bool, error) {
	node, nodeChange, err := a.h.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		expiry,
		util.RegisterMethodOIDC,
	)
	if err != nil {
		return false, fmt.Errorf("registering node: %w", err)
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// SaveNode (which automatically updates the policy manager) and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	routesChange, err := a.h.state.AutoApproveRoutes(node)
	if err != nil {
		return false, fmt.Errorf("auto approving routes: %w", err)
	}

	// Send both changes. Empty changes are ignored by Change().
	a.h.Change(nodeChange, routesChange)

	return !nodeChange.IsEmpty(), nil
}

func renderRegistrationSuccessTemplate(
	user *types.User,
	newNode bool,
) *bytes.Buffer {
	result := templates.AuthSuccessResult{
		Title:   "Headscale - Node Reauthenticated",
		Heading: "Node reauthenticated",
		Verb:    "Reauthenticated",
		User:    user.Display(),
		Message: "You can now close this window.",
	}
	if newNode {
		result.Title = "Headscale - Node Registered"
		result.Heading = "Node registered"
		result.Verb = "Registered"
	}

	return bytes.NewBufferString(templates.AuthSuccess(result).Render())
}

func renderAuthSuccessTemplate(
	user *types.User,
) *bytes.Buffer {
	result := templates.AuthSuccessResult{
		Title:   "Headscale - SSH Session Authorized",
		Heading: "SSH session authorized",
		Verb:    "Authorized",
		User:    user.Display(),
		Message: "You may return to your terminal.",
	}

	return bytes.NewBufferString(templates.AuthSuccess(result).Render())
}

// getCookieName generates a unique cookie name based on a cookie value. It
// uses at most [cookieNamePrefixLen] bytes of value, and fewer if value is
// shorter, so a short value (e.g. a malformed nonce from a misbehaving IdP)
// yields a non-matching name rather than panicking with slice-out-of-range.
func getCookieName(baseName, value string) string {
	n := min(len(value), cookieNamePrefixLen)

	return fmt.Sprintf("%s_%s", baseName, value[:n])
}

// clearOIDCCallbackCookie expires an OIDC callback cookie by name. Matching
// the browser-facing path the cookie was set with is required for the browser
// to drop it.
func (a *AuthProviderOIDC) clearOIDCCallbackCookie(w http.ResponseWriter, name string) {
	//nolint:gosec // G124: a deletion cookie (empty value, MaxAge<0); security attributes are moot
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Path:   a.oidcCallbackPath(),
		MaxAge: -1,
	})
}

func (a *AuthProviderOIDC) setCSRFCookie(
	w http.ResponseWriter,
	r *http.Request,
	name string,
) {
	val := rands.HexString(64)
	a.setCSRFCookieValue(w, r, name, val)
}

func (a *AuthProviderOIDC) setCSRFCookieValue(
	w http.ResponseWriter,
	r *http.Request,
	name string,
	val string,
) {
	//nolint:gosec // G124: Secure from server_url scheme or req.TLS; HttpOnly + SameSite set below
	c := &http.Cookie{
		Path:     a.oidcCallbackPath(),
		Name:     getCookieName(name, val),
		Value:    val,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   a.cookiesSecure() || r.TLS != nil,
		HttpOnly: true,
		// Lax, not Strict: the OIDC callback is a cross-site top-level GET
		// redirect from the IdP that must still carry this cookie. Strict
		// would drop it and break login. Setting it explicitly also stops
		// pre-Lax-default browsers from sending it on other cross-site
		// requests.
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, c)
}
