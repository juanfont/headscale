package hscontrol

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
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
)

const (
	randomByteSize           = 16
	defaultOAuthOptionsCount = 3
	authCacheExpiration      = time.Minute * 15

	// authCacheMaxEntries bounds the OIDC state→AuthInfo cache to prevent
	// unauthenticated cache-fill DoS via repeated /register/{auth_id} or
	// /auth/{auth_id} GETs that mint OIDC state cookies.
	authCacheMaxEntries = 1024

	// cookieNamePrefixLen is the number of leading characters from a
	// state/nonce value that getCookieName splices into the cookie name.
	// State and nonce values that are shorter than this are rejected at
	// the callback boundary so getCookieName cannot panic on a slice
	// out-of-range.
	cookieNamePrefixLen = 6
)

var errOIDCStateTooShort = errors.New("oidc state parameter is too short")

var (
	errEmptyOIDCCallbackParams = errors.New("empty OIDC callback params")
	errNoOIDCIDToken           = errors.New("extracting ID token")
	errNoOIDCRegistrationInfo  = errors.New("registration info not in cache")
	errOIDCAllowedDomains      = errors.New(
		"authenticated principal does not match any allowed domain",
	)
	errOIDCAllowedGroups = errors.New("authenticated principal is not in any allowed group")
	errOIDCAllowedUsers  = errors.New(
		"authenticated principal does not match any allowed user",
	)
	errOIDCUnverifiedEmail = errors.New("authenticated principal has an unverified email")
)

// AuthInfo contains both auth ID and verifier information for OIDC validation.
type AuthInfo struct {
	AuthID       types.AuthID
	Verifier     *string
	Registration bool
}

type AuthProviderOIDC struct {
	h         *Headscale
	serverURL string
	cfg       *types.OIDCConfig

	// authCache holds auth information between the auth and the callback
	// steps. It is a bounded LRU keyed by OIDC state, evicting oldest
	// entries to keep the cache footprint constant under attack.
	authCache *expirable.LRU[string, AuthInfo]

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(
	ctx context.Context,
	h *Headscale,
	serverURL string,
	cfg *types.OIDCConfig,
) (*AuthProviderOIDC, error) {
	var err error
	// grab oidc config if it hasn't been already
	oidcProvider, err := oidc.NewProvider(context.Background(), cfg.Issuer) //nolint:contextcheck
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider from issuer config: %w", err)
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     oidcProvider.Endpoint(),
		RedirectURL:  strings.TrimSuffix(serverURL, "/") + "/oidc/callback",
		Scopes:       cfg.Scope,
	}

	authCache := expirable.NewLRU[string, AuthInfo](
		authCacheMaxEntries,
		nil,
		authCacheExpiration,
	)

	return &AuthProviderOIDC{
		h:         h,
		serverURL: serverURL,
		cfg:       cfg,
		authCache: authCache,

		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
	}, nil
}

func (a *AuthProviderOIDC) AuthURL(authID types.AuthID) string {
	return fmt.Sprintf(
		"%s/auth/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		authID.String())
}

func (a *AuthProviderOIDC) AuthHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	a.authHandler(writer, req, false)
}

func (a *AuthProviderOIDC) RegisterURL(authID types.AuthID) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		authID.String())
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

	// Set the state and nonce cookies to protect against CSRF attacks
	state, err := setCSRFCookie(writer, req, "state")
	if err != nil {
		httpUserError(writer, err)
		return
	}

	// Set the state and nonce cookies to protect against CSRF attacks
	nonce, err := setCSRFCookie(writer, req, "nonce")
	if err != nil {
		httpUserError(writer, err)
		return
	}

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
		}
	}

	// Add any extra parameters from configuration
	for k, v := range a.cfg.ExtraParams {
		extras = append(extras, oauth2.SetAuthURLParam(k, v))
	}

	extras = append(extras, oidc.Nonce(nonce))

	// Cache the registration info
	a.authCache.Add(state, registrationInfo)

	authURL := a.oauth2Config.AuthCodeURL(state, extras...)
	log.Debug().Caller().Msgf("redirecting to %s for authentication", authURL)

	http.Redirect(writer, req, authURL, http.StatusFound)
}

// OIDCCallbackHandler handles the callback from the OIDC endpoint
// Retrieves the nkey from the state cache and adds the node to the users email user
// TODO: A confirmation page for new nodes should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into node HostInfo
// Listens in /oidc/callback.
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

	oauth2Token, err := a.getOauth2Token(req.Context(), code, state)
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

	// The oidc.UserInfo type only decodes some fields (Subject, Profile, Email, EmailVerified).
	// We are interested in other fields too (e.g. groups are required for allowedGroups) so we
	// decode into our own OIDCUserInfo type using the underlying claims struct.
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
	} else {
		util.LogErr(err, "could not get userinfo; only using claims from id token")
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

	// TODO(kradalby): Is this comment right?
	// If the node exists, then the node should be reauthenticated,
	// if the node does not exist, and the machine key exists, then
	// this is a new node that should be registered.
	authInfo := a.getAuthInfoFromState(state)
	if authInfo == nil {
		log.Debug().Caller().Str("state", state).Msg("state not found in cache, login session may have expired")
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	// If this is a registration flow, render the confirmation
	// interstitial instead of finalising the registration immediately.
	// Without an explicit user click, a single GET to
	// /register/{auth_id} could silently complete a registration when
	// the IdP allows silent SSO.
	if authInfo.Registration {
		a.renderRegistrationConfirmInterstitial(writer, req, authInfo.AuthID, user, nodeExpiry)

		return
	}

	// If this is not a registration callback, then it is an SSH
	// check-mode auth callback. Confirm the OIDC identity is the owner
	// of the SSH source node before recording approval; without this
	// check any tailnet user could approve a check-mode prompt for any
	// other user's node, defeating the stolen-key protection that
	// check-mode is meant to provide.

	authReq, ok := a.h.state.GetAuthCacheEntry(authInfo.AuthID)
	if !ok {
		log.Debug().Caller().Str("auth_id", authInfo.AuthID.String()).Msg("auth session expired before authorization completed")
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	if !authReq.IsSSHCheck() {
		log.Warn().Caller().
			Str("auth_id", authInfo.AuthID.String()).
			Msg("OIDC callback hit non-registration path with auth request that is not an SSH check binding")
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "auth session is not for SSH check", nil))

		return
	}

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

	// Identity verified — record the verdict for the waiting follow-up.
	authReq.FinishAuth(types.AuthVerdict{})

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

	// Reject states that are too short for getCookieName to splice
	// into a cookie name. Without this guard a request with
	// ?state=abc panics on the slice out-of-range and is recovered by
	// chi's middleware.Recoverer, amplifying small-DoS log noise.
	if len(state) < cookieNamePrefixLen {
		return "", "", NewHTTPError(http.StatusBadRequest, "invalid state parameter", errOIDCStateTooShort)
	}

	return code, state, nil
}

// getOauth2Token exchanges the code from the callback for an oauth2 token.
func (a *AuthProviderOIDC) getOauth2Token(
	ctx context.Context,
	code string,
	state string,
) (*oauth2.Token, error) {
	var exchangeOpts []oauth2.AuthCodeOption

	if a.cfg.PKCE.Enabled {
		regInfo, ok := a.authCache.Get(state)
		if !ok {
			return nil, NewHTTPError(http.StatusNotFound, "registration not found", errNoOIDCRegistrationInfo)
		}

		if regInfo.Verifier != nil {
			exchangeOpts = []oauth2.AuthCodeOption{oauth2.VerifierOption(*regInfo.Verifier)}
		}
	}

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "invalid code", fmt.Errorf("exchanging code for token: %w", err))
	}

	return oauth2Token, err
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
		if at := strings.LastIndex(claims.Email, "@"); at < 0 ||
			!slices.Contains(allowedDomains, claims.Email[at+1:]) {
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
// - validateOIDCAllowedGroups
//
// The following tests are applied if cfg.EmailVerifiedRequired=false
// or claims.email_verified=true:
//
// - validateOIDCAllowedDomains
// - validateOIDCAllowedUsers
//
// NOTE that, contrary to the function name, validateOIDCAllowedUsers
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

// getAuthInfoFromState retrieves the registration ID from the state.
func (a *AuthProviderOIDC) getAuthInfoFromState(state string) *AuthInfo {
	authInfo, ok := a.authCache.Get(state)
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

// renderRegistrationConfirmInterstitial captures the resolved OIDC
// identity and node expiry into the cached AuthRequest, sets the CSRF
// cookie, and renders the confirmation page that the user must
// explicitly submit before the registration is finalised.
func (a *AuthProviderOIDC) renderRegistrationConfirmInterstitial(
	writer http.ResponseWriter,
	req *http.Request,
	authID types.AuthID,
	user *types.User,
	nodeExpiry *time.Time,
) {
	authReq, ok := a.h.state.GetAuthCacheEntry(authID)
	if !ok {
		log.Debug().Caller().Str("auth_id", authID.String()).Msg("registration session expired before authorization completed")
		httpUserError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))

		return
	}

	if !authReq.IsRegistration() {
		log.Warn().Caller().
			Str("auth_id", authID.String()).
			Msg("OIDC callback hit registration path with auth request that is not a node registration")
		httpUserError(writer, NewHTTPError(http.StatusBadRequest, "auth session is not for node registration", nil))

		return
	}

	csrf, err := util.GenerateRandomStringURLSafe(32)
	if err != nil {
		httpUserError(writer, fmt.Errorf("generating csrf token: %w", err))

		return
	}

	authReq.SetPendingConfirmation(&types.PendingRegistrationConfirmation{
		UserID:     user.ID,
		NodeExpiry: nodeExpiry,
		CSRF:       csrf,
	})

	http.SetCookie(writer, &http.Cookie{
		Name:     registerConfirmCSRFCookie,
		Value:    csrf,
		Path:     "/register/confirm/" + authID.String(),
		MaxAge:   int(authCacheExpiration.Seconds()),
		Secure:   req.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	regData := authReq.RegistrationData()

	info := templates.RegisterConfirmInfo{
		FormAction:    "/register/confirm/" + authID.String(),
		CSRFTokenName: registerConfirmCSRFCookie,
		CSRFToken:     csrf,
		User:          user.Display(),
		Hostname:      regData.Hostname,
		MachineKey:    regData.MachineKey.ShortString(),
	}
	if regData.Hostinfo != nil {
		info.OS = regData.Hostinfo.OS
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	if _, err := writer.Write([]byte(templates.RegisterConfirm(info).Render())); err != nil { //nolint:noinlineerr
		util.LogErr(err, "Failed to write HTTP response")
	}
}

// RegisterConfirmHandler is the POST endpoint behind the OIDC
// registration confirmation interstitial. It validates the CSRF cookie
// against the form-submitted token, finalises the registration via
// handleRegistration, and renders the success page.
func (a *AuthProviderOIDC) RegisterConfirmHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	if req.Method != http.MethodPost {
		httpUserError(writer, errMethodNotAllowed)

		return
	}

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
		httpUserError(writer, NewHTTPError(http.StatusGone, "registration session expired", nil))

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
			httpUserError(writer, NewHTTPError(http.StatusGone, "registration session expired", err))

			return
		}

		httpUserError(writer, err)

		return
	}

	// Clear the CSRF cookie now that the registration is final.
	http.SetCookie(writer, &http.Cookie{
		Name:     registerConfirmCSRFCookie,
		Value:    "",
		Path:     "/register/confirm/" + authID.String(),
		MaxAge:   -1,
		Secure:   req.TLS != nil,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	content := renderRegistrationSuccessTemplate(user, newNode)

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)

	// renderRegistrationSuccessTemplate's output only embeds
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

// getCookieName generates a unique cookie name based on a cookie value.
// Callers must ensure value has at least cookieNamePrefixLen bytes;
// extractCodeAndStateParamFromRequest enforces this for the state
// parameter, and setCSRFCookie always supplies a 64-byte random value.
func getCookieName(baseName, value string) string {
	return fmt.Sprintf("%s_%s", baseName, value[:cookieNamePrefixLen])
}

func setCSRFCookie(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	val, err := util.GenerateRandomStringURLSafe(64)
	if err != nil {
		return val, err
	}

	c := &http.Cookie{
		Path:     "/oidc/callback",
		Name:     getCookieName(name, val),
		Value:    val,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)

	return val, nil
}
