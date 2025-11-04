package hscontrol

import (
	"bytes"
	"cmp"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"zgo.at/zcache/v2"
)

const (
	randomByteSize           = 16
	defaultOAuthOptionsCount = 3
	registerCacheExpiration  = time.Minute * 15
	registerCacheCleanup     = time.Minute * 20
)

var (
	errEmptyOIDCCallbackParams = errors.New("empty OIDC callback params")
	errNoOIDCIDToken           = errors.New("could not extract ID Token for OIDC callback")
	errNoOIDCRegistrationInfo  = errors.New("could not get registration info from cache")
	errOIDCAllowedDomains      = errors.New(
		"authenticated principal does not match any allowed domain",
	)
	errOIDCAllowedGroups = errors.New("authenticated principal is not in any allowed group")
	errOIDCAllowedUsers  = errors.New(
		"authenticated principal does not match any allowed user",
	)
	errOIDCInvalidNodeState = errors.New(
		"requested node state key expired before authorisation completed",
	)
	errOIDCNodeKeyMissing = errors.New("could not get node key from cache")
)

// RegistrationInfo contains both machine key and verifier information for OIDC validation.
type RegistrationInfo struct {
	RegistrationID types.RegistrationID
	Verifier       *string
}

type AuthProviderOIDC struct {
	h                 *Headscale
	serverURL         string
	cfg               *types.OIDCConfig
	registrationCache *zcache.Cache[string, RegistrationInfo]

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
	oidcProvider, err := oidc.NewProvider(context.Background(), cfg.Issuer)
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

	registrationCache := zcache.New[string, RegistrationInfo](
		registerCacheExpiration,
		registerCacheCleanup,
	)

	return &AuthProviderOIDC{
		h:                 h,
		serverURL:         serverURL,
		cfg:               cfg,
		registrationCache: registrationCache,

		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
	}, nil
}

func (a *AuthProviderOIDC) AuthURL(registrationID types.RegistrationID) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		registrationID.String())
}

func (a *AuthProviderOIDC) determineNodeExpiry(idTokenExpiration time.Time) time.Time {
	if a.cfg.UseExpiryFromToken {
		return idTokenExpiration
	}

	return time.Now().Add(a.cfg.Expiry)
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts NodeKey in cache so the callback can retrieve it using the oidc state param
// Listens in /register/:registration_id.
func (a *AuthProviderOIDC) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	registrationIdStr := vars["registration_id"]

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	registrationId, err := types.RegistrationIDFromString(registrationIdStr)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "invalid registration id", err))
		return
	}

	// Set the state and nonce cookies to protect against CSRF attacks
	state, err := setCSRFCookie(writer, req, "state")
	if err != nil {
		httpError(writer, err)
		return
	}

	// Set the state and nonce cookies to protect against CSRF attacks
	nonce, err := setCSRFCookie(writer, req, "nonce")
	if err != nil {
		httpError(writer, err)
		return
	}

	// Initialize registration info with machine key
	registrationInfo := RegistrationInfo{
		RegistrationID: registrationId,
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
	a.registrationCache.Set(state, registrationInfo)

	authURL := a.oauth2Config.AuthCodeURL(state, extras...)
	log.Debug().Caller().Msgf("Redirecting to %s for authentication", authURL)

	http.Redirect(writer, req, authURL, http.StatusFound)
}

type oidcCallbackTemplateConfig struct {
	User string
	Verb string
}

//go:embed assets/oidc_callback_template.html
var oidcCallbackTemplateContent string

var oidcCallbackTemplate = template.Must(
	template.New("oidccallback").Parse(oidcCallbackTemplateContent),
)

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
		httpError(writer, err)
		return
	}

	stateCookieName := getCookieName("state", state)
	cookieState, err := req.Cookie(stateCookieName)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "state not found", err))
		return
	}

	if state != cookieState.Value {
		httpError(writer, NewHTTPError(http.StatusForbidden, "state did not match", nil))
		return
	}

	oauth2Token, err := a.getOauth2Token(req.Context(), code, state)
	if err != nil {
		httpError(writer, err)
		return
	}

	idToken, err := a.extractIDToken(req.Context(), oauth2Token)
	if err != nil {
		httpError(writer, err)
		return
	}
	if idToken.Nonce == "" {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "nonce not found in IDToken", err))
		return
	}

	nonceCookieName := getCookieName("nonce", idToken.Nonce)
	nonce, err := req.Cookie(nonceCookieName)
	if err != nil {
		httpError(writer, NewHTTPError(http.StatusBadRequest, "nonce not found", err))
		return
	}
	if idToken.Nonce != nonce.Value {
		httpError(writer, NewHTTPError(http.StatusForbidden, "nonce did not match", nil))
		return
	}

	nodeExpiry := a.determineNodeExpiry(idToken.Expiry)

	var claims types.OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		httpError(writer, fmt.Errorf("decoding ID token claims: %w", err))
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
	if err := validateOIDCAllowedDomains(a.cfg.AllowedDomains, &claims); err != nil {
		httpError(writer, err)
		return
	}

	if err := validateOIDCAllowedGroups(a.cfg.AllowedGroups, &claims); err != nil {
		httpError(writer, err)
		return
	}

	if err := validateOIDCAllowedUsers(a.cfg.AllowedUsers, &claims); err != nil {
		httpError(writer, err)
		return
	}

	user, c, err := a.createOrUpdateUserFromClaim(&claims)
	if err != nil {
		log.Error().
			Err(err).
			Caller().
			Msgf("could not create or update user")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("Could not create or update user"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write HTTP response")
		}

		return
	}

	// Send policy update notifications if needed
	a.h.Change(c)

	// TODO(kradalby): Is this comment right?
	// If the node exists, then the node should be reauthenticated,
	// if the node does not exist, and the machine key exists, then
	// this is a new node that should be registered.
	registrationId := a.getRegistrationIDFromState(state)

	// Register the node if it does not exist.
	if registrationId != nil {
		verb := "Reauthenticated"
		newNode, err := a.handleRegistration(user, *registrationId, nodeExpiry)
		if err != nil {
			if errors.Is(err, db.ErrNodeNotFoundRegistrationCache) {
				log.Debug().Caller().Str("registration_id", registrationId.String()).Msg("registration session expired before authorization completed")
				httpError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", err))

				return
			}
			httpError(writer, err)
			return
		}

		if newNode {
			verb = "Authenticated"
		}

		// TODO(kradalby): replace with go-elem
		content, err := renderOIDCCallbackTemplate(user, verb)
		if err != nil {
			httpError(writer, err)
			return
		}

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		if _, err := writer.Write(content.Bytes()); err != nil {
			util.LogErr(err, "Failed to write HTTP response")
		}

		return
	}

	// Neither node nor machine key was found in the state cache meaning
	// that we could not reauth nor register the node.
	httpError(writer, NewHTTPError(http.StatusGone, "login session expired, try again", nil))
}

func extractCodeAndStateParamFromRequest(
	req *http.Request,
) (string, string, error) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" || state == "" {
		return "", "", NewHTTPError(http.StatusBadRequest, "missing code or state parameter", errEmptyOIDCCallbackParams)
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
		regInfo, ok := a.registrationCache.Get(state)
		if !ok {
			return nil, NewHTTPError(http.StatusNotFound, "registration not found", errNoOIDCRegistrationInfo)
		}
		if regInfo.Verifier != nil {
			exchangeOpts = []oauth2.AuthCodeOption{oauth2.VerifierOption(*regInfo.Verifier)}
		}
	}

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, NewHTTPError(http.StatusForbidden, "invalid code", fmt.Errorf("could not exchange code for token: %w", err))
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
		return nil, NewHTTPError(http.StatusForbidden, "failed to verify id_token", fmt.Errorf("failed to verify ID token: %w", err))
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
	if len(allowedGroups) > 0 {
		for _, group := range allowedGroups {
			if slices.Contains(claims.Groups, group) {
				return nil
			}
		}

		return NewHTTPError(http.StatusUnauthorized, "unauthorised group", errOIDCAllowedGroups)
	}

	return nil
}

// validateOIDCAllowedUsers checks that if AllowedUsers is provided,
// that the authenticated principal is part of that list.
func validateOIDCAllowedUsers(
	allowedUsers []string,
	claims *types.OIDCClaims,
) error {
	if len(allowedUsers) > 0 &&
		!slices.Contains(allowedUsers, claims.Email) {
		return NewHTTPError(http.StatusUnauthorized, "unauthorised user", errOIDCAllowedUsers)
	}

	return nil
}

// getRegistrationIDFromState retrieves the registration ID from the state.
func (a *AuthProviderOIDC) getRegistrationIDFromState(state string) *types.RegistrationID {
	regInfo, ok := a.registrationCache.Get(state)
	if !ok {
		return nil
	}

	return &regInfo.RegistrationID
}

func (a *AuthProviderOIDC) createOrUpdateUserFromClaim(
	claims *types.OIDCClaims,
) (*types.User, change.ChangeSet, error) {
	var user *types.User
	var err error
	var newUser bool
	var c change.ChangeSet
	user, err = a.h.state.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, change.EmptySet, fmt.Errorf("creating or updating user: %w", err)
	}

	// if the user is still not found, create a new empty user.
	// TODO(kradalby): This might cause us to not have an ID below which
	// is a problem.
	if user == nil {
		newUser = true
		user = &types.User{}
	}

	user.FromClaim(claims)

	if newUser {
		user, c, err = a.h.state.CreateUser(*user)
		if err != nil {
			return nil, change.EmptySet, fmt.Errorf("creating user: %w", err)
		}
	} else {
		_, c, err = a.h.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
			*u = *user
			return nil
		})
		if err != nil {
			return nil, change.EmptySet, fmt.Errorf("updating user: %w", err)
		}
	}

	return user, c, nil
}

func (a *AuthProviderOIDC) handleRegistration(
	user *types.User,
	registrationID types.RegistrationID,
	expiry time.Time,
) (bool, error) {
	node, nodeChange, err := a.h.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		&expiry,
		util.RegisterMethodOIDC,
	)
	if err != nil {
		return false, fmt.Errorf("could not register node: %w", err)
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
	_ = a.h.state.AutoApproveRoutes(node)
	_, policyChange, err := a.h.state.SaveNode(node)
	if err != nil {
		return false, fmt.Errorf("saving auto approved routes to node: %w", err)
	}

	// Policy updates are full and take precedence over node changes.
	if !policyChange.Empty() {
		a.h.Change(policyChange)
	} else {
		a.h.Change(nodeChange)
	}

	return !nodeChange.Empty(), nil
}

// TODO(kradalby):
// Rewrite in elem-go.
func renderOIDCCallbackTemplate(
	user *types.User,
	verb string,
) (*bytes.Buffer, error) {
	var content bytes.Buffer
	if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
		User: user.Display(),
		Verb: verb,
	}); err != nil {
		return nil, fmt.Errorf("rendering OIDC callback template: %w", err)
	}

	return &content, nil
}

// getCookieName generates a unique cookie name based on a cookie value.
func getCookieName(baseName, value string) string {
	return fmt.Sprintf("%s_%s", baseName, value[:6])
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
