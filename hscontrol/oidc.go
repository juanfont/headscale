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
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
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
	serverURL         string
	cfg               *types.OIDCConfig
	state             *state.State
	registrationCache *zcache.Cache[string, RegistrationInfo]
	notifier          *notifier.Notifier

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(
	ctx context.Context,
	serverURL string,
	cfg *types.OIDCConfig,
	state *state.State,
	notif *notifier.Notifier,
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
		serverURL:         serverURL,
		cfg:               cfg,
		state:             state,
		registrationCache: registrationCache,
		notifier:          notif,

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
	log.Debug().Msgf("Redirecting to %s for authentication", authURL)

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

	cookieState, err := req.Cookie("state")
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

	nonce, err := req.Cookie("nonce")
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

	var userinfo *oidc.UserInfo
	userinfo, err = a.oidcProvider.UserInfo(req.Context(), oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		util.LogErr(err, "could not get userinfo; only checking claim")
	}

	// If the userinfo is available, we can check if the subject matches the
	// claims, then use some of the userinfo fields to update the user.
	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	if userinfo != nil && userinfo.Subject == claims.Sub {
		claims.Email = cmp.Or(claims.Email, userinfo.Email)
		claims.EmailVerified = cmp.Or(claims.EmailVerified, types.FlexibleBoolean(userinfo.EmailVerified))

		// The userinfo has some extra fields that we can use to update the user but they are only
		// available in the underlying claims struct.
		// TODO(kradalby): there might be more interesting fields here that we have not found yet.
		var userinfo2 types.OIDCUserInfo
		if err := userinfo.Claims(&userinfo2); err == nil {
			claims.Username = cmp.Or(claims.Username, userinfo2.PreferredUsername)
			claims.Name = cmp.Or(claims.Name, userinfo2.Name)
			claims.ProfilePictureURL = cmp.Or(claims.ProfilePictureURL, userinfo2.Picture)
		}
	}

	user, policyChanged, err := a.createOrUpdateUserFromClaim(&claims)
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
				Msg("Failed to write response")
		}

		return
	}

	// Send policy update notifications if needed
	if policyChanged {
		ctx := types.NotifyCtx(context.Background(), "oidc-user-created", user.Name)
		a.notifier.NotifyAll(ctx, types.UpdateFull())
	}

	// TODO(kradalby): Is this comment right?
	// If the node exists, then the node should be reauthenticated,
	// if the node does not exist, and the machine key exists, then
	// this is a new node that should be registered.
	registrationId := a.getRegistrationIDFromState(state)

	// Register the node if it does not exist.
	if registrationId != nil {
		verb := "Reauthenticated"
		nodeID, newNode, err := a.handleRegistration(user, *registrationId, nodeExpiry)
		if err != nil {
			httpError(writer, err)
			return
		}

		if newNode {
			verb = "Authenticated"
		}

		// Create or update OIDC session for this node
		if err := a.createOrUpdateOIDCSession(*registrationId, oauth2Token, *nodeID); err != nil {
			log.Error().Err(err).Msg("Failed to create OIDC session")
			// Don't fail the auth flow, just log the error
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
			util.LogErr(err, "Failed to write response")
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

// createOrUpdateOIDCSession creates or updates an OIDC session for a node
func (a *AuthProviderOIDC) createOrUpdateOIDCSession(registrationID types.RegistrationID, token *oauth2.Token, nodeID types.NodeID) error {
	if token.RefreshToken == "" {
		log.Warn().
			Str("node_id", nodeID.String()).
			Str("registration_id", registrationID.String()).
			Msg("OIDC: No refresh token in OAuth2 token, skipping session creation (check offline_access scope)")
		return nil
	}

	// Generate session ID
	sessionID, err := util.GenerateRandomStringURLSafe(32)
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Create or update session
	tokenExpiryUTC := token.Expiry.UTC()
	session := &types.OIDCSession{
		NodeID:         nodeID,
		SessionID:      sessionID,
		RegistrationID: registrationID,
		RefreshToken:   token.RefreshToken,
		TokenExpiry:    &tokenExpiryUTC,
		IsActive:       true,
	}

	now := time.Now().UTC()
	session.LastRefreshedAt = &now
	session.LastSeenAt = &now

	// Try to update existing session first
	var existingSession types.OIDCSession
	err = a.db.DB.Where("node_id = ?", nodeID).First(&existingSession).Error
	if err == nil {
		// Update existing session
		existingSession.RefreshToken = token.RefreshToken
		tokenExpiryUTC := token.Expiry.UTC()
		existingSession.TokenExpiry = &tokenExpiryUTC
		existingSession.LastRefreshedAt = &now
		existingSession.LastSeenAt = &now
		existingSession.IsActive = true
		existingSession.RefreshCount = existingSession.RefreshCount + 1

		err = a.db.DB.Save(&existingSession).Error
		if err != nil {
			return fmt.Errorf("failed to update OIDC session: %w", err)
		}

	} else {
		// Create new session
		err = a.db.DB.Create(session).Error
		if err != nil {
			return fmt.Errorf("failed to create OIDC session: %w", err)
		}
	}

	return nil
}

// RefreshOIDCSession refreshes an expired OIDC session using the stored refresh token
// and updates the node expiry using the existing HandleNodeFromAuthPath flow
func (a *AuthProviderOIDC) RefreshOIDCSession(ctx context.Context, session *types.OIDCSession) error {
	if session.RefreshToken == "" {
		return fmt.Errorf("no refresh token available for session %s", session.SessionID)
	}

	tokenSource := a.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: session.RefreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return fmt.Errorf("failed to refresh OIDC token: %w", err)
	}

	// Calculate new node expiry based on the access token expiry (not ID token)
	// Access tokens determine when we need to refresh, so node should live as long as access token
	nodeExpiry := a.determineNodeExpiry(newToken.Expiry)

	// Load the node for logging
	var node types.Node
	err = a.db.DB.Preload("User").First(&node, session.NodeID).Error
	if err != nil {
		return fmt.Errorf("failed to load node: %w", err)
	}

	// Update the node expiry directly for token refresh
	// We don't use HandleNodeFromAuthPath for refresh as the node is already registered
	err = a.db.DB.Model(&node).Update("expiry", nodeExpiry).Error
	if err != nil {
		return fmt.Errorf("failed to update node expiry: %w", err)
	}

	// Update the local node object for consistency
	node.Expiry = &nodeExpiry

	// Update the session with new token information
	now := time.Now().UTC()

	if newToken.RefreshToken != "" {
		session.RefreshToken = newToken.RefreshToken
	} else {
		log.Debug().
			Str("session_id", session.SessionID).
			Msg("OIDC: No new refresh token received, keeping existing one")
	}

	// Store token expiry in UTC to avoid timezone issues
	utcExpiry := newToken.Expiry.UTC()
	session.TokenExpiry = &utcExpiry
	session.LastRefreshedAt = &now
	session.RefreshCount = session.RefreshCount + 1

	// Save the updated session
	err = a.db.DB.Save(session).Error
	if err != nil {
		log.Error().Err(err).
			Str("session_id", session.SessionID).
			Msg("OIDC: Failed to save updated session to database")
		return fmt.Errorf("failed to save updated session: %w", err)
	}

	return nil
}

// RefreshExpiredTokens checks for and refreshes OIDC sessions that will expire soon
func (a *AuthProviderOIDC) RefreshExpiredTokens(ctx context.Context) error {
	var sessions []types.OIDCSession

	// Find active sessions with tokens expiring in the configured threshold time
	currentTime := time.Now().UTC()
	threshold := currentTime.Add(a.cfg.TokenRefresh.ExpiryThreshold)

	// Only refresh tokens for sessions linked to OIDC-registered nodes
	err := a.db.DB.Preload("Node").Preload("Node.User").
		Joins("JOIN nodes ON nodes.id = oidc_sessions.node_id").
		Where("oidc_sessions.is_active = ? AND oidc_sessions.token_expiry IS NOT NULL AND oidc_sessions.token_expiry < ? AND oidc_sessions.refresh_token != '' AND nodes.register_method = ?",
			true, threshold, "oidc").
		Find(&sessions).Error
	if err != nil {
		return fmt.Errorf("failed to query sessions with expiring tokens: %w", err)
	}

	if len(sessions) == 0 {
		return nil
	}

	log.Debug().Msgf("OIDC: Found %d sessions with tokens expiring soon, refreshing...", len(sessions))

	for _, session := range sessions {
		if err := a.RefreshOIDCSession(ctx, &session); err != nil {
			log.Error().Err(err).
				Str("session_id", session.SessionID).
				Uint("user_id", session.Node.UserID).
				Uint64("node_id", uint64(session.NodeID)).
				Msg("OIDC: Failed to refresh session, deactivating")
			// Deactivate the session if refresh fails
			session.Deactivate()
			a.db.DB.Save(&session)
			continue
		}
	}

	return nil
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
) (*types.User, bool, error) {
	var user *types.User
	var err error
	var newUser bool
	var policyChanged bool
	user, err = a.state.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, false, fmt.Errorf("creating or updating user: %w", err)
	}

	// if the user is still not found, create a new empty user.
	if user == nil {
		newUser = true
		user = &types.User{}
	}

	user.FromClaim(claims)

	if newUser {
		user, policyChanged, err = a.state.CreateUser(*user)
		if err != nil {
			return nil, false, fmt.Errorf("creating user: %w", err)
		}
	} else {
		_, policyChanged, err = a.state.UpdateUser(types.UserID(user.ID), func(u *types.User) error {
			*u = *user
			return nil
		})
		if err != nil {
			return nil, false, fmt.Errorf("updating user: %w", err)
		}
	}

	return user, policyChanged, nil
}

func (a *AuthProviderOIDC) handleRegistration(
	user *types.User,
	registrationID types.RegistrationID,
	expiry time.Time,
) (*types.NodeID, bool, error) {
	node, newNode, err := a.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		&expiry,
		util.RegisterMethodOIDC,
	)
	if err != nil {
		return nil, false, fmt.Errorf("could not register node: %w", err)
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
	routesChanged := a.state.AutoApproveRoutes(node)
	_, policyChanged, err := a.state.SaveNode(node)
	if err != nil {
		return nil, false, fmt.Errorf("saving auto approved routes to node: %w", err)
	}

	// Send policy update notifications if needed (from SaveNode or route changes)
	if policyChanged {
		ctx := types.NotifyCtx(context.Background(), "oidc-nodes-change", "all")
		a.notifier.NotifyAll(ctx, types.UpdateFull())
	}

	if routesChanged {
		ctx := types.NotifyCtx(context.Background(), "oidc-expiry-self", node.Hostname)
		a.notifier.NotifyByNodeID(
			ctx,
			types.UpdateSelf(node.ID),
			node.ID,
		)

		ctx = types.NotifyCtx(context.Background(), "oidc-expiry-peers", node.Hostname)
		a.notifier.NotifyWithIgnore(ctx, types.UpdatePeerChanged(node.ID), node.ID)
	}

	return &node.ID, newNode, nil
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

func setCSRFCookie(w http.ResponseWriter, r *http.Request, name string) (string, error) {
	val, err := util.GenerateRandomStringURLSafe(64)
	if err != nil {
		return val, err
	}

	c := &http.Cookie{
		Path:     "/oidc/callback",
		Name:     name,
		Value:    val,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)

	return val, nil
}
