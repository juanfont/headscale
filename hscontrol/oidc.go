package hscontrol

import (
	"bytes"
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
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"zgo.at/zcache/v2"
)

const (
	randomByteSize           = 16
	defaultOAuthOptionsCount = 3
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
	db                *db.HSDatabase
	registrationCache *zcache.Cache[string, RegistrationInfo]
	notifier          *notifier.Notifier
	ipAlloc           *db.IPAllocator
	polMan            policy.PolicyManager

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(
	ctx context.Context,
	serverURL string,
	cfg *types.OIDCConfig,
	db *db.HSDatabase,
	notif *notifier.Notifier,
	ipAlloc *db.IPAllocator,
	polMan policy.PolicyManager,
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
		RedirectURL: fmt.Sprintf(
			"%s/oidc/callback",
			strings.TrimSuffix(serverURL, "/"),
		),
		Scopes: cfg.Scope,
	}

	registrationCache := zcache.New[string, RegistrationInfo](
		registerCacheExpiration,
		registerCacheCleanup,
	)

	return &AuthProviderOIDC{
		serverURL:         serverURL,
		cfg:               cfg,
		db:                db,
		registrationCache: registrationCache,
		notifier:          notif,
		ipAlloc:           ipAlloc,
		polMan:            polMan,

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
	registrationIdStr, ok := vars["registration_id"]

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	registrationId, err := types.RegistrationIDFromString(registrationIdStr)
	if err != nil {
		http.Error(writer, "invalid registration ID", http.StatusBadRequest)
		return
	}

	log.Debug().
		Caller().
		Str("registration_id", registrationId.String()).
		Bool("ok", ok).
		Msg("Received oidc register call")

	// Set the state and nonce cookies to protect against CSRF attacks
	state, err := setCSRFCookie(writer, req, "state")
	if err != nil {
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set the state and nonce cookies to protect against CSRF attacks
	nonce, err := setCSRFCookie(writer, req, "nonce")
	if err != nil {
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
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
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	log.Debug().Interface("cookies", req.Cookies()).Msg("Received oidc callback")
	cookieState, err := req.Cookie("state")
	if err != nil {
		http.Error(writer, "state not found", http.StatusBadRequest)
		return
	}

	if state != cookieState.Value {
		http.Error(writer, "state did not match", http.StatusBadRequest)
		return
	}

	idToken, err := a.extractIDToken(req.Context(), code, state)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	nonce, err := req.Cookie("nonce")
	if err != nil {
		http.Error(writer, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(writer, "nonce did not match", http.StatusBadRequest)
		return
	}

	nodeExpiry := a.determineNodeExpiry(idToken.Expiry)

	var claims types.OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		http.Error(writer, fmt.Errorf("failed to decode ID token claims: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	if err := validateOIDCAllowedDomains(a.cfg.AllowedDomains, &claims); err != nil {
		http.Error(writer, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := validateOIDCAllowedGroups(a.cfg.AllowedGroups, &claims); err != nil {
		http.Error(writer, err.Error(), http.StatusUnauthorized)
		return
	}

	if err := validateOIDCAllowedUsers(a.cfg.AllowedUsers, &claims); err != nil {
		http.Error(writer, err.Error(), http.StatusUnauthorized)
		return
	}

	user, err := a.createOrUpdateUserFromClaim(&claims)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO(kradalby): Is this comment right?
	// If the node exists, then the node should be reauthenticated,
	// if the node does not exist, and the machine key exists, then
	// this is a new node that should be registered.
	registrationId := a.getRegistrationIDFromState(state)

	// Register the node if it does not exist.
	if registrationId != nil {
		verb := "Reauthenticated"
		newNode, err := a.handleRegistrationID(user, *registrationId, nodeExpiry)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		if newNode {
			verb = "Authenticated"
		}

		// TODO(kradalby): replace with go-elem
		content, err := renderOIDCCallbackTemplate(user, verb)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
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
	http.Error(writer, "login session expired, try again", http.StatusInternalServerError)
	return
}

func extractCodeAndStateParamFromRequest(
	req *http.Request,
) (string, string, error) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" || state == "" {
		return "", "", errEmptyOIDCCallbackParams
	}

	return code, state, nil
}

// extractIDToken takes the code parameter from the callback
// and extracts the ID token from the oauth2 token.
func (a *AuthProviderOIDC) extractIDToken(
	ctx context.Context,
	code string,
	state string,
) (*oidc.IDToken, error) {
	var exchangeOpts []oauth2.AuthCodeOption

	if a.cfg.PKCE.Enabled {
		regInfo, ok := a.registrationCache.Get(state)
		if !ok {
			return nil, errNoOIDCRegistrationInfo
		}
		if regInfo.Verifier != nil {
			exchangeOpts = []oauth2.AuthCodeOption{oauth2.VerifierOption(*regInfo.Verifier)}
		}
	}

	oauth2Token, err := a.oauth2Config.Exchange(ctx, code, exchangeOpts...)
	if err != nil {
		return nil, fmt.Errorf("could not exchange code for token: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errNoOIDCIDToken
	}

	verifier := a.oidcProvider.Verifier(&oidc.Config{ClientID: a.cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
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
			return errOIDCAllowedDomains
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

		return errOIDCAllowedGroups
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
		log.Trace().Msg("authenticated principal does not match any allowed user")
		return errOIDCAllowedUsers
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
) (*types.User, error) {
	var user *types.User
	var err error
	user, err = a.db.GetUserByOIDCIdentifier(claims.Identifier())
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, fmt.Errorf("creating or updating user: %w", err)
	}

	// This check is for legacy, if the user cannot be found by the OIDC identifier
	// look it up by username. This should only be needed once.
	// This branch will persist for a number of versions after the OIDC migration and
	// then be removed following a deprecation.
	// TODO(kradalby): Remove when strip_email_domain and migration is removed
	// after #2170 is cleaned up.
	if a.cfg.MapLegacyUsers && user == nil {
		log.Trace().Str("username", claims.Username).Str("sub", claims.Sub).Msg("user not found by OIDC identifier, looking up by username")
		if oldUsername, err := getUserName(claims, a.cfg.StripEmaildomain); err == nil {
			log.Trace().Str("old_username", oldUsername).Str("sub", claims.Sub).Msg("found username")
			user, err = a.db.GetUserByName(oldUsername)
			if err != nil && !errors.Is(err, db.ErrUserNotFound) {
				return nil, fmt.Errorf("getting user: %w", err)
			}

			// If the user exists, but it already has a provider identifier (OIDC sub), create a new user.
			// This is to prevent users that have already been migrated to the new OIDC format
			// to be updated with the new OIDC identifier inexplicitly which might be the cause of an
			// account takeover.
			if user != nil && user.ProviderIdentifier.Valid {
				log.Info().Str("username", claims.Username).Str("sub", claims.Sub).Msg("user found by username, but has provider identifier, creating new user.")
				user = &types.User{}
			}
		}
	}

	// if the user is still not found, create a new empty user.
	if user == nil {
		user = &types.User{}
	}

	user.FromClaim(claims)
	err = a.db.DB.Save(user).Error
	if err != nil {
		return nil, fmt.Errorf("creating or updating user: %w", err)
	}

	err = usersChangedHook(a.db, a.polMan, a.notifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using user: %w", err)
	}

	return user, nil
}

func (a *AuthProviderOIDC) handleRegistrationID(
	user *types.User,
	registrationID types.RegistrationID,
	expiry time.Time,
) (bool, error) {
	ipv4, ipv6, err := a.ipAlloc.Next()
	if err != nil {
		return false, err
	}

	node, newNode, err := a.db.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		&expiry,
		util.RegisterMethodOIDC,
		ipv4, ipv6,
	)
	if err != nil {
		return false, fmt.Errorf("could not register node: %w", err)
	}

	// Send an update to all nodes if this is a new node that they need to know
	// about.
	// If this is a refresh, just send new expiry updates.
	if newNode {
		err = nodesChangedHook(a.db, a.polMan, a.notifier)
		if err != nil {
			return false, fmt.Errorf("updating resources using node: %w", err)
		}
	} else {
		ctx := types.NotifyCtx(context.Background(), "oidc-expiry-self", node.Hostname)
		a.notifier.NotifyByNodeID(
			ctx,
			types.StateUpdate{
				Type:        types.StateSelfUpdate,
				ChangeNodes: []types.NodeID{node.ID},
			},
			node.ID,
		)

		ctx = types.NotifyCtx(context.Background(), "oidc-expiry-peers", node.Hostname)
		a.notifier.NotifyWithIgnore(ctx, types.StateUpdateExpire(node.ID, expiry), node.ID)
	}

	return newNode, nil
}

// TODO(kradalby):
// Rewrite in elem-go.
func renderOIDCCallbackTemplate(
	user *types.User,
	verb string,
) (*bytes.Buffer, error) {
	var content bytes.Buffer
	if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
		User: user.DisplayNameOrUsername(),
		Verb: verb,
	}); err != nil {
		return nil, fmt.Errorf("rendering OIDC callback template: %w", err)
	}

	return &content, nil
}

// TODO(kradalby): Reintroduce when strip_email_domain is removed
// after #2170 is cleaned up
// DEPRECATED: DO NOT USE.
func getUserName(
	claims *types.OIDCClaims,
	stripEmaildomain bool,
) (string, error) {
	if !claims.EmailVerified {
		return "", fmt.Errorf("email not verified")
	}
	userName, err := util.NormalizeToFQDNRules(
		claims.Email,
		stripEmaildomain,
	)
	if err != nil {
		return "", err
	}

	return userName, nil
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
