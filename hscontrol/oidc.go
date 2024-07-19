package hscontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
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
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"tailscale.com/types/key"
)

const (
	randomByteSize = 16
)

var (
	errEmptyOIDCCallbackParams = errors.New("empty OIDC callback params")
	errNoOIDCIDToken           = errors.New("could not extract ID Token for OIDC callback")
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

type AuthProviderOIDC struct {
	serverURL         string
	cfg               *types.OIDCConfig
	db                *db.HSDatabase
	registrationCache *cache.Cache
	notifier          *notifier.Notifier
	ipAlloc           *db.IPAllocator

	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

func NewAuthProviderOIDC(ctx context.Context, serverURL string, cfg *types.OIDCConfig, db *db.HSDatabase, registrationCache *cache.Cache, notif *notifier.Notifier, ipAlloc *db.IPAllocator) (*AuthProviderOIDC, error) {
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

	return &AuthProviderOIDC{
		serverURL:         serverURL,
		cfg:               cfg,
		db:                db,
		registrationCache: registrationCache,
		notifier:          notif,
		ipAlloc:           ipAlloc,

		oidcProvider: oidcProvider,
		oauth2Config: oauth2Config,
	}, nil
}

func (a *AuthProviderOIDC) AuthURL(mKey key.MachinePublic) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		mKey.String())
}

func (a *AuthProviderOIDC) determineTokenExpiration(idTokenExpiration time.Time) time.Time {
	if a.cfg.UseExpiryFromToken {
		return idTokenExpiration
	}

	return time.Now().Add(a.cfg.Expiry)
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts NodeKey in cache so the callback can retrieve it using the oidc state param
// Listens in /register/:mKey.
func (a *AuthProviderOIDC) RegisterHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr, ok := vars["mkey"]

	log.Debug().
		Caller().
		Str("machine_key", machineKeyStr).
		Bool("ok", ok).
		Msg("Received oidc register call")

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText(
		[]byte(machineKeyStr),
	)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	randomBlob := make([]byte, randomByteSize)
	if _, err := rand.Read(randomBlob); err != nil {
		http.Error(writer, "Internal server error", http.StatusInternalServerError)
		return
	}

	stateStr := hex.EncodeToString(randomBlob)[:32]

	// place the node key into the state cache, so it can be retrieved later
	a.registrationCache.Set(
		stateStr,
		machineKey,
		registerCacheExpiration,
	)

	// Add any extra parameter provided in the configuration to the Authorize Endpoint request
	extras := make([]oauth2.AuthCodeOption, 0, len(a.cfg.ExtraParams))

	for k, v := range a.cfg.ExtraParams {
		extras = append(extras, oauth2.SetAuthURLParam(k, v))
	}

	authURL := a.oauth2Config.AuthCodeURL(stateStr, extras...)
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

// OIDCCallback handles the callback from the OIDC endpoint
// Retrieves the nkey from the state cache and adds the node to the users email user
// TODO: A confirmation page for new nodes should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into node HostInfo
// Listens in /oidc/callback.
func (a *AuthProviderOIDC) OIDCCallback(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, err := validateOIDCCallbackParams(req)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	rawIDToken, err := a.getIDTokenForOIDCCallback(req.Context(), code)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}

	idToken, err := a.verifyIDTokenForOIDCCallback(req.Context(), rawIDToken)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	idTokenExpiry := a.determineTokenExpiration(idToken.Expiry)

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

	machineKey, nodeExists, err := a.validateNodeForOIDCCallback(
		writer,
		state,
		&claims,
		idTokenExpiry,
	)
	if err != nil || nodeExists {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	// register the node if it's new
	log.Debug().Msg("Registering new node after successful callback")

	user, err := a.createOrUpdateUserFromClaim(&claims)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.registerNodeForOIDCCallback(user, machineKey, idTokenExpiry); err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	content, err := renderOIDCCallbackTemplate(&claims)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(content.Bytes()); err != nil {
		util.LogErr(err, "Failed to write response")
	}
}

func validateOIDCCallbackParams(
	req *http.Request,
) (string, string, error) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" || state == "" {
		return "", "", errEmptyOIDCCallbackParams
	}

	return code, state, nil
}

func (a *AuthProviderOIDC) getIDTokenForOIDCCallback(
	ctx context.Context,
	code string,
) (string, error) {
	oauth2Token, err := a.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("could not exchange code for token: %w", err)
	}

	rawIDToken, rawIDTokenOK := oauth2Token.Extra("id_token").(string)
	if !rawIDTokenOK {
		return "", errNoOIDCIDToken
	}

	return rawIDToken, nil
}

func (a *AuthProviderOIDC) verifyIDTokenForOIDCCallback(
	ctx context.Context,
	rawIDToken string,
) (*oidc.IDToken, error) {
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

// validateNode retrieves node information if it exist
// The error is not important, because if it does not
// exist, then this is a new node and we will move
// on to registration.
func (a *AuthProviderOIDC) validateNodeForOIDCCallback(
	writer http.ResponseWriter,
	state string,
	claims *types.OIDCClaims,
	expiry time.Time,
) (*key.MachinePublic, bool, error) {
	// retrieve nodekey from state cache
	machineKeyIf, machineKeyFound := a.registrationCache.Get(state)
	if !machineKeyFound {
		return nil, false, errOIDCNodeKeyMissing
	}

	var machineKey key.MachinePublic
	machineKey, machineKeyOK := machineKeyIf.(key.MachinePublic)
	if !machineKeyOK {
		return nil, false, errOIDCInvalidNodeState
	}

	// retrieve node information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new node and we will move
	// on to registration.
	node, _ := a.db.GetNodeByMachineKey(machineKey)

	if node != nil {
		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Msg("node already registered, reauthenticating")

		err := a.db.NodeSetExpiry(node.ID, expiry)
		if err != nil {
			return nil, true, err
		}
		log.Debug().
			Str("node", node.Hostname).
			Time("expiresAt", expiry).
			Msg("successfully refreshed node")

		var content bytes.Buffer
		if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
			User: claims.Email,
			Verb: "Reauthenticated",
		}); err != nil {
			return nil, true, fmt.Errorf("rendering OIDC callback template: %w", err)
		}

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err = writer.Write(content.Bytes())
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		ctx := types.NotifyCtx(context.Background(), "oidc-expiry", "na")
		a.notifier.NotifyWithIgnore(ctx, types.StateUpdateExpire(node.ID, expiry), node.ID)

		return nil, true, nil
	}

	return &machineKey, false, nil
}

func (a *AuthProviderOIDC) createOrUpdateUserFromClaim(
	claims *types.OIDCClaims,
) (*types.User, error) {
	var user *types.User
	var err error
	user, err = a.db.GetUserByOIDCIdentifier(claims.Sub)
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		return nil, fmt.Errorf("creating or updating user: %w", err)
	}

	// This check is for legacy, if the user cannot be found by the OIDC identifier
	// look it up by username. This should only be needed once.
	if user == nil {
		user, err = a.db.GetUserByName(claims.Username)
		if err != nil && !errors.Is(err, db.ErrUserNotFound) {
			return nil, fmt.Errorf("creating or updating user: %w", err)
		}

		// if the user is still not found, create a new empty user.
		if user == nil {
			user = &types.User{}
		}
	}

	user.FromClaim(claims)
	err = a.db.DB.Save(user).Error
	if err != nil {
		return nil, fmt.Errorf("creating or updating user: %w", err)
	}

	return user, nil
}

func (a *AuthProviderOIDC) registerNodeForOIDCCallback(
	user *types.User,
	machineKey *key.MachinePublic,
	expiry time.Time,
) error {
	ipv4, ipv6, err := a.ipAlloc.Next()
	if err != nil {
		return err
	}

	if err := a.db.Write(func(tx *gorm.DB) error {
		if _, err := db.RegisterNodeFromAuthCallback(
			// TODO(kradalby): find a better way to use the cache across modules
			tx,
			a.registrationCache,
			*machineKey,
			user.Name,
			&expiry,
			util.RegisterMethodOIDC,
			ipv4, ipv6,
		); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return fmt.Errorf("could not register node: %w", err)
	}

	return nil
}

func renderOIDCCallbackTemplate(
	claims *types.OIDCClaims,
) (*bytes.Buffer, error) {
	var content bytes.Buffer
	if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
		User: claims.Email,
		Verb: "Authenticated",
	}); err != nil {
		return nil, fmt.Errorf("rendering OIDC callback template: %w", err)
	}

	return &content, nil
}
