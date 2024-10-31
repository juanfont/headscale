package hscontrol

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/templates"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"tailscale.com/types/key"
	"zgo.at/zcache/v2"
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
	registrationCache *zcache.Cache[string, key.MachinePublic]
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

	registrationCache := zcache.New[string, key.MachinePublic](
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

func (a *AuthProviderOIDC) AuthURL(mKey key.MachinePublic) string {
	return fmt.Sprintf(
		"%s/register/%s",
		strings.TrimSuffix(a.serverURL, "/"),
		mKey.String())
}

func (a *AuthProviderOIDC) determineNodeExpiry(idTokenExpiration time.Time) time.Time {
	if a.cfg.UseExpiryFromToken {
		return idTokenExpiration
	}

	return time.Now().Add(a.cfg.Expiry)
}

// RegisterHandler redirects to the OIDC provider for authentication
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

	idToken, err := a.extractIDToken(req.Context(), code)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
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

	// Retrieve the node and the machine key from the state cache and
	// database.
	// If the node exists, then the node should be reauthenticated,
	// if the node does not exist, and the machine key exists, then
	// this is a new node that should be registered.
	node, mKey := a.getMachineKeyFromState(state)

	// Reauthenticate the node if it does exists.
	if node != nil {
		err := a.reauthenticateNode(node, nodeExpiry)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		content := templates.OidcCallback(node, user, "Reauthenticated")

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err = writer.Write([]byte(content))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return
	}

	// Register the node if it does not exist.
	if mKey != nil {
		node, err = a.registerNode(user, mKey, nodeExpiry)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}

		content := templates.OidcCallback(node, user, "Authenticated")

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		if _, err := writer.Write([]byte(content)); err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return
	}

	// Neither node nor machine key was found in the state cache meaning
	// that we could not reauth nor register the node.
	http.Error(writer, err.Error(), http.StatusInternalServerError)
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
) (*oidc.IDToken, error) {
	oauth2Token, err := a.oauth2Config.Exchange(ctx, code)
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

// getMachineKeyFromState retrieves the machine key from the state
// cache. If the machine key is found, it will try retrieve the
// node information from the database.
func (a *AuthProviderOIDC) getMachineKeyFromState(state string) (*types.Node, *key.MachinePublic) {
	machineKey, ok := a.registrationCache.Get(state)
	if !ok {
		return nil, nil
	}

	// retrieve node information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new node and we will move
	// on to registration.
	node, _ := a.db.GetNodeByMachineKey(machineKey)

	return node, &machineKey
}

// reauthenticateNode updates the node expiry in the database
// and notifies the node and its peers about the change.
func (a *AuthProviderOIDC) reauthenticateNode(
	node *types.Node,
	expiry time.Time,
) error {
	err := a.db.NodeSetExpiry(node.ID, expiry)
	if err != nil {
		return err
	}

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

	return nil
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
	// This branch will presist for a number of versions after the OIDC migration and
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

func (a *AuthProviderOIDC) registerNode(
	user *types.User,
	machineKey *key.MachinePublic,
	expiry time.Time,
) (*types.Node, error) {
	ipv4, ipv6, err := a.ipAlloc.Next()
	if err != nil {
		return nil, err
	}

	node, err := a.db.RegisterNodeFromAuthCallback(
		*machineKey,
		types.UserID(user.ID),
		&expiry,
		util.RegisterMethodOIDC,
		ipv4, ipv6,
	)
	if err != nil {
		return nil, fmt.Errorf("could not register node: %w", err)
	}

	err = nodesChangedHook(a.db, a.polMan, a.notifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using node: %w", err)
	}

	return node, nil
}

// TODO(kradalby): Reintroduce when strip_email_domain is removed
// after #2170 is cleaned up
// DEPRECATED: DO NOT USE
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
