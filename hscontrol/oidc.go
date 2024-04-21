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
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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

type IDTokenClaims struct {
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Email    string   `json:"email"`
	Username string   `json:"preferred_username,omitempty"`
}

func (h *Headscale) initOIDC() error {
	var err error
	// grab oidc config if it hasn't been already
	if h.oauth2Config == nil {
		h.oidcProvider, err = oidc.NewProvider(context.Background(), h.cfg.OIDC.Issuer)

		if err != nil {
			return fmt.Errorf("creating OIDC provider from issuer config: %w", err)
		}

		h.oauth2Config = &oauth2.Config{
			ClientID:     h.cfg.OIDC.ClientID,
			ClientSecret: h.cfg.OIDC.ClientSecret,
			Endpoint:     h.oidcProvider.Endpoint(),
			RedirectURL: fmt.Sprintf(
				"%s/oidc/callback",
				strings.TrimSuffix(h.cfg.ServerURL, "/"),
			),
			Scopes: h.cfg.OIDC.Scope,
		}
	}

	return nil
}

func (h *Headscale) determineTokenExpiration(idTokenExpiration time.Time) time.Time {
	if h.cfg.OIDC.UseExpiryFromToken {
		return idTokenExpiration
	}

	return time.Now().Add(h.cfg.OIDC.Expiry)
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts NodeKey in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:mKey.
func (h *Headscale) RegisterOIDC(
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
		log.Warn().
			Err(err).
			Msg("Failed to parse incoming nodekey in OIDC registration")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Wrong params"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return
	}

	randomBlob := make([]byte, randomByteSize)
	if _, err := rand.Read(randomBlob); err != nil {
		util.LogErr(err, "could not read 16 bytes from rand")

		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	stateStr := hex.EncodeToString(randomBlob)[:32]

	// place the node key into the state cache, so it can be retrieved later
	h.registrationCache.Set(
		stateStr,
		machineKey,
		registerCacheExpiration,
	)

	// Add any extra parameter provided in the configuration to the Authorize Endpoint request
	extras := make([]oauth2.AuthCodeOption, 0, len(h.cfg.OIDC.ExtraParams))

	for k, v := range h.cfg.OIDC.ExtraParams {
		extras = append(extras, oauth2.SetAuthURLParam(k, v))
	}

	authURL := h.oauth2Config.AuthCodeURL(stateStr, extras...)
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
func (h *Headscale) OIDCCallback(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, err := validateOIDCCallbackParams(writer, req)
	if err != nil {
		return
	}

	rawIDToken, err := h.getIDTokenForOIDCCallback(req.Context(), writer, code, state)
	if err != nil {
		return
	}

	idToken, err := h.verifyIDTokenForOIDCCallback(req.Context(), writer, rawIDToken)
	if err != nil {
		return
	}
	idTokenExpiry := h.determineTokenExpiration(idToken.Expiry)

	// TODO: we can use userinfo at some point to grab additional information about the user (groups membership, etc)
	// userInfo, err := oidcProvider.UserInfo(context.Background(), oauth2.StaticTokenSource(oauth2Token))
	// if err != nil {
	// 	c.String(http.StatusBadRequest, fmt.Sprintf("Failed to retrieve userinfo"))
	// 	return
	// }

	claims, err := extractIDTokenClaims(writer, idToken)
	if err != nil {
		return
	}

	if err := validateOIDCAllowedDomains(writer, h.cfg.OIDC.AllowedDomains, claims); err != nil {
		return
	}

	if err := validateOIDCAllowedGroups(writer, h.cfg.OIDC.AllowedGroups, claims); err != nil {
		return
	}

	if err := validateOIDCAllowedUsers(writer, h.cfg.OIDC.AllowedUsers, claims); err != nil {
		return
	}

	machineKey, nodeExists, err := h.validateNodeForOIDCCallback(
		writer,
		state,
		claims,
		idTokenExpiry,
	)
	if err != nil || nodeExists {
		return
	}

	userName, err := getUserName(writer, claims, h.cfg.OIDC.StripEmaildomain)
	if err != nil {
		return
	}

	// register the node if it's new
	log.Debug().Msg("Registering new node after successful callback")

	user, err := h.findOrCreateNewUserForOIDCCallback(writer, userName)
	if err != nil {
		return
	}

	if err := h.registerNodeForOIDCCallback(writer, user, machineKey, idTokenExpiry); err != nil {
		return
	}

	content, err := renderOIDCCallbackTemplate(writer, claims)
	if err != nil {
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(content.Bytes()); err != nil {
		util.LogErr(err, "Failed to write response")
	}
}

func validateOIDCCallbackParams(
	writer http.ResponseWriter,
	req *http.Request,
) (string, string, error) {
	code := req.URL.Query().Get("code")
	state := req.URL.Query().Get("state")

	if code == "" || state == "" {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Wrong params"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return "", "", errEmptyOIDCCallbackParams
	}

	return code, state, nil
}

func (h *Headscale) getIDTokenForOIDCCallback(
	ctx context.Context,
	writer http.ResponseWriter,
	code, state string,
) (string, error) {
	oauth2Token, err := h.oauth2Config.Exchange(ctx, code)
	if err != nil {
		util.LogErr(err, "Could not exchange code for token")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("Could not exchange code for token"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return "", err
	}

	log.Trace().
		Caller().
		Str("code", code).
		Str("state", state).
		Msg("Got oidc callback")

	rawIDToken, rawIDTokenOK := oauth2Token.Extra("id_token").(string)
	if !rawIDTokenOK {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Could not extract ID Token"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return "", errNoOIDCIDToken
	}

	return rawIDToken, nil
}

func (h *Headscale) verifyIDTokenForOIDCCallback(
	ctx context.Context,
	writer http.ResponseWriter,
	rawIDToken string,
) (*oidc.IDToken, error) {
	verifier := h.oidcProvider.Verifier(&oidc.Config{ClientID: h.cfg.OIDC.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		util.LogErr(err, "failed to verify id token")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("Failed to verify id token"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return nil, err
	}

	return idToken, nil
}

func extractIDTokenClaims(
	writer http.ResponseWriter,
	idToken *oidc.IDToken,
) (*IDTokenClaims, error) {
	var claims IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		util.LogErr(err, "Failed to decode id token claims")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("Failed to decode id token claims"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return nil, err
	}

	return &claims, nil
}

// validateOIDCAllowedDomains checks that if AllowedDomains is provided,
// that the authenticated principal ends with @<alloweddomain>.
func validateOIDCAllowedDomains(
	writer http.ResponseWriter,
	allowedDomains []string,
	claims *IDTokenClaims,
) error {
	if len(allowedDomains) > 0 {
		if at := strings.LastIndex(claims.Email, "@"); at < 0 ||
			!util.IsStringInSlice(allowedDomains, claims.Email[at+1:]) {
			log.Trace().Msg("authenticated principal does not match any allowed domain")

			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusBadRequest)
			_, err := writer.Write([]byte("unauthorized principal (domain mismatch)"))
			if err != nil {
				util.LogErr(err, "Failed to write response")
			}

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
	writer http.ResponseWriter,
	allowedGroups []string,
	claims *IDTokenClaims,
) error {
	if len(allowedGroups) > 0 {
		for _, group := range allowedGroups {
			if util.IsStringInSlice(claims.Groups, group) {
				return nil
			}
		}

		log.Trace().Msg("authenticated principal not in any allowed groups")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("unauthorized principal (allowed groups)"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return errOIDCAllowedGroups
	}

	return nil
}

// validateOIDCAllowedUsers checks that if AllowedUsers is provided,
// that the authenticated principal is part of that list.
func validateOIDCAllowedUsers(
	writer http.ResponseWriter,
	allowedUsers []string,
	claims *IDTokenClaims,
) error {
	if len(allowedUsers) > 0 &&
		!util.IsStringInSlice(allowedUsers, claims.Email) {
		log.Trace().Msg("authenticated principal does not match any allowed user")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("unauthorized principal (user mismatch)"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return errOIDCAllowedUsers
	}

	return nil
}

// validateNode retrieves node information if it exist
// The error is not important, because if it does not
// exist, then this is a new node and we will move
// on to registration.
func (h *Headscale) validateNodeForOIDCCallback(
	writer http.ResponseWriter,
	state string,
	claims *IDTokenClaims,
	expiry time.Time,
) (*key.MachinePublic, bool, error) {
	// retrieve nodekey from state cache
	machineKeyIf, machineKeyFound := h.registrationCache.Get(state)
	if !machineKeyFound {
		log.Trace().
			Msg("requested node state key expired before authorisation completed")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("state has expired"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return nil, false, errOIDCNodeKeyMissing
	}

	var machineKey key.MachinePublic
	machineKey, machineKeyOK := machineKeyIf.(key.MachinePublic)
	if !machineKeyOK {
		log.Trace().
			Interface("got", machineKeyIf).
			Msg("requested node state key is not a nodekey")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("state is invalid"))
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		return nil, false, errOIDCInvalidNodeState
	}

	// retrieve node information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new node and we will move
	// on to registration.
	node, _ := h.db.GetNodeByMachineKey(machineKey)

	if node != nil {
		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Msg("node already registered, reauthenticating")

		err := h.db.NodeSetExpiry(node.ID, expiry)
		if err != nil {
			util.LogErr(err, "Failed to refresh node")
			http.Error(
				writer,
				"Failed to refresh node",
				http.StatusInternalServerError,
			)

			return nil, true, err
		}
		log.Debug().
			Str("node", node.Hostname).
			Str("expiresAt", fmt.Sprintf("%v", expiry)).
			Msg("successfully refreshed node")

		var content bytes.Buffer
		if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
			User: claims.Email,
			Verb: "Reauthenticated",
		}); err != nil {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, werr := writer.Write([]byte("Could not render OIDC callback template"))
			if werr != nil {
				util.LogErr(err, "Failed to write response")
			}

			return nil, true, fmt.Errorf("rendering OIDC callback template: %w", err)
		}

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err = writer.Write(content.Bytes())
		if err != nil {
			util.LogErr(err, "Failed to write response")
		}

		ctx := types.NotifyCtx(context.Background(), "oidc-expiry", "na")
		h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdateExpire(node.ID, expiry), node.ID)

		return nil, true, nil
	}

	return &machineKey, false, nil
}

func getUserName(
	writer http.ResponseWriter,
	claims *IDTokenClaims,
	stripEmaildomain bool,
) (string, error) {
	userName, err := util.NormalizeToFQDNRules(
		claims.Email,
		stripEmaildomain,
	)
	if err != nil {
		util.LogErr(err, "couldn't normalize email")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("couldn't normalize email"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return "", err
	}

	return userName, nil
}

func (h *Headscale) findOrCreateNewUserForOIDCCallback(
	writer http.ResponseWriter,
	userName string,
) (*types.User, error) {
	user, err := h.db.GetUser(userName)
	if errors.Is(err, db.ErrUserNotFound) {
		user, err = h.db.CreateUser(userName)
		if err != nil {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, werr := writer.Write([]byte("could not create user"))
			if werr != nil {
				util.LogErr(err, "Failed to write response")
			}

			return nil, fmt.Errorf("creating new user: %w", err)
		}
	} else if err != nil {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("could not find or create user"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return nil, fmt.Errorf("find or create user: %w", err)
	}

	return user, nil
}

func (h *Headscale) registerNodeForOIDCCallback(
	writer http.ResponseWriter,
	user *types.User,
	machineKey *key.MachinePublic,
	expiry time.Time,
) error {
	ipv4, ipv6, err := h.ipAlloc.Next()
	if err != nil {
		return err
	}

	if err := h.db.Write(func(tx *gorm.DB) error {
		if _, err := db.RegisterNodeFromAuthCallback(
			// TODO(kradalby): find a better way to use the cache across modules
			tx,
			h.registrationCache,
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
		util.LogErr(err, "could not register node")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("could not register node"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return err
	}

	return nil
}

func renderOIDCCallbackTemplate(
	writer http.ResponseWriter,
	claims *IDTokenClaims,
) (*bytes.Buffer, error) {
	var content bytes.Buffer
	if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
		User: claims.Email,
		Verb: "Authenticated",
	}); err != nil {
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("Could not render OIDC callback template"))
		if werr != nil {
			util.LogErr(err, "Failed to write response")
		}

		return nil, fmt.Errorf("rendering OIDC callback template: %w", err)
	}

	return &content, nil
}
