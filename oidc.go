package headscale

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"tailscale.com/types/key"
)

const (
	randomByteSize = 16

	errEmptyOIDCCallbackParams = Error("empty OIDC callback params")
	errNoOIDCIDToken           = Error("could not extract ID Token for OIDC callback")
	errOIDCAllowedDomains      = Error("authenticated principal does not match any allowed domain")
	errOIDCAllowedGroups       = Error("authenticated principal is not in any allowed group")
	errOIDCAllowedUsers        = Error("authenticated principal does not match any allowed user")
	errOIDCInvalidMachineState = Error("requested machine state key expired before authorisation completed")
	errOIDCNodeKeyMissing      = Error("could not get node key from cache")
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
			log.Error().
				Err(err).
				Caller().
				Msgf("Could not retrieve OIDC Config: %s", err.Error())

			return err
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

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts NodeKey in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:nKey.
func (h *Headscale) RegisterOIDC(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	nodeKeyStr, ok := vars["nkey"]

	log.Debug().
		Caller().
		Str("node_key", nodeKeyStr).
		Bool("ok", ok).
		Msg("Received oidc register call")

	if !NodePublicKeyRegex.Match([]byte(nodeKeyStr)) {
		log.Warn().Str("node_key", nodeKeyStr).Msg("Invalid node key passed to registration url")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_, err := writer.Write([]byte("Unauthorized"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	// We need to make sure we dont open for XSS style injections, if the parameter that
	// is passed as a key is not parsable/validated as a NodePublic key, then fail to render
	// the template and log an error.
	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText(
		[]byte(NodePublicKeyEnsurePrefix(nodeKeyStr)),
	)

	if !ok || nodeKeyStr == "" || err != nil {
		log.Warn().
			Err(err).
			Msg("Failed to parse incoming nodekey in OIDC registration")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Wrong params"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	randomBlob := make([]byte, randomByteSize)
	if _, err := rand.Read(randomBlob); err != nil {
		log.Error().
			Caller().
			Msg("could not read 16 bytes from rand")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	stateStr := hex.EncodeToString(randomBlob)[:32]

	// place the node key into the state cache, so it can be retrieved later
	h.registrationCache.Set(stateStr, NodePublicKeyStripPrefix(nodeKey), registerCacheExpiration)

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

var oidcCallbackTemplate = template.Must(
	template.New("oidccallback").Parse(`<html>
	<body>
	<h1>headscale</h1>
	<p>
			{{.Verb}} as {{.User}}, you can now close this window.
	</p>
	</body>
	</html>`),
)

// OIDCCallback handles the callback from the OIDC endpoint
// Retrieves the nkey from the state cache and adds the machine to the users email user
// TODO: A confirmation page for new machines should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into machine HostInfo
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

	nodeKey, machineExists, err := h.validateMachineForOIDCCallback(writer, state, claims, idToken.Expiry)
	if err != nil || machineExists {
		return
	}

	userName, err := getUserName(writer, claims, h.cfg.OIDC.StripEmaildomain)
	if err != nil {
		return
	}

	// register the machine if it's new
	log.Debug().Msg("Registering new machine after successful callback")

	user, err := h.findOrCreateNewUserForOIDCCallback(writer, userName)
	if err != nil {
		return
	}

	if err := h.registerMachineForOIDCCallback(writer, user, nodeKey, idToken.Expiry); err != nil {
		return
	}

	content, err := renderOIDCCallbackTemplate(writer, claims)
	if err != nil {
		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(content.Bytes()); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
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
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
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
		log.Error().
			Err(err).
			Caller().
			Msg("Could not exchange code for token")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("Could not exchange code for token"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
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
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
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
		log.Error().
			Err(err).
			Caller().
			Msg("failed to verify id token")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("Failed to verify id token"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
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
		log.Error().
			Err(err).
			Caller().
			Msg("Failed to decode id token claims")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("Failed to decode id token claims"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
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
			!IsStringInSlice(allowedDomains, claims.Email[at+1:]) {
			log.Error().Msg("authenticated principal does not match any allowed domain")
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusBadRequest)
			_, err := writer.Write([]byte("unauthorized principal (domain mismatch)"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
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
			if IsStringInSlice(claims.Groups, group) {
				return nil
			}
		}

		log.Error().Msg("authenticated principal not in any allowed groups")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("unauthorized principal (allowed groups)"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
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
		!IsStringInSlice(allowedUsers, claims.Email) {
		log.Error().Msg("authenticated principal does not match any allowed user")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("unauthorized principal (user mismatch)"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return errOIDCAllowedUsers
	}

	return nil
}

// validateMachine retrieves machine information if it exist
// The error is not important, because if it does not
// exist, then this is a new machine and we will move
// on to registration.
func (h *Headscale) validateMachineForOIDCCallback(
	writer http.ResponseWriter,
	state string,
	claims *IDTokenClaims,
	expiry time.Time,
) (*key.NodePublic, bool, error) {
	// retrieve machinekey from state cache
	nodeKeyIf, nodeKeyFound := h.registrationCache.Get(state)
	if !nodeKeyFound {
		log.Error().
			Msg("requested machine state key expired before authorisation completed")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("state has expired"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false, errOIDCNodeKeyMissing
	}

	var nodeKey key.NodePublic
	nodeKeyFromCache, nodeKeyOK := nodeKeyIf.(string)
	if !nodeKeyOK {
		log.Error().
			Msg("requested machine state key is not a string")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("state is invalid"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false, errOIDCInvalidMachineState
	}

	err := nodeKey.UnmarshalText(
		[]byte(NodePublicKeyEnsurePrefix(nodeKeyFromCache)),
	)
	if err != nil {
		log.Error().
			Str("nodeKey", nodeKeyFromCache).
			Bool("nodeKeyOK", nodeKeyOK).
			Msg("could not parse node public key")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, werr := writer.Write([]byte("could not parse node public key"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
		}

		return nil, false, err
	}

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.GetMachineByNodeKey(nodeKey)

	if machine != nil {
		log.Trace().
			Caller().
			Str("machine", machine.Hostname).
			Msg("machine already registered, reauthenticating")

		err := h.RefreshMachine(machine, expiry)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to refresh machine")
			http.Error(
				writer,
				"Failed to refresh machine",
				http.StatusInternalServerError,
			)

			return nil, true, err
		}
		log.Debug().
			Str("machine", machine.Hostname).
			Str("expiresAt", fmt.Sprintf("%v", expiry)).
			Msg("successfully refreshed machine")

		var content bytes.Buffer
		if err := oidcCallbackTemplate.Execute(&content, oidcCallbackTemplateConfig{
			User: claims.Email,
			Verb: "Reauthenticated",
		}); err != nil {
			log.Error().
				Str("func", "OIDCCallback").
				Str("type", "reauthenticate").
				Err(err).
				Msg("Could not render OIDC callback template")

			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, werr := writer.Write([]byte("Could not render OIDC callback template"))
			if werr != nil {
				log.Error().
					Caller().
					Err(werr).
					Msg("Failed to write response")
			}

			return nil, true, err
		}

		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err = writer.Write(content.Bytes())
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, true, nil
	}

	return &nodeKey, false, nil
}

func getUserName(
	writer http.ResponseWriter,
	claims *IDTokenClaims,
	stripEmaildomain bool,
) (string, error) {
	userName, err := NormalizeToFQDNRules(
		claims.Email,
		stripEmaildomain,
	)
	if err != nil {
		log.Error().Err(err).Caller().Msgf("couldn't normalize email")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("couldn't normalize email"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
		}

		return "", err
	}

	return userName, nil
}

func (h *Headscale) findOrCreateNewUserForOIDCCallback(
	writer http.ResponseWriter,
	userName string,
) (*User, error) {
	user, err := h.GetUser(userName)
	if errors.Is(err, ErrUserNotFound) {
		user, err = h.CreateUser(userName)

		if err != nil {
			log.Error().
				Err(err).
				Caller().
				Msgf("could not create new user '%s'", userName)
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, werr := writer.Write([]byte("could not create user"))
			if werr != nil {
				log.Error().
					Caller().
					Err(werr).
					Msg("Failed to write response")
			}

			return nil, err
		}
	} else if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("user", userName).
			Msg("could not find or create user")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("could not find or create user"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
		}

		return nil, err
	}

	return user, nil
}

func (h *Headscale) registerMachineForOIDCCallback(
	writer http.ResponseWriter,
	user *User,
	nodeKey *key.NodePublic,
	expiry time.Time,
) error {
	if _, err := h.RegisterMachineFromAuthCallback(
		nodeKey.String(),
		user.Name,
		&expiry,
		RegisterMethodOIDC,
	); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("could not register machine")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("could not register machine"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
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
		log.Error().
			Str("func", "OIDCCallback").
			Str("type", "authenticate").
			Err(err).
			Msg("Could not render OIDC callback template")

		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, werr := writer.Write([]byte("Could not render OIDC callback template"))
		if werr != nil {
			log.Error().
				Caller().
				Err(werr).
				Msg("Failed to write response")
		}

		return nil, err
	}

	return &content, nil
}
