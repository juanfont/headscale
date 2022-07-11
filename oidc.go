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
// Puts machine key in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:mKey.
func (h *Headscale) RegisterOIDC(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr, ok := vars["mkey"]
	if !ok || machineKeyStr == "" {
		log.Error().
			Caller().
			Msg("Missing machine key in URL")
		http.Error(writer, "Missing machine key in URL", http.StatusBadRequest)

		return
	}

	log.Trace().
		Caller().
		Str("machine_key", machineKeyStr).
		Msg("Received oidc register call")

	randomBlob := make([]byte, randomByteSize)
	if _, err := rand.Read(randomBlob); err != nil {
		log.Error().
			Caller().
			Msg("could not read 16 bytes from rand")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	stateStr := hex.EncodeToString(randomBlob)[:32]

	// place the machine key into the state cache, so it can be retrieved later
	h.registrationCache.Set(stateStr, machineKeyStr, registerCacheExpiration)

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
// Retrieves the mkey from the state cache and adds the machine to the users email namespace
// TODO: A confirmation page for new machines should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into machine HostInfo
// Listens in /oidc/callback.
func (h *Headscale) OIDCCallback(
	writer http.ResponseWriter,
	req *http.Request,
) {
	code, state, ok := validateOIDCCallbackParams(writer, req)
	if !ok {
		return
	}

	rawIDToken, ok := h.getIDTokenForOIDCCallback(writer, code, state)
	if !ok {
		return
	}

	idToken, ok := h.verifyIDTokenForOIDCCallback(writer, rawIDToken)
	if !ok {
		return
	}

	// TODO: we can use userinfo at some point to grab additional information about the user (groups membership, etc)
	// userInfo, err := oidcProvider.UserInfo(context.Background(), oauth2.StaticTokenSource(oauth2Token))
	// if err != nil {
	// 	c.String(http.StatusBadRequest, fmt.Sprintf("Failed to retrieve userinfo"))
	// 	return
	// }

	claims, ok := extractIDTokenClaims(writer, idToken)
	if !ok {
		return
	}

	if ok := validateOIDCAllowedDomains(writer, h.cfg.OIDC.AllowedDomains, claims); !ok {
		return
	}

	if ok := validateOIDCAllowedUsers(writer, h.cfg.OIDC.AllowedUsers, claims); !ok {
		return
	}

	machineKey, ok := h.validateMachineForOIDCCallback(writer, state, claims)
	if !ok {
		return
	}

	namespaceName, ok := getNamespaceName(writer, claims, h.cfg.OIDC.StripEmaildomain)
	if !ok {
		return
	}

	// register the machine if it's new
	log.Debug().Msg("Registering new machine after successful callback")

	namespace, ok := h.findOrCreateNewNamespaceForOIDCCallback(writer, namespaceName)
	if !ok {
		return
	}

	if ok := h.registerMachineForOIDCCallback(writer, namespace, machineKey); !ok {
		return
	}

	content, ok := renderOIDCCallbackTemplate(writer, claims)
	if !ok {
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
) (string, string, bool) {
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

		return "", "", false
	}

	return code, state, true
}

func (h *Headscale) getIDTokenForOIDCCallback(
	writer http.ResponseWriter,
	code, state string,
) (string, bool) {
	oauth2Token, err := h.oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		log.Error().
			Err(err).
			Caller().
			Msg("Could not exchange code for token")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Could not exchange code for token"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return "", false
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

		return "", false
	}

	return rawIDToken, true
}

func (h *Headscale) verifyIDTokenForOIDCCallback(
	writer http.ResponseWriter,
	rawIDToken string,
) (*oidc.IDToken, bool) {
	verifier := h.oidcProvider.Verifier(&oidc.Config{ClientID: h.cfg.OIDC.ClientID})
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		log.Error().
			Err(err).
			Caller().
			Msg("failed to verify id token")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Failed to verify id token"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false
	}

	return idToken, true
}

func extractIDTokenClaims(
	writer http.ResponseWriter,
	idToken *oidc.IDToken,
) (*IDTokenClaims, bool) {
	var claims IDTokenClaims
	if err := idToken.Claims(claims); err != nil {
		log.Error().
			Err(err).
			Caller().
			Msg("Failed to decode id token claims")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("Failed to decode id token claims"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false
	}

	return &claims, true
}

// validateOIDCAllowedDomains checks that if AllowedDomains is provided,
// that the authenticated principal ends with @<alloweddomain>.
func validateOIDCAllowedDomains(
	writer http.ResponseWriter,
	allowedDomains []string,
	claims *IDTokenClaims,
) bool {
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

			return false
		}
	}

	return true
}

// validateOIDCAllowedUsers checks that if AllowedUsers is provided,
// that the authenticated principal is part of that list.
func validateOIDCAllowedUsers(
	writer http.ResponseWriter,
	allowedUsers []string,
	claims *IDTokenClaims,
) bool {
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

		return false
	}

	return true
}

// validateMachine retrieves machine information if it exist
// The error is not important, because if it does not
// exist, then this is a new machine and we will move
// on to registration.
func (h *Headscale) validateMachineForOIDCCallback(
	writer http.ResponseWriter,
	state string,
	claims *IDTokenClaims,
) (*key.MachinePublic, bool) {
	// retrieve machinekey from state cache
	machineKeyIf, machineKeyFound := h.registrationCache.Get(state)
	if !machineKeyFound {
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

		return nil, false
	}

	var machineKey key.MachinePublic
	machineKeyFromCache, machineKeyOK := machineKeyIf.(string)
	err := machineKey.UnmarshalText(
		[]byte(MachinePublicKeyEnsurePrefix(machineKeyFromCache)),
	)
	if err != nil {
		log.Error().
			Msg("could not parse machine public key")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusBadRequest)
		_, err := writer.Write([]byte("could not parse public key"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false
	}

	if !machineKeyOK {
		log.Error().Msg("could not get machine key from cache")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("could not get machine key from cache"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false
	}

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.GetMachineByMachineKey(machineKey)

	if machine != nil {
		log.Trace().
			Caller().
			Str("machine", machine.Hostname).
			Msg("machine already registered, reauthenticating")

		err := h.RefreshMachine(machine, time.Time{})
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to refresh machine")
			http.Error(writer, "Failed to refresh machine", http.StatusInternalServerError)

			return nil, false
		}

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
			_, err := writer.Write([]byte("Could not render OIDC callback template"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return nil, false
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

		return nil, false
	}

	return &machineKey, true
}

func getNamespaceName(
	writer http.ResponseWriter,
	claims *IDTokenClaims,
	stripEmaildomain bool,
) (string, bool) {
	namespaceName, err := NormalizeToFQDNRules(
		claims.Email,
		stripEmaildomain,
	)
	if err != nil {
		log.Error().Err(err).Caller().Msgf("couldn't normalize email")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("couldn't normalize email"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return "", false
	}

	return namespaceName, true
}

func (h *Headscale) findOrCreateNewNamespaceForOIDCCallback(
	writer http.ResponseWriter,
	namespaceName string,
) (*Namespace, bool) {
	namespace, err := h.GetNamespace(namespaceName)
	if errors.Is(err, errNamespaceNotFound) {
		namespace, err = h.CreateNamespace(namespaceName)

		if err != nil {
			log.Error().
				Err(err).
				Caller().
				Msgf("could not create new namespace '%s'", namespaceName)
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusInternalServerError)
			_, err := writer.Write([]byte("could not create namespace"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return nil, false
		}
	} else if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("namespace", namespaceName).
			Msg("could not find or create namespace")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("could not find or create namespace"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false
	}

	return namespace, true
}

func (h *Headscale) registerMachineForOIDCCallback(
	writer http.ResponseWriter,
	namespace *Namespace,
	machineKey *key.MachinePublic,
) bool {
	machineKeyStr := MachinePublicKeyStripPrefix(*machineKey)

	if _, err := h.RegisterMachineFromAuthCallback(
		machineKeyStr,
		namespace.Name,
		RegisterMethodOIDC,
	); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("could not register machine")
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusInternalServerError)
		_, err := writer.Write([]byte("could not register machine"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return false
	}

	return true
}

func renderOIDCCallbackTemplate(
	writer http.ResponseWriter,
	claims *IDTokenClaims,
) (*bytes.Buffer, bool) {
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
		_, err := writer.Write([]byte("Could not render OIDC callback template"))
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return nil, false
	}

	return &content, true
}
