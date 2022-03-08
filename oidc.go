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

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
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
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		}
	}

	return nil
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts machine key in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:mKey.
func (h *Headscale) RegisterOIDC(ctx *gin.Context) {
	machineKeyStr := ctx.Param("mkey")
	if machineKeyStr == "" {
		ctx.String(http.StatusBadRequest, "Wrong params")

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
		ctx.String(http.StatusInternalServerError, "could not read 16 bytes from rand")

		return
	}

	stateStr := hex.EncodeToString(randomBlob)[:32]

	// place the machine key into the state cache, so it can be retrieved later
	h.registrationCache.Set(stateStr, machineKeyStr, registerCacheExpiration)

	authURL := h.oauth2Config.AuthCodeURL(stateStr)
	log.Debug().Msgf("Redirecting to %s for authentication", authURL)

	ctx.Redirect(http.StatusFound, authURL)
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
func (h *Headscale) OIDCCallback(ctx *gin.Context) {
	code := ctx.Query("code")
	state := ctx.Query("state")

	if code == "" || state == "" {
		ctx.String(http.StatusBadRequest, "Wrong params")

		return
	}

	oauth2Token, err := h.oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		ctx.String(http.StatusBadRequest, "Could not exchange code for token")

		return
	}

	log.Trace().
		Caller().
		Str("code", code).
		Str("state", state).
		Msg("Got oidc callback")

	rawIDToken, rawIDTokenOK := oauth2Token.Extra("id_token").(string)
	if !rawIDTokenOK {
		ctx.String(http.StatusBadRequest, "Could not extract ID Token")

		return
	}

	verifier := h.oidcProvider.Verifier(&oidc.Config{ClientID: h.cfg.OIDC.ClientID})

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		log.Error().
			Err(err).
			Caller().
			Msg("failed to verify id token")
		ctx.String(http.StatusBadRequest, "Failed to verify id token")

		return
	}

	// TODO: we can use userinfo at some point to grab additional information about the user (groups membership, etc)
	// userInfo, err := oidcProvider.UserInfo(context.Background(), oauth2.StaticTokenSource(oauth2Token))
	// if err != nil {
	// 	c.String(http.StatusBadRequest, fmt.Sprintf("Failed to retrieve userinfo"))
	// 	return
	// }

	// Extract custom claims
	var claims IDTokenClaims
	if err = idToken.Claims(&claims); err != nil {
		log.Error().
			Err(err).
			Caller().
			Msg("Failed to decode id token claims")
		ctx.String(
			http.StatusBadRequest,
			"Failed to decode id token claims",
		)

		return
	}

	// retrieve machinekey from state cache
	machineKeyIf, machineKeyFound := h.registrationCache.Get(state)

	if !machineKeyFound {
		log.Error().
			Msg("requested machine state key expired before authorisation completed")
		ctx.String(http.StatusBadRequest, "state has expired")

		return
	}

	machineKeyFromCache, machineKeyOK := machineKeyIf.(string)

	var machineKey key.MachinePublic
	err = machineKey.UnmarshalText(
		[]byte(MachinePublicKeyEnsurePrefix(machineKeyFromCache)),
	)
	if err != nil {
		log.Error().
			Msg("could not parse machine public key")
		ctx.String(http.StatusBadRequest, "could not parse public key")

		return
	}

	if !machineKeyOK {
		log.Error().Msg("could not get machine key from cache")
		ctx.String(
			http.StatusInternalServerError,
			"could not get machine key from cache",
		)

		return
	}

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.GetMachineByMachineKey(machineKey)

	if machine != nil {
		log.Trace().
			Caller().
			Str("machine", machine.Name).
			Msg("machine already registered, reauthenticating")

		h.RefreshMachine(machine, *machine.Expiry)

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
			ctx.Data(
				http.StatusInternalServerError,
				"text/html; charset=utf-8",
				[]byte("Could not render OIDC callback template"),
			)
		}

		ctx.Data(http.StatusOK, "text/html; charset=utf-8", content.Bytes())

		return
	}

	namespaceName, err := NormalizeToFQDNRules(
		claims.Email,
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		log.Error().Err(err).Caller().Msgf("couldn't normalize email")
		ctx.String(
			http.StatusInternalServerError,
			"couldn't normalize email",
		)

		return
	}

	// register the machine if it's new
	log.Debug().Msg("Registering new machine after successful callback")

	namespace, err := h.GetNamespace(namespaceName)
	if errors.Is(err, errNamespaceNotFound) {
		namespace, err = h.CreateNamespace(namespaceName)

		if err != nil {
			log.Error().
				Err(err).
				Caller().
				Msgf("could not create new namespace '%s'", namespaceName)
			ctx.String(
				http.StatusInternalServerError,
				"could not create new namespace",
			)

			return
		}
	} else if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("namespace", namespaceName).
			Msg("could not find or create namespace")
		ctx.String(
			http.StatusInternalServerError,
			"could not find or create namespace",
		)

		return
	}

	machineKeyStr := MachinePublicKeyStripPrefix(machineKey)

	_, err = h.RegisterMachineFromAuthCallback(
		machineKeyStr,
		namespace.Name,
		RegisterMethodOIDC,
	)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("could not register machine")
		ctx.String(
			http.StatusInternalServerError,
			"could not register machine",
		)

		return
	}

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
		ctx.Data(
			http.StatusInternalServerError,
			"text/html; charset=utf-8",
			[]byte("Could not render OIDC callback template"),
		)
	}

	ctx.Data(http.StatusOK, "text/html; charset=utf-8", content.Bytes())
}
