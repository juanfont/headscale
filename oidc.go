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
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"tailscale.com/types/key"
)

const (
	oidcStateCacheExpiration      = time.Minute * 5
	oidcStateCacheCleanupInterval = time.Minute * 10
	randomByteSize                = 16
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

	// init the state cache if it hasn't been already
	if h.oidcStateCache == nil {
		h.oidcStateCache = cache.New(
			oidcStateCacheExpiration,
			oidcStateCacheCleanupInterval,
		)
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
	h.oidcStateCache.Set(stateStr, machineKeyStr, oidcStateCacheExpiration)

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

// TODO: Why is the entire machine registration logic duplicated here?
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
	machineKeyIf, machineKeyFound := h.oidcStateCache.Get(state)

	if !machineKeyFound {
		log.Error().
			Msg("requested machine state key expired before authorisation completed")
		ctx.String(http.StatusBadRequest, "state has expired")

		return
	}

	machineKeyStr, machineKeyOK := machineKeyIf.(string)

	var machineKey key.MachinePublic
	err = machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
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

	// TODO(kradalby): Currently, if it fails to find a requested expiry, non will be set
	requestedTime := time.Time{}
	if requestedTimeIf, found := h.requestedExpiryCache.Get(machineKey.String()); found {
		if reqTime, ok := requestedTimeIf.(time.Time); ok {
			requestedTime = reqTime
		}
	}

	// retrieve machine information
	machine, err := h.GetMachineByMachineKey(machineKey)
	if err != nil {
		log.Error().Msg("machine key not found in database")
		ctx.String(
			http.StatusInternalServerError,
			"could not get machine info from database",
		)

		return
	}

	if machine.isRegistered() {
		log.Trace().
			Caller().
			Str("machine", machine.Name).
			Msg("machine already registered, reauthenticating")

		h.RefreshMachine(machine, requestedTime)

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

	now := time.Now().UTC()

	if namespaceName, ok := h.getNamespaceFromEmail(claims.Email); ok {
		// register the machine if it's new
		if !machine.Registered {
			log.Debug().Msg("Registering new machine after successful callback")

			namespace, err := h.GetNamespace(namespaceName)
			if errors.Is(err, gorm.ErrRecordNotFound) {
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

			ips, err := h.getAvailableIPs()
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("could not get an IP from the pool")
				ctx.String(
					http.StatusInternalServerError,
					"could not get an IP from the pool",
				)

				return
			}

			machine.IPAddresses = ips
			machine.NamespaceID = namespace.ID
			machine.Registered = true
			machine.RegisterMethod = RegisterMethodOIDC
			machine.LastSuccessfulUpdate = &now
			machine.Expiry = &requestedTime
			h.db.Save(&machine)
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

		return
	}

	log.Error().
		Caller().
		Str("email", claims.Email).
		Str("username", claims.Username).
		Str("machine", machine.Name).
		Msg("Email could not be mapped to a namespace")
	ctx.String(
		http.StatusBadRequest,
		"email from claim could not be mapped to a namespace",
	)
}

// getNamespaceFromEmail passes the users email through a list of "matchers"
// and iterates through them until it matches and returns a namespace.
// If no match is found, an empty string will be returned.
// TODO(kradalby): golang Maps key order is not stable, so this list is _not_ deterministic. Find a way to make the list of keys stable, preferably in the order presented in a users configuration.
func (h *Headscale) getNamespaceFromEmail(email string) (string, bool) {
	for match, namespace := range h.cfg.OIDC.MatchMap {
		regex := regexp.MustCompile(match)
		if regex.MatchString(email) {
			return namespace, true
		}
	}

	return "", false
}
