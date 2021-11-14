package headscale

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

const (
	OIDC_STATE_CACHE_EXPIRATION       = time.Minute * 5
	OIDC_STATE_CACHE_CLEANUP_INTERVAL = time.Minute * 10
	RANDOM_BYTE_SIZE                  = 16
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
			log.Error().Msgf("Could not retrieve OIDC Config: %s", err.Error())

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
			OIDC_STATE_CACHE_EXPIRATION,
			OIDC_STATE_CACHE_CLEANUP_INTERVAL,
		)
	}

	return nil
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts machine key in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:mKey.
func (h *Headscale) RegisterOIDC(c *gin.Context) {
	mKeyStr := c.Param("mkey")
	if mKeyStr == "" {
		c.String(http.StatusBadRequest, "Wrong params")

		return
	}

	b := make([]byte, RANDOM_BYTE_SIZE)
	if _, err := rand.Read(b); err != nil {
		log.Error().Msg("could not read 16 bytes from rand")
		c.String(http.StatusInternalServerError, "could not read 16 bytes from rand")

		return
	}

	stateStr := hex.EncodeToString(b)[:32]

	// place the machine key into the state cache, so it can be retrieved later
	h.oidcStateCache.Set(stateStr, mKeyStr, OIDC_STATE_CACHE_EXPIRATION)

	authUrl := h.oauth2Config.AuthCodeURL(stateStr)
	log.Debug().Msgf("Redirecting to %s for authentication", authUrl)

	c.Redirect(http.StatusFound, authUrl)
}

// OIDCCallback handles the callback from the OIDC endpoint
// Retrieves the mkey from the state cache and adds the machine to the users email namespace
// TODO: A confirmation page for new machines should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into machine HostInfo
// Listens in /oidc/callback.
func (h *Headscale) OIDCCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.String(http.StatusBadRequest, "Wrong params")

		return
	}

	oauth2Token, err := h.oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusBadRequest, "Could not exchange code for token")

		return
	}

	log.Debug().Msgf("AccessToken: %v", oauth2Token.AccessToken)

	rawIDToken, rawIDTokenOK := oauth2Token.Extra("id_token").(string)
	if !rawIDTokenOK {
		c.String(http.StatusBadRequest, "Could not extract ID Token")

		return
	}

	verifier := h.oidcProvider.Verifier(&oidc.Config{ClientID: h.cfg.OIDC.ClientID})

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to verify id token: %s", err.Error())

		return
	}

	// TODO: we can use userinfo at some point to grab additional information about the user (groups membership, etc)
	//userInfo, err := oidcProvider.UserInfo(context.Background(), oauth2.StaticTokenSource(oauth2Token))
	//if err != nil {
	//	c.String(http.StatusBadRequest, fmt.Sprintf("Failed to retrieve userinfo: %s", err))
	//	return
	//}

	// Extract custom claims
	var claims IDTokenClaims
	if err = idToken.Claims(&claims); err != nil {
		c.String(
			http.StatusBadRequest,
			fmt.Sprintf("Failed to decode id token claims: %s", err),
		)

		return
	}

	// retrieve machinekey from state cache
	mKeyIf, mKeyFound := h.oidcStateCache.Get(state)

	if !mKeyFound {
		log.Error().
			Msg("requested machine state key expired before authorisation completed")
		c.String(http.StatusBadRequest, "state has expired")

		return
	}
	mKeyStr, mKeyOK := mKeyIf.(string)

	if !mKeyOK {
		log.Error().Msg("could not get machine key from cache")
		c.String(http.StatusInternalServerError, "could not get machine key from cache")

		return
	}

	// retrieve machine information
	m, err := h.GetMachineByMachineKey(mKeyStr)
	if err != nil {
		log.Error().Msg("machine key not found in database")
		c.String(
			http.StatusInternalServerError,
			"could not get machine info from database",
		)

		return
	}

	now := time.Now().UTC()

	if nsName, ok := h.getNamespaceFromEmail(claims.Email); ok {
		// register the machine if it's new
		if !m.Registered {
			log.Debug().Msg("Registering new machine after successful callback")

			ns, err := h.GetNamespace(nsName)
			if err != nil {
				ns, err = h.CreateNamespace(nsName)

				if err != nil {
					log.Error().
						Msgf("could not create new namespace '%s'", claims.Email)
					c.String(
						http.StatusInternalServerError,
						"could not create new namespace",
					)

					return
				}
			}

			ip, err := h.getAvailableIP()
			if err != nil {
				c.String(
					http.StatusInternalServerError,
					"could not get an IP from the pool",
				)

				return
			}

			m.IPAddress = ip.String()
			m.NamespaceID = ns.ID
			m.Registered = true
			m.RegisterMethod = "oidc"
			m.LastSuccessfulUpdate = &now
			h.db.Save(&m)
		}

		h.updateMachineExpiry(m)

		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf(`
<html>
<body>
<h1>headscale</h1>
<p>
    Authenticated as %s, you can now close this window.
</p>
</body>
</html>

`, claims.Email)))
	}

	log.Error().
		Str("email", claims.Email).
		Str("username", claims.Username).
		Str("machine", m.Name).
		Msg("Email could not be mapped to a namespace")
	c.String(
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
