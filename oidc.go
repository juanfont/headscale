package headscale

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
	"net/http"
	"time"
)

type IDTokenClaims struct {
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Email    string   `json:"email"`
	Username string   `json:"preferred_username,omitempty"`
}

var oidcProvider *oidc.Provider
var oauth2Config *oauth2.Config
var stateCache *cache.Cache

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts machine key in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:mKey
func (h *Headscale) RegisterOIDC(c *gin.Context) {
	mKeyStr := c.Param("mkey")
	if mKeyStr == "" {
		c.String(http.StatusBadRequest, "Wrong params")
		return
	}

	var err error

	// grab oidc config if it hasn't been already
	if oauth2Config == nil {
		oidcProvider, err = oidc.NewProvider(context.Background(), h.cfg.OIDCIssuer)

		if err != nil {
			log.Error().Msgf("Could not retrieve OIDC Config: %s", err.Error())
			c.String(http.StatusInternalServerError, "Could not retrieve OIDC Config")
			return
		}

		oauth2Config = &oauth2.Config{
			ClientID:     h.cfg.OIDCClientID,
			ClientSecret: h.cfg.OIDCClientSecret,
			Endpoint:     oidcProvider.Endpoint(),
			RedirectURL:  fmt.Sprintf("%s/oidc/callback", strings.TrimSuffix(h.cfg.ServerURL, "/")),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

	}

	b := make([]byte, 16)
	_, err = rand.Read(b)

	if err != nil {
		log.Error().Msg("could not read 16 bytes from rand")
		c.String(http.StatusInternalServerError, "could not read 16 bytes from rand")
		return
	}

	stateStr := hex.EncodeToString(b)[:32]

	// init the state cache if it hasn't been already
	if stateCache == nil {
		stateCache = cache.New(time.Minute*5, time.Minute*10)
	}

	// place the machine key into the state cache, so it can be retrieved later
	stateCache.Set(stateStr, mKeyStr, time.Minute*5)

	authUrl := oauth2Config.AuthCodeURL(stateStr)
	log.Debug().Msgf("Redirecting to %s for authentication", authUrl)

	c.Redirect(http.StatusFound, authUrl)
}

// OIDCCallback handles the callback from the OIDC endpoint
// Retrieves the mkey from the state cache and adds the machine to the users email namespace
// TODO: A confirmation page for new machines should be added to avoid phishing vulnerabilities
// TODO: Add groups information from OIDC tokens into machine HostInfo
// Listens in /oidc/callback
func (h *Headscale) OIDCCallback(c *gin.Context) {

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.String(http.StatusBadRequest, "Wrong params")
		return
	}

	oauth2Token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		c.String(http.StatusBadRequest, "Could not exchange code for token")
		return
	}

	rawIDToken, rawIDTokenOK := oauth2Token.Extra("id_token").(string)
	if !rawIDTokenOK {
		c.String(http.StatusBadRequest, "Could not extract ID Token")
		return
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: h.cfg.OIDCClientID})

	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		c.String(http.StatusBadRequest, "Failed to verify id token: %s", err.Error())
		return
	}

	//userInfo, err := oidcProvider.UserInfo(context.Background(), oauth2.StaticTokenSource(oauth2Token))
	//if err != nil {
	//	c.String(http.StatusBadRequest, "Failed to retrieve userinfo: "+err.Error())
	//	return
	//}

	// Extract custom claims
	var claims IDTokenClaims
	if err = idToken.Claims(&claims); err != nil {
		c.String(http.StatusBadRequest, "Failed to decode id token claims: "+err.Error())
		return
	}

	//retrieve machinekey from state cache
	mKeyIf, mKeyFound := stateCache.Get(state)

	if !mKeyFound {
		c.String(http.StatusBadRequest, "state has expired")
		return
	}
	mKeyStr, mKeyOK := mKeyIf.(string)

	if !mKeyOK {
		c.String(http.StatusInternalServerError, "could not get machine key from cache")
		return
	}

	// retrieve machine information
	var m Machine
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", mKeyStr); errors.Is(result.Error, gorm.ErrRecordNotFound) {
		log.Error().Msg("machine key not found in database")
		c.String(http.StatusInternalServerError, "could not get machine info from database")
		return
	}

	//look for a namespace of the users email for now
	if !m.Registered {

		ns, err := h.GetNamespace(claims.Email)
		if err != nil {
			ns, err = h.CreateNamespace(claims.Email)

			if err != nil {
				log.Error().Msgf("could not create new namespace '%s'", claims.Email)
				c.String(http.StatusInternalServerError, "could not create new namespace")
				return
			}

		}

		ip, err := h.getAvailableIP()
		if err != nil {
			c.String(http.StatusInternalServerError, "could not get an IP from the pool")
			return
		}

		m.IPAddress = ip.String()
		m.NamespaceID = ns.ID
		m.Registered = true
		m.RegisterMethod = "oidc"
		h.db.Save(&m)
	}

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
