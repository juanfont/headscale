package headscale

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/s12v/go-jwks"
	"gopkg.in/square/go-jose.v2/jwt"
	"gorm.io/gorm"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type OpenIDTokens struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	IdToken          string `json:"id_token"`
	NotBeforePolicy  int    `json:"not-before-policy,omitempty"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	SessionState     string `json:"session_state,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
}

type AccessToken struct {
	jwt.Claims
	Name     string   `json:"name,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	Email    string   `json:"email"`
	Username string   `json:"preferred_username,omitempty"`
}

var oidcConfig *OpenIDConfiguration
var stateCache *cache.Cache
var jwksSource *jwks.WebSource
var jwksClient jwks.JWKSClient

func verifyToken(token string) (*AccessToken, error) {

	if jwksClient == nil {
		jwksSource = jwks.NewWebSource(oidcConfig.JWKSURI)
		jwksClient = jwks.NewDefaultClient(
			jwksSource,
			time.Hour,    // Refresh keys every 1 hour
			12*time.Hour, // Expire keys after 12 hours
		)
	}

	//decode jwt
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, err
	}

	if tok.Headers[0].KeyID != "" {
		log.Debug().Msgf("Checking KID %s\n", tok.Headers[0].KeyID)

		jwk, err := jwksClient.GetSignatureKey(tok.Headers[0].KeyID)
		if err != nil {
			return nil, err
		}

		claims := AccessToken{}

		err = tok.Claims(jwk.Certificates[0].PublicKey, &claims)
		if err != nil {
			return nil, err
		} else {

			err = claims.Validate(jwt.Expected{
				Time: time.Now(),
			})
			if err != nil {
				return nil, err
			}

			return &claims, nil
		}

	} else {
		return nil, err
	}
}

func getOIDCConfig(oidcConfigURL string) (*OpenIDConfiguration, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", oidcConfigURL, nil)
	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}

	log.Debug().Msgf("Requesting OIDC Config from %s", oidcConfigURL)

	oidcConfigResp, err := client.Do(req)
	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}
	defer oidcConfigResp.Body.Close()

	var oidcConfig OpenIDConfiguration

	err = json.NewDecoder(oidcConfigResp.Body).Decode(&oidcConfig)
	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}
	return &oidcConfig, nil
}

func (h *Headscale) exchangeCodeForTokens(code string, redirectURI string) (*OpenIDTokens, error) {
	var err error

	if oidcConfig == nil {
		oidcConfig, err = getOIDCConfig(fmt.Sprintf("%s.well-known/openid-configuration", h.cfg.OIDCEndpoint))
		if err != nil {
			return nil, err
		}
	}

	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("client_id", h.cfg.OIDCClientID)
	params.Add("client_secret", h.cfg.OIDCClientSecret)
	params.Add("redirect_uri", redirectURI)

	client := &http.Client{}
	req, err := http.NewRequest("POST", oidcConfig.TokenEndpoint, strings.NewReader(params.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}

	tokenResp, err := client.Do(req)
	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != 200 {
		b, _ := io.ReadAll(tokenResp.Body)
		log.Error().Msgf("%s", b)
	}

	var tokens OpenIDTokens

	err = json.NewDecoder(tokenResp.Body).Decode(&tokens)
	if err != nil {
		log.Error().Msgf("%v", err)
		return nil, err
	}

	log.Info().Msg("Successfully exchanged code for tokens")

	return &tokens, nil
}

// RegisterOIDC redirects to the OIDC provider for authentication
// Puts machine key in cache so the callback can retrieve it using the oidc state param
// Listens in /oidc/register/:mKey
func (h *Headscale) RegisterOIDC(c *gin.Context) {
	mKeyStr := c.Param("mKey")
	if mKeyStr == "" {
		c.String(http.StatusBadRequest, "Wrong params")
		return
	}

	var err error

	// grab oidc config if it hasn't been already
	if oidcConfig == nil {
		oidcConfig, err = getOIDCConfig(fmt.Sprintf("%s.well-known/openid-configuration", h.cfg.OIDCEndpoint))

		if err != nil {
			c.String(http.StatusInternalServerError, "Could not retrieve OIDC Config")
			return
		}
	}

	b := make([]byte, 16)
	_, err = rand.Read(b)
	stateStr := hex.EncodeToString(b)[:32]

	// init the state cache if it hasn't been already
	if stateCache == nil {
		stateCache = cache.New(time.Minute*5, time.Minute*10)
	}

	// place the machine key into the state cache, so it can be retrieved later
	stateCache.Set(stateStr, mKeyStr, time.Minute*5)

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", h.cfg.OIDCClientID)
	params.Add("redirect_uri", fmt.Sprintf("%s/oidc/callback", h.cfg.ServerURL))
	params.Add("scope", "openid")
	params.Add("state", stateStr)

	authUrl := fmt.Sprintf("%s?%s", oidcConfig.AuthorizationEndpoint, params.Encode())
	log.Debug().Msg(authUrl)

	c.Redirect(http.StatusFound, authUrl)
}

// OIDCCallback handles the callback from the OIDC endpoint
// Retrieves the mkey from the state cache, if the machine is not registered, presents a confirmation
// Listens in /oidc/callback
func (h *Headscale) OIDCCallback(c *gin.Context) {

	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		c.String(http.StatusBadRequest, "Wrong params")
		return
	}

	redirectURI := fmt.Sprintf("%s/oidc/callback", h.cfg.ServerURL)

	tokens, err := h.exchangeCodeForTokens(code, redirectURI)

	if err != nil {
		c.String(http.StatusBadRequest, "Could not exchange code for token")
		return
	}

	//verify tokens
	claims, err := verifyToken(tokens.AccessToken)

	if err != nil {
		c.String(http.StatusBadRequest, "invalid tokens")
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
    Authenticated, you can now close this window.
</p>
</body>
</html>

`)))
}
