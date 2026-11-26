// Package mockoidc runs a mock OpenID Connect server for the integration
// tests: `headscale debug mockoidc` runs it.
package mockoidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	errMockOidcClientIDNotDefined     = errors.New("MOCKOIDC_CLIENT_ID not defined")
	errMockOidcClientSecretNotDefined = errors.New("MOCKOIDC_CLIENT_SECRET not defined")
	errMockOidcPortNotDefined         = errors.New("MOCKOIDC_PORT not defined")
	errMockOidcUsersNotDefined        = errors.New("MOCKOIDC_USERS not defined")
)

const (
	refreshTTL       = 60 * time.Minute
	defaultAccessTTL = 2 * time.Minute
)

// Run serves the mock OIDC server that the MOCKOIDC_* variables of environ
// (os.Environ form) describe, until ctx ends.
func Run(ctx context.Context, environ []string) error {
	// A server logs what it serves; the new CLI starts every command with
	// the log off, which only it does.
	if zerolog.GlobalLevel() == zerolog.Disabled {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	err := run(ctx, environ)
	if err != nil {
		return fmt.Errorf("running mock OIDC server: %w", err)
	}

	return nil
}

func run(ctx context.Context, environ []string) error {
	getenv := func(name string) string {
		for _, kv := range slices.Backward(environ) {
			if v, ok := strings.CutPrefix(kv, name+"="); ok {
				return v
			}
		}

		return ""
	}

	clientID := getenv("MOCKOIDC_CLIENT_ID")
	if clientID == "" {
		return errMockOidcClientIDNotDefined
	}

	clientSecret := getenv("MOCKOIDC_CLIENT_SECRET")
	if clientSecret == "" {
		return errMockOidcClientSecretNotDefined
	}

	addrStr := getenv("MOCKOIDC_ADDR")
	if addrStr == "" {
		return errMockOidcPortNotDefined
	}

	portStr := getenv("MOCKOIDC_PORT")
	if portStr == "" {
		return errMockOidcPortNotDefined
	}

	accessTTL := defaultAccessTTL

	accessTTLOverride := getenv("MOCKOIDC_ACCESS_TTL")
	if accessTTLOverride != "" {
		newTTL, err := time.ParseDuration(accessTTLOverride)
		if err != nil {
			return err
		}

		accessTTL = newTTL
	}

	userStr := getenv("MOCKOIDC_USERS")
	if userStr == "" {
		return errMockOidcUsersNotDefined
	}

	var users []mockoidc.MockUser

	err := json.Unmarshal([]byte(userStr), &users)
	if err != nil {
		return fmt.Errorf("unmarshalling users: %w", err)
	}

	log.Info().Interface(zf.Users, users).Msg("loading users from JSON")

	log.Info().Msgf("access token TTL: %s", accessTTL)

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	mock, err := getMockOIDC(clientID, clientSecret, accessTTL, users)
	if err != nil {
		return err
	}

	listener, err := new(net.ListenConfig).Listen(ctx, "tcp", fmt.Sprintf("%s:%d", addrStr, port))
	if err != nil {
		return err
	}

	err = mock.Start(listener, nil)
	if err != nil {
		return err
	}

	log.Info().Msgf("mock OIDC server listening on %s", listener.Addr().String())
	log.Info().Msgf("issuer: %s", mock.Issuer())

	<-ctx.Done()

	return mock.Shutdown()
}

func getMockOIDC(clientID string, clientSecret string, accessTTL time.Duration, users []mockoidc.MockUser) (*mockoidc.MockOIDC, error) {
	keypair, err := mockoidc.NewKeypair(nil)
	if err != nil {
		return nil, err
	}

	userQueue := mockoidc.UserQueue{}

	for _, user := range users {
		userQueue.Push(&user)
	}

	mock := mockoidc.MockOIDC{
		ClientID:                      clientID,
		ClientSecret:                  clientSecret,
		AccessTTL:                     accessTTL,
		RefreshTTL:                    refreshTTL,
		CodeChallengeMethodsSupported: []string{"plain", "S256"},
		Keypair:                       keypair,
		SessionStore:                  mockoidc.NewSessionStore(),
		UserQueue:                     &userQueue,
		ErrorQueue:                    &mockoidc.ErrorQueue{},
	}

	_ = mock.AddMiddleware(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Info().Msgf("request: %+v", r)
			h.ServeHTTP(w, r)

			if r.Response != nil {
				log.Info().Msgf("response: %+v", r.Response)
			}
		})
	})

	return &mock, nil
}
