package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog/log"
	"tailscale.com/types/key"
)

// Dev command flags
var devArgs struct {
	Name   string `flag:"name,Node name"`
	User   string `flag:"user,u,User identifier"`
	Key    string `flag:"key,k,Registration key"`
	Routes string `flag:"routes,r,Comma-separated routes"`
}

const (
	errMockOidcClientIDNotDefined     = "MOCKOIDC_CLIENT_ID not defined"
	errMockOidcClientSecretNotDefined = "MOCKOIDC_CLIENT_SECRET not defined"
	errMockOidcPortNotDefined         = "MOCKOIDC_PORT not defined"
	refreshTTL                        = 60 * time.Minute
)

var accessTTL = 2 * time.Minute

// Dev command implementations

func generatePrivateKeyCommand(env *command.Env) error {
	// Generate a private key locally using Tailscale's key library
	machineKey := key.NewMachine()

	machineKeyStr, err := machineKey.MarshalText()
	if err != nil {
		return fmt.Errorf("cannot marshal private key: %w", err)
	}

	result := map[string]string{
		"private_key": string(machineKeyStr),
	}

	return outputResult(result, "Private key generated", globalArgs.Output)
}

func devCreateNodeCommand(env *command.Env) error {
	if err := requireString(devArgs.Name, "name"); err != nil {
		return err
	}
	if err := requireString(devArgs.User, "user"); err != nil {
		return err
	}
	if err := requireString(devArgs.Key, "key"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.DebugCreateNodeRequest{
			Name:   devArgs.Name,
			User:   devArgs.User,
			Key:    devArgs.Key,
			Routes: parseCommaSeparated(devArgs.Routes),
		}

		response, err := client.DebugCreateNode(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot create debug node: %w", err)
		}

		return outputResult(response.GetNode(), "Debug node created", globalArgs.Output)
	})
}

// Mock OIDC command implementation

func mockOIDCCommand(env *command.Env) error {
	clientID := os.Getenv("MOCKOIDC_CLIENT_ID")
	if clientID == "" {
		return fmt.Errorf(errMockOidcClientIDNotDefined)
	}
	clientSecret := os.Getenv("MOCKOIDC_CLIENT_SECRET")
	if clientSecret == "" {
		return fmt.Errorf(errMockOidcClientSecretNotDefined)
	}
	addrStr := os.Getenv("MOCKOIDC_ADDR")
	if addrStr == "" {
		return fmt.Errorf(errMockOidcPortNotDefined)
	}
	portStr := os.Getenv("MOCKOIDC_PORT")
	if portStr == "" {
		return fmt.Errorf(errMockOidcPortNotDefined)
	}
	accessTTLOverride := os.Getenv("MOCKOIDC_ACCESS_TTL")
	if accessTTLOverride != "" {
		newTTL, err := time.ParseDuration(accessTTLOverride)
		if err != nil {
			return err
		}
		accessTTL = newTTL
	}

	userStr := os.Getenv("MOCKOIDC_USERS")
	if userStr == "" {
		return fmt.Errorf("MOCKOIDC_USERS not defined")
	}

	var users []mockoidc.MockUser
	err := json.Unmarshal([]byte(userStr), &users)
	if err != nil {
		return fmt.Errorf("unmarshalling users: %w", err)
	}

	log.Info().Interface("users", users).Msg("loading users from JSON")

	log.Info().Msgf("Access token TTL: %s", accessTTL)

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	mock, err := getMockOIDC(clientID, clientSecret, users)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addrStr, port))
	if err != nil {
		return err
	}

	err = mock.Start(listener, nil)
	if err != nil {
		return err
	}
	log.Info().Msgf("Mock OIDC server listening on %s", listener.Addr().String())
	log.Info().Msgf("Issuer: %s", mock.Issuer())
	c := make(chan struct{})
	<-c

	return nil
}

func getMockOIDC(clientID string, clientSecret string, users []mockoidc.MockUser) (*mockoidc.MockOIDC, error) {
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

	mock.AddMiddleware(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Info().Msgf("Request: %+v", r)
			h.ServeHTTP(w, r)
			if r.Response != nil {
				log.Info().Msgf("Response: %+v", r.Response)
			}
		})
	})

	return &mock, nil
}

// Dev command definitions

func devCommands() []*command.C {
	generateCommand := &command.C{
		Name:  "generate",
		Usage: "<subcommand> [flags]",
		Help:  "Generate various resources",
		Commands: []*command.C{
			{
				Name:  "private-key",
				Usage: "",
				Help:  "Generate a private key for the headscale server",
				Run:   generatePrivateKeyCommand,
			},
		},
	}

	devCommand := &command.C{
		Name:     "dev",
		Usage:    "<subcommand> [flags] [args...]",
		Help:     "Development and testing commands",
		SetFlags: command.Flags(flax.MustBind, &globalArgs),
		Unlisted: true,
		Commands: []*command.C{
			{
				Name:     "generate",
				Usage:    "<subcommand> [flags] [args...]",
				Help:     "Generate various resources",
				Commands: generateCommand.Commands,
				Unlisted: true,
			},
			{
				Name:     "create-node",
				Usage:    "--name <n> --user <user> --key <key> [--routes <routes>]",
				Help:     "Create a debug node that can be registered",
				SetFlags: command.Flags(flax.MustBind, &globalArgs, &devArgs),
				Run:      devCreateNodeCommand,
				Unlisted: true,
			},
			{
				Name:     "mockoidc",
				Usage:    "",
				Help:     "Runs a mock OIDC server for testing purposes",
				Run:      mockOIDCCommand,
				Unlisted: true,
			},
		},
	}

	return []*command.C{
		devCommand,
	}
}
