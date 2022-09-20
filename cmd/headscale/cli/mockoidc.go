package cli

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mockOidcCmd)
}

var mockOidcCmd = &cobra.Command{
	Use:   "mockoidc",
	Short: "Runs a mock OIDC server for testing",
	Long:  "This internal command runs a OpenID Connect for testing purposes",
	Run: func(cmd *cobra.Command, args []string) {
		err := mockOIDC()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func mockOIDC() error {
	clientID := os.Getenv("MOCKOIDC_CLIENT_ID")
	if clientID == "" {
		return fmt.Errorf("MOCKOIDC_CLIENT_ID not set")
	}
	clientSecret := os.Getenv("MOCKOIDC_CLIENT_SECRET")
	if clientSecret == "" {
		return fmt.Errorf("MOCKOIDC_CLIENT_SECRET not set")
	}
	portStr := os.Getenv("MOCKOIDC_PORT")
	if portStr == "" {
		return fmt.Errorf("MOCKOIDC_PORT not set")
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	mock, err := getMockOIDC(clientID, clientSecret)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", fmt.Sprintf("mockoidc:%d", port))
	if err != nil {
		return err
	}

	mock.Start(ln, nil)
	log.Info().Msgf("Mock OIDC server listening on %s", ln.Addr().String())
	log.Info().Msgf("Issuer: %s", mock.Issuer())
	c := make(chan struct{})
	<-c

	return nil
}

func getMockOIDC(clientID string, clientSecret string) (*mockoidc.MockOIDC, error) {
	keypair, err := mockoidc.NewKeypair(nil)
	if err != nil {
		return nil, err
	}

	mock := mockoidc.MockOIDC{
		ClientID:                      clientID,
		ClientSecret:                  clientSecret,
		AccessTTL:                     time.Duration(10) * time.Minute,
		RefreshTTL:                    time.Duration(60) * time.Minute,
		CodeChallengeMethodsSupported: []string{"plain", "S256"},
		Keypair:                       keypair,
		SessionStore:                  mockoidc.NewSessionStore(),
		UserQueue:                     &mockoidc.UserQueue{},
		ErrorQueue:                    &mockoidc.ErrorQueue{},
	}

	return &mock, nil
}
