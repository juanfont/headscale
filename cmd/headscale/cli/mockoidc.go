package cli

import (
	"context"
	"os"

	"github.com/juanfont/headscale/cmd/headscale/mockoidc"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(mockOidcCmd)
}

var mockOidcCmd = &cobra.Command{
	Use:   "mockoidc",
	Short: "Runs a mock OIDC server for testing",
	Long:  "This internal command runs a OpenID Connect for testing purposes",
	RunE: func(cmd *cobra.Command, args []string) error {
		return mockoidc.Run(context.Background(), os.Environ())
	},
}
