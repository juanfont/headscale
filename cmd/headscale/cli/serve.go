package cli

import (
	"errors"
	"fmt"
	"net/http"
	"syscall"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/tailscale/squibble"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Launches the headscale server",
	RunE: func(cmd *cobra.Command, args []string) error {
		app, err := newHeadscaleServerWithConfig()
		if err != nil {
			if squibbleErr, ok := errors.AsType[squibble.ValidationError](err); ok {
				fmt.Printf("SQLite schema failed to validate:\n")
				fmt.Println(squibbleErr.Diff)
			}

			return fmt.Errorf("initializing: %w", err)
		}

		err = app.Serve()
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return classifyServeError(err)
	},
}

// classifyServeError augments specific error classes with operator
// hints. The underlying chain is left intact so errors.Is / errors.As
// continue to walk to ListenerBindError, syscall.EADDRINUSE, etc.
func classifyServeError(err error) error {
	var bindErr *types.ListenerBindError
	if !errors.As(err, &bindErr) {
		return err
	}

	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		port, _ := types.PortFromAddr(bindErr.Addr)

		return fmt.Errorf(
			"%w\n\nHint: another process on this host is bound to the same address. "+
				"Find it with: sudo ss -tlnp 'sport = :%d'",
			err, port)

	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf(
			"%w\n\nHint: binding to a privileged port (<1024) requires root or "+
				"CAP_NET_BIND_SERVICE. The shipped systemd unit grants this capability; "+
				"if running manually, use sudo or "+
				"`setcap cap_net_bind_service=+ep ./headscale`",
			err)
	}

	return err
}
