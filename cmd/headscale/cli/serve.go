package cli

import (
	"errors"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
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
		logNoConfigFile(loaded)

		app, err := newHeadscaleServerWithConfig()
		if err != nil {
			if squibbleErr, ok := errors.AsType[squibble.ValidationError](err); ok {
				fmt.Printf("SQLite schema failed to validate:\n")
				fmt.Println(squibbleErr.Diff)
			}

			return fmt.Errorf("initializing: %w", err)
		}

		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		defer stop()

		err = app.Serve(ctx)
		if err != nil {
			return classifyServeError(err)
		}

		return nil
	},
}

// exitConfig is EX_CONFIG from sysexits.h. serve exits with it when its
// configuration is the cause, which a restart with the same inputs cannot
// fix, so the systemd units set RestartPreventExitStatus to it.
const exitConfig = 78

// exitCode is how cmd exits on err, file being the configuration file it
// loaded: exitConfig when serve stops on what that configuration says; 1
// otherwise. Without a file, the one expected may be on a mount not yet up,
// and a database, a port or a file the configuration names may yet become
// available, so systemd keeps retrying those.
func exitCode(cmd *cobra.Command, file string, err error) int {
	if cmd == serveCmd && file != "" && errors.Is(err, types.ErrConfig) {
		return exitConfig
	}

	return 1
}

// logNoConfigFile says when the server runs without a file. The loader does
// not warn: client commands need no file unless they use an API key.
func logNoConfigFile(l *config.Loaded) {
	if l.File == "" {
		log.Info().Msg("no configuration file, using defaults and the environment")
	}
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
		port, perr := types.PortFromAddr(bindErr.Addr)
		if perr != nil {
			return fmt.Errorf(
				"%w\n\nHint: another process on this host is bound to the same address. "+
					"Find it with: sudo ss -tlnp",
				err)
		}

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
