package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"syscall"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tailscale/squibble"
)

// RunServer runs the server that l configures, as `headscale serve` does,
// until ctx ends or the process gets SIGINT, SIGTERM or SIGQUIT. The diff of
// a SQLite schema that fails to validate goes to stdout.
func RunServer(ctx context.Context, l *config.Loaded, stdout io.Writer) error {
	logNoConfigFile(l)

	cfg := l.Config
	// The server never uses the CLI's key, which may be an unread file:
	// reference.
	cfg.CLI.APIKey = ""

	app, err := NewHeadscale(cfg) //nolint:contextcheck // making the server takes no context
	if err != nil {
		if squibbleErr, ok := errors.AsType[squibble.ValidationError](err); ok {
			fmt.Fprintf(stdout, "SQLite schema failed to validate:\n")
			fmt.Fprintln(stdout, squibbleErr.Diff)
		}

		return fmt.Errorf("initializing: creating new headscale: %w", err)
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stop()

	err = app.Serve(ctx)
	if err != nil {
		return types.ExplainBindError(err)
	}

	return nil
}

// UseLogConfig applies cfg's log.level, and logs to w as JSON when cfg sets
// log.format: json.
func UseLogConfig(cfg *types.Config, w io.Writer) {
	zerolog.SetGlobalLevel(cfg.Log.Level.Zerolog())

	if cfg.Log.Format == types.JSONLogFormat {
		log.Logger = log.Output(w)
	}
}

// LogWarnings logs each of warnings, such as what loading a configuration
// warns about.
func LogWarnings(warnings []string) {
	for _, w := range warnings {
		log.Warn().Msg(w)
	}
}

// logNoConfigFile says when the server runs without a file. The loader does
// not warn: client commands need no file unless they use an API key.
func logNoConfigFile(l *config.Loaded) {
	if l.File == "" {
		log.Info().Msg("no configuration file, using defaults and the environment")
	}
}
