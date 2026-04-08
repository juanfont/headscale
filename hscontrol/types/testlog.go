package types

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
)

// EnvTestLogLevel overrides the default test log level. Accepts any zerolog
// level string: trace, debug, info, warn, error, fatal, panic, disabled.
const EnvTestLogLevel = "HEADSCALE_TEST_LOG_LEVEL"

// init quiets zerolog when this package is loaded inside a test binary.
//
// hscontrol/types is transitively imported by every test in the repo that
// emits zerolog output, so this init() runs once per test binary and is
// the only place that needs to know about test logging configuration.
//
// Default: ErrorLevel (silent in green-path runs, real errors still surface).
// Override: HEADSCALE_TEST_LOG_LEVEL=debug (or trace, info, warn, disabled).
//
// Production binaries are unaffected because testing.Testing() returns false
// outside of test execution. The same testing.Testing() pattern is already
// used in hscontrol/db/users.go and hscontrol/db/node.go, so importing the
// testing package here is consistent with existing project conventions.
//
// Pitfalls:
//   - log.Fatal still calls os.Exit and log.Panic still panics regardless of
//     level — only the rendered message is suppressed.
//   - Local buffer loggers (zerolog.New(&buf)) are also gated by the global
//     level. Tests that assert on log output (currently only
//     hscontrol/util/zlog) re-enable trace level via their own init_test.go.
func init() {
	if !testing.Testing() {
		return
	}

	if raw := os.Getenv(EnvTestLogLevel); raw != "" {
		lvl, err := zerolog.ParseLevel(raw)
		if err == nil {
			zerolog.SetGlobalLevel(lvl)
			return
		}
	}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)
}
