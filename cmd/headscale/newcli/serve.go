package newcli

import (
	"github.com/juanfont/headscale/client"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var serveCmd = command.New(command.Spec[command.NoInput, command.NoOutput]{
	Name:  "serve",
	Short: "Run the control server",
	Long: `Run the headscale control server until it gets SIGINT, SIGTERM or
SIGQUIT, and exit 0 then.

The configuration is the file that --config or HEADSCALE_CONFIG names, or
the first file found in /etc/headscale, $XDG_CONFIG_HOME/headscale,
headscale under each $XDG_CONFIG_DIRS entry, ~/.headscale and the working
directory, with the HEADSCALE_* variables of the environment. Each
directory is searched for config.json, config.toml, config.yaml,
config.yml, config.hujson, config.dotenv and config.env, in that order; a
.toml, .dotenv or .env file, a format of old releases, is an error, and the
search does not go past it. Without a file, the defaults and the
environment are the configuration, and the log says so.

The log goes to stderr, or to stdout as JSON with log.format: json. At
startup, serve checks GitHub for a newer release in the background and logs
one line when there is one; disable_check_updates turns this off.

serve exits 78 (EX_CONFIG) when the configuration file it loaded is wrong,
which a restart cannot fix, and 1 for every other failure. The systemd
units of headscale do not restart it on 78.`,
	Example: []string{
		"headscale serve",
		"headscale serve -c config.yaml",
	},
	Local:       true,
	ReadsConfig: true,
	// The loader warns about the environment before it reads the file.
	MissingConfig: func(c command.Ctx) {
		l, _ := config.LoadFile(c.ConfigFile, c.Environ)
		logLoadWarnings(l)
	},
	Run: func(c command.Ctx, _ command.NoInput) (command.NoOutput, error) {
		l, err := config.LoadFile(c.ConfigFile, c.Environ)
		if err != nil {
			logLoadWarnings(l)

			return command.NoOutput{}, command.ExitCode(
				types.ServeExitCode(l.File, err),
				err,
			)
		}

		hscontrol.UseLogConfig(l.Config, c.ServerOutput())
		hscontrol.LogWarnings(l.Warnings)

		if v := c.API.Build(); !l.Config.DisableUpdateCheck &&
			client.IsRelease(v.Version) &&
			!v.Dirty {
			go logNewerRelease(c, v.Version)
		}

		err = hscontrol.RunServer(c, l, c.ServerOutput())
		if err != nil {
			return command.NoOutput{}, command.ExitCode(
				types.ServeExitCode(l.File, err),
				err,
			)
		}

		return command.NoOutput{}, nil
	},
})

// logLoadWarnings logs what loading the config warned about, when it
// failed: no log.format applies, so main's console logger, on stderr, at
// log.level's default, since Run turned the log off.
func logLoadWarnings(l *config.Loaded) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	hscontrol.LogWarnings(l.Warnings)
}

// logNewerRelease logs one line when GitHub has a release newer than
// current, as the update check of version finds it.
func logNewerRelease(c command.Ctx, current string) {
	if latest := newest(current, releases(c)); updateHint(current, latest) != "" {
		log.Warn().
			Msg("An updated version of Headscale has been found (" + latest + " vs. your current " + current + "). Check it out https://github.com/juanfont/headscale/releases")
	}
}
