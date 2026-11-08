package cli

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/tcnksm/go-latest"
)

var cfgFile string = ""

func init() {
	if len(os.Args) > 1 &&
		(os.Args[1] == "version" || os.Args[1] == "mockoidc" || os.Args[1] == "completion") {
		return
	}

	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().
		StringVarP(&cfgFile, "config", "c", "", "config file (default is /etc/headscale/config.yaml)")
	rootCmd.PersistentFlags().
		StringP("output", "o", "", "Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'")
	rootCmd.PersistentFlags().
		Bool("force", false, "Disable prompts and forces the execution")

	// Re-enable usage output only for flag-parsing errors; runtime errors
	// from [cobra.Command.RunE] should never dump usage text.
	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.SilenceUsage = false

		return err
	})
}

// skipsInitConfig reports whether args select the check command group, which
// must work without a loadable config. Find runs lazily because init order
// across files is not guaranteed to have registered every command.
func skipsInitConfig(args []string) bool {
	cmd, rest, err := rootCmd.Find(args)
	// `help check …` must work wherever `check …` does.
	if err == nil && cmd.Name() == "help" && cmd.Parent() == rootCmd {
		cmd, _, err = rootCmd.Find(rest)
	}

	return err == nil && (cmd == checkCmd || cmd.HasParent() && cmd.Parent() == checkCmd)
}

// loadConfig loads path, else the file -c names, else $HEADSCALE_CONFIG,
// else the first config.* in /etc/headscale, $XDG_CONFIG_HOME/headscale,
// headscale under each $XDG_CONFIG_DIRS entry, ~/.headscale or ".". Without
// a file it loads defaults and environment only.
func loadConfig(path string) error {
	for _, p := range []string{path, cfgFile, os.Getenv("HEADSCALE_CONFIG")} {
		if p == "" {
			continue
		}

		err := types.LoadConfig(p, true)
		if err != nil {
			return fmt.Errorf("loading config file %s: %w", p, err)
		}

		return nil
	}

	err := types.LoadConfig("", false)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	return nil
}

func initConfig() {
	if skipsInitConfig(os.Args[1:]) {
		// Loading a config sets the log level; without one, use log.level's default.
		zerolog.SetGlobalLevel(zerolog.InfoLevel)

		return
	}

	err := loadConfig("")
	if err != nil {
		log.Fatal().Caller().Err(err).Msg("error loading config")
	}

	machineOutput := hasMachineOutputFlag()

	// If the user has requested a "node" readable format,
	// then disable login so the output remains valid.
	if machineOutput {
		zerolog.SetGlobalLevel(zerolog.Disabled)
	}

	if types.LogFormatSetting() == types.JSONLogFormat {
		log.Logger = log.Output(os.Stdout)
	}

	if !types.UpdateCheckDisabled() && !machineOutput {
		versionInfo := types.GetVersionInfo()
		if (runtime.GOOS == "linux" || runtime.GOOS == "darwin") &&
			!versionInfo.Dirty {
			githubTag := &latest.GithubTag{
				Owner:         "juanfont",
				Repository:    "headscale",
				TagFilterFunc: filterPreReleasesIfStable(func() string { return versionInfo.Version }),
			}

			res, err := latest.Check(githubTag, versionInfo.Version)
			if err == nil && res.Outdated {
				//nolint
				log.Warn().Msgf(
					"An updated version of Headscale has been found (%s vs. your current %s). Check it out https://github.com/juanfont/headscale/releases\n",
					res.Current,
					versionInfo.Version,
				)
			}
		}
	}
}

var prereleases = []string{"alpha", "beta", "rc", "dev"}

func isPreReleaseVersion(version string) bool {
	return slices.ContainsFunc(prereleases, func(unstable string) bool {
		return strings.Contains(version, unstable)
	})
}

// filterPreReleasesIfStable returns a function that filters out
// pre-release tags if the current version is stable.
// If the current version is a pre-release, it does not filter anything.
// versionFunc is a function that returns the current version string, it is
// a func for testability.
func filterPreReleasesIfStable(versionFunc func() string) func(string) bool {
	return func(tag string) bool {
		version := versionFunc()

		// If we are on a pre-release version, then we do not filter anything
		// as we want to recommend the user the latest pre-release.
		if isPreReleaseVersion(version) {
			return false
		}

		// If we are on a stable release, filter out pre-releases.
		return isPreReleaseVersion(tag)
	}
}

var rootCmd = &cobra.Command{
	Use:   "headscale",
	Short: "headscale - a Tailscale control server",
	Long: `
headscale is an open source implementation of the Tailscale control server

https://github.com/juanfont/headscale`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() {
	cmd, err := rootCmd.ExecuteC()
	if err != nil {
		outputFormat, _ := cmd.Flags().GetString("output")
		printError(err, outputFormat)
		os.Exit(1)
	}
}
