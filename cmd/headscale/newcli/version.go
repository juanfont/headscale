package newcli

import (
	"context"
	"strings"
	"time"

	"github.com/juanfont/headscale/client"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/hscontrol/config"
	"golang.org/x/mod/semver"
)

// versionOut is what `version -o json` prints. It is an output of the CLI,
// not an API object, so its keys are the Go field names.
type versionOut struct {
	Version   string
	Commit    string
	BuildTime string
	Go        struct{ Version, OS, Arch string }
	Dirty     bool

	text string
}

var versionCmd = command.New(command.Spec[command.NoInput, versionOut]{
	Name:  "version",
	Short: "Print the version",
	Long: `Print the version of headscale, and check GitHub for a newer release.

The hint about a newer release goes to stderr. The check has a short
timeout; when it fails, no hint is printed and the command still succeeds.
The config key disable_check_updates turns the check off. A build that is
not a release does not check.

With -o json the command prints the version with the keys Version, Commit,
BuildTime, Go and Dirty.`,
	Example: []string{
		"headscale version",
		"headscale version -o json",
	},
	Local:       true,
	ReadsConfig: true,
	Run: func(c command.Ctx, _ command.NoInput) (versionOut, error) {
		v := c.API.Build()
		out := versionOut{
			Version:   v.Version,
			Commit:    v.Commit,
			BuildTime: v.BuildTime,
			Dirty:     v.Dirty,
			text:      v.String(),
		}
		out.Go.Version, out.Go.OS, out.Go.Arch = v.Go.Version, v.Go.OS, v.Go.Arch

		if checkUpdates(c) {
			if hint := updateHint(
				v.Version,
				newest(v.Version, releases(c)),
			); hint != "" {
				c.Note(hint)
			}
		}

		return out, nil
	},
	Done: func(_ command.NoInput, v versionOut, _ time.Time) string { return v.text },
})

// checkUpdates reads disable_check_updates from the config. A config
// that cannot be read is no reason to stop `version`, nor to ask GitHub
// against an opt-out it may hold. A build that is not a release has no
// number to compare.
func checkUpdates(c command.Ctx) bool {
	if !client.IsRelease(c.API.Build().Version) {
		return false
	}

	l, err := config.Load(c.ConfigFile, c.ConfigFile != "", c.Environ)
	if err != nil {
		return false
	}

	return !l.Config.DisableUpdateCheck
}

// releases are the release tags, within a short time; none when they
// cannot be had.
func releases(c command.Ctx) []string {
	ctx, cancel := context.WithTimeout(c, 3*time.Second)
	defer cancel()

	tags, _ := c.API.Releases(ctx)

	return tags
}

// newest is the newest release among tags. A stable build is told only
// about stable releases; a prerelease build about any.
func newest(current string, tags []string) string {
	stable := semver.Prerelease(canonical(current)) == ""
	best := ""

	for _, t := range tags {
		v := canonical(t)
		if !semver.IsValid(v) || stable && semver.Prerelease(v) != "" {
			continue
		}

		if best == "" || semver.Compare(v, best) > 0 {
			best = v
		}
	}

	return best
}

// updateHint is the line about a newer release; "" when latest is not
// newer than current.
func updateHint(current, latest string) string {
	if latest == "" || semver.Compare(canonical(latest), canonical(current)) <= 0 {
		return ""
	}

	return "A newer version is available: " + canonical(latest)
}

func canonical(v string) string { return "v" + strings.TrimPrefix(v, "v") }
