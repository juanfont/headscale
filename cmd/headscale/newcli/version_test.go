package newcli

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

const versionJSON = `{
  "Version": "{version}",
  "Commit": "{commit}",
  "BuildTime": "{buildtime}",
  "Go": {
    "Version": "{go}",
    "OS": "{os}",
    "Arch": "{arch}"
  },
  "Dirty": {dirty}
}
`

var versionCases = []cliCase{
	{name: "text", args: "version", stdout: "{versiontext}"},
	{
		name:   "json has the Go field names",
		args:   "version -o json",
		stdout: versionJSON,
	},
	{name: "-o before the command", args: "-o json version", stdout: versionJSON},
	{
		name:   "--version prints the version line",
		args:   "--version",
		stdout: "headscale version {version}\n",
	},
	{
		name:   "--version stands alone",
		args:   "-c x --version",
		stderr: "Error: --version takes no other flag.\n",
		code:   1,
	},
	{
		name:   "--version is a flag of the root only",
		args:   "version --version",
		stderr: "Error: unknown flag --version for `version`.\nRun `headscale version --help`.\n",
		code:   1,
	},
	{
		name:   "no arguments",
		args:   "version 1",
		stderr: "Error: `version` takes no arguments, got 1.\n\n  headscale version\n",
		code:   1,
	},
	{
		name:    "a release is told about a newer stable release",
		args:    "version",
		release: "0.30.0",
		stdout:  "{releasetext}",
		stderr:  "A newer version is available: v0.30.1\n",
	},
	{
		name:    "a prerelease is told about any newer release",
		args:    "version",
		release: "0.31.0-beta.1",
		stdout:  "{betatext}",
		stderr:  "A newer version is available: v0.31.0-beta.2\n",
	},
	{
		name:    "the hint is a note",
		args:    "version -o json",
		release: "0.30.0",
		setup:   asRelease,
		stdout:  versionJSON,
	},
	{
		name:    "disable_check_updates turns the check off",
		args:    "version",
		release: "0.30.0",
		env:     []string{"HEADSCALE_DISABLE_CHECK_UPDATES=true"},
		stdout:  "{releasetext}",
	},
	{
		name:    "a config that does not load asks nothing",
		args:    "version -c {badconfig}",
		release: "0.30.0",
		setup:   badConfig,
		env:     []string{"HEADSCALE_DISABLE_CHECK_UPDATES=true"},
		stdout:  "{releasetext}",
	},
	{
		name:   "a config file that does not exist",
		args:   "version -c /nonexistent.yaml",
		stderr: "Error: the config file /nonexistent.yaml does not exist.\n",
		code:   1,
	},
}

func TestVersion(t *testing.T) {
	t.Parallel()

	runCases(t, versionSetup, versionCases)
}

func versionSetup(tb testing.TB, f *fixture) {
	tb.Helper()

	v := types.GetVersionInfo()
	f.vars["versiontext"] = v.String()
	f.vars["version"] = v.Version
	f.vars["commit"] = v.Commit
	f.vars["buildtime"] = v.BuildTime
	f.vars["go"] = v.Go.Version
	f.vars["os"] = v.Go.OS
	f.vars["arch"] = v.Go.Arch
	f.vars["dirty"] = strconv.FormatBool(v.Dirty)

	f.releases = []string{"v0.29.0", "v0.30.1", "v0.31.0-beta.2", "not-a-version"}

	for name, version := range map[string]string{"releasetext": "0.30.0", "betatext": "0.31.0-beta.1"} {
		r := *v
		r.Version = version
		f.vars[name] = r.String()
	}
}

// badConfig is a config file that does not load, as {badconfig}.
func badConfig(tb testing.TB, f *fixture) {
	tb.Helper()

	f.vars["badconfig"] = filepath.Join(tb.TempDir(), "config.yaml")
	require.NoError(
		tb,
		os.WriteFile(f.vars["badconfig"], []byte("server_url: [\n"), 0o600),
	)
}

// asRelease makes {version} the release that a case claims.
func asRelease(tb testing.TB, f *fixture) {
	tb.Helper()

	f.vars["version"] = "0.30.0"
}

func TestNewest(t *testing.T) {
	t.Parallel()

	tags := []string{"v0.29.0", "v0.30.1", "0.31.0-beta.2", "junk"}
	require.Equal(t, "v0.30.1", newest("0.30.0", tags))
	require.Equal(t, "v0.31.0-beta.2", newest("0.31.0-beta.1", tags))
	require.Empty(t, newest("0.30.0", nil))
}

func TestUpdateHint(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ current, latest, want string }{
		{"0.30.0", "v0.30.1", "A newer version is available: v0.30.1"},
		{"v0.30.0", "0.31.0", "A newer version is available: v0.31.0"},
		{"0.30.1", "v0.30.1", ""},
		{"0.31.0", "v0.30.1", ""},
		{"0.30.0", "", ""},
	} {
		require.Equal(
			t,
			tt.want,
			updateHint(tt.current, tt.latest),
			"%s → %s",
			tt.current,
			tt.latest,
		)
	}
}
