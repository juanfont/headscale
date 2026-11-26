package newcli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// example is what generate config prints with opts.
func example(opts config.ExampleOptions) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, _ result) string {
		tb.Helper()

		d := config.Default()
		out, err := config.GenerateExample(&d, opts)
		require.NoError(tb, err)

		return string(out)
	}
}

// running is the configuration that the server sent, as generate config
// --running prints it; docs says whether the CLI asked for the comments.
// That the server sends its own configuration, redacted, is the API's test.
func running(docs bool) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		bodies := r.answers["/api/headscale/v0/config"]
		require.Len(tb, bodies, 1)
		require.Equal(tb, docs, strings.Contains(string(bodies[0]), "\n#"), "comments")
		require.Contains(tb, string(bodies[0]), "server_url: ")

		return string(bytes.TrimSpace(bodies[0])) + "\n"
	}
}

// committed is a generated page of the repository: a stale page fails here.
func committed(path string) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, _ result) string {
		tb.Helper()

		b, err := os.ReadFile(path)
		require.NoError(tb, err, "run go generate ./cmd/headscale/newcli/")

		// The macros plugin of mkdocs reads a page as Jinja.
		for _, jinja := range []string{"{{", "{%", "{#"} {
			if strings.HasSuffix(path, ".md") && strings.Contains(string(b), jinja) {
				tb.Errorf(
					"%s holds %q, which mkdocs would expand as a macro: reword the help text that has it",
					path,
					jinja,
				)
			}
		}

		return string(b)
	}
}

var generateCases = []cliCase{
	{
		name: "a private key", args: "generate private-key",
		want: func(tb testing.TB, _ *fixture, r result) string {
			tb.Helper()
			require.Regexp(tb, `^privkey:[0-9a-f]{64}\n$`, r.stdout)

			return r.stdout
		},
	},
	{
		name:   "private-key takes no --output",
		args:   "generate private-key -o json",
		code:   1,
		stderr: "Error: --output does not apply to `generate private-key`.\nRun `headscale generate private-key --help`.\n",
	},
	{
		name:   "private-key reads no config",
		args:   "generate private-key -c x.yaml",
		code:   1,
		stderr: "Error: --config does not apply to `generate private-key`.\nRun `headscale generate private-key --help`.\n",
	},

	{
		name: "config",
		args: "generate config",
		want: example(config.ExampleOptions{Docs: true}),
	},
	{
		name: "config --minimal",
		args: "generate config --minimal",
		want: example(config.ExampleOptions{Docs: true, Minimal: true}),
	},
	{
		name: "config --no-docs",
		args: "generate config --no-docs",
		want: example(config.ExampleOptions{}),
	},
	{
		name:   "config --minimal --no-docs",
		args:   "generate config --minimal --no-docs",
		stdout: "server_url: \"\"\n",
	},
	// Only --running reads the config, and only it looks for the one named.
	{
		name: "config reads no config",
		args: "generate config",
		env:  []string{"HEADSCALE_CONFIG=nope.yaml"},
		want: example(config.ExampleOptions{Docs: true}),
	},
	{
		name:   "config --running reads the config",
		args:   "generate config --running",
		env:    []string{"HEADSCALE_CONFIG=nope.yaml"},
		code:   1,
		stderr: "Error: the config file nope.yaml does not exist.\n",
	},
	{name: "config --running", args: "generate config --running", want: running(true)},
	{
		name: "config --running --no-docs",
		args: "generate config --running --no-docs",
		want: running(false),
	},
	{
		name: "config --running with a token of all", args: "generate config --running",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "all")
		},
		env:  []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		want: running(true),
	},
	{
		name: "config --running with a token that may only read",
		args: "generate config --running",
		code: 1,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "all:read")
		},
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\nIt lacks the scope all.\n",
	},
	{
		name:   "config --minimal --running",
		args:   "generate config --minimal --running",
		code:   1,
		stderr: "Error: --minimal and --running cannot be given together: the running configuration has every key.\n",
	},
	{
		name:   "config takes no --output",
		args:   "generate config --running -o json",
		code:   1,
		stderr: "Error: --output does not apply to `generate config`.\nRun `headscale generate config --help`.\n",
	},
	{
		name:   "the old dumpConfig points here",
		args:   "dumpConfig",
		code:   1,
		stderr: "Error: unknown command \"dumpConfig\". It is now \"generate config --running\".\nRun `headscale generate config --help`.\n",
	},

	{
		name: "nixos-options", args: "generate nixos-options",
		want: func(tb testing.TB, _ *fixture, _ result) string {
			tb.Helper()

			out, err := config.GenerateNixOptions(nil)
			require.NoError(tb, err)

			return string(out)
		},
	},
	{
		name: "nixos-options --release from a build of no known commit",
		args: "generate nixos-options --release",
		code: 1,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()

			_, err := config.ReleaseStamp(types.GetVersionInfo())
			require.Error(tb, err)
			f.vars["err"] = err.Error()
		},
		stderr: "Error: {err}\n",
	},

	{
		name: "cli-reference is the committed page",
		args: "generate cli-reference",
		want: committed("../../../docs/ref/cli.md"),
	},
	{
		name: "man is the committed page",
		args: "generate man",
		want: committed("../../../docs/ref/headscale.1"),
	},

	{
		name:   "gen points here",
		args:   "gen private-key",
		code:   1,
		stderr: "Error: unknown command \"gen\". It is now \"generate\".\nRun `headscale generate --help`.\n",
	},
}

func TestGenerate(t *testing.T) {
	t.Parallel()

	runCases(t, nil, generateCases)
}

// TestReferenceNamesEveryCommand: the reference page and the man page have
// a section for every command, with its help, and the columns of a list.
func TestReferenceNamesEveryCommand(t *testing.T) {
	t.Parallel()

	ref, err := os.ReadFile("../../../docs/ref/cli.md")
	require.NoError(t, err)

	man, err := os.ReadFile("../../../docs/ref/headscale.1")
	require.NoError(t, err)

	for _, c := range Tree().Commands() {
		require.Contains(t, string(ref), "\n### headscale "+c.Path+"\n", "reference")
		require.Contains(
			t,
			string(man),
			`.SS "headscale `+strings.ReplaceAll(c.Path, "-", `\-`)+`"`,
			"man page",
		)
	}

	require.Contains(
		t,
		string(ref),
		"Columns:\n\n```text\nCOLUMN",
		"a list ends with its columns",
	)
}
