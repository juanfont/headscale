package cli

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/cmd/headscale/cli/command"
	"github.com/juanfont/headscale/hscontrol/config"
)

var checkGroup = command.Group{
	Name:  "check",
	Short: "Check files offline: no server, no database, no prompt",
	Commands: []command.Node{
		checkConfig,
		checkPolicy,
		checkDERPMap,
		checkExtraRecords,
		checkAll,
	},
}

type (
	checkConfigIn struct {
		File command.Opt[command.Path] `arg:"file" help:"[file] is the config file, or - for stdin; by default the one --config names or serve finds."`
	}
	checkFileIn struct {
		File command.Path `arg:"file" help:"<file> is the file to check, or - for stdin."`
	}
	checkAllIn struct {
		File command.Opt[command.Path] `arg:"config-file" help:"[config-file] is the config file, or - for stdin; by default the one --config names or serve finds."`
	}
)

var checkConfig = command.New(command.Spec[checkConfigIn, command.Text]{
	Name:  "config",
	Short: "Check a config file",
	Long: `Check the configuration: its syntax, its keys and its values.

Unknown and removed keys are errors. The files that the configuration names
are not checked; check all does that. Without a file, the command checks
the file that --config or HEADSCALE_CONFIG names, or the one that serve
finds, and the environment; with one, it does not look at --config or
HEADSCALE_CONFIG. The file - reads the configuration from stdin, as HuJSON
when it starts with { or [ after space and comments, and as YAML
otherwise; paths in it are relative to the working directory.

It prints one line to stdout when the configuration is valid. Otherwise it
prints the reason to stderr and exits 1. What the configuration warns about
goes to stderr either way, as "warning: ...".

It needs no server and no database, and it writes no file.`,
	Example: []string{
		"headscale check config",
		"headscale check config config.yaml",
	},
	OldNames:      []string{"configtest"},
	Local:         true,
	ReadsConfig:   true,
	IgnoresConfig: func(in checkConfigIn) bool { _, given := in.File.Get(); return given },
	Run: func(c command.Ctx, in checkConfigIn) (command.Text, error) {
		l, err := loadChecked(c, in.File)
		if err != nil {
			return "", err
		}

		return command.Text("Configuration " + l.Source() + " is valid.\n"), nil
	},
})

var checkPolicy = command.New(command.Spec[checkFileIn, command.Text]{
	Name:  "policy",
	Short: "Check a policy file and run its tests",
	Long: `Check a policy file and run its "tests" and "sshTests".

The tests run against stand-in users and nodes built from the policy
itself, one for each user and tag it names, not against your tailnet. A
host alias or an IP address matches no stand-in, so an SSH test that names
one is always denied. To test a policy against the users and nodes of a
running server, use policy set --dry-run.

The file - reads the policy from stdin, as in
"generate-policy.sh | headscale check policy -".

It prints one line to stdout when the policy is valid and its tests pass.
Otherwise it prints the reason to stderr and exits 1. It needs no server,
no database and no config, and it writes no file.`,
	Example:  []string{"headscale check policy policy.hujson"},
	OldNames: []string{"policy check"},
	Local:    true,
	Run: func(c command.Ctx, in checkFileIn) (command.Text, error) {
		b, err := c.ReadFile(in.File)
		if err != nil {
			return "", err
		}

		n, err := config.CheckPolicyText(b)

		switch {
		case err != nil:
			return "", policyRefused(b, err)
		case n == 0:
			return "Policy is valid (no tests).\n", nil
		case n == 1:
			return "Policy is valid (1 test passed).\n", nil
		}

		return command.Text(
			"Policy is valid (" + strconv.Itoa(n) + " tests passed).\n",
		), nil
	},
})

var checkDERPMap = command.New(command.Spec[checkFileIn, command.Text]{
	Name:  "derp-map",
	Short: "Check a DERP map file",
	Long: `Check a DERP map file, as derp.paths names one: its format, its keys and
its regions. The extension names the format, .json, .hujson, .yaml or .yml;
stdin, the file -, is read as HuJSON when it starts with { or [ after space
and comments, and as YAML otherwise.

It prints one line to stdout when the file is valid. Otherwise it prints the
reason to stderr and exits 1. It needs no server and no config.`,
	Example: []string{"headscale check derp-map derp.yaml"},
	Local:   true,
	Run: func(c command.Ctx, in checkFileIn) (command.Text, error) {
		b, err := c.ReadFile(in.File)
		if err != nil {
			return "", err
		}

		err = config.CheckDERPMapData(named(in.File), extOf(in.File, b), b)
		if err != nil {
			return "", err
		}

		return command.Text("DERP map " + named(in.File) + " is valid.\n"), nil
	},
})

var checkExtraRecords = command.New(command.Spec[checkFileIn, command.Text]{
	Name:  "extra-records",
	Short: "Check an extra records file",
	Long: `Check a file of extra DNS records, as dns.extra_records_path names one.
The extension names the format, .json, .hujson, .yaml or .yml; stdin, the
file -, is read as HuJSON when it starts with { or [ after space and
comments, and as YAML otherwise.

It prints one line to stdout when the file is valid. Otherwise it prints the
reason to stderr and exits 1. It needs no server and no config.`,
	Example: []string{"headscale check extra-records records.json"},
	Local:   true,
	Run: func(c command.Ctx, in checkFileIn) (command.Text, error) {
		b, err := c.ReadFile(in.File)
		if err != nil {
			return "", err
		}

		err = config.CheckExtraRecordsData(named(in.File), extOf(in.File, b), b)
		if err != nil {
			return "", err
		}

		return command.Text("Extra records " + named(in.File) + " are valid.\n"), nil
	},
})

var checkAll = command.New(command.Spec[checkAllIn, command.Text]{
	Name:  "all",
	Short: "Check the config and every file it points at",
	Long: `Check the configuration, then each file it names: the policy, the DERP
maps, the extra records, the TLS certificate and key, and the private keys.

It prints its whole report to stdout, one line per file: ok, FAIL with the
error below it, or skip. Skip is a key file that startup creates when it is
missing, or a "file:<path>" secret, which no check reads. It exits 1 when a
line is FAIL. A derp.paths file that fails to parse is FAIL here, although
startup only skips it with a warning.

Without a file, the command checks the file that --config or
HEADSCALE_CONFIG names, or the one that serve finds; with one, it does not
look at --config or HEADSCALE_CONFIG. The file - reads the configuration
from stdin, as check config does. What the configuration warns about goes
to stderr, as "warning: ...". It needs no server and no database, and it
writes no file.`,
	Example: []string{
		"headscale check all",
		"headscale check all config.yaml",
	},
	Local:         true,
	ReadsConfig:   true,
	IgnoresConfig: func(in checkAllIn) bool { _, given := in.File.Get(); return given },
	Run: func(c command.Ctx, in checkAllIn) (command.Text, error) {
		l, err := loadChecked(c, in.File)

		var report strings.Builder

		err = config.CheckAll(&report, l.Config, l.Source(), err)
		if err != nil {
			return command.Text(report.String()), command.Failed(err)
		}

		return command.Text(report.String()), nil
	},
})

// loadChecked loads and validates the configuration of file, else of
// --config, else the one serve finds, and says on stderr what it warns
// about.
func loadChecked(
	c command.Ctx,
	file command.Opt[command.Path],
) (*config.Loaded, error) {
	// Only the argument - is stdin: --config and HEADSCALE_CONFIG name a
	// file, also when it is called -.
	path, given := file.Get()
	if !given {
		path = command.Path(c.ConfigFile)
	}

	var (
		l   *config.Loaded
		err error
	)

	if given && path == stdin {
		var (
			b   []byte
			ext string
		)

		b, ext, err = readStdin(c)
		if err != nil {
			return &config.Loaded{File: stdinName}, err
		}

		l, err = config.CheckConfigData(stdinName, ext, b, c.Environ)
	} else {
		l, err = config.CheckConfig(string(path), c.Environ)
	}

	for _, w := range l.Warnings {
		c.Note(warning(w))
	}

	return l, err
}

// warning is w after "warning: ", without the blank lines around it. The
// lines after the first are set under it, so a box keeps its shape.
func warning(w string) string {
	lines := strings.Split(w, "\n")
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}

	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}

	const prefix = "warning: "

	for i := 1; i < len(lines); i++ {
		if lines[i] != "" {
			lines[i] = strings.Repeat(" ", len(prefix)) + lines[i]
		}
	}

	return prefix + strings.Join(lines, "\n")
}

// stdin is the file argument that reads stdin.
const stdin command.Path = "-"

// stdinName is how every message names stdin.
const stdinName = "(stdin)"

// named is a file as a message names it.
func named(p command.Path) string {
	if p == stdin {
		return stdinName
	}

	return string(p)
}

// readStdin reads stdin, as every file argument is read, and names its
// format by the extension of a file in it.
func readStdin(c command.Ctx) ([]byte, string, error) {
	b, err := c.ReadFile(stdin)

	return b, stdinExt(b), err
}

// extOf is the format of the file p that holds b: its extension, or for
// stdin what b starts with.
func extOf(p command.Path, b []byte) string {
	if p == stdin {
		return stdinExt(b)
	}

	return filepath.Ext(string(p))
}

// stdinExt is the format of b, which has no file name to tell: HuJSON when
// its first character after space and HuJSON comments is { or [, and YAML
// otherwise. It goes by the start and not by what parses, so broken HuJSON
// gets HuJSON's error. A "#" comment is YAML's.
func stdinExt(b []byte) string {
	for {
		b = bytes.TrimLeft(b, " \t\r\n")

		switch {
		case bytes.HasPrefix(b, []byte("//")):
			_, b, _ = bytes.Cut(b, []byte("\n"))
		case bytes.HasPrefix(b, []byte("/*")):
			_, b, _ = bytes.Cut(b[2:], []byte("*/"))
		case len(b) > 0 && (b[0] == '{' || b[0] == '['):
			return ".hujson"
		default:
			return ".yaml"
		}
	}
}
