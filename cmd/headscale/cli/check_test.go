package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	validConfig = "server_url: https://headscale.example.com\n"
	derpMap     = `regions:
  900:
    regionid: 900
    regioncode: test
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.example.com
`
	twoTests = `{
  "tagOwners": {"tag:web": ["alice@"]},
  "acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:22"]}],
  "ssh": [{"action": "accept", "src": ["alice@"], "dst": ["tag:web"], "users": ["root"]}],
  "tests": [{"src": "alice@", "accept": ["bob@:22"]}],
  "sshTests": [{"src": "alice@", "dst": ["tag:web"], "accept": ["root"]}],
}`
)

// checkFiles are the files the check cases read, in the directory they run
// in.
var checkFiles = map[string]string{
	"config.yaml":      validConfig + "noise:\n  private_key_path: noise.key\n",
	"bad.yaml":         validConfig + "bogus_key: 1\n",
	"wrong.yaml":       "server_url: ftp://headscale.example.com\n",
	"syntax.yaml":      validConfig + "derp: [\n",
	"policy.hujson":    twoTests,
	"onetest.hujson":   `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:22"]}], "tests": [{"src": "alice@", "accept": ["bob@:22"]}]}`,
	"notests.hujson":   `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`,
	"failing.hujson":   `{"acls": [], "tests": [{"src": "alice@", "accept": ["bob@:22"]}]}`,
	"badgroup.hujson":  `{"acls": [{"action": "accept", "src": ["group:missing"], "dst": ["*:*"]}]}`,
	"derp.yaml":        derpMap,
	"emptyderp.yaml":   "{}",
	"records.json":     `[{"name": "a.example.com", "type": "A", "value": "100.64.0.1"}]`,
	"badrecords.json":  "{",
	"all.yaml":         validConfig + "policy:\n  path: policy.hujson\nderp:\n  paths: [derp.yaml]\nnoise:\n  private_key_path: noise.key\n",
	"allfail.yaml":     validConfig + "policy:\n  path: failing.hujson\nderp:\n  paths: [derp.yaml, emptyderp.yaml]\nnoise:\n  private_key_path: noise.key\n",
	"records.yaml":     "- name: a.example.com\n  type: A\n  value: 100.64.0.1\n",
	"extrarecords.yml": "dns:\n  extra_records_path: badrecords.json\n",
}

// emptyFile is the refusal of a file argument that is given and empty, as
// of an empty --config.
func emptyFile(arg string) string {
	return "Error: \"\" is not a valid <" + arg + ">: it takes a path, or - for stdin.\n"
}

// dashFile writes a valid config in a file named -, which --config and
// HEADSCALE_CONFIG name as any other file.
func dashFile(tb testing.TB, _ *fixture) {
	tb.Helper()
	require.NoError(tb, os.WriteFile("-", []byte(validConfig), 0o600))
	tb.Cleanup(func() { _ = os.Remove("-") })
}

// dashFileError is a config file named -: its name has no format.
const dashFileError = "Error: loading config file -: Fatal config error: unsupported config file format \"\": use .json, .yaml, .yml or .hujson (-)\n\n"

var checkCases = []cliCase{
	// check config
	{
		name:   "config: the file that HEADSCALE_CONFIG names",
		args:   "check config",
		env:    []string{"HEADSCALE_CONFIG={dir}/config.yaml"},
		stdout: "Configuration {dir}/config.yaml is valid.\n",
	},
	{
		name:   "config: a file",
		args:   "check config config.yaml",
		stdout: "Configuration config.yaml is valid.\n",
	},
	{
		name:   "config: --config",
		args:   "check config -c config.yaml",
		stdout: "Configuration config.yaml is valid.\n",
	},
	{
		name:   "config: the argument wins over --config",
		args:   "check config config.yaml -c bad.yaml",
		stdout: "Configuration config.yaml is valid.\n",
	},
	{
		name:   "config: stdin",
		args:   "check config -",
		stdin:  validConfig,
		stdout: "Configuration (stdin) is valid.\n",
	},
	{
		name:   "config: stdin as JSON",
		args:   "check config -",
		stdin:  `{"server_url": "https://headscale.example.com"}`,
		stdout: "Configuration (stdin) is valid.\n",
	},
	{
		name:   "config: an unknown key",
		args:   "check config bad.yaml",
		code:   1,
		stderr: "Error: loading config file bad.yaml: Fatal config error: unknown configuration key bogus_key (bad.yaml:2:1)\n\n",
	},
	{
		name:   "config: a value that is wrong",
		args:   "check config wrong.yaml",
		code:   1,
		stderr: "Error: Fatal config error: server_url is missing a scheme\n  current: server_url: \"ftp://headscale.example.com\"\n  hint: prefix the URL with https:// (recommended) or http://\n\n",
	},
	{
		name:   "config: a syntax error",
		args:   "check config syntax.yaml",
		code:   1,
		stderr: "Error: loading config file syntax.yaml: Fatal config error: cannot parse config file syntax.yaml\n  why: yaml: line 2: did not find expected node content\n\n",
	},
	{
		name:   "config: a file that does not exist",
		args:   "check config nope.yaml",
		code:   1,
		stderr: "Error: loading config file nope.yaml: fatal error reading config file: open nope.yaml: no such file or directory\n",
	},
	{
		name:   "config: --config that does not exist",
		args:   "check config -c nope.yaml",
		code:   1,
		stderr: "Error: the config file nope.yaml does not exist.\n",
	},
	{
		name:   "config: HEADSCALE_CONFIG that does not exist",
		args:   "check config",
		env:    []string{"HEADSCALE_CONFIG=nope.yaml"},
		code:   1,
		stderr: "Error: the config file nope.yaml does not exist.\n",
	},
	// A file checked before it is put where the unit's HEADSCALE_CONFIG says.
	{
		name:   "config: a file, and HEADSCALE_CONFIG that does not exist yet",
		args:   "check config config.yaml",
		env:    []string{"HEADSCALE_CONFIG=nope.yaml"},
		stdout: "Configuration config.yaml is valid.\n",
	},
	{
		name:   "config: a file, and --config that does not exist",
		args:   "check config config.yaml -c nope.yaml",
		stdout: "Configuration config.yaml is valid.\n",
	},
	{
		name:   "config: stdin with a YAML error",
		args:   "check config -",
		stdin:  "server_url: [\n",
		code:   1,
		stderr: "Error: loading config file (stdin): Fatal config error: cannot parse config file (stdin)\n  why: yaml: line 1: did not find expected node content\n\n",
	},
	{
		name:   "config: stdin with a HuJSON error",
		args:   "check config -",
		stdin:  "// a comment\n{\"server_url\": \"https://x\",, }",
		code:   1,
		stderr: "Error: loading config file (stdin): Fatal config error: cannot parse config file (stdin)\n  why: line 2, column 28: not valid HuJSON\n\n",
	},
	{
		name:   "config: a warning goes to stderr",
		args:   "check config config.yaml",
		env:    []string{"HEADSCALE_BOGUS=1"},
		stdout: "Configuration config.yaml is valid.\n",
		stderr: "warning: unknown environment variable HEADSCALE_BOGUS\n",
	},
	{
		name:   "config: a warning goes to stderr with the error",
		args:   "check config bad.yaml",
		env:    []string{"HEADSCALE_BOGUS=1"},
		code:   1,
		stderr: "warning: unknown environment variable HEADSCALE_BOGUS\nError: loading config file bad.yaml: Fatal config error: unknown configuration key bogus_key (bad.yaml:2:1)\n\n",
	},
	{
		name:   "config: an empty argument",
		args:   `check config ""`,
		code:   1,
		stderr: emptyFile("file"),
	},
	{
		name:   "all: an empty argument",
		args:   `check all ""`,
		code:   1,
		stderr: emptyFile("config-file"),
	},
	{
		name:   "all: an empty argument and --config",
		args:   `check all "" -c config.yaml`,
		code:   1,
		stderr: emptyFile("config-file"),
	},
	{
		name:   "policy: an empty argument",
		args:   `check policy ""`,
		code:   1,
		stderr: emptyFile("file"),
	},
	// --config and HEADSCALE_CONFIG name a file, - too; only the argument
	// - is stdin.
	{
		name:   "config: --config -, no such file",
		args:   "check config -c -",
		stdin:  validConfig,
		code:   1,
		stderr: "Error: the config file - does not exist.\n",
	},
	{
		name:   "config: HEADSCALE_CONFIG=-, no such file",
		args:   "check config",
		env:    []string{"HEADSCALE_CONFIG=-"},
		stdin:  validConfig,
		code:   1,
		stderr: "Error: the config file - does not exist.\n",
	},
	{
		name:   "all: --config -, no such file",
		args:   "check all -c -",
		stdin:  validConfig,
		code:   1,
		stderr: "Error: the config file - does not exist.\n",
	},
	{
		name:   "config: --config -, a file named -",
		args:   "check config -c -",
		setup:  dashFile,
		stdin:  validConfig,
		code:   1,
		stderr: dashFileError,
	},
	{
		name:   "config: HEADSCALE_CONFIG=-, a file named -",
		args:   "check config",
		env:    []string{"HEADSCALE_CONFIG=-"},
		setup:  dashFile,
		stdin:  validConfig,
		code:   1,
		stderr: dashFileError,
	},
	{
		name:   "all: HEADSCALE_CONFIG=-, a file named -",
		args:   "check all",
		env:    []string{"HEADSCALE_CONFIG=-"},
		setup:  dashFile,
		stdin:  validConfig,
		code:   1,
		stdout: "FAIL  config  -\n      loading config file -: Fatal config error: unsupported config file format \"\": use .json, .yaml, .yml or .hujson (-)\n      \n",
		stderr: "Error: check failed: config, files not checked\n",
	},
	{
		name:   "config: the argument - with a file named -",
		args:   "check config -",
		setup:  dashFile,
		stdin:  validConfig,
		stdout: "Configuration (stdin) is valid.\n",
	},
	{
		name:   "config: at most one file",
		args:   "check config a b",
		code:   1,
		stderr: "Error: `check config` takes at most 1 argument, got 2.\n\n  headscale check config [file]\n",
	},
	{
		name:   "config: no --output",
		args:   "check config -o json",
		code:   1,
		stderr: "Error: --output does not apply to `check config`.\nRun `headscale check config --help`.\n",
	},
	{
		name:   "config: the old name points here",
		args:   "configtest",
		code:   1,
		stderr: "Error: unknown command \"configtest\". It is now \"check config\".\nRun `headscale check config --help`.\n",
	},

	// check policy
	{
		name:   "policy: its tests pass",
		args:   "check policy policy.hujson",
		stdout: "Policy is valid (2 tests passed).\n",
	},
	{
		name:   "policy: one test",
		args:   "check policy onetest.hujson",
		stdout: "Policy is valid (1 test passed).\n",
	},
	{
		name:   "policy: no tests",
		args:   "check policy notests.hujson",
		stdout: "Policy is valid (no tests).\n",
	},
	{
		name:   "policy: stdin",
		args:   "check policy -",
		stdin:  twoTests,
		stdout: "Policy is valid (2 tests passed).\n",
	},
	{
		name:   "policy: a test fails",
		args:   "check policy failing.hujson",
		code:   1,
		stderr: "Error: the policy is not valid.\n  line 1, column 24: test alice@ -> bob@:22: expected accept, got deny\n",
	},
	{
		name:   "policy: a group that is not defined",
		args:   "check policy badgroup.hujson",
		code:   1,
		stderr: "Error: the policy is not valid.\n  line 1, column 40: unknown group \"group:missing\"\n",
	},
	{
		name:   "policy: stdin that is empty",
		args:   "check policy -",
		code:   1,
		stderr: "Error: the policy is not valid.\n  policy is empty, use \"{}\" to allow all\n",
	},
	{
		name:   "policy: stdin that does not end",
		args:   "check policy -",
		stdin:  strings.Repeat(" ", 16<<20+1),
		code:   1,
		stderr: "Error: (stdin) is larger than 16 MiB, more than a command reads.\n",
	},
	{
		name:   "policy: a file that does not exist",
		args:   "check policy nope.hujson",
		code:   1,
		stderr: "Error: the file nope.hujson does not exist.\n",
	},
	{
		name:   "policy: reads no config",
		args:   "check policy policy.hujson",
		env:    []string{"HEADSCALE_CONFIG={dir}/bad.yaml"},
		stdout: "Policy is valid (2 tests passed).\n",
	},
	{
		name:   "policy: a file is needed",
		args:   "check policy",
		code:   1,
		stderr: "Error: `check policy` needs 1 argument, got 0.\n\n  headscale check policy <file>\n",
	},
	{
		name:   "policy: no --config",
		args:   "check policy policy.hujson -c config.yaml",
		code:   1,
		stderr: "Error: --config does not apply to `check policy`.\nRun `headscale check policy --help`.\n",
	},

	// check derp-map
	{
		name:   "derp-map: a valid file",
		args:   "check derp-map derp.yaml",
		stdout: "DERP map derp.yaml is valid.\n",
	},
	{
		name:   "derp-map: stdin",
		args:   "check derp-map -",
		stdin:  derpMap,
		stdout: "DERP map (stdin) is valid.\n",
	},
	{
		name:   "derp-map: stdin with a JSON error",
		args:   "check derp-map -",
		stdin:  `{"Regions": {"900": }}`,
		code:   1,
		stderr: "Error: reading DERP map: decoding (stdin): hujson: line 1, column 21: invalid character '}' at start of value\n",
	},
	{
		name:   "derp-map: an empty map on stdin",
		args:   "check derp-map -",
		stdin:  "{}",
		code:   1,
		stderr: "Error: DERP map file has no regions or homeparams: (stdin)\n",
	},
	{
		name:   "derp-map: an empty map",
		args:   "check derp-map emptyderp.yaml",
		code:   1,
		stderr: "Error: DERP map file has no regions or homeparams: emptyderp.yaml\n",
	},
	{
		name:   "derp-map: a file that does not exist",
		args:   "check derp-map nope.yaml",
		code:   1,
		stderr: "Error: the file nope.yaml does not exist.\n",
	},

	// check extra-records
	{
		name:   "extra-records: a valid file",
		args:   "check extra-records records.json",
		stdout: "Extra records records.json are valid.\n",
	},
	{
		name:   "extra-records: YAML",
		args:   "check extra-records records.yaml",
		stdout: "Extra records records.yaml are valid.\n",
	},
	{
		name:   "extra-records: stdin",
		args:   "check extra-records -",
		stdin:  checkFiles["records.json"],
		stdout: "Extra records (stdin) are valid.\n",
	},
	{
		name:   "extra-records: a file that does not parse",
		args:   "check extra-records badrecords.json",
		code:   1,
		stderr: "Error: unmarshalling records: decoding badrecords.json: hujson: line 1, column 2: parsing value: unexpected EOF\n",
	},

	// check all
	{
		name: "all: every file is valid",
		args: "check all",
		env:  []string{"HEADSCALE_CONFIG={dir}/all.yaml"},
		stdout: "ok    config                  {dir}/all.yaml\n" +
			"ok    policy.path             {dir}/policy.hujson\n" +
			"ok    derp.paths              derp.yaml\n" +
			"skip  noise.private_key_path  {dir}/noise.key (missing; startup creates it)\n",
	},
	{
		name: "all: a file", args: "check all all.yaml",
		stdout: "ok    config                  all.yaml\n" +
			"ok    policy.path             {dir}/policy.hujson\n" +
			"ok    derp.paths              derp.yaml\n" +
			"skip  noise.private_key_path  {dir}/noise.key (missing; startup creates it)\n",
	},
	{
		name: "all: files that fail", args: "check all allfail.yaml", code: 1,
		stdout: "ok    config                  allfail.yaml\n" +
			"FAIL  policy.path             {dir}/failing.hujson\n" +
			"      test(s) failed:\n" +
			"      alice@ -> bob@:22: expected ALLOWED, got DENIED\n" +
			"ok    derp.paths              derp.yaml\n" +
			"FAIL  derp.paths              emptyderp.yaml\n" +
			"      DERP map file has no regions or homeparams: emptyderp.yaml\n" +
			"skip  noise.private_key_path  {dir}/noise.key (missing; startup creates it)\n",
		stderr: "Error: check failed: 2 of 4 files\n",
	},
	{
		name:   "all: a config that fails is the one line",
		args:   "check all bad.yaml",
		code:   1,
		stdout: "FAIL  config  bad.yaml\n      loading config file bad.yaml: Fatal config error: unknown configuration key bogus_key (bad.yaml:2:1)\n      \n",
		stderr: "Error: check failed: config, files not checked\n",
	},
	{
		name: "all: stdin", args: "check all -", stdin: checkFiles["all.yaml"],
		stdout: "ok    config                  (stdin)\n" +
			"ok    policy.path             {dir}/policy.hujson\n" +
			"ok    derp.paths              derp.yaml\n" +
			"skip  noise.private_key_path  {dir}/noise.key (missing; startup creates it)\n",
	},
	{
		name:   "all: a file, and --config that does not exist",
		args:   "check all config.yaml -c nope.yaml",
		stdout: "ok    config                  config.yaml\nskip  noise.private_key_path  {dir}/noise.key (missing; startup creates it)\n",
	},
	{
		name:   "all: --config that does not exist",
		args:   "check all -c nope.yaml",
		code:   1,
		stderr: "Error: the config file nope.yaml does not exist.\n",
	},
	{
		name:   "all: a config that names no file",
		args:   "check all config.yaml",
		stdout: "ok    config                  config.yaml\nskip  noise.private_key_path  {dir}/noise.key (missing; startup creates it)\n",
	},
	{
		name:   "all: no --output",
		args:   "-o json check all",
		code:   1,
		stderr: "Error: --output does not apply to `check all`.\nRun `headscale check all --help`.\n",
	},

	{name: "the group shows its help", args: "check", stdout: checkHelp},
}

const checkHelp = `Check files offline: no server, no database, no prompt

Commands:

  config [file]          Check a config file
  policy <file>          Check a policy file and run its tests
  derp-map <file>        Check a DERP map file
  extra-records <file>   Check an extra records file
  all [config-file]      Check the config and every file it points at

Examples:

  headscale check config
  headscale check policy policy.hujson
  headscale check derp-map derp.yaml
  headscale check extra-records records.json
  headscale check all
`

// TestCheck runs in a directory that holds the files it checks: the
// examples name files next to the person who runs them.
func TestCheck(t *testing.T) { //nolint:paralleltest // it changes the working directory
	runCasesIn(t, checkFiles, nil, checkCases)
}

// TestWarningOfManyLines: a warning of several lines, such as the banner of
// prefixes outside the Tailscale ranges, starts on the line of "warning: "
// and keeps its shape under it.
func TestWarningOfManyLines(t *testing.T) {
	t.Parallel()

	require.Equal(t, "warning: one line", warning("one line"))
	require.Equal(
		t,
		"warning: ####\n         # a #\n\n         ####",
		warning("\n\n####\n# a #\n\n####\n"),
	)
}
