package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
)

// TestCheckData: what a caller read is checked in the format it names, and
// named as it names it.
func TestCheckData(t *testing.T) {
	const (
		derpYAML = "regions:\n  900:\n    regionid: 900\n    regioncode: test\n    nodes:\n      - name: 900a\n        regionid: 900\n        hostname: derp.example.com\n"
		derpJSON = `{"Regions": {"900": {"RegionID": 900, "RegionCode": "test", "Nodes": [{"Name": "900a", "RegionID": 900, "HostName": "derp.example.com"}]}}}`
		records  = `[{"name": "a.example.com", "type": "A", "value": "100.64.0.1"}]`
	)

	t.Chdir(t.TempDir())

	for _, tt := range []struct {
		name    string
		check   func(ext, data string) error
		ext     string
		data    string
		wantErr string
	}{
		{name: "derp map as YAML", check: derpCheck, ext: ".yaml", data: derpYAML},
		{name: "derp map as JSON", check: derpCheck, ext: ".hujson", data: derpJSON},
		{name: "derp map with an unknown key", check: derpCheck, ext: ".yaml", data: derpYAML + "bogus: 1\n", wantErr: "bogus"},
		{name: "empty derp map", check: derpCheck, ext: ".hujson", data: "{}", wantErr: "DERP map file has no regions or homeparams: (stdin)"},
		{name: "extra records as JSON", check: recordsCheck, ext: ".hujson", data: records},
		{name: "extra records as YAML", check: recordsCheck, ext: ".yaml", data: "- name: a.example.com\n  type: A\n  value: 100.64.0.1\n"},
		{name: "no extra records", check: recordsCheck, ext: ".hujson"},
		{name: "extra records that do not parse", check: recordsCheck, ext: ".hujson", data: "[", wantErr: "unmarshalling records: decoding (stdin): "},
		{name: "config as YAML", check: configCheck, ext: ".yaml", data: "server_url: https://hs.example.com\n"},
		{name: "config as JSON", check: configCheck, ext: ".hujson", data: `{"server_url": "https://hs.example.com"}`},
		{name: "config that is not valid", check: configCheck, ext: ".yaml", data: "server_url: ftp://hs.example.com\n", wantErr: "server_url"},
		{name: "config with a syntax error", check: configCheck, ext: ".yaml", data: "server_url: [\n", wantErr: "cannot parse config file (stdin)\n"},
		{name: "config with a HuJSON error", check: configCheck, ext: ".hujson", data: `{"server_url": "https://x",, }`, wantErr: "cannot parse config file (stdin)\n  why: line 1, column 28: not valid HuJSON"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.check(tt.ext, tt.data)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
		})
	}
}

func derpCheck(ext, data string) error { return CheckDERPMapData("(stdin)", ext, []byte(data)) }

func recordsCheck(ext, data string) error { return CheckExtraRecordsData("(stdin)", ext, []byte(data)) }

func configCheck(ext, data string) error {
	l, err := CheckConfigData("(stdin)", ext, []byte(data), nil)
	if l.File != "(stdin)" {
		return errors.New("named " + l.File) //nolint:err113 // a test
	}

	return err
}

// TestCheckFileNamedDash: "-" is a file like any other here; only a caller
// that holds a stdin gives it a meaning.
func TestCheckFileNamedDash(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("-", []byte(`{"Regions": {"900": {"RegionID": 900, "RegionCode": "t", "Nodes": [{"Name": "a", "RegionID": 900, "HostName": "d.example.com"}]}}}`), 0o600))

	require.ErrorIs(t, CheckDERPMapFile("-"), util.ErrUnknownFileFormat)
	require.ErrorIs(t, CheckExtraRecordsFile("-"), util.ErrUnknownFileFormat)

	l, err := CheckConfig("-", nil)
	require.ErrorContains(t, err, `unsupported config file format ""`)
	require.Equal(t, "-", l.Source())
}

func TestCheckConfigSource(t *testing.T) {
	require.Equal(t, "(defaults and environment)", (&Loaded{}).Source())
	require.Equal(t, "/etc/headscale/config.yaml", (&Loaded{File: "/etc/headscale/config.yaml"}).Source())
}

// TestCheckReadsAtMost: a check of an endless file or stdin ends with an
// error that names it and the limit.
func TestCheckReadsAtMost(t *testing.T) {
	zero := "/dev/zero"

	_, err := os.Stat(zero)
	if err != nil {
		t.Skip("no /dev/zero")
	}

	_, err = CheckPolicy(zero)
	require.EqualError(t, err, "reading policy file: /dev/zero is larger than 16 MiB, more than a command reads")
	require.EqualError(t, CheckPolicyFile(zero), "/dev/zero is larger than 16 MiB, more than a command reads")
	require.EqualError(t, CheckDERPMapFile(zero), "reading DERP map: /dev/zero is larger than 16 MiB, more than a command reads")
	require.EqualError(t, CheckExtraRecordsFile(zero), "reading path: /dev/zero, err: /dev/zero is larger than 16 MiB, more than a command reads")

	// The format comes from the name.
	config := filepath.Join(t.TempDir(), "zero.yaml")
	require.NoError(t, os.Symlink(zero, config))

	_, err = CheckConfig(config, nil)
	require.ErrorContains(t, err, "fatal error reading config file: "+config+" is larger than 16 MiB, more than a command reads")

	_, err = ReadAtMost("(stdin)", strings.NewReader("12345"), 4)
	require.ErrorContains(t, err, "(stdin) is larger than")

	// The server reads a policy of any size; a check takes what the API
	// would refuse, 1 MiB and more.
	big := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(big, []byte(`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`+strings.Repeat(" ", 2<<20)), 0o600))
	_, err = CheckPolicy(big)
	require.NoError(t, err)
	require.NoError(t, CheckPolicyFile(big))

	b, err := ReadAtMost("(stdin)", strings.NewReader("1234"), 4)
	require.NoError(t, err)
	require.Equal(t, "1234", string(b))
}

// TestCheckPolicyCounts: the tests and sshTests that passed are counted.
func TestCheckPolicyCounts(t *testing.T) {
	const twoTests = `{
  "tagOwners": {"tag:web": ["alice@"]},
  "acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:22"]}],
  "ssh": [{"action": "accept", "src": ["alice@"], "dst": ["tag:web"], "users": ["root"]}],
  "tests": [{"src": "alice@", "accept": ["bob@:22"]}],
  "sshTests": [{"src": "alice@", "dst": ["tag:web"], "accept": ["root"]}],
}`

	for _, tt := range []struct {
		name, policy string
		want         int
		wantErr      string
	}{
		{name: "no tests", policy: `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`},
		{name: "tests and sshTests", policy: twoTests, want: 2},
		{name: "a test that fails", policy: `{"acls": [], "tests": [{"src": "alice@", "accept": ["bob@:22"]}]}`, wantErr: "test(s) failed"},
		{name: "empty", policy: "", wantErr: "policy is empty"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.hujson")
			require.NoError(t, os.WriteFile(path, []byte(tt.policy), 0o600))

			for _, got := range []func() (int, error){
				func() (int, error) { return CheckPolicy(path) },
				func() (int, error) { return CheckPolicyData([]byte(tt.policy)) },
			} {
				n, err := got()
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)

					continue
				}

				require.NoError(t, err)
				require.Equal(t, tt.want, n)
			}
		})
	}

	_, err := CheckPolicy(filepath.Join(t.TempDir(), "nope.hujson"))
	require.ErrorIs(t, err, os.ErrNotExist)
	require.ErrorContains(t, err, "reading policy file: ")

	// What API v0 refuses before it parses a policy, CheckPolicyText
	// refuses too; CheckPolicyData, the old CLI's, takes it as it did.
	for _, text := range []string{"null\n", "{\"acls\": []}\n// \x00\n"} {
		_, err := CheckPolicyText([]byte(text))
		require.Error(t, err, "%q", text)

		_, err = CheckPolicyData([]byte(text))
		require.NoError(t, err, "%q", text)
	}

	n, err := CheckPolicyText([]byte(twoTests))
	require.NoError(t, err)
	require.Equal(t, 2, n)
}
