package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSkipsInitConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"check policy", []string{"check", "policy", "-f", "p"}, true},
		{"check policy with config flag", []string{"-c", "x.yaml", "check", "policy"}, true},
		{"check", []string{"check"}, true},
		{"help check policy", []string{"help", "check", "policy"}, true},
		{"policy get", []string{"policy", "get"}, false},
		{"help nodes", []string{"help", "nodes"}, false},
		{"nodes list", []string{"nodes", "list"}, false},
	}

	// Execute adds the help command; these tests call Find without it.
	rootCmd.InitDefaultHelpCmd()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, skipsInitConfig(tt.args))
		})
	}
}

func newCheckPolicyCmd(t *testing.T, path string) (*cobra.Command, *bytes.Buffer) {
	t.Helper()

	cmd := &cobra.Command{}
	cmd.Flags().String("file", path, "")

	var buf bytes.Buffer

	cmd.SetOut(&buf)

	return cmd, &buf
}

func TestCheckPolicy(t *testing.T) {
	const (
		valid       = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
		failingTest = `{"acls":[],"tests":[{"src":"alice@","accept":["bob@:22"]}]}`
		passingTest = `{"acls":[{"action":"accept","src":["alice@"],"dst":["bob@:22"]}],"tests":[{"src":"alice@","accept":["bob@:22"]}]}` //nolint:gosec // policy fixture
		failingSSH  = `{"tagOwners":{"tag:web":["alice@"]},"sshTests":[{"src":"alice@","dst":["tag:web"],"accept":["root"]}]}`
	)

	writePolicy := func(t *testing.T, body string) string {
		t.Helper()

		p := filepath.Join(t.TempDir(), "policy.hujson")
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))

		return p
	}

	for _, tt := range []struct {
		name    string
		policy  string
		wantErr string
	}{
		{"valid", valid, ""},
		{"empty file", "", ""},
		{"tests pass", passingTest, ""},
		{"tests fail", failingTest, "test(s) failed"},
		{"sshTests fail", failingSSH, "test(s) failed"},
		{"undefined group", `{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`, policyv2.ErrGroupNotDefined.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd, out := newCheckPolicyCmd(t, writePolicy(t, tt.policy))

			err := checkPolicyCmd.RunE(cmd, nil)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Empty(t, out.String())

				return
			}

			require.NoError(t, err)
			require.Equal(t, "Policy is valid\n", out.String())
		})
	}

	t.Run("missing file", func(t *testing.T) {
		cmd, _ := newCheckPolicyCmd(t, filepath.Join(t.TempDir(), "nope.hujson"))
		require.ErrorIs(t, checkPolicyCmd.RunE(cmd, nil), os.ErrNotExist)
	})

	t.Run("broken config ignored", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		require.NoError(t, os.WriteFile(bad, []byte("server_url: ["), 0o600))
		t.Setenv("HEADSCALE_CONFIG", bad)

		cmd, _ := newCheckPolicyCmd(t, writePolicy(t, valid))
		require.NoError(t, checkPolicyCmd.RunE(cmd, nil))
	})
}
