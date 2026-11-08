package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    string
	}{
		{
			name:    "bare host defaults to https",
			address: "headscale.example.com:50443",
			want:    "https://headscale.example.com:50443",
		},
		{
			name:    "explicit https scheme is kept",
			address: "https://headscale.example.com",
			want:    "https://headscale.example.com",
		},
		{
			name:    "explicit http scheme is kept",
			address: "http://localhost:8080",
			want:    "http://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientBaseURL(tt.address); got != tt.want {
				t.Errorf("clientBaseURL(%q) = %q, want %q", tt.address, got, tt.want)
			}
		})
	}
}

// TestCLIAPIKey pins that only a remote CLI reads cli.api_key; over the unix
// socket the key is never read.
func TestCLIAPIKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	require.NoError(t, os.WriteFile(keyFile, []byte("from-file\n"), 0o600))

	missing := "file:" + filepath.Join(dir, "missing")

	tests := []struct {
		name    string
		address string
		apiKey  string
		want    string // the key a remote CLI sends
		wantErr string
	}{
		{name: "remote literal", address: "headscale.example.com:443", apiKey: "literal", want: "literal"},
		{name: "remote reads the file", address: "headscale.example.com:443", apiKey: "file:" + keyFile, want: "from-file"},
		{name: "remote file missing", address: "headscale.example.com:443", apiKey: missing, wantErr: "cli.api_key: "},
		{name: "remote without a key", address: "headscale.example.com:443", wantErr: errAPIKeyNotSet.Error()},
		{name: "socket never reads", apiKey: missing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgDir := t.TempDir()
			cfgPath := filepath.Join(cfgDir, "config.yaml")
			require.NoError(t, os.WriteFile(cfgPath,
				[]byte("unix_socket: "+filepath.Join(cfgDir, "headscale.sock")+"\n"), 0o600))
			t.Setenv("HEADSCALE_CLI_ADDRESS", tt.address)
			t.Setenv("HEADSCALE_CLI_API_KEY", tt.apiKey)
			useLoaded(t, cfgPath)

			if tt.address != "" && tt.wantErr == "" {
				got, err := cliAPIKey(loaded.Config.CLI)
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}

			_, _, cancel, err := newHeadscaleCLIWithConfig()
			_, _, cancelV2, errV2 := newV2Client()

			for _, err := range []error{err, errV2} {
				if tt.wantErr != "" {
					require.ErrorContains(t, err, tt.wantErr)
				} else {
					require.NoError(t, err)
				}
			}

			if err == nil {
				cancel()
				cancelV2()
			}
		})
	}
}

// TestServerConfigDropsCLIKey: the server never holds the CLI's key, which
// may be a file only the CLI can read.
func TestServerConfigDropsCLIKey(t *testing.T) {
	dir := t.TempDir()
	useLoaded(t, writeServerConfig(t, dir, "cli:\n  api_key: file:"+filepath.Join(dir, "missing")+"\n"))

	assert.Empty(t, serverConfig().CLI.APIKey)
}

// TestBypassDatabaseValidates: the policy commands' --bypass path, which
// starts no server, validates the configuration before opening the
// database.
func TestBypassDatabaseValidates(t *testing.T) {
	dir := t.TempDir()
	useLoaded(t, writeServerConfig(t, dir, "node:\n  ephemeral:\n    inactivity_timeout: 1s\n"))

	_, err := bypassDatabase()
	require.ErrorContains(t, err, "node.ephemeral.inactivity_timeout is below the minimum")
	assert.NoFileExists(t, filepath.Join(dir, "headscale.db"))
}
