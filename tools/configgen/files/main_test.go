package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestWrite(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "nix"), 0o755))
	require.NoError(t, write(root))

	want, err := config.GenerateNixOptions(nil)
	require.NoError(t, err)

	tests := []struct {
		path string
		want []byte
	}{
		{path: "nix/options.generated.nix", want: want},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, err := os.ReadFile(filepath.Join(root, tt.path))
			require.NoError(t, err)

			if diff := cmp.Diff(string(tt.want), string(got)); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

// TestLoad: load prints a file as config.Load reads it, in canonical form
// and without the cli section; it fails on what Load rejects.
func TestLoad(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"server_url": "https://example.com", "node": {"ephemeral": {"inactivity_timeout": "60m"}}, "cli": {"timeout": "9s"}}`), 0o600))

	var buf bytes.Buffer
	require.NoError(t, load(&buf, path))

	var got map[string]any
	require.NoError(t, yaml.Unmarshal(buf.Bytes(), &got))
	assert.Equal(t, "https://example.com", got["server_url"])
	assert.Equal(t, "1h", got["node"].(map[string]any)["ephemeral"].(map[string]any)["inactivity_timeout"])
	assert.NotContains(t, got, "cli")

	broken := filepath.Join(dir, "broken.json")
	require.NoError(t, os.WriteFile(broken, []byte(`{"bogus_key": 1}`), 0o600))
	require.Error(t, load(io.Discard, broken))
}
