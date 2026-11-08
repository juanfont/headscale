package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// generatedFiles are the files write writes, below the repository root.
var generatedFiles = []string{"nix/options.generated.nix", "docs/ref/configuration-options.md", "docs/ref/config-example.yaml"}

// writeTree runs write into a new repository root.
func writeTree(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	for _, dir := range []string{"nix", "docs/ref"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
	}

	require.NoError(t, write(root))

	return root
}

func TestWrite(t *testing.T) {
	root := writeTree(t)

	nix, err := config.GenerateNixOptions(nil)
	require.NoError(t, err)

	page, err := config.GenerateReference()
	require.NoError(t, err)

	d := config.Default()
	example, err := config.GenerateExample(&d, config.ExampleOptions{Docs: true})
	require.NoError(t, err)

	tests := []struct {
		path string
		want []byte
	}{
		{path: "nix/options.generated.nix", want: nix},
		{path: "docs/ref/configuration-options.md", want: page},
		{path: "docs/ref/config-example.yaml", want: append([]byte("# Generated from hscontrol/types/config.go by go generate; do not edit.\n"), example...)},
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

// TestGeneratedFiles: each file is the same on every run, ends in one
// newline and has no trailing whitespace, so the repository's hooks leave
// it alone.
func TestGeneratedFiles(t *testing.T) {
	first, second := writeTree(t), writeTree(t)
	trailing := regexp.MustCompile(`(?m)[ \t]$`)

	for _, path := range generatedFiles {
		t.Run(path, func(t *testing.T) {
			a, err := os.ReadFile(filepath.Join(first, path))
			require.NoError(t, err)

			b, err := os.ReadFile(filepath.Join(second, path))
			require.NoError(t, err)

			require.Equal(t, a, b)
			require.True(t, bytes.HasSuffix(a, []byte("\n")) && !bytes.HasSuffix(a, []byte("\n\n")), "must end in one newline")
			require.Empty(t, trailing.FindAll(a, -1), "trailing whitespace")
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
