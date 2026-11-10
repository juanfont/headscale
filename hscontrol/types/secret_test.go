package types

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveSecret(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "s"), []byte("  from-file\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty"), []byte(" \n"), 0o600))
	t.Setenv("SECRET_DIR", dir)

	tests := []struct {
		name    string
		value   string
		want    string
		wantErr string
	}{
		{name: "literal", value: "hunter2", want: "hunter2"},
		{name: "empty", value: "", want: ""},
		{name: "file is read and trimmed", value: "file:" + filepath.Join(dir, "s"), want: "from-file"},
		{name: "env in path is expanded", value: "file:${SECRET_DIR}/s", want: "from-file"},
		{name: "missing file names the key", value: "file:" + filepath.Join(dir, "missing"), wantErr: "no such file or directory"},
		{name: "empty file", value: "file:" + filepath.Join(dir, "empty"), wantErr: "is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSecret("oidc.client_secret", tt.value)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.ErrorContains(t, err, "oidc.client_secret: ")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
