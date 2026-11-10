package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFileLoading(t *testing.T) {
	tmpDir := t.TempDir()

	path, err := os.Getwd()
	require.NoError(t, err)

	cfgFile := filepath.Join(tmpDir, "config.yaml")

	// Symlink the example config file
	err = os.Symlink(
		filepath.Clean(path+"/../../config-example.yaml"),
		cfgFile,
	)
	require.NoError(t, err)

	// Load example config, it should load without validation errors
	err = types.LoadConfig(cfgFile, true)
	require.NoError(t, err)

	assertExampleConfig(t)
}

func TestConfigLoading(t *testing.T) {
	tmpDir := t.TempDir()

	path, err := os.Getwd()
	require.NoError(t, err)

	// Symlink the example config file
	err = os.Symlink(
		filepath.Clean(path+"/../../config-example.yaml"),
		filepath.Join(tmpDir, "config.yaml"),
	)
	require.NoError(t, err)

	// Load example config, it should load without validation errors
	err = types.LoadConfig(tmpDir, false)
	require.NoError(t, err)

	assertExampleConfig(t)
}

// assertExampleConfig checks the loaded config-example.yaml was interpreted
// correctly.
func assertExampleConfig(t *testing.T) {
	t.Helper()

	cfg, err := types.LoadServerConfig()
	require.NoError(t, err)

	assert.Equal(t, "http://127.0.0.1:8080", cfg.ServerURL)
	assert.Equal(t, "127.0.0.1:8080", cfg.Addr)
	assert.Equal(t, "127.0.0.1:9090", cfg.MetricsAddr)
	assert.Equal(t, types.DatabaseSqlite, cfg.Database.Type)
	assert.Equal(t, "/var/lib/headscale/db.sqlite", cfg.Database.Sqlite.Path)
	assert.Empty(t, cfg.TLS.ACME.Hostname)
	assert.Equal(t, ":http", cfg.TLS.ACME.HTTPListen)
	assert.Equal(t, "HTTP-01", cfg.TLS.ACME.ChallengeType)
	assert.Equal(t, fs.FileMode(0o770), cfg.UnixSocketPermission)
	assert.False(t, cfg.LogTail.Enabled)
}
