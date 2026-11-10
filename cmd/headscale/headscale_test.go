package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/config"
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
	l, err := config.Load(cfgFile, true, os.Environ())
	require.NoError(t, err)

	assertExampleConfig(t, l.Config)
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
	l, err := config.Load(tmpDir, false, os.Environ())
	require.NoError(t, err)

	assertExampleConfig(t, l.Config)
}

// assertExampleConfig checks the loaded config-example.yaml was interpreted
// correctly.
func assertExampleConfig(t *testing.T, cfg *types.Config) {
	t.Helper()

	require.NoError(t, config.Validate(cfg))

	assert.Equal(t, "http://127.0.0.1:8080", cfg.ServerURL)
	assert.Equal(t, types.ListenAddr("127.0.0.1:8080"), cfg.Addr)
	assert.Equal(t, types.ListenAddr("127.0.0.1:9090"), cfg.MetricsAddr)
	assert.True(t, cfg.Database.IsSQLite(), cfg.Database.Type)
	assert.Equal(t, "/var/lib/headscale/db.sqlite", cfg.SQLitePath())
	assert.Empty(t, cfg.TLS.ACME.Hostname)
	assert.Equal(t, types.ListenAddr(":http"), cfg.TLS.ACME.HTTPListen)
	assert.Equal(t, types.HTTP01ChallengeType, cfg.TLS.ACME.ChallengeType)
	assert.Equal(t, types.FileMode(0o770), cfg.UnixSocketPermission)
	assert.False(t, cfg.LogTail.Enabled)
}
