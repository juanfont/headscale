package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFileLoading(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "headscale")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

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

	// Test that config file was interpreted correctly
	assert.Equal(t, "http://127.0.0.1:8080", viper.GetString("server_url"))
	assert.Equal(t, "127.0.0.1:8080", viper.GetString("listen_addr"))
	assert.Equal(t, "127.0.0.1:9090", viper.GetString("metrics_listen_addr"))
	assert.Equal(t, "sqlite", viper.GetString("database.type"))
	assert.Equal(t, "/var/lib/headscale/db.sqlite", viper.GetString("database.sqlite.path"))
	assert.Empty(t, viper.GetString("tls_letsencrypt_hostname"))
	assert.Equal(t, ":http", viper.GetString("tls_letsencrypt_listen"))
	assert.Equal(t, "HTTP-01", viper.GetString("tls_letsencrypt_challenge_type"))
	assert.Equal(t, fs.FileMode(0o770), util.GetFileMode("unix_socket_permission"))
	assert.False(t, viper.GetBool("logtail.enabled"))
}

func TestConfigLoading(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "headscale")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

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

	// Test that config file was interpreted correctly
	assert.Equal(t, "http://127.0.0.1:8080", viper.GetString("server_url"))
	assert.Equal(t, "127.0.0.1:8080", viper.GetString("listen_addr"))
	assert.Equal(t, "127.0.0.1:9090", viper.GetString("metrics_listen_addr"))
	assert.Equal(t, "sqlite", viper.GetString("database.type"))
	assert.Equal(t, "/var/lib/headscale/db.sqlite", viper.GetString("database.sqlite.path"))
	assert.Empty(t, viper.GetString("tls_letsencrypt_hostname"))
	assert.Equal(t, ":http", viper.GetString("tls_letsencrypt_listen"))
	assert.Equal(t, "HTTP-01", viper.GetString("tls_letsencrypt_challenge_type"))
	assert.Equal(t, fs.FileMode(0o770), util.GetFileMode("unix_socket_permission"))
	assert.False(t, viper.GetBool("logtail.enabled"))
	assert.False(t, viper.GetBool("randomize_client_port"))
}
