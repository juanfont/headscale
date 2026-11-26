package integration

import (
	"encoding/json"
	"strings"
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// TestServerInfoCommands covers the standalone server/info commands that do not
// fit the resource CRUD groups: `debug health`, `version`, the checks of the
// config and the policy, and `generate private-key` and `generate config`.
// They are exercised against a populated server (one user with a node) so
// `debug health` reports a real, connected database, and the checks read the
// config the server runs with.
func TestServerInfoCommands(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-serverinfo", []string{"user1"}, 1)
	defer scenario.ShutdownAssertNoPanics(t)

	t.Run("health", func(t *testing.T) {
		health := assertJSONRoundtrip[*clientv0.Health](t, headscale, []string{
			"headscale", "debug", "health", "--output", "json",
		})
		assert.True(t, health.DatabaseConnectivity, "database should be reachable")
		assert.True(t, health.Healthy, "server should be healthy")
	})

	t.Run("version", func(t *testing.T) {
		info := assertJSONRoundtrip[types.VersionInfo](t, headscale, []string{
			"headscale", "version", "--output", "json",
		})
		assert.NotEmpty(t, info.Version, "version string should be populated")
		assert.NotEmpty(t, info.Go.Version, "go version should be populated")
	})

	t.Run("generate-private-key", func(t *testing.T) {
		// generate has no --output: it prints the key alone.
		out, err := headscale.Execute([]string{"headscale", "generate", "private-key"})
		require.NoError(t, err)

		priv := strings.TrimSpace(out)
		assert.NotEmpty(t, priv, "generated private key should not be empty")
		assert.Contains(t, priv, "privkey:", "machine private key should carry the privkey: prefix")
	})

	t.Run("check-config", func(t *testing.T) {
		out, err := headscale.Execute([]string{"headscale", "check", "config"})
		require.NoError(t, err)
		assert.Contains(t, out, "is valid.")
	})

	t.Run("check-all", func(t *testing.T) {
		out, err := headscale.Execute([]string{"headscale", "check", "all"})
		require.NoError(t, err)
		assert.Contains(t, out, "noise.private_key_path")
	})

	t.Run("check-policy", func(t *testing.T) {
		const path = "/tmp/check-policy.json"

		pol, err := json.Marshal(allowAllWithTagOwners("user1", "tag:check"))
		require.NoError(t, err)
		require.NoError(t, headscale.WriteFile(path, pol))

		out, err := headscale.Execute([]string{"headscale", "check", "policy", path})
		require.NoError(t, err)
		assert.Contains(t, out, "Policy is valid")

		require.NoError(t, headscale.WriteFile(path, []byte(`{"acls": [{"action": "unknown-action"}]}`)))

		_, err = headscale.Execute([]string{"headscale", "check", "policy", path})
		require.ErrorContains(t, err, "the policy is not valid.")
	})

	t.Run("generate-config-running", func(t *testing.T) {
		// The config of the running server, as YAML, with its secrets hidden.
		out, err := headscale.Execute([]string{"headscale", "generate", "config", "--running"})
		require.NoError(t, err)

		var cfg map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(out), &cfg))
		assert.Contains(t, cfg, "server_url")
		assert.NotContains(t, cfg, "cli", "the running config leaves out the cli section")
	})
}
