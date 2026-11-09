package servertest_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

// TestServerURLOnly: a configuration that sets only server_url, from a file
// or from the environment, loads as the defaults and serves a client.
func TestServerURLOnly(t *testing.T) {
	t.Parallel()

	const serverURL = "https://headscale.example.com"

	tests := []struct {
		name string
		load func(t *testing.T) (*config.Loaded, error)
	}{
		{
			name: "file",
			load: func(t *testing.T) (*config.Loaded, error) {
				t.Helper()

				path := filepath.Join(t.TempDir(), "config.yaml")
				require.NoError(t, os.WriteFile(path, []byte("server_url: "+serverURL+"\n"), 0o600))

				return config.Load(path, true, nil)
			},
		},
		{
			name: "env",
			load: func(t *testing.T) (*config.Loaded, error) {
				t.Helper()

				l, err := config.Load(t.TempDir(), false, []string{"HEADSCALE_SERVER_URL=" + serverURL})
				assert.Empty(t, l.File)

				return l, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, err := tt.load(t)
			require.NoError(t, err)
			assert.Empty(t, l.Warnings)

			want := config.Default()
			want.ServerURL = serverURL

			diff := cmp.Diff(&want, l.Config,
				cmpopts.EquateComparable(netip.Prefix{}),
				cmpopts.IgnoreFields(types.Config{}, "ConfigDir"),
				cmpopts.IgnoreUnexported(types.Config{}),
			)
			if diff != "" {
				t.Errorf("loaded config (-want +got):\n%s", diff)
			}

			cfg := *l.Config
			// /var/lib/headscale belongs to the host and is not writable in a test.
			dir := t.TempDir()
			cfg.Noise.PrivateKeyPath = filepath.Join(dir, "noise_private.key")
			cfg.Database.Sqlite.Path = filepath.Join(dir, "db.sqlite")

			ts := servertest.NewServerFromConfig(t, cfg)
			c := servertest.NewClient(t, ts, "node1")
			c.WaitForCondition(t, "self node", 10*time.Second, func(nm *netmap.NetworkMap) bool {
				return nm.SelfNode.Valid()
			})

			nm := c.Netmap()

			addrs := nm.GetAddresses().AsSlice()
			require.Len(t, addrs, 2)

			for _, p := range []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"} {
				prefix := netip.MustParsePrefix(p)
				assert.True(t, slices.ContainsFunc(addrs, func(a netip.Prefix) bool {
					return prefix.Contains(a.Addr())
				}), "no address in %s: %v", prefix, addrs)
			}

			// No resolver is chosen for the operator: clients keep their own DNS.
			assert.Empty(t, nm.DNS.Resolvers)
			assert.Empty(t, nm.DNS.FallbackResolvers)

			require.NotEmpty(t, nm.DNS.Domains)
			assert.Equal(t, "tailnet.internal", nm.DNS.Domains[0])
			assert.True(t, strings.HasSuffix(nm.SelfNode.Name(), ".tailnet.internal."), "self name %q", nm.SelfNode.Name())
		})
	}
}
