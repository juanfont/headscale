package v2

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestSetUsersRecompilesPerNodeGrants checks that a user change which only
// affects per-node grants (via, autogroup:self) is reported as a policy change
// and reaches the per-node filters. Those grants are absent from the global
// filter, so its hash alone cannot detect the change, and a node whose filter
// was already cached would otherwise keep a stale one.
func TestSetUsersRecompilesPerNodeGrants(t *testing.T) {
	alice, bob := idpTestUsers()

	tests := []struct {
		name   string
		pol    string
		before types.Users
		after  types.Users
		// node whose per-node filter is checked, by index into the nodes
		node int
	}{
		{
			name: "via grant loses a group member",
			pol: `{
				"tagOwners": {"tag:router": ["alice@example.com"]},
				"grants": [{"src": ["group:eng@example.com"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:router"]}]
			}`,
			before: types.Users{withGroups(alice, "eng@example.com"), bob},
			after:  types.Users{alice, bob},
			node:   2,
		},
		{
			name: "via grant gains a group member",
			pol: `{
				"tagOwners": {"tag:router": ["alice@example.com"]},
				"grants": [{"src": ["group:eng@example.com"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:router"]}]
			}`,
			before: types.Users{alice, bob},
			after:  types.Users{withGroups(alice, "eng@example.com"), bob},
			node:   2,
		},
		{
			name: "autogroup:self loses a group member",
			pol: `{
				"grants": [{"src": ["group:eng@example.com"], "dst": ["autogroup:self"], "ip": ["*"]}]
			}`,
			before: types.Users{withGroups(alice, "eng@example.com"), bob},
			after:  types.Users{alice, bob},
			node:   0,
		},
		{
			name: "autogroup:self source user renamed",
			pol: `{
				"grants": [{"src": ["alice@example.com"], "dst": ["autogroup:self"], "ip": ["*"]}]
			}`,
			before: types.Users{alice, bob},
			after: func() types.Users {
				renamed := alice
				renamed.Email = "alice@renamed.example"

				return types.Users{renamed, bob}
			}(),
			node: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodes := idpTestNodes(alice, bob)
			nodes[2].Tags = []string{"tag:router"}
			nodes[2].ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
			nodes[2].Hostinfo = &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			}

			pm := newIdPTestPM(t, tt.pol, tt.before, nodes)
			node := nodes[tt.node].View()

			before, err := pm.FilterForNode(node)
			require.NoError(t, err)

			changed, _, err := pm.SetUsers(tt.after)
			require.NoError(t, err)

			fresh := newIdPTestPM(t, tt.pol, tt.after, nodes)
			want, err := fresh.FilterForNode(node)
			require.NoError(t, err)
			require.NotEqual(t, want, before, "test setup must change the node's filter")

			got, err := pm.FilterForNode(node)
			require.NoError(t, err)
			assert.Equal(t, want, got, "the per-node filter must match a freshly compiled policy")
			assert.True(t, changed, "the change must be reported so it is broadcast")
		})
	}
}
