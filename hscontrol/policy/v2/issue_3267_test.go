package v2

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

const issue3267AliceEmail = "alice@headscale.net"

// TestIssue3267ViaGrantBroaderDestination locks the SaaS contract for
// a via grant whose destination is a host alias broader than (or
// narrower than) the router's advertised subnet route. Alice's only
// path into the subnet is via tag:subnet-router. The grant destination
// resolves to a /64 (IPv6) or /16 (IPv4), and the router advertises a
// contained /120 / /24. Pre-fix the policy compiler emitted no rule
// and ViaRoutesForPeer left Include empty because the prefix relation
// was checked by slices.Contains (exact equality). SaaS behaviour is
// the authority — see testdata/grant_results/via-grant-v47..v51 for
// the equivalent compatibility regression.
func TestIssue3267ViaGrantBroaderDestination(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "alice", Email: issue3267AliceEmail}, //nolint:goconst
	}

	cases := []struct {
		name       string
		hostAlias  string
		dst        string // value the hosts alias resolves to
		advertised string // narrower prefix the router actually serves
	}{
		{
			name:       "ipv6_4via6_64_dst_with_120_advertised",
			hostAlias:  "example-4via6",
			dst:        "fd7a:115c:a1e0:b1a::/64",
			advertised: "fd7a:115c:a1e0:b1a:0:13:ad2:7300/120",
		},
		{
			name:       "ipv4_16_dst_with_24_advertised",
			hostAlias:  "subnet",
			dst:        "10.33.0.0/16",
			advertised: "10.33.5.0/24",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			aliceLaptop := node("alice-laptop", "100.64.0.10", "fd7a:115c:a1e0::a", users[0])
			aliceLaptop.ID = 1

			router := node("subnet-router", "100.64.0.11", "fd7a:115c:a1e0::b", users[0])
			router.ID = 2
			router.Tags = []string{"tag:subnet-router"}
			route := netip.MustParsePrefix(tc.advertised)
			router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			router.ApprovedRoutes = []netip.Prefix{route}

			nodes := types.Nodes{aliceLaptop, router}

			policy := `{
				"tagOwners": {
					"tag:subnet-router": ["` + issue3267AliceEmail + `"]
				},
				"hosts": {
					"` + tc.hostAlias + `": "` + tc.dst + `"
				},
				"grants": [
					{
						"src": ["` + issue3267AliceEmail + `"],
						"dst": ["` + tc.hostAlias + `"],
						"via": ["tag:subnet-router"],
						"ip": ["icmp:*"]
					}
				]
			}`

			pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
			require.NoError(t, err)

			pol, err := unmarshalPolicy([]byte(policy))
			require.NoError(t, err)
			require.NoError(t, pol.validate())

			t.Run("compileFilterRulesForNode_emits_rule_with_grant_dst", func(t *testing.T) {
				t.Parallel()

				rules := pol.compileFilterRulesForNode(users, router.View(), nodes.ViewSlice())

				found := slices.ContainsFunc(rules, func(r tailcfg.FilterRule) bool {
					return slices.ContainsFunc(r.DstPorts, func(d tailcfg.NetPortRange) bool {
						return d.IP == tc.dst
					})
				})
				require.Truef(t, found,
					"router %s must receive a via filter rule whose DstPorts.IP equals the grant dst %q; got rules=%+v",
					router.Hostname, tc.dst, rules)
			})

			t.Run("ViaRoutesForPeer_includes_advertised_prefix", func(t *testing.T) {
				t.Parallel()

				result := pm.ViaRoutesForPeer(aliceLaptop.View(), router.View())
				require.Contains(t, result.Include, route,
					"alice viewing tag:subnet-router must Include advertised prefix %s — drives AllowedIPs in state.RoutesForPeer", route)
				require.Empty(t, result.Exclude,
					"alice viewing tag:subnet-router must not Exclude any prefix — there is no competing via tag")
			})
		})
	}
}
