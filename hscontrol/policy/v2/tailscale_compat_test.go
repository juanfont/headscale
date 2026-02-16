// This file is "generated" by Claude.
// It contains a large set of input ACL/Policy JSON configurations that
// the AI agent has systematically applied to a Tailnet on Tailscale SaaS
// and then observed the individual clients connected to the Tailnet
// with a given policy and recorded the resulting Packet filter rules sent
// to the clients.
//
// There is likely a lot of duplicate or overlapping tests, however, the main
// exercise of this work was to create a comperehensive test set for comparing
// the behaviour of our policy engine and the upstream one.
//
// We aim to keep these tests to make sure we do not regress as we evolve
// and improve our policy implementation.
// This file is NOT intended for developer/humans to change and should be
// consider a "black box" test suite.
package v2

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// ptrAddr is a helper to create a pointer to a netip.Addr.
func ptrAddr(s string) *netip.Addr {
	addr := netip.MustParseAddr(s)
	return &addr
}

// setupTailscaleCompatUsers returns the test users for compatibility tests.
func setupTailscaleCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "kratail2tid"},
	}
}

// setupTailscaleCompatNodes returns the test nodes for compatibility tests.
// The node configuration matches the Tailscale test environment:
// - 1 user-owned node (user1)
// - 4 tagged nodes (tagged-server, tagged-client, tagged-db, tagged-web).
func setupTailscaleCompatNodes(users types.Users) types.Nodes {
	// Node: user1 - User-owned by kratail2tid
	nodeUser1 := &types.Node{
		ID:        1,
		GivenName: "user1",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv4:      ptrAddr("100.90.199.68"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	// Node: tagged-server - Has tag:server
	nodeTaggedServer := &types.Node{
		ID:        2,
		GivenName: "tagged-server",
		IPv4:      ptrAddr("100.108.74.26"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
		Tags:      []string{"tag:server"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	// Node: tagged-client - Has tag:client
	nodeTaggedClient := &types.Node{
		ID:        3,
		GivenName: "tagged-client",
		IPv4:      ptrAddr("100.80.238.75"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::7901:ee86"),
		Tags:      []string{"tag:client"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	// Node: tagged-db - Has tag:database
	nodeTaggedDB := &types.Node{
		ID:        4,
		GivenName: "tagged-db",
		IPv4:      ptrAddr("100.74.60.128"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2f01:3c9c"),
		Tags:      []string{"tag:database"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	// Node: tagged-web - Has tag:web
	nodeTaggedWeb := &types.Node{
		ID:        5,
		GivenName: "tagged-web",
		IPv4:      ptrAddr("100.94.92.91"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::ef01:5c81"),
		Tags:      []string{"tag:web"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	return types.Nodes{
		nodeUser1,
		nodeTaggedServer,
		nodeTaggedClient,
		nodeTaggedDB,
		nodeTaggedWeb,
	}
}

// findNodeByGivenName finds a node by its GivenName field.
func findNodeByGivenName(nodes types.Nodes, name string) *types.Node {
	for _, n := range nodes {
		if n.GivenName == name {
			return n
		}
	}

	return nil
}

// tailscaleCompatTest defines a test case for Tailscale compatibility testing.
type tailscaleCompatTest struct {
	name        string                          // Test name
	policy      string                          // HuJSON policy as multiline raw string
	wantFilters map[string][]tailcfg.FilterRule // node GivenName -> expected filters
}

// basePolicyTemplate provides the standard groups, tagOwners, and hosts
// that are used in all Tailscale compatibility tests.
const basePolicyPrefix = `{
	"groups": {
		"group:admins": ["kratail2tid@"],
		"group:developers": ["kratail2tid@"],
		"group:empty": []
	},
	"tagOwners": {
		"tag:server": ["kratail2tid@"],
		"tag:client": ["kratail2tid@"],
		"tag:database": ["kratail2tid@"],
		"tag:web": ["kratail2tid@"]
	},
	"hosts": {
		"webserver": "100.108.74.26",
		"database": "100.74.60.128",
		"internal": "10.0.0.0/8",
		"subnet24": "192.168.1.0/24"
	},
	"acls": [`

const basePolicySuffix = `
	]
}`

// makePolicy creates a full policy from just the ACL rules portion.
func makePolicy(aclRules string) string {
	return basePolicyPrefix + aclRules + basePolicySuffix
}

// cmpOptions returns comparison options for FilterRule slices.
// It sorts SrcIPs and DstPorts to handle ordering differences.
func cmpOptions() []cmp.Option {
	return []cmp.Option{
		cmpopts.SortSlices(func(a, b string) bool { return a < b }),
		cmpopts.SortSlices(func(a, b tailcfg.NetPortRange) bool {
			if a.IP != b.IP {
				return a.IP < b.IP
			}

			if a.Ports.First != b.Ports.First {
				return a.Ports.First < b.Ports.First
			}

			return a.Ports.Last < b.Ports.Last
		}),
		cmpopts.SortSlices(func(a, b int) bool { return a < b }),
	}
}

// Tailscale uses partitioned CGNAT CIDR ranges for wildcard source expansion
// (excluding the ChromeOS VM range 100.115.92.0/23). Headscale uses the simpler
// full CGNAT range (100.64.0.0/10) and Tailscale ULA range (fd7a:115c:a1e0::/48).
// This is functionally equivalent for access control purposes.
//
// For reference, Tailscale's partitioned ranges are:
// var tailscaleCGNATCIDRs = []string{
// 	"100.64.0.0/11",
// 	"100.96.0.0/12",
// 	"100.112.0.0/15",
// 	"100.114.0.0/16",
// 	"100.115.0.0/18",
// 	"100.115.64.0/20",
// 	"100.115.80.0/21",
// 	"100.115.88.0/22",
// 	"100.115.94.0/23",
// 	"100.115.96.0/19",
// 	"100.115.128.0/17",
// 	"100.116.0.0/14",
// 	"100.120.0.0/13",
// 	"fd7a:115c:a1e0::/48",
// }

// TestTailscaleCompatWildcardACLs tests wildcard ACL rules (* source and destination).
// These are the most fundamental tests for basic allow-all and IP-based rules.
func TestTailscaleCompatWildcardACLs(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "allow_all_wildcard",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["*:*"]}
	`),
			// All nodes receive the same filter for allow-all rule.
			// NOTE: Tailscale expands `*` source to partitioned CGNAT CIDR ranges:
			// 100.64.0.0/11, 100.96.0.0/12, 100.112.0.0/15, etc. plus fd7a:115c:a1e0::/48
			// Headscale uses the full 100.64.0.0/10 and fd7a:115c:a1e0::/48 ranges.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full range.
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "single_ip_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["100.90.199.68"], "dst": ["*:*"]}
	`),
			// Single IP source: Headscale resolves the IP to a node and includes ALL of the
			// node's IPs (both IPv4 and IPv6). Tailscale uses only the literal IP specified.
			// TODO: Tailscale only includes the literal IP "100.90.199.68/32" without IPv6.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// TODO: Tailscale only includes the literal IP:
						// SrcIPs: []string{"100.90.199.68/32"},
						// Headscale: Resolves IP to node and includes ALL node IPs (IPv4+IPv6)
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "cidr_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["100.64.0.0/16"], "dst": ["*:*"]}
	`),
			// CIDR source is passed through unchanged to the filter.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{"100.64.0.0/16"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{"100.64.0.0/16"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{"100.64.0.0/16"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{"100.64.0.0/16"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{"100.64.0.0/16"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "single_ip_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["100.108.74.26:*"]}
	`),
			// Single IP destination: ONLY that node receives the filter.
			// KEY INSIGHT: Destination filters are only sent to nodes that ARE the destination.
			// NOTE: This IP (100.108.74.26) is tagged-server.
			// NOTE: Headscale resolves the IP to a node and includes ALL of the node's IPs.
			// TODO: Tailscale only includes the literal destination IP without IPv6.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// TODO: Tailscale only includes the literal destination IP:
						// DstPorts: []tailcfg.NetPortRange{
						// 	{IP: "100.108.74.26/32", Ports: tailcfg.PortRangeAny},
						// },
						// Headscale: Resolves IP to node and includes ALL node IPs (IPv4+IPv6)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "cidr_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["100.64.0.0/12:*"]}
	`),
			// CIDR destination: only nodes with IPs in the CIDR range receive the filter.
			// 100.64.0.0/12 covers 100.64.0.0 - 100.79.255.255
			// Of our test nodes, only tagged-db (100.74.60.128) falls in this range.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil, // 100.90.199.68 is NOT in 100.64.0.0/12
				"tagged-server": nil, // 100.108.74.26 is NOT in 100.64.0.0/12
				"tagged-client": nil, // 100.80.238.75 is NOT in 100.64.0.0/12
				"tagged-db": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.64.0.0/12", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil, // 100.94.92.91 is NOT in 100.64.0.0/12
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatBasicTags tests basic tag-to-tag ACL rules.
// These tests verify that tags are correctly expanded to node IPs
// and that filters are distributed to the correct destination nodes.
func TestTailscaleCompatBasicTags(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "tag_client_to_tag_server_port_22",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "tag_as_source_wildcard_dest",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["*:*"]}
	`),
			// When dst is *, all nodes should receive the filter
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "multiple_source_tags",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client", "tag:web"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "tag_as_destination_only",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["tag:server:22"]}
	`),
			// When using wildcard source and tag destination, ONLY the tagged node receives the filter.
			// This is different from tag_as_source_wildcard_dest where all nodes receive the filter.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_destination_tags",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:5432", "tag:web:80"]}
	`),
			// Multiple destination tags in a single rule.
			// Each tagged node receives ONLY its own destination portion.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "all_tagged_nodes_as_source_to_specific_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:tagged"], "dst": ["tag:database:5432"]}
	`),
			// All tagged nodes as source (including the destination node itself).
			// Only the destination node receives the filter.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				// Handle nil vs empty slice comparison
				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatUsersGroups tests user and group ACL rules.
func TestTailscaleCompatUsersGroups(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "user_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["kratail2tid@"], "dst": ["*:*"]}
	`),
			// User as source expands to IPs of nodes owned by that user
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "user_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["kratail2tid@:*"]}
	`),
			// User as destination - only user-owned nodes receive the filter
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "group_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]}
	`),
			// Group as source expands to IPs of nodes owned by group members
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "group_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["group:admins:*"]}
	`),
			// Group as destination - only nodes owned by group members receive the filter
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_destinations_different_ports",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:5432"]}
	`),
			// Each destination node receives ONLY its own destination portion
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatAutogroups tests autogroup ACL rules.
func TestTailscaleCompatAutogroups(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "autogroup_member_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member"], "dst": ["*:*"]}
	`),
			// autogroup:member expands to IPs of user-owned nodes only
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "autogroup_tagged_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:tagged"], "dst": ["*:*"]}
	`),
			// autogroup:tagged expands to IPs of all tagged nodes
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "autogroup_member_plus_tag_client",
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["tag:server:22"]}
	`),
			// Sources are merged into one Srcs array
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "autogroup_self_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*"]}
	`),
			// autogroup:self allows a node to access ITSELF.
			// The source wildcard `*` is narrowed to the node's own IP for autogroup:self.
			// KEY INSIGHT: Tagged nodes do NOT receive autogroup:self filters.
			// Only user-owned nodes can use autogroup:self.
			// NOTE: For autogroup:self destinations, both Tailscale and Headscale narrow
			// the wildcard source to only the same-user untagged nodes.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// Source is narrowed to the node's own IPs for autogroup:self.
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						// Tailscale uses CIDR format: "100.90.199.68/32" and "fd7a:115c:a1e0::2d01:c747/128"
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil, // Tagged nodes do NOT receive autogroup:self filters
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "autogroup_internet_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:internet:*"]}
	`),
			// autogroup:internet produces NO PacketFilter entries.
			// This autogroup relates to exit node routing, not direct node-to-node filters.
			// It controls what traffic can be routed through exit nodes to the internet.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "autogroup_member_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:member:*"]}
	`),
			// autogroup:member as destination - only user-owned nodes receive the filter.
			// Tagged nodes do NOT receive this filter.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "autogroup_self_mixed_with_tag",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*", "tag:server:22"]}
	`),
			// KEY FINDING: Mixed destinations create SEPARATE filter entries with different Srcs!
			// - autogroup:self narrows Srcs to the user's own IPs
			// - tag:server keeps Srcs as full wildcard
			// user1 gets ONLY the self filter (narrowed Srcs to user1's IPs)
			// tagged-server gets ONLY the tag filter (full wildcard Srcs)
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// autogroup:self narrows Srcs to user's own IPs
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						// tag:server keeps full wildcard Srcs
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil, // Not in destination
				"tagged-db":     nil, // Not in destination
				"tagged-web":    nil, // Not in destination
			},
		},
		{
			name: "autogroup_tagged_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:tagged:*"]}
	`),
			// autogroup:tagged as destination - all tagged nodes receive the filter.
			// User-owned nodes do NOT receive this filter.
			// KEY INSIGHT: ReduceFilterRules filters DstPorts to only the current node's IPs.
			// So each tagged node only sees its OWN IPs in DstPorts after reduction.
			// TODO: Tailscale includes ALL tagged nodes' IPs in DstPorts for each node.
			// Headscale only includes the current node's IPs after ReduceFilterRules.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// TODO: Tailscale includes ALL tagged nodes' IPs:
						// DstPorts: []tailcfg.NetPortRange{
						// 	{IP: "100.108.74.26/32", Ports: tailcfg.PortRangeAny},
						// 	{IP: "100.74.60.128/32", Ports: tailcfg.PortRangeAny},
						// 	{IP: "100.80.238.75/32", Ports: tailcfg.PortRangeAny},
						// 	{IP: "100.94.92.91/32", Ports: tailcfg.PortRangeAny},
						// 	{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRangeAny},
						// 	{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRangeAny},
						// 	{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRangeAny},
						// 	{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRangeAny},
						// },
						// Headscale: After ReduceFilterRules, only this node's IPs are in DstPorts
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// TODO: Tailscale includes ALL tagged nodes' IPs (see tagged-server comment)
						// Headscale: Only this node's IPs after ReduceFilterRules
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// TODO: Tailscale includes ALL tagged nodes' IPs (see tagged-server comment)
						// Headscale: Only this node's IPs after ReduceFilterRules
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// TODO: Tailscale includes ALL tagged nodes' IPs (see tagged-server comment)
						// Headscale: Only this node's IPs after ReduceFilterRules
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatHosts tests host alias ACL rules.
func TestTailscaleCompatHosts(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "host_as_destination",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["webserver:80"]}
	`),
			// Host reference webserver = 100.108.74.26 = tagged-server
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// TODO: Tailscale only includes the literal IPv4 for host aliases:
						// DstPorts: []tailcfg.NetPortRange{
						// 	{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						// },
						// Headscale: Resolves host alias to node and includes ALL node IPs (IPv4+IPv6)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "host_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["webserver"], "dst": ["*:*"]}
	`),
			// Host as source resolves to the defined IP
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// TODO: Tailscale only includes the literal IPv4 for host aliases:
						// SrcIPs: []string{"100.108.74.26/32"},
						// Headscale: Resolves host alias to node and includes ALL node IPs (IPv4+IPv6)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						// TODO: Tailscale only includes the literal IPv4 for host aliases (see user1 comment)
						// Headscale: Resolves host alias to node and includes ALL node IPs (IPv4+IPv6)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						// TODO: Tailscale only includes the literal IPv4 for host aliases (see user1 comment)
						// Headscale: Resolves host alias to node and includes ALL node IPs (IPv4+IPv6)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						// TODO: Tailscale only includes the literal IPv4 for host aliases (see user1 comment)
						// Headscale: Resolves host alias to node and includes ALL node IPs (IPv4+IPv6)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						// TODO: Tailscale only includes the literal IPv4 for host aliases (see user1 comment)
						// Headscale: Resolves host alias to node and includes ALL node IPs (IPv4+IPv6)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "cidr_host_as_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["internal"], "dst": ["*:*"]}
	`),
			// CIDR host definition (10.0.0.0/8) is passed through unchanged
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{"10.0.0.0/8"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{"10.0.0.0/8"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{"10.0.0.0/8"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{"10.0.0.0/8"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{"10.0.0.0/8"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatProtocolsPorts tests protocol and port ACL rules.
func TestTailscaleCompatProtocolsPorts(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "tcp_only_protocol",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "proto": "tcp", "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "udp_only_protocol",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "proto": "udp", "dst": ["tag:server:53"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 53, Last: 53}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 53, Last: 53}},
						},
						IPProto: []int{ProtocolUDP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "icmp_numeric_protocol",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "proto": "1", "dst": ["tag:server:*"]}
	`),
			// Numeric protocol values work (e.g., "1" for ICMP)
			// Even for ICMP (which doesn't use ports), the ports field is 0-65535
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "port_range",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["tag:server:80-443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_comma_separated_ports",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["tag:server:22,80,443"]}
	`),
			// Comma-separated ports expand into separate DstPorts entries
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "wildcard_port",
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["tag:server:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRangeAny},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatMixedSources tests mixing different source types in a single rule.
// From findings/09-mixed-scenarios.md - Category 1: Mixed Sources (Single Rule).
func TestTailscaleCompatMixedSources(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "autogroup_tagged_plus_autogroup_member_full_tailnet",
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:tagged", "autogroup:member"], "dst": ["tag:server:22"]}
	`),
			// Full tailnet coverage: autogroup:tagged (all 4 tagged) + autogroup:member (user1)
			// All 5 nodes' IPv4 and IPv6 addresses should be in Srcs (10 total entries)
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "group_plus_tag",
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins", "tag:client"], "dst": ["tag:server:22"]}
	`),
			// group:admins → user1's IPs + tag:client → tagged-client's IPs
			// Both merged into single Srcs array (4 IPs total)
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "explicit_user_plus_tag",
			policy: makePolicy(`
		{"action": "accept", "src": ["kratail2tid@", "tag:client"], "dst": ["tag:server:22"]}
	`),
			// Explicit user kratail2tid@ → user1's IPs + tag:client → tagged-client's IPs
			// Both merged into single Srcs array (4 IPs total)
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "cidr_plus_tag",
			policy: makePolicy(`
		{"action": "accept", "src": ["10.0.0.0/8", "tag:client"], "dst": ["tag:server:22"]}
	`),
			// CIDR 10.0.0.0/8 + tag:client IPs merged into single Srcs array
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"10.0.0.0/8",
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "host_plus_tag",
			policy: makePolicy(`
		{"action": "accept", "src": ["internal", "tag:client"], "dst": ["tag:server:22"]}
	`),
			// Host alias "internal" (10.0.0.0/8) + tag:client IPs merged into single Srcs array
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"10.0.0.0/8",
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "webserver_host_plus_tag",
			// Test 1.5: webserver (host) + tag:client
			// Host aliases are IPv4 only; tags include IPv6.
			policy: makePolicy(`
		{"action": "accept", "src": ["webserver", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// TODO: Tailscale: webserver host = 100.108.74.26/32 (IPv4 only)
						// Tailscale Srcs: ["100.108.74.26/32", "100.80.238.75/32", "fd7a:115c:a1e0::7901:ee86/128"]
						// Headscale: Host resolves to node and includes ALL node IPs
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "raw_ip_plus_tag",
			// Test 1.6: 100.90.199.68 (raw IP) + tag:client
			// Raw IPs are treated as literal CIDRs
			policy: makePolicy(`
		{"action": "accept", "src": ["100.90.199.68", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// Raw IP 100.90.199.68 resolves to user1 node - Headscale includes all node IPs
						// tag:client expands to tagged-client's IPs
						// TODO: Tailscale may treat raw IP as literal /32 only without IPv6
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128", // user1 IPv6 added by Headscale
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_user_three_ways",
			// Test 1.7: autogroup:member + group:admins + kratail2tid@ (same user 3 ways)
			// All three resolve to user1, should deduplicate to just user1's IPs
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "group:admins", "kratail2tid@"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// All three sources resolve to user1 - should be deduplicated
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_ip_two_ways_as_source",
			// Test 1.8: tag:server + webserver (same IP via tag and host)
			// Both reference tagged-server's IP - should deduplicate
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:server", "webserver"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db": {
					{
						// TODO: Tailscale: webserver host only adds IPv4
						// Tailscale Srcs: ["100.108.74.26/32", "fd7a:115c:a1e0::b901:4a87/128"]
						// Headscale: Both tag:server and webserver resolve to all node IPs
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatComplexScenarios tests complex ACL rule combinations.
func TestTailscaleCompatComplexScenarios(t *testing.T) {
	t.Parallel()

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	tests := []tailscaleCompatTest{
		{
			name: "empty_group_produces_no_filter",
			policy: makePolicy(`
		{"action": "accept", "src": ["group:empty"], "dst": ["*:*"]}
	`),
			// Empty groups produce no filter entries
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_rules_same_source_merged",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80,443"]}
	`),
			// KEY INSIGHT: In Tailscale, multiple rules with the SAME source are MERGED into a
			// single filter entry with all destination ports combined.
			// Headscale now merges rules with identical SrcIPs and IPProto.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: Both ACL rules combined into single filter entry
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "different_sources_same_destination_separate",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:database"], "dst": ["tag:server:22"]}
	`),
			// KEY INSIGHT: Different sources are NEVER merged - always separate filter entries.
			// Each source gets its own filter entry even with identical destinations.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "mixed_overlapping_rules",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:443"]}
	`),
			// In Tailscale: 4 rules → 2 filter entries (merged per-source)
			// - tag:client rules merged (ports 22, 80)
			// - tag:web rules merged (ports 22, 443)
			// Headscale now merges rules with identical SrcIPs and IPProto.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: tag:client rules (ports 22, 80)
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Merged: tag:web rules (ports 22, 443)
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_tag_destinations_distributed",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:5432"]}
	`),
			// Multiple tag destinations are distributed to their respective nodes.
			// tagged-server gets port 22, tagged-db gets port 5432.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		{
			name: "same_node_different_ports_via_tag_and_host",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "webserver:80"]}
	`),
			// KEY FINDING: Same IP can appear multiple times in Dsts with different ports
			// when referenced via different aliases (tag vs host).
			// - tag:server adds both IPv4 and IPv6 (port 22)
			// - webserver host adds only IPv4 (port 80)
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// TODO: Tailscale includes webserver:80 BEFORE tag:server:22 in Dsts:
						// DstPorts: []tailcfg.NetPortRange{
						//   {IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						//   {IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						//   {IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						// },
						// Headscale: tag destinations come first, then host destinations
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// Host alias "webserver" expands to node's IPs (IPv4 + IPv6)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "group_and_tag_destinations_distributed",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["group:admins:22", "tag:server:80"]}
	`),
			// Group:admins → user1, tag:server → tagged-server
			// Each destination type distributed to its respective nodes.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "wildcard_mixed_with_specific_source",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["*"], "dst": ["tag:server:80"]}
	`),
			// Wildcard `*` is NOT merged with specific sources.
			// Each remains a separate filter entry.
			// Wildcard expands to CIDR ranges, specific tag expands to node IP.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_src_different_dest_ports_merged",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]}
	`),
			// KEY FINDING: Same source, same dest node, different ports = MERGED
			// 2 rules → 1 filter entry with all ports combined (4 Dsts: 2 ports × 2 IPs)
			// Headscale now merges rules with identical SrcIPs and IPProto.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: Both rules combined
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_src_different_dest_nodes_separate",
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]}
	`),
			// Same source, different destination nodes = separate filter entries per node.
			// Each destination node only receives its relevant filter.
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		// Category 2: Mixed Destinations - Additional tests
		{
			name: "tag_plus_raw_ip_same_node_different_ports",
			// Test 2.3: tag:server:22 + 100.108.74.26:80 (tag + raw IP, same node)
			// Same behavior as Test 2.2 - same IP can appear multiple times with different ports
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "100.108.74.26:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:server adds both IPv4+IPv6 for port 22
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// Headscale resolves raw IP to node and includes all IPs (IPv4+IPv6)
							// TODO: Tailscale adds only IPv4 for raw IP destinations
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "user_via_email_and_group_different_ports",
			// Test 2.6: kratail2tid@:22 + group:admins:80 (same user via email + group)
			// Same user referenced via email and group creates separate Dst entries per port
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["kratail2tid@:22", "group:admins:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// Same user via email and group with different ports - 4 Dst entries total
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_host_destinations",
			// Test 2.7: webserver:22 + database:5432 (multiple hosts)
			// Host destinations are properly distributed to matching nodes
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["webserver:22", "database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// Headscale resolves host alias to node and includes all IPs (IPv4+IPv6)
						// TODO: Tailscale host alias is IPv4-only
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// Headscale resolves host alias to node and includes all IPs (IPv4+IPv6)
						// TODO: Tailscale host alias is IPv4-only
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		// Category 3: Overlapping References - Same entity via different names
		{
			name: "same_ip_via_tag_and_host_source",
			// Test 3.1: src: [tag:server, webserver] - same IP via tag and host
			// Duplicate IPs should be deduplicated in Srcs
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:server", "webserver"], "dst": ["tag:client:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": {
					{
						// tag:server gives IPv4+IPv6, webserver adds IPv4 again (but deduplicated)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db":  nil,
				"tagged-web": nil,
			},
		},
		{
			name: "same_ip_port_via_tag_and_host_dest",
			// Test 3.3: dst: [tag:server:22, webserver:22] - same IP:port via tag and host
			// Destinations are NOT deduplicated - same IP:port can appear multiple times
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "webserver:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// Destinations NOT deduplicated - same IP can appear twice
						// tag:server adds IPv4:22 + IPv6:22
						// webserver adds IPv4:22 again + Headscale adds IPv6 too
						// TODO: Tailscale: webserver adds IPv4:22 only (duplicated with tag:server)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_ip_port_via_tag_and_raw_ip_dest",
			// Test 3.4: dst: [tag:server:22, 100.108.74.26:22] - tag + raw IP (identical)
			// Same behavior as Test 3.3 - Dsts not deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "100.108.74.26:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// Destinations NOT deduplicated
						// tag:server adds IPv4:22 + IPv6:22
						// Raw IP adds IPv4:22 again + Headscale adds IPv6 too
						// TODO: Tailscale: raw IP adds IPv4:22 only (duplicated)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "tag_database_plus_host_database_source",
			// Test 3.5: src: [tag:database, database] - tag:database + host database (same node)
			// Sources ARE deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:database", "database"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// Sources deduplicated: tag:database (IPv4+IPv6) + database host (IPv4)
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 4: Cross-Type Source→Destination Combinations
		{
			name: "autogroup_tagged_to_user",
			// Test 4.2: autogroup:tagged → kratail2tid@:22
			// Tagged nodes → user-owned nodes
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:tagged"], "dst": ["kratail2tid@:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// All 4 tagged nodes (8 IPs) can access user1:22
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "group_to_host_alias",
			// Test 4.3: group:admins → webserver:22
			// Group → host alias
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["webserver:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						// Headscale resolves host alias to node and adds IPv6 too
						// TODO: Tailscale host alias is IPv4-only
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 5: Order Effects - Order does NOT affect output
		{
			name: "source_order_independence",
			// Test 5.1: Order of sources doesn't affect output - they are sorted
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:web", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// Sources are sorted: IPv4 first (ascending), then IPv6 (ascending)
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 6: Edge Cases
		{
			name: "cidr_host_as_source",
			// Test 6.5: internal (10.0.0.0/8) → tag:server:22
			// CIDR host definitions work as sources
			policy: makePolicy(`
		{"action": "accept", "src": ["internal"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// CIDR host goes directly into SrcIPs
						SrcIPs: []string{
							"10.0.0.0/8",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "cidr_host_as_destination_no_matching_nodes",
			// Test 6.6: tag:client → internal:22 (CIDR host as destination)
			// No nodes in 10.0.0.0/8 range, so no filters generated for any tailnet nodes
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["internal:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 7: Maximum Combinations
		{
			name: "multiple_tags_as_sources",
			// Test 7.x: Multiple tags as sources
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client", "tag:web", "tag:database"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// All 3 tags' IPs
						SrcIPs: []string{
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "tag_to_multiple_destinations_ports",
			// Test 7.x: tag:client → multiple destinations with different ports
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:5432", "tag:web:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 8: Redundancy Stress Tests
		{
			name: "user1_referenced_multiple_ways_as_source",
			// Test 8.1: user1 referenced 5 ways - all deduplicated
			// autogroup:member, kratail2tid@, group:admins, group:developers, 100.90.199.68
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "kratail2tid@", "group:admins", "group:developers", "100.90.199.68"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// All 5 references resolve to user1 - deduplicated
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 9: All Tags + All Autogroups
		{
			name: "all_four_tags_as_sources",
			// Test 9.1: All 4 tags as sources
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:server", "tag:client", "tag:database", "tag:web"], "dst": ["kratail2tid@:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// All 4 tagged nodes (8 IPs total)
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "all_four_tags_as_destinations",
			// Test 9.2: All 4 tags as destinations
			policy: makePolicy(`
		{"action": "accept", "src": ["kratail2tid@"], "dst": ["tag:server:22", "tag:client:22", "tag:database:22", "tag:web:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "both_autogroups_as_sources",
			// Test 9.3: autogroup:member + autogroup:tagged as sources (full tailnet)
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "autogroup:tagged"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// All 5 nodes (10 IPs)
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 10: Multiple Rules with Mixed Types
		{
			name: "cross_type_separate_rules",
			// Test 10.1: Different source types in separate rules
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		// Category 11: Port Variations with Mixed Types
		{
			name: "mixed_sources_with_port_range",
			// Test 11.2: Mixed sources with port range
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["tag:server:80-443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 14: Multi-Rule Compounding
		{
			name: "same_src_different_dests_two_rules",
			// Test 14.1: Same src, different dests (2 rules)
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		{
			name: "different_srcs_same_dest_two_rules",
			// Test 14.6: Different srcs, same dest (2 rules)
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Two separate filter rules for each ACL rule
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 12: CIDR Host Combinations
		{
			name: "cidr_host_plus_tag_as_sources",
			// Test 12.1: CIDR host + tag as sources
			// internal (10.0.0.0/8) + tag:client
			policy: makePolicy(`
		{"action": "accept", "src": ["internal", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// CIDR host appears as-is in Srcs + tag:client IPs
						SrcIPs: []string{
							"10.0.0.0/8",
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "multiple_cidr_hosts_as_sources",
			// Test 12.2: Multiple CIDR hosts as sources
			// internal (10.0.0.0/8) + subnet24 (192.168.1.0/24)
			policy: makePolicy(`
		{"action": "accept", "src": ["internal", "subnet24"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// Both CIDR hosts appear in Srcs
						SrcIPs: []string{
							"10.0.0.0/8",
							"192.168.1.0/24",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_cidr_via_host_and_raw",
			// Test 12.4: Same CIDR referenced via host alias and raw CIDR
			// internal (10.0.0.0/8) + 10.0.0.0/8 - should deduplicate
			policy: makePolicy(`
		{"action": "accept", "src": ["internal", "10.0.0.0/8"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// Same CIDR referenced 2 ways should deduplicate
						SrcIPs: []string{
							"10.0.0.0/8",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 13: autogroup:self Deep Dive - Tests where autogroup:self works
		{
			name: "wildcard_to_autogroup_self",
			// Test 13.1: * → autogroup:self:*
			// CRITICAL: autogroup:self NARROWS Srcs even when source is wildcard
			// Only user-owned nodes receive filters; tagged nodes get empty
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// Srcs narrowed to user1's own IPs (NOT wildcard CIDRs)
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						// Dsts = user1's own IPs with all ports (no CIDR notation for autogroup:self)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// Tagged nodes receive NO filters for autogroup:self
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "wildcard_to_autogroup_self_specific_port",
			// Test 13.2: * → autogroup:self:22
			// Specific port with autogroup:self
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "autogroup_member_to_self",
			// Test 13.5: autogroup:member → autogroup:self:*
			// autogroup:member is a valid source for autogroup:self
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "specific_user_to_self",
			// Test 13.8: kratail2tid@ → autogroup:self:*
			// Specific user email is a valid source for autogroup:self
			policy: makePolicy(`
		{"action": "accept", "src": ["kratail2tid@"], "dst": ["autogroup:self:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "group_to_self",
			// Test 13.9: group:admins → autogroup:self:*
			// Groups are valid sources for autogroup:self
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["autogroup:self:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "wildcard_to_self_plus_tag",
			// Test 13.16: * → [autogroup:self:*, tag:server:22]
			// Mixed destinations with autogroup:self - different Srcs for each
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*", "tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						// Self filter gets narrowed Srcs (user1's IPs only)
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						// autogroup:self destinations use plain IPs (no CIDR notation)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						// Tag filter gets full wildcard Srcs
						// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						// Tag destinations use CIDR notation
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 14: More Multi-Rule Compounding
		{
			name: "same_src_same_dest_different_ports_two_rules",
			// Test 14.2: Same src, same dest, different ports (2 rules)
			// In Tailscale: MERGED into single filter entry with combined Dsts
			// Headscale now merges rules with identical SrcIPs and IPProto.
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: Both rules combined
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "three_different_srcs_same_dest_different_ports",
			// Test 14.21: 3 different sources → same dest, different ports
			// Each rule becomes a separate filter entry
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:80"]},
		{"action": "accept", "src": ["tag:database"], "dst": ["tag:server:443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "overlapping_dests_same_src_different_rules",
			// Test 10.2: Overlapping destinations, different sources (2 rules)
			// Each rule creates its own filter entry on destination nodes
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:*"]},
		{"action": "accept", "src": ["autogroup:tagged"], "dst": ["tag:server:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// Rule 1: group:admins → tag:server:*
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						// Rule 2: autogroup:tagged → tag:server:*
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "mixed_sources_comma_ports",
			// Test 11.1: Mixed sources with comma-separated ports
			// Each port becomes a separate Dst entry
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["tag:server:22,80,443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// Each port is a separate Dst entry (6 total: 3 ports × 2 IPs)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "full_autogroups_with_wildcard_and_specific_port",
			// Test 11.4: Both autogroups with wildcard and specific port destinations
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:tagged", "autogroup:member"], "dst": ["tag:server:*", "tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						// All 5 nodes (10 IPs) as sources
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						// Wildcard port → 0-65535
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		// Category 13: More autogroup:self tests
		{
			name: "wildcard_to_self_comma_ports",
			// Test 13.3: * → autogroup:self:22,80,443
			// Comma-separated ports create separate Dsts entries
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22,80,443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						// 6 Dsts: 3 ports × 2 IPs (autogroup:self uses plain IPs)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "wildcard_to_self_port_range",
			// Test 13.4: * → autogroup:self:80-443
			// Port range preserved as First/Last
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:80-443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						// Port range preserved (autogroup:self uses plain IPs)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "self_twice_separate_rules_merged",
			// Test 13.36: Self twice in separate rules (merged)
			// * → autogroup:self:22
			// * → autogroup:self:80
			// Tailscale MERGES these into a single filter entry with 4 Dsts
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Merged: Both rules combined into 1 filter entry with 4 Dsts
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Category 14: More Multi-Rule Compounding
		{
			name: "same_src_different_dests_two_rules_distributed",
			// Test 14.1: Same src, different dests (2 rules)
			// Rules distributed to different destination nodes
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": nil,
			},
		},
		{
			name: "different_srcs_same_dest_two_rules",
			// Test 14.6: Different srcs, same dest (2 rules)
			// Creates 2 SEPARATE filter entries (not merged)
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "group_and_user_same_person_same_dest",
			// Test 14.8: Group + user (same person) → same dest (2 rules)
			// Srcs DEDUPLICATED but Dsts NOT deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["kratail2tid@"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: 1 filter entry with Srcs deduplicated and 4 Dsts (duplicated)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "wildcard_to_self_plus_group",
			// Test 13.20: * → [autogroup:self:*, group:admins:22]
			// user1 gets TWO filter entries (different Srcs)
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*", "group:admins:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Entry 1: autogroup:self with narrowed Srcs
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: group:admins with full wildcard Srcs
					// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_src_same_dest_different_ports_two_rules_merged",
			// Test 14.2: Same src, same dest, different ports (2 rules)
			// MERGED into single filter entry with 4 Dsts
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: Both rules combined
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "three_different_srcs_same_dest_different_ports",
			// Test 14.21: 3 different srcs → same dest, different ports (3 rules)
			// Creates 3 SEPARATE filter entries
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:80"]},
		{"action": "accept", "src": ["tag:database"], "dst": ["tag:server:443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "three_refs_same_user_same_dest_port",
			// Test 14.22: 3 refs to same user → same dest:port (3 rules)
			// Srcs DEDUPLICATED, Dsts NOT deduplicated (6 entries)
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["kratail2tid@"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					// Merged: 1 filter entry with Srcs deduplicated and 6 Dsts (not deduplicated)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_src_three_different_dests",
			// Test 14.23: Same src → 3 different dests (3 rules)
			// Each destination node receives its own filter entry
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:web:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "full_wildcard_plus_specific_rule",
			// Test 14.36: Full wildcard + specific rule
			// BOTH rules create filter entries (wildcard does NOT subsume specific)
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Wildcard rule only
					{
						// NOTE: Tailscale uses partitioned CGNAT CIDRs and IPProto [0] (any).
						// Headscale uses full 100.64.0.0/10 and explicit IPProto list.
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					// TODO: Tailscale produces 2 entries: wildcard (IPProto [0]) + specific (IPProto [6,17,1,58])
					// Headscale produces 2 entries but with same IPProto
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "both_autogroups_to_wildcard",
			// Test 14.42: Both autogroups → wildcard (full network)
			// Different Srcs = separate entries, even with identical Dsts
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:tagged"], "dst": ["*:*"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["*:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Entry 1: autogroup:tagged Srcs
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: autogroup:member Srcs
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "triple_src_ref_each_rule",
			// Test 14.45: Triple src ref each rule
			// Sources deduplicated within each rule
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "group:admins", "kratail2tid@"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:server", "webserver", "100.108.74.26"], "dst": ["group:admins:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Rule 2: tag:server + webserver + raw IP → group:admins (user1)
					{
						// Srcs deduplicated to 1 IP + IPv6 (all resolve to same tagged-server)
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					// Rule 1: autogroup:member + group:admins + user → tag:server
					{
						// Srcs deduplicated to user1's IPs (all 3 resolve to same user)
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "same_src_four_dests",
			// Test 14.47: Same src → 4 dests
			// Same Srcs across 4 rules = merged into single filter entry per destination node
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:database:5432"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:80"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["webserver:443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": nil,
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "overlapping_destinations_different_sources",
			// Test 10.2: Overlapping destinations, different sources
			// Rules with same destination create SEPARATE filter entries, NOT merged
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["*:*"]},
		{"action": "accept", "src": ["autogroup:tagged"], "dst": ["*:*"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Entry 1: group:admins → *:*
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: autogroup:tagged → *:*
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "same_dest_node_via_tag_vs_host_source",
			// Test 10.3: Same dest node via tag vs host source
			// Same destination with different sources = separate entries
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["webserver"], "dst": ["tag:server:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Entry 1: tag:client → :22
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: webserver → :80 (host source expands to node IPs)
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "three_rules_same_dest_different_sources",
			// Test 10.4: 3 rules, same dest, different sources
			// 3 separate filter entries on the same destination node
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Entry 1: * → :22
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: tag:client → :80
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 3: autogroup:member → :443
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "mixed_sources_in_multiple_rules",
			// Test 10.5: Mixed sources in multiple rules
			// Sources within a rule are deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client", "tag:web"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["autogroup:member", "group:admins"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Rule 1: [tag:client, tag:web] → tag:server:22
					// Sources merged and deduplicated
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					// Rule 2: [autogroup:member, group:admins] → tag:database:5432
					// Both resolve to user1, deduplicated
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "mixed_sources_with_port_range_11_2",
			// Test 11.2: Mixed sources with port range
			// Port range preserved as First/Last
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins", "webserver"], "dst": ["tag:server:80-443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// group:admins (IPv4+IPv6) + webserver (node IPs) = 4 Srcs
						SrcIPs: []string{
							"100.90.199.68/32",
							"100.108.74.26/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "same_dest_node_different_ports_via_different_refs_2_2",
			// Test 2.2: Same node referenced via tag and host with different ports
			// Same IP can appear multiple times in Dsts with different ports
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "webserver:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:server:22 adds IPv4 and IPv6
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// webserver:80 expands to node IPs (both IPv4 and IPv6)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "same_user_different_ports_via_email_and_group_2_6",
			// Test 2.6: Same user referenced via email and group with different ports
			// Destinations are NOT deduplicated when ports differ
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["kratail2tid@:22", "group:admins:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// 4 entries: user1's IPv4 and IPv6 for EACH port (22 and 80)
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "diff_srcs_same_dest_14_6",
			// Test 14.6: Different srcs, same dest (2 rules)
			// Different sources, same destination = 2 SEPARATE filter entries
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Entry 1: tag:client → :22
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: tag:web → :22
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "group_plus_user_same_person_same_dest_14_8",
			// Test 14.8: Group + user (same person) → same dest (2 rules)
			// Same person via group + user email = 1 filter entry, Srcs MERGED, Dsts NOT merged
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["kratail2tid@"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Merged: 1 filter entry with 4 Dsts (duplicated)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "self_overlap_with_explicit_user_13_86",
			// Test 13.86: self:22 + user:22 (overlap on same node)
			// Different Srcs for self vs explicit user = separate entries
			// NOTE: Tailscale produces 2 entries, one with wildcard CGNAT Srcs, one with user1's IPs.
			// Headscale produces similar with full CGNAT range (100.64.0.0/10).
			// In Headscale, autogroup:self entry comes FIRST, explicit user SECOND.
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22", "kratail2tid@:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Entry 1: * → autogroup:self:22 (Srcs narrowed to user1's IPs, no CIDR in DstPorts)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: * → kratail2tid@:22 (wildcard Srcs, CIDR in DstPorts)
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "self_twice_different_ports_13_36",
			// Test 13.36: Self twice in separate rules (merged)
			// Multiple self rules with same source = MERGED into single filter entry
			policy: makePolicy(`
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Merged: 1 filter entry with 4 Dsts
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		{
			name: "six_rules_mixing_all_patterns",
			// Test 14.50: 6 rules mixing all patterns
			// Self-referential rules work, different Srcs create separate entries
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:server"], "dst": ["tag:server:22"]},
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:client:22"]},
		{"action": "accept", "src": ["tag:database"], "dst": ["tag:database:22"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:web:22"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["*:80"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:member:443"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					// Entry 1: autogroup:member → *:80
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: * → autogroup:member:443 (user1 is in autogroup:member)
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					// Entry 1: tag:server → tag:server:22 (self-reference)
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: autogroup:member → *:80
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					// Entry 1: tag:client → tag:client:22 (self-reference)
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: autogroup:member → *:80
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					// Entry 1: tag:database → tag:database:22 (self-reference)
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: autogroup:member → *:80
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					// Entry 1: tag:web → tag:web:22 (self-reference)
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: autogroup:member → *:80
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 1: Mixed Sources
		{
			name: "autogroup_member_plus_tag_client_1_1",
			// Test 1.1: autogroup:member + tag:client
			// Sources are merged into single Srcs array
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// autogroup:member (user1) + tag:client = merged
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "group_admins_plus_tag_client_1_3",
			// Test 1.3: group:admins + tag:client
			// Sources are merged into single Srcs array
			policy: makePolicy(`
		{"action": "accept", "src": ["group:admins", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// group:admins (user1) + tag:client = merged
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "user_email_plus_tag_client_1_4",
			// Test 1.4: kratail2tid@ + tag:client
			// User email expanded to IPs + tag = merged
			policy: makePolicy(`
		{"action": "accept", "src": ["kratail2tid@", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "host_plus_tag_client_1_5",
			// Test 1.5: webserver (host) + tag:client
			// Host expands to node IPs + tag = merged
			policy: makePolicy(`
		{"action": "accept", "src": ["webserver", "tag:client"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-server": nil,
				"tagged-web":    nil,
				"tagged-db": {
					{
						// webserver (tagged-server IPs) + tag:client = merged
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.108.74.26/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "raw_ip_plus_tag_client_1_6",
			// Test 1.6: 100.90.199.68 (raw IP) + tag:client
			// Raw IP expands to node's both IPs + tag = merged
			policy: makePolicy(`
		{"action": "accept", "src": ["100.90.199.68", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Raw IP expands to user1's IPs + tag:client = merged (4 IPs)
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "user1_three_ways_1_7",
			// Test 1.7: autogroup:member + group:admins + kratail2tid@
			// Same user referenced 3 ways = deduplicated to 2 IPs
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "group:admins", "kratail2tid@"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// All 3 references resolve to user1's IPs, deduplicated
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 2: Mixed Destinations
		{
			name: "tag_server_22_plus_tag_database_5432_2_1",
			// Test 2.1: tag:server:22 + tag:database:5432
			// Multiple destinations in same rule, distributed to each node
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "tag_server_22_plus_raw_ip_80_2_3",
			// Test 2.3: tag:server:22 + 100.108.74.26:80 (tag + raw IP, same node)
			// Same node via tag and raw IP, different ports = NOT deduplicated in Dsts
			// Raw IP destination expands to include node's IPv6
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "100.108.74.26:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:server:22 adds IPv4 and IPv6
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// raw IP:80 expands to both IPs
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "group_admins_22_plus_tag_server_80_2_4",
			// Test 2.4: group:admins:22 + tag:server:80
			// User destination on port 22, tag destination on port 80
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["group:admins:22", "tag:server:80"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "webserver_22_plus_database_5432_2_7",
			// Test 2.7: webserver:22 + database:5432 (multiple hosts)
			// Multiple host destinations
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["webserver:22", "database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// webserver host expands to tagged-server's IPs
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// database host expands to tagged-db's IPs
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 3: Overlapping References
		{
			name: "user1_three_ways_source_3_2",
			// Test 3.2: user1 referenced 3 ways as source
			// All resolve to same IPs, deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "kratail2tid@", "group:admins"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// All 3 references resolve to user1, deduplicated to 2 IPs
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "same_ip_port_tag_and_host_dest_3_3",
			// Test 3.3: Same IP:port via tag and host as dest
			// Same IP:port referenced two ways = NOT deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "webserver:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:server:22 adds IPv4 and IPv6
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// webserver:22 also expands to same IPs - NOT deduplicated
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "same_ip_port_tag_and_raw_ip_dest_3_4",
			// Test 3.4: Same IP:port via tag and raw IP
			// Raw IP also expands to both IPs when matching a node
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "100.108.74.26:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:server:22 adds IPv4 and IPv6
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// raw IP also expands to both IPs (NOT deduplicated)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 4: Cross-Type Source→Destination Combinations
		{
			name: "raw_ip_to_tag_server_4_7",
			// Test 4.7: 100.90.199.68 → tag:server:22
			// Raw IP as source, tag as destination
			// In Headscale, raw IP that matches a node expands to include IPv6
			policy: makePolicy(`
		{"action": "accept", "src": ["100.90.199.68"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "tag_client_to_raw_ip_4_8",
			// Test 4.8: tag:client → 100.108.74.26:22
			// Tag as source, raw IP as destination
			// In Headscale, raw IP destination that matches a node expands to include IPv6
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["100.108.74.26:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 7: Maximum Combinations ("Kitchen Sink")
		{
			name: "all_source_types_to_tag_server_7_1",
			// Test 7.1: ALL source types → tag:server:22
			// Mix of all source types in one rule
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "autogroup:tagged", "group:admins", "tag:client", "webserver", "100.74.60.128"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// All sources merged: user1, all tagged, webserver, database IP
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 8: Redundancy Stress Tests
		{
			name: "user1_referenced_5_ways_8_1",
			// Test 8.1: user1 referenced 5 ways
			// All references deduplicated to user1's 2 IPs
			policy: makePolicy(`
		{"action": "accept", "src": ["autogroup:member", "group:admins", "group:developers", "kratail2tid@", "100.90.199.68"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// 5 references → deduplicated to user1's IPs + raw IP
						// Note: raw IP only adds IPv4, others add both
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "tagged_server_3_ways_source_8_2",
			// Test 8.2: tagged-server referenced 3 ways as source
			// tag:server + webserver + raw IP = deduplicated
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:server", "webserver", "100.108.74.26"], "dst": ["tag:database:5432"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-server": nil,
				"tagged-web":    nil,
				"tagged-db": {
					{
						// All 3 references resolve to tagged-server's IPs, deduplicated
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		{
			name: "same_ip_port_3_ways_dest_8_5",
			// Test 8.5: Same IP:port referenced 3 ways as destination
			// tag:server:22 + webserver:22 + 100.108.74.26:22
			// Destinations are NOT deduplicated, raw IP also expands
			policy: makePolicy(`
		{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "webserver:22", "100.108.74.26:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:server:22 adds both IPs
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// webserver:22 also adds both IPs (NOT deduplicated)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// raw IP also adds both IPs (NOT deduplicated)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Category 12: CIDR Host Combinations
		{
			name: "cidr_subnet_plus_tag_as_sources_12_3",
			// Test 12.3: internal (CIDR host) + tag as sources
			// External CIDR doesn't match nodes, tag does
			policy: makePolicy(`
		{"action": "accept", "src": ["internal", "tag:client"], "dst": ["tag:server:22"]}
	`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// internal (10.0.0.0/8) + tag:client IPs
						SrcIPs: []string{
							"10.0.0.0/8",
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 5: Order Effects
		// ===========================================
		// Test 5.1a: Source Order - [tag:client, tag:web]
		{
			name: "source_order_client_web_5_1a",
			// Test that order of sources doesn't affect output
			policy: makePolicy(`{"action": "accept", "src": ["tag:client", "tag:web"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Sources merged and sorted: IPv4 first (sorted), then IPv6 (sorted)
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 5.1b: Source Order Reversed - [tag:web, tag:client]
		{
			name: "source_order_web_client_5_1b",
			// Same as 5.1a but reversed order - should produce identical output
			policy: makePolicy(`{"action": "accept", "src": ["tag:web", "tag:client"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Should be identical to 5.1a - order doesn't matter
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 5.2a: Destination Order - [tag:server:22, tag:database:80]
		{
			name: "dest_order_server_db_5_2a",
			// Test destination order - each node should get only its portion
			policy: makePolicy(`{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:80"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 5.2b: Destination Order Reversed - [tag:database:80, tag:server:22]
		{
			name: "dest_order_db_server_5_2b",
			// Same as 5.2a but reversed - should produce identical per-node filters
			policy: makePolicy(`{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:80", "tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 5.3a: Mixed Source Types Order - [autogroup:member, tag:client]
		{
			name: "mixed_source_order_member_client_5_3a",
			// Test mixed source types order
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Sources sorted: IPv4 first, then IPv6
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 5.3b: Mixed Source Types Order Reversed - [tag:client, autogroup:member]
		{
			name: "mixed_source_order_client_member_5_3b",
			// Same as 5.3a but reversed - should produce identical output
			policy: makePolicy(`{"action": "accept", "src": ["tag:client", "autogroup:member"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Should be identical to 5.3a
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 6: Edge Cases
		// ===========================================
		// Test 6.3: Empty group as source - no filters expected
		{
			name: "empty_group_source_6_3",
			// group:empty has no members, so no filters should be generated
			policy: makePolicy(`{"action": "accept", "src": ["group:empty"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil, // No filter because source group is empty
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Test 6.5: CIDR host (internal = 10.0.0.0/8) as source
		{
			name: "cidr_host_source_6_5",
			// Host "internal" defined as 10.0.0.0/8 - CIDR goes directly into Srcs
			policy: makePolicy(`{"action": "accept", "src": ["internal"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{"10.0.0.0/8"},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 6.6: CIDR host as destination - no tailnet nodes match
		{
			name: "cidr_host_dest_6_6",
			// internal (10.0.0.0/8) as destination - no tailnet nodes in this range
			policy: makePolicy(`{"action": "accept", "src": ["tag:client"], "dst": ["internal:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// No nodes match 10.0.0.0/8, so no filters generated
			},
		},

		// ===========================================
		// Category 9: All Tags + All Autogroups
		// ===========================================
		// Test 9.1: All 4 tags as sources
		{
			name: "all_four_tags_sources_9_1",
			// All 4 tags combined as sources
			policy: makePolicy(`{"action": "accept", "src": ["tag:server", "tag:client", "tag:database", "tag:web"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// 4 tags = 8 IPs (4 IPv4 + 4 IPv6, deduplicated)
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 9.2: All 4 tags as destinations
		{
			name: "all_four_tags_dests_9_2",
			// All 4 tags as destinations - each node gets only its own IP:port
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22", "tag:client:22", "tag:database:22", "tag:web:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil, // Not a destination
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 9.3: Both autogroups as sources
		{
			name: "both_autogroups_sources_9_3",
			// autogroup:member + autogroup:tagged = full tailnet coverage
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:member", "autogroup:tagged"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Full tailnet: 5 nodes = 10 IPs (5 IPv4 + 5 IPv6)
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 10: Multiple Rules with Mixed Types
		// ===========================================
		// Test 10.1: Cross-type in separate rules
		{
			name: "cross_type_separate_rules_10_1",
			// Rule 1: autogroup:member → tag:server:22
			// Rule 2: tag:client → group:admins:80
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["group:admins:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1 gets filter from Rule 2 (tag:client → group:admins:80)
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server gets filter from Rule 1 (autogroup:member → tag:server:22)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 10.2: Overlapping destinations, different sources
		{
			name: "overlapping_dests_diff_sources_10_2",
			// Rule 1: group:admins → tag:server:22
			// Rule 2: autogroup:tagged → tag:server:22
			// Same destination, different sources - creates separate filter entries
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server gets TWO separate filter entries (one per rule)
				"tagged-server": {
					// Rule 1: group:admins
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Rule 2: autogroup:tagged
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 10.3: Three rules to same destination
		{
			name: "three_rules_same_dest_10_3",
			// Rule 1: autogroup:member → tag:server:22
			// Rule 2: tag:client → tag:server:22
			// Rule 3: group:admins → tag:server:22
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server gets TWO filter entries (Rules 1+3 merged, Rule 2 separate)
				"tagged-server": {
					// Rules 1+3: autogroup:member and group:admins (same SrcIPs) merged
					// DstPorts combined from both rules (duplicates included)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Rule 2: tag:client (different SrcIPs, not merged)
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 11: Port Variations with Mixed Types
		// ===========================================
		// Test 11.1: Mixed sources with comma ports
		{
			name: "mixed_sources_comma_ports_11_1",
			// Comma-separated ports create separate Dsts entries
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["tag:server:22,80,443"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						// 3 ports × 2 IPs = 6 Dsts entries
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 11.2: Mixed sources with port range
		{
			name: "mixed_sources_port_range_11_2",
			// Port ranges preserved as First/Last in Dsts
			policy: makePolicy(`{"action": "accept", "src": ["group:admins", "webserver"], "dst": ["tag:server:80-443"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// group:admins (IPv4+IPv6) + webserver (IPv4+IPv6 since it matches tagged-server node)
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 11.4: Full autogroups with wildcard port
		{
			name: "autogroups_wildcard_port_11_4",
			// Wildcard port (*) expands to 0-65535
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:tagged", "autogroup:member"], "dst": ["tag:server:*"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						// Full tailnet: 5 nodes = 10 IPs
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 13: autogroup:self Deep Dive
		// ===========================================
		// Test 13.1: Wildcard → self:*
		{
			name: "wildcard_to_self_all_ports_13_1",
			// autogroup:self NARROWS Srcs even when source is wildcard
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				// Only user1 (user-owned) receives filter
				"user1": {
					{
						// Srcs NARROWED to user1's IPs only (not wildcard CIDRs!)
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// Tagged nodes receive NO filters
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Test 13.2: Wildcard → self:22
		{
			name: "wildcard_to_self_port_22_13_2",
			// Specific port with self
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Test 13.5: autogroup:member → self:*
		{
			name: "member_to_self_13_5",
			// autogroup:member works with autogroup:self
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Test 13.8: Specific user → self:*
		{
			name: "specific_user_to_self_13_8",
			// Specific user email works with autogroup:self
			policy: makePolicy(`{"action": "accept", "src": ["kratail2tid@"], "dst": ["autogroup:self:*"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},
		// Test 13.9: group:admins → self:*
		{
			name: "group_to_self_13_9",
			// Groups work with autogroup:self
			policy: makePolicy(`{"action": "accept", "src": ["group:admins"], "dst": ["autogroup:self:*"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
			},
		},

		// ===========================================
		// Category 14: Multi-Rule Compounding
		// ===========================================
		// Test 14.1: Same src, different dests (2 rules)
		{
			name: "same_src_diff_dests_14_1",
			// Same source, different destinations = separate filter entries per dest node
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.2: Same src, same dest, different ports (2 rules)
		{
			name: "same_src_same_dest_diff_ports_merged_14_2",
			// Same source + dest node + different ports
			// MERGED into 1 filter entry with 4 Dsts
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Merged: 1 entry with 4 DstPorts
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.6: Different srcs, same dest (2 rules)
		{
			name: "diff_srcs_same_dest_14_6",
			// Different sources, same dest = 2 SEPARATE filter entries
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// TWO separate filter entries
				"tagged-server": {
					// Entry 1: tag:client
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					// Entry 2: tag:web
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.8: Group + user (same person) → same dest (2 rules)
		{
			name: "group_user_same_person_same_dest_14_8",
			// Group + user (same person)
			// MERGED into 1 filter entry (Srcs deduplicated, Dsts NOT)
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["kratail2tid@"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Merged: 1 entry with deduplicated Srcs but duplicated Dsts
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 7: Kitchen Sink Tests
		// ===========================================
		// Test 7.2: tag:client → ALL destination types
		{
			name: "all_dest_types_7_2",
			// Test ALL destination types from one source
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:database:5432", "webserver:80", "database:443", "group:admins:8080", "kratail2tid@:3000", "100.108.74.26:9000"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": nil,
				"tagged-web":    nil,
				// user1 gets entries for user:3000 and group:8080
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 3000, Last: 3000}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 3000, Last: 3000}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server gets tag:server:22, webserver:80, raw IP:9000
				// Note: Host aliases that match node IPs get expanded to include IPv6
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 9000, Last: 9000}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 9000, Last: 9000}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db gets tag:database:5432 and database:443
				// Note: Host aliases that match node IPs get expanded to include IPv6
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 7.3: 10 different sources → *:*
		{
			name: "ten_sources_to_wildcard_7_3",
			// 10 different source types all deduplicated
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:member", "autogroup:tagged", "group:admins", "group:developers", "kratail2tid@", "tag:client", "tag:web", "tag:database", "webserver", "database"], "dst": ["*:*"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				// All nodes receive the deduplicated sources (including tagged-client since it's in *:*)
				// The sources are: autogroup:member, autogroup:tagged, group:admins, group:developers,
				// kratail2tid@, tag:client, tag:web, tag:database, webserver, database
				// autogroup:tagged includes ALL tagged nodes: tagged-server, tagged-client, tagged-db, tagged-web
				// All 5 nodes' IPs are included in the sources
				"user1": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===========================================
		// Category 12: CIDR Host Combinations
		// ===========================================
		// Test 12.1: CIDR host + tag as sources
		{
			name: "cidr_host_plus_tag_sources_12_1",
			// CIDR host (10.0.0.0/8) combined with tag as sources
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["internal", "tag:client"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"10.0.0.0/8",
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 12.2: Multiple CIDR hosts as sources
		{
			name: "multiple_cidr_hosts_sources_12_2",
			// Multiple CIDR hosts (10.0.0.0/8 + 192.168.1.0/24)
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["internal", "subnet24"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					{
						SrcIPs: []string{
							"10.0.0.0/8",
							"192.168.1.0/24",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 12.4: Host CIDR + raw CIDR (same value) as sources
		{
			name: "host_cidr_plus_raw_cidr_same_12_4",
			// Same CIDR via host alias and raw value - should deduplicate
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["internal", "10.0.0.0/8"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// Deduplicated - only one 10.0.0.0/8 entry
				"tagged-server": {
					{
						SrcIPs: []string{
							"10.0.0.0/8",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// ===========================================
		// Additional Missing Tests from 09-mixed-scenarios.md
		// ===========================================
		// Test 6.2: * → [webserver:22, database:5432]
		// Wildcard source + multiple host destinations
		{
			name:   "wildcard_to_multiple_hosts_6_2",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["webserver:22", "database:5432"]}`),
			// Wildcard `*` expands to all nodes (Headscale uses 0.0.0.0/0 and ::/0)
			// Host destinations are properly distributed to matching nodes
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				// tagged-server gets webserver:22 (since webserver = 100.108.74.26 = tagged-server)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							// NOTE: Tailscale uses partitioned CGNAT CIDRs, Headscale uses full 100.64.0.0/10:
							// "100.115.94.0/23", "100.115.96.0/19", ..., "fd7a:115c:a1e0::/48"
							// TODO: Host destination is IPv4-only in Tailscale, but Headscale
							// resolves host aliases to node IPs and includes both IPv4+IPv6
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db gets database:5432 (since database = 100.74.60.128 = tagged-db)
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							// TODO: Host destination is IPv4-only in Tailscale
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 7.4: * → 9 destinations (multiple per node)
		// Destinations: tag:server:22, tag:server:80, tag:server:443, tag:database:5432,
		//               tag:database:3306, tag:web:80, tag:web:443, webserver:8080, database:8080
		{
			name:   "wildcard_to_9_destinations_7_4",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["tag:server:22", "tag:server:80", "tag:server:443", "tag:database:5432", "tag:database:3306", "tag:web:80", "tag:web:443", "webserver:8080", "database:8080"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				// tagged-server gets: tag:server:22/80/443 + webserver:8080
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							// webserver:8080 (host alias - Headscale includes IPv4+IPv6)
							// TODO: Tailscale host destinations are IPv4-only
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							// tag:server:22 (IPv4)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// tag:server:80 (IPv4)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							// tag:server:443 (IPv4)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							// tag:server:22 (IPv6)
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// tag:server:80 (IPv6)
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							// tag:server:443 (IPv6)
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db gets: tag:database:5432/3306 + database:8080
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							// database:8080 (host alias - Headscale includes IPv4+IPv6)
							// TODO: Tailscale host destinations are IPv4-only
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							// tag:database:5432 (IPv4)
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							// tag:database:3306 (IPv4)
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 3306, Last: 3306}},
							// tag:database:5432 (IPv6)
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							// tag:database:3306 (IPv6)
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 3306, Last: 3306}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-web gets: tag:web:80/443
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							// tag:web:80 (IPv4)
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							// tag:web:443 (IPv4)
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							// tag:web:80 (IPv6)
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							// tag:web:443 (IPv6)
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 7.5: MANY sources → MANY destinations
		// Sources: autogroup:member, group:admins, kratail2tid@, tag:client, tag:web, 100.80.238.75, 100.94.92.91
		// Destinations: tag:server:22, webserver:80, 100.108.74.26:443, group:admins:8080, kratail2tid@:9000
		{
			name:   "many_sources_many_destinations_7_5",
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:member", "group:admins", "kratail2tid@", "tag:client", "tag:web", "100.80.238.75", "100.94.92.91"], "dst": ["tag:server:22", "webserver:80", "100.108.74.26:443", "group:admins:8080", "kratail2tid@:9000"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1 gets: group:admins:8080 + kratail2tid@:9000
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// kratail2tid@:9000
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 9000, Last: 9000}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 9000, Last: 9000}},
							// group:admins:8080
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server gets: tag:server:22 + webserver:80 + 100.108.74.26:443
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// webserver:80 (host alias matches tagged-server, includes IPv6)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							// tag:server:22
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// 100.108.74.26:443 (raw IP matches node, so Headscale includes IPv6)
							// TODO: Tailscale raw IP destinations are IPv4-only
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 8.3: tagged-db referenced 3 ways as source
		// Sources: tag:database, database (host alias), 100.74.60.128 (raw IP)
		// All 3 resolve to tagged-db - should be deduplicated in Srcs
		{
			name:   "tagged_db_3_ways_source_8_3",
			policy: makePolicy(`{"action": "accept", "src": ["tag:database", "database", "100.74.60.128"], "dst": ["tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server receives filter
				// Srcs should be deduplicated: tag adds IPv6, host/raw IP are IPv4-only
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 8.4: autogroup:tagged + all 4 tags as sources
		// Sources: autogroup:tagged, tag:server, tag:client, tag:database, tag:web
		// autogroup:tagged covers all 4 tags, so individual tags are redundant
		// Should deduplicate to just 8 IPs (4 nodes × 2 IPs each)
		{
			name:   "autogroup_tagged_plus_all_4_tags_8_4",
			policy: makePolicy(`{"action": "accept", "src": ["autogroup:tagged", "tag:server", "tag:client", "tag:database", "tag:web"], "dst": ["autogroup:member:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1 (autogroup:member) receives the filter
				// Srcs = all 4 tagged nodes deduplicated = 8 IPs
				"user1": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// ===========================================
		// Additional Missing Tests - Batch 2
		// ===========================================
		// Test 1.8: tag:server + webserver (same IP two ways as sources)
		{
			name:   "tag_server_plus_webserver_same_ip_1_8",
			policy: makePolicy(`{"action": "accept", "src": ["tag:server", "webserver"], "dst": ["tag:client:22"]}`),
			// tag:server and webserver both resolve to tagged-server (100.108.74.26)
			// Sources should be deduplicated
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-server": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-client receives the filter
				"tagged-client": {
					{
						SrcIPs: []string{
							// Deduplicated: tag:server adds IPv4+IPv6, webserver adds IPv4 only
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 4.3: group:admins → webserver:22
		{
			name:   "group_admins_to_webserver_4_3",
			policy: makePolicy(`{"action": "accept", "src": ["group:admins"], "dst": ["webserver:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server (webserver) receives the filter
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// TODO: Tailscale only includes IPv4 for host alias
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 4.4: webserver → group:admins:22
		{
			name:   "webserver_to_group_admins_4_4",
			policy: makePolicy(`{"action": "accept", "src": ["webserver"], "dst": ["group:admins:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1 (group:admins member) receives the filter
				"user1": {
					{
						SrcIPs: []string{
							// TODO: Tailscale only includes IPv4 for host source
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 8.6: user1:22 referenced 4 ways as destination
		// Destinations: group:admins:22, group:developers:22, kratail2tid@:22, 100.90.199.68:22
		{
			name:   "user1_4_ways_dest_8_6",
			policy: makePolicy(`{"action": "accept", "src": ["tag:client"], "dst": ["group:admins:22", "group:developers:22", "kratail2tid@:22", "100.90.199.68:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1 receives the filter - Dsts NOT deduplicated
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// kratail2tid@:22
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// group:admins:22
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// group:developers:22
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// 100.90.199.68:22 (raw IP matches node, includes IPv6)
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 8.7: Same node, 5 ports via different references
		// Destinations: tag:server:22, tag:server:80, tag:server:443, webserver:8080, 100.108.74.26:9000
		{
			name:   "same_node_5_ports_different_refs_8_7",
			policy: makePolicy(`{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22", "tag:server:80", "tag:server:443", "webserver:8080", "100.108.74.26:9000"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server receives the filter
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// webserver:8080 (host alias - includes IPv6)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 8080, Last: 8080}},
							// 100.108.74.26:9000 (raw IP - includes IPv6)
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 9000, Last: 9000}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 9000, Last: 9000}},
							// tag:server:22
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// tag:server:80
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							// tag:server:443
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 9.4: Wildcard to autogroup:self
		{
			name:   "wildcard_to_autogroup_self_9_4",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*"]}`),
			// Only user1 (user-owned) receives filter; tagged nodes don't support autogroup:self
			// Sources narrowed to user1's own IPs (not full wildcard)
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// Note: autogroup:self destinations use raw IP format (no /32 suffix)
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 10.4: 3 rules, same dest, different sources
		// Rule 1: * → tag:server:22
		// Rule 2: tag:client → tag:server:80
		// Rule 3: autogroup:member → tag:server:443
		{
			name: "three_rules_same_dest_different_sources_10_4",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server receives 3 filter entries
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 10.5: Mixed sources in multiple rules
		// Rule 1: [tag:client, tag:web] → tag:server:22
		// Rule 2: [autogroup:member, group:admins] → tag:database:5432
		{
			name: "mixed_sources_multiple_rules_10_5",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"],
					"group:developers": ["kratail2tid@"],
					"group:empty": []
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26",
					"database": "100.74.60.128",
					"internal": "10.0.0.0/8",
					"subnet24": "192.168.1.0/24"
				},
				"acls": [
					{"action": "accept", "src": ["tag:client", "tag:web"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["autogroup:member", "group:admins"], "dst": ["tag:database:5432"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				// tagged-server receives filter from rule 1
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db receives filter from rule 2
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 11.3: Mixed sources with mixed port formats
		// Destinations: tag:server:22, tag:server:80-443, tag:database:5432,3306
		{
			name:   "mixed_sources_mixed_port_formats_11_3",
			policy: makePolicy(`{"action": "accept", "src": ["tag:client", "tag:web"], "dst": ["tag:server:22", "tag:server:80-443", "tag:database:5432,3306"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-web":    nil,
				// tagged-server receives :22 and :80-443
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// :22
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							// :80-443
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db receives :5432,3306
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// :5432
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							// :3306
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 3306, Last: 3306}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 3306, Last: 3306}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 12.5: Multiple CIDR + tag destinations
		// Destinations: internal:22, subnet24:80, tag:server:443
		// CIDR destinations don't match tailnet nodes
		{
			name:   "multiple_cidr_plus_tag_destinations_12_5",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["internal:22", "subnet24:80", "tag:server:443"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// Only tag:server:443 is delivered (CIDRs don't match tailnet nodes)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 13.4: Wildcard → self:80-443 (port range)
		{
			name:   "wildcard_to_self_port_range_13_4",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["autogroup:self:80-443"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// Note: autogroup:self destinations use raw IP format (no /32 suffix)
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 443}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 13.16: Wildcard → self + tag:server:22 (mixed destinations)
		{
			name:   "wildcard_to_self_plus_tag_server_13_16",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*", "tag:server:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1: receives narrowed Srcs for autogroup:self
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// Note: autogroup:self destinations use raw IP format (no /32 suffix)
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server: receives full wildcard Srcs for tag:server:22
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 13.20: Wildcard → self + group:admins:22 (same dest node)
		{
			name:   "wildcard_to_self_plus_group_admins_13_20",
			policy: makePolicy(`{"action": "accept", "src": ["*"], "dst": ["autogroup:self:*", "group:admins:22"]}`),
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// user1 gets 2 filter entries:
				// Entry 1: autogroup:self:* with narrowed Srcs (processed first due to autogroup:self splitting)
				// Entry 2: group:admins:22 with full wildcard
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							// Note: autogroup:self destinations use raw IP format (no /32 suffix)
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 0, Last: 65535}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},

		// ===== Category 14: Multi-Rule Tests =====

		// Test 14.21: 3 different srcs → same dest, different ports (3 rules)
		{
			name: "three_diff_srcs_same_dest_diff_ports_14_21",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:server:80"]},
					{"action": "accept", "src": ["tag:database"], "dst": ["tag:server:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server: receives 3 separate filter entries (different Srcs = separate)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.22: 3 refs to same user → same dest:port (3 rules)
		// MERGED into 1 entry with 6 Dsts (not deduplicated)
		{
			name: "three_refs_same_user_same_dest_14_22",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["group:admins"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["kratail2tid@"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"tagged-server": {
					// Merged: 1 entry with 6 Dsts (not deduplicated)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.23: Same src → 3 different dests (3 rules)
		{
			name: "same_src_three_diff_dests_14_23",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:5432"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:web:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				// Each destination node receives its own filter (same Srcs per node)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.26: Same entity as both src and dst in 2 rules
		// MERGED into 1 entry with 4 Dsts (not deduplicated)
		{
			name: "same_entity_src_and_dst_14_26",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:22"]},
					{"action": "accept", "src": ["group:admins"], "dst": ["group:admins:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					// Merged: 1 entry with 4 Dsts (not deduplicated)
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.27: User→user:22, group→user:80 (same Srcs, different ports)
		// MERGED into 1 entry with 4 Dsts
		{
			name: "user_to_user_22_group_to_user_80_14_27",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["kratail2tid@"], "dst": ["kratail2tid@:22"]},
					{"action": "accept", "src": ["group:admins"], "dst": ["kratail2tid@:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					// Merged: 1 entry with 4 Dsts
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.29: tagged→tagged:22, specific tags→tagged:80
		{
			name: "tagged_to_tagged_specific_tags_14_29",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:tagged:22"]},
					{"action": "accept", "src": ["tag:client", "tag:web"], "dst": ["autogroup:tagged:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1": nil,
				// Each tagged node receives 2 filter entries (different Srcs = separate)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.42: Both autogroups → wildcard (full network)
		{
			name: "both_autogroups_to_wildcard_14_42",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["*:*"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["*:*"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				// All nodes receive 2 filter entries (different Srcs = separate entries)
				"user1": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.45: Triple src ref each rule
		{
			name: "triple_src_ref_each_rule_14_45",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:member", "group:admins", "kratail2tid@"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:server", "webserver", "100.108.74.26"], "dst": ["group:admins:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				// tagged-server: receives filter from rule 1 (triple user ref deduplicated to 1 IP)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// user1: receives filter from rule 2 (triple ref deduplicated to tag:server IP)
				"user1": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.47: Same src → 4 dests (4 rules)
		{
			name: "same_src_four_dests_14_47",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:database:5432"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:80"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["webserver:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				// tagged-server: merged entry for :22 and :443 (same SrcIPs)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.50: 6 rules mixing all patterns
		{
			name: "six_rules_mixed_patterns_14_50",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["tag:server"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:client:22"]},
					{"action": "accept", "src": ["tag:database"], "dst": ["tag:database:22"]},
					{"action": "accept", "src": ["tag:web"], "dst": ["tag:web:22"]},
					{"action": "accept", "src": ["autogroup:member"], "dst": ["*:80"]},
					{"action": "accept", "src": ["*"], "dst": ["autogroup:member:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				// user1: receives 2 entries: member→*:80 and *→user1:443
				"user1": {
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server: receives self-ref + member→*:80
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"fd7a:115c:a1e0::b901:4a87/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-client: receives self-ref + member→*:80
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db: receives self-ref + member→*:80
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.74.60.128/32",
							"fd7a:115c:a1e0::2f01:3c9c/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-web: receives self-ref + member→*:80
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.94.92.91/32",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.90.199.68/32",
							"fd7a:115c:a1e0::2d01:c747/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.17: Wildcard → group and user (same person):22
		// Test 14.17: * → group:admins:22 and * → kratail2tid@:22
		// MERGED into 1 entry with 4 Dsts (duplicated)
		{
			name: "wildcard_to_group_and_user_same_14_17",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["group:admins:22"]},
					{"action": "accept", "src": ["*"], "dst": ["kratail2tid@:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					// Merged: 1 entry with 4 Dsts (duplicated)
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.18: Tag → member and group (same):22
		// MERGED into 1 entry with 4 Dsts (duplicated)
		{
			name: "tag_to_member_and_group_same_14_18",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["autogroup:member:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["group:admins:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-server": nil,
				"tagged-client": nil,
				"tagged-db":     nil,
				"tagged-web":    nil,
				"user1": {
					// Merged: 1 entry with 4 Dsts (duplicated)
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.20: Two rules with multi-dest, partial dest overlap
		{
			name: "two_rules_multi_dest_partial_overlap_14_20",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["tag:server:22", "tag:database:5432"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80", "tag:web:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				// tagged-server: receives both wildcard:22 and tag:client:80
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db: receives wildcard:5432
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-web: receives tag:client:443
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 443, Last: 443}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.30: All→all subset, wildcard→wildcard
		{
			name: "all_to_all_subset_wildcard_wildcard_14_30",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["autogroup:member", "autogroup:tagged"], "dst": ["autogroup:member:22", "autogroup:tagged:80"]},
					{"action": "accept", "src": ["*"], "dst": ["*:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				// user1: receives member:22 (first rule dst) + *:443 (second rule)
				"user1": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.90.199.68/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2d01:c747/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-web: receives tagged:80 (first rule dst) + *:443 (second rule)
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// Other tagged nodes: same pattern - tagged:80 + *:443
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.80.238.75/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::7901:ee86/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.108.74.26/32",
							"100.74.60.128/32",
							"100.80.238.75/32",
							"100.90.199.68/32",
							"100.94.92.91/32",
							"fd7a:115c:a1e0::2d01:c747/128",
							"fd7a:115c:a1e0::2f01:3c9c/128",
							"fd7a:115c:a1e0::7901:ee86/128",
							"fd7a:115c:a1e0::b901:4a87/128",
							"fd7a:115c:a1e0::ef01:5c81/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.37: Multiple wildcard src rules
		// Rules with same SrcIPs going to the same node are MERGED
		{
			name: "multiple_wildcard_src_rules_14_37",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["*"], "dst": ["tag:database:5432"]},
					{"action": "accept", "src": ["*"], "dst": ["*:80"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server: receives rule 1 (:22) and rule 3 (:80) - MERGED
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db: receives rule 2 (:5432) and rule 3 (:80) - MERGED
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"user1": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 80, Last: 80}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.38: Wildcard dest + specific dest
		// TODO: Tailscale subsumes specific into wildcard (1 entry), Headscale creates 2 separate entries
		{
			name: "wildcard_dest_plus_specific_dest_14_38",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["*:*"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				// tagged-client: receives only wildcard (tag:server:22 doesn't apply to tagged-client)
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server: receives both wildcard and specific (specific is subset)
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRangeAny},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.40: Wildcard in different positions
		{
			name: "wildcard_in_different_positions_14_40",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["tag:server:22", "tag:database:5432"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80", "*:443"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				// user1: receives only *:443 from rule 2
				"user1": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-server: receives wildcard:22 and tag:client:80 and tag:client:443
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 80, Last: 80}},
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db: receives wildcard:5432 and tag:client:443
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.64.0.0/10",
							"fd7a:115c:a1e0::/48",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 5432, Last: 5432}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-web: receives only tag:client:443
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-client: receives only tag:client:443
				"tagged-client": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "*", Ports: tailcfg.PortRange{First: 443, Last: 443}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
		// Test 14.49: Same src → 5 dests (some overlap)
		// TODO: Tailscale merges, Headscale creates separate entries but may deduplicate destinations
		{
			name: "same_src_five_dests_overlap_14_49",
			policy: `{
				"groups": {"group:admins": ["kratail2tid@"]},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"],
					"tag:database": ["kratail2tid@"],
					"tag:web": ["kratail2tid@"]
				},
				"hosts": {"webserver": "100.108.74.26", "database": "100.74.60.128"},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:database:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["tag:web:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["webserver:22"]},
					{"action": "accept", "src": ["tag:client"], "dst": ["database:22"]}
				]
			}`,
			wantFilters: map[string][]tailcfg.FilterRule{
				"user1":         nil,
				"tagged-client": nil,
				// tagged-server: receives rules 1 and 4 (tag:server:22 and webserver:22 resolve to same node)
				// Note: Host alias (webserver) also resolves to both IPv4 and IPv6 when it matches a node
				"tagged-server": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.108.74.26/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::b901:4a87/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-db: receives rules 2 and 5 (tag:database:22 and database:22 resolve to same node)
				"tagged-db": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "100.74.60.128/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::2f01:3c9c/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
				// tagged-web: receives rule 3 only
				"tagged-web": {
					{
						SrcIPs: []string{
							"100.80.238.75/32",
							"fd7a:115c:a1e0::7901:ee86/128",
						},
						DstPorts: []tailcfg.NetPortRange{
							{IP: "100.94.92.91/32", Ports: tailcfg.PortRange{First: 22, Last: 22}},
							{IP: "fd7a:115c:a1e0::ef01:5c81/128", Ports: tailcfg.PortRange{First: 22, Last: 22}},
						},
						IPProto: []int{ProtocolTCP, ProtocolUDP, ProtocolICMP, ProtocolIPv6ICMP},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			require.NoError(t, err, "failed to parse policy")

			err = pol.validate()
			require.NoError(t, err, "policy validation failed")

			for nodeName, wantFilters := range tt.wantFilters {
				node := findNodeByGivenName(nodes, nodeName)
				require.NotNil(t, node, "node %s not found", nodeName)

				// Get compiled filters for this specific node
				compiledFilters, err := pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice())
				require.NoError(t, err, "failed to compile filters for node %s", nodeName)

				// Reduce to only rules where this node is a destination
				gotFilters := policyutil.ReduceFilterRules(node.View(), compiledFilters)

				if len(wantFilters) == 0 && len(gotFilters) == 0 {
					continue
				}

				if diff := cmp.Diff(wantFilters, gotFilters, cmpOptions()...); diff != "" {
					t.Errorf("node %s filters mismatch (-want +got):\n%s", nodeName, diff)
				}
			}
		})
	}
}

// TestTailscaleCompatErrorCases tests ACL configurations that should produce validation errors.
// These tests verify that Headscale correctly rejects invalid policies, matching Tailscale's behavior
// where the coordination server rejects the policy at update time (400 Bad Request).
//
// Reference: /home/kradalby/acl-explore/findings/09-mixed-scenarios.md.
func TestTailscaleCompatErrorCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		policy    string
		wantErr   string
		reference string // Test case reference from findings
	}{
		// Test 6.4: tag:nonexistent → tag:server:22 (ERROR)
		// Tailscale error: "src=tag not found: \"tag:nonexistent\" (400)"
		{
			name: "undefined_tag_source_6_4",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["tag:nonexistent"], "dst": ["tag:server:22"]}
				]
			}`,
			wantErr:   `tag not defined in policy: "tag:nonexistent"`,
			reference: "Test 6.4: tag:nonexistent → tag:server:22",
		},

		// Test 13.41: autogroup:self as SOURCE (ERROR)
		// Tailscale error: "\"autogroup:self\" not valid on the src side of a rule (400)"
		{
			name: "self_as_source_13_41",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:self"], "dst": ["tag:server:22"]}
				]
			}`,
			wantErr:   `autogroup:self can only be used in ACL destinations`,
			reference: "Test 13.41: autogroup:self as SOURCE",
		},

		// Test 13.43: autogroup:self without port (ERROR)
		// Tailscale error: "dst=\"autogroup:self\": port range \"self\": invalid first integer (400)"
		{
			name: "self_without_port_13_43",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["*"], "dst": ["autogroup:self"]}
				]
			}`,
			wantErr:   `invalid port number`,
			reference: "Test 13.43: autogroup:self without port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pol, err := unmarshalPolicy([]byte(tt.policy))
			// Check for parsing errors (some errors occur at parse time)
			if err != nil {
				require.ErrorContains(t, err, tt.wantErr,
					"test %s (%s): expected parse error containing %q, got %q",
					tt.name, tt.reference, tt.wantErr, err.Error())

				return
			}

			// Check for validation errors
			err = pol.validate()
			require.Error(t, err, "test %s (%s): expected validation error, got none", tt.name, tt.reference)
			require.ErrorContains(t, err, tt.wantErr,
				"test %s (%s): expected error containing %q, got %q",
				tt.name, tt.reference, tt.wantErr, err.Error())
		})
	}
}

// TestTailscaleCompatErrorCasesHeadscaleDiffers validates that Headscale correctly rejects
// policies that Tailscale also rejects. These tests verify that autogroup:self destination
// validation for ACL rules matches Tailscale's behavior.
//
// Tailscale validates that autogroup:self can only be used when ALL sources are
// users, groups, or autogroup:member. Headscale now performs this same validation.
//
// Reference: /home/kradalby/acl-explore/findings/09-mixed-scenarios.md.
func TestTailscaleCompatErrorCasesHeadscaleDiffers(t *testing.T) {
	t.Parallel()

	// These tests verify that Headscale rejects policies the same way Tailscale does.
	// Tailscale rejects these policies at validation time (400 Bad Request),
	// and Headscale now does the same.
	tests := []struct {
		name           string
		policy         string
		tailscaleError string // What Tailscale returns (and Headscale should match)
		reference      string
	}{
		// Test 2.5: tag:client → autogroup:self:* + tag:server:22
		// Tailscale REJECTS this - autogroup:self requires user/group sources
		{
			name: "tag_source_with_self_dest_2_5",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"],
					"tag:client": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["autogroup:self:*", "tag:server:22"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 2.5: tag:client → autogroup:self:* + tag:server:22",
		},

		// Test 4.5: tag:client → autogroup:self:*
		// Tailscale REJECTS this - autogroup:self requires user/group sources
		{
			name: "tag_source_to_self_dest_only_4_5",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:client": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 4.5: tag:client → autogroup:self:*",
		},

		// Test 6.1: autogroup:tagged → autogroup:self:*
		// Tailscale REJECTS this - autogroup:tagged is NOT a valid source for autogroup:self
		{
			name: "autogroup_tagged_to_self_6_1",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 6.1: autogroup:tagged → autogroup:self:*",
		},

		// Test 9.5: [autogroup:member, autogroup:tagged] → [autogroup:self:*, tag:server:22]
		// Tailscale REJECTS this - ANY invalid source (autogroup:tagged) invalidates the rule
		{
			name: "both_autogroups_to_self_plus_tag_9_5",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:member", "autogroup:tagged"], "dst": ["autogroup:self:*", "tag:server:22"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 9.5: [autogroup:member, autogroup:tagged] → [autogroup:self:*, tag:server:22]",
		},

		// Test 13.6: autogroup:tagged → self:*
		// Tailscale REJECTS this - same as 6.1
		{
			name: "autogroup_tagged_to_self_13_6",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 13.6: autogroup:tagged → self:*",
		},

		// Test 13.10: tag:client → self:*
		// Tailscale REJECTS this - tags are not valid sources for autogroup:self
		{
			name: "tag_to_self_13_10",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:client": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["tag:client"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 13.10: tag:client → self:*",
		},

		// Test 13.13: Host → self:*
		// Tailscale REJECTS this - hosts are not valid sources for autogroup:self
		{
			name: "host_to_self_13_13",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"hosts": {
					"webserver": "100.108.74.26"
				},
				"acls": [
					{"action": "accept", "src": ["webserver"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 13.13: Host → self:*",
		},

		// Test 13.14: Raw IP → self:*
		// Tailscale REJECTS this - raw IPs are not valid sources for autogroup:self
		{
			name: "raw_ip_to_self_13_14",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:server": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["100.90.199.68"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 13.14: Raw IP (user1) → self:*",
		},

		// Test 13.25: [autogroup:member, tag:client] → self:*
		// Tailscale REJECTS this - ANY invalid source (tag:client) invalidates the rule
		{
			name: "mixed_valid_invalid_sources_to_self_13_25",
			policy: `{
				"groups": {
					"group:admins": ["kratail2tid@"]
				},
				"tagOwners": {
					"tag:client": ["kratail2tid@"]
				},
				"acls": [
					{"action": "accept", "src": ["autogroup:member", "tag:client"], "dst": ["autogroup:self:*"]}
				]
			}`,
			tailscaleError: "autogroup:self can only be used with users, groups, or supported autogroups (400)",
			reference:      "Test 13.25: [autogroup:member, tag:client] → self:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// unmarshalPolicy calls validate() internally, so we expect it to fail
			// with our validation error
			_, err := unmarshalPolicy([]byte(tt.policy))
			require.Error(t, err,
				"test %s (%s): should reject policy like Tailscale",
				tt.name, tt.reference)
			require.ErrorIs(t, err, ErrACLAutogroupSelfInvalidSource,
				"test %s (%s): expected autogroup:self validation error",
				tt.name, tt.reference)
		})
	}
}
