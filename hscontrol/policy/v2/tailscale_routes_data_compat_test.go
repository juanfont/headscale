// This file implements data-driven test runners for routes compatibility tests.
// It loads HuJSON golden files from testdata/routes_results/routes-*.hujson,
// captured from Tailscale SaaS by tscap, and compares headscale's route-aware
// ACL engine output against the captured packet filter rules.
//
// Each capture file is a testcapture.Capture containing:
//   - A full policy (groups, tagOwners, hosts, acls) in Input.FullPolicy
//   - A Topology section with nodes, including RoutableIPs and ApprovedRoutes
//   - Expected packet_filter_rules per node in Captures[name].PacketFilterRules
//
// Two test runners use this data:
//
//   - TestRoutesCompat: validates filter rule compilation (compileFilterRulesForNode
//     + ReduceFilterRules) against golden file captures.
//
//   - TestRoutesCompatPeerVisibility: validates peer visibility (CanAccess /
//     ReduceNodes) for the subnet-to-subnet scenarios (f10–f15). These tests
//     derive expected peer relationships from the golden file captures: if
//     Tailscale SaaS delivers filter rules to a node, then the subnet routers
//     referenced in those rules must be visible as peers. This exercises the
//     CanAccess fix from issue #3157.
//
// Test data source: testdata/routes_results/routes-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// loadRoutesTestFile loads and parses a single routes capture HuJSON file.
func loadRoutesTestFile(t *testing.T, path string) *testcapture.Capture {
	t.Helper()

	c, err := testcapture.Read(path)
	require.NoError(t, err, "failed to read test file %s", path)

	return c
}

// convertSaaSEmail used to map SaaS-side emails to @example.com placeholders.
// tscap now anonymizes captures at write time (norse-god names + pokémon
// hostnames), so the captured topology emails are already in their final
// form and this is a passthrough.
func convertSaaSEmail(email string) string {
	return email
}

// buildRoutesUsersAndNodes constructs types.Users and types.Nodes from the
// captured topology. This allows each test file to define its own topology
// (e.g., the IPv6 tests use different nodes than the standard tests).
func buildRoutesUsersAndNodes(
	t *testing.T,
	topo testcapture.Topology,
) (types.Users, types.Nodes) {
	t.Helper()

	// Build users — if topology has users section, use it.
	// Otherwise fall back to the standard 3-user setup matching
	// the grant topology (used by Tailscale SaaS captures).
	var users types.Users
	if len(topo.Users) > 0 {
		users = make(types.Users, 0, len(topo.Users))
		for _, u := range topo.Users {
			users = append(users, types.User{
				Model: gorm.Model{ID: u.ID},
				Name:  u.Name,
				Email: convertSaaSEmail(u.Email),
			})
		}
	} else {
		users = types.Users{
			{Model: gorm.Model{ID: 1}, Name: "kratail2tid", Email: "kratail2tid@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "kristoffer", Email: "kristoffer@example.com"},
			{Model: gorm.Model{ID: 3}, Name: "monitorpasskeykradalby", Email: "monitorpasskeykradalby@example.com"},
		}
	}

	// Build nodes. Topology nodes are keyed by GivenName.
	// Assign sequential IDs (the capture format does not store them);
	// unique IDs are required by ReduceNodes / BuildPeerMap which skip
	// peers by comparing node.ID.
	nodes := make(types.Nodes, 0, len(topo.Nodes))
	autoID := 1

	for _, nodeDef := range topo.Nodes {
		nodeID := autoID
		autoID++

		node := &types.Node{
			ID:        types.NodeID(nodeID), //nolint:gosec
			GivenName: nodeDef.Hostname,
			IPv4:      ptrAddr(nodeDef.IPv4),
			IPv6:      ptrAddr(nodeDef.IPv6),
			Tags:      nodeDef.Tags,
		}

		// Set up Hostinfo with RoutableIPs
		hostinfo := &tailcfg.Hostinfo{}

		if len(nodeDef.RoutableIPs) > 0 {
			routableIPs := make(
				[]netip.Prefix,
				0,
				len(nodeDef.RoutableIPs),
			)
			for _, r := range nodeDef.RoutableIPs {
				routableIPs = append(
					routableIPs,
					netip.MustParsePrefix(r),
				)
			}

			hostinfo.RoutableIPs = routableIPs
		}

		node.Hostinfo = hostinfo

		// Set ApprovedRoutes
		if len(nodeDef.ApprovedRoutes) > 0 {
			approvedRoutes := make(
				[]netip.Prefix,
				0,
				len(nodeDef.ApprovedRoutes),
			)
			for _, r := range nodeDef.ApprovedRoutes {
				approvedRoutes = append(
					approvedRoutes,
					netip.MustParsePrefix(r),
				)
			}

			node.ApprovedRoutes = approvedRoutes
		} else {
			node.ApprovedRoutes = []netip.Prefix{}
		}

		// Assign user if specified
		if nodeDef.User != "" {
			for i := range users {
				if users[i].Name == nodeDef.User {
					node.User = &users[i]
					node.UserID = &users[i].ID

					break
				}
			}
		}

		nodes = append(nodes, node)
	}

	return users, nodes
}

// subnetToSubnetFiles lists the golden files that test subnet-to-subnet
// ACL scenarios. These are the scenarios where the fix for issue #3157
// (CanAccess considering subnet routes as source identity) is critical.
var subnetToSubnetFiles = []string{
	"routes-f10-subnet-to-subnet-issue3157",
	"routes-f11-subnet-to-subnet-bidirectional",
	"routes-f12-subnet-to-subnet-host-aliases",
	"routes-f13-subnet-to-subnet-disjoint",
	"routes-f14-subnet-to-subnet-overlapping-one-router",
	"routes-f15-subnet-to-subnet-cross-routers",
}

// TestRoutesCompat is a data-driven test that loads all routes-*.hujson test
// files and compares headscale's route-aware ACL engine output against the
// expected behavior.
func TestRoutesCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "routes_results", "routes-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no routes-*.hujson test files found in testdata/routes_results/",
	)

	t.Logf("Loaded %d routes test files", len(files))

	for _, file := range files {
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Build topology from JSON
			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)

			// Convert Tailscale SaaS user emails to headscale format
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			// Parse and validate policy
			pol, err := unmarshalPolicy(policyJSON)
			require.NoError(
				t,
				err,
				"%s: policy should parse successfully",
				tf.TestID,
			)

			err = pol.validate()
			require.NoError(
				t,
				err,
				"%s: policy should validate successfully",
				tf.TestID,
			)

			for nodeName, capture := range tf.Captures {
				t.Run(nodeName, func(t *testing.T) {
					node := findNodeByGivenName(nodes, nodeName)
					require.NotNilf(t, node,
						"golden node %s not found in topology", nodeName)

					compiledRules, err := pol.compileFilterRulesForNode(
						users,
						node.View(),
						nodes.ViewSlice(),
					)
					require.NoError(
						t,
						err,
						"%s/%s: failed to compile filter rules",
						tf.TestID,
						nodeName,
					)

					gotRules := policyutil.ReduceFilterRules(
						node.View(),
						compiledRules,
					)

					wantRules := capture.PacketFilterRules

					opts := append(
						cmpOptions(),
						cmpopts.EquateEmpty(),
					)
					if diff := cmp.Diff(
						wantRules,
						gotRules,
						opts...,
					); diff != "" {
						t.Errorf(
							"%s/%s: filter rules mismatch (-want +got):\n%s",
							tf.TestID,
							nodeName,
							diff,
						)
					}
				})
			}
		})
	}
}

// derivePeerPairsFromCaptures builds the set of expected peer pairs from
// golden file captures. For each node that receives filter rules from
// Tailscale SaaS, the SrcIPs identify subnets whose traffic will arrive
// at this node. Any other node whose approved subnet routes overlap
// those SrcIPs must be peered with this node — otherwise the traffic
// cannot flow.
//
// Returns a set of unordered node-name pairs that must be peers.
func derivePeerPairsFromCaptures(
	t *testing.T,
	tf *testcapture.Capture,
	nodes types.Nodes,
) map[[2]string]bool {
	t.Helper()

	pairs := make(map[[2]string]bool)

	for dstNodeName, capture := range tf.Captures {
		if len(capture.PacketFilterRules) == 0 {
			continue
		}

		rules := capture.PacketFilterRules

		// Build an IPSet of all SrcIPs from the capture's filter rules.
		var srcBuilder netipx.IPSetBuilder

		for _, rule := range rules {
			for _, srcIP := range rule.SrcIPs {
				addSrcIPToBuilder(t, &srcBuilder,
					srcIP, tf.TestID, dstNodeName,
				)
			}
		}

		srcSet, err := srcBuilder.IPSet()
		require.NoError(t, err)

		// Find all nodes whose SubnetRoutes overlap srcSet.
		for _, node := range nodes {
			if node.GivenName == dstNodeName {
				continue
			}

			if slices.ContainsFunc(node.SubnetRoutes(), srcSet.OverlapsPrefix) {
				pair := orderedPair(dstNodeName, node.GivenName)
				pairs[pair] = true
			}
		}
	}

	return pairs
}

// orderedPair returns a canonical [2]string with the names sorted
// so that (A,B) and (B,A) map to the same key.
func orderedPair(a, b string) [2]string {
	if a > b {
		return [2]string{b, a}
	}

	return [2]string{a, b}
}

// addSrcIPToBuilder parses a SrcIP string (CIDR, bare IP, wildcard "*",
// or IP range like "100.64.0.0-100.115.91.255") and adds it to the
// IPSetBuilder.
func addSrcIPToBuilder(
	t *testing.T,
	builder *netipx.IPSetBuilder,
	srcIP, testID, nodeName string,
) {
	t.Helper()

	// Handle wildcard.
	if srcIP == "*" {
		builder.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
		builder.AddPrefix(netip.MustParsePrefix("::/0"))

		return
	}

	// Try CIDR notation first.
	prefix, prefixErr := netip.ParsePrefix(srcIP)
	if prefixErr == nil {
		builder.AddPrefix(prefix)

		return
	}

	// Try IP range notation: "A.B.C.D-E.F.G.H"
	if strings.Contains(srcIP, "-") {
		parts := strings.SplitN(srcIP, "-", 2)
		ip1, err1 := netip.ParseAddr(parts[0])
		ip2, err2 := netip.ParseAddr(parts[1])

		require.NoError(t, err1,
			"%s/%s: cannot parse range start in %q",
			testID, nodeName, srcIP,
		)
		require.NoError(t, err2,
			"%s/%s: cannot parse range end in %q",
			testID, nodeName, srcIP,
		)

		r := netipx.IPRangeFrom(ip1, ip2)
		for _, pfx := range r.Prefixes() {
			builder.AddPrefix(pfx)
		}

		return
	}

	// Try single IP address.
	addr, err := netip.ParseAddr(srcIP)
	require.NoError(t, err,
		"%s/%s: cannot parse SrcIP %q",
		testID, nodeName, srcIP,
	)

	builder.Add(addr)
}

// deriveAllPeerPairsFromCaptures extends derivePeerPairsFromCaptures
// to find ALL expected peer relationships from golden file captures,
// not just subnet-route-based ones. It checks:
//   - Node's SubnetRoutes overlap the capture's SrcIPs (subnet-to-subnet)
//   - Node's direct IPs (IPv4/IPv6) appear in the capture's SrcIPs
//     (tag/user/group resolved sources)
func deriveAllPeerPairsFromCaptures(
	t *testing.T,
	tf *testcapture.Capture,
	nodes types.Nodes,
) map[[2]string]bool {
	t.Helper()

	pairs := make(map[[2]string]bool)

	for dstNodeName, capture := range tf.Captures {
		if len(capture.PacketFilterRules) == 0 {
			continue
		}

		rules := capture.PacketFilterRules

		// Build an IPSet of all SrcIPs.
		var srcBuilder netipx.IPSetBuilder

		for _, rule := range rules {
			for _, srcIP := range rule.SrcIPs {
				addSrcIPToBuilder(t, &srcBuilder,
					srcIP, tf.TestID, dstNodeName,
				)
			}
		}

		srcSet, err := srcBuilder.IPSet()
		require.NoError(t, err)

		for _, node := range nodes {
			if node.GivenName == dstNodeName {
				continue
			}

			// Check subnet routes overlap.
			if slices.ContainsFunc(
				node.SubnetRoutes(), srcSet.OverlapsPrefix,
			) {
				pairs[orderedPair(dstNodeName, node.GivenName)] = true

				continue
			}

			// Check direct node IPs in SrcIPs.
			if slices.ContainsFunc(
				node.IPs(), srcSet.Contains,
			) {
				pairs[orderedPair(dstNodeName, node.GivenName)] = true
			}
		}
	}

	return pairs
}

// TestRoutesCompatPeerVisibility is a data-driven test that validates peer
// visibility (CanAccess) for subnet-to-subnet ACL scenarios using the same
// golden file data captured from Tailscale SaaS.
//
// Unlike TestRoutesCompat which tests filter rule compilation
// (compileFilterRulesForNode + ReduceFilterRules), this test exercises the
// CanAccess code path that determines whether two nodes should see each
// other as peers. This is the code path fixed in issue #3157: before the
// fix, CanAccess only checked node IPs against matcher sources, missing
// the case where a node's approved subnet routes overlap the source set.
//
// The test derives expected peer pairs from the golden file captures:
// if Tailscale SaaS delivers filter rules to node X with SrcIPs
// overlapping node Y's subnet routes, then Y must be able to CanAccess X
// (Y acts as source identity for its advertised subnets).
func TestRoutesCompatPeerVisibility(t *testing.T) {
	t.Parallel()

	for _, testID := range subnetToSubnetFiles {
		file := filepath.Join(
			"testdata", "routes_results", testID+".hujson",
		)
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Build topology from JSON.
			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)

			// Convert Tailscale SaaS user emails to headscale format.
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			// Create a PolicyManager — this compiles the global filter
			// rules and produces matchers used for peer visibility.
			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoError(t, err,
				"%s: failed to create policy manager", tf.TestID,
			)

			// Derive expected peer pairs from golden file captures.
			wantPairs := derivePeerPairsFromCaptures(t, tf, nodes)
			require.NotEmpty(t, wantPairs,
				"%s: no peer pairs derived — golden file has no "+
					"subnet-to-subnet relationships to test",
				tf.TestID,
			)

			t.Run("CanAccess", func(t *testing.T) {
				// Peer visibility is satisfied if either direction of
				// CanAccess returns true — that mirrors the
				// ReduceNodes semantics used at runtime. An ACL may
				// legitimately grant access in only one direction
				// (tested in ReduceNodes below), and a symmetric
				// assertion would reject the intentional asymmetry.
				for pair := range wantPairs {
					nodeA := findNodeByGivenName(nodes, pair[0])
					nodeB := findNodeByGivenName(nodes, pair[1])
					require.NotNilf(t, nodeA,
						"node %s not found", pair[0],
					)
					require.NotNilf(t, nodeB,
						"node %s not found", pair[1],
					)

					matchersA, err := pm.MatchersForNode(nodeA.View())
					require.NoError(t, err)
					matchersB, err := pm.MatchersForNode(nodeB.View())
					require.NoError(t, err)

					canAccess := nodeA.View().CanAccess(
						matchersA, nodeB.View(),
					) || nodeB.View().CanAccess(
						matchersB, nodeA.View(),
					)
					assert.Truef(t, canAccess,
						"%s: %s and %s should be peers "+
							"(subnet routers must see each other "+
							"when ACL references their subnets)",
						tf.TestID, pair[0], pair[1],
					)
				}
			})

			t.Run("ReduceNodes", func(t *testing.T) {
				// Build the complete peer map using CanAccess and
				// verify it contains all expected pairs.
				// This is equivalent to policy.ReduceNodes but
				// inlined to avoid an import cycle with the policy
				// package.
				for _, node := range nodes {
					matchers, err := pm.MatchersForNode(
						node.View(),
					)
					require.NoError(t, err)

					var peerNames []string

					for _, peer := range nodes {
						if peer.ID == node.ID {
							continue
						}

						if node.View().CanAccess(
							matchers, peer.View(),
						) || peer.View().CanAccess(
							matchers, node.View(),
						) {
							peerNames = append(
								peerNames, peer.GivenName,
							)
						}
					}

					// Collect expected peers for this node.
					var wantPeers []string

					for pair := range wantPairs {
						if pair[0] == node.GivenName {
							wantPeers = append(
								wantPeers, pair[1],
							)
						} else if pair[1] == node.GivenName {
							wantPeers = append(
								wantPeers, pair[0],
							)
						}
					}

					if len(wantPeers) == 0 {
						continue
					}

					sort.Strings(peerNames)
					sort.Strings(wantPeers)

					for _, wantPeer := range wantPeers {
						assert.Containsf(t, peerNames, wantPeer,
							"%s: node %s should have peer %s "+
								"in ReduceNodes result",
							tf.TestID, node.GivenName, wantPeer,
						)
					}
				}
			})

			t.Run("ReduceRoutes", func(t *testing.T) {
				// For each node that has captures with filter rules,
				// verify that CanAccessRoute returns true for the
				// destination routes referenced in those rules, when
				// called from a node whose subnet routes overlap the
				// source CIDRs.
				for dstNodeName, capture := range tf.Captures {
					if len(capture.PacketFilterRules) == 0 {
						continue
					}

					rules := capture.PacketFilterRules

					// Extract destination prefixes from the rules.
					var dstPrefixes []netip.Prefix

					for _, rule := range rules {
						for _, dp := range rule.DstPorts {
							if dp.IP == "*" {
								continue
							}

							prefix, err := netip.ParsePrefix(dp.IP)
							if err != nil {
								// DstPorts.IP can be a bare IP without /prefix.
								addr, addrErr := netip.ParseAddr(dp.IP)
								require.NoErrorf(t, addrErr,
									"golden DstPorts.IP %q unparseable as prefix or addr", dp.IP)

								prefix = netip.PrefixFrom(addr, addr.BitLen())
							}

							dstPrefixes = append(
								dstPrefixes, prefix,
							)
						}
					}

					// For each source node (whose subnets overlap
					// the SrcIPs), verify it can access the dst
					// routes.
					for pair := range wantPairs {
						var srcNodeName string

						switch {
						case pair[0] == dstNodeName:
							srcNodeName = pair[1]
						case pair[1] == dstNodeName:
							srcNodeName = pair[0]
						default:
							continue
						}

						srcNode := findNodeByGivenName(
							nodes, srcNodeName,
						)
						require.NotNil(t, srcNode)

						matchers, err := pm.MatchersForNode(
							srcNode.View(),
						)
						require.NoError(t, err)

						for _, route := range dstPrefixes {
							canAccess := srcNode.View().CanAccessRoute(
								matchers, route,
							)
							assert.Truef(t, canAccess,
								"%s: node %s (routing %v) "+
									"should be able to access "+
									"route %s on node %s",
								tf.TestID, srcNodeName,
								srcNode.SubnetRoutes(),
								route, dstNodeName,
							)
						}
					}
				}
			})
		})
	}
}

// TestRoutesCompatAutoApproval validates that headscale's auto-approval
// logic (NodeCanApproveRoute) produces the same approval decisions as
// captured in the golden files from Tailscale SaaS.
//
// For each node that has routable_ips, the test verifies:
//   - Routes in approved_routes: NodeCanApproveRoute returns true
//   - Routes in routable_ips but NOT in approved_routes: returns false
//
// This covers d1–d11 scenarios (auto-approval edge cases) as well as
// every other golden file whose topology includes routable_ips — all 98
// files have autoApprovers and routable_ips defined.
func TestRoutesCompatAutoApproval(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "routes_results", "routes-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no routes-*.hujson test files found in testdata/routes_results/",
	)

	for _, file := range files {
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Build topology from JSON.
			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)

			// Convert Tailscale SaaS user emails to headscale format.
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			// Create a PolicyManager — this resolves autoApprovers
			// and builds the auto-approve map.
			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoError(t, err,
				"%s: failed to create policy manager", tf.TestID,
			)

			// Track whether this test file had any testable nodes.
			testedNodes := 0

			for nodeName, nodeDef := range tf.Topology.Nodes {
				if len(nodeDef.RoutableIPs) == 0 {
					continue
				}

				node := findNodeByGivenName(nodes, nodeName)
				if node == nil {
					continue
				}

				testedNodes++

				// Build the set of approved routes for quick lookup.
				approvedSet := make(
					map[netip.Prefix]bool,
					len(nodeDef.ApprovedRoutes),
				)
				for _, r := range nodeDef.ApprovedRoutes {
					pfx, err := netip.ParsePrefix(r)
					require.NoErrorf(t, err,
						"golden approved_route %q for %s", r, nodeName)

					approvedSet[pfx] = true
				}

				t.Run(nodeName, func(t *testing.T) {
					for _, routeStr := range nodeDef.RoutableIPs {
						route, err := netip.ParsePrefix(routeStr)
						require.NoErrorf(t, err,
							"golden routable_ip %q for %s", routeStr, nodeName)

						wantApproved := approvedSet[route]
						gotApproved := pm.NodeCanApproveRoute(
							node.View(), route,
						)

						if wantApproved {
							assert.Truef(t, gotApproved,
								"%s/%s: route %s is in "+
									"approved_routes but "+
									"NodeCanApproveRoute "+
									"returned false",
								tf.TestID, nodeName, route,
							)
						} else {
							assert.Falsef(t, gotApproved,
								"%s/%s: route %s is NOT in "+
									"approved_routes but "+
									"NodeCanApproveRoute "+
									"returned true",
								tf.TestID, nodeName, route,
							)
						}
					}
				})
			}

			if testedNodes == 0 {
				t.Skipf(
					"%s: no nodes with routable_ips found",
					tf.TestID,
				)
			}
		})
	}
}

// TestRoutesCompatReduceRoutes validates that headscale's CanAccessRoute
// produces route visibility decisions consistent with the golden file
// captures from Tailscale SaaS.
//
// For each golden file, the test identifies nodes that received filter
// rules from Tailscale SaaS (non-null captures with DstPorts), then
// verifies that viewer nodes whose identity (IPs or subnet routes)
// overlaps the capture's SrcIPs can indeed access those destination
// route prefixes via CanAccessRoute.
//
// This extends the ReduceRoutes sub-test from TestRoutesCompatPeerVisibility
// (which only covers f10–f15) to all 98 golden files.
func TestRoutesCompatReduceRoutes(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "routes_results", "routes-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no routes-*.hujson test files found in testdata/routes_results/",
	)

	for _, file := range files {
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Build topology from JSON.
			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)

			// Convert Tailscale SaaS user emails to headscale format.
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			// Create a PolicyManager.
			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoError(t, err,
				"%s: failed to create policy manager", tf.TestID,
			)

			// For each node that receives filter rules, check that
			// source nodes can access the destination prefixes via
			// CanAccessRoute. Match src↔dst pairs PER RULE — a
			// source IP in rule N should only be tested against
			// the destinations in rule N, not destinations from
			// other rules. This matters when tag-based rules
			// (dst=node-IPs) and CIDR rules (dst=subnets) coexist
			// on the same node.
			for dstNodeName, capture := range tf.Captures {
				if len(capture.PacketFilterRules) == 0 {
					continue
				}

				for ruleIdx, rule := range capture.PacketFilterRules {
					// Extract destination prefixes from this rule.
					var dstPrefixes []netip.Prefix

					for _, dp := range rule.DstPorts {
						if dp.IP == "*" {
							continue
						}

						prefix, parseErr := netip.ParsePrefix(dp.IP)
						if parseErr != nil {
							addr, addrErr := netip.ParseAddr(dp.IP)
							require.NoErrorf(t, addrErr,
								"golden DstPorts.IP %q unparseable", dp.IP)

							prefix = netip.PrefixFrom(addr, addr.BitLen())
						}

						if !slices.Contains(dstPrefixes, prefix) {
							dstPrefixes = append(dstPrefixes, prefix)
						}
					}

					if len(dstPrefixes) == 0 {
						continue
					}

					// Build SrcIPs set from THIS rule only.
					var srcBuilder netipx.IPSetBuilder

					for _, srcIP := range rule.SrcIPs {
						if srcIP == "*" {
							continue
						}

						// SrcIPs can be CIDR prefixes, bare IPs, or
						// dash-separated IP ranges (e.g. "100.115.94.0-100.127.255.255").
						if strings.Contains(srcIP, "-") {
							ipRange, rangeErr := netipx.ParseIPRange(srcIP)
							require.NoErrorf(t, rangeErr,
								"golden SrcIP range %q unparseable", srcIP)

							srcBuilder.AddRange(ipRange)

							continue
						}

						prefix, parseErr := netip.ParsePrefix(srcIP)
						if parseErr != nil {
							addr, parseErr2 := netip.ParseAddr(srcIP)
							require.NoErrorf(t, parseErr2,
								"golden SrcIP %q unparseable as prefix or addr", srcIP)

							srcBuilder.Add(addr)

							continue
						}

						srcBuilder.AddPrefix(prefix)
					}

					srcSet, err := srcBuilder.IPSet()
					require.NoError(t, err)

					for _, viewerNode := range nodes {
						if viewerNode.GivenName == dstNodeName {
							continue
						}

						nv := viewerNode.View()

						// Check if viewer matches THIS rule's sources.
						if !slices.ContainsFunc(nv.IPs(), srcSet.Contains) &&
							!slices.ContainsFunc(nv.SubnetRoutes(), srcSet.OverlapsPrefix) {
							continue
						}

						matchers, matchErr := pm.MatchersForNode(nv)
						require.NoError(t, matchErr)

						t.Run(
							fmt.Sprintf(
								"%s/rule%d/from_%s",
								dstNodeName, ruleIdx,
								viewerNode.GivenName,
							),
							func(t *testing.T) {
								for _, route := range dstPrefixes {
									canAccess := nv.CanAccessRoute(
										matchers, route,
									)
									assert.Truef(t, canAccess,
										"%s: viewer %s should "+
											"access route %s on %s",
										tf.TestID,
										viewerNode.GivenName,
										route, dstNodeName,
									)
								}
							},
						)
					}
				}
			}
		})
	}
}

// TestRoutesCompatExitNodePeerVisibility validates that CanAccess
// correctly handles exit node peer visibility for the b-series golden
// files. These files exercise exit route behaviors (b1-b10) which
// TestRoutesCompat validates for filter rule compilation, but peer
// visibility (CanAccess) was never tested.
//
// For b-series files, the test validates:
//   - Nodes that receive non-null filter rules ARE visible as peers
//   - Nodes that receive null filter rules may or may not be visible
//     depending on the ACL structure
//
// This exercises the DestsIsTheInternet() + IsExitNode() code path
// in CanAccess (types/node.go:339) which had zero test coverage.
func TestRoutesCompatExitNodePeerVisibility(t *testing.T) {
	t.Parallel()

	// b2: tag:exit -> tag:exit:* — only exit nodes peer with each other
	// b8: autogroup:member -> autogroup:internet:* — no filter rules at all
	exitNodeTests := []struct {
		testID string
		// expectedNullAll: if true, all captures should be null
		expectedNullAll bool
	}{
		{testID: "routes-b2-tag-exit-excludes-exit-routes"},
		{testID: "routes-b8-autogroup-internet-no-filters", expectedNullAll: true},
	}

	for _, tc := range exitNodeTests {
		file := filepath.Join(
			"testdata", "routes_results", tc.testID+".hujson",
		)
		tf := loadRoutesTestFile(t, file)

		// Derive exit node names from the topology instead of
		// hard-coding them. The topology's tag arrays are the
		// source of truth for which nodes are exit nodes.
		var exitNodeNames []string

		for name, node := range tf.Topology.Nodes {
			if slices.Contains(node.Tags, "tag:exit") {
				exitNodeNames = append(exitNodeNames, name)
			}
		}

		sort.Strings(exitNodeNames)
		require.NotEmpty(t, exitNodeNames,
			"%s: topology has no nodes with tag:exit", tf.TestID,
		)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoError(t, err)

			if tc.expectedNullAll {
				// All captures null: verify no CanAccess pairs
				// involving exit nodes via this ACL alone.
				for _, exitName := range exitNodeNames {
					exitNode := findNodeByGivenName(
						nodes, exitName,
					)
					require.NotNil(t, exitNode)

					matchers, err := pm.MatchersForNode(
						exitNode.View(),
					)
					require.NoError(t, err)

					for _, other := range nodes {
						if other.ID == exitNode.ID {
							continue
						}

						canAccess := exitNode.View().CanAccess(
							matchers, other.View(),
						)
						assert.Falsef(t, canAccess,
							"exit node %s should NOT "+
								"CanAccess %s when "+
								"autogroup:internet produces "+
								"no filter rules",
							exitName, other.GivenName,
						)
					}
				}

				return
			}

			// For b2: tag:exit -> tag:exit:*, only exit nodes
			// should see each other. Verify exit<->exit pairs
			// have CanAccess=true.
			for i, name1 := range exitNodeNames {
				for j := i + 1; j < len(exitNodeNames); j++ {
					name2 := exitNodeNames[j]
					node1 := findNodeByGivenName(nodes, name1)
					node2 := findNodeByGivenName(nodes, name2)

					require.NotNil(t, node1)
					require.NotNil(t, node2)

					matchers1, err := pm.MatchersForNode(
						node1.View(),
					)
					require.NoError(t, err)

					matchers2, err := pm.MatchersForNode(
						node2.View(),
					)
					require.NoError(t, err)

					canAccess := node1.View().CanAccess(
						matchers1, node2.View(),
					) || node2.View().CanAccess(
						matchers2, node1.View(),
					)

					assert.Truef(t, canAccess,
						"exit nodes %s and %s should be "+
							"peers (ACL: tag:exit -> "+
							"tag:exit:*)",
						name1, name2,
					)
				}
			}

			// Verify non-exit nodes don't peer with exit nodes
			// through this restricted ACL.
			for _, exitName := range exitNodeNames {
				exitNode := findNodeByGivenName(
					nodes, exitName,
				)
				require.NotNil(t, exitNode)

				for _, other := range nodes {
					if other.ID == exitNode.ID {
						continue
					}

					isExit := slices.Contains(
						exitNodeNames, other.GivenName,
					)
					if isExit {
						continue
					}

					matchers, err := pm.MatchersForNode(
						other.View(),
					)
					require.NoError(t, err)

					canAccess := other.View().CanAccess(
						matchers, exitNode.View(),
					)
					assert.Falsef(t, canAccess,
						"non-exit node %s should NOT "+
							"CanAccess exit node %s "+
							"(ACL: tag:exit -> tag:exit:*)",
						other.GivenName, exitName,
					)
				}
			}
		})
	}
}

// TestRoutesCompatNoPeersBeyondCaptures verifies that headscale does not
// create peer relationships beyond what the golden file captures imply.
// For every pair of nodes NOT in the expected peer set (derived from
// the capture SrcIPs), CanAccess must return false.
//
// This extends TestRoutesCompatNoFalsePositivePeers (which only covers
// f10-f15 with hardcoded non-router names) to all 98 ROUTES golden
// files with a generic, data-driven approach.
func TestRoutesCompatNoPeersBeyondCaptures(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "routes_results", "routes-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files)

	for _, file := range files {
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoError(t, err)

			// Derive the complete set of expected peer pairs
			// from the golden file captures.
			expectedPairs := deriveAllPeerPairsFromCaptures(
				t, tf, nodes,
			)

			// Also add pairs implied by DstPorts: if a node's IP
			// appears in DstPorts of rules delivered to another
			// node, they must be peers.
			for dstNodeName, capture := range tf.Captures {
				if len(capture.PacketFilterRules) == 0 {
					continue
				}

				rules := capture.PacketFilterRules

				var dstBuilder netipx.IPSetBuilder

				for _, rule := range rules {
					for _, dp := range rule.DstPorts {
						addSrcIPToBuilder(t, &dstBuilder,
							dp.IP, tf.TestID, dstNodeName,
						)
					}
				}

				dstSet, dstErr := dstBuilder.IPSet()
				if dstErr != nil {
					continue
				}

				for _, node := range nodes {
					if node.GivenName == dstNodeName {
						continue
					}

					if slices.ContainsFunc(
						node.IPs(), dstSet.Contains,
					) {
						expectedPairs[orderedPair(
							dstNodeName, node.GivenName,
						)] = true
					}

					if slices.ContainsFunc(
						node.SubnetRoutes(),
						dstSet.OverlapsPrefix,
					) {
						expectedPairs[orderedPair(
							dstNodeName, node.GivenName,
						)] = true
					}
				}
			}

			falsePositives := 0

			for i, nodeA := range nodes {
				matchersA, err := pm.MatchersForNode(
					nodeA.View(),
				)
				require.NoError(t, err)

				for j := i + 1; j < len(nodes); j++ {
					nodeB := nodes[j]
					pair := orderedPair(
						nodeA.GivenName, nodeB.GivenName,
					)

					if expectedPairs[pair] {
						continue
					}

					matchersB, err := pm.MatchersForNode(
						nodeB.View(),
					)
					require.NoError(t, err)

					canAccess := nodeA.View().CanAccess(
						matchersA, nodeB.View(),
					) || nodeB.View().CanAccess(
						matchersB, nodeA.View(),
					)

					if canAccess {
						t.Errorf(
							"%s: unexpected peer "+
								"relationship: %s <-> %s",
							tf.TestID,
							nodeA.GivenName,
							nodeB.GivenName,
						)

						falsePositives++
					}
				}
			}

			if falsePositives == 0 && len(expectedPairs) == 0 {
				// All-null captures: verify no peers at all.
				t.Logf(
					"%s: all-null captures, verified no "+
						"false-positive peers among %d nodes",
					tf.TestID, len(nodes),
				)
			}
		})
	}
}

// TestRoutesCompatNoFalsePositivePeers verifies that nodes which do NOT
// have subnet routes overlapping an ACL's source or destination CIDRs
// are NOT incorrectly peered with subnet routers.
//
// This is the negative counterpart to TestRoutesCompatPeerVisibility:
// while that test verifies subnet routers CAN see each other, this test
// verifies that unrelated nodes (tagged-server, user1, etc.) are NOT
// made peers of subnet routers solely because of subnet-to-subnet ACLs.
func TestRoutesCompatNoFalsePositivePeers(t *testing.T) {
	t.Parallel()

	// nodesWithoutRoutes lists nodes that have no subnet routes and whose
	// IPs don't appear in any subnet-to-subnet ACL. They should never be
	// peers of subnet routers through these ACLs alone.
	nodesWithoutRoutes := []string{
		"tagged-server",
		"tagged-prod",
		"tagged-client",
		"user1",
		"user-kris",
		"user-mon",
	}

	for _, testID := range subnetToSubnetFiles {
		file := filepath.Join(
			"testdata", "routes_results", testID+".hujson",
		)
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			pm, err := NewPolicyManager(
				policyJSON, users, nodes.ViewSlice(),
			)
			require.NoError(t, err)

			// Collect the set of nodes that participate in the ACL
			// (have non-null captures).
			routerNodes := make(map[string]bool)

			for nodeName, capture := range tf.Captures {
				if len(capture.PacketFilterRules) > 0 {
					routerNodes[nodeName] = true
				}
			}

			for _, nonRouterName := range nodesWithoutRoutes {
				nonRouter := findNodeByGivenName(
					nodes, nonRouterName,
				)
				if nonRouter == nil {
					continue
				}

				matchers, err := pm.MatchersForNode(
					nonRouter.View(),
				)
				require.NoError(t, err)

				for routerName := range routerNodes {
					router := findNodeByGivenName(
						nodes, routerName,
					)
					require.NotNil(t, router)

					canAccess := nonRouter.View().CanAccess(
						matchers, router.View(),
					) || router.View().CanAccess(
						matchers, nonRouter.View(),
					)

					assert.Falsef(t, canAccess,
						"%s: non-router node %s should NOT "+
							"be a peer of subnet router %s "+
							"via subnet-to-subnet ACL alone",
						tf.TestID, nonRouterName, routerName,
					)
				}
			}
		})
	}
}

// prefixStrings converts a slice of netip.Prefix to sorted strings for
// readable comparison in test assertions.
func prefixStrings(pfxs []netip.Prefix) []string {
	out := make([]string, len(pfxs))
	for i, p := range pfxs {
		out[i] = p.String()
	}

	sort.Strings(out)

	return out
}

// TestRoutesCompatPeerAllowedIPs validates that headscale computes the same
// peer AllowedIPs as Tailscale SaaS. For each golden file that contains
// netmap captures, the test compares the AllowedIPs that SaaS delivered
// for each peer against what headscale's ReduceRoutes (the core of
// RoutesForPeer) would produce.
//
// This is the authoritative proof that approved exit routes (0.0.0.0/0,
// ::/0) belong in peer AllowedIPs: the ea-series captures from SaaS show
// exit routes in every peer's AllowedIPs when they are approved, and
// absent when they are not (b9 series).
func TestRoutesCompatPeerAllowedIPs(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "routes_results", "routes-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files)

	// Count how many files actually had netmap data to test.
	testedFiles := 0

	for _, file := range files {
		tf := loadRoutesTestFile(t, file)

		// Only test files that have netmap captures with peers.
		hasNetmap := false

		for _, capture := range tf.Captures {
			if capture.Netmap != nil && len(capture.Netmap.Peers) > 0 {
				hasNetmap = true

				break
			}
		}

		if !hasNetmap {
			continue
		}

		testedFiles++

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// SaaS rejected this policy — verify headscale also rejects it.
			if tf.Error {
				testRoutesError(t, tf)

				return
			}

			users, nodes := buildRoutesUsersAndNodes(t, tf.Topology)
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			pm, err := NewPolicyManager(policyJSON, users, nodes.ViewSlice())
			require.NoError(t, err, "%s: failed to create policy manager", tf.TestID)

			for viewerName, capture := range tf.Captures {
				if capture.Netmap == nil || len(capture.Netmap.Peers) == 0 {
					continue
				}

				viewer := findNodeByGivenName(nodes, viewerName)
				if viewer == nil {
					continue
				}

				t.Run(viewerName, func(t *testing.T) {
					matchers, err := pm.MatchersForNode(viewer.View())
					require.NoError(t, err)

					for _, nmPeer := range capture.Netmap.Peers {
						// Extract the short name from the FQDN.
						peerName := strings.Split(nmPeer.Name(), ".")[0]

						peer := findNodeByGivenName(nodes, peerName)
						if peer == nil {
							continue
						}

						// Compute what headscale would put in AllowedIPs.
						//
						// The SaaS netmap PrimaryRoutes tells us which
						// subnet routes won HA election. Exit routes
						// (0.0.0.0/0, ::/0) are never in PrimaryRoutes
						// but DO appear in AllowedIPs when approved.
						// This mirrors RoutesForPeer: primaryRoutes + exitRoutes
						// filtered through ReduceRoutes.
						peerPrimaries := nmPeer.PrimaryRoutes().AsSlice()
						exitRoutes := peer.ExitRoutes()
						allRoutes := slices.Concat(peerPrimaries, exitRoutes)

						var reducedRoutes []netip.Prefix

						for _, route := range allRoutes {
							if viewer.View().CanAccessRoute(matchers, route) {
								reducedRoutes = append(reducedRoutes, route)
							}
						}

						gotAllowedIPs := slices.Concat(
							peer.View().Prefixes(), reducedRoutes,
						)
						slices.SortFunc(gotAllowedIPs, netip.Prefix.Compare)

						wantAllowedIPs := nmPeer.AllowedIPs().AsSlice()
						slices.SortFunc(wantAllowedIPs, netip.Prefix.Compare)

						assert.Equalf(t,
							prefixStrings(wantAllowedIPs),
							prefixStrings(gotAllowedIPs),
							"%s/%s: peer %s AllowedIPs mismatch",
							tf.TestID, viewerName, peerName,
						)
					}
				})
			}
		})
	}

	require.Positive(t, testedFiles,
		"no golden files with netmap data found — test is vacuous",
	)
}

// testRoutesError verifies that an invalid policy produces the expected error.
func testRoutesError(t *testing.T, tf *testcapture.Capture) {
	t.Helper()

	policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

	pol, err := unmarshalPolicy(policyJSON)
	if err != nil {
		// Parse-time error.
		if tf.Input.APIResponseBody != nil {
			wantMsg := tf.Input.APIResponseBody.Message
			if wantMsg != "" {
				assertRoutesErrorContains(t, err, wantMsg, tf.TestID)
			}
		}

		return
	}

	err = pol.validate()
	if err != nil {
		if tf.Input.APIResponseBody != nil {
			wantMsg := tf.Input.APIResponseBody.Message
			if wantMsg != "" {
				assertRoutesErrorContains(t, err, wantMsg, tf.TestID)
			}
		}

		return
	}

	t.Errorf(
		"%s: expected error but policy parsed and validated successfully",
		tf.TestID,
	)
}

// assertRoutesErrorContains requires that headscale's error contains
// the Tailscale SaaS error message exactly. Divergence means an
// emitter needs to be aligned, not papered over with a translation
// table.
func assertRoutesErrorContains(
	t *testing.T,
	err error,
	wantMsg string,
	testID string,
) {
	t.Helper()

	errStr := err.Error()
	if strings.Contains(errStr, wantMsg) {
		return
	}

	t.Errorf(
		"%s: error message mismatch\n"+
			"  want (tailscale): %q\n"+
			"  got  (headscale): %q",
		testID,
		wantMsg,
		errStr,
	)
}
