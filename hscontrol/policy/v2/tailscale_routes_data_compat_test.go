// This file implements data-driven test runners for routes compatibility tests.
// It loads HuJSON golden files from testdata/routes_results/ROUTES-*.hujson and
// compares headscale's route-aware ACL engine output against the expected
// packet filter rules.
//
// Each HuJSON file contains:
//   - A full policy (groups, tagOwners, hosts, acls)
//   - A topology section with nodes, including routable_ips and approved_routes
//   - Expected packet_filter_rules per node
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
// Test data source: testdata/routes_results/ROUTES-*.hujson
// Original source: Tailscale SaaS captures + headscale-generated expansions

package v2

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
	"go4.org/netipx"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// routesTestFile represents the JSON structure of a captured routes test file.
type routesTestFile struct {
	TestID     string `json:"test_id"`
	Source     string `json:"source"`
	ParentTest string `json:"parent_test"`
	Input      struct {
		FullPolicy json.RawMessage `json:"full_policy"`
	} `json:"input"`
	Topology routesTopology `json:"topology"`
	Captures map[string]struct {
		PacketFilterRules json.RawMessage `json:"packet_filter_rules"`
	} `json:"captures"`
}

// routesTopology describes the node topology for a routes test.
type routesTopology struct {
	Users []struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	} `json:"users"`
	Nodes map[string]routesNodeDef `json:"nodes"`
}

// routesNodeDef describes a single node in the routes test topology.
type routesNodeDef struct {
	ID             int      `json:"id"`
	Hostname       string   `json:"hostname"`
	IPv4           string   `json:"ipv4"`
	IPv6           string   `json:"ipv6"`
	Tags           []string `json:"tags"`
	User           string   `json:"user,omitempty"`
	RoutableIPs    []string `json:"routable_ips"`
	ApprovedRoutes []string `json:"approved_routes"`
}

// loadRoutesTestFile loads and parses a single routes test JSON file.
func loadRoutesTestFile(t *testing.T, path string) routesTestFile {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test file %s", path)

	ast, err := hujson.Parse(content)
	require.NoError(t, err, "failed to parse HuJSON in %s", path)
	ast.Standardize()

	var tf routesTestFile

	err = json.Unmarshal(ast.Pack(), &tf)
	require.NoError(t, err, "failed to unmarshal test file %s", path)

	return tf
}

// buildRoutesUsersAndNodes constructs types.Users and types.Nodes from the
// JSON topology definition. This allows each test file to define its own
// topology (e.g., the IPv6 tests use different nodes than the standard tests).
func buildRoutesUsersAndNodes(
	t *testing.T,
	topo routesTopology,
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
			})
		}
	} else {
		users = types.Users{
			{Model: gorm.Model{ID: 1}, Name: "kratail2tid", Email: "kratail2tid@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "kristoffer", Email: "kristoffer@example.com"},
			{Model: gorm.Model{ID: 3}, Name: "monitorpasskeykradalby", Email: "monitorpasskeykradalby@example.com"},
		}
	}

	// Build nodes.
	// Auto-assign unique IDs when the JSON topology does not provide
	// them (id defaults to 0). Unique IDs are required by ReduceNodes /
	// BuildPeerMap which skip peers by comparing node.ID.
	nodes := make(types.Nodes, 0, len(topo.Nodes))
	autoID := 1

	for _, nodeDef := range topo.Nodes {
		nodeID := nodeDef.ID
		if nodeID == 0 {
			nodeID = autoID
			autoID++
		}

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

// routesSkipReasons documents WHY tests are expected to fail.
var routesSkipReasons = map[string]string{}

// subnetToSubnetFiles lists the golden files that test subnet-to-subnet
// ACL scenarios. These are the scenarios where the fix for issue #3157
// (CanAccess considering subnet routes as source identity) is critical.
var subnetToSubnetFiles = []string{
	"ROUTES-f10_subnet_to_subnet_issue3157",
	"ROUTES-f11_subnet_to_subnet_bidirectional",
	"ROUTES-f12_subnet_to_subnet_host_aliases",
	"ROUTES-f13_subnet_to_subnet_disjoint",
	"ROUTES-f14_subnet_to_subnet_overlapping_one_router",
	"ROUTES-f15_subnet_to_subnet_cross_routers",
}

// TestRoutesCompat is a data-driven test that loads all ROUTES-*.json test
// files and compares headscale's route-aware ACL engine output against the
// expected behavior.
func TestRoutesCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "routes_results", "ROUTES-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no ROUTES-*.hujson test files found in testdata/routes_results/",
	)

	t.Logf("Loaded %d routes test files", len(files))

	for _, file := range files {
		tf := loadRoutesTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			if reason, ok := routesSkipReasons[tf.TestID]; ok {
				t.Skipf(
					"TODO: %s — see routesSkipReasons for details",
					reason,
				)

				return
			}

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
					captureIsNull := len(capture.PacketFilterRules) == 0 ||
						string(capture.PacketFilterRules) == "null" //nolint:goconst

					node := findNodeByGivenName(nodes, nodeName)
					if node == nil {
						t.Skipf(
							"node %s not found in topology",
							nodeName,
						)

						return
					}

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

					var wantRules []tailcfg.FilterRule
					if !captureIsNull {
						err = json.Unmarshal(
							capture.PacketFilterRules,
							&wantRules,
						)
						require.NoError(
							t,
							err,
							"%s/%s: failed to unmarshal expected rules",
							tf.TestID,
							nodeName,
						)
					}

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
	tf routesTestFile,
	nodes types.Nodes,
) map[[2]string]bool {
	t.Helper()

	pairs := make(map[[2]string]bool)

	for dstNodeName, capture := range tf.Captures {
		captureIsNull := len(capture.PacketFilterRules) == 0 ||
			string(capture.PacketFilterRules) == "null"
		if captureIsNull {
			continue
		}

		var rules []tailcfg.FilterRule

		err := json.Unmarshal(capture.PacketFilterRules, &rules)
		require.NoError(t, err,
			"%s/%s: failed to unmarshal capture rules",
			tf.TestID, dstNodeName,
		)

		// Build an IPSet of all SrcIPs from the capture's filter rules.
		var srcBuilder netipx.IPSetBuilder

		for _, rule := range rules {
			for _, srcIP := range rule.SrcIPs {
				prefix, err := netip.ParsePrefix(srcIP)
				if err != nil {
					// Single IP like "100.x.y.z" — try as host address.
					addr, err2 := netip.ParseAddr(srcIP)
					require.NoError(t, err2,
						"%s/%s: cannot parse SrcIP %q",
						tf.TestID, dstNodeName, srcIP,
					)

					srcBuilder.Add(addr)

					continue
				}

				srcBuilder.AddPrefix(prefix)
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
				// For each expected pair, verify that at least one
				// direction of CanAccess returns true.
				for pair := range wantPairs {
					nodeA := findNodeByGivenName(nodes, pair[0])
					nodeB := findNodeByGivenName(nodes, pair[1])
					require.NotNilf(t, nodeA,
						"node %s not found", pair[0],
					)
					require.NotNilf(t, nodeB,
						"node %s not found", pair[1],
					)

					// Get matchers — these are the unreduced global
					// matchers used for peer relationship determination.
					matchers, err := pm.MatchersForNode(nodeA.View())
					require.NoError(t, err)

					canAccess := nodeA.View().CanAccess(
						matchers, nodeB.View(),
					) || nodeB.View().CanAccess(
						matchers, nodeA.View(),
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
					captureIsNull := len(
						capture.PacketFilterRules,
					) == 0 ||
						string(
							capture.PacketFilterRules,
						) == "null"
					if captureIsNull {
						continue
					}

					var rules []tailcfg.FilterRule

					err := json.Unmarshal(
						capture.PacketFilterRules, &rules,
					)
					require.NoError(t, err)

					// Extract destination prefixes from the rules.
					var dstPrefixes []netip.Prefix

					for _, rule := range rules {
						for _, dp := range rule.DstPorts {
							prefix, err := netip.ParsePrefix(
								dp.IP,
							)
							if err != nil {
								continue
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
		filepath.Join("testdata", "routes_results", "ROUTES-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no ROUTES-*.hujson test files found in testdata/routes_results/",
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
					approvedSet[netip.MustParsePrefix(r)] = true
				}

				t.Run(nodeName, func(t *testing.T) {
					for _, routeStr := range nodeDef.RoutableIPs {
						route := netip.MustParsePrefix(routeStr)

						// Skip exit routes (0.0.0.0/0, ::/0).
						// Tailscale SaaS stores exit routes
						// under autoApprovers.routes alongside
						// regular subnets, while headscale uses
						// a separate autoApprovers.exitNode
						// field. NodeCanApproveRoute checks the
						// exitSet (from exitNode) first and
						// never reaches the autoApproveMap
						// (from routes), causing a known format
						// mismatch. This is not a bug — just a
						// structural difference in where exit
						// routes are declared.
						if tsaddr.IsExitRoute(route) {
							continue
						}

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
		filepath.Join("testdata", "routes_results", "ROUTES-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no ROUTES-*.hujson test files found in testdata/routes_results/",
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

			// For each node that receives filter rules (non-null
			// capture), extract the DstPort prefixes and SrcIPs.
			// Then verify that viewer nodes with matching source
			// identity can access those routes via CanAccessRoute.
			for dstNodeName, capture := range tf.Captures {
				captureIsNull := len(
					capture.PacketFilterRules,
				) == 0 ||
					string(
						capture.PacketFilterRules,
					) == "null"
				if captureIsNull {
					continue
				}

				var rules []tailcfg.FilterRule

				err := json.Unmarshal(
					capture.PacketFilterRules, &rules,
				)
				require.NoError(t, err,
					"%s/%s: failed to unmarshal capture rules",
					tf.TestID, dstNodeName,
				)

				// Build the set of destination route prefixes.
				var dstPrefixes []netip.Prefix

				for _, rule := range rules {
					for _, dp := range rule.DstPorts {
						prefix, parseErr := netip.ParsePrefix(
							dp.IP,
						)
						if parseErr != nil {
							continue
						}

						if !slices.Contains(
							dstPrefixes, prefix,
						) {
							dstPrefixes = append(
								dstPrefixes, prefix,
							)
						}
					}
				}

				if len(dstPrefixes) == 0 {
					continue
				}

				// Build SrcIPs set from all rules in this capture.
				var srcBuilder netipx.IPSetBuilder

				for _, rule := range rules {
					for _, srcIP := range rule.SrcIPs {
						prefix, parseErr := netip.ParsePrefix(
							srcIP,
						)
						if parseErr != nil {
							addr, parseErr2 := netip.ParseAddr(
								srcIP,
							)
							if parseErr2 != nil {
								continue
							}

							srcBuilder.Add(addr)

							continue
						}

						srcBuilder.AddPrefix(prefix)
					}
				}

				srcSet, err := srcBuilder.IPSet()
				require.NoError(t, err)

				// For each peer node, check if it should be able
				// to access the dst routes.
				for _, viewerNode := range nodes {
					if viewerNode.GivenName == dstNodeName {
						continue
					}

					// Determine if this viewer has source identity
					// that matches the capture's SrcIPs.
					viewerMatchesSrc := false

					nv := viewerNode.View()
					if slices.ContainsFunc(nv.IPs(), srcSet.Contains) {
						viewerMatchesSrc = true
					}

					if !viewerMatchesSrc {
						if slices.ContainsFunc(nv.SubnetRoutes(), srcSet.OverlapsPrefix) {
							viewerMatchesSrc = true
						}
					}

					if !viewerMatchesSrc {
						continue
					}

					matchers, matchErr := pm.MatchersForNode(nv)
					require.NoError(t, matchErr)

					t.Run(
						dstNodeName+"/from_"+viewerNode.GivenName,
						func(t *testing.T) {
							for _, route := range dstPrefixes {
								canAccess := nv.CanAccessRoute(
									matchers, route,
								)
								assert.Truef(t, canAccess,
									"%s: viewer %s (IPs=%v, "+
										"subnets=%v) should be "+
										"able to access route "+
										"%s on node %s (SaaS "+
										"delivered matching "+
										"filter rules)",
									tf.TestID,
									viewerNode.GivenName,
									nv.IPs(),
									nv.SubnetRoutes(),
									route,
									dstNodeName,
								)
							}
						},
					)
				}
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
				captureIsNull := len(capture.PacketFilterRules) == 0 ||
					string(capture.PacketFilterRules) == "null"
				if !captureIsNull {
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
