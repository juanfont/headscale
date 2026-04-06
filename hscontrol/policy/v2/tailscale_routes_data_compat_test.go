// This file implements a data-driven test runner for routes compatibility tests.
// It loads JSON golden files from testdata/routes_results/ROUTES-*.json and
// compares headscale's route-aware ACL engine output against the expected
// packet filter rules.
//
// Each JSON file contains:
//   - A full policy (groups, tagOwners, hosts, acls)
//   - A topology section with nodes, including routable_ips and approved_routes
//   - Expected packet_filter_rules per node
//
// Test data source: testdata/routes_results/ROUTES-*.json
// Original source: Tailscale SaaS captures + headscale-generated expansions

package v2

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
	"gorm.io/gorm"
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

	// Build nodes
	nodes := make(types.Nodes, 0, len(topo.Nodes))

	for _, nodeDef := range topo.Nodes {
		node := &types.Node{
			ID:        types.NodeID(nodeDef.ID), //nolint:gosec
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
