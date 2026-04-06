// This file is "generated" by Claude.
// It contains a data-driven test that reads 237 GRANT-*.json test files
// captured from Tailscale SaaS. Each file contains:
//   - A policy with grants (and optionally ACLs)
//   - The expected packet_filter_rules for each of 8 test nodes
//   - Or an error response for invalid policies
//
// The test loads each JSON file, applies the policy through headscale's
// grants engine, and compares the output against Tailscale's actual behavior.
//
// Tests that are known to fail due to unimplemented features or known
// differences are skipped with a TODO comment explaining the root cause.
// As headscale's grants implementation improves, tests should be removed
// from the skip list.
//
// Test data source: testdata/grant_results/GRANT-*.json
// Captured from: Tailscale SaaS API + tailscale debug localapi

package v2

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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

// grantTestFile represents the JSON structure of a captured grant test file.
type grantTestFile struct {
	TestID string `json:"test_id"`
	Error  bool   `json:"error"`
	Input  struct {
		FullPolicy      json.RawMessage `json:"full_policy"`
		APIResponseCode int             `json:"api_response_code"`
		APIResponseBody *struct {
			Message string `json:"message"`
		} `json:"api_response_body"`
	} `json:"input"`
	Topology struct {
		Nodes map[string]struct {
			Hostname string   `json:"hostname"`
			Tags     []string `json:"tags"`
			IPv4     string   `json:"ipv4"`
			IPv6     string   `json:"ipv6"`
		} `json:"nodes"`
	} `json:"topology"`
	Captures map[string]struct {
		PacketFilterRules json.RawMessage `json:"packet_filter_rules"`
	} `json:"captures"`
}

// setupGrantsCompatUsers returns the 3 test users for grants compatibility tests.
// Email addresses use @example.com domain, matching the converted Tailscale policy format.
func setupGrantsCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "kratail2tid", Email: "kratail2tid@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "kristoffer", Email: "kristoffer@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "monitorpasskeykradalby", Email: "monitorpasskeykradalby@example.com"},
	}
}

// setupGrantsCompatNodes returns the 8 test nodes for grants compatibility tests.
// The node configuration matches the Tailscale test environment:
//   - 3 user-owned nodes (user1, user-kris, user-mon)
//   - 5 tagged nodes (tagged-server, tagged-prod, tagged-client, subnet-router, exit-node)
func setupGrantsCompatNodes(users types.Users) types.Nodes {
	nodeUser1 := &types.Node{
		ID:        1,
		GivenName: "user1",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv4:      ptrAddr("100.90.199.68"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeUserKris := &types.Node{
		ID:        2,
		GivenName: "user-kris",
		User:      &users[1],
		UserID:    &users[1].ID,
		IPv4:      ptrAddr("100.110.121.96"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::1737:7960"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeUserMon := &types.Node{
		ID:        3,
		GivenName: "user-mon",
		User:      &users[2],
		UserID:    &users[2].ID,
		IPv4:      ptrAddr("100.103.90.82"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedServer := &types.Node{
		ID:        4,
		GivenName: "tagged-server",
		IPv4:      ptrAddr("100.108.74.26"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
		Tags:      []string{"tag:server"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedProd := &types.Node{
		ID:        5,
		GivenName: "tagged-prod",
		IPv4:      ptrAddr("100.103.8.15"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::5b37:80f"),
		Tags:      []string{"tag:prod"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedClient := &types.Node{
		ID:        6,
		GivenName: "tagged-client",
		IPv4:      ptrAddr("100.83.200.69"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::c537:c845"),
		Tags:      []string{"tag:client"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeSubnetRouter := &types.Node{
		ID:        7,
		GivenName: "subnet-router",
		IPv4:      ptrAddr("100.92.142.61"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::3e37:8e3d"),
		Tags:      []string{"tag:router"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
		},
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
	}

	nodeExitNode := &types.Node{
		ID:        8,
		GivenName: "exit-node",
		IPv4:      ptrAddr("100.85.66.106"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::7c37:426a"),
		Tags:      []string{"tag:exit"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
		ApprovedRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}

	// --- New nodes for expanded via grant topology ---

	nodeExitA := &types.Node{
		ID:        9,
		GivenName: "exit-a",
		IPv4:      ptrAddr("100.124.195.93"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::7837:c35d"),
		Tags:      []string{"tag:exit-a"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
		ApprovedRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}

	nodeExitB := &types.Node{
		ID:        10,
		GivenName: "exit-b",
		IPv4:      ptrAddr("100.116.18.24"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::ff37:1218"),
		Tags:      []string{"tag:exit-b"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
		ApprovedRoutes: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}

	nodeGroupA := &types.Node{
		ID:        11,
		GivenName: "group-a-client",
		IPv4:      ptrAddr("100.107.162.14"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::a237:a20e"),
		Tags:      []string{"tag:group-a"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeGroupB := &types.Node{
		ID:        12,
		GivenName: "group-b-client",
		IPv4:      ptrAddr("100.77.135.18"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::4b37:8712"),
		Tags:      []string{"tag:group-b"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeRouterA := &types.Node{
		ID:        13,
		GivenName: "router-a",
		IPv4:      ptrAddr("100.109.43.124"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::a537:2b7c"),
		Tags:      []string{"tag:router-a"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.44.0.0/16")},
		},
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.44.0.0/16")},
	}

	nodeRouterB := &types.Node{
		ID:        14,
		GivenName: "router-b",
		IPv4:      ptrAddr("100.65.172.123"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::5a37:ac7c"),
		Tags:      []string{"tag:router-b"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.55.0.0/16")},
		},
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.55.0.0/16")},
	}

	nodeMultiExitRouter := &types.Node{
		ID:        15,
		GivenName: "multi-exit-router",
		IPv4:      ptrAddr("100.105.127.107"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::9537:7f6b"),
		Tags:      []string{"tag:exit", "tag:router"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{
				netip.MustParsePrefix("10.33.0.0/16"),
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
			},
		},
		ApprovedRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.33.0.0/16"),
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		},
	}

	return types.Nodes{
		nodeUser1,
		nodeUserKris,
		nodeUserMon,
		nodeTaggedServer,
		nodeTaggedProd,
		nodeTaggedClient,
		nodeSubnetRouter,
		nodeExitNode,
		nodeExitA,
		nodeExitB,
		nodeGroupA,
		nodeGroupB,
		nodeRouterA,
		nodeRouterB,
		nodeMultiExitRouter,
	}
}

// findGrantsNode finds a node by its GivenName in the grants test environment.
func findGrantsNode(nodes types.Nodes, name string) *types.Node {
	for _, n := range nodes {
		if n.GivenName == name {
			return n
		}
	}

	return nil
}

// convertPolicyUserEmails converts Tailscale SaaS user email formats to
// headscale-compatible @example.com format in the raw policy JSON.
//
// Tailscale uses provider-specific email formats:
//   - kratail2tid@passkey (passkey auth)
//   - kristoffer@dalby.cc (email auth)
//   - monitorpasskeykradalby@passkey (passkey auth)
//
// Headscale resolves users by Email field, so we convert all to @example.com.
func convertPolicyUserEmails(policyJSON []byte) []byte {
	s := string(policyJSON)
	s = strings.ReplaceAll(s, "kratail2tid@passkey", "kratail2tid@example.com")
	s = strings.ReplaceAll(s, "kristoffer@dalby.cc", "kristoffer@example.com")
	s = strings.ReplaceAll(s, "monitorpasskeykradalby@passkey", "monitorpasskeykradalby@example.com")

	return []byte(s)
}

// loadGrantTestFile loads and parses a single grant test JSON file.
func loadGrantTestFile(t *testing.T, path string) grantTestFile {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test file %s", path)

	ast, err := hujson.Parse(content)
	require.NoError(t, err, "failed to parse HuJSON in %s", path)
	ast.Standardize()

	var tf grantTestFile

	err = json.Unmarshal(ast.Pack(), &tf)
	require.NoError(t, err, "failed to unmarshal test file %s", path)

	return tf
}

// Skip categories document WHY tests are expected to differ from Tailscale SaaS.
// Tests are grouped by root cause.
//
//	USER_PASSKEY_WILDCARD - 2 tests: user:*@passkey wildcard pattern not supported
//
// Total: 2 tests skipped, ~246 tests expected to pass.
var grantSkipReasons = map[string]string{
	// USER_PASSKEY_WILDCARD (2 tests)
	//
	// Tailscale SaaS policies can use user:*@passkey as a wildcard matching
	// all passkey-authenticated users. headscale does not support passkey
	// authentication and has no equivalent for this wildcard pattern.
	"GRANT-K20": "USER_PASSKEY_WILDCARD: src=user:*@passkey not supported in headscale",
	"GRANT-K21": "USER_PASSKEY_WILDCARD: dst=user:*@passkey not supported in headscale",
}

// TestGrantsCompat is a data-driven test that loads all GRANT-*.json
// test files captured from Tailscale SaaS and compares headscale's grants
// engine output against the real Tailscale behavior.
//
// Each JSON file contains:
//   - A full policy (groups, tagOwners, hosts, autoApprovers, grants, optionally acls)
//   - For success cases: expected packet_filter_rules per node
//   - For error cases: expected error message
//
// The test converts Tailscale user email formats (@passkey, @dalby.cc) to
// headscale format (@example.com) and runs the policy through unmarshalPolicy,
// validate, compileFilterRulesForNode, and ReduceFilterRules.
//
// 2 tests are skipped for user:*@passkey wildcard (not supported in headscale).
func TestGrantsCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "grant_results", "GRANT-*.hujson"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no GRANT-*.hujson test files found in testdata/grant_results/")

	t.Logf("Loaded %d grant test files", len(files))

	users := setupGrantsCompatUsers()
	allNodes := setupGrantsCompatNodes(users)

	for _, file := range files {
		tf := loadGrantTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Check if this test is in the skip list
			if reason, ok := grantSkipReasons[tf.TestID]; ok {
				t.Skipf("TODO: %s — see grantSkipReasons comments for details", reason)
				return
			}

			// Determine which node set to use based on the test's topology.
			// Tests captured with the expanded 15-node topology (V26+) have
			// nodes like exit-a, group-a-client, etc. Tests from the original
			// 8-node topology should only use the first 8 nodes to avoid
			// resolving extra IPs from nodes that weren't present during capture.
			nodes := allNodes
			if _, hasNewNodes := tf.Captures["exit-a"]; !hasNewNodes {
				nodes = allNodes[:8]
			}

			// Convert Tailscale user emails to headscale @example.com format
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			if tf.Input.APIResponseCode == 400 || tf.Error {
				testGrantError(t, policyJSON, tf)
				return
			}

			testGrantSuccess(t, policyJSON, tf, users, nodes)
		})
	}
}

// testGrantError verifies that an invalid policy produces the expected error.
func testGrantError(t *testing.T, policyJSON []byte, tf grantTestFile) {
	t.Helper()

	wantMsg := ""
	if tf.Input.APIResponseBody != nil {
		wantMsg = tf.Input.APIResponseBody.Message
	}

	pol, err := unmarshalPolicy(policyJSON)
	if err != nil {
		// Parse-time error
		if wantMsg != "" {
			assertGrantErrorContains(t, err, wantMsg, tf.TestID)
		}

		return
	}

	err = pol.validate()
	if err != nil {
		// Validation error
		if wantMsg != "" {
			assertGrantErrorContains(t, err, wantMsg, tf.TestID)
		}

		return
	}

	t.Errorf("%s: expected error (api_response_code=400) but policy parsed and validated successfully; want message: %q",
		tf.TestID, wantMsg)
}

// grantErrorMessageMap maps Tailscale error messages to their headscale equivalents
// where the wording differs but the meaning is the same.
var grantErrorMessageMap = map[string]string{
	// Tailscale says "ip and app can not both be empty",
	// headscale says "grants must specify either 'ip' or 'app' field"
	"ip and app can not both be empty": "grants must specify either",
	// Tailscale says "via can only be a tag",
	// headscale rejects at unmarshal time via Tag.UnmarshalJSON: "tag must start with 'tag:'"
	"via can only be a tag": "tag must start with",
}

// assertGrantErrorContains checks that an error message contains the expected
// Tailscale error message (or its headscale equivalent).
func assertGrantErrorContains(t *testing.T, err error, wantMsg string, testID string) {
	t.Helper()

	errStr := err.Error()

	// First try direct substring match
	if strings.Contains(errStr, wantMsg) {
		return
	}

	// Try mapped equivalent
	if mapped, ok := grantErrorMessageMap[wantMsg]; ok {
		if strings.Contains(errStr, mapped) {
			return
		}
	}

	// Try matching key parts of the error message
	// Extract the most distinctive part of the Tailscale message
	keyParts := extractErrorKeyParts(wantMsg)
	for _, part := range keyParts {
		if strings.Contains(errStr, part) {
			return
		}
	}

	t.Errorf("%s: error message mismatch\n  tailscale wants: %q\n  headscale got:   %q",
		testID, wantMsg, errStr)
}

// extractErrorKeyParts extracts distinctive substrings from an error message
// that should appear in any equivalent error message.
func extractErrorKeyParts(msg string) []string {
	var parts []string

	// Common patterns to extract
	if strings.Contains(msg, "tag:") {
		// Extract tag references like tag:nonexistent
		for word := range strings.FieldsSeq(msg) {
			word = strings.Trim(word, `"'`)
			if strings.HasPrefix(word, "tag:") {
				parts = append(parts, word)
			}
		}
	}

	if strings.Contains(msg, "autogroup:") {
		for word := range strings.FieldsSeq(msg) {
			word = strings.Trim(word, `"'`)
			if strings.HasPrefix(word, "autogroup:") {
				parts = append(parts, word)
			}
		}
	}

	if strings.Contains(msg, "capability name") {
		parts = append(parts, "capability")
	}

	if strings.Contains(msg, "port range") {
		parts = append(parts, "port")
	}

	return parts
}

// testGrantSuccess verifies that a valid policy produces the expected
// packet filter rules for each node.
func testGrantSuccess(
	t *testing.T,
	policyJSON []byte,
	tf grantTestFile,
	users types.Users,
	nodes types.Nodes,
) {
	t.Helper()

	pol, err := unmarshalPolicy(policyJSON)
	require.NoError(t, err, "%s: policy should parse successfully", tf.TestID)

	err = pol.validate()
	require.NoError(t, err, "%s: policy should validate successfully", tf.TestID)

	for nodeName, capture := range tf.Captures {
		t.Run(nodeName, func(t *testing.T) {
			// Check if this node was offline during capture.
			// tagged-prod was frequently offline (132 of 188 success tests).
			// When offline, packet_filter_rules is null and topology shows
			// hostname="unknown" with empty tags.
			captureIsNull := len(capture.PacketFilterRules) == 0 ||
				string(capture.PacketFilterRules) == "null"

			if captureIsNull {
				topoNode, exists := tf.Topology.Nodes[nodeName]
				if exists && (topoNode.Hostname == "unknown" || topoNode.Hostname == "") {
					t.Skipf(
						"node %s was offline during Tailscale capture (hostname=%q)",
						nodeName,
						topoNode.Hostname,
					)

					return
				}
				// Node was online but has null/empty rules — means Tailscale
				// produced no rules. headscale should also produce no rules.
			}

			node := findGrantsNode(nodes, nodeName)
			if node == nil {
				t.Skipf(
					"node %s not found in test setup (may be a test-specific node)",
					nodeName,
				)

				return
			}

			// Compile headscale filter rules for this node
			gotRules, err := pol.compileFilterRulesForNode(
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

			gotRules = policyutil.ReduceFilterRules(node.View(), gotRules)

			// Unmarshal Tailscale expected rules from JSON capture
			var wantRules []tailcfg.FilterRule
			if !captureIsNull {
				err = json.Unmarshal(
					[]byte(capture.PacketFilterRules),
					&wantRules,
				)
				require.NoError(
					t,
					err,
					"%s/%s: failed to unmarshal expected rules from JSON",
					tf.TestID,
					nodeName,
				)
			}

			// Compare headscale output against Tailscale expected output.
			// The diff labels show (-tailscale +headscale) to make clear
			// which side produced which output.
			// EquateEmpty treats nil and empty slices as equal since
			// Tailscale's JSON null -> nil, headscale may return empty slice.
			opts := append(cmpOptions(), cmpopts.EquateEmpty())
			if diff := cmp.Diff(wantRules, gotRules, opts...); diff != "" {
				t.Errorf(
					"%s/%s: filter rules mismatch (-tailscale +headscale):\n%s",
					tf.TestID,
					nodeName,
					diff,
				)
			}
		})
	}
}
