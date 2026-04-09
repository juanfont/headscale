// This file implements a data-driven test runner for grant compatibility
// tests. It loads HuJSON golden files from testdata/grant_results/grant-*.hujson
// and via-grant-*.hujson, captured from Tailscale SaaS by tscap, and compares
// headscale's grants engine output against the captured packet filter rules.
//
// Each file is a testcapture.Capture containing:
//   - A full policy with grants (and optionally ACLs)
//   - The expected packet_filter_rules for each of 8-15 test nodes
//   - Or an error response for invalid policies
//
// Tests known to fail due to unimplemented features or known differences are
// skipped with a TODO comment explaining the root cause. As headscale's grants
// implementation improves, tests should be removed from the skip list.
//
// Test data source: testdata/grant_results/{grant,via-grant}-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)


// setupGrantsCompatUsers returns the 3 test users for grants compatibility tests.
// Users get norse-god names; nodes get original-151 pokémon names — matching
// the anonymized identifiers tscap writes into the capture files
// (see github.com/kradalby/tscap/anonymize).
func setupGrantsCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "odin", Email: "odin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "thor", Email: "thor@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "freya", Email: "freya@example.com"},
	}
}

// setupGrantsCompatNodes returns the 15 test nodes for grants compatibility tests.
// The node configuration matches the Tailscale test environment:
//   - 3 user-owned nodes (bulbasaur, ivysaur, venusaur)
//   - 12 tagged nodes (beedrill, kakuna, weedle, squirtle, charmander,
//     pidgey, pidgeotto, rattata, raticate, spearow, fearow, blastoise)
func setupGrantsCompatNodes(users types.Users) types.Nodes {
	nodeBulbasaur := &types.Node{
		ID:        1,
		GivenName: "bulbasaur",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv4:      ptrAddr("100.90.199.68"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeIvysaur := &types.Node{
		ID:        2,
		GivenName: "ivysaur",
		User:      &users[1],
		UserID:    &users[1].ID,
		IPv4:      ptrAddr("100.110.121.96"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::1737:7960"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeVenusaur := &types.Node{
		ID:        3,
		GivenName: "venusaur",
		User:      &users[2],
		UserID:    &users[2].ID,
		IPv4:      ptrAddr("100.103.90.82"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeBeedrill := &types.Node{
		ID:        4,
		GivenName: "beedrill",
		IPv4:      ptrAddr("100.108.74.26"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
		Tags:      []string{"tag:server"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeKakuna := &types.Node{
		ID:        5,
		GivenName: "kakuna",
		IPv4:      ptrAddr("100.103.8.15"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::5b37:80f"),
		Tags:      []string{"tag:prod"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeWeedle := &types.Node{
		ID:        6,
		GivenName: "weedle",
		IPv4:      ptrAddr("100.83.200.69"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::c537:c845"),
		Tags:      []string{"tag:client"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeSquirtle := &types.Node{
		ID:        7,
		GivenName: "squirtle",
		IPv4:      ptrAddr("100.92.142.61"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::3e37:8e3d"),
		Tags:      []string{"tag:router"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
		},
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
	}

	nodeCharmander := &types.Node{
		ID:        8,
		GivenName: "charmander",
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

	nodePidgey := &types.Node{
		ID:        9,
		GivenName: "pidgey",
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

	nodePidgeotto := &types.Node{
		ID:        10,
		GivenName: "pidgeotto",
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

	nodeRattata := &types.Node{
		ID:        11,
		GivenName: "rattata",
		IPv4:      ptrAddr("100.107.162.14"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::a237:a20e"),
		Tags:      []string{"tag:group-a"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeRaticate := &types.Node{
		ID:        12,
		GivenName: "raticate",
		IPv4:      ptrAddr("100.77.135.18"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::4b37:8712"),
		Tags:      []string{"tag:group-b"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeSpearow := &types.Node{
		ID:        13,
		GivenName: "spearow",
		IPv4:      ptrAddr("100.109.43.124"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::a537:2b7c"),
		Tags:      []string{"tag:router-a"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.44.0.0/16")},
		},
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.44.0.0/16")},
	}

	nodeFearow := &types.Node{
		ID:        14,
		GivenName: "fearow",
		IPv4:      ptrAddr("100.65.172.123"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::5a37:ac7c"),
		Tags:      []string{"tag:router-b"},
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.55.0.0/16")},
		},
		ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.55.0.0/16")},
	}

	nodeBlastoise := &types.Node{
		ID:        15,
		GivenName: "blastoise",
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
		nodeBulbasaur,
		nodeIvysaur,
		nodeVenusaur,
		nodeBeedrill,
		nodeKakuna,
		nodeWeedle,
		nodeSquirtle,
		nodeCharmander,
		nodePidgey,
		nodePidgeotto,
		nodeRattata,
		nodeRaticate,
		nodeSpearow,
		nodeFearow,
		nodeBlastoise,
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

// convertPolicyUserEmails used to map SaaS-side emails to @example.com.
// tscap now anonymizes the policy JSON at write time (kratail2tid -> odin,
// kristoffer -> thor, monitorpasskeykradalby -> freya), so the captured
// FullPolicy is already in its final form and this is a passthrough that
// just adapts the captured string value to the []byte that the policy
// parser expects.
func convertPolicyUserEmails(policyJSON string) []byte {
	return []byte(policyJSON)
}

// loadGrantTestFile loads and parses a single grant capture HuJSON file.
func loadGrantTestFile(t *testing.T, path string) *testcapture.Capture {
	t.Helper()

	c, err := testcapture.Read(path)
	require.NoError(t, err, "failed to read test file %s", path)

	return c
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
	"grant-k20": "USER_PASSKEY_WILDCARD: src=user:*@passkey not supported in headscale",
	"grant-k21": "USER_PASSKEY_WILDCARD: dst=user:*@passkey not supported in headscale",
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

	files, err := filepath.Glob(filepath.Join("testdata", "grant_results", "*-*.hujson"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no grant test files found in testdata/grant_results/")

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
			// nodes like pidgey (exit-a), rattata (group-a-client), etc.
			// Tests from the original 8-node topology should only use the
			// first 8 nodes to avoid resolving extra IPs from nodes that
			// weren't present during capture.
			nodes := allNodes
			if _, hasNewNodes := tf.Captures["pidgey"]; !hasNewNodes {
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
func testGrantError(t *testing.T, policyJSON []byte, tf *testcapture.Capture) {
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
	tf *testcapture.Capture,
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
			// kakuna (tag:prod) was frequently offline (132 of 188 success tests).
			// When offline, packet_filter_rules is null and topology shows
			// hostname="unknown" with empty tags.
			if len(capture.PacketFilterRules) == 0 {
				topoNode, exists := tf.Topology.Nodes[nodeName]
				if exists && (topoNode.Hostname == "unknown" || topoNode.Hostname == "") {
					t.Skipf(
						"node %s was offline during Tailscale capture (hostname=%q)",
						nodeName,
						topoNode.Hostname,
					)

					return
				}
				// Node was online but has empty rules — means Tailscale
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

			wantRules := capture.PacketFilterRules

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
