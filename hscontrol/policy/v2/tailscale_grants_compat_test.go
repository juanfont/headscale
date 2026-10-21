// This file implements a data-driven test runner for grant compatibility
// tests. It loads HuJSON golden files from testdata/grant_results/grant-*.hujson
// and via-grant-*.hujson, captured from a Tailscale-hosted control plane, and compares
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
	"tailscale.com/tailcfg"
)

// setupGrantsCompatUsers returns the 3 test users for grants compatibility tests.
// Users get norse-god names; nodes get original-151 pokémon names — matching
// the anonymized identifiers the capture tool writes into the capture files
// .
func setupGrantsCompatUsers() types.Users {
	return types.Users{
		{ID: 1, Name: "odin", Email: "odin@example.com"},
		{ID: 2, Name: "thor", Email: "thor@example.org"},
		{ID: 3, Name: "freya", Email: "freya@example.com"},
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

// buildGrantsNodesFromCapture constructs types.Nodes from a capture's
// topology section. Each scenario in the capture tool uses clean-slate mode, so
// node IPs differ between scenarios; this builds the node set with
// the IPs that were actually present during that capture.
func buildGrantsNodesFromCapture(
	users types.Users,
	tf *testcapture.Capture,
) types.Nodes {
	nodes := make(types.Nodes, 0, len(tf.Topology.Nodes))
	autoID := 1

	for _, nodeDef := range tf.Topology.Nodes {
		node := &types.Node{
			ID:        types.NodeID(autoID), //nolint:gosec
			Hostname:  nodeDef.Hostname,
			GivenName: nodeDef.Hostname,
			IPv4:      ptrAddr(nodeDef.IPv4),
			IPv6:      ptrAddr(nodeDef.IPv6),
			Tags:      nodeDef.Tags,
		}
		autoID++

		hostinfo := &tailcfg.Hostinfo{}

		if len(nodeDef.RoutableIPs) > 0 {
			routableIPs := make([]netip.Prefix, 0, len(nodeDef.RoutableIPs))
			for _, r := range nodeDef.RoutableIPs {
				routableIPs = append(routableIPs, netip.MustParsePrefix(r))
			}

			hostinfo.RoutableIPs = routableIPs
		}

		node.Hostinfo = hostinfo

		if len(nodeDef.ApprovedRoutes) > 0 {
			approved := make([]netip.Prefix, 0, len(nodeDef.ApprovedRoutes))
			for _, r := range nodeDef.ApprovedRoutes {
				approved = append(approved, netip.MustParsePrefix(r))
			}

			node.ApprovedRoutes = approved
		} else {
			node.ApprovedRoutes = []netip.Prefix{}
		}

		// Assign user — untagged nodes look up by User field.
		if len(nodeDef.Tags) == 0 && nodeDef.User != "" {
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

	return nodes
}

// convertPolicyUserEmails used to map SaaS-side emails to @example.com.
// captures anonymize the policy JSON at write time (kratail2tid -> odin,
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

	// SaaS lists contiguous source addresses one by one and writes
	// autogroup:internet as address ranges; headscale merges sources into
	// ranges and writes the internet as prefixes. The address sets match;
	// TestViaGrantMapCompat compares these captures' filters by address.
	"via-grant-v52": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v53": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v54": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v55": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v56": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v57": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v58": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v59": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v60": "FILTER_ADDRESS_FORM: same addresses, different wire form and rule order",
	"via-grant-v61": "FILTER_ADDRESS_FORM: same addresses, different wire form",
	"via-grant-v62": "FILTER_ADDRESS_FORM: same addresses, different wire form",

	// Checks keyed <test_id>/<node>/filter: a listed check that matches
	// fails, so a fix must delete its entry. Contiguous pinned addresses;
	// TestViaGrantHACompat compares these filters by address.
	"via-grant-v64/client-a/filter":  srcAddressForm,
	"via-grant-v64/client-b/filter":  srcAddressForm,
	"via-grant-v64/plain/filter":     srcAddressForm,
	"via-grant-v64/srv/filter":       srcAddressForm,
	"via-grant-v64/via-empty/filter": srcAddressForm,
	"via-grant-v64/via-r/filter":     srcAddressForm,
	"via-grant-v65/client-a/filter":  srcAddressForm,
	"via-grant-v65/client-b/filter":  srcAddressForm,
	"via-grant-v65/plain/filter":     srcAddressForm,
	"via-grant-v65/srv/filter":       srcAddressForm,
	"via-grant-v65/via-empty/filter": srcAddressForm,
	"via-grant-v65/via-r/filter":     srcAddressForm,
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
// The test converts Tailscale user email formats to headscale format
// (@example.com, @example.org) and runs the policy through unmarshalPolicy,
// validate, compileFilterRulesForNode, and ReduceFilterRules.
//
// Scenarios in grantSkipReasons are skipped.
func TestGrantsCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "grant_results", "*-*.hujson"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no grant test files found in testdata/grant_results/")

	t.Logf("Loaded %d grant test files", len(files))

	users := setupGrantsCompatUsers()

	for _, file := range files {
		tf := loadGrantTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Check if this test is in the skip list
			if reason, ok := grantSkipReasons[tf.TestID]; ok {
				t.Skipf("TODO: %s — see grantSkipReasons comments for details", reason)
				return
			}

			// Build nodes per-scenario from this file's topology.
			// the capture tool uses clean-slate mode, so each scenario has
			// different node IPs.
			nodes := buildGrantsNodesFromCapture(users, tf)

			// Use the captured full policy as is (anonymization
			// the capture tool already rewrote SaaS emails).
			policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

			if tf.Input.APIResponseCode == 400 || tf.Error {
				testCompatRefusal(t, grantSkipReasons, tf)
				return
			}

			testGrantSuccess(t, policyJSON, tf, users, nodes)
		})
	}
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

	// The manager adds the global merge and its caches on top of the
	// per-node compile; nodes get their filter from it.
	pm, err := NewPolicyManager(policyJSON, users, nodes.ViewSlice())
	require.NoError(t, err, "%s: policy manager should load the policy", tf.TestID)

	// EquateEmpty treats nil and empty slices as equal since Tailscale's
	// JSON null -> nil, headscale may return empty slice.
	opts := append(cmpOptions(), cmpopts.EquateEmpty())

	for nodeName, capture := range tf.Captures {
		t.Run(nodeName, func(t *testing.T) {
			node := findGrantsNode(nodes, nodeName)
			require.NotNilf(t, node,
				"golden node %s not found in test setup", nodeName)

			wantRules := capture.PacketFilterRules

			compatCheck(t, grantSkipReasons, tf.TestID+"/"+nodeName+"/filter", func() string {
				gotRules := policyutil.ReduceFilterRules(
					node.View(),
					pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice()),
				)

				pmRules, err := pm.FilterForNode(node.View())
				if err != nil {
					return err.Error()
				}

				var diffs []string

				if diff := cmp.Diff(wantRules, gotRules, opts...); diff != "" {
					diffs = append(diffs, "filter rules mismatch (-tailscale +headscale):\n"+diff)
				}

				if diff := cmp.Diff(wantRules, pmRules, opts...); diff != "" {
					diffs = append(diffs, "policy manager filter rules mismatch (-tailscale +headscale):\n"+diff)
				}

				return strings.Join(diffs, "\n")
			})
		})
	}
}
