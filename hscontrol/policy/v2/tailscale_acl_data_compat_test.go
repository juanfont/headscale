// This file implements a data-driven test runner for ACL compatibility tests.
// It loads HuJSON golden files from testdata/acl_results/acl-*.hujson and
// compares headscale's ACL engine output against the expected packet filter
// rules captured from a Tailscale-hosted control plane by an external capture tool.
//
// Each file is a testcapture.Capture containing:
//   - The full policy that was POSTed to the Tailscale SaaS API
//   - The 8-node topology used for the capture run
//   - Expected packet_filter_rules per node (or error metadata for
//     scenarios that the SaaS rejected)
//
// Test data source: testdata/acl_results/acl-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"encoding/json"
	"fmt"
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

// ptrAddr is a helper to create a pointer to a netip.Addr.
func ptrAddr(s string) *netip.Addr {
	addr := netip.MustParseAddr(s)

	return &addr
}

// setupACLCompatUsers returns the 3 test users for ACL compatibility tests.
// Names and emails match the anonymized identifiers the capture tool writes into the
// capture files users get
// norse-god names and nodes get original-151 pokémon names.
func setupACLCompatUsers() types.Users {
	return types.Users{
		{ID: 1, Name: "odin", Email: "odin@example.com"},
		{ID: 2, Name: "thor", Email: "thor@example.org"},
		{ID: 3, Name: "freya", Email: "freya@example.com"},
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

// cmpOptions returns comparison options for FilterRule slices.
// It sorts SrcIPs and DstPorts to handle ordering differences.
func cmpOptions() []cmp.Option {
	return []cmp.Option{
		cmpopts.EquateComparable(netip.Prefix{}, netip.Addr{}),
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
		cmpopts.SortSlices(func(a, b netip.Prefix) bool {
			if a.Addr() != b.Addr() {
				return a.Addr().Less(b.Addr())
			}

			return a.Bits() < b.Bits()
		}),
		// Compare tailcfg.RawMessage semantically (it's a string type
		// containing JSON) to handle indentation differences. Both
		// sides must be valid JSON — golden data parse failures are
		// always errors.
		cmp.Comparer(func(a, b tailcfg.RawMessage) bool {
			var va, vb any

			err := json.Unmarshal([]byte(a), &va)
			if err != nil {
				panic(fmt.Sprintf("golden RawMessage A unparseable: %v", err))
			}

			err = json.Unmarshal([]byte(b), &vb)
			if err != nil {
				panic(fmt.Sprintf("golden RawMessage B unparseable: %v", err))
			}

			ja, _ := json.Marshal(va)
			jb, _ := json.Marshal(vb)

			return string(ja) == string(jb)
		}),
	}
}

// buildACLUsersAndNodes constructs users and nodes from an ACL
// golden file's topology. This ensures the test creates the same
// nodes that were present during the Tailscale SaaS capture.
func buildACLUsersAndNodes(
	t *testing.T,
	tf *testcapture.Capture,
) (types.Users, types.Nodes) {
	t.Helper()

	users := setupACLCompatUsers()
	nodes := make(types.Nodes, 0, len(tf.Topology.Nodes))
	autoID := 1

	for name, nodeDef := range tf.Topology.Nodes {
		node := &types.Node{
			ID:        types.NodeID(autoID), //nolint:gosec
			GivenName: name,
			IPv4:      ptrAddr(nodeDef.IPv4),
			IPv6:      ptrAddr(nodeDef.IPv6),
			Tags:      nodeDef.Tags,
		}
		autoID++

		hostinfo := &tailcfg.Hostinfo{}

		if len(nodeDef.RoutableIPs) > 0 {
			routableIPs := make(
				[]netip.Prefix, 0, len(nodeDef.RoutableIPs),
			)

			for _, r := range nodeDef.RoutableIPs {
				routableIPs = append(
					routableIPs, netip.MustParsePrefix(r),
				)
			}

			hostinfo.RoutableIPs = routableIPs
		}

		node.Hostinfo = hostinfo

		if len(nodeDef.ApprovedRoutes) > 0 {
			approved := make(
				[]netip.Prefix, 0, len(nodeDef.ApprovedRoutes),
			)

			for _, r := range nodeDef.ApprovedRoutes {
				approved = append(
					approved, netip.MustParsePrefix(r),
				)
			}

			node.ApprovedRoutes = approved
		} else {
			node.ApprovedRoutes = []netip.Prefix{}
		}

		// Assign user — untagged nodes get user1
		if len(nodeDef.Tags) == 0 {
			if nodeDef.User != "" {
				for i := range users {
					if users[i].Name == nodeDef.User {
						node.User = &users[i]
						node.UserID = &users[i].ID

						break
					}
				}
			} else {
				node.User = &users[0]
				node.UserID = &users[0].ID
			}
		}

		nodes = append(nodes, node)
	}

	return users, nodes
}

// loadACLTestFile loads and parses a single ACL capture HuJSON file.
func loadACLTestFile(t *testing.T, path string) *testcapture.Capture {
	t.Helper()

	c, err := testcapture.Read(path)
	require.NoError(t, err, "failed to read test file %s", path)

	return c
}

// aclSkipReasons lists checks where headscale differs from SaaS, keyed
// <test_id>[/<node>]/<check>.
var aclSkipReasons = map[string]string{
	"acl-err10/refused": routeHostBits,
	"acl-err11/refused": routeHostBits,

	"acl-n01/beedrill/filter":   allowAllForm,
	"acl-n01/bulbasaur/filter":  allowAllForm,
	"acl-n01/charmander/filter": allowAllForm,
	"acl-n01/ivysaur/filter":    allowAllForm,
	"acl-n01/kakuna/filter":     allowAllForm,
	"acl-n01/squirtle/filter":   allowAllForm,
	"acl-n01/venusaur/filter":   allowAllForm,
	"acl-n01/weedle/filter":     allowAllForm,

	"acl-dup-src-dst/beedrill/filter":   aclDstDedupe,
	"acl-dup-src-dst/bulbasaur/filter":  aclDstDedupe,
	"acl-dup-src-dst/charmander/filter": aclDstDedupe,
	"acl-dup-src-dst/ivysaur/filter":    aclDstDedupe,
	"acl-dup-src-dst/kakuna/filter":     aclDstDedupe,
	"acl-dup-src-dst/squirtle/filter":   aclDstDedupe,
	"acl-dup-src-dst/venusaur/filter":   aclDstDedupe,
	"acl-dup-src-dst/weedle/filter":     aclDstDedupe,
	"acl-dxp-dup-ports/beedrill/filter": aclDstDedupe,

	"acl-self-plus-dsts/kakuna/filter":    srcAddressForm,
	"acl-self-plus-dsts/beedrill/filter":  "FILTER_ADDRESS_FORM+ACL_DST_DEDUPE: sources listed one by one, a repeated destination written once",
	"acl-self-plus-dsts/bulbasaur/filter": "FILTER_ADDRESS_FORM+SELF_DST_REPEAT: sources listed one by one, the autogroup:self destination written once per source alias",
}

const (
	routeHostBits  = "ROUTE_HOST_BITS: SaaS refuses an autoApprovers route with host bits; headscale accepts it"
	allowAllForm   = "ALLOW_ALL_FORM: SaaS writes the allow-all default's sources as the tailnet ranges, headscale as \"*\""
	aclDstDedupe   = "ACL_DST_DEDUPE: SaaS writes a destination repeated within one ACL once, headscale once per mention"
	srcAddressForm = "FILTER_ADDRESS_FORM: SaaS lists contiguous source addresses one by one, headscale as a range"
)

// TestACLCompat is a data-driven test that loads all ACL-*.json test files
// and compares headscale's ACL engine output against the expected behavior.
//
// Each JSON file contains:
//   - A full policy with groups, tagOwners, hosts, and acls
//   - For success cases: expected packet_filter_rules per node (5 nodes)
//   - For error cases: expected error message
func TestACLCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "acl_results", "acl-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no acl-*.hujson test files found in testdata/acl_results/",
	)

	t.Logf("Loaded %d ACL test files", len(files))

	for _, file := range files {
		tf := loadACLTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			if tf.Error {
				testCompatRefusal(t, aclSkipReasons, tf)

				return
			}

			// Build nodes per-scenario from this file's topology.
			// the capture tool uses clean-slate mode, so each scenario has
			// different node IPs; using a shared topology would
			// cause IP mismatches in filter rule comparisons.
			users, nodes := buildACLUsersAndNodes(t, tf)
			require.NotEmpty(t, nodes, "%s: topology is empty", tf.TestID)

			testACLSuccess(t, tf, users, nodes)
		})
	}
}

// testCompatRefusal checks that headscale refuses a policy SaaS refused, with
// SaaS's message in its error; checks are keyed <test_id>/<check> in skips.
func testCompatRefusal(t *testing.T, skips map[string]string, tf *testcapture.Capture) {
	t.Helper()

	policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

	pol, err := unmarshalPolicy(policyJSON)
	if err == nil {
		err = pol.validate()
	}

	key := tf.TestID + "/"

	compatCheck(t, skips, key+"refused", func() string {
		if err == nil {
			return "SaaS refused; the policy parsed and validated"
		}

		return ""
	})

	if err == nil {
		compatChecksNotRun(t, skips, key+"message")

		return
	}

	// An emitter that differs is aligned, not papered over with a
	// translation table.
	var want string
	if tf.Input.APIResponseBody != nil {
		want = tf.Input.APIResponseBody.Message
	}

	compatCheck(t, skips, key+"message", func() string {
		if strings.Contains(err.Error(), want) {
			return ""
		}

		return fmt.Sprintf("want (tailscale): %q\ngot  (headscale): %q", want, err.Error())
	})
}

// testACLSuccess verifies that a valid policy produces the expected
// packet filter rules for each node.
func testACLSuccess(
	t *testing.T,
	tf *testcapture.Capture,
	users types.Users,
	nodes types.Nodes,
) {
	t.Helper()

	// Convert Tailscale SaaS user emails to headscale @example.com format.
	policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

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

	// The manager adds the global merge and its caches on top of the
	// per-node compile; nodes get their filter from it.
	pm, err := NewPolicyManager(policyJSON, users, nodes.ViewSlice())
	require.NoError(t, err, "%s: policy manager should load the policy", tf.TestID)

	opts := append(cmpOptions(), cmpopts.EquateEmpty())

	for nodeName, capture := range tf.Captures {
		t.Run(nodeName, func(t *testing.T) {
			node := findNodeByGivenName(nodes, nodeName)
			if node == nil {
				t.Skipf(
					"node %s not found in test setup",
					nodeName,
				)

				return
			}

			wantRules := capture.PacketFilterRules

			compatCheck(t, aclSkipReasons, tf.TestID+"/"+nodeName+"/filter", func() string {
				var diffs []string

				// Only the manager installs the allow-all default of a
				// policy with neither acls nor grants.
				if pol.ACLs != nil || pol.Grants != nil {
					gotRules := policyutil.ReduceFilterRules(
						node.View(),
						pol.compileFilterRulesForNode(users, node.View(), nodes.ViewSlice()),
					)

					if diff := cmp.Diff(wantRules, gotRules, opts...); diff != "" {
						diffs = append(diffs, "filter rules mismatch (-want +got):\n"+diff)
					}
				}

				pmRules, err := pm.FilterForNode(node.View())
				if err != nil {
					return err.Error()
				}

				if diff := cmp.Diff(wantRules, pmRules, opts...); diff != "" {
					diffs = append(diffs, "policy manager filter rules mismatch (-want +got):\n"+diff)
				}

				return strings.Join(diffs, "\n")
			})
		})
	}
}
