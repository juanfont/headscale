// This file implements a data-driven test runner for ACL compatibility tests.
// It loads HuJSON golden files from testdata/acl_results/acl-*.hujson and
// compares headscale's ACL engine output against the expected packet filter
// rules captured from Tailscale SaaS by the tscap tool.
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
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// ptrAddr is a helper to create a pointer to a netip.Addr.
func ptrAddr(s string) *netip.Addr {
	addr := netip.MustParseAddr(s)

	return &addr
}

// setupACLCompatUsers returns the 3 test users for ACL compatibility tests.
// Names and emails match the anonymized identifiers tscap writes into the
// capture files (see github.com/kradalby/tscap/anonymize): users get
// norse-god names and nodes get original-151 pokémon names.
func setupACLCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "odin", Email: "odin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "thor", Email: "thor@example.org"},
		{Model: gorm.Model{ID: 3}, Name: "freya", Email: "freya@example.com"},
	}
}

// setupACLCompatNodes returns the 8 test nodes for ACL compatibility tests.
// Node GivenNames match tscap's anonymized pokémon naming.
func setupACLCompatNodes(users types.Users) types.Nodes {
	return types.Nodes{
		{
			ID: 1, GivenName: "bulbasaur",
			User: &users[0], UserID: &users[0].ID,
			IPv4: ptrAddr("100.90.199.68"), IPv6: ptrAddr("fd7a:115c:a1e0::2d01:c747"),
			Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 2, GivenName: "ivysaur",
			User: &users[1], UserID: &users[1].ID,
			IPv4: ptrAddr("100.110.121.96"), IPv6: ptrAddr("fd7a:115c:a1e0::1737:7960"),
			Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 3, GivenName: "venusaur",
			User: &users[2], UserID: &users[2].ID,
			IPv4: ptrAddr("100.103.90.82"), IPv6: ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
			Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 4, GivenName: "beedrill",
			IPv4: ptrAddr("100.108.74.26"), IPv6: ptrAddr("fd7a:115c:a1e0::b901:4a87"),
			Tags: []string{"tag:server"}, Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 5, GivenName: "kakuna",
			IPv4: ptrAddr("100.103.8.15"), IPv6: ptrAddr("fd7a:115c:a1e0::5b37:80f"),
			Tags: []string{"tag:prod"}, Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 6, GivenName: "weedle",
			IPv4: ptrAddr("100.83.200.69"), IPv6: ptrAddr("fd7a:115c:a1e0::c537:c845"),
			Tags: []string{"tag:client"}, Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 7, GivenName: "squirtle",
			IPv4: ptrAddr("100.92.142.61"), IPv6: ptrAddr("fd7a:115c:a1e0::3e37:8e3d"),
			Tags: []string{"tag:router"},
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			},
			ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
		},
		{
			ID: 8, GivenName: "charmander",
			IPv4: ptrAddr("100.85.66.106"), IPv6: ptrAddr("fd7a:115c:a1e0::7c37:426a"),
			Tags: []string{"tag:exit"}, Hostinfo: &tailcfg.Hostinfo{},
		},
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
				testACLError(t, tf)

				return
			}

			// Build nodes per-scenario from this file's topology.
			// tscap uses clean-slate mode, so each scenario has
			// different node IPs; using a shared topology would
			// cause IP mismatches in filter rule comparisons.
			users, nodes := buildACLUsersAndNodes(t, tf)
			require.NotEmpty(t, nodes, "%s: topology is empty", tf.TestID)

			testACLSuccess(t, tf, users, nodes)
		})
	}
}

// testACLError verifies that an invalid policy produces the expected error.
func testACLError(t *testing.T, tf *testcapture.Capture) {
	t.Helper()

	policyJSON := convertPolicyUserEmails(tf.Input.FullPolicy)

	pol, err := unmarshalPolicy(policyJSON)
	if err != nil {
		// Parse-time error.
		if tf.Input.APIResponseBody != nil {
			wantMsg := tf.Input.APIResponseBody.Message
			if wantMsg != "" {
				assertACLErrorContains(
					t, err, wantMsg, tf.TestID,
				)
			}
		}

		return
	}

	err = pol.validate()
	if err != nil {
		if tf.Input.APIResponseBody != nil {
			wantMsg := tf.Input.APIResponseBody.Message
			if wantMsg != "" {
				assertACLErrorContains(
					t, err, wantMsg, tf.TestID,
				)
			}
		}

		return
	}

	t.Errorf(
		"%s: expected error but policy parsed and validated successfully",
		tf.TestID,
	)
}

// assertACLErrorContains requires that headscale's error contains the
// Tailscale SaaS error message verbatim. Divergence means an emitter
// needs to be aligned, not papered over with a translation table.
func assertACLErrorContains(
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

			// Compile headscale filter rules for this node
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

			// Compare
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
}
