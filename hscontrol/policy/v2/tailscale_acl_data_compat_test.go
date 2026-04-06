// This file implements a data-driven test runner for ACL compatibility tests.
// It loads JSON golden files from testdata/acl_results/ACL-*.json and compares
// headscale's ACL engine output against the expected packet filter rules.
//
// The JSON files were converted from the original inline Go struct test cases
// in tailscale_acl_compat_test.go. Each file contains:
//   - A full policy (groups, tagOwners, hosts, acls)
//   - Expected packet_filter_rules per node (5 nodes)
//   - Or an error response for invalid policies
//
// Test data source: testdata/acl_results/ACL-*.json
// Original source: Tailscale SaaS API captures + headscale-generated expansions

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

// ptrAddr is a helper to create a pointer to a netip.Addr.
func ptrAddr(s string) *netip.Addr {
	addr := netip.MustParseAddr(s)

	return &addr
}

// setupACLCompatUsers returns the 3 test users for ACL compatibility tests.
// Email addresses use @example.com domain, matching the converted Tailscale
// policy format (Tailscale uses @passkey and @dalby.cc).
func setupACLCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "kratail2tid", Email: "kratail2tid@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "kristoffer", Email: "kristoffer@example.com"},
		{Model: gorm.Model{ID: 3}, Name: "monitorpasskeykradalby", Email: "monitorpasskeykradalby@example.com"},
	}
}

// setupACLCompatNodes returns the 8 test nodes for ACL compatibility tests.
// Uses the same topology as the grants compat tests.
func setupACLCompatNodes(users types.Users) types.Nodes {
	return types.Nodes{
		{
			ID: 1, GivenName: "user1",
			User: &users[0], UserID: &users[0].ID,
			IPv4: ptrAddr("100.90.199.68"), IPv6: ptrAddr("fd7a:115c:a1e0::2d01:c747"),
			Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 2, GivenName: "user-kris",
			User: &users[1], UserID: &users[1].ID,
			IPv4: ptrAddr("100.110.121.96"), IPv6: ptrAddr("fd7a:115c:a1e0::1737:7960"),
			Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 3, GivenName: "user-mon",
			User: &users[2], UserID: &users[2].ID,
			IPv4: ptrAddr("100.103.90.82"), IPv6: ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
			Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 4, GivenName: "tagged-server",
			IPv4: ptrAddr("100.108.74.26"), IPv6: ptrAddr("fd7a:115c:a1e0::b901:4a87"),
			Tags: []string{"tag:server"}, Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 5, GivenName: "tagged-prod",
			IPv4: ptrAddr("100.103.8.15"), IPv6: ptrAddr("fd7a:115c:a1e0::5b37:80f"),
			Tags: []string{"tag:prod"}, Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 6, GivenName: "tagged-client",
			IPv4: ptrAddr("100.83.200.69"), IPv6: ptrAddr("fd7a:115c:a1e0::c537:c845"),
			Tags: []string{"tag:client"}, Hostinfo: &tailcfg.Hostinfo{},
		},
		{
			ID: 7, GivenName: "subnet-router",
			IPv4: ptrAddr("100.92.142.61"), IPv6: ptrAddr("fd7a:115c:a1e0::3e37:8e3d"),
			Tags: []string{"tag:router"},
			Hostinfo: &tailcfg.Hostinfo{
				RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
			},
			ApprovedRoutes: []netip.Prefix{netip.MustParsePrefix("10.33.0.0/16")},
		},
		{
			ID: 8, GivenName: "exit-node",
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
		// Compare json.RawMessage semantically rather than by exact
		// bytes to handle indentation differences between the policy
		// source and the golden capture data.
		cmp.Comparer(func(a, b json.RawMessage) bool {
			var va, vb any

			err := json.Unmarshal(a, &va)
			if err != nil {
				return string(a) == string(b)
			}

			err = json.Unmarshal(b, &vb)
			if err != nil {
				return string(a) == string(b)
			}

			ja, _ := json.Marshal(va)
			jb, _ := json.Marshal(vb)

			return string(ja) == string(jb)
		}),
		// Compare tailcfg.RawMessage semantically (it's a string type
		// containing JSON) to handle indentation differences.
		cmp.Comparer(func(a, b tailcfg.RawMessage) bool {
			var va, vb any

			err := json.Unmarshal([]byte(a), &va)
			if err != nil {
				return a == b
			}

			err = json.Unmarshal([]byte(b), &vb)
			if err != nil {
				return a == b
			}

			ja, _ := json.Marshal(va)
			jb, _ := json.Marshal(vb)

			return string(ja) == string(jb)
		}),
	}
}

// aclTestFile represents the JSON structure of a captured ACL test file.
type aclTestFile struct {
	TestID           string `json:"test_id"`
	Source           string `json:"source"` // "tailscale_saas" or "headscale_adapted"
	Error            bool   `json:"error"`
	HeadscaleDiffers bool   `json:"headscale_differs"`
	ParentTest       string `json:"parent_test"`
	Input            struct {
		FullPolicy      json.RawMessage `json:"full_policy"`
		APIResponseCode int             `json:"api_response_code"`
		APIResponseBody *struct {
			Message string `json:"message"`
		} `json:"api_response_body"`
	} `json:"input"`
	Topology struct {
		Nodes map[string]struct {
			Hostname       string   `json:"hostname"`
			Tags           []string `json:"tags"`
			IPv4           string   `json:"ipv4"`
			IPv6           string   `json:"ipv6"`
			User           string   `json:"user"`
			RoutableIPs    []string `json:"routable_ips"`
			ApprovedRoutes []string `json:"approved_routes"`
		} `json:"nodes"`
	} `json:"topology"`
	Captures map[string]struct {
		PacketFilterRules json.RawMessage `json:"packet_filter_rules"`
	} `json:"captures"`
}

// buildACLUsersAndNodes constructs users and nodes from an ACL
// golden file's topology. This ensures the test creates the same
// nodes that were present during the Tailscale SaaS capture.
func buildACLUsersAndNodes(
	t *testing.T,
	tf aclTestFile,
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

// loadACLTestFile loads and parses a single ACL test JSON file.
func loadACLTestFile(t *testing.T, path string) aclTestFile {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test file %s", path)

	ast, err := hujson.Parse(content)
	require.NoError(t, err, "failed to parse HuJSON in %s", path)
	ast.Standardize()

	var tf aclTestFile

	err = json.Unmarshal(ast.Pack(), &tf)
	require.NoError(t, err, "failed to unmarshal test file %s", path)

	return tf
}

// aclSkipReasons documents WHY tests are expected to fail and WHAT needs to be
// implemented to fix them. Tests are grouped by root cause.
//
// Impact summary:
//
//	SRCIPS_FORMAT            - tests: SrcIPs use adapted format (100.64.0.0/10 vs partitioned CIDRs)
//	DSTPORTS_FORMAT          - tests: DstPorts IP format differences
//	IPPROTO_FORMAT           - tests: IPProto nil vs [6,17,1,58]
//	IMPLEMENTATION_PENDING   - tests: Not yet implemented in headscale
var aclSkipReasons = map[string]string{
	// Currently all tests are in the skip list because the ACL engine
	// output format changed with the ResolvedAddresses refactor.
	// Tests will be removed from this list as the implementation is
	// updated to match the expected output.
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
		filepath.Join("testdata", "acl_results", "ACL-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no ACL-*.hujson test files found in testdata/acl_results/",
	)

	t.Logf("Loaded %d ACL test files", len(files))

	// Build nodes from the first non-error file's topology.
	// All files share the same 19-node tailnet topology.
	var users types.Users

	var nodes types.Nodes

	for _, file := range files {
		tf := loadACLTestFile(t, file)
		if !tf.Error && len(tf.Topology.Nodes) > 0 {
			users, nodes = buildACLUsersAndNodes(t, tf)

			break
		}
	}

	require.NotEmpty(t, nodes, "no non-error ACL file found")

	for _, file := range files {
		tf := loadACLTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Check skip list
			if reason, ok := aclSkipReasons[tf.TestID]; ok {
				t.Skipf(
					"TODO: %s — see aclSkipReasons for details",
					reason,
				)

				return
			}

			if tf.Error {
				testACLError(t, tf)

				return
			}

			testACLSuccess(t, tf, users, nodes)
		})
	}
}

// aclErrorMessageMap maps Tailscale SaaS error substrings to headscale
// equivalents. Populated as mismatches are discovered.
var aclErrorMessageMap = map[string]string{
	// Add known wording differences here as they are discovered.
	// Example: "tag not found" -> "undefined tag",
}

// testACLError verifies that an invalid policy produces the expected error.
func testACLError(t *testing.T, tf aclTestFile) {
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

	// For headscale_differs tests, headscale may accept what
	// Tailscale rejects. Log as skip so it appears in output.
	if tf.HeadscaleDiffers {
		t.Skipf(
			"%s: headscale accepts this policy (Tailscale rejects it)",
			tf.TestID,
		)

		return
	}

	t.Errorf(
		"%s: expected error but policy parsed and validated successfully",
		tf.TestID,
	)
}

// assertACLErrorContains checks that an error message matches the
// expected Tailscale SaaS message, using progressive fallbacks:
//  1. Direct substring match
//  2. Mapped equivalent from aclErrorMessageMap
//  3. Key-part extraction (tags, autogroups, port, undefined)
//  4. t.Errorf on no match (strict)
func assertACLErrorContains(
	t *testing.T,
	err error,
	wantMsg string,
	testID string,
) {
	t.Helper()

	errStr := err.Error()

	// 1. Direct substring match.
	if strings.Contains(errStr, wantMsg) {
		return
	}

	// 2. Mapped equivalent.
	for tsKey, hsKey := range aclErrorMessageMap {
		if strings.Contains(wantMsg, tsKey) &&
			strings.Contains(errStr, hsKey) {
			return
		}
	}

	// 3. Key-part extraction.
	for _, part := range []string{
		"autogroup:self",
		"not valid on the src",
		"port range",
		"tag not found",
		"tag:",
		"undefined",
		"capability",
	} {
		if strings.Contains(wantMsg, part) &&
			strings.Contains(errStr, part) {
			return
		}
	}

	// 4. No match — strict failure.
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
	tf aclTestFile,
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
			captureIsNull := len(capture.PacketFilterRules) == 0 ||
				string(capture.PacketFilterRules) == "null" //nolint:goconst

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

			// Parse expected rules from JSON
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
