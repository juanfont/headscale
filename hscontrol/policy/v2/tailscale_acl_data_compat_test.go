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
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
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

// filterRuleBucket keeps each source/destination association intact. Callers
// must compare one recipient at a time, before discarding viewer/owner identity.
type filterRuleBucket struct {
	Sources    string
	Protocols  string
	Kind       string
	Ports      tailcfg.PortRange
	Capability string
}

func filterRulesDiff(tb testing.TB, want, got []tailcfg.FilterRule) string {
	tb.Helper()

	return cmp.Diff(
		semanticFilterRules(tb, want),
		semanticFilterRules(tb, got),
		cmpopts.EquateComparable(netip.Prefix{}),
	)
}

func semanticFilterRules(
	tb testing.TB,
	rules []tailcfg.FilterRule,
) map[filterRuleBucket][]netip.Prefix {
	tb.Helper()

	buckets := make(map[filterRuleBucket]*netipx.IPSetBuilder)

	for _, rule := range rules {
		var sources netipx.IPSetBuilder

		for i, source := range rule.SrcIPs {
			var bits *int
			if i < len(rule.SrcBits) {
				bits = &rule.SrcBits[i]
			}

			addFilterIPToBuilder(tb, &sources, source, bits)
		}

		sourceSet, err := sources.IPSet()
		require.NoError(tb, err)

		protocols := slices.Clone(rule.IPProto)
		if len(protocols) == 0 {
			protocols = []int{1, 6, 17, 58}
		}

		slices.Sort(protocols)
		protocols = slices.Compact(protocols)
		key := filterRuleBucket{
			Sources:   fmt.Sprint(sourceSet.Prefixes()),
			Protocols: fmt.Sprint(protocols),
			Kind:      "network",
		}

		require.False(tb, len(rule.DstPorts) > 0 && len(rule.CapGrant) > 0,
			"mixed network and capability rule: %+v", rule)

		for _, destination := range rule.DstPorts {
			key.Ports = destination.Ports
			if buckets[key] == nil {
				buckets[key] = new(netipx.IPSetBuilder)
			}

			addFilterIPToBuilder(tb, buckets[key], destination.IP, destination.Bits)
		}

		key.Kind = "capability"
		for _, grant := range rule.CapGrant {
			key.Capability = capabilityPayload(tb, grant)
			if buckets[key] == nil {
				buckets[key] = new(netipx.IPSetBuilder)
			}

			for _, destination := range grant.Dsts {
				buckets[key].AddPrefix(destination)
			}
		}
	}

	result := make(map[filterRuleBucket][]netip.Prefix, len(buckets))
	for key, builder := range buckets {
		set, err := builder.IPSet()
		require.NoError(tb, err)

		if prefixes := set.Prefixes(); len(prefixes) > 0 {
			result[key] = prefixes
		}
	}

	return result
}

func addFilterIPToBuilder(
	tb testing.TB,
	builder *netipx.IPSetBuilder,
	ip string,
	bits *int,
) {
	tb.Helper()

	address, err := netip.ParseAddr(ip)
	if err == nil && bits != nil {
		require.GreaterOrEqual(tb, *bits, 0)
		require.LessOrEqual(tb, *bits, address.BitLen())
		builder.AddPrefix(netip.PrefixFrom(address, *bits))

		return
	}

	addSrcIPToBuilder(tb, builder, ip, "filter comparison", "recipient")
}

func capabilityPayload(tb testing.TB, grant tailcfg.CapGrant) string {
	tb.Helper()

	var capMap tailcfg.PeerCapMap
	if grant.CapMap != nil {
		capMap = make(tailcfg.PeerCapMap, len(grant.CapMap))
	}

	for name, values := range grant.CapMap {
		capMap[name] = nil
		if values != nil {
			capMap[name] = make([]tailcfg.RawMessage, len(values))
		}

		for i, raw := range values {
			require.True(tb, json.Valid([]byte(raw)), "invalid capability JSON: %q", raw)
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.UseNumber()

			var value any
			require.NoError(tb, decoder.Decode(&value))
			canonical, err := json.Marshal(value)
			require.NoError(tb, err)

			capMap[name][i] = tailcfg.RawMessage(canonical)
		}
	}

	// No omitempty: nil/empty containers and ordered values are payload, too.
	payload, err := json.Marshal(struct {
		Caps   []peercap.Cap
		CapMap tailcfg.PeerCapMap
	}{grant.Caps, capMap})
	require.NoError(tb, err)

	return string(payload)
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
			// the capture tool uses clean-slate mode, so each scenario has
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
// Tailscale SaaS error message exactly. Divergence means an emitter
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
			compiledRules := pol.compileFilterRulesForNode(
				users,
				node.View(),
				nodes.ViewSlice(),
			)

			gotRules := reduceWireRulesForTest(
				node.View(),
				compiledRules,
			)

			wantRules := capture.PacketFilterRules

			// Compare coverage for this recipient, preserving source associations.
			if diff := filterRulesDiff(t, wantRules, gotRules); diff != "" {
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

func TestFilterRulesSemanticComparison(t *testing.T) {
	t.Parallel()

	http := tailcfg.PortRange{First: 80, Last: 80}
	https := tailcfg.PortRange{First: 443, Last: 443}
	network := func(src, dst string, ports tailcfg.PortRange, proto ...int) tailcfg.FilterRule {
		return tailcfg.FilterRule{
			SrcIPs: []string{src}, IPProto: proto,
			DstPorts: []tailcfg.NetPortRange{{IP: dst, Ports: ports}},
		}
	}
	capability := func(dst string, payload tailcfg.PeerCapMap) tailcfg.FilterRule {
		return tailcfg.FilterRule{
			SrcIPs: []string{"100.64.0.1"},
			CapGrant: []tailcfg.CapGrant{{
				Dsts: []netip.Prefix{netip.MustParsePrefix(dst)}, CapMap: payload,
			}},
		}
	}

	web := network("100.64.0.1", "10.0.0.0/24", http)
	secure := network("100.64.0.1", "10.0.1.0/24", https)
	mergedSources := network("100.64.0.0/31", "10.0.0.0/24", http)
	listedSources := web
	listedSources.SrcIPs = []string{"100.64.0.1", "100.64.0.0"}
	legacySource := web
	legacySource.SrcBits = []int{24}
	legacyDestination := web
	legacyDestination.DstPorts = []tailcfg.NetPortRange{{
		IP: "10.0.0.1", Bits: new(24), Ports: http,
	}}
	capPayload := tailcfg.PeerCapMap{
		"example.com/cap":  {`{"role":"reader","ids":[1,2]}`},
		"example.com/flag": nil,
	}
	capRule := capability("10.0.0.0/24", capPayload)
	legacyCap := capability("10.0.0.0/24", nil)
	legacyCap.CapGrant[0].Caps = []peercap.Cap{"example.com/legacy"}
	otherLegacyCap := capability("10.0.0.0/24", nil)
	otherLegacyCap.CapGrant[0].Caps = []peercap.Cap{"example.com/other"}

	tests := []struct {
		name  string
		want  []tailcfg.FilterRule
		got   []tailcfg.FilterRule
		equal bool
	}{
		{
			name:  "bare-host-and-cidr",
			want:  []tailcfg.FilterRule{network("100.64.0.1", "10.0.0.1", http)},
			got:   []tailcfg.FilterRule{network("100.64.0.1/32", "10.0.0.1/32", http)},
			equal: true,
		},
		{
			name: "wildcard-and-all-prefixes",
			want: []tailcfg.FilterRule{network("*", "*", http)},
			got: []tailcfg.FilterRule{{
				SrcIPs: []string{"0.0.0.0/0", "::/0"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "0.0.0.0/0", Ports: http}, {IP: "::/0", Ports: http},
				},
			}},
			equal: true,
		},
		{
			name:  "equivalent-source-merging",
			want:  []tailcfg.FilterRule{listedSources},
			got:   []tailcfg.FilterRule{mergedSources},
			equal: true,
		},
		{
			name: "destination-union-across-rules",
			want: []tailcfg.FilterRule{
				network("100.64.0.1", "10.0.0.0/25", http),
				network("100.64.0.1/32", "10.0.0.128-10.0.0.255", http),
				web,
			},
			got:   []tailcfg.FilterRule{web},
			equal: true,
		},
		{
			name: "default-protocols-and-duplicates",
			want: []tailcfg.FilterRule{web},
			got: []tailcfg.FilterRule{
				network("100.64.0.1", "10.0.0.0/24", http, 58, 17, 6, 1, 6),
			},
			equal: true,
		},
		{
			name:  "legacy-source-bits",
			want:  []tailcfg.FilterRule{legacySource},
			got:   []tailcfg.FilterRule{network("100.64.0.0/24", "10.0.0.0/24", http)},
			equal: true,
		},
		{
			name: "legacy-destination-bits",
			want: []tailcfg.FilterRule{
				legacyDestination,
			},
			got:   []tailcfg.FilterRule{web},
			equal: true,
		},
		{
			name:  "empty-revocation",
			want:  nil,
			got:   []tailcfg.FilterRule{},
			equal: true,
		},
		{
			name: "swapped-ports",
			want: []tailcfg.FilterRule{web, secure},
			got: []tailcfg.FilterRule{
				network("100.64.0.1", "10.0.0.0/24", https),
				network("100.64.0.1", "10.0.1.0/24", http),
			},
		},
		{
			name: "exact-port-ranges",
			want: []tailcfg.FilterRule{
				network(
					"100.64.0.1",
					"10.0.0.0/24",
					tailcfg.PortRange{First: 80, Last: 81},
				),
			},
			got: []tailcfg.FilterRule{
				web,
				network(
					"100.64.0.1",
					"10.0.0.0/24",
					tailcfg.PortRange{First: 81, Last: 81},
				),
			},
		},
		{
			name: "widened-source", want: []tailcfg.FilterRule{web},
			got: []tailcfg.FilterRule{network("100.64.0.0/24", "10.0.0.0/24", http)},
		},
		{
			name: "source-destination-cross-product",
			want: []tailcfg.FilterRule{web, network("100.64.0.2", "10.0.1.0/24", http)},
			got: []tailcfg.FilterRule{{
				SrcIPs: []string{"100.64.0.1", "100.64.0.2"},
				DstPorts: []tailcfg.NetPortRange{
					{IP: "10.0.0.0/24", Ports: http}, {IP: "10.0.1.0/24", Ports: http},
				},
			}},
		},
		{
			name: "missing-destination-coverage", want: []tailcfg.FilterRule{web},
			got: []tailcfg.FilterRule{network("100.64.0.1", "10.0.0.0/25", http)},
		},
		{
			name: "missing-ipv6-coverage",
			want: []tailcfg.FilterRule{network("*", "*", http)},
			got:  []tailcfg.FilterRule{network("*", "0.0.0.0/0", http)},
		},
		{
			name: "widened-protocols",
			want: []tailcfg.FilterRule{web},
			got: []tailcfg.FilterRule{
				network("100.64.0.1", "10.0.0.0/24", http, 1, 6, 17, 47, 58, 132),
			},
		},
		{
			name: "removed-protocols", want: []tailcfg.FilterRule{web},
			got: []tailcfg.FilterRule{network("100.64.0.1", "10.0.0.0/24", http, 6)},
		},
		{
			name: "protocol-destination-cross-product",
			want: []tailcfg.FilterRule{
				network("100.64.0.1", "10.0.0.0/24", http, 6),
				network("100.64.0.1", "10.0.1.0/24", http, 17),
			},
			got: []tailcfg.FilterRule{
				network("100.64.0.1", "10.0.0.0/24", http, 17),
				network("100.64.0.1", "10.0.1.0/24", http, 6),
			},
		},
		{
			name: "mapped-is-not-native",
			want: []tailcfg.FilterRule{network("100.64.0.1", "10.0.0.1", http)},
			got:  []tailcfg.FilterRule{network("100.64.0.1", "::ffff:10.0.0.1", http)},
		},
		{
			name: "capability-union-and-json-object-order",
			want: []tailcfg.FilterRule{capRule},
			got: []tailcfg.FilterRule{
				capability("10.0.0.0/25", capPayload),
				capability("10.0.0.128/25", tailcfg.PeerCapMap{
					"example.com/flag": nil,
					"example.com/cap":  {`{ "ids": [1, 2], "role": "reader" }`},
				}),
			},
			equal: true,
		},
		{
			name: "changed-capability-value", want: []tailcfg.FilterRule{capRule},
			got: []tailcfg.FilterRule{capability("10.0.0.0/24", tailcfg.PeerCapMap{
				"example.com/cap": {
					`{"role":"writer","ids":[1,2]}`,
				},
				"example.com/flag": nil,
			})},
		},
		{
			name: "removed-capability-key", want: []tailcfg.FilterRule{capRule},
			got: []tailcfg.FilterRule{capability("10.0.0.0/24", tailcfg.PeerCapMap{
				"example.com/cap": {`{"role":"reader","ids":[1,2]}`},
			})},
		},
		{
			name: "capability-value-array-order",
			want: []tailcfg.FilterRule{
				capability(
					"10.0.0.0/24",
					tailcfg.PeerCapMap{"example.com/cap": {`1`, `2`}},
				),
			},
			got: []tailcfg.FilterRule{
				capability(
					"10.0.0.0/24",
					tailcfg.PeerCapMap{"example.com/cap": {`2`, `1`}},
				),
			},
		},
		{
			name: "capability-nil-and-empty-values",
			want: []tailcfg.FilterRule{
				capability("10.0.0.0/24", tailcfg.PeerCapMap{"example.com/cap": nil}),
			},
			got: []tailcfg.FilterRule{
				capability("10.0.0.0/24", tailcfg.PeerCapMap{"example.com/cap": {}}),
			},
		},
		{
			name: "capability-large-integers",
			want: []tailcfg.FilterRule{
				capability(
					"10.0.0.0/24",
					tailcfg.PeerCapMap{"example.com/cap": {`9007199254740992`}},
				),
			},
			got: []tailcfg.FilterRule{
				capability(
					"10.0.0.0/24",
					tailcfg.PeerCapMap{"example.com/cap": {`9007199254740993`}},
				),
			},
		},
		{
			name: "capability-payload-destination-association",
			want: []tailcfg.FilterRule{
				capRule,
				capability("10.0.1.0/24", tailcfg.PeerCapMap{"example.com/other": nil}),
			},
			got: []tailcfg.FilterRule{
				capability("10.0.1.0/24", capPayload),
				capability("10.0.0.0/24", tailcfg.PeerCapMap{"example.com/other": nil}),
			},
		},
		{
			name: "legacy-capability-payload", want: []tailcfg.FilterRule{legacyCap},
			got: []tailcfg.FilterRule{otherLegacyCap},
		},
		{
			name: "network-capability-kind", want: []tailcfg.FilterRule{web},
			got: []tailcfg.FilterRule{capRule},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			beforeWant, err := json.Marshal(tt.want)
			require.NoError(t, err)
			beforeGot, err := json.Marshal(tt.got)
			require.NoError(t, err)

			diff := filterRulesDiff(t, tt.want, tt.got)
			if tt.equal {
				require.Empty(t, diff, "equivalent rules differ (-want +got)")
			} else {
				require.NotEmpty(
					t,
					diff,
					"comparison lost an authorization distinction",
				)
			}

			afterWant, err := json.Marshal(tt.want)
			require.NoError(t, err)
			afterGot, err := json.Marshal(tt.got)
			require.NoError(t, err)
			require.Equal(t, beforeWant, afterWant, "comparison mutated expected rules")
			require.Equal(t, beforeGot, afterGot, "comparison mutated actual rules")
		})
	}
}
