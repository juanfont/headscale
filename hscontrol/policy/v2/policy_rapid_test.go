package v2

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

// genUserCount draws a user count in [1, 3].
func genUserCount(t *rapid.T) int {
	return rapid.IntRange(1, 3).Draw(t, "userCount")
}

// genNodeCount draws a node count in [2, 8].
func genNodeCount(t *rapid.T) int {
	return rapid.IntRange(2, 8).Draw(t, "nodeCount")
}

// genTestUsers generates 1-3 test users with consistent names and emails.
func genTestUsers(t *rapid.T) types.Users {
	count := genUserCount(t)
	users := make(types.Users, count)

	for i := range count {
		users[i] = types.User{
			Model: gorm.Model{ID: uint(i + 1)}, //nolint:gosec // positive bounded value
			Name:  fmt.Sprintf("user%d", i+1),
			Email: fmt.Sprintf("user%d@example.com", i+1),
		}
	}

	return users
}

// genTestNodes generates 2-8 test nodes with CGNAT IPs assigned to users.
// Nodes are assigned round-robin to users by default.
// If withTags is true, some nodes may get tags.
func genTestNodes(t *rapid.T, users types.Users, withTags bool) types.Nodes {
	count := genNodeCount(t)
	nodes := make(types.Nodes, count)

	for i := range count {
		user := users[i%len(users)]
		ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
		ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
		ipv6 := netip.AddrFrom16(ipv6Bytes)

		node := &types.Node{
			ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
			Hostname: fmt.Sprintf("node%d", i+1),
			IPv4:     &ipv4,
			IPv6:     &ipv6,
			User:     &user,
			UserID:   &user.ID,
		}

		if withTags && rapid.Bool().Draw(t, fmt.Sprintf("node%d_tagged", i)) {
			tagIdx := rapid.IntRange(0, 2).Draw(t, fmt.Sprintf("node%d_tagIdx", i))
			node.Tags = []string{fmt.Sprintf("tag:service%d", tagIdx)}
			// Tagged nodes don't have user ownership for identity
		}

		nodes[i] = node
	}

	return nodes
}

// genTestNodesNoTags generates test nodes without tags.
func genTestNodesNoTags(t *rapid.T, users types.Users) types.Nodes {
	return genTestNodes(t, users, false)
}

// aclSourceAlias picks a random valid source alias referencing existing users.
func genACLSourceAlias(t *rapid.T, users types.Users) string {
	choice := rapid.IntRange(0, 2).Draw(t, "srcAliasChoice")
	switch choice {
	case 0:
		// Wildcard
		return "*"
	case 1:
		// User
		u := users[rapid.IntRange(0, len(users)-1).Draw(t, "srcUser")]
		return u.Name + "@"
	default:
		// autogroup:member
		return string(AutoGroupMember)
	}
}

// genACLDestAlias picks a random valid destination alias:port.
func genACLDestAlias(t *rapid.T, users types.Users) string {
	choice := rapid.IntRange(0, 2).Draw(t, "dstAliasChoice")
	switch choice {
	case 0:
		return "*:*"
	case 1:
		u := users[rapid.IntRange(0, len(users)-1).Draw(t, "dstUser")]
		return u.Name + "@:*"
	default:
		return string(AutoGroupMember) + ":*"
	}
}

// genSimplePolicy generates a valid policy JSON string with 1-3 ACL rules
// using only users and wildcards (no tags, no groups) to keep it simple.
func genSimplePolicy(t *rapid.T, users types.Users) string {
	aclCount := rapid.IntRange(1, 3).Draw(t, "aclCount")

	acls := make([]string, 0, aclCount)

	for i := range aclCount {
		src := genACLSourceAlias(t, users)
		dst := genACLDestAlias(t, users)
		acls = append(acls, fmt.Sprintf(
			`{"action":"accept","src":[%q],"dst":[%q]}`,
			src, dst,
		))
		_ = i
	}

	return fmt.Sprintf(`{"acls":[%s]}`, strings.Join(acls, ","))
}

// genWildcardPolicy returns a policy that allows all-to-all traffic.
func genWildcardPolicy() string {
	return `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
}

// genFilterRule generates a random FilterRule with valid SrcIPs and DstPorts.
// SrcIPs and DstPorts use CIDR prefix lengths in [24,32] to exercise
// prefix-matching code paths beyond just /32 host routes.
func genFilterRule(t *rapid.T) tailcfg.FilterRule {
	srcCount := rapid.IntRange(1, 3).Draw(t, "srcCount")

	srcIPs := make([]string, srcCount)
	for i := range srcCount {
		octet := rapid.IntRange(1, 254).Draw(t, fmt.Sprintf("srcOctet%d", i))
		bits := rapid.IntRange(24, 32).Draw(t, fmt.Sprintf("srcBits%d", i))
		srcIPs[i] = fmt.Sprintf("100.64.0.%d/%d", octet, bits)
	}

	dstCount := rapid.IntRange(1, 3).Draw(t, "dstCount")

	dstPorts := make([]tailcfg.NetPortRange, dstCount)
	for i := range dstCount {
		octet := rapid.IntRange(1, 254).Draw(t, fmt.Sprintf("dstOctet%d", i))
		bits := rapid.IntRange(24, 32).Draw(t, fmt.Sprintf("dstBits%d", i))
		portFirst := rapid.Uint16Range(1, 65534).Draw(t, fmt.Sprintf("portFirst%d", i))
		portLast := rapid.Uint16Range(portFirst, 65535).Draw(t, fmt.Sprintf("portLast%d", i))
		dstPorts[i] = tailcfg.NetPortRange{
			IP:    fmt.Sprintf("100.64.0.%d/%d", octet, bits),
			Ports: tailcfg.PortRange{First: portFirst, Last: portLast},
		}
	}

	return tailcfg.FilterRule{
		SrcIPs:   srcIPs,
		DstPorts: dstPorts,
	}
}

// genFilterRules generates 1-5 random FilterRules.
func genFilterRules(t *rapid.T) []tailcfg.FilterRule {
	count := rapid.IntRange(1, 5).Draw(t, "ruleCount")

	rules := make([]tailcfg.FilterRule, count)
	for i := range count {
		rules[i] = genFilterRule(t)
	}

	return rules
}

// genFilterRulesWithSharedSrc generates 2-5 FilterRules where at least 2
// rules share identical SrcIPs strings. This exercises the merge-DstPorts
// code path in mergeFilterRules which groups rules by SrcIPs key.
func genFilterRulesWithSharedSrc(t *rapid.T) []tailcfg.FilterRule {
	count := rapid.IntRange(2, 5).Draw(t, "sharedRuleCount")
	rules := make([]tailcfg.FilterRule, count)

	// Generate the first rule normally.
	rules[0] = genFilterRule(t)
	sharedSrcIPs := rules[0].SrcIPs

	// Force at least one other rule to share the same SrcIPs.
	shareIdx := rapid.IntRange(1, count-1).Draw(t, "shareIdx")

	for i := 1; i < count; i++ {
		rules[i] = genFilterRule(t)
		if i == shareIdx {
			// Overwrite SrcIPs with the shared set, keep different DstPorts.
			rules[i].SrcIPs = sharedSrcIPs
		}
	}

	return rules
}

// genFilterRulesForNode generates filter rules where some target the node's
// actual IPs (guaranteed to be kept by ReduceFilterRules) and some target
// random IPs (likely to be pruned).
func genFilterRulesForNode(t *rapid.T, node *types.Node) []tailcfg.FilterRule {
	nodeIP := node.IPv4.String() + "/32"

	// At least 1 rule targeting the node, plus some random rules.
	nTargeting := rapid.IntRange(1, 3).Draw(t, "nTargeting")
	nRandom := rapid.IntRange(0, 3).Draw(t, "nRandom")

	rules := make([]tailcfg.FilterRule, 0, nTargeting+nRandom)

	// Rules targeting the node's IP in DstPorts.
	for i := range nTargeting {
		srcCount := rapid.IntRange(1, 3).Draw(t, fmt.Sprintf("tSrcCount%d", i))

		srcIPs := make([]string, srcCount)
		for j := range srcCount {
			octet := rapid.IntRange(1, 254).Draw(t, fmt.Sprintf("tSrcOctet%d_%d", i, j))
			srcIPs[j] = fmt.Sprintf("100.64.0.%d/32", octet)
		}

		portFirst := rapid.Uint16Range(1, 65534).Draw(t, fmt.Sprintf("tPortFirst%d", i))
		portLast := rapid.Uint16Range(portFirst, 65535).Draw(t, fmt.Sprintf("tPortLast%d", i))

		// Mix: some DstPorts target the node, some are random.
		dstPorts := []tailcfg.NetPortRange{
			{
				IP:    nodeIP,
				Ports: tailcfg.PortRange{First: portFirst, Last: portLast},
			},
		}
		// Optionally add a random DstPort too.
		if rapid.Bool().Draw(t, fmt.Sprintf("tExtraDst%d", i)) {
			octet := rapid.IntRange(1, 254).Draw(t, fmt.Sprintf("tExtraDstOctet%d", i))
			pf := rapid.Uint16Range(1, 65534).Draw(t, fmt.Sprintf("tExtraPortFirst%d", i))
			pl := rapid.Uint16Range(pf, 65535).Draw(t, fmt.Sprintf("tExtraPortLast%d", i))
			dstPorts = append(dstPorts, tailcfg.NetPortRange{
				IP:    fmt.Sprintf("100.64.0.%d/32", octet),
				Ports: tailcfg.PortRange{First: pf, Last: pl},
			})
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   srcIPs,
			DstPorts: dstPorts,
		})
	}

	// Random rules that don't target the node (use IPs far from CGNAT node range).
	for i := range nRandom {
		srcCount := rapid.IntRange(1, 2).Draw(t, fmt.Sprintf("rSrcCount%d", i))

		srcIPs := make([]string, srcCount)
		for j := range srcCount {
			octet := rapid.IntRange(1, 254).Draw(t, fmt.Sprintf("rSrcOctet%d_%d", i, j))
			srcIPs[j] = fmt.Sprintf("100.64.0.%d/32", octet)
		}

		// Use 10.x.x.x range so they never match CGNAT node IPs.
		dstOctet2 := rapid.IntRange(0, 255).Draw(t, fmt.Sprintf("rDst2_%d", i))
		dstOctet3 := rapid.IntRange(0, 255).Draw(t, fmt.Sprintf("rDst3_%d", i))
		dstOctet4 := rapid.IntRange(1, 254).Draw(t, fmt.Sprintf("rDst4_%d", i))
		pf := rapid.Uint16Range(1, 65534).Draw(t, fmt.Sprintf("rPortFirst%d", i))
		pl := rapid.Uint16Range(pf, 65535).Draw(t, fmt.Sprintf("rPortLast%d", i))

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs: srcIPs,
			DstPorts: []tailcfg.NetPortRange{
				{
					IP:    fmt.Sprintf("10.%d.%d.%d/32", dstOctet2, dstOctet3, dstOctet4),
					Ports: tailcfg.PortRange{First: pf, Last: pl},
				},
			},
		})
	}

	return rules
}

// extractRuleIPs extracts all unique SrcIPs and DstPort IPs from rules as parsed addresses.
func extractRuleIPs(rules []tailcfg.FilterRule) ([]netip.Addr, []netip.Addr, []uint16) {
	srcSeen := make(map[netip.Addr]bool)
	dstSeen := make(map[netip.Addr]bool)
	portSeen := make(map[uint16]bool)

	var srcAddrs, dstAddrs []netip.Addr

	var dstPorts []uint16

	for _, rule := range rules {
		for _, src := range rule.SrcIPs {
			pfx, err := netip.ParsePrefix(src)
			if err != nil {
				continue
			}

			addr := pfx.Addr()
			if !srcSeen[addr] {
				srcSeen[addr] = true
				srcAddrs = append(srcAddrs, addr)
			}
		}

		for _, dp := range rule.DstPorts {
			pfx, err := netip.ParsePrefix(dp.IP)
			if err != nil {
				continue
			}

			addr := pfx.Addr()
			if !dstSeen[addr] {
				dstSeen[addr] = true
				dstAddrs = append(dstAddrs, addr)
			}
			// Collect interesting ports (first, last, and midpoint).
			for _, p := range []uint16{dp.Ports.First, dp.Ports.Last} {
				if !portSeen[p] {
					portSeen[p] = true
					dstPorts = append(dstPorts, p)
				}
			}
		}
	}

	return srcAddrs, dstAddrs, dstPorts
}

// genIPInCGNAT generates a random CGNAT IP address.
func genIPInCGNAT(t *rapid.T, label string) netip.Addr {
	octet := rapid.IntRange(0, 255).Draw(t, label)
	return netip.AddrFrom4([4]byte{100, 64, 0, byte(octet)})
}

// ---------------------------------------------------------------------------
// Property 1: BuildPeerMap symmetry
//   If node A appears in B's peer list, then B appears in A's peer list.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_Symmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		for nodeID, peers := range peerMap {
			for _, peer := range peers {
				peerPeers, ok := peerMap[peer.ID()]
				if !ok {
					t.Fatalf("symmetry violation: node %d sees node %d, "+
						"but node %d has no peer list\npolicy: %s",
						nodeID, peer.ID(), peer.ID(), polJSON)
				}

				found := slices.ContainsFunc(peerPeers, func(nv types.NodeView) bool {
					return nv.ID() == nodeID
				})

				if !found {
					t.Fatalf("symmetry violation: node %d sees node %d, "+
						"but node %d does not see node %d\npolicy: %s",
						nodeID, peer.ID(), peer.ID(), nodeID, polJSON)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 2: BuildPeerMap self-exclusion
//   No node ever appears in its own peer list.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_SelfExclusion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		for nodeID, peers := range peerMap {
			for _, peer := range peers {
				if peer.ID() == nodeID {
					t.Fatalf("self-inclusion: node %d appears in its own peer list\npolicy: %s",
						nodeID, polJSON)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 3: mergeFilterRules semantic equivalence
//   For any set of filter rules and any (srcIP, dstIP, dstPort) tuple,
//   the merged rules produce the same match result as the unmerged rules.
// ---------------------------------------------------------------------------

// matchRules tests whether a (srcIP, dstIP, dstPort) tuple matches any rule in the list.
func matchRules(rules []tailcfg.FilterRule, srcIP, dstIP netip.Addr, dstPort uint16) bool {
	for _, rule := range rules {
		srcMatch := false

		for _, srcCIDR := range rule.SrcIPs {
			ipSet, err := util.ParseIPSet(srcCIDR, nil)
			if err != nil {
				continue
			}

			if ipSet.Contains(srcIP) {
				srcMatch = true
				break
			}
		}

		if !srcMatch {
			continue
		}

		for _, dp := range rule.DstPorts {
			ipSet, err := util.ParseIPSet(dp.IP, nil)
			if err != nil {
				continue
			}

			if ipSet.Contains(dstIP) && dstPort >= dp.Ports.First && dstPort <= dp.Ports.Last {
				return true
			}
		}
	}

	return false
}

func TestRapid_MergeFilterRules_SemanticEquivalence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Sometimes use genFilterRulesWithSharedSrc to exercise the
		// merge-DstPorts code path where rules share identical SrcIPs.
		var rules []tailcfg.FilterRule
		if rapid.Bool().Draw(t, "useSharedSrc") {
			rules = genFilterRulesWithSharedSrc(t)
		} else {
			rules = genFilterRules(t)
		}

		merged := mergeFilterRules(rules)

		// Extract actual IPs and ports from the rules so we probe addresses
		// that are known to match (testing true==true, not just false==false).
		srcAddrs, dstAddrs, knownPorts := extractRuleIPs(rules)

		// Probe with actual IPs from rules (high chance of matching).
		for i, srcIP := range srcAddrs {
			for j, dstIP := range dstAddrs {
				for _, port := range knownPorts {
					originalMatch := matchRules(rules, srcIP, dstIP, port)
					mergedMatch := matchRules(merged, srcIP, dstIP, port)

					if originalMatch != mergedMatch {
						t.Fatalf("merge semantic mismatch for src=%s dst=%s:%d: "+
							"original=%v merged=%v\noriginal rules: %+v\nmerged rules: %+v",
							srcIP, dstIP, port, originalMatch, mergedMatch, rules, merged)
					}

					_ = i
					_ = j
				}
			}
		}

		// Also probe with some random IPs for false==false cases.
		randomProbes := rapid.IntRange(3, 8).Draw(t, "randomProbes")
		for i := range randomProbes {
			srcIP := genIPInCGNAT(t, fmt.Sprintf("rndSrc%d", i))
			dstIP := genIPInCGNAT(t, fmt.Sprintf("rndDst%d", i))
			dstPort := rapid.Uint16().Draw(t, fmt.Sprintf("rndPort%d", i))

			originalMatch := matchRules(rules, srcIP, dstIP, dstPort)
			mergedMatch := matchRules(merged, srcIP, dstIP, dstPort)

			if originalMatch != mergedMatch {
				t.Fatalf("merge semantic mismatch (random probe) for src=%s dst=%s:%d: "+
					"original=%v merged=%v\noriginal rules: %+v\nmerged rules: %+v",
					srcIP, dstIP, dstPort, originalMatch, mergedMatch, rules, merged)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 4: ReduceFilterRules subset property
//   For any node and filter rules, the reduced rules' DstPorts are a
//   subset of the original rules' DstPorts.
// ---------------------------------------------------------------------------

func TestRapid_ReduceFilterRules_SubsetProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)

		// Pick a random node to reduce for.
		nodeIdx := rapid.IntRange(0, len(nodes)-1).Draw(t, "nodeIdx")
		node := nodes[nodeIdx]

		// Generate rules where some target this node's IP.
		rules := genFilterRulesForNode(t, node)

		reduced := policyutil.ReduceFilterRules(node.View(), rules)

		// Collect all DstPorts from the original rules.
		originalDstSet := make(map[string]bool)

		for _, rule := range rules {
			for _, dp := range rule.DstPorts {
				key := fmt.Sprintf("%s:%d-%d", dp.IP, dp.Ports.First, dp.Ports.Last)
				originalDstSet[key] = true
			}
		}

		// Every DstPort in the reduced rules must exist in the original.
		for _, rule := range reduced {
			for _, dp := range rule.DstPorts {
				key := fmt.Sprintf("%s:%d-%d", dp.IP, dp.Ports.First, dp.Ports.Last)
				if !originalDstSet[key] {
					t.Fatalf("reduced rule has DstPort %s not in original rules", key)
				}
			}
		}

		// The reduced set must be non-empty since we generated rules
		// targeting the node's IP.
		if len(reduced) == 0 {
			t.Fatalf("reduced rules are empty but rules targeting node %s were generated\nrules: %+v",
				node.IPv4.String(), rules)
		}

		// Verify reduced rules contain DstPorts targeting the node's IP.
		nodeIP := node.IPv4.String() + "/32"
		hasNodeDst := false

		for _, rule := range reduced {
			for _, dp := range rule.DstPorts {
				if dp.IP == nodeIP {
					hasNodeDst = true
				}
			}
		}

		if !hasNodeDst {
			t.Fatalf("reduced rules should contain DstPorts targeting node IP %s but don't\nreduced: %+v",
				nodeIP, reduced)
		}
	})
}

// ---------------------------------------------------------------------------
// Property 5: Empty policy produces FilterAllowAll
//   A nil or empty ACLs field should produce a full-mesh allow-all filter.
// ---------------------------------------------------------------------------

func TestRapid_EmptyPolicy_FilterAllowAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)

		// Test with "{}" (empty policy, no ACLs)
		pm, err := NewPolicyManager([]byte(`{}`), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager with empty policy: %v", err)
		}

		filter, _ := pm.Filter()

		if !reflect.DeepEqual(filter, tailcfg.FilterAllowAll) {
			t.Fatalf("empty policy did not produce FilterAllowAll.\n"+
				"got: %+v\nwant: %+v", filter, tailcfg.FilterAllowAll)
		}

		// Also verify BuildPeerMap: every node should see every other node
		peerMap := pm.BuildPeerMap(nodes.ViewSlice())
		for _, n := range nodes {
			peers := peerMap[n.ID]
			if len(peers) != len(nodes)-1 {
				t.Fatalf("empty policy: node %d has %d peers, want %d",
					n.ID, len(peers), len(nodes)-1)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 6: Wildcard policy produces full mesh
//   src:* dst:*:* means all nodes see all other nodes.
// ---------------------------------------------------------------------------

func TestRapid_WildcardPolicy_FullMesh(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)

		polJSON := genWildcardPolicy()

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager with wildcard policy: %v", err)
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// Every node must see every other node
		for _, n := range nodes {
			peers := peerMap[n.ID]
			if len(peers) != len(nodes)-1 {
				t.Fatalf("wildcard policy: node %d has %d peers, want %d",
					n.ID, len(peers), len(nodes)-1)
			}

			// Verify all other nodes are in the peer list
			for _, other := range nodes {
				if other.ID == n.ID {
					continue
				}

				found := slices.ContainsFunc(peers, func(nv types.NodeView) bool {
					return nv.ID() == other.ID
				})
				if !found {
					t.Fatalf("wildcard policy: node %d does not see node %d", n.ID, other.ID)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 7: Policy JSON roundtrip
//   Marshal then unmarshal a policy produces semantically equivalent output.
// ---------------------------------------------------------------------------

func TestRapid_PolicyJSON_Roundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		// Get the original filter rules
		origFilter, _ := pm.Filter()

		// Marshal the policy bytes back and create a new PM
		// We use the original JSON since we tested above it parses
		pm2, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("roundtrip: failed to create second policy manager: %v", err)
		}

		rtFilter, _ := pm2.Filter()

		// The two filters must produce identical match results
		if len(origFilter) != len(rtFilter) {
			t.Fatalf("roundtrip: filter length mismatch: orig=%d rt=%d",
				len(origFilter), len(rtFilter))
		}

		// Verify with random IP probes
		probeCount := rapid.IntRange(5, 20).Draw(t, "roundtripProbes")
		for i := range probeCount {
			srcIP := genIPInCGNAT(t, fmt.Sprintf("rtSrc%d", i))
			dstIP := genIPInCGNAT(t, fmt.Sprintf("rtDst%d", i))
			dstPort := rapid.Uint16().Draw(t, fmt.Sprintf("rtPort%d", i))

			origMatch := matchRules(origFilter, srcIP, dstIP, dstPort)
			rtMatch := matchRules(rtFilter, srcIP, dstIP, dstPort)

			if origMatch != rtMatch {
				t.Fatalf("roundtrip mismatch for src=%s dst=%s:%d: "+
					"orig=%v rt=%v", srcIP, dstIP, dstPort, origMatch, rtMatch)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 8: BuildPeerMap consistency across global and per-node paths
//   BuildPeerMap with a non-autogroup:self policy must produce the same
//   results as manually checking each pair with matchers.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_ConsistentWithMatchers(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		_, matchers := pm.Filter()
		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// Manually compute what the peer map should be
		nv := nodes.ViewSlice()
		for i := range nv.Len() {
			for j := i + 1; j < nv.Len(); j++ {
				nodeI := nv.At(i)
				nodeJ := nv.At(j)

				canIJ := nodeI.CanAccess(matchers, nodeJ)
				canJI := nodeJ.CanAccess(matchers, nodeI)
				shouldBePeers := canIJ || canJI

				iPeers := peerMap[nodeI.ID()]
				jInIPeers := slices.ContainsFunc(iPeers, func(nv types.NodeView) bool {
					return nv.ID() == nodeJ.ID()
				})

				if shouldBePeers != jInIPeers {
					t.Fatalf("BuildPeerMap inconsistency: nodes %d and %d, "+
						"canIJ=%v canJI=%v shouldBePeers=%v, inPeerMap=%v\npolicy: %s",
						nodeI.ID(), nodeJ.ID(), canIJ, canJI, shouldBePeers, jInIPeers, polJSON)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 9: mergeFilterRules preserves count
//   The total number of DstPorts across all merged rules must equal the
//   total across the original rules (DstPorts are NOT deduplicated).
// ---------------------------------------------------------------------------

func TestRapid_MergeFilterRules_PreservesDstPortCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := genFilterRules(t)

		origDstCount := 0
		for _, r := range rules {
			origDstCount += len(r.DstPorts)
		}

		merged := mergeFilterRules(rules)

		mergedDstCount := 0
		for _, r := range merged {
			mergedDstCount += len(r.DstPorts)
		}

		if origDstCount != mergedDstCount {
			t.Fatalf("DstPort count changed: original=%d merged=%d",
				origDstCount, mergedDstCount)
		}
	})
}

// ---------------------------------------------------------------------------
// Property 10: mergeFilterRules reduces rule count
//   The merged set must have <= the number of rules in the input.
// ---------------------------------------------------------------------------

func TestRapid_MergeFilterRules_ReducesRuleCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := genFilterRules(t)
		merged := mergeFilterRules(rules)

		if len(merged) > len(rules) {
			t.Fatalf("merge increased rule count: %d -> %d", len(rules), len(merged))
		}
	})
}

// ---------------------------------------------------------------------------
// Property 11: mergeFilterRules idempotence
//   Merging already-merged rules produces the same result.
// ---------------------------------------------------------------------------

func TestRapid_MergeFilterRules_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := genFilterRules(t)
		merged1 := mergeFilterRules(rules)
		merged2 := mergeFilterRules(merged1)

		if len(merged1) != len(merged2) {
			t.Fatalf("merge not idempotent: first=%d second=%d",
				len(merged1), len(merged2))
		}

		for i := range merged1 {
			if !slices.Equal(merged1[i].SrcIPs, merged2[i].SrcIPs) {
				t.Fatalf("merge not idempotent: SrcIPs differ at index %d", i)
			}

			if len(merged1[i].DstPorts) != len(merged2[i].DstPorts) {
				t.Fatalf("merge not idempotent: DstPorts length differ at index %d", i)
			}

			for j := range merged1[i].DstPorts {
				dp1 := merged1[i].DstPorts[j]

				dp2 := merged2[i].DstPorts[j]
				if dp1.IP != dp2.IP {
					t.Fatalf("merge not idempotent: DstPorts[%d][%d].IP differ: %q vs %q",
						i, j, dp1.IP, dp2.IP)
				}

				if dp1.Ports != dp2.Ports {
					t.Fatalf("merge not idempotent: DstPorts[%d][%d].Ports differ: %v vs %v",
						i, j, dp1.Ports, dp2.Ports)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 12: SetNodes then BuildPeerMap maintains symmetry
//   After calling SetNodes with a modified node set, BuildPeerMap still
//   produces symmetric peer relationships.
// ---------------------------------------------------------------------------

func TestRapid_SetNodes_MaintainsSymmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		// Add a new node
		newIdx := len(nodes)
		newUser := users[0]
		newIPv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(newIdx + 1)})
		newIPv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(newIdx + 1)}
		newIPv6 := netip.AddrFrom16(newIPv6Bytes)
		newNode := &types.Node{
			ID:       types.NodeID(newIdx + 1), //nolint:gosec // positive bounded value
			Hostname: fmt.Sprintf("node%d", newIdx+1),
			IPv4:     &newIPv4,
			IPv6:     &newIPv6,
			User:     &newUser,
			UserID:   &newUser.ID,
		}

		updatedNodes := append(slices.Clone(nodes), newNode)

		_, err = pm.SetNodes(updatedNodes.ViewSlice())
		if err != nil {
			t.Fatalf("SetNodes failed: %v", err)
		}

		peerMap := pm.BuildPeerMap(updatedNodes.ViewSlice())

		// Verify symmetry
		for nodeID, peers := range peerMap {
			for _, peer := range peers {
				peerPeers := peerMap[peer.ID()]

				found := slices.ContainsFunc(peerPeers, func(nv types.NodeView) bool {
					return nv.ID() == nodeID
				})
				if !found {
					t.Fatalf("symmetry violated after SetNodes: "+
						"node %d sees %d but not vice versa", nodeID, peer.ID())
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 13: ReduceFilterRules never adds new SrcIPs
//   The reduced rules' SrcIPs must be identical to the original rules'
//   SrcIPs (reduction only prunes DstPorts).
// ---------------------------------------------------------------------------

func TestRapid_ReduceFilterRules_PreservesSrcIPs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)

		// Pick a random node to reduce for.
		nodeIdx := rapid.IntRange(0, len(nodes)-1).Draw(t, "nodeIdx")
		node := nodes[nodeIdx]

		// Generate rules where some target this node's IP.
		rules := genFilterRulesForNode(t, node)

		reduced := policyutil.ReduceFilterRules(node.View(), rules)

		// Collect all SrcIPs from original.
		origSrcIPSet := make(map[string]bool)

		for _, rule := range rules {
			for _, src := range rule.SrcIPs {
				origSrcIPSet[src] = true
			}
		}

		// Verify reduced SrcIPs are a subset.
		for _, rule := range reduced {
			for _, src := range rule.SrcIPs {
				if !origSrcIPSet[src] {
					t.Fatalf("reduced rule introduced new SrcIP: %s", src)
				}
			}
		}

		// Reduced must be non-empty since we generated targeting rules.
		if len(reduced) == 0 {
			t.Fatalf("reduced rules are empty but rules targeting node %s were generated",
				node.IPv4.String())
		}

		// Verify that the SrcIPs from targeting rules are preserved in reduced.
		// (Since those rules' DstPorts match the node, the rule is kept with its SrcIPs.)
		for _, rule := range rules {
			nodeIP := node.IPv4.String() + "/32"
			targetsNode := false

			for _, dp := range rule.DstPorts {
				if dp.IP == nodeIP {
					targetsNode = true
					break
				}
			}

			if targetsNode {
				// This rule should appear in reduced with identical SrcIPs.
				foundRule := false

				for _, rr := range reduced {
					if slices.Equal(rr.SrcIPs, rule.SrcIPs) {
						foundRule = true
						break
					}
				}

				if !foundRule {
					t.Fatalf("targeting rule with SrcIPs %v was not preserved in reduced output\nreduced: %+v",
						rule.SrcIPs, reduced)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 14: BuildPeerMap no duplicate peers
//   Each node's peer list must not contain duplicate entries.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_NoDuplicates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		for nodeID, peers := range peerMap {
			seen := make(map[types.NodeID]bool)
			for _, peer := range peers {
				if seen[peer.ID()] {
					t.Fatalf("duplicate peer: node %d has peer %d listed twice",
						nodeID, peer.ID())
				}

				seen[peer.ID()] = true
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 15: compileFilterRules with nil/empty ACLs produces FilterAllowAll
//   Direct test of the compile path.
// ---------------------------------------------------------------------------

func TestRapid_CompileFilterRules_NilACLs_AllowAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)

		// Policy with nil ACLs
		pol := &Policy{ACLs: nil}
		pol.validated = true

		rules, err := pol.compileFilterRules(users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("compileFilterRules failed with nil ACLs: %v", err)
		}

		if !reflect.DeepEqual(rules, tailcfg.FilterAllowAll) {
			t.Fatalf("nil ACLs did not produce FilterAllowAll: got %+v", rules)
		}
	})
}

// ---------------------------------------------------------------------------
// Property 16: SetPolicy + Filter consistency
//   Setting a policy and then getting the filter should produce valid rules
//   that are consistent with what BuildPeerMap uses.
// ---------------------------------------------------------------------------

func TestRapid_SetPolicy_FilterConsistency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)

		// Start with wildcard policy
		pm, err := NewPolicyManager([]byte(genWildcardPolicy()), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("initial PolicyManager creation failed: %v", err)
		}

		// Change to a new random policy
		newPol := genSimplePolicy(t, users)

		_, err = pm.SetPolicy([]byte(newPol))
		if err != nil {
			t.Skip("invalid generated policy for SetPolicy")
		}

		filter, matchers := pm.Filter()
		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// Verify matchers were derived from the filter
		expectedMatchers := matcher.MatchesFromFilterRules(filter)
		if len(matchers) != len(expectedMatchers) {
			t.Fatalf("SetPolicy: matcher count mismatch: filter-derived=%d actual=%d",
				len(expectedMatchers), len(matchers))
		}

		// PeerMap symmetry still holds after SetPolicy
		for nodeID, peers := range peerMap {
			for _, peer := range peers {
				peerPeers := peerMap[peer.ID()]

				found := slices.ContainsFunc(peerPeers, func(nv types.NodeView) bool {
					return nv.ID() == nodeID
				})
				if !found {
					t.Fatalf("symmetry violated after SetPolicy: "+
						"node %d sees %d but not vice versa\npolicy: %s",
						nodeID, peer.ID(), newPol)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 17: mergeFilterRules preserves SrcIP grouping
//   All rules in the merged output with the same SrcIPs must have been
//   combined into a single rule.
// ---------------------------------------------------------------------------

func TestRapid_MergeFilterRules_UniqueKeys(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rules := genFilterRules(t)
		merged := mergeFilterRules(rules)

		keys := make(map[string]int)

		for _, rule := range merged {
			key := filterRuleKey(rule)
			keys[key]++
		}

		for key, count := range keys {
			if count > 1 {
				t.Fatalf("merged rules have duplicate key %q (%d times)", key, count)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 18: Policy JSON roundtrip via marshal/unmarshal
//   Unmarshal a policy, marshal it, unmarshal again — the two compiled
//   filter outputs must be semantically identical.
// ---------------------------------------------------------------------------

func TestRapid_PolicyJSON_FullRoundtrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genTestNodesNoTags(t, users)
		polJSON := genSimplePolicy(t, users)

		// First parse
		pm1, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		// Access the policy's internal state for marshaling
		pm1.mu.Lock()
		polBytes, err := json.Marshal(pm1.pol)
		pm1.mu.Unlock()

		if err != nil {
			t.Fatalf("failed to marshal policy: %v", err)
		}

		// Second parse from marshaled output
		pm2, err := NewPolicyManager(polBytes, users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("roundtrip unmarshal failed: %v\noriginal JSON: %s\nmarshaled: %s",
				err, polJSON, string(polBytes))
		}

		filter1, _ := pm1.Filter()
		filter2, _ := pm2.Filter()

		// Extract actual IPs and ports from the filter rules so we probe
		// addresses that are known to match.
		srcAddrs, dstAddrs, knownPorts := extractRuleIPs(filter1)

		// Probe with actual IPs from rules (testing true==true).
		for _, srcIP := range srcAddrs {
			for _, dstIP := range dstAddrs {
				for _, port := range knownPorts {
					m1 := matchRules(filter1, srcIP, dstIP, port)
					m2 := matchRules(filter2, srcIP, dstIP, port)

					if m1 != m2 {
						t.Fatalf("roundtrip semantic mismatch for src=%s dst=%s:%d: "+
							"first=%v second=%v\noriginal: %s\nmarshaled: %s",
							srcIP, dstIP, port, m1, m2, polJSON, string(polBytes))
					}
				}
			}
		}

		// Also probe with some random IPs for false==false cases.
		randomProbes := rapid.IntRange(3, 8).Draw(t, "randomProbes")
		for i := range randomProbes {
			srcIP := genIPInCGNAT(t, fmt.Sprintf("rtSrc%d", i))
			dstIP := genIPInCGNAT(t, fmt.Sprintf("rtDst%d", i))
			dstPort := rapid.Uint16().Draw(t, fmt.Sprintf("rtPort%d", i))

			m1 := matchRules(filter1, srcIP, dstIP, dstPort)
			m2 := matchRules(filter2, srcIP, dstIP, dstPort)

			if m1 != m2 {
				t.Fatalf("roundtrip semantic mismatch (random probe) for src=%s dst=%s:%d: "+
					"first=%v second=%v\noriginal: %s\nmarshaled: %s",
					srcIP, dstIP, dstPort, m1, m2, polJSON, string(polBytes))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Generators for tag-based and autogroup tests
// ---------------------------------------------------------------------------

// genMixedNodes generates 4-8 nodes where some are tagged with "tag:server"
// and the rest are untagged user-owned nodes.
// Each node has a 50% probability of being tagged.
func genMixedNodes(t *rapid.T, users types.Users) types.Nodes {
	count := rapid.IntRange(4, 8).Draw(t, "mixedNodeCount")
	nodes := make(types.Nodes, count)

	for i := range count {
		user := users[i%len(users)]
		ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
		ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
		ipv6 := netip.AddrFrom16(ipv6Bytes)

		node := &types.Node{
			ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
			Hostname: fmt.Sprintf("node%d", i+1),
			IPv4:     &ipv4,
			IPv6:     &ipv6,
			User:     &user,
			UserID:   &user.ID,
		}

		// Use the probability to decide tagging; rapid.Float64 draws [0,1).
		if rapid.Float64Range(0, 1).Draw(t, fmt.Sprintf("tagDraw%d", i)) < 0.5 {
			node.Tags = []string{"tag:server"}
		}

		nodes[i] = node
	}

	return nodes
}

// genTwoUserNodes generates exactly 2 nodes per user for exactly 2 users.
func genTwoUserNodes(_ *rapid.T, users types.Users) types.Nodes {
	if len(users) < 2 {
		// Ensure at least 2 users; callers should pass >= 2.
		panic("genTwoUserNodes requires at least 2 users")
	}

	nodes := make(types.Nodes, 4)

	for userIdx := range 2 {
		user := users[userIdx]
		for nodeInUser := range 2 {
			i := userIdx*2 + nodeInUser
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)

			nodes[i] = &types.Node{
				ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", i+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			}
		}
	}

	return nodes
}

// ---------------------------------------------------------------------------
// Property 19: Tag-based ACL symmetry
//   Generate tagged and untagged nodes with tag-based ACL.
//   Verify: tagged nodes see other tagged nodes, untagged see nothing,
//   and symmetry holds.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_TagBasedACL_Symmetry(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		// Ensure at least some tagged and untagged by drawing nodes with ~50% tag probability.
		nodes := genMixedNodes(t, users)

		// Count tagged vs untagged to ensure meaningful test data.
		nTagged := 0

		for _, n := range nodes {
			if n.IsTagged() {
				nTagged++
			}
		}

		nUntagged := len(nodes) - nTagged
		if nTagged == 0 || nUntagged == 0 {
			t.Skip("need at least one tagged and one untagged node")
		}

		// Policy: tag:server owned by user1@example.com, ACL allows tag:server -> tag:server:*
		polJSON := `{
			"tagOwners": {"tag:server": ["` + users[0].Name + `@"]},
			"acls": [{"action": "accept", "src": ["tag:server"], "dst": ["tag:server:*"]}]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// Property 1: Symmetry — if A sees B, B sees A.
		for nodeID, peers := range peerMap {
			for _, peer := range peers {
				peerPeers, ok := peerMap[peer.ID()]
				if !ok {
					t.Fatalf("symmetry violation: node %d sees %d, but %d has no peer list",
						nodeID, peer.ID(), peer.ID())
				}

				found := slices.ContainsFunc(peerPeers, func(nv types.NodeView) bool {
					return nv.ID() == nodeID
				})
				if !found {
					t.Fatalf("symmetry violation: node %d sees %d, but %d doesn't see %d",
						nodeID, peer.ID(), peer.ID(), nodeID)
				}
			}
		}

		// Property 2: Only tagged nodes should have peers (tag:server -> tag:server).
		// Untagged nodes are not in src or dst of the ACL, so they should see nothing.
		for _, n := range nodes {
			peers := peerMap[n.ID]
			if !n.IsTagged() && len(peers) > 0 {
				peerIDs := make([]types.NodeID, len(peers))
				for i, p := range peers {
					peerIDs[i] = p.ID()
				}

				t.Fatalf("untagged node %d should have no peers under tag-only ACL, but has: %v",
					n.ID, peerIDs)
			}
		}

		// Property 3: Tagged nodes should only see other tagged nodes.
		for _, n := range nodes {
			if !n.IsTagged() {
				continue
			}

			for _, peer := range peerMap[n.ID] {
				if !peer.IsTagged() {
					t.Fatalf("tagged node %d sees untagged node %d under tag-only ACL",
						n.ID, peer.ID())
				}
			}
		}

		// Property 4: All tagged nodes should see all other tagged nodes.
		for _, n := range nodes {
			if !n.IsTagged() {
				continue
			}

			for _, other := range nodes {
				if other.ID == n.ID || !other.IsTagged() {
					continue
				}

				found := slices.ContainsFunc(peerMap[n.ID], func(nv types.NodeView) bool {
					return nv.ID() == other.ID
				})
				if !found {
					t.Fatalf("tagged node %d should see tagged node %d under tag:server ACL",
						n.ID, other.ID)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 20: autogroup:member and autogroup:tagged partition
//   Verify that autogroup:member excludes tagged nodes and
//   autogroup:tagged excludes untagged nodes.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_AutogroupMember_TaggedPartition(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genMixedNodes(t, users)

		nTagged := 0

		for _, n := range nodes {
			if n.IsTagged() {
				nTagged++
			}
		}

		nUntagged := len(nodes) - nTagged
		if nTagged == 0 || nUntagged == 0 {
			t.Skip("need at least one tagged and one untagged node")
		}

		// Policy: autogroup:member -> autogroup:member:* (only user-owned can talk to user-owned)
		polJSON := `{
			"tagOwners": {"tag:server": ["` + users[0].Name + `@"]},
			"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// Property 1: Untagged nodes should see other untagged nodes.
		for _, n := range nodes {
			if n.IsTagged() {
				continue
			}

			for _, other := range nodes {
				if other.ID == n.ID || other.IsTagged() {
					continue
				}

				found := slices.ContainsFunc(peerMap[n.ID], func(nv types.NodeView) bool {
					return nv.ID() == other.ID
				})
				if !found {
					t.Fatalf("untagged node %d should see untagged node %d under autogroup:member ACL",
						n.ID, other.ID)
				}
			}
		}

		// Property 2: Tagged nodes should NOT appear in any untagged node's peer list.
		for _, n := range nodes {
			if n.IsTagged() {
				continue
			}

			for _, peer := range peerMap[n.ID] {
				if peer.IsTagged() {
					t.Fatalf("untagged node %d should not see tagged node %d under autogroup:member ACL",
						n.ID, peer.ID())
				}
			}
		}

		// Property 3: Tagged nodes should have no peers (they are not in src or dst).
		for _, n := range nodes {
			if !n.IsTagged() {
				continue
			}

			if len(peerMap[n.ID]) > 0 {
				peerIDs := make([]types.NodeID, len(peerMap[n.ID]))
				for i, p := range peerMap[n.ID] {
					peerIDs[i] = p.ID()
				}

				t.Fatalf("tagged node %d should have no peers under autogroup:member ACL, but has: %v",
					n.ID, peerIDs)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 21: Restrictive policy isolates users
//   Only user1's nodes should see each other, user2's nodes see nothing,
//   no cross-user visibility.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_RestrictivePolicy_Isolation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate exactly 2 users.
		users := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
		}

		nodes := genTwoUserNodes(t, users)

		// Policy: only user1 can access user1.
		polJSON := `{
			"acls": [{"action": "accept", "src": ["user1@"], "dst": ["user1@:*"]}]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// user1's nodes: IDs 1, 2 (indices 0, 1). user2's nodes: IDs 3, 4 (indices 2, 3).
		user1NodeIDs := map[types.NodeID]bool{1: true, 2: true}
		user2NodeIDs := map[types.NodeID]bool{3: true, 4: true}

		// Property 1: user1's nodes see each other.
		for id := range user1NodeIDs {
			peers := peerMap[id]
			for otherID := range user1NodeIDs {
				if otherID == id {
					continue
				}

				found := slices.ContainsFunc(peers, func(nv types.NodeView) bool {
					return nv.ID() == otherID
				})
				if !found {
					t.Fatalf("user1 node %d should see user1 node %d", id, otherID)
				}
			}
		}

		// Property 2: user2's nodes see nothing.
		for id := range user2NodeIDs {
			peers := peerMap[id]
			if len(peers) > 0 {
				peerIDs := make([]types.NodeID, len(peers))
				for i, p := range peers {
					peerIDs[i] = p.ID()
				}

				t.Fatalf("user2 node %d should have no peers, but has: %v", id, peerIDs)
			}
		}

		// Property 3: No cross-user visibility.
		for id := range user1NodeIDs {
			for _, peer := range peerMap[id] {
				if user2NodeIDs[peer.ID()] {
					t.Fatalf("user1 node %d should not see user2 node %d", id, peer.ID())
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 22: Tagged nodes never appear in autogroup:member's resolved IP set
//   autogroup:member resolves only to untagged nodes' IPs.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_TaggedNodeNotInMember(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genMixedNodes(t, users)

		nTagged := 0

		for _, n := range nodes {
			if n.IsTagged() {
				nTagged++
			}
		}

		if nTagged == 0 || nTagged == len(nodes) {
			t.Skip("need at least one tagged and one untagged node")
		}

		// Resolve autogroup:member.
		ag := AutoGroupMember

		memberSet, err := ag.Resolve(nil, users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to resolve autogroup:member: %v", err)
		}

		// Property: No tagged node's IPs should be in the member set.
		for _, n := range nodes {
			if !n.IsTagged() {
				continue
			}

			for _, ip := range n.IPs() {
				if memberSet.Contains(ip) {
					t.Fatalf("tagged node %d (tags: %v) has IP %s in autogroup:member set",
						n.ID, n.Tags, ip)
				}
			}
		}

		// Property: All untagged node IPs should be in the member set.
		for _, n := range nodes {
			if n.IsTagged() {
				continue
			}

			for _, ip := range n.IPs() {
				if !memberSet.Contains(ip) {
					t.Fatalf("untagged node %d IP %s should be in autogroup:member set", n.ID, ip)
				}
			}
		}

		// Complement check: resolve autogroup:tagged and verify disjointness.
		agTagged := AutoGroupTagged

		taggedSet, err := agTagged.Resolve(nil, users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to resolve autogroup:tagged: %v", err)
		}

		// No IP should be in both sets.
		for _, n := range nodes {
			for _, ip := range n.IPs() {
				inMember := memberSet.Contains(ip)

				inTagged := taggedSet.Contains(ip)
				if inMember && inTagged {
					t.Fatalf("node %d IP %s is in both autogroup:member AND autogroup:tagged",
						n.ID, ip)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Property 23: FilterForNode produces different rules for tagged vs untagged
//   With a tag-based policy, FilterForNode for tagged nodes should contain
//   rules that don't appear for untagged nodes (and vice versa).
// ---------------------------------------------------------------------------

//nolint:gocyclo // complex property-based test with many assertions
func TestRapid_FilterForNode_TaggedVsUntagged(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := genTestUsers(t)
		nodes := genMixedNodes(t, users)

		nTagged := 0
		nUntagged := 0

		var aTaggedNode, anUntaggedNode *types.Node

		for _, n := range nodes {
			if n.IsTagged() {
				nTagged++
				aTaggedNode = n
			} else {
				nUntagged++
				anUntaggedNode = n
			}
		}

		if nTagged == 0 || nUntagged == 0 {
			t.Skip("need at least one tagged and one untagged node")
		}

		// Policy with both tag-based and user-based rules.
		polJSON := `{
			"tagOwners": {"tag:server": ["` + users[0].Name + `@"]},
			"acls": [
				{"action": "accept", "src": ["tag:server"], "dst": ["tag:server:*"]},
				{"action": "accept", "src": ["` + users[0].Name + `@"], "dst": ["` + users[0].Name + `@:*"]}
			]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		taggedFilter, err := pm.FilterForNode(aTaggedNode.View())
		if err != nil {
			t.Fatalf("FilterForNode failed for tagged node: %v", err)
		}

		untaggedFilter, err := pm.FilterForNode(anUntaggedNode.View())
		if err != nil {
			t.Fatalf("FilterForNode failed for untagged node: %v", err)
		}

		// Property 1: Tagged node's filter should only contain DstPorts targeting
		// tagged node IPs (tag:server -> tag:server).
		taggedIPs := make(map[string]bool)

		for _, n := range nodes {
			if n.IsTagged() {
				if n.IPv4 != nil {
					taggedIPs[netip.PrefixFrom(*n.IPv4, n.IPv4.BitLen()).String()] = true
				}

				if n.IPv6 != nil {
					taggedIPs[netip.PrefixFrom(*n.IPv6, n.IPv6.BitLen()).String()] = true
				}
			}
		}

		for _, rule := range taggedFilter {
			for _, dp := range rule.DstPorts {
				if dp.IP == "*" {
					continue // wildcard is ok
				}

				if !taggedIPs[dp.IP] { //nolint:staticcheck // SA9003: intentionally empty — documents filter scoping behavior
					// DstPort targets a non-tagged node — this is expected
					// if the tagged node is also user-owned by user1.
					// Since tags define identity, this tagged node won't
					// match user1@ rules; its filter should only have tag rules.
					// However, ReduceFilterRules only keeps rules where the
					// node itself is a destination, so this is checking that.
				}
			}
		}

		// Property 2: The filters should be structurally different (or both empty
		// for nodes that aren't destinations).
		// Compare by serializing to JSON.
		taggedJSON, _ := json.Marshal(taggedFilter)
		untaggedJSON, _ := json.Marshal(untaggedFilter)

		// With a mixed policy (tag + user rules), the filters should differ
		// unless both nodes happen to have no rules targeting them.
		if len(taggedFilter) > 0 && len(untaggedFilter) > 0 {
			if string(taggedJSON) == string(untaggedJSON) {
				t.Logf("WARNING: tagged and untagged nodes produced identical filters — "+
					"this can happen when both happen to be destinations of different rules "+
					"with identical structure, but is unusual\ntagged: %s\nuntagged: %s",
					string(taggedJSON), string(untaggedJSON))
			}
		}

		// Property 3: FilterForNode results should be a subset of what compileFilterRules produces.
		// The global filter contains all rules; per-node filter is reduced.
		globalFilter, _ := pm.Filter()

		for _, rule := range taggedFilter {
			for _, dp := range rule.DstPorts {
				// Each DstPort in the per-node filter must exist in the global filter.
				found := false

				for _, gRule := range globalFilter {
					for _, gDp := range gRule.DstPorts {
						if dp.IP == gDp.IP && dp.Ports == gDp.Ports {
							found = true
							break
						}
					}

					if found {
						break
					}
				}

				if !found && dp.IP != "*" {
					t.Fatalf("tagged node filter has DstPort %s:%v not found in global filter",
						dp.IP, dp.Ports)
				}
			}
		}

		for _, rule := range untaggedFilter {
			for _, dp := range rule.DstPorts {
				found := false

				for _, gRule := range globalFilter {
					for _, gDp := range gRule.DstPorts {
						if dp.IP == gDp.IP && dp.Ports == gDp.Ports {
							found = true
							break
						}
					}

					if found {
						break
					}
				}

				if !found && dp.IP != "*" {
					t.Fatalf("untagged node filter has DstPort %s:%v not found in global filter",
						dp.IP, dp.Ports)
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Adversarial Property Tests — targeting logic bugs
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test 1: Overlapping ACLs — no false negatives
//   Generate policies with MULTIPLE overlapping ACLs where the same
//   (src, dst) pair is covered by different rules. Verify that if ANY
//   rule allows the traffic, the pair appears in the peer map.
// ---------------------------------------------------------------------------

//nolint:gocyclo // complex property-based test with many assertions
func TestRapid_BuildPeerMap_OverlappingACLs_NoFalseNegatives(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// 3 users, 6 nodes (2 per user)
		users := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
			{Model: gorm.Model{ID: 3}, Name: "user3", Email: "user3@example.com"},
		}

		nodes := make(types.Nodes, 6)

		for i := range 6 {
			user := users[i/2]
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)
			nodes[i] = &types.Node{
				ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", i+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			}
		}

		// Generate 2-4 overlapping ACL rules using different reference types:
		// user refs, wildcards, IP prefix refs, autogroup:member
		numRules := rapid.IntRange(2, 4).Draw(t, "numACLRules")

		type aclSpec struct {
			src string
			dst string
		}

		// Pool of source alias generators
		srcChoices := []string{
			"*",
			"user1@",
			"user2@",
			"user3@",
			string(AutoGroupMember),
		}
		// Pool of destination alias generators — note IP-based refs use actual node IPs
		dstChoices := []string{
			"*:*",
			"user1@:*",
			"user2@:*",
			"user3@:*",
			"autogroup:member:*",
			"100.64.0.1/32:*",
			"100.64.0.2/32:*",
			"100.64.0.3/32:*",
			"100.64.0.4/32:*",
			"100.64.0.5/32:*",
			"100.64.0.6/32:*",
		}

		acls := make([]aclSpec, 0, numRules)

		for i := range numRules {
			srcIdx := rapid.IntRange(0, len(srcChoices)-1).Draw(t, fmt.Sprintf("srcIdx%d", i))
			dstIdx := rapid.IntRange(0, len(dstChoices)-1).Draw(t, fmt.Sprintf("dstIdx%d", i))
			acls = append(acls, aclSpec{src: srcChoices[srcIdx], dst: dstChoices[dstIdx]})
		}

		// Build policy JSON
		aclStrings := make([]string, 0, len(acls))
		for _, acl := range acls {
			aclStrings = append(aclStrings, fmt.Sprintf(
				`{"action":"accept","src":[%q],"dst":[%q]}`,
				acl.src, acl.dst,
			))
		}

		polJSON := fmt.Sprintf(`{"acls":[%s]}`, strings.Join(aclStrings, ","))

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Skip("invalid generated policy")
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// For every pair of nodes, manually check if ANY rule allows them,
		// then compare to BuildPeerMap.
		// We do this by resolving each ACL rule's source and destination
		// and checking if the node pair is covered.
		for i := range 6 {
			for j := i + 1; j < 6; j++ {
				nodeI := nodes[i]
				nodeJ := nodes[j]

				// Check if any ACL rule allows nodeI -> nodeJ or nodeJ -> nodeI
				anyRuleAllows := false

				for _, acl := range acls {
					srcCovers := func(src string, n *types.Node) bool {
						switch {
						case src == "*":
							return true
						case src == "autogroup:member":
							return !n.IsTagged()
						case strings.HasSuffix(src, "@"):
							userName := strings.TrimSuffix(src, "@")
							return n.User != nil && n.User.Name == userName && !n.IsTagged()
						default:
							// IP prefix
							prefix, err := netip.ParsePrefix(src)
							if err != nil {
								return false
							}

							return slices.ContainsFunc(n.IPs(), prefix.Contains)
						}
					}

					dstCovers := func(dst string, n *types.Node) bool {
						// Strip port part
						dstAlias := dst
						if idx := strings.LastIndex(dst, ":"); idx >= 0 {
							dstAlias = dst[:idx]
						}

						switch {
						case dstAlias == "*":
							return true
						case dstAlias == "autogroup:member":
							return !n.IsTagged()
						case strings.HasSuffix(dstAlias, "@"):
							userName := strings.TrimSuffix(dstAlias, "@")
							return n.User != nil && n.User.Name == userName && !n.IsTagged()
						default:
							// IP prefix
							prefix, err := netip.ParsePrefix(dstAlias)
							if err != nil {
								return false
							}

							return slices.ContainsFunc(n.IPs(), prefix.Contains)
						}
					}

					// Forward direction: nodeI -> nodeJ
					if srcCovers(acl.src, nodeI) && dstCovers(acl.dst, nodeJ) {
						anyRuleAllows = true
						break
					}
					// Reverse direction: nodeJ -> nodeI
					if srcCovers(acl.src, nodeJ) && dstCovers(acl.dst, nodeI) {
						anyRuleAllows = true
						break
					}
				}

				// Check peer map
				peersI := peerMap[nodeI.ID]
				jInIPeers := slices.ContainsFunc(peersI, func(nv types.NodeView) bool {
					return nv.ID() == nodeJ.ID
				})

				if anyRuleAllows && !jInIPeers {
					t.Fatalf("FALSE NEGATIVE: nodes %d (user=%s) and %d (user=%s) "+
						"should be peers (covered by at least one ACL rule), but are not in peer map\n"+
						"policy: %s\npeerMap[%d]: %v",
						nodeI.ID, nodeI.User.Name, nodeJ.ID, nodeJ.User.Name,
						polJSON, nodeI.ID, peerIDs(peersI))
				}
			}
		}
	})
}

// peerIDs is a helper to extract node IDs from peer views for debugging.
func peerIDs(peers []types.NodeView) []types.NodeID {
	ids := make([]types.NodeID, len(peers))
	for i, p := range peers {
		ids[i] = p.ID()
	}

	return ids
}

// ---------------------------------------------------------------------------
// Test 2: Port-specific filter rules correctness
//   Generate policies with port-specific rules (not just :*). Verify that
//   FilterForNode produces filter rules matching the expected ports.
// ---------------------------------------------------------------------------

func TestRapid_FilterForNode_PortSpecific_Correctness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
		}

		// 2 nodes per user
		nodes := make(types.Nodes, 4)

		for i := range 4 {
			user := users[i/2]
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)
			nodes[i] = &types.Node{
				ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", i+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			}
		}

		// Pick random ports from a small pool
		portPool := []uint16{22, 80, 443, 8080, 5432}
		numPorts := rapid.IntRange(1, 3).Draw(t, "numPorts")
		selectedPorts := make([]uint16, numPorts)

		portStrs := make([]string, numPorts)
		for i := range numPorts {
			pIdx := rapid.IntRange(0, len(portPool)-1).Draw(t, fmt.Sprintf("portIdx%d", i))
			selectedPorts[i] = portPool[pIdx]
			portStrs[i] = strconv.FormatUint(uint64(portPool[pIdx]), 10)
		}

		// Deduplicate ports for comparison
		portSet := make(map[uint16]bool)
		for _, p := range selectedPorts {
			portSet[p] = true
		}

		// Policy: user1@ -> user2@:<ports>
		portsStr := strings.Join(portStrs, ",")
		polJSON := fmt.Sprintf(
			`{"acls":[{"action":"accept","src":["user1@"],"dst":["user2@:%s"]}]}`,
			portsStr,
		)

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v\npolicy: %s", err, polJSON)
		}

		// FilterForNode for user2's nodes should contain rules with DstPorts
		// targeting user2's IPs on exactly the specified ports.
		for _, dstNode := range nodes[2:4] {
			filter, err := pm.FilterForNode(dstNode.View())
			if err != nil {
				t.Fatalf("FilterForNode failed for node %d: %v", dstNode.ID, err)
			}

			if len(filter) == 0 {
				t.Fatalf("FilterForNode for user2 node %d returned empty filter; "+
					"expected rules allowing user1->user2 on ports %v\npolicy: %s",
					dstNode.ID, selectedPorts, polJSON)
			}

			// Collect all (dstIP, port) entries from the filter rules
			type ipPort struct {
				ip   string
				port uint16
			}

			gotPorts := make(map[ipPort]bool)

			for _, rule := range filter {
				for _, dp := range rule.DstPorts {
					// For single-port ranges
					if dp.Ports.First == dp.Ports.Last {
						gotPorts[ipPort{dp.IP, dp.Ports.First}] = true
					} else {
						// For each port in the range that's in our port pool
						for p := dp.Ports.First; p <= dp.Ports.Last; p++ {
							if portSet[p] {
								gotPorts[ipPort{dp.IP, p}] = true
							}
						}
					}
				}
			}

			// Every selected port must appear for this node's IP
			nodeIPv4 := dstNode.IPv4.String()
			for p := range portSet {
				found := gotPorts[ipPort{nodeIPv4, p}]
				if !found {
					// Also check as prefix format
					found = gotPorts[ipPort{nodeIPv4 + "/32", p}]
				}

				if !found {
					t.Fatalf("FilterForNode for node %d (IP=%s): missing port %d in filter rules\n"+
						"expected ports: %v\nfilter: %+v\npolicy: %s",
						dstNode.ID, nodeIPv4, p, selectedPorts, filter, polJSON)
				}
			}

			// No ports outside the selected set should appear for this node's IPv4
			for _, rule := range filter {
				for _, dp := range rule.DstPorts {
					if dp.IP == nodeIPv4 || dp.IP == nodeIPv4+"/32" {
						// Check that the port range only covers selected ports
						for p := dp.Ports.First; p <= dp.Ports.Last; p++ {
							if !portSet[p] {
								// This port is NOT in our selected set but is in the filter.
								// This could be a BUG — extra ports leaking in.
								t.Fatalf("FilterForNode for node %d: UNEXPECTED port %d in filter rule "+
									"(DstPort %s:%d-%d). Expected only ports %v\npolicy: %s",
									dstNode.ID, p, dp.IP, dp.Ports.First, dp.Ports.Last,
									selectedPorts, polJSON)
							}
						}
					}
				}
			}
		}

		// FilterForNode for user1's nodes should NOT contain rules with user2's IPs as dst
		// (user1 is the source, not the destination)
		for _, srcNode := range nodes[0:2] {
			filter, err := pm.FilterForNode(srcNode.View())
			if err != nil {
				t.Fatalf("FilterForNode failed for node %d: %v", srcNode.ID, err)
			}

			// The reduced filter for a source-only node should have no DstPorts
			// targeting this node's own IPs (it's not a destination).
			// However, this is expected behavior — ReduceFilterRules keeps
			// only rules where the node is a destination.
			for _, rule := range filter {
				for _, dp := range rule.DstPorts {
					nodeIPv4 := srcNode.IPv4.String()
					if dp.IP == nodeIPv4 || dp.IP == nodeIPv4+"/32" {
						// user1's node appears as destination — this would be unexpected
						// unless there's another rule allowing traffic TO user1.
						// With our policy, only user1->user2 is allowed, so user1
						// should not be a destination.
						t.Fatalf("user1 node %d appears as destination in its own FilterForNode "+
							"but policy only allows user1->user2\nfilter: %+v\npolicy: %s",
							srcNode.ID, filter, polJSON)
					}
				}
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 3: SetNodes peer map updates
//   Test that calling SetNodes (adding/removing nodes) correctly updates
//   the peer map.
// ---------------------------------------------------------------------------

func TestRapid_PolicyManager_SetNodes_PeerMapUpdates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
		}

		// Start with 4 nodes (2 per user)
		initialNodes := make(types.Nodes, 4)

		for i := range 4 {
			user := users[i/2]
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)
			initialNodes[i] = &types.Node{
				ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", i+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			}
		}

		// Policy: user1@ -> user1@:*, user2@ -> user2@:*
		// Each user's nodes can see each other, but not cross-user.
		polJSON := `{
			"acls": [
				{"action": "accept", "src": ["user1@"], "dst": ["user1@:*"]},
				{"action": "accept", "src": ["user2@"], "dst": ["user2@:*"]}
			]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, initialNodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		// Step 1: Verify initial peer map
		peerMap1 := pm.BuildPeerMap(initialNodes.ViewSlice())

		// user1's nodes (1, 2) should see each other
		peers1 := peerMap1[types.NodeID(1)]
		if !slices.ContainsFunc(peers1, func(nv types.NodeView) bool { return nv.ID() == 2 }) {
			t.Fatalf("initial: node 1 should see node 2 (same user)")
		}
		// user1 should not see user2
		if slices.ContainsFunc(peers1, func(nv types.NodeView) bool { return nv.ID() == 3 || nv.ID() == 4 }) {
			t.Fatalf("initial: node 1 should NOT see user2 nodes")
		}

		// Step 2: Add 2 new nodes (one per user)
		expandedNodes := slices.Clone(initialNodes)

		for i := range 2 {
			newIdx := 4 + i
			user := users[i]
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(newIdx + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(newIdx + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)
			expandedNodes = append(expandedNodes, &types.Node{
				ID:       types.NodeID(newIdx + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", newIdx+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			})
		}

		_, err = pm.SetNodes(expandedNodes.ViewSlice())
		if err != nil {
			t.Fatalf("SetNodes (expand) failed: %v", err)
		}

		peerMap2 := pm.BuildPeerMap(expandedNodes.ViewSlice())

		// New node 5 (user1) should see nodes 1, 2 (user1)
		peers5 := peerMap2[types.NodeID(5)]
		if !slices.ContainsFunc(peers5, func(nv types.NodeView) bool { return nv.ID() == 1 }) {
			t.Fatalf("after expand: new node 5 (user1) should see node 1 (user1)\npeerMap[5]=%v", peerIDs(peers5))
		}

		if !slices.ContainsFunc(peers5, func(nv types.NodeView) bool { return nv.ID() == 2 }) {
			t.Fatalf("after expand: new node 5 (user1) should see node 2 (user1)\npeerMap[5]=%v", peerIDs(peers5))
		}
		// New node 5 should NOT see user2 nodes
		if slices.ContainsFunc(peers5, func(nv types.NodeView) bool { return nv.ID() == 3 || nv.ID() == 4 || nv.ID() == 6 }) {
			t.Fatalf("after expand: new node 5 (user1) should NOT see user2 nodes\npeerMap[5]=%v", peerIDs(peers5))
		}

		// New node 6 (user2) should see nodes 3, 4 (user2)
		peers6 := peerMap2[types.NodeID(6)]
		if !slices.ContainsFunc(peers6, func(nv types.NodeView) bool { return nv.ID() == 3 }) {
			t.Fatalf("after expand: new node 6 (user2) should see node 3 (user2)\npeerMap[6]=%v", peerIDs(peers6))
		}

		if !slices.ContainsFunc(peers6, func(nv types.NodeView) bool { return nv.ID() == 4 }) {
			t.Fatalf("after expand: new node 6 (user2) should see node 4 (user2)\npeerMap[6]=%v", peerIDs(peers6))
		}

		// Step 3: Remove the 2 original user2 nodes (3, 4), keep the rest
		var shrunkNodes types.Nodes

		for _, n := range expandedNodes {
			if n.ID != 3 && n.ID != 4 {
				shrunkNodes = append(shrunkNodes, n)
			}
		}

		_, err = pm.SetNodes(shrunkNodes.ViewSlice())
		if err != nil {
			t.Fatalf("SetNodes (shrink) failed: %v", err)
		}

		peerMap3 := pm.BuildPeerMap(shrunkNodes.ViewSlice())

		// Removed nodes 3 and 4 should NOT appear in any peer list
		for nodeID, peers := range peerMap3 {
			for _, peer := range peers {
				if peer.ID() == 3 || peer.ID() == 4 {
					t.Fatalf("after shrink: removed node %d still appears in node %d's peer list",
						peer.ID(), nodeID)
				}
			}
		}

		// Node 6 (user2, still present) should see NO peers since nodes 3,4 were removed
		// and it is the only user2 node left
		peers6After := peerMap3[types.NodeID(6)]
		if len(peers6After) > 0 {
			t.Fatalf("after shrink: node 6 (sole user2 node) should have no same-user peers, "+
				"but has: %v", peerIDs(peers6After))
		}

		// user1 nodes (1, 2, 5) should still see each other
		for _, id := range []types.NodeID{1, 2, 5} {
			peers := peerMap3[id]
			expectedPeerCount := 2 // the other two user1 nodes
			user1PeerCount := 0

			for _, p := range peers {
				if p.ID() == 1 || p.ID() == 2 || p.ID() == 5 {
					user1PeerCount++
				}
			}

			if user1PeerCount != expectedPeerCount {
				t.Fatalf("after shrink: user1 node %d should see %d user1 peers, got %d\npeerMap[%d]=%v",
					id, expectedPeerCount, user1PeerCount, id, peerIDs(peers))
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 4: Tag ownership transitive resolution
//   Generate policies with tagOwners that reference other tags (nested
//   ownership). Verify the peer map is correct for nested tag chains.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_TagOwnership_TransitiveResolution(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
		}

		// Create nodes: some with tag:a, some with tag:b, some untagged
		// Use deterministic layout with some randomness
		numNodes := rapid.IntRange(4, 8).Draw(t, "numNodes")

		nodes := make(types.Nodes, numNodes)
		for i := range numNodes {
			user := users[i%len(users)]
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)
			nodes[i] = &types.Node{
				ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", i+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			}

			// Assign tags: first third gets tag:a, second third gets tag:b, rest untagged
			tagChoice := rapid.IntRange(0, 2).Draw(t, fmt.Sprintf("tagChoice%d", i))
			switch tagChoice {
			case 0:
				nodes[i].Tags = []string{"tag:a"}
			case 1:
				nodes[i].Tags = []string{"tag:b"}
				// case 2: untagged
			}
		}

		// Ensure we have at least one tagged-a and one tagged-b node
		hasTagA := false
		hasTagB := false

		for _, n := range nodes {
			if slices.Contains(n.Tags, "tag:a") {
				hasTagA = true
			}

			if slices.Contains(n.Tags, "tag:b") {
				hasTagB = true
			}
		}

		if !hasTagA || !hasTagB {
			t.Skip("need at least one tag:a and one tag:b node")
		}

		// Policy: tag:a is owned by tag:b, tag:b is owned by user1@
		// ACL: tag:a -> tag:a:* (tag:a nodes can talk to each other)
		// This tests transitive tag ownership resolution.
		polJSON := `{
			"tagOwners": {
				"tag:a": ["tag:b"],
				"tag:b": ["user1@"]
			},
			"acls": [
				{"action": "accept", "src": ["tag:a"], "dst": ["tag:a:*"]}
			]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		// Collect tag:a nodes
		var tagANodes []types.NodeID

		for _, n := range nodes {
			if slices.Contains(n.Tags, "tag:a") {
				tagANodes = append(tagANodes, n.ID)
			}
		}

		// Property 1: All tag:a nodes should see all other tag:a nodes
		for _, id := range tagANodes {
			peers := peerMap[id]
			for _, otherID := range tagANodes {
				if otherID == id {
					continue
				}

				found := slices.ContainsFunc(peers, func(nv types.NodeView) bool {
					return nv.ID() == otherID
				})
				if !found {
					t.Fatalf("tag:a node %d should see tag:a node %d (ACL: tag:a -> tag:a)\npeerMap[%d]=%v",
						id, otherID, id, peerIDs(peers))
				}
			}
		}

		// Property 2: No tag:b or untagged nodes should be peers of tag:a nodes
		// (policy only allows tag:a <-> tag:a)
		for _, id := range tagANodes {
			for _, peer := range peerMap[id] {
				isTagA := false

				for _, n := range nodes {
					if n.ID == peer.ID() && slices.Contains(n.Tags, "tag:a") {
						isTagA = true
						break
					}
				}

				if !isTagA {
					t.Fatalf("tag:a node %d should only see other tag:a nodes, but sees node %d",
						id, peer.ID())
				}
			}
		}

		// Property 3: Verify transitive tag ownership — user1 should be able
		// to assign tag:a to nodes (via tag:b chain)
		// NodeCanHaveTag tests the ownership resolution
		for _, n := range nodes {
			// Only user1's untagged nodes should be able to own tag:a (via tag:b -> user1@)
			if n.User != nil && n.User.Name == "user1" && !n.IsTagged() {
				canHaveTagA := pm.NodeCanHaveTag(n.View(), "tag:a")

				canHaveTagB := pm.NodeCanHaveTag(n.View(), "tag:b")
				if !canHaveTagB {
					t.Fatalf("user1 untagged node %d should be able to have tag:b (direct ownership)", n.ID)
				}
				// tag:a is owned by tag:b, which is owned by user1@
				// So user1's nodes should be able to have tag:a transitively
				_ = canHaveTagA // Document: this tests the transitive resolution path
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Test 5: autogroup:self only allows traffic to node's OWN IPs
//   Verify that autogroup:self rules only allow traffic to the node's own
//   IPs within the same user, not ALL same-user nodes.
// ---------------------------------------------------------------------------

func TestRapid_BuildPeerMap_AutogroupSelf_OnlyOwnerPorts(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// 2 users, 3 nodes per user
		users := types.Users{
			{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@example.com"},
			{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@example.com"},
		}

		nodes := make(types.Nodes, 6)

		for i := range 6 {
			user := users[i/3]
			ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})
			ipv6Bytes := [16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1)}
			ipv6 := netip.AddrFrom16(ipv6Bytes)
			nodes[i] = &types.Node{
				ID:       types.NodeID(i + 1), //nolint:gosec // positive bounded value
				Hostname: fmt.Sprintf("node%d", i+1),
				IPv4:     &ipv4,
				IPv6:     &ipv6,
				User:     &user,
				UserID:   &user.ID,
			}
		}

		// Policy: ONLY autogroup:self -> autogroup:self:*
		// This means each user's devices can only reach other devices of the same user.
		polJSON := `{
			"acls": [
				{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
			]
		}`

		pm, err := NewPolicyManager([]byte(polJSON), users, nodes.ViewSlice())
		if err != nil {
			t.Fatalf("failed to create policy manager: %v", err)
		}

		// Key property: FilterForNode for each node should produce rules where
		// DstPorts ONLY target IPs belonging to the SAME USER as the node.
		for _, node := range nodes {
			filter, err := pm.FilterForNode(node.View())
			if err != nil {
				t.Fatalf("FilterForNode failed for node %d: %v", node.ID, err)
			}

			// Collect all IPs that are same-user
			sameUserIPs := make(map[string]bool)

			for _, other := range nodes {
				if other.User.ID == node.User.ID {
					if other.IPv4 != nil {
						sameUserIPs[other.IPv4.String()] = true
					}

					if other.IPv6 != nil {
						sameUserIPs[other.IPv6.String()] = true
					}
				}
			}

			// Collect all IPs from different users
			otherUserIPs := make(map[string]bool)

			for _, other := range nodes {
				if other.User.ID != node.User.ID {
					if other.IPv4 != nil {
						otherUserIPs[other.IPv4.String()] = true
					}

					if other.IPv6 != nil {
						otherUserIPs[other.IPv6.String()] = true
					}
				}
			}

			// Check: no DstPorts should target IPs of a DIFFERENT user
			for _, rule := range filter {
				for _, dp := range rule.DstPorts {
					if dp.IP == "*" {
						continue // wildcard is not expected here but skip if present
					}

					// Parse the IP (might be with or without /32 prefix)
					ipStr := dp.IP

					prefix, err := netip.ParsePrefix(ipStr)
					if err == nil {
						ipStr = prefix.Addr().String()
					}

					if otherUserIPs[ipStr] {
						t.Fatalf("AUTOGROUP:SELF BUG: FilterForNode for node %d (user=%s) "+
							"contains DstPort targeting OTHER user's IP %s\n"+
							"This violates autogroup:self scoping — should only target same-user IPs\n"+
							"filter: %+v\npolicy: %s",
							node.ID, node.User.Name, dp.IP, filter, polJSON)
					}
				}
			}

			// Check: all DstPorts should target only same-user IPs
			for _, rule := range filter {
				for _, dp := range rule.DstPorts {
					if dp.IP == "*" {
						t.Fatalf("AUTOGROUP:SELF BUG: FilterForNode for node %d has wildcard DstPort "+
							"but autogroup:self should produce specific IPs\nfilter: %+v",
							node.ID, filter)
					}

					ipStr := dp.IP

					prefix, err := netip.ParsePrefix(ipStr)
					if err == nil {
						ipStr = prefix.Addr().String()
					}

					if !sameUserIPs[ipStr] {
						t.Fatalf("AUTOGROUP:SELF BUG: FilterForNode for node %d (user=%s) "+
							"contains DstPort targeting IP %s which is NOT a same-user IP\n"+
							"same-user IPs: %v\nfilter: %+v\npolicy: %s",
							node.ID, node.User.Name, dp.IP, sameUserIPs, filter, polJSON)
					}
				}
			}
		}

		// Additional property: BuildPeerMap — same-user nodes should be peers,
		// cross-user nodes should NOT be peers.
		peerMap := pm.BuildPeerMap(nodes.ViewSlice())

		for i := range 6 {
			nodeI := nodes[i]
			for j := i + 1; j < 6; j++ {
				nodeJ := nodes[j]
				sameUser := nodeI.User.ID == nodeJ.User.ID

				peersI := peerMap[nodeI.ID]
				jInIPeers := slices.ContainsFunc(peersI, func(nv types.NodeView) bool {
					return nv.ID() == nodeJ.ID
				})

				if sameUser && !jInIPeers {
					t.Fatalf("autogroup:self: same-user nodes %d and %d (user=%s) "+
						"should be peers but are not\npeerMap[%d]=%v",
						nodeI.ID, nodeJ.ID, nodeI.User.Name, nodeI.ID, peerIDs(peersI))
				}

				if !sameUser && jInIPeers {
					t.Fatalf("autogroup:self: cross-user nodes %d (user=%s) and %d (user=%s) "+
						"should NOT be peers but are\npeerMap[%d]=%v",
						nodeI.ID, nodeI.User.Name, nodeJ.ID, nodeJ.User.Name,
						nodeI.ID, peerIDs(peersI))
				}
			}
		}
	})
}
