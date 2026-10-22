package policyutil

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

// ReduceFilterRules takes a node and a set of global filter rules and removes all rules
// and destinations that are not relevant to that particular node.
//
// IMPORTANT: This function is designed for global filters only. Per-node filters
// (from autogroup:self policies) are already node-specific and should not be passed
// to this function. Use [policy.PolicyManager.FilterForNode] instead, which handles
// both cases.
func ReduceFilterRules(node types.NodeView, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}
	nodeIPs := node.IPs()
	subnetRoutes := node.SubnetRoutes()
	exitRoutes := node.ExitRoutes()

	for _, rule := range rules {
		// Handle CapGrant rules separately — they use CapGrant[].Dsts
		// instead of DstPorts for destination matching.
		if len(rule.CapGrant) > 0 {
			reduced := reduceCapGrantRule(node, rule)
			if reduced != nil {
				ret = append(ret, *reduced)
			}

			continue
		}

		// record if the rule is actually relevant for the given node.
		var dests []tailcfg.NetPortRange

		for _, dest := range rule.DstPorts {
			if destReachesNode(dest.IP, nodeIPs, subnetRoutes, exitRoutes) {
				dests = append(dests, dest)
			}
		}

		if len(dests) > 0 {
			// Struct-copy preserves any unknown future FilterRule
			// fields.
			out := rule
			out.DstPorts = dests
			ret = append(ret, out)
		}
	}

	return ret
}

// destReachesNode reports whether a DstPorts entry targets the node: one of
// its addresses, or a route it serves. Every node reduces every entry on
// every policy change, so the entry is parsed as one range rather than an
// IPSet. Unparseable entries fail closed.
func destReachesNode(dst string, nodeIPs []netip.Addr, subnetRoutes, exitRoutes []netip.Prefix) bool {
	// Spans both families, so it is the one form that is not a range.
	if dst == "*" {
		return len(nodeIPs) > 0 || len(subnetRoutes) > 0 || len(exitRoutes) > 0
	}

	r, err := util.ParseIPRange(dst)
	if err != nil {
		return false
	}

	overlaps := func(p netip.Prefix) bool { return r.Overlaps(netipx.RangeOfPrefix(p)) }

	// [types.NodeView.SubnetRoutes] holds only approved, non-exit routes:
	// Tailscale SaaS generates no rules for advertised-but-unapproved
	// routes. Approved exit routes count like subnet routes. They contain
	// every destination, so SaaS sends an exit node every rule, not only
	// internet ones.
	return slices.ContainsFunc(nodeIPs, r.Contains) ||
		slices.ContainsFunc(subnetRoutes, overlaps) ||
		slices.ContainsFunc(exitRoutes, overlaps)
}

// reduceCapGrantRule filters a [tailcfg.CapGrant] rule to only include
// [tailcfg.CapGrant] entries whose Dsts match the given node's IPs. When a
// broad prefix (e.g. 100.64.0.0/10 from dst:*) contains a node's IP, it is
// narrowed to the node's specific /32 or /128 prefix. Returns nil if
// no [tailcfg.CapGrant] entries are relevant to this node.
func reduceCapGrantRule(
	node types.NodeView,
	rule tailcfg.FilterRule,
) *tailcfg.FilterRule {
	var capGrants []tailcfg.CapGrant

	nodeIPs := node.IPs()
	subnetRoutes := node.SubnetRoutes()

	for _, cg := range rule.CapGrant {
		// Collect the node's IPs that fall within any of this
		// CapGrant's Dsts. Broad prefixes are narrowed to specific
		// /32 and /128 entries for the node.
		var matchingDsts []netip.Prefix

		for _, dst := range cg.Dsts {
			if dst.IsSingleIP() {
				// Already a specific IP — keep it if it matches
				// any of the node's IPs.
				if slices.Contains(nodeIPs, dst.Addr()) {
					matchingDsts = append(matchingDsts, dst)
				}
			} else {
				// Broad prefix — narrow to node's specific IPs.
				for _, ip := range nodeIPs {
					if dst.Contains(ip) {
						matchingDsts = append(matchingDsts, netip.PrefixFrom(ip, ip.BitLen()))
					}
				}
			}
		}

		// Asymmetric on purpose: the IP-match loop above narrows broad
		// prefixes to node-specific /32 or /128 so peers receive only
		// the minimum routing surface. The route-match loop below
		// preserves the original prefix so the subnet-serving node
		// receives the full CapGrant scope. [types.NodeView.SubnetRoutes]
		// excludes both unapproved and exit routes, matching Tailscale
		// SaaS behavior.
		for _, dst := range cg.Dsts {
			for _, subnetRoute := range subnetRoutes {
				if dst.Overlaps(subnetRoute) {
					// For route overlaps, keep the original prefix.
					matchingDsts = append(matchingDsts, dst)
				}
			}
		}

		if len(matchingDsts) > 0 {
			// A Dst can be appended twice when a broad prefix both
			// contains a node IP and overlaps one of its approved
			// subnet routes. Sort + Compact dedups; [netip.Prefix] is
			// comparable so Compact works with ==.
			slices.SortFunc(matchingDsts, netip.Prefix.Compare)
			matchingDsts = slices.Compact(matchingDsts)

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   matchingDsts,
				CapMap: cg.CapMap,
			})
		}
	}

	if len(capGrants) == 0 {
		return nil
	}

	return &tailcfg.FilterRule{
		SrcIPs:   rule.SrcIPs,
		CapGrant: capGrants,
	}
}
