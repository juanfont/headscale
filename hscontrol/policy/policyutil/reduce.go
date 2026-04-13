package policyutil

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// ReduceFilterRules takes a node and a set of global filter rules and removes all rules
// and destinations that are not relevant to that particular node.
//
// IMPORTANT: This function is designed for global filters only. Per-node filters
// (from autogroup:self policies) are already node-specific and should not be passed
// to this function. Use PolicyManager.FilterForNode() instead, which handles both cases.
func ReduceFilterRules(node types.NodeView, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}

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

	DEST_LOOP:
		for _, dest := range rule.DstPorts {
			expanded, err := util.ParseIPSet(dest.IP, nil)
			// Fail closed, if we can't parse it, then we should not allow
			// access.
			if err != nil {
				continue DEST_LOOP
			}

			if node.InIPSet(expanded) {
				dests = append(dests, dest)
				continue DEST_LOOP
			}

			// If the node exposes routes, ensure they are not removed
			// when the filters are reduced. Exit routes (0.0.0.0/0, ::/0)
			// are skipped here because exit nodes handle traffic via
			// AllowedIPs/routing, not packet filter rules. This matches
			// Tailscale SaaS behavior where exit nodes do not receive
			// filter rules for destinations that only overlap via exit routes.
			if node.Hostinfo().Valid() {
				routableIPs := node.Hostinfo().RoutableIPs()
				if routableIPs.Len() > 0 {
					for _, routableIP := range routableIPs.All() {
						if tsaddr.IsExitRoute(routableIP) {
							continue
						}

						if expanded.OverlapsPrefix(routableIP) {
							dests = append(dests, dest)
							continue DEST_LOOP
						}
					}
				}
			}

			// Also check approved subnet routes - nodes should have access
			// to subnets they're approved to route traffic for.
			subnetRoutes := node.SubnetRoutes()

			for _, subnetRoute := range subnetRoutes {
				if expanded.OverlapsPrefix(subnetRoute) {
					dests = append(dests, dest)
					continue DEST_LOOP
				}
			}
		}

		if len(dests) > 0 {
			ret = append(ret, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: dests,
				IPProto:  rule.IPProto,
			})
		}
	}

	return ret
}

// reduceCapGrantRule filters a CapGrant rule to only include CapGrant
// entries whose Dsts match the given node's IPs. When a broad prefix
// (e.g. 100.64.0.0/10 from dst:*) contains a node's IP, it is
// narrowed to the node's specific /32 or /128 prefix. Returns nil if
// no CapGrant entries are relevant to this node.
func reduceCapGrantRule(
	node types.NodeView,
	rule tailcfg.FilterRule,
) *tailcfg.FilterRule {
	var capGrants []tailcfg.CapGrant

	nodeIPs := node.IPs()

	for _, cg := range rule.CapGrant {
		// Collect the node's IPs that fall within any of this
		// CapGrant's Dsts. Broad prefixes are narrowed to specific
		// /32 and /128 entries for the node.
		var matchingDsts []netip.Prefix

		for _, dst := range cg.Dsts {
			if dst.IsSingleIP() {
				// Already a specific IP — keep it if it matches.
				if dst.Addr() == nodeIPs[0] || (len(nodeIPs) > 1 && dst.Addr() == nodeIPs[1]) {
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

		// Also check routable IPs (subnet routes) — nodes that
		// advertise routes should receive CapGrant rules for
		// destinations that overlap their routes.
		if node.Hostinfo().Valid() {
			routableIPs := node.Hostinfo().RoutableIPs()
			if routableIPs.Len() > 0 {
				for _, dst := range cg.Dsts {
					for _, routableIP := range routableIPs.All() {
						if tsaddr.IsExitRoute(routableIP) {
							continue
						}

						if dst.Overlaps(routableIP) {
							// For route overlaps, keep the original prefix.
							matchingDsts = append(matchingDsts, dst)
						}
					}
				}
			}
		}

		if len(matchingDsts) > 0 {
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
