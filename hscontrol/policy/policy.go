package policy

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
)

// FilterNodesByACL returns the list of peers authorized to be accessed from a given node.
func FilterNodesByACL(
	node *types.Node,
	nodes types.Nodes,
	filter []tailcfg.FilterRule,
) types.Nodes {
	var result types.Nodes

	for index, peer := range nodes {
		if peer.ID == node.ID {
			continue
		}

		if node.CanAccess(filter, nodes[index]) || peer.CanAccess(filter, node) {
			result = append(result, peer)
		}
	}

	return result
}

// ReduceFilterRules takes a node and a set of rules and removes all rules and destinations
// that are not relevant to that particular node.
func ReduceFilterRules(node *types.Node, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	ret := []tailcfg.FilterRule{}

	for _, rule := range rules {
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

			// If the node exposes routes, ensure they are note removed
			// when the filters are reduced.
			if node.Hostinfo != nil {
				if len(node.Hostinfo.RoutableIPs) > 0 {
					for _, routableIP := range node.Hostinfo.RoutableIPs {
						if expanded.OverlapsPrefix(routableIP) {
							dests = append(dests, dest)
							continue DEST_LOOP
						}
					}
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
