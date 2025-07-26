package policy

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// ReduceNodes returns the list of peers authorized to be accessed from a given node.
func ReduceNodes(
	node types.NodeView,
	nodes views.Slice[types.NodeView],
	matchers []matcher.Match,
) views.Slice[types.NodeView] {
	var result []types.NodeView

	for _, peer := range nodes.All() {
		if peer.ID() == node.ID() {
			continue
		}

		if node.CanAccess(matchers, peer) || peer.CanAccess(matchers, node) {
			result = append(result, peer)
		}
	}

	return views.SliceOf(result)
}

// ReduceRoutes returns a reduced list of routes for a given node that it can access.
func ReduceRoutes(
	node types.NodeView,
	routes []netip.Prefix,
	matchers []matcher.Match,
) []netip.Prefix {
	var result []netip.Prefix

	for _, route := range routes {
		if node.CanAccessRoute(matchers, route) {
			result = append(result, route)
		}
	}

	return result
}

// BuildPeerMap builds a map of all peers that can be accessed by each node.
func BuildPeerMap(
	nodes views.Slice[types.NodeView],
	matchers []matcher.Match,
) map[types.NodeID][]types.NodeView {
	ret := make(map[types.NodeID][]types.NodeView, nodes.Len())

	// Build the map of all peers according to the matchers.
	// Compared to ReduceNodes, which builds the list per node, we end up with doing
	// the full work for every node (On^2), while this will reduce the list as we see
	// relationships while building the map, making it O(n^2/2) in the end, but with less work per node.
	for i := range nodes.Len() {
		for j := i + 1; j < nodes.Len(); j++ {
			if nodes.At(i).ID() == nodes.At(j).ID() {
				continue
			}

			if nodes.At(i).CanAccess(matchers, nodes.At(j)) || nodes.At(j).CanAccess(matchers, nodes.At(i)) {
				ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j))
				ret[nodes.At(j).ID()] = append(ret[nodes.At(j).ID()], nodes.At(i))
			}
		}
	}

	return ret
}

// ReduceFilterRules takes a node and a set of rules and removes all rules and destinations
// that are not relevant to that particular node.
func ReduceFilterRules(node types.NodeView, rules []tailcfg.FilterRule) []tailcfg.FilterRule {
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
			if node.Hostinfo().Valid() {
				routableIPs := node.Hostinfo().RoutableIPs()
				if routableIPs.Len() > 0 {
					for _, routableIP := range routableIPs.All() {
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

// ApproveRoutesWithPolicy approves any route that can be autoapproved from
// the nodes perspective according to the given policy.
// If the node's approved routes change, it returns the new list and true.
func ApproveRoutesWithPolicy(pm PolicyManager, nv types.NodeView) ([]netip.Prefix, bool) {
	if pm == nil {
		log.Debug().Msg("PolicyManager is nil, no approval")
		return nil, false
	}
	var newApproved []netip.Prefix
	announcedRoutes := nv.AnnouncedRoutes()
	currentApproved := nv.ApprovedRoutes().AsSlice()

	log.Debug().
		Uint64("node.id", nv.ID().Uint64()).
		Strs("announcedRoutes", util.PrefixesToString(announcedRoutes)).
		Strs("currentApprovedRoutes", util.PrefixesToString(currentApproved)).
		Msg("evaluating route approval")

	for _, route := range announcedRoutes {
		canApprove := pm.NodeCanApproveRoute(nv, route)
		log.Debug().
			Uint64("node.id", nv.ID().Uint64()).
			Str("route", route.String()).
			Bool("canApprove", canApprove).
			Msg("checking individual route approval")
		if canApprove {
			newApproved = append(newApproved, route)
		}
	}

	log.Debug().
		Uint64("node.id", nv.ID().Uint64()).
		Strs("newApproved", util.PrefixesToString(newApproved)).
		Int("newApprovedCount", len(newApproved)).
		Msg("auto-approval results")

	// Only modify ApprovedRoutes if we have new routes to approve.
	// This prevents clearing existing approved routes when nodes
	// temporarily don't have announced routes during policy changes.
	if len(newApproved) > 0 {
		combined := nv.ApprovedRoutes().AppendTo(newApproved)
		tsaddr.SortPrefixes(combined)
		combined = slices.Compact(combined)
		combined = lo.Filter(combined, func(route netip.Prefix, index int) bool {
			return route.IsValid()
		})

		log.Debug().
			Uint64("node.id", nv.ID().Uint64()).
			Strs("combinedRoutes", util.PrefixesToString(combined)).
			Strs("oldApprovedRoutes", util.PrefixesToString(currentApproved)).
			Bool("routesChanged", !slices.Equal(currentApproved, combined)).
			Msg("final route approval calculation")

		// Only update if the routes actually changed
		if !slices.Equal(currentApproved, combined) {
			log.Info().
				Uint64("node.id", nv.ID().Uint64()).
				Strs("finalApprovedRoutes", util.PrefixesToString(combined)).
				Msg("auto-approving routes based on policy")
			return combined, true
		}
	}

	log.Debug().
		Uint64("node.id", nv.ID().Uint64()).
		Msg("no route changes needed")
	return currentApproved, false
}
