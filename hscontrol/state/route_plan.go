package state

import (
	"cmp"
	"maps"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// MapView retains the node snapshot and policy generation for one response.
// Mutable results belong to the caller; node views remain immutable.
type MapView struct {
	snapshot *Snapshot
	viewer   types.NodeView
	peerIDs  []types.NodeID
	routes   viewerRoutePlan
}

type viewerRoutePlan struct {
	rules   []packetfilter.Rule
	via     map[types.NodeID]types.ViaRouteResult
	subnets []netip.Prefix
}

// MapView captures response inputs before any rendering or peer diff work.
func (s *State) MapView(viewerID types.NodeID) (MapView, error) {
	snapshot := s.nodeStore.data.Load()
	if snapshot.policyBuildErr != nil {
		return MapView{}, snapshot.policyBuildErr
	}

	if !snapshot.policy.Valid() {
		return MapView{}, ErrInvalidPolicyView
	}

	viewer, ok := snapshot.nodeViewsByID[viewerID]
	if !ok {
		return MapView{}, ErrNodeNotFound
	}

	rules, err := snapshot.policy.PeerRulesForNode(viewer)
	if err != nil {
		return MapView{}, err
	}

	return MapView{
		snapshot: snapshot,
		viewer:   viewer,
		peerIDs:  slices.Sorted(slices.Values(snapshot.peersByNode[viewerID])),
		routes: viewerRoutePlan{
			rules:   rules,
			via:     snapshot.policy.ViaRoutesForViewer(viewer, views.SliceOf(snapshot.allNodes)),
			subnets: viewer.SubnetRoutes(),
		},
	}, nil
}

func (v MapView) Viewer() types.NodeView { return v.viewer }

// Peers selects only visible nodes from the retained snapshot, sorted by ID.
// With no IDs it returns the complete peer set.
func (v MapView) Peers(ids ...types.NodeID) views.Slice[types.NodeView] {
	visible := v.peerIDs
	if len(ids) == 0 {
		ids = visible
	}

	peers := make([]types.NodeView, 0, len(ids))
	for _, id := range ids {
		if _, ok := slices.BinarySearch(visible, id); id == v.viewer.ID() || !ok {
			continue
		}

		if node, ok := v.snapshot.nodeViewsByID[id]; ok {
			peers = append(peers, node)
		}
	}

	slices.SortFunc(peers, func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })
	peers = slices.CompactFunc(peers, func(a, b types.NodeView) bool { return a.ID() == b.ID() })

	return views.SliceOf(peers)
}

func (v MapView) PeerIDs() []types.NodeID {
	return slices.Clone(v.peerIDs)
}

func (v MapView) PacketRules() ([]packetfilter.Rule, error) {
	return v.snapshot.policy.PacketRulesForNode(v.viewer)
}

func (v MapView) SSHPolicy(baseURL string) (*tailcfg.SSHPolicy, error) {
	return v.snapshot.policy.SSHPolicy(baseURL, v.viewer)
}

func (v MapView) NodeCapMap(id types.NodeID) tailcfg.NodeCapMap {
	capMap := maps.Clone(v.snapshot.policy.NodeCapMap(id))
	for cap, values := range capMap {
		capMap[cap] = slices.Clone(values)
	}

	return capMap
}

func (v MapView) PeerCapMap(id types.NodeID) tailcfg.NodeCapMap {
	peer, ok := v.snapshot.nodeViewsByID[id]
	if !ok {
		return nil
	}

	capMap := maps.Clone(v.snapshot.policy.PeerCapMap(peer))
	for cap, values := range capMap {
		capMap[cap] = slices.Clone(values)
	}

	return capMap
}

// NodeAddresses prepares independent address slices for self or a visible peer.
func (v MapView) NodeAddresses(id types.NodeID) (types.NodeAddresses, error) {
	node, ok := v.snapshot.nodeViewsByID[id]

	_, visible := slices.BinarySearch(v.peerIDs, id)
	if !ok || id != v.viewer.ID() && !visible {
		return types.NodeAddresses{}, ErrNodeNotFound
	}

	addresses := node.Prefixes()
	if _, disabled := v.snapshot.policy.NodeCapMap(id)["disable-ipv4"]; disabled {
		addresses = slices.DeleteFunc(addresses, func(p netip.Prefix) bool { return p.Addr().Is4() })
	}

	var routes []netip.Prefix
	if id == v.viewer.ID() {
		// Self has no via steering. Approved exits are never reduced for self.
		routes = slices.Concat(policy.ReduceRoutes(node, v.snapshot.primaryRoutesByNode[id], v.snapshot.policy.PacketRules()), node.ExitRoutes())
	} else {
		routes = v.routesForPeer(node)
	}

	allowed := slices.Concat(addresses, routes)
	slices.SortFunc(allowed, netip.Prefix.Compare)

	var primary []netip.Prefix

	for _, route := range routes {
		if !tsaddr.IsExitRoute(route) {
			primary = append(primary, route)
		}
	}

	return types.NodeAddresses{Addresses: addresses, AllowedIPs: allowed, PrimaryRoutes: primary}, nil
}

func (v MapView) routesForPeer(peer types.NodeView) []netip.Prefix {
	via := v.routes.via[peer.ID()]
	primaries := v.snapshot.primaryRoutesByNode[peer.ID()]

	routes := slices.Concat(primaries, peer.ExitRoutes())
	if len(via.Exclude) > 0 {
		routes = slices.DeleteFunc(routes, func(p netip.Prefix) bool { return slices.Contains(via.Exclude, p) })
	}

	reduced := policy.ReduceRoutes(v.viewer, routes, v.routes.rules)
	// Via authorizes a route directly unless a regular grant requires the
	// global primary. Independent via groups retain their own elections.
	for _, route := range via.Include {
		if !slices.Contains(reduced, route) && (slices.Contains(primaries, route) || !slices.Contains(via.UsePrimary, route)) {
			reduced = append(reduced, route)
		}
	}
	// Co-routers must see the exact shared prefix's elected primary.
	for _, route := range primaries {
		if slices.Contains(v.routes.subnets, route) && !slices.Contains(reduced, route) {
			reduced = append(reduced, route)
		}
	}

	return reduced
}
