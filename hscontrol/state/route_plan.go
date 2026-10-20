package state

import (
	"cmp"
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

	// Only approved-route advertisers can contribute via routing facts.
	var routers []types.NodeView

	for _, node := range snapshot.allNodes {
		if node.ApprovedRoutes().Len() > 0 {
			routers = append(routers, node)
		}
	}

	view := MapView{
		snapshot: snapshot,
		viewer:   viewer,
		peerIDs:  slices.Clone(snapshot.peersByNode[viewerID]),
	}
	slices.Sort(view.peerIDs)

	if len(routers) > 0 {
		rules, err := snapshot.policy.PeerRulesForNode(viewer)
		if err != nil {
			return MapView{}, err
		}

		view.routes = viewerRoutePlan{
			rules:   rules,
			via:     snapshot.policy.ViaRoutesForViewer(viewer, views.SliceOf(routers)),
			subnets: viewer.SubnetRoutes(),
		}
	}

	return view, nil
}

func (v MapView) Viewer() types.NodeView { return v.viewer }

// Peers selects only visible nodes from the retained snapshot, sorted by ID.
// With no IDs it returns the complete peer set.
func (v MapView) Peers(ids ...types.NodeID) views.Slice[types.NodeView] {
	visible := v.peerIDs

	all := len(ids) == 0
	if all {
		ids = visible
	}

	peers := make([]types.NodeView, 0, len(ids))
	for _, id := range ids {
		if id == v.viewer.ID() {
			continue
		}

		if !all {
			if _, ok := slices.BinarySearch(visible, id); !ok {
				continue
			}
		}

		if node, ok := v.snapshot.nodeViewsByID[id]; ok {
			peers = append(peers, node)
		}
	}

	if !all {
		slices.SortFunc(peers, func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })
		peers = slices.CompactFunc(peers, func(a, b types.NodeView) bool { return a.ID() == b.ID() })
	}

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
	return v.snapshot.policy.NodeCapMap(id)
}

func (v MapView) PeerCapMap(id types.NodeID) tailcfg.NodeCapMap {
	peer, ok := v.snapshot.nodeViewsByID[id]
	if !ok {
		return nil
	}

	return v.snapshot.policy.PeerCapMap(peer)
}

// NodeAddresses prepares independent address slices for self or a visible peer.
func (v MapView) NodeAddresses(id types.NodeID) (types.NodeAddresses, error) {
	node, ok := v.snapshot.nodeViewsByID[id]

	_, visible := slices.BinarySearch(v.peerIDs, id)
	if !ok || id != v.viewer.ID() && !visible {
		return types.NodeAddresses{}, ErrNodeNotFound
	}

	var addresses []netip.Prefix
	if node.IPv4().Valid() || node.IPv6().Valid() {
		addresses = make([]netip.Prefix, 0, 2)
	}

	_, disabled := v.snapshot.policy.NodeCapMap(id)["disable-ipv4"]

	for _, address := range [...]views.ValuePointer[netip.Addr]{node.IPv4(), node.IPv6()} {
		if address.Valid() {
			ip := address.Get()
			if !disabled || !ip.Is4() {
				addresses = append(addresses, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}

	var routes []netip.Prefix
	if id == v.viewer.ID() {
		// Self has no via steering. Approved exits are never reduced for self.
		if primaries := v.snapshot.primaryRoutesByNode[id]; len(primaries) > 0 {
			routes = policy.ReduceRoutes(node, primaries, v.snapshot.policy.PacketRules())
		}

		routes = append(routes, node.ExitRoutes()...)
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
