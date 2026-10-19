package v2

import (
	"errors"
	"maps"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v4"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
)

// ReadView retains immutable policy inputs and only that generation's caches.
var errInvalidPolicyReadView = errors.New("invalid policy read view")

type ReadView struct {
	generation *compiledGeneration
	caches     *generationCaches
}

type compiledGeneration struct {
	pol       *Policy
	users     types.Users
	nodes     views.Slice[types.NodeView]
	nodesByID map[types.NodeID]types.NodeView
	grants    []compiledGrant
	self      map[selfKey][]ruleFragment
	userIDs   []uint
	peer      ruleIndex
	packet    ruleIndex
	global    []packetfilter.Rule
	nodeCaps  map[types.NodeID]tailcfg.NodeCapMap
}

type generationCaches struct {
	packet *xsync.Map[types.NodeID, []packetfilter.Rule]
	ssh    *xsync.Map[types.NodeID, sshPolicy]
}

type ownerApplicability struct {
	unrestricted bool
	ordinals     []int
}
type ownedFragment struct {
	fragment ruleFragment
	owners   ownerApplicability
}
type ruleIndex struct {
	rules  []packetfilter.Rule
	owners []ownerApplicability
	byNode map[types.NodeID][]int
}

func newReadView(
	pol *Policy,
	users types.Users,
	nodes views.Slice[types.NodeView],
	grants []compiledGrant,
	caps map[types.NodeID]tailcfg.NodeCapMap,
) ReadView {
	ownedNodes := make([]types.NodeView, nodes.Len())
	for i, node := range nodes.All() {
		if node.Valid() {
			ownedNodes[i] = node.AsStruct().View()
		}
	}

	nodes = views.SliceOf(ownedNodes)

	ownedUsers := make(types.Users, len(users))
	for i := range users {
		ownedUsers[i] = *users[i].Clone()
	}

	users = ownedUsers

	ownedCaps := make(map[types.NodeID]tailcfg.NodeCapMap, len(caps))
	for id, capMap := range caps {
		cloned := maps.Clone(capMap)
		for cap, values := range cloned {
			cloned[cap] = slices.Clone(values)
		}

		ownedCaps[id] = cloned
	}

	caps = ownedCaps
	g := &compiledGeneration{
		pol:       pol,
		users:     slices.Clone(users),
		nodes:     nodes,
		nodesByID: nodeIDViewMap(nodes),
		grants:    grants,
		self:      make(map[selfKey][]ruleFragment),
		nodeCaps:  caps,
	}
	userNodes := buildUserNodeIndex(nodes)
	g.userIDs = slices.Sorted(maps.Keys(userNodes))

	for i := range grants {
		if grants[i].self != nil {
			for _, uid := range slices.Sorted(maps.Keys(userNodes)) {
				g.self[selfKey{i, uid}] = compileSelfForUser(&grants[i], userNodes[uid])
			}
		}
	}

	g.peer = g.buildRuleIndex(nodes, false)
	g.packet = g.peer

	hasExit := false
	for _, node := range nodes.All() {
		hasExit = hasExit || node.IsExitNode()
	}

	if hasExit && len(g.self) > 0 {
		g.packet = g.buildRuleIndex(nodes, true)
	}

	for i, rule := range g.peer.rules {
		if g.peer.owners[i].unrestricted {
			g.global = append(g.global, rule)
		}
	}

	return ReadView{
		g,
		&generationCaches{
			packet: xsync.NewMap[types.NodeID, []packetfilter.Rule](),
			ssh:    xsync.NewMap[types.NodeID, sshPolicy](),
		},
	}
}

func (g *compiledGeneration) buildRuleIndex(
	nodes views.Slice[types.NodeView],
	packet bool,
) ruleIndex {
	byID := nodeIDViewMap(nodes)
	userOwners := make(map[uint][]int)

	var exitOrdinals []int

	for ordinal, node := range nodes.All() {
		node = byID[node.ID()]
		if !node.IsTagged() && node.User().Valid() {
			uid := node.User().ID()
			userOwners[uid] = append(userOwners[uid], ordinal)
		}

		if packet && node.IsExitNode() {
			exitOrdinals = append(exitOrdinals, ordinal)
		}
	}

	otherUserExits := make(map[uint][]int)

	if len(exitOrdinals) > 0 {
		for _, uid := range g.userIDs {
			for _, ordinal := range exitOrdinals {
				node := byID[nodes.At(ordinal).ID()]
				if node.IsTagged() || !node.User().Valid() || node.User().ID() != uid {
					otherUserExits[uid] = append(otherUserExits[uid], ordinal)
				}
			}
		}
	}

	var fragments, exitExtras []ownedFragment
	if g.pol == nil || (g.pol.ACLs == nil && g.pol.Grants == nil) {
		fragments = append(
			fragments,
			ownedFragment{
				fragment: ruleFragment{
					sources: ipset.All(),
					destinations: []packetfilter.Destination{
						{
							Addresses: ipset.All(),
							Ports:     tailcfg.PortRange{First: 0, Last: 65535},
						},
					},
					protocols: Protocol(0).IPProtocols(),
				},
				owners: ownerApplicability{unrestricted: true},
			},
		)
	}

	for grantID := range g.grants {
		grant := &g.grants[grantID]
		for _, fragment := range grant.fragments {
			fragments = append(
				fragments,
				ownedFragment{fragment, ownerApplicability{unrestricted: true}},
			)
		}

		if grant.self != nil {
			for _, uid := range g.userIDs {
				owners := userOwners[uid]

				exitOwners := otherUserExits[uid]
				for _, fragment := range g.self[selfKey{grantID, uid}] {
					if len(owners) > 0 {
						fragments = append(fragments, ownedFragment{fragment, ownerApplicability{ordinals: owners}})
					}

					if len(exitOwners) > 0 {
						exitExtras = append(exitExtras, ownedFragment{fragment, ownerApplicability{ordinals: exitOwners}})
					}
				}
			}
		}

		if grant.via != nil {
			// Share identical via fragments within the grant before owner-aware merging.
			buckets := make(map[deephash.Sum][]int)
			selected := make(map[types.NodeID][]int)

			for ordinal, node := range nodes.All() {
				id := node.ID()

				indices, ok := selected[id]
				if !ok {
					for _, fragment := range compileViaForNode(grant, byID[id]) {
						hash := fragmentDestinationHash(fragment)
						index := -1

						for _, candidate := range buckets[hash] {
							if equalNetworkFragment(
								fragments[candidate].fragment,
								fragment,
							) {
								index = candidate
								break
							}
						}

						if index < 0 {
							index = len(fragments)
							fragments = append(
								fragments,
								ownedFragment{fragment: fragment},
							)
							buckets[hash] = append(buckets[hash], index)
						}

						indices = append(indices, index)
					}

					selected[id] = indices
				}

				for _, index := range indices {
					fragments[index].owners.ordinals = append(
						fragments[index].owners.ordinals,
						ordinal,
					)
				}
			}
		}
	}

	fragments = append(fragments, exitExtras...)

	return mergeFragments(fragments, nodes)
}

// mergeFragments determines complete applicability before constructing final Rules.
func mergeFragments(
	fragments []ownedFragment,
	nodes views.Slice[types.NodeView],
) ruleIndex {
	return mergeFragmentsWithHash(fragments, nodes, mergeFragmentHash)
}

func mergeFragmentsWithHash(
	fragments []ownedFragment,
	nodes views.Slice[types.NodeView],
	hashKey func(ownedFragment) deephash.Sum,
) ruleIndex {
	var merged []ownedFragment

	buckets := make(map[deephash.Sum][]int)

	for _, fragment := range fragments {
		fragment.fragment.protocols = slices.Clone(fragment.fragment.protocols)
		slices.Sort(fragment.fragment.protocols)

		fragment.fragment.protocols = slices.Compact(fragment.fragment.protocols)
		if len(fragment.fragment.capabilities) > 0 {
			merged = append(merged, fragment)
			continue
		}

		hash := hashKey(fragment)
		index := -1

		for _, candidate := range buckets[hash] {
			other := merged[candidate]
			if fragment.fragment.sources.Equal(other.fragment.sources) &&
				slices.Equal(fragment.fragment.protocols, other.fragment.protocols) &&
				equalOwners(fragment.owners, other.owners) {
				index = candidate
				break
			}
		}

		if index < 0 {
			fragment.fragment.destinations = slices.Clone(fragment.fragment.destinations)

			buckets[hash] = append(buckets[hash], len(merged))
			merged = append(merged, fragment)
		} else {
			merged[index].fragment.destinations = append(
				merged[index].fragment.destinations,
				fragment.fragment.destinations...)
		}
	}

	index := ruleIndex{byNode: make(map[types.NodeID][]int)}

	for _, fragment := range merged {
		var rule packetfilter.Rule
		if len(fragment.fragment.capabilities) > 0 {
			rule = packetfilter.NewCapabilityRule(
				fragment.fragment.sources,
				fragment.fragment.capabilities,
			)
		} else {
			rule = packetfilter.NewNetworkRule(
				fragment.fragment.sources,
				fragment.fragment.destinations,
				fragment.fragment.protocols,
			)
		}

		id := len(index.rules)
		index.rules = append(index.rules, rule)

		index.owners = append(index.owners, fragment.owners)
		if fragment.owners.unrestricted {
			for _, node := range nodes.All() {
				ids := index.byNode[node.ID()]
				if len(ids) == 0 || ids[len(ids)-1] != id {
					index.byNode[node.ID()] = append(ids, id)
				}
			}
		} else {
			for _, ordinal := range fragment.owners.ordinals {
				nodeID := nodes.At(ordinal).ID()

				ids := index.byNode[nodeID]
				if len(ids) == 0 || ids[len(ids)-1] != id {
					index.byNode[nodeID] = append(ids, id)
				}
			}
		}
	}

	return index
}

func equalOwners(a, b ownerApplicability) bool {
	return a.unrestricted == b.unrestricted && slices.Equal(a.ordinals, b.ordinals)
}

func mergeFragmentHash(fragment ownedFragment) deephash.Sum {
	projection := struct {
		Sources   []netip.Prefix
		Protocols []ipproto.Proto
		Owners    ownerApplicability
		Kind      packetfilter.Kind
	}{slices.Collect(fragment.fragment.sources.Prefixes()), fragment.fragment.protocols, fragment.owners, packetfilter.KindNetwork}

	return deephash.Hash(&projection)
}

func fragmentDestinationHash(fragment ruleFragment) deephash.Sum {
	type destination struct {
		Prefixes []netip.Prefix
		Ports    tailcfg.PortRange
	}

	projection := make([]destination, 0, len(fragment.destinations))
	for _, entry := range fragment.destinations {
		projection = append(
			projection,
			destination{slices.Collect(entry.Addresses.Prefixes()), entry.Ports},
		)
	}

	return deephash.Hash(&projection)
}

func equalNetworkFragment(a, b ruleFragment) bool {
	if !a.sources.Equal(b.sources) || !slices.Equal(a.protocols, b.protocols) ||
		len(a.destinations) != len(b.destinations) {
		return false
	}

	for i, destination := range a.destinations {
		if destination.Ports != b.destinations[i].Ports ||
			!destination.Addresses.Equal(b.destinations[i].Addresses) {
			return false
		}
	}

	return true
}

func (v ReadView) Valid() bool { return v.generation != nil && v.caches != nil }
func (v ReadView) PacketRules() []packetfilter.Rule {
	if !v.Valid() {
		return nil
	}

	return slices.Clone(v.generation.global)
}

func (v ReadView) cacheable(node types.NodeView) bool {
	own, ok := v.generation.nodesByID[node.ID()]
	return ok && !node.HasPolicyChange(own) && !node.HasNetworkChanges(own)
}

func (index ruleIndex) forNode(id types.NodeID) []packetfilter.Rule {
	rules := make([]packetfilter.Rule, 0, len(index.byNode[id]))
	for _, ruleID := range index.byNode[id] {
		rules = append(rules, index.rules[ruleID])
	}

	return rules
}

func (v ReadView) PeerRulesForNode(node types.NodeView) ([]packetfilter.Rule, error) {
	if !v.Valid() {
		return nil, errInvalidPolicyReadView
	}

	if !node.Valid() {
		return nil, nil
	}

	if v.cacheable(node) {
		return v.generation.peer.forNode(node.ID()), nil
	}

	return v.generation.buildRuleIndex(views.SliceOf([]types.NodeView{node}), false).
			forNode(node.ID()),
		nil
}

func (v ReadView) PacketRulesForNode(node types.NodeView) ([]packetfilter.Rule, error) {
	if !v.Valid() {
		return nil, errInvalidPolicyReadView
	}

	if !node.Valid() {
		return nil, nil
	}

	cacheable := v.cacheable(node)
	if cacheable {
		if rules, ok := v.caches.packet.Load(node.ID()); ok {
			return slices.Clone(rules), nil
		}
	}

	index := v.generation.packet
	if !cacheable {
		index = v.generation.buildRuleIndex(views.SliceOf([]types.NodeView{node}), true)
	}

	rules := packetfilter.Reduce(index.forNode(node.ID()), targetForNode(node))
	if cacheable {
		v.caches.packet.Store(node.ID(), rules)
	}

	return slices.Clone(rules), nil
}

func (v ReadView) NodeCapMap(id types.NodeID) tailcfg.NodeCapMap {
	if !v.Valid() {
		return nil
	}

	caps := maps.Clone(v.generation.nodeCaps[id])
	for cap, values := range caps {
		caps[cap] = slices.Clone(values)
	}

	return caps
}

func (v ReadView) PeerCapMap(node types.NodeView) tailcfg.NodeCapMap {
	return PeerCapMap(node, v.NodeCapMap(node.ID()))
}
