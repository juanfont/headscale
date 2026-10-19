package v2

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/types/views"
)

type selfKey struct {
	grant  int
	userID uint
}

// userNodeIndex excludes tagged devices, including those with creator UserIDs.
type userNodeIndex map[uint][]types.NodeView

func buildUserNodeIndex(nodes views.Slice[types.NodeView]) userNodeIndex {
	index := make(userNodeIndex)

	for _, node := range nodes.All() {
		if !node.IsTagged() && node.User().Valid() {
			id := node.User().ID()
			index[id] = append(index[id], node)
		}
	}

	return index
}

func compileSelfForUser(grant *compiledGrant, nodes []types.NodeView) []ruleFragment {
	var sources ipset.Builder

	nodeAddresses := make([][]ipset.Set, 0, len(nodes))

	for _, node := range nodes {
		// Membership is device-based: a match in either family includes both.
		if node.InIPSet(grant.sources.Raw) {
			node.AppendToIPSet(&sources)
		}

		var addresses []ipset.Set
		for _, addr := range node.IPs() {
			addresses = append(addresses,
				singletonPrefix(netip.PrefixFrom(addr, addr.BitLen())))
		}

		nodeAddresses = append(nodeAddresses, addresses)
	}

	raw, _ := sources.Build()
	if raw.IsEmpty() {
		return nil
	}

	var fragments []ruleFragment

	for _, protocol := range grant.self.internetProtocols {
		var entries []packetfilter.Destination
		// Self keeps the legacy node/port/family order while sharing address Sets.
		for _, addresses := range nodeAddresses {
			for _, ports := range protocol.Ports {
				for _, set := range addresses {
					entries = append(entries,
						packetfilter.Destination{Addresses: set, Ports: ports})
				}
			}
		}

		if len(entries) > 0 {
			fragments = append(fragments, ruleFragment{
				sources: raw, destinations: entries,
				protocols: protocol.Protocol.IPProtocols(),
			})
		}
	}

	if grant.self.app != nil {
		var destinations []resolvedDestination

		for _, addresses := range nodeAddresses {
			for _, set := range addresses {
				destinations = append(destinations, resolvedDestination{addresses: set})
			}
		}

		fragments = append(fragments, compileDestinations(
			raw, raw, destinations, nil, grant.self.app, ipset.Set{},
		)...)
	}

	return fragments
}

func singletonPrefix(prefix netip.Prefix) ipset.Set {
	var builder ipset.Builder
	builder.AddPrefix(prefix)
	set, _ := builder.Build()

	return set
}

func targetForNode(node types.NodeView) packetfilter.Target {
	target := packetfilter.Target{
		SubnetRoutes: node.SubnetRoutes(),
		ExitRoutes:   node.ExitRoutes(),
	}
	if node.IPv4().Valid() {
		addr := node.IPv4().Get()
		target.IPv4 = &addr
	}

	if node.IPv6().Valid() {
		addr := node.IPv6().Get()
		target.IPv6 = &addr
	}

	return target
}
