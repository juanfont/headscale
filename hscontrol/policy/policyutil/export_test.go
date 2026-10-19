package policyutil

import (
	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
)

func TypedRulesForTest(wire []tailcfg.FilterRule) []packetfilter.Rule {
	rules := make([]packetfilter.Rule, 0, len(wire))
	for _, rule := range wire {
		var src ipset.Builder

		for _, raw := range rule.SrcIPs {
			set, err := util.ParseIPSet(raw, nil)
			if err == nil {
				src.AddSet(set)
			}
		}

		sources, _ := src.Build()

		if len(rule.CapGrant) > 0 {
			caps := make([]packetfilter.CapabilityGrant, 0, len(rule.CapGrant))
			for _, grant := range rule.CapGrant {
				var dst ipset.Builder
				for _, prefix := range grant.Dsts {
					dst.AddPrefix(prefix)
				}

				set, _ := dst.Build()
				caps = append(
					caps,
					packetfilter.CapabilityGrant{Addresses: set, CapMap: grant.CapMap},
				)
			}

			rules = append(rules, packetfilter.NewCapabilityRule(sources, caps))

			continue
		}

		var destinations []packetfilter.Destination

		for _, entry := range rule.DstPorts {
			set, err := util.ParseIPSet(entry.IP, nil)
			if err == nil {
				destinations = append(
					destinations,
					packetfilter.Destination{Addresses: set, Ports: entry.Ports},
				)
			}
		}

		var protocols []ipproto.Proto

		for _, protocol := range rule.IPProto {
			if protocol >= 0 && protocol <= 255 {
				protocols = append(protocols, ipproto.Proto(protocol))
			}
		}

		rules = append(
			rules,
			packetfilter.NewNetworkRule(sources, destinations, protocols),
		)
	}

	return rules
}

func ReduceTypedRules(
	node types.NodeView,
	wire []tailcfg.FilterRule,
) []tailcfg.FilterRule {
	target := packetfilter.Target{}
	if node.Valid() {
		target = packetfilter.Target{
			IPv4:         node.IPv4().Clone(),
			IPv6:         node.IPv6().Clone(),
			SubnetRoutes: node.SubnetRoutes(),
			ExitRoutes:   node.ExitRoutes(),
		}
	}

	return packetfilter.ToTailcfg(packetfilter.Reduce(TypedRulesForTest(wire), target))
}
