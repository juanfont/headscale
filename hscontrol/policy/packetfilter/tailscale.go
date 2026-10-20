package packetfilter

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"tailscale.com/tailcfg"
)

// ToTailcfg constructs independent wire objects, including an explicit empty
// slice when there are no permissions, so callers can revoke prior filters.
func ToTailcfg(rules []Rule) []tailcfg.FilterRule {
	encoded := make([]tailcfg.FilterRule, 0, len(rules))
	for _, rule := range rules {
		if rule.kind == KindInvalid {
			continue
		}

		wire := tailcfg.FilterRule{}
		if rule.sources.Equal(ipset.All()) {
			wire.SrcIPs = []string{"*"}
		} else {
			for addresses := range rule.sources.Ranges() {
				if prefix, ok := addresses.Prefix(); ok {
					wire.SrcIPs = append(wire.SrcIPs, prefixString(prefix))
				} else {
					wire.SrcIPs = append(wire.SrcIPs, addresses.String())
				}
			}
		}

		switch rule.kind {
		case KindInvalid:
			continue
		case KindNetwork:
			for _, destination := range rule.destinations {
				if destination.Addresses.Equal(ipset.All()) {
					wire.DstPorts = append(wire.DstPorts, tailcfg.NetPortRange{
						IP:    "*",
						Ports: destination.Ports,
					})

					continue
				}

				for prefix := range destination.Addresses.Prefixes() {
					wire.DstPorts = append(wire.DstPorts, tailcfg.NetPortRange{
						IP:    prefixString(prefix),
						Ports: destination.Ports,
					})
				}
			}

			if !slices.Equal(rule.protocols, defaultProtocols[:]) {
				for _, protocol := range rule.protocols {
					wire.IPProto = append(wire.IPProto, int(protocol))
				}
			}
		case KindCapability:
			for _, grant := range rule.capGrants {
				wire.CapGrant = append(wire.CapGrant, tailcfg.CapGrant{
					Dsts:   slices.Collect(grant.Addresses.Prefixes()),
					CapMap: cloneCapMap(grant.CapMap),
				})
			}
		}

		encoded = append(encoded, wire)
	}

	return encoded
}

func prefixString(prefix netip.Prefix) string {
	if prefix.IsSingleIP() {
		return prefix.Addr().String()
	}

	return prefix.String()
}
