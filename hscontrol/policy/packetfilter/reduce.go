package packetfilter

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/ipset"
)

// Target contains stored node addresses and only approved routes.
type Target struct {
	IPv4         *netip.Addr
	IPv6         *netip.Addr
	SubnetRoutes []netip.Prefix
	ExitRoutes   []netip.Prefix
}

// Reduce selects complete network groups relevant to target. Capability grants
// instead narrow to stored node addresses and preserve overlapping subnet scope.
func Reduce(rules []Rule, target Target) []Rule {
	reduced := make([]Rule, 0)

	for _, rule := range rules {
		switch rule.kind {
		case KindInvalid:
			continue
		case KindNetwork:
			if !matchesTarget(rule.destinationSet, target, true) {
				continue
			}

			var destinations []Destination
			for _, destination := range rule.destinations {
				if matchesTarget(destination.Addresses, target, true) {
					destinations = append(destinations, destination)
				}
			}

			if len(destinations) == len(rule.destinations) {
				reduced = append(reduced, rule)
			} else if len(destinations) > 0 {
				reduced = append(
					reduced,
					NewNetworkRule(rule.sources, destinations, rule.protocols),
				)
			}
		case KindCapability:
			if !matchesTarget(rule.destinationSet, target, false) {
				continue
			}

			var grants []CapabilityGrant

			for _, grant := range rule.capGrants {
				var builder ipset.Builder

				for _, address := range [...]*netip.Addr{target.IPv4, target.IPv6} {
					if address != nil && grant.Addresses.Contains(*address) {
						builder.AddAddr(*address)
					}
				}

				for prefix := range grant.Addresses.Prefixes() {
					if slices.ContainsFunc(target.SubnetRoutes, prefix.Overlaps) {
						builder.AddPrefix(prefix)
					}
				}
				// Membership and overlap selected only valid, unzoned inputs.
				addresses, _ := builder.Build()
				if !addresses.IsEmpty() {
					grants = append(
						grants,
						CapabilityGrant{Addresses: addresses, CapMap: grant.CapMap},
					)
				}
			}

			if len(grants) > 0 {
				reduced = append(reduced, NewCapabilityRule(rule.sources, grants))
			}
		}
	}

	return reduced
}

func matchesTarget(addresses ipset.Set, target Target, includeExits bool) bool {
	return (target.IPv4 != nil && addresses.Contains(*target.IPv4)) ||
		(target.IPv6 != nil && addresses.Contains(*target.IPv6)) ||
		slices.ContainsFunc(target.SubnetRoutes, addresses.OverlapsPrefix) ||
		(includeExits && slices.ContainsFunc(target.ExitRoutes, addresses.OverlapsPrefix))
}
