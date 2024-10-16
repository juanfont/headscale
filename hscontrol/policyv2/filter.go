package policyv2

import (
	"errors"
	"fmt"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
)

var (
	ErrInvalidAction = errors.New("invalid action")
)

// CompileFilterRules takes a set of nodes and an ACLPolicy and generates a
// set of Tailscale compatible FilterRules used to allow traffic on clients.
func (pol *Policy) CompileFilterRules(
	nodes types.Nodes,
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != "accept" {
			return nil, ErrInvalidAction
		}

		srcIPs, err := acl.Sources.Resolve(pol, nodes)
		if err != nil {
			return nil, fmt.Errorf("resolving source ips: %w", err)
		}

		// TODO(kradalby): integrate type into schema
		// TODO(kradalby): figure out the _ is wildcard stuff
		protocols, _, err := parseProtocol(acl.Protocol)
		if err != nil {
			return nil, fmt.Errorf("parsing policy, protocol err: %w ", err)
		}

		var destPorts []tailcfg.NetPortRange
		for _, dest := range acl.Destinations {
			ips, err := dest.Alias.Resolve(pol, nodes)
			if err != nil {
				return nil, err
			}

			for _, pref := range ips.Prefixes() {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   ipSetToPrefixStringList(srcIPs),
			DstPorts: destPorts,
			IPProto:  protocols,
		})
	}

	return rules, nil
}

func ipSetToPrefixStringList(ips *netipx.IPSet) []string {
	var out []string

	for _, pref := range ips.Prefixes() {
		out = append(out, pref.String())
	}
	return out
}
