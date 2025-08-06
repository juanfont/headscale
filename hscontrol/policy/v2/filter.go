package v2

import (
	"errors"
	"fmt"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var ErrInvalidAction = errors.New("invalid action")

// compileFilterRules takes a set of nodes and an ACLPolicy and generates a
// set of Tailscale compatible FilterRules used to allow traffic on clients.
func (pol *Policy) compileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil || pol.ACLs == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != ActionAccept {
			return nil, ErrInvalidAction
		}

		srcIPs, err := acl.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
			continue
		}

		protocols, _ := acl.Protocol.parseProtocol()

		var destPorts []tailcfg.NetPortRange
		for _, dest := range acl.Destinations {
			ips, err := dest.Resolve(pol, users, nodes)
			if err != nil {
				log.Trace().Caller().Err(err).Msgf("resolving destination ips")
			}

			if ips == nil {
				log.Debug().Caller().Msgf("destination resolved to nil ips: %v", dest)
				continue
			}

			prefixes := ips.Prefixes()

			for _, pref := range prefixes {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}

		if len(destPorts) == 0 {
			continue
		}

		rules = append(rules, tailcfg.FilterRule{
			SrcIPs:   ipSetToPrefixStringList(srcIPs),
			DstPorts: destPorts,
			IPProto:  protocols,
		})
	}

	return rules, nil
}

// compileFilterRulesForNode compiles filter rules for a specific node.
func (pol *Policy) compileFilterRulesForNode(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	for _, acl := range pol.ACLs {
		if acl.Action != ActionAccept {
			return nil, ErrInvalidAction
		}

		rule, err := pol.compileACLWithAutogroupSelf(acl, users, node, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("compiling ACL")
			continue
		}

		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

// compileACLWithAutogroupSelf compiles a single ACL rule, handling
// autogroup:self per-node while supporting all other alias types normally.
func (pol *Policy) compileACLWithAutogroupSelf(
	acl ACL,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.FilterRule, error) {
	// Check if any destination uses autogroup:self
	hasAutogroupSelfInDst := false

	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			hasAutogroupSelfInDst = true
			break
		}
	}

	var srcIPs netipx.IPSetBuilder

	// Resolve sources to only include devices from the same user as the target node.
	for _, src := range acl.Sources {
		// autogroup:self is not allowed in sources
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, fmt.Errorf("autogroup:self cannot be used in sources")
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("resolving source ips")
			continue
		}

		if ips != nil {
			if hasAutogroupSelfInDst {
				// Instead of iterating all addresses (which could be millions),
				// check each node's IPs against the source set
				for _, n := range nodes.All() {
					if n.User().ID == node.User().ID && !n.IsTagged() {
						// Check if any of this node's IPs are in the source set
						for _, nodeIP := range n.IPs() {
							if ips.Contains(nodeIP) {
								n.AppendToIPSet(&srcIPs)
								break // Found this node, move to next
							}
						}
					}
				}
			} else {
				// No autogroup:self in destination, use all resolved sources
				srcIPs.AddSet(ips)
			}
		}
	}

	srcSet, err := srcIPs.IPSet()
	if err != nil {
		return nil, err
	}

	if srcSet == nil || len(srcSet.Prefixes()) == 0 {
		// No sources resolved, skip this rule
		return nil, nil //nolint:nilnil
	}

	protocols, _ := acl.Protocol.parseProtocol()

	var destPorts []tailcfg.NetPortRange

	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			for _, n := range nodes.All() {
				if n.User().ID == node.User().ID && !n.IsTagged() {
					for _, port := range dest.Ports {
						for _, ip := range n.IPs() {
							pr := tailcfg.NetPortRange{
								IP:    ip.String(),
								Ports: port,
							}
							destPorts = append(destPorts, pr)
						}
					}
				}
			}
		} else {
			ips, err := dest.Resolve(pol, users, nodes)
			if err != nil {
				log.Trace().Err(err).Msgf("resolving destination ips")
				continue
			}

			if ips == nil {
				log.Debug().Msgf("destination resolved to nil ips: %v", dest)
				continue
			}

			prefixes := ips.Prefixes()

			for _, pref := range prefixes {
				for _, port := range dest.Ports {
					pr := tailcfg.NetPortRange{
						IP:    pref.String(),
						Ports: port,
					}
					destPorts = append(destPorts, pr)
				}
			}
		}
	}

	if len(destPorts) == 0 {
		// No destinations resolved, skip this rule
		return nil, nil //nolint:nilnil
	}

	return &tailcfg.FilterRule{
		SrcIPs:   ipSetToPrefixStringList(srcSet),
		DstPorts: destPorts,
		IPProto:  protocols,
	}, nil
}

func sshAction(accept bool, duration time.Duration) tailcfg.SSHAction {
	return tailcfg.SSHAction{
		Reject:                    !accept,
		Accept:                    accept,
		SessionDuration:           duration,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}
}

func (pol *Policy) compileSSHPolicy(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	if pol == nil || pol.SSHs == nil || len(pol.SSHs) == 0 {
		return nil, nil
	}

	log.Trace().Caller().Msgf("compiling SSH policy for node %q", node.Hostname())

	var rules []*tailcfg.SSHRule

	for index, rule := range pol.SSHs {
		// Check if any destination uses autogroup:self
		hasAutogroupSelfInDst := false
		for _, dst := range rule.Destinations {
			if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				hasAutogroupSelfInDst = true
				break
			}
		}

		// If autogroup:self is used, skip tagged nodes
		if hasAutogroupSelfInDst && node.IsTagged() {
			continue
		}

		var dest netipx.IPSetBuilder
		for _, src := range rule.Destinations {
			// Handle autogroup:self specially
			if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				// For autogroup:self, only include the target user's untagged devices
				for _, n := range nodes.All() {
					if n.User().ID == node.User().ID && !n.IsTagged() {
						n.AppendToIPSet(&dest)
					}
				}
			} else {
				ips, err := src.Resolve(pol, users, nodes)
				if err != nil {
					log.Trace().Caller().Err(err).Msgf("resolving destination ips")
					continue
				}
				dest.AddSet(ips)
			}
		}

		destSet, err := dest.IPSet()
		if err != nil {
			return nil, err
		}

		if !node.InIPSet(destSet) {
			continue
		}

		var action tailcfg.SSHAction
		switch rule.Action {
		case SSHActionAccept:
			action = sshAction(true, 0)
		case SSHActionCheck:
			action = sshAction(true, time.Duration(rule.CheckPeriod))
		default:
			return nil, fmt.Errorf("parsing SSH policy, unknown action %q, index: %d: %w", rule.Action, index, err)
		}

		var principals []*tailcfg.SSHPrincipal
		srcIPs, err := rule.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("SSH policy compilation failed resolving source ips for rule %+v", rule)
			continue // Skip this rule if we can't resolve sources
		}

		// If autogroup:self is in destinations, filter sources to same user only
		if hasAutogroupSelfInDst {
			var filteredSrcIPs netipx.IPSetBuilder
			// Instead of iterating all addresses, check each node's IPs
			for _, n := range nodes.All() {
				if n.User().ID == node.User().ID && !n.IsTagged() {
					// Check if any of this node's IPs are in the source set
					for _, nodeIP := range n.IPs() {
						if srcIPs.Contains(nodeIP) {
							n.AppendToIPSet(&filteredSrcIPs)
							break // Found this node, move to next
						}
					}
				}
			}

			srcIPs, err = filteredSrcIPs.IPSet()
			if err != nil {
				return nil, err
			}

			if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
				// No valid sources after filtering, skip this rule
				continue
			}
		}

		for addr := range util.IPSetAddrIter(srcIPs) {
			principals = append(principals, &tailcfg.SSHPrincipal{
				NodeIP: addr.String(),
			})
		}

		userMap := make(map[string]string, len(rule.Users))
		if rule.Users.ContainsNonRoot() {
			userMap["*"] = "="

			// by default, we do not allow root unless explicitly stated
			userMap["root"] = ""
		}
		if rule.Users.ContainsRoot() {
			userMap["root"] = "root"
		}
		for _, u := range rule.Users.NormalUsers() {
			userMap[u.String()] = u.String()
		}
		rules = append(rules, &tailcfg.SSHRule{
			Principals: principals,
			SSHUsers:   userMap,
			Action:     &action,
		})
	}

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}, nil
}

func ipSetToPrefixStringList(ips *netipx.IPSet) []string {
	var out []string

	if ips == nil {
		return out
	}

	for _, pref := range ips.Prefixes() {
		out = append(out, pref.String())
	}

	return out
}
