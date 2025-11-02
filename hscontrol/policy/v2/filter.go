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

		aclRules, err := pol.compileACLWithAutogroupSelf(acl, users, node, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("compiling ACL")
			continue
		}

		for _, rule := range aclRules {
			if rule != nil {
				rules = append(rules, *rule)
			}
		}
	}

	return rules, nil
}

// compileACLWithAutogroupSelf compiles a single ACL rule, handling
// autogroup:self per-node while supporting all other alias types normally.
// It returns a slice of filter rules because when an ACL has both autogroup:self
// and other destinations, they need to be split into separate rules with different
// source filtering logic.
func (pol *Policy) compileACLWithAutogroupSelf(
	acl ACL,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]*tailcfg.FilterRule, error) {
	var autogroupSelfDests []AliasWithPorts
	var otherDests []AliasWithPorts

	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			autogroupSelfDests = append(autogroupSelfDests, dest)
		} else {
			otherDests = append(otherDests, dest)
		}
	}

	protocols, _ := acl.Protocol.parseProtocol()
	var rules []*tailcfg.FilterRule

	var resolvedSrcIPs []*netipx.IPSet

	for _, src := range acl.Sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, fmt.Errorf("autogroup:self cannot be used in sources")
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("resolving source ips")
			continue
		}

		if ips != nil {
			resolvedSrcIPs = append(resolvedSrcIPs, ips)
		}
	}

	if len(resolvedSrcIPs) == 0 {
		return rules, nil
	}

	// Handle autogroup:self destinations (if any)
	if len(autogroupSelfDests) > 0 {
		// Pre-filter to same-user untagged devices once - reuse for both sources and destinations
		sameUserNodes := make([]types.NodeView, 0)
		for _, n := range nodes.All() {
			if n.User().ID == node.User().ID && !n.IsTagged() {
				sameUserNodes = append(sameUserNodes, n)
			}
		}

		if len(sameUserNodes) > 0 {
			// Filter sources to only same-user untagged devices
			var srcIPs netipx.IPSetBuilder
			for _, ips := range resolvedSrcIPs {
				for _, n := range sameUserNodes {
					// Check if any of this node's IPs are in the source set
					for _, nodeIP := range n.IPs() {
						if ips.Contains(nodeIP) {
							n.AppendToIPSet(&srcIPs)
							break
						}
					}
				}
			}

			srcSet, err := srcIPs.IPSet()
			if err != nil {
				return nil, err
			}

			if srcSet != nil && len(srcSet.Prefixes()) > 0 {
				var destPorts []tailcfg.NetPortRange
				for _, dest := range autogroupSelfDests {
					for _, n := range sameUserNodes {
						for _, port := range dest.Ports {
							for _, ip := range n.IPs() {
								destPorts = append(destPorts, tailcfg.NetPortRange{
									IP:    ip.String(),
									Ports: port,
								})
							}
						}
					}
				}

				if len(destPorts) > 0 {
					rules = append(rules, &tailcfg.FilterRule{
						SrcIPs:   ipSetToPrefixStringList(srcSet),
						DstPorts: destPorts,
						IPProto:  protocols,
					})
				}
			}
		}
	}

	if len(otherDests) > 0 {
		var srcIPs netipx.IPSetBuilder

		for _, ips := range resolvedSrcIPs {
			srcIPs.AddSet(ips)
		}

		srcSet, err := srcIPs.IPSet()
		if err != nil {
			return nil, err
		}

		if srcSet != nil && len(srcSet.Prefixes()) > 0 {
			var destPorts []tailcfg.NetPortRange

			for _, dest := range otherDests {
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

			if len(destPorts) > 0 {
				rules = append(rules, &tailcfg.FilterRule{
					SrcIPs:   ipSetToPrefixStringList(srcSet),
					DstPorts: destPorts,
					IPProto:  protocols,
				})
			}
		}
	}

	return rules, nil
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
		// Separate destinations into autogroup:self and others
		// This is needed because autogroup:self requires filtering sources to same-user only,
		// while other destinations should use all resolved sources
		var autogroupSelfDests []Alias
		var otherDests []Alias

		for _, dst := range rule.Destinations {
			if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				autogroupSelfDests = append(autogroupSelfDests, dst)
			} else {
				otherDests = append(otherDests, dst)
			}
		}

		// Note: Tagged nodes can't match autogroup:self destinations, but can still match other destinations

		// Resolve sources once - we'll use them differently for each destination type
		srcIPs, err := rule.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("SSH policy compilation failed resolving source ips for rule %+v", rule)
			continue // Skip this rule if we can't resolve sources
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
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

		// Handle autogroup:self destinations (if any)
		// Note: Tagged nodes can't match autogroup:self, so skip this block for tagged nodes
		if len(autogroupSelfDests) > 0 && !node.IsTagged() {
			// Build destination set for autogroup:self (same-user untagged devices only)
			var dest netipx.IPSetBuilder
			for _, n := range nodes.All() {
				if n.User().ID == node.User().ID && !n.IsTagged() {
					n.AppendToIPSet(&dest)
				}
			}

			destSet, err := dest.IPSet()
			if err != nil {
				return nil, err
			}

			// Only create rule if this node is in the destination set
			if node.InIPSet(destSet) {
				// Filter sources to only same-user untagged devices
				// Pre-filter to same-user untagged devices for efficiency
				sameUserNodes := make([]types.NodeView, 0)
				for _, n := range nodes.All() {
					if n.User().ID == node.User().ID && !n.IsTagged() {
						sameUserNodes = append(sameUserNodes, n)
					}
				}

				var filteredSrcIPs netipx.IPSetBuilder
				for _, n := range sameUserNodes {
					// Check if any of this node's IPs are in the source set
					for _, nodeIP := range n.IPs() {
						if srcIPs.Contains(nodeIP) {
							n.AppendToIPSet(&filteredSrcIPs)
							break // Found this node, move to next
						}
					}
				}

				filteredSrcSet, err := filteredSrcIPs.IPSet()
				if err != nil {
					return nil, err
				}

				if filteredSrcSet != nil && len(filteredSrcSet.Prefixes()) > 0 {
					var principals []*tailcfg.SSHPrincipal
					for addr := range util.IPSetAddrIter(filteredSrcSet) {
						principals = append(principals, &tailcfg.SSHPrincipal{
							NodeIP: addr.String(),
						})
					}

					if len(principals) > 0 {
						rules = append(rules, &tailcfg.SSHRule{
							Principals: principals,
							SSHUsers:   userMap,
							Action:     &action,
						})
					}
				}
			}
		}

		// Handle other destinations (if any)
		if len(otherDests) > 0 {
			// Build destination set for other destinations
			var dest netipx.IPSetBuilder
			for _, dst := range otherDests {
				ips, err := dst.Resolve(pol, users, nodes)
				if err != nil {
					log.Trace().Caller().Err(err).Msgf("resolving destination ips")
					continue
				}
				if ips != nil {
					dest.AddSet(ips)
				}
			}

			destSet, err := dest.IPSet()
			if err != nil {
				return nil, err
			}

			// Only create rule if this node is in the destination set
			if node.InIPSet(destSet) {
				// For non-autogroup:self destinations, use all resolved sources (no filtering)
				var principals []*tailcfg.SSHPrincipal
				for addr := range util.IPSetAddrIter(srcIPs) {
					principals = append(principals, &tailcfg.SSHPrincipal{
						NodeIP: addr.String(),
					})
				}

				if len(principals) > 0 {
					rules = append(rules, &tailcfg.SSHRule{
						Principals: principals,
						SSHUsers:   userMap,
						Action:     &action,
					})
				}
			}
		}
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
