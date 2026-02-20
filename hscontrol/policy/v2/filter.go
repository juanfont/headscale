package v2

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var (
	ErrInvalidAction = errors.New("invalid action")
	errSelfInSources = errors.New("autogroup:self cannot be used in sources")
)

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

		protocols := acl.Protocol.parseProtocol()

		var destPorts []tailcfg.NetPortRange

		for _, dest := range acl.Destinations {
			// Check if destination is a wildcard - use "*" directly instead of expanding
			if _, isWildcard := dest.Alias.(Asterix); isWildcard {
				for _, port := range dest.Ports {
					destPorts = append(destPorts, tailcfg.NetPortRange{
						IP:    "*",
						Ports: port,
					})
				}

				continue
			}

			// autogroup:internet does not generate packet filters - it's handled
			// by exit node routing via AllowedIPs, not by packet filtering.
			if ag, isAutoGroup := dest.Alias.(*AutoGroup); isAutoGroup && ag.Is(AutoGroupInternet) {
				continue
			}

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

	return mergeFilterRules(rules), nil
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

	return mergeFilterRules(rules), nil
}

// compileACLWithAutogroupSelf compiles a single ACL rule, handling
// autogroup:self per-node while supporting all other alias types normally.
// It returns a slice of filter rules because when an ACL has both autogroup:self
// and other destinations, they need to be split into separate rules with different
// source filtering logic.
//
//nolint:gocyclo // complex ACL compilation logic
func (pol *Policy) compileACLWithAutogroupSelf(
	acl ACL,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]*tailcfg.FilterRule, error) {
	var (
		autogroupSelfDests []AliasWithPorts
		otherDests         []AliasWithPorts
	)

	for _, dest := range acl.Destinations {
		if ag, ok := dest.Alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			autogroupSelfDests = append(autogroupSelfDests, dest)
		} else {
			otherDests = append(otherDests, dest)
		}
	}

	protocols := acl.Protocol.parseProtocol()

	var rules []*tailcfg.FilterRule

	var resolvedSrcIPs []*netipx.IPSet

	for _, src := range acl.Sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if ips != nil {
			resolvedSrcIPs = append(resolvedSrcIPs, ips)
		}
	}

	if len(resolvedSrcIPs) == 0 {
		return rules, nil
	}

	// Handle autogroup:self destinations (if any)
	// Tagged nodes don't participate in autogroup:self (identity is tag-based, not user-based)
	if len(autogroupSelfDests) > 0 && !node.IsTagged() {
		// Pre-filter to same-user untagged devices once - reuse for both sources and destinations
		sameUserNodes := make([]types.NodeView, 0)

		for _, n := range nodes.All() {
			if !n.IsTagged() && n.User().ID() == node.User().ID() {
				sameUserNodes = append(sameUserNodes, n)
			}
		}

		if len(sameUserNodes) > 0 {
			// Filter sources to only same-user untagged devices
			var srcIPs netipx.IPSetBuilder

			for _, ips := range resolvedSrcIPs {
				for _, n := range sameUserNodes {
					// Check if any of this node's IPs are in the source set
					if slices.ContainsFunc(n.IPs(), ips.Contains) {
						n.AppendToIPSet(&srcIPs)
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
									IP:    netip.PrefixFrom(ip, ip.BitLen()).String(),
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
				// Check if destination is a wildcard - use "*" directly instead of expanding
				if _, isWildcard := dest.Alias.(Asterix); isWildcard {
					for _, port := range dest.Ports {
						destPorts = append(destPorts, tailcfg.NetPortRange{
							IP:    "*",
							Ports: port,
						})
					}

					continue
				}

				// autogroup:internet does not generate packet filters - it's handled
				// by exit node routing via AllowedIPs, not by packet filtering.
				if ag, isAutoGroup := dest.Alias.(*AutoGroup); isAutoGroup && ag.Is(AutoGroupInternet) {
					continue
				}

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

//nolint:gocyclo // complex SSH policy compilation logic
func (pol *Policy) compileSSHPolicy(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	if pol == nil || pol.SSHs == nil || len(pol.SSHs) == 0 {
		return nil, nil //nolint:nilnil // intentional: no SSH policy when none configured
	}

	log.Trace().Caller().Msgf("compiling SSH policy for node %q", node.Hostname())

	var rules []*tailcfg.SSHRule

	for index, rule := range pol.SSHs {
		// Separate destinations into autogroup:self and others
		// This is needed because autogroup:self requires filtering sources to same-user only,
		// while other destinations should use all resolved sources
		var (
			autogroupSelfDests []Alias
			otherDests         []Alias
		)

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
			log.Trace().Caller().Err(err).Msgf("ssh policy compilation failed resolving source ips for rule %+v", rule)
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

		// Build the "common" userMap for non-localpart entries (root, autogroup:nonroot, specific users).
		const rootUser = "root"

		commonUserMap := make(map[string]string, len(rule.Users))
		if rule.Users.ContainsNonRoot() {
			commonUserMap["*"] = "="
			// by default, we do not allow root unless explicitly stated
			commonUserMap[rootUser] = ""
		}

		if rule.Users.ContainsRoot() {
			commonUserMap[rootUser] = rootUser
		}

		for _, u := range rule.Users.NormalUsers() {
			commonUserMap[u.String()] = u.String()
		}

		// Resolve localpart entries into per-user rules.
		// Each localpart:*@<domain> entry maps users in that domain to their email local-part.
		// Because SSHUsers is a static map per rule, we need a separate rule per user
		// to constrain each user to only their own local-part.
		localpartRules := resolveLocalpartRules(
			rule.Users.LocalpartEntries(),
			users,
			nodes,
			srcIPs,
			commonUserMap,
			&action,
		)

		// Determine whether the common userMap has any entries worth emitting.
		hasCommonUsers := len(commonUserMap) > 0

		// Handle autogroup:self destinations (if any)
		// Note: Tagged nodes can't match autogroup:self, so skip this block for tagged nodes
		if len(autogroupSelfDests) > 0 && !node.IsTagged() {
			// Build destination set for autogroup:self (same-user untagged devices only)
			var dest netipx.IPSetBuilder

			for _, n := range nodes.All() {
				if !n.IsTagged() && n.User().ID() == node.User().ID() {
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
					if !n.IsTagged() && n.User().ID() == node.User().ID() {
						sameUserNodes = append(sameUserNodes, n)
					}
				}

				var filteredSrcIPs netipx.IPSetBuilder

				for _, n := range sameUserNodes {
					// Check if any of this node's IPs are in the source set
					if slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
						n.AppendToIPSet(&filteredSrcIPs) // Found this node, move to next
					}
				}

				filteredSrcSet, err := filteredSrcIPs.IPSet()
				if err != nil {
					return nil, err
				}

				if filteredSrcSet != nil && len(filteredSrcSet.Prefixes()) > 0 {
					// Emit common rule if there are non-localpart users
					if hasCommonUsers {
						var principals []*tailcfg.SSHPrincipal
						for addr := range util.IPSetAddrIter(filteredSrcSet) {
							principals = append(principals, &tailcfg.SSHPrincipal{
								NodeIP: addr.String(),
							})
						}

						if len(principals) > 0 {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: principals,
								SSHUsers:   commonUserMap,
								Action:     &action,
							})
						}
					}

					// Emit per-user localpart rules, filtered to autogroup:self sources
					for _, lpRule := range localpartRules {
						var filteredPrincipals []*tailcfg.SSHPrincipal

						for _, p := range lpRule.Principals {
							addr, err := netip.ParseAddr(p.NodeIP)
							if err != nil {
								continue
							}

							if filteredSrcSet.Contains(addr) {
								filteredPrincipals = append(filteredPrincipals, p)
							}
						}

						if len(filteredPrincipals) > 0 {
							rules = append(rules, &tailcfg.SSHRule{
								Principals: filteredPrincipals,
								SSHUsers:   lpRule.SSHUsers,
								Action:     lpRule.Action,
							})
						}
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
				// Emit common rule if there are non-localpart users
				if hasCommonUsers {
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
							SSHUsers:   commonUserMap,
							Action:     &action,
						})
					}
				}

				// Emit per-user localpart rules
				rules = append(rules, localpartRules...)
			}
		}
	}

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}, nil
}

// resolveLocalpartRules generates per-user SSH rules for localpart:*@<domain> entries.
// For each localpart entry, it finds all users whose email is in the specified domain,
// extracts their email local-part, and creates a tailcfg.SSHRule scoped to that user's
// node IPs with an SSHUsers map that only allows their local-part.
// The commonUserMap entries (root, autogroup:nonroot, specific users) are merged into
// each per-user rule so that localpart rules compose with other user entries.
func resolveLocalpartRules(
	localpartEntries []SSHUser,
	users types.Users,
	nodes views.Slice[types.NodeView],
	srcIPs *netipx.IPSet,
	commonUserMap map[string]string,
	action *tailcfg.SSHAction,
) []*tailcfg.SSHRule {
	if len(localpartEntries) == 0 {
		return nil
	}

	var rules []*tailcfg.SSHRule

	for _, entry := range localpartEntries {
		domain, err := entry.ParseLocalpart()
		if err != nil {
			// Should not happen if validation passed, but skip gracefully.
			log.Warn().Err(err).Msgf("skipping invalid localpart entry %q during SSH compilation", entry)

			continue
		}

		// Find users whose email matches *@<domain> and build per-user rules.
		for _, user := range users {
			if user.Email == "" {
				continue
			}

			atIdx := strings.LastIndex(user.Email, "@")
			if atIdx < 0 {
				continue
			}

			emailDomain := user.Email[atIdx+1:]
			if !strings.EqualFold(emailDomain, domain) {
				continue
			}

			localPart := user.Email[:atIdx]

			// Find this user's non-tagged nodes that are in the source IP set.
			var userSrcIPs netipx.IPSetBuilder

			for _, n := range nodes.All() {
				if n.IsTagged() {
					continue
				}

				if !n.User().Valid() || n.User().ID() != user.ID {
					continue
				}

				if slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
					n.AppendToIPSet(&userSrcIPs)
				}
			}

			userSrcSet, err := userSrcIPs.IPSet()
			if err != nil || userSrcSet == nil || len(userSrcSet.Prefixes()) == 0 {
				continue
			}

			var principals []*tailcfg.SSHPrincipal
			for addr := range util.IPSetAddrIter(userSrcSet) {
				principals = append(principals, &tailcfg.SSHPrincipal{
					NodeIP: addr.String(),
				})
			}

			if len(principals) == 0 {
				continue
			}

			// Build per-user SSHUsers map: start with the common entries, then add the localpart.
			userMap := make(map[string]string, len(commonUserMap)+1)
			maps.Copy(userMap, commonUserMap)

			userMap[localPart] = localPart

			rules = append(rules, &tailcfg.SSHRule{
				Principals: principals,
				SSHUsers:   userMap,
				Action:     action,
			})
		}
	}

	return rules
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

// filterRuleKey generates a unique key for merging based on SrcIPs and IPProto.
func filterRuleKey(rule tailcfg.FilterRule) string {
	srcKey := strings.Join(rule.SrcIPs, ",")

	protoStrs := make([]string, len(rule.IPProto))
	for i, p := range rule.IPProto {
		protoStrs[i] = strconv.Itoa(p)
	}

	return srcKey + "|" + strings.Join(protoStrs, ",")
}

// mergeFilterRules merges rules with identical SrcIPs and IPProto by combining
// their DstPorts. DstPorts are NOT deduplicated to match Tailscale behavior.
func mergeFilterRules(rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	if len(rules) <= 1 {
		return rules
	}

	keyToIdx := make(map[string]int)
	result := make([]tailcfg.FilterRule, 0, len(rules))

	for _, rule := range rules {
		key := filterRuleKey(rule)

		if idx, exists := keyToIdx[key]; exists {
			// Merge: append DstPorts to existing rule
			result[idx].DstPorts = append(result[idx].DstPorts, rule.DstPorts...)
		} else {
			// New unique combination
			keyToIdx[key] = len(result)
			result = append(result, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: slices.Clone(rule.DstPorts),
				IPProto:  rule.IPProto,
			})
		}
	}

	return result
}
