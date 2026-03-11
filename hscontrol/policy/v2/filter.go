package v2

import (
	"errors"
	"fmt"
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

var sshAccept = tailcfg.SSHAction{
	Reject:                    false,
	Accept:                    true,
	AllowAgentForwarding:      true,
	AllowLocalPortForwarding:  true,
	AllowRemotePortForwarding: true,
}

// checkPeriodFromRule extracts the check period duration from an SSH rule.
// Returns SSHCheckPeriodDefault if no checkPeriod is configured,
// 0 if checkPeriod is "always", or the configured duration otherwise.
func checkPeriodFromRule(rule SSH) time.Duration {
	switch {
	case rule.CheckPeriod == nil:
		return SSHCheckPeriodDefault
	case rule.CheckPeriod.Always:
		return 0
	default:
		return rule.CheckPeriod.Duration
	}
}

func sshCheck(baseURL string, duration time.Duration) tailcfg.SSHAction {
	holdURL := baseURL + "/machine/ssh/action/from/$SRC_NODE_ID/to/$DST_NODE_ID?ssh_user=$SSH_USER&local_user=$LOCAL_USER"

	return tailcfg.SSHAction{
		Reject:          false,
		Accept:          false,
		SessionDuration: duration,
		// Replaced in the client:
		//   * $SRC_NODE_IP (URL escaped)
		//   * $SRC_NODE_ID (Node.ID as int64 string)
		//   * $DST_NODE_IP (URL escaped)
		//   * $DST_NODE_ID (Node.ID as int64 string)
		//   * $SSH_USER (URL escaped, ssh user requested)
		//   * $LOCAL_USER (URL escaped, local user mapped)
		HoldAndDelegate:           holdURL,
		AllowAgentForwarding:      true,
		AllowLocalPortForwarding:  true,
		AllowRemotePortForwarding: true,
	}
}

func (pol *Policy) compileSSHPolicy(
	baseURL string,
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
		var autogroupSelfDests, otherDests []Alias

		for _, dst := range rule.Destinations {
			if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				autogroupSelfDests = append(autogroupSelfDests, dst)
			} else {
				otherDests = append(otherDests, dst)
			}
		}

		srcIPs, err := rule.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf(
				"ssh policy compilation failed resolving source ips for rule %+v", rule,
			)
		}

		if srcIPs == nil || len(srcIPs.Prefixes()) == 0 {
			continue
		}

		var action tailcfg.SSHAction

		switch rule.Action {
		case SSHActionAccept:
			action = sshAccept
		case SSHActionCheck:
			action = sshCheck(baseURL, checkPeriodFromRule(rule))
		default:
			return nil, fmt.Errorf(
				"parsing SSH policy, unknown action %q, index: %d: %w",
				rule.Action, index, err,
			)
		}

		acceptEnv := rule.AcceptEnv

		// Build the common userMap (always has at least a root entry).
		const rootUser = "root"

		baseUserMap := make(map[string]string, len(rule.Users))
		if rule.Users.ContainsNonRoot() {
			baseUserMap["*"] = "="
		}

		if rule.Users.ContainsRoot() {
			baseUserMap[rootUser] = rootUser
		} else {
			baseUserMap[rootUser] = ""
		}

		for _, u := range rule.Users.NormalUsers() {
			baseUserMap[u.String()] = u.String()
		}

		hasLocalpart := rule.Users.ContainsLocalpart()

		var localpartByUser map[uint]string
		if hasLocalpart {
			localpartByUser = resolveLocalparts(
				rule.Users.LocalpartEntries(), users,
			)
		}

		userIDs, principalsByUser, taggedPrincipals := groupSourcesByUser(
			nodes, srcIPs,
		)

		// appendRules emits a common rule and, if the user has a
		// localpart match, a per-user localpart rule.
		appendRules := func(principals []*tailcfg.SSHPrincipal, uid uint, hasUID bool) {
			rules = append(rules, &tailcfg.SSHRule{
				Principals: principals,
				SSHUsers:   baseUserMap,
				Action:     &action,
				AcceptEnv:  acceptEnv,
			})

			if hasUID {
				if lp, ok := localpartByUser[uid]; ok {
					rules = append(rules, &tailcfg.SSHRule{
						Principals: principals,
						SSHUsers:   map[string]string{lp: lp},
						Action:     &action,
						AcceptEnv:  acceptEnv,
					})
				}
			}
		}

		// Handle autogroup:self destinations.
		// Tagged nodes can't match autogroup:self.
		if len(autogroupSelfDests) > 0 &&
			!node.IsTagged() && node.User().Valid() {
			uid := node.User().ID()

			if principals := principalsByUser[uid]; len(principals) > 0 {
				appendRules(principals, uid, true)
			}
		}

		// Handle other destinations.
		if len(otherDests) > 0 {
			var dest netipx.IPSetBuilder

			for _, dst := range otherDests {
				ips, err := dst.Resolve(pol, users, nodes)
				if err != nil {
					log.Trace().Caller().Err(err).
						Msgf("resolving destination ips")
				}

				if ips != nil {
					dest.AddSet(ips)
				}
			}

			destSet, err := dest.IPSet()
			if err != nil {
				return nil, err
			}

			if node.InIPSet(destSet) {
				// Node is a destination — emit rules.
				// When localpart entries exist, interleave common
				// and localpart rules per source user to match
				// Tailscale SaaS first-match-wins ordering.
				if hasLocalpart {
					for _, uid := range userIDs {
						appendRules(principalsByUser[uid], uid, true)
					}

					if len(taggedPrincipals) > 0 {
						appendRules(taggedPrincipals, 0, false)
					}
				} else {
					if principals := ipSetToPrincipals(srcIPs); len(principals) > 0 {
						rules = append(rules, &tailcfg.SSHRule{
							Principals: principals,
							SSHUsers:   baseUserMap,
							Action:     &action,
							AcceptEnv:  acceptEnv,
						})
					}
				}
			} else if hasLocalpart && node.InIPSet(srcIPs) {
				// Self-access: source node not in destination set
				// receives rules scoped to its own user.
				if node.IsTagged() {
					var builder netipx.IPSetBuilder

					node.AppendToIPSet(&builder)

					ipSet, err := builder.IPSet()
					if err == nil && ipSet != nil {
						if principals := ipSetToPrincipals(ipSet); len(principals) > 0 {
							appendRules(principals, 0, false)
						}
					}
				} else if node.User().Valid() {
					uid := node.User().ID()
					if principals := principalsByUser[uid]; len(principals) > 0 {
						appendRules(principals, uid, true)
					}
				}
			}
		}
	}

	// Sort rules: check (HoldAndDelegate) before accept, per Tailscale
	// evaluation order (most-restrictive first).
	slices.SortStableFunc(rules, func(a, b *tailcfg.SSHRule) int {
		aIsCheck := a.Action != nil && a.Action.HoldAndDelegate != ""

		bIsCheck := b.Action != nil && b.Action.HoldAndDelegate != ""
		if aIsCheck == bIsCheck {
			return 0
		}

		if aIsCheck {
			return -1
		}

		return 1
	})

	return &tailcfg.SSHPolicy{
		Rules: rules,
	}, nil
}

// ipSetToPrincipals converts an IPSet into SSH principals, one per address.
func ipSetToPrincipals(ipSet *netipx.IPSet) []*tailcfg.SSHPrincipal {
	if ipSet == nil {
		return nil
	}

	var principals []*tailcfg.SSHPrincipal

	for addr := range util.IPSetAddrIter(ipSet) {
		principals = append(principals, &tailcfg.SSHPrincipal{
			NodeIP: addr.String(),
		})
	}

	return principals
}

// resolveLocalparts maps each user whose email matches a localpart:*@<domain>
// entry to their email local-part. Returns userID → localPart (e.g. {1: "alice"}).
// This is a pure data function — no node walking or IP resolution.
func resolveLocalparts(
	entries []SSHUser,
	users types.Users,
) map[uint]string {
	if len(entries) == 0 {
		return nil
	}

	result := make(map[uint]string)

	for _, entry := range entries {
		domain, err := entry.ParseLocalpart()
		if err != nil {
			log.Warn().Err(err).Msgf(
				"skipping invalid localpart entry %q during SSH compilation",
				entry,
			)

			continue
		}

		for _, user := range users {
			if user.Email == "" {
				continue
			}

			atIdx := strings.LastIndex(user.Email, "@")
			if atIdx < 0 {
				continue
			}

			if !strings.EqualFold(user.Email[atIdx+1:], domain) {
				continue
			}

			result[user.ID] = user.Email[:atIdx]
		}
	}

	return result
}

// groupSourcesByUser groups source node IPs by user ownership. Returns sorted
// user IDs for deterministic iteration, per-user principals, and tagged principals.
// Only includes nodes whose IPs are in the srcIPs set.
func groupSourcesByUser(
	nodes views.Slice[types.NodeView],
	srcIPs *netipx.IPSet,
) ([]uint, map[uint][]*tailcfg.SSHPrincipal, []*tailcfg.SSHPrincipal) {
	userIPSets := make(map[uint]*netipx.IPSetBuilder)

	var taggedIPSet netipx.IPSetBuilder

	hasTagged := false

	for _, n := range nodes.All() {
		if !slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
			continue
		}

		if n.IsTagged() {
			n.AppendToIPSet(&taggedIPSet)

			hasTagged = true

			continue
		}

		if !n.User().Valid() {
			continue
		}

		uid := n.User().ID()

		if _, ok := userIPSets[uid]; !ok {
			userIPSets[uid] = &netipx.IPSetBuilder{}
		}

		n.AppendToIPSet(userIPSets[uid])
	}

	var userIDs []uint

	principalsByUser := make(map[uint][]*tailcfg.SSHPrincipal, len(userIPSets))

	for uid, builder := range userIPSets {
		ipSet, err := builder.IPSet()
		if err != nil || ipSet == nil {
			continue
		}

		if principals := ipSetToPrincipals(ipSet); len(principals) > 0 {
			principalsByUser[uid] = principals
			userIDs = append(userIDs, uid)
		}
	}

	slices.Sort(userIDs)

	var tagged []*tailcfg.SSHPrincipal

	if hasTagged {
		taggedSet, err := taggedIPSet.IPSet()
		if err == nil && taggedSet != nil {
			tagged = ipSetToPrincipals(taggedSet)
		}
	}

	return userIDs, principalsByUser, tagged
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
