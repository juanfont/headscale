package v2

import (
	"cmp"
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

// companionCaps maps certain well-known Tailscale capabilities to
// their companion capability. When a grant includes one of these
// capabilities, Tailscale automatically generates an additional
// [tailcfg.FilterRule] with the companion capability and a nil CapMap value.
var companionCaps = map[tailcfg.PeerCapability]tailcfg.PeerCapability{
	tailcfg.PeerCapabilityTaildrive: tailcfg.PeerCapabilityTaildriveSharer,
	tailcfg.PeerCapabilityRelay:     tailcfg.PeerCapabilityRelayTarget,
}

// companionCapGrantRules returns additional [tailcfg.FilterRule]s for any
// well-known capabilities that have companion caps. Companion rules
// are **reversed**: SrcIPs come from the original destinations and
// CapGrant Dsts come from the original sources. This allows
// [policyutil.ReduceFilterRules] to distribute companion rules to source
// nodes (e.g. drive-sharer goes to the member nodes, not the destination).
// Rules are ordered by the original capability name.
//
// dstIPStrings are the resolved destination IPs as strings (used as
// companion SrcIPs). srcPrefixes are the resolved source IPs as
// [netip.Prefix] (used as companion CapGrant Dsts).
func companionCapGrantRules(
	dstIPStrings []string,
	srcPrefixes []netip.Prefix,
	capMap tailcfg.PeerCapMap,
) []tailcfg.FilterRule {
	// Process in deterministic order by original capability name.
	type pair struct {
		original  tailcfg.PeerCapability
		companion tailcfg.PeerCapability
	}

	var pairs []pair

	for cap, companion := range companionCaps {
		if _, ok := capMap[cap]; ok {
			pairs = append(pairs, pair{cap, companion})
		}
	}

	slices.SortFunc(pairs, func(a, b pair) int {
		return cmp.Compare(a.original, b.original)
	})

	companions := make([]tailcfg.FilterRule, 0, len(pairs))

	for _, p := range pairs {
		companions = append(companions, tailcfg.FilterRule{
			SrcIPs: dstIPStrings,
			CapGrant: []tailcfg.CapGrant{
				{
					Dsts: srcPrefixes,
					CapMap: tailcfg.PeerCapMap{
						p.companion: nil,
					},
				},
			},
		})
	}

	return companions
}

// sourcesHaveWildcard returns true if any of the source aliases is
// a wildcard (*). Used to determine whether approved subnet routes
// should be appended to [tailcfg.FilterRule.SrcIPs].
func sourcesHaveWildcard(srcs Aliases) bool {
	for _, src := range srcs {
		if _, ok := src.(Asterix); ok {
			return true
		}
	}

	return false
}

// sourcesHaveDangerAll returns true if any of the source aliases is
// autogroup:danger-all. When present, [tailcfg.FilterRule.SrcIPs] should
// be ["*"] to represent all IP addresses including non-Tailscale addresses.
func sourcesHaveDangerAll(srcs Aliases) bool {
	for _, src := range srcs {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupDangerAll) {
			return true
		}
	}

	return false
}

// srcIPsWithRoutes returns the [tailcfg.FilterRule.SrcIPs] string slice,
// appending approved subnet routes when the sources include a wildcard.
// When hasDangerAll is true, returns ["*"] to represent all IPs.
func srcIPsWithRoutes(
	resolved ResolvedAddresses,
	hasWildcard bool,
	hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	if hasDangerAll {
		return []string{"*"}
	}

	ips := resolved.Strings()
	if hasWildcard {
		ips = append(ips, approvedSubnetRoutes(nodes)...)
	}

	return ips
}

// compileFilterRules takes a set of nodes and a [Policy] and generates a
// set of Tailscale compatible [tailcfg.FilterRule]s used to allow traffic
// on clients.
func (pol *Policy) compileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return tailcfg.FilterAllowAll
	}

	return globalFilterRules(pol.compileGrants(users, nodes))
}

func (pol *Policy) destinationsToNetPortRange(
	users types.Users,
	nodes views.Slice[types.NodeView],
	dests Aliases,
	ports []tailcfg.PortRange,
) []tailcfg.NetPortRange {
	var ret []tailcfg.NetPortRange

	for _, dest := range dests {
		// Check if destination is a wildcard - use "*" directly instead of expanding
		if _, isWildcard := dest.(Asterix); isWildcard {
			for _, port := range ports {
				ret = append(ret, tailcfg.NetPortRange{
					IP:    "*",
					Ports: port,
				})
			}

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
			for _, port := range ports {
				pr := tailcfg.NetPortRange{
					IP:    pref.String(),
					Ports: port,
				}
				// Drop the prefix bits if its a single IP.
				if pref.IsSingleIP() {
					pr.IP = pref.Addr().String()
				}

				ret = append(ret, pr)
			}
		}
	}

	return ret
}

// compileFilterRulesForNode compiles filter rules for a specific node.
func (pol *Policy) compileFilterRulesForNode(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	if pol == nil {
		return tailcfg.FilterAllowAll
	}

	grants := pol.compileGrants(users, nodes)
	userIdx := buildUserNodeIndex(nodes)

	return filterRulesForNode(grants, node, userIdx)
}

var sshAccept = tailcfg.SSHAction{
	Reject:                    false,
	Accept:                    true,
	AllowAgentForwarding:      true,
	AllowLocalPortForwarding:  true,
	AllowRemotePortForwarding: true,
}

// checkPeriodFromRule extracts the check period duration from an [SSH] rule.
// Returns [SSHCheckPeriodDefault] if no checkPeriod is configured,
// 0 if checkPeriod is "always", or the configured duration otherwise.
// This is used server-side by [PolicyManager.SSHCheckParams] to resolve the
// real period when the client calls back; the wire format always sends 0.
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

func sshCheck(baseURL string, _ time.Duration) tailcfg.SSHAction {
	holdURL := baseURL + "/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"

	return tailcfg.SSHAction{
		Reject:          false,
		Accept:          false,
		SessionDuration: 0,
		// Replaced in the client:
		//   * $SRC_NODE_IP (URL escaped)
		//   * $SRC_NODE_ID (Node.ID as int64 string)
		//   * $DST_NODE_IP (URL escaped)
		//   * $DST_NODE_ID (Node.ID as int64 string)
		//   * $SSH_USER (URL escaped, ssh user requested)
		//   * $LOCAL_USER (URL escaped, local user mapped)
		HoldAndDelegate:           holdURL,
		AllowAgentForwarding:      false,
		AllowLocalPortForwarding:  false,
		AllowRemotePortForwarding: false,
	}
}

//nolint:gocyclo // SSH compilation walks per-rule branches with intertwined autogroup:self handling
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
					for _, pref := range ips.Prefixes() {
						dest.AddPrefix(pref)
					}
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
					// Merge user and tagged principals into a
					// single list. Tagged principals preserve
					// per-tag duplication (a node with N tags
					// appears N times, matching SaaS behavior).
					var allPrincipals []*tailcfg.SSHPrincipal
					for _, uid := range userIDs {
						allPrincipals = append(allPrincipals, principalsByUser[uid]...)
					}

					allPrincipals = append(allPrincipals, taggedPrincipals...)

					if len(allPrincipals) > 0 {
						rules = append(rules, &tailcfg.SSHRule{
							Principals: allPrincipals,
							SSHUsers:   baseUserMap,
							Action:     &action,
							AcceptEnv:  acceptEnv,
						})
					}
				}
			} else if hasLocalpart && slices.ContainsFunc(node.IPs(), srcIPs.Contains) {
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

// ipSetToPrincipals converts an [netipx.IPSet] into SSH principals, one per address.
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
	srcIPs ResolvedAddresses,
) ([]uint, map[uint][]*tailcfg.SSHPrincipal, []*tailcfg.SSHPrincipal) {
	userIPSets := make(map[uint]*netipx.IPSetBuilder)

	var taggedPrincipals []*tailcfg.SSHPrincipal

	for _, n := range nodes.All() {
		if !slices.ContainsFunc(n.IPs(), srcIPs.Contains) {
			continue
		}

		if n.IsTagged() {
			// Tailscale SaaS resolves autogroup:tagged by
			// iterating tag membership lists. A node with N
			// tags produces N copies of its IPs in the
			// principal list. Match that behavior so the SSH
			// wire format is identical.
			for range n.Tags().Len() {
				for _, ip := range n.IPs() {
					taggedPrincipals = append(taggedPrincipals,
						&tailcfg.SSHPrincipal{NodeIP: ip.String()})
				}
			}

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

	return userIDs, principalsByUser, taggedPrincipals
}

// filterRuleKey generates a unique key for merging based on [tailcfg.FilterRule.SrcIPs]
// and [tailcfg.FilterRule.IPProto].
func filterRuleKey(rule tailcfg.FilterRule) string {
	srcKey := strings.Join(rule.SrcIPs, ",")

	protoStrs := make([]string, len(rule.IPProto))
	for i, p := range rule.IPProto {
		protoStrs[i] = strconv.Itoa(p)
	}

	return srcKey + "|" + strings.Join(protoStrs, ",")
}

// mergeFilterRules merges rules with identical [tailcfg.FilterRule.SrcIPs] and
// [tailcfg.FilterRule.IPProto] by combining their [tailcfg.FilterRule.DstPorts].
// DstPorts are NOT deduplicated to match Tailscale behavior.
// [tailcfg.CapGrant] rules (which have no [tailcfg.FilterRule.DstPorts]) are
// passed through without merging since [tailcfg.CapGrant] and
// [tailcfg.FilterRule.DstPorts] are mutually exclusive in a
// [tailcfg.FilterRule].
func mergeFilterRules(rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	if len(rules) <= 1 {
		return rules
	}

	keyToIdx := make(map[string]int)
	result := make([]tailcfg.FilterRule, 0, len(rules))

	for _, rule := range rules {
		// CapGrant rules are not merged — they are structurally
		// different from DstPorts rules and passed through as-is.
		if len(rule.CapGrant) > 0 {
			result = append(result, rule)

			continue
		}

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
