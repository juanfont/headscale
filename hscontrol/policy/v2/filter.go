package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/views"
)

var (
	ErrInvalidAction = errors.New("invalid action")
	errSelfInSources = errors.New("autogroup:self cannot be used in sources")
)

// companionCap pairs a well-known Tailscale capability with its
// companion capability.
type companionCap struct {
	original  peercap.Cap
	companion peercap.Cap
}

// companionCaps lists certain well-known Tailscale capabilities and
// their companion capability. When a grant includes one of these
// capabilities, Tailscale automatically generates an additional
// [tailcfg.FilterRule] with the companion capability and a nil CapMap value.
// The slice is ordered by the original capability name so that
// generated companion rules are emitted deterministically.
var companionCaps = []companionCap{
	{peercap.Taildrive, peercap.TaildriveSharer},
	{peercap.Relay, peercap.RelayTarget},
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
	companions := make([]tailcfg.FilterRule, 0, len(companionCaps))

	for _, c := range companionCaps {
		if _, ok := capMap[c.original]; ok {
			companions = append(companions, tailcfg.FilterRule{
				SrcIPs: dstIPStrings,
				CapGrant: []tailcfg.CapGrant{
					{
						Dsts: srcPrefixes,
						CapMap: tailcfg.PeerCapMap{
							c.companion: nil,
						},
					},
				},
			})
		}
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
				ret = append(ret, tailcfg.NetPortRange{
					IP:    filterIP(pref),
					Ports: port,
				})
			}
		}
	}

	return ret
}

// filterIP writes pref as a filter destination: a single address bare,
// any other prefix with its bits, as Tailscale SaaS writes them.
func filterIP(pref netip.Prefix) string {
	if pref.IsSingleIP() {
		return pref.Addr().String()
	}

	return pref.String()
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

	return append(
		filterRulesForNode(grants, node, userIdx),
		exitNodeSelfRules(grants, node, userIdx)...,
	)
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

func sshCheck(baseURL string) tailcfg.SSHAction {
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

// compiledSSHRule is an [SSH] rule with everything that does not depend on
// the node it is delivered to already resolved, as [compiledGrant] is for
// grants. It is read-only once built: the SSH policies of all nodes point
// into it, so what a rule expands to is kept once and not once per node.
type compiledSSHRule struct {
	srcs *sshSources

	sshUsers        map[string]string
	localpartByUser map[uint]string
	action          *tailcfg.SSHAction
	acceptEnv       []string

	hasLocalpart bool
	hasSelfDest  bool

	// userRules holds the rules scoped to one source user's own nodes,
	// for autogroup:self destinations and localpart self-access.
	userRules map[uint][]*tailcfg.SSHRule

	// dests holds the destinations other than autogroup:self, nil if
	// there are none. Every node in it gets destRules.
	dests     *netipx.IPSet
	destRules []*tailcfg.SSHRule
}

// uidZeroLogin is a login name that can resolve to uid 0 on the node, so
// every rule that maps root maps it to no local user, as Tailscale SaaS does.
const uidZeroLogin = "0"

// sshSources is what the sources of an [SSH] rule resolve to. It is
// read-only once built: rules with the same source addresses share it.
type sshSources struct {
	ips              ResolvedAddresses
	userIDs          []uint
	principalsByUser map[uint][]*tailcfg.SSHPrincipal
	taggedPrincipals []*tailcfg.SSHPrincipal

	// allPrincipals merges user and tagged principals into a single
	// list. Tagged principals preserve per-tag duplication (a node with
	// N tags appears N times, matching SaaS behavior).
	allPrincipals []*tailcfg.SSHPrincipal
}

// rules emits a common rule and, if the user has a localpart match, a
// per-user localpart rule.
func (r *compiledSSHRule) rules(
	principals []*tailcfg.SSHPrincipal,
	uid uint,
	hasUID bool,
) []*tailcfg.SSHRule {
	rules := []*tailcfg.SSHRule{{
		Principals: principals,
		SSHUsers:   r.sshUsers,
		Action:     r.action,
		AcceptEnv:  r.acceptEnv,
	}}

	if hasUID {
		if lp, ok := r.localpartByUser[uid]; ok {
			rules = append(rules, &tailcfg.SSHRule{
				Principals: principals,
				SSHUsers:   map[string]string{lp: lp},
				Action:     r.action,
				AcceptEnv:  r.acceptEnv,
			})
		}
	}

	return rules
}

// compileSSHRules resolves all SSH rules of the policy into
// [compiledSSHRule] structs. Rules whose sources resolve to nothing are
// left out.
//
//nolint:gocyclo // SSH compilation walks per-rule branches with intertwined autogroup:self handling
func (pol *Policy) compileSSHRules(
	baseURL string,
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]compiledSSHRule, error) {
	if pol == nil {
		return nil, nil
	}

	compiled := make([]compiledSSHRule, 0, len(pol.SSHs))

	// There is one principal per source address and the policy author
	// decides how many rules there are, so rules whose sources resolve to
	// the same addresses share their principals.
	sources := make(map[string]*sshSources)

	for index, rule := range pol.SSHs {
		var otherDests []Alias

		cr := compiledSSHRule{
			hasLocalpart: rule.Users.ContainsLocalpart(),
			acceptEnv:    rule.AcceptEnv,
		}

		for _, dst := range rule.Destinations {
			if ag, ok := dst.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				cr.hasSelfDest = true
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
			action = sshCheck(baseURL)
		default:
			return nil, fmt.Errorf(
				"parsing SSH policy, unknown action %q, index: %d: %w",
				rule.Action, index, err,
			)
		}

		cr.action = &action

		// Build the common userMap (always has at least a root entry).
		const rootUser = "root"

		cr.sshUsers = make(map[string]string, len(rule.Users))
		if rule.Users.ContainsNonRoot() {
			cr.sshUsers["*"] = "="
		}

		if rule.Users.ContainsRoot() {
			cr.sshUsers[rootUser] = rootUser
		} else {
			cr.sshUsers[rootUser] = ""
		}

		for _, u := range rule.Users.NormalUsers() {
			cr.sshUsers[u.String()] = u.String()
		}

		// After the literal users, so listing "0" cannot map it.
		cr.sshUsers[uidZeroLogin] = ""

		if cr.hasLocalpart {
			cr.localpartByUser = resolveLocalparts(
				rule.Users.LocalpartEntries(), users,
			)
		}

		srcKey := strings.Join(srcIPs.Strings(), ",")

		srcs, ok := sources[srcKey]
		if !ok {
			userIDs, byUser, tagged := groupSourcesByUser(nodes, srcIPs)
			srcs = &sshSources{
				ips:              srcIPs,
				userIDs:          userIDs,
				principalsByUser: byUser,
				taggedPrincipals: tagged,
			}

			for _, uid := range srcs.userIDs {
				srcs.allPrincipals = append(
					srcs.allPrincipals, srcs.principalsByUser[uid]...,
				)
			}

			srcs.allPrincipals = append(srcs.allPrincipals, srcs.taggedPrincipals...)

			sources[srcKey] = srcs
		}

		cr.srcs = srcs

		if cr.hasSelfDest || cr.hasLocalpart {
			cr.userRules = make(map[uint][]*tailcfg.SSHRule, len(srcs.userIDs))
			for _, uid := range srcs.userIDs {
				cr.userRules[uid] = cr.rules(srcs.principalsByUser[uid], uid, true)
			}
		}

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

			cr.dests, err = dest.IPSet()
			if err != nil {
				return nil, err
			}

			// When localpart entries exist, interleave common
			// and localpart rules per source user to match
			// Tailscale SaaS first-match-wins ordering.
			if cr.hasLocalpart {
				for _, uid := range srcs.userIDs {
					cr.destRules = append(cr.destRules, cr.userRules[uid]...)
				}

				if len(srcs.taggedPrincipals) > 0 {
					cr.destRules = append(
						cr.destRules, cr.rules(srcs.taggedPrincipals, 0, false)...,
					)
				}
			} else if len(srcs.allPrincipals) > 0 {
				cr.destRules = cr.rules(srcs.allPrincipals, 0, false)
			}
		}

		compiled = append(compiled, cr)
	}

	return compiled, nil
}

// sshPolicyForNode picks the rules that apply to node out of compiled.
func sshPolicyForNode(
	compiled []compiledSSHRule,
	node types.NodeView,
) *tailcfg.SSHPolicy {
	// Never nil: clients read a nil SSHPolicy as "keep the previous
	// rules", so revoked access would stay. SaaS sends "rules":[].
	rules := []*tailcfg.SSHRule{}

	for i := range compiled {
		cr := &compiled[i]

		// Handle autogroup:self destinations.
		// Tagged nodes can't match autogroup:self.
		if cr.hasSelfDest && !node.IsTagged() && node.User().Valid() {
			rules = append(rules, cr.userRules[node.User().ID()]...)
		}

		// Handle other destinations.
		if cr.dests == nil {
			continue
		}

		if node.InIPSet(cr.dests) {
			// Node is a destination — emit rules.
			rules = append(rules, cr.destRules...)
		} else if cr.hasLocalpart &&
			slices.ContainsFunc(node.IPs(), cr.srcs.ips.Contains) {
			// Self-access: source node not in destination set
			// receives rules scoped to its own user.
			if node.IsTagged() {
				var builder netipx.IPSetBuilder

				node.AppendToIPSet(&builder)

				ipSet, err := builder.IPSet()
				if err == nil && ipSet != nil {
					if principals := ipSetToPrincipals(ipSet); len(principals) > 0 {
						rules = append(rules, cr.rules(principals, 0, false)...)
					}
				}
			} else if node.User().Valid() {
				rules = append(rules, cr.userRules[node.User().ID()]...)
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
	}
}

// compileSSHPolicy compiles the SSH policy of a single node.
// [PolicyManager.SSHPolicy], which is asked for every node, keeps the
// result of [Policy.compileSSHRules] instead.
func (pol *Policy) compileSSHPolicy(
	baseURL string,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	log.Trace().Caller().Msgf("compiling SSH policy for node %q", node.Hostname())

	compiled, err := pol.compileSSHRules(baseURL, users, nodes)
	if err != nil {
		return nil, err
	}

	return sshPolicyForNode(compiled, node), nil
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

			localpart, emailDomain, found := strings.CutLast(user.Email, "@")
			if !found {
				continue
			}

			if !strings.EqualFold(emailDomain, domain) {
				continue
			}

			result[user.ID] = localpart
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
	return fmt.Sprintf("%s|%v", strings.Join(rule.SrcIPs, ","), rule.IPProto)
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

	// sharedSrcIPs identifies a SrcIPs slice by its backing array.
	type sharedSrcIPs struct {
		first   *string
		n       int
		ipProto string
	}

	keyToIdx := make(map[string]int)
	sharedToIdx := make(map[sharedSrcIPs]int)
	result := make([]tailcfg.FilterRule, 0, len(rules))

	for _, rule := range rules {
		// CapGrant rules are not merged — they are structurally
		// different from DstPorts rules and passed through as-is.
		if len(rule.CapGrant) > 0 {
			result = append(result, rule)

			continue
		}

		// An ACL compiles to one rule per destination, all with the same
		// SrcIPs slice. Build the key of a slice once, or merging them is
		// len(src) × len(dst) work.
		shared := sharedSrcIPs{
			n:       len(rule.SrcIPs),
			ipProto: fmt.Sprint(rule.IPProto),
		}
		if len(rule.SrcIPs) > 0 {
			shared.first = &rule.SrcIPs[0]
		}

		idx, exists := sharedToIdx[shared]
		if !exists {
			key := filterRuleKey(rule)

			idx, exists = keyToIdx[key]
			if !exists {
				idx = len(result)
				keyToIdx[key] = idx
			}

			sharedToIdx[shared] = idx
		}

		if exists {
			// Merge: append DstPorts to existing rule
			result[idx].DstPorts = append(result[idx].DstPorts, rule.DstPorts...)
		} else {
			// New unique combination
			result = append(result, tailcfg.FilterRule{
				SrcIPs:   rule.SrcIPs,
				DstPorts: slices.Clone(rule.DstPorts),
				IPProto:  rule.IPProto,
			})
		}
	}

	return result
}
