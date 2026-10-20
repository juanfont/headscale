package v2

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var errSSHNodeNotInGeneration = errors.New("SSH node does not match policy generation")

func (v ReadView) SSHPolicy(
	baseURL string,
	node types.NodeView,
) (*tailcfg.SSHPolicy, error) {
	policy, err := v.sshPolicy(node)
	if err != nil {
		return nil, err
	}

	return policy.toTailcfg(baseURL), nil
}

func (v ReadView) SSHCheckParams(
	srcNodeID, dstNodeID types.NodeID,
	localUser string,
) (time.Duration, bool) {
	if !v.Valid() {
		return 0, false
	}

	src := v.generation.nodesByID[srcNodeID]
	dst := v.generation.nodesByID[dstNodeID]

	if !src.Valid() || !dst.Valid() {
		return 0, false
	}

	policy, err := v.sshPolicy(dst)
	if err != nil {
		return 0, false
	}

	return policy.checkParams(src, localUser)
}

func (v ReadView) sshPolicy(node types.NodeView) (sshPolicy, error) {
	if !v.Valid() {
		return sshPolicy{}, errInvalidPolicyReadView
	}

	if !node.Valid() || !v.cacheable(node) {
		return sshPolicy{}, errSSHNodeNotInGeneration
	}

	if policy, ok := v.caches.ssh.Load(node.ID()); ok {
		return policy, nil
	}

	g := v.generation

	policy, err := g.pol.compileSSHRules(g.users, g.nodesByID[node.ID()], g.nodes)
	if err != nil {
		return sshPolicy{}, err
	}

	policy, _ = v.caches.ssh.LoadOrStore(node.ID(), policy)

	return policy, nil
}

type sshRule struct {
	principals  []netip.Addr
	users       map[string]string
	action      SSHAction
	checkPeriod time.Duration
	acceptEnv   []string
}

type sshPolicy struct {
	rules []sshRule
}

func (p sshPolicy) toTailcfg(baseURL string) *tailcfg.SSHPolicy {
	// Never nil: clients read a nil SSHPolicy as "keep the previous
	// rules", so revoked access would stay. SaaS sends "rules":[].
	wire := &tailcfg.SSHPolicy{Rules: make([]*tailcfg.SSHRule, 0, len(p.rules))}
	for _, rule := range p.rules {
		var action tailcfg.SSHAction
		switch rule.action {
		case SSHActionAccept:
			action = tailcfg.SSHAction{
				Reject:                    false,
				Accept:                    true,
				AllowAgentForwarding:      true,
				AllowLocalPortForwarding:  true,
				AllowRemotePortForwarding: true,
			}
		case SSHActionCheck:
			holdURL := baseURL + "/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"

			action = tailcfg.SSHAction{
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

		principals := make([]*tailcfg.SSHPrincipal, len(rule.principals))
		for i, addr := range rule.principals {
			principals[i] = &tailcfg.SSHPrincipal{NodeIP: addr.String()}
		}

		wire.Rules = append(wire.Rules, &tailcfg.SSHRule{
			Principals: principals,
			SSHUsers:   maps.Clone(rule.users),
			Action:     &action,
			AcceptEnv:  slices.Clone(rule.acceptEnv),
		})
	}

	return wire
}

// reachableSets returns the addresses that can log in as user via:
//
//   - any matching rule (reach, satisfies accept assertions)
//   - a check-action rule (check, satisfies check assertions)
func (p sshPolicy) reachableSets(user string) (ipset.Set, ipset.Set, error) {
	var reachable, checked ipset.Builder

	for _, rule := range p.rules {
		if !sshUserMapAllows(rule.users, user) {
			continue
		}

		switch rule.action {
		case SSHActionAccept, SSHActionCheck:
			for _, addr := range rule.principals {
				// Source sets have no zones, so a zoned principal cannot match.
				if addr.Zone() != "" {
					continue
				}

				reachable.AddAddr(addr)

				if rule.action == SSHActionCheck {
					checked.AddAddr(addr)
				}
			}
		}
	}

	reach, err := reachable.Build()
	if err != nil {
		return ipset.Set{}, ipset.Set{}, err
	}

	check, err := checked.Build()

	return reach, check, err
}

// checkParams returns the first matching check rule's server-side period.
func (p sshPolicy) checkParams(
	src types.NodeView,
	localUser string,
) (time.Duration, bool) {
	for _, rule := range p.rules {
		if rule.action != SSHActionCheck || !sshUserMapAllows(rule.users, localUser) {
			continue
		}

		for _, addr := range src.IPs() {
			if slices.Contains(rule.principals, addr) {
				return rule.checkPeriod, true
			}
		}
	}

	return 0, false
}

// sshUserMapAllows reports whether [SSHUsers] permits user. The [SSHUsers]
// mapping shape (see ssh.go compileSSHRules):
//
//   - SSHUsers["root"] == "root" allows root; == "" disallows it.
//   - SSHUsers["*"] == "=" is the wildcard fallback for non-root users
//     (set when the rule lists autogroup:nonroot).
//   - SSHUsers[<literal>] == <literal> for every named user.
func sshUserMapAllows(m map[string]string, user string) bool {
	if user == "" {
		return false
	}

	if v, ok := m[user]; ok {
		return v != ""
	}

	if user == "root" {
		return false
	}

	// Wildcard fallback for non-root users.
	if v, ok := m["*"]; ok {
		return v != ""
	}

	return false
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

//nolint:gocyclo // SSH compilation walks per-rule branches with intertwined autogroup:self handling
func (pol *Policy) compileSSHRules(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (sshPolicy, error) {
	if pol == nil || len(pol.SSHs) == 0 {
		return sshPolicy{}, nil
	}

	log.Trace().Caller().Msgf("compiling SSH policy for node %q", node.Hostname())

	var rules []sshRule

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

		if srcIPs.IsEmpty() {
			continue
		}

		switch rule.Action {
		case SSHActionAccept, SSHActionCheck:
		default:
			return sshPolicy{}, fmt.Errorf(
				"parsing SSH policy, unknown action %q, index: %d: %w",
				rule.Action, index, ErrSSHActionInvalid,
			)
		}

		acceptEnv := slices.Clone(rule.AcceptEnv)

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
		appendRules := func(principals []netip.Addr, uid uint, hasUID bool) {
			rules = append(rules, sshRule{
				principals:  principals,
				users:       baseUserMap,
				action:      rule.Action,
				checkPeriod: checkPeriodFromRule(rule),
				acceptEnv:   acceptEnv,
			})

			if hasUID {
				if lp, ok := localpartByUser[uid]; ok {
					rules = append(rules, sshRule{
						principals:  principals,
						users:       map[string]string{lp: lp},
						action:      rule.Action,
						checkPeriod: checkPeriodFromRule(rule),
						acceptEnv:   acceptEnv,
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
			var dest ipset.Builder

			for _, dst := range otherDests {
				ips, err := dst.Resolve(pol, users, nodes)
				if err != nil {
					log.Trace().Caller().Err(err).
						Msgf("resolving destination ips")
				}

				dest.AddSet(ips)
			}

			destSet, err := dest.Build()
			if err != nil {
				return sshPolicy{}, err
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
					var allPrincipals []netip.Addr
					for _, uid := range userIDs {
						allPrincipals = append(allPrincipals, principalsByUser[uid]...)
					}

					allPrincipals = append(allPrincipals, taggedPrincipals...)

					if len(allPrincipals) > 0 {
						appendRules(allPrincipals, 0, false)
					}
				}
			} else if hasLocalpart && node.InIPSet(srcIPs) {
				// Self-access: source node not in destination set
				// receives rules scoped to its own user.
				if node.IsTagged() {
					var builder ipset.Builder

					node.AppendToIPSet(&builder)

					ipSet, err := builder.Build()
					if err == nil && !ipSet.IsEmpty() {
						if principals := slices.Collect(
							ipSet.Addrs(),
						); len(
							principals,
						) > 0 {
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
	slices.SortStableFunc(rules, func(a, b sshRule) int {
		aIsCheck := a.action == SSHActionCheck

		bIsCheck := b.action == SSHActionCheck
		if aIsCheck == bIsCheck {
			return 0
		}

		if aIsCheck {
			return -1
		}

		return 1
	})

	return sshPolicy{rules: rules}, nil
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
	srcIPs ipset.Set,
) ([]uint, map[uint][]netip.Addr, []netip.Addr) {
	userIPSets := make(map[uint]*ipset.Builder)

	var taggedPrincipals []netip.Addr

	for _, n := range nodes.All() {
		if !n.InIPSet(srcIPs) {
			continue
		}

		if n.IsTagged() {
			// Tailscale SaaS resolves autogroup:tagged by
			// iterating tag membership lists. A node with N
			// tags produces N copies of its IPs in the
			// principal list. Match that behavior so the SSH
			// wire format is identical.
			for range n.Tags().Len() {
				taggedPrincipals = append(taggedPrincipals, n.IPs()...)
			}

			continue
		}

		if !n.User().Valid() {
			continue
		}

		uid := n.User().ID()

		if _, ok := userIPSets[uid]; !ok {
			userIPSets[uid] = &ipset.Builder{}
		}

		n.AppendToIPSet(userIPSets[uid])
	}

	var userIDs []uint

	principalsByUser := make(map[uint][]netip.Addr, len(userIPSets))

	for uid, builder := range userIPSets {
		ipSet, err := builder.Build()
		if err != nil || ipSet.IsEmpty() {
			continue
		}

		if principals := slices.Collect(ipSet.Addrs()); len(principals) > 0 {
			principalsByUser[uid] = principals
			userIDs = append(userIDs, uid)
		}
	}

	slices.Sort(userIDs)

	return userIDs, principalsByUser, taggedPrincipals
}
