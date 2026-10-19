package v2

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

var (
	ErrInvalidAction = errors.New("invalid action")
	errSelfInSources = errors.New("autogroup:self cannot be used in sources")
)

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

//nolint:gocyclo // SSH compilation walks per-rule branches with intertwined autogroup:self handling
func (pol *Policy) compileSSHPolicy(
	baseURL string,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) (*tailcfg.SSHPolicy, error) {
	// Never nil: clients read a nil SSHPolicy as "keep the previous
	// rules", so revoked access would stay. SaaS sends "rules":[].
	if pol == nil || len(pol.SSHs) == 0 {
		return &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}, nil
	}

	log.Trace().Caller().Msgf("compiling SSH policy for node %q", node.Hostname())

	rules := []*tailcfg.SSHRule{}

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
						appendRules(allPrincipals, 0, false)
					}
				}
			} else if hasLocalpart && slices.ContainsFunc(node.IPs(), srcIPs.Contains) {
				// Self-access: source node not in destination set
				// receives rules scoped to its own user.
				if node.IsTagged() {
					var builder ipset.Builder

					node.AppendToIPSet(&builder)

					ipSet, err := builder.Build()
					if err == nil && !ipSet.IsEmpty() {
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

// ipSetToPrincipals converts an [ipset.Set] into SSH principals, one per address.
func ipSetToPrincipals(ipSet ipset.Set) []*tailcfg.SSHPrincipal {
	if ipSet.IsEmpty() {
		return nil
	}

	var principals []*tailcfg.SSHPrincipal

	for addr := range ipSet.Addrs() {
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
	srcIPs ipset.Set,
) ([]uint, map[uint][]*tailcfg.SSHPrincipal, []*tailcfg.SSHPrincipal) {
	userIPSets := make(map[uint]*ipset.Builder)

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
			userIPSets[uid] = &ipset.Builder{}
		}

		n.AppendToIPSet(userIPSets[uid])
	}

	var userIDs []uint

	principalsByUser := make(map[uint][]*tailcfg.SSHPrincipal, len(userIPSets))

	for uid, builder := range userIPSets {
		ipSet, err := builder.Build()
		if err != nil || ipSet.IsEmpty() {
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
