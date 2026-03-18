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

// companionCaps maps certain well-known Tailscale capabilities to
// their companion capability. When a grant includes one of these
// capabilities, Tailscale automatically generates an additional
// FilterRule with the companion capability and a nil CapMap value.
var companionCaps = map[tailcfg.PeerCapability]tailcfg.PeerCapability{
	tailcfg.PeerCapabilityTaildrive: tailcfg.PeerCapabilityTaildriveSharer,
	tailcfg.PeerCapabilityRelay:     tailcfg.PeerCapabilityRelayTarget,
}

// companionCapGrantRules returns additional FilterRules for any
// well-known capabilities that have companion caps. Companion rules
// are **reversed**: SrcIPs come from the original destinations and
// CapGrant Dsts come from the original sources. This allows
// ReduceFilterRules to distribute companion rules to source nodes
// (e.g. drive-sharer goes to the member nodes, not the destination).
// Rules are ordered by the original capability name.
//
// dstIPStrings are the resolved destination IPs as strings (used as
// companion SrcIPs). srcPrefixes are the resolved source IPs as
// netip.Prefix (used as companion CapGrant Dsts).
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
		return strings.Compare(string(a.original), string(b.original))
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
// should be appended to SrcIPs.
func sourcesHaveWildcard(srcs Aliases) bool {
	for _, src := range srcs {
		if _, ok := src.(Asterix); ok {
			return true
		}
	}

	return false
}

// sourcesHaveDangerAll returns true if any of the source aliases is
// autogroup:danger-all. When present, SrcIPs should be ["*"] to
// represent all IP addresses including non-Tailscale addresses.
func sourcesHaveDangerAll(srcs Aliases) bool {
	for _, src := range srcs {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupDangerAll) {
			return true
		}
	}

	return false
}

// srcIPsWithRoutes returns the SrcIPs string slice, appending
// approved subnet routes when the sources include a wildcard.
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

	grants := pol.Grants
	for _, acl := range pol.ACLs {
		grants = append(grants, aclToGrants(acl)...)
	}

	for _, grant := range grants {
		// Via grants are compiled per-node in compileViaGrant,
		// not in the global filter set.
		if len(grant.Via) > 0 {
			continue
		}

		srcIPs, err := grant.Sources.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if srcIPs.Empty() {
			continue
		}

		hasWildcard := sourcesHaveWildcard(grant.Sources)
		hasDangerAll := sourcesHaveDangerAll(grant.Sources)

		for _, ipp := range grant.InternetProtocols {
			destPorts := pol.destinationsToNetPortRange(users, nodes, grant.Destinations, ipp.Ports)

			if len(destPorts) > 0 {
				rules = append(rules, tailcfg.FilterRule{
					SrcIPs:   srcIPsWithRoutes(srcIPs, hasWildcard, hasDangerAll, nodes),
					DstPorts: destPorts,
					IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
				})
			}
		}

		if grant.App != nil {
			var (
				capGrants    []tailcfg.CapGrant
				dstIPStrings []string
			)

			for _, dst := range grant.Destinations {
				ips, err := dst.Resolve(pol, users, nodes)
				if err != nil {
					continue
				}

				dstPrefixes := ips.Prefixes()
				capGrants = append(capGrants, tailcfg.CapGrant{
					Dsts:   dstPrefixes,
					CapMap: grant.App,
				})

				dstIPStrings = append(dstIPStrings, ips.Strings()...)
			}

			srcIPStrs := srcIPsWithRoutes(srcIPs, hasWildcard, hasDangerAll, nodes)
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcIPStrs,
				CapGrant: capGrants,
			})

			// Companion rules use reversed direction: SrcIPs are
			// destination IPs and CapGrant Dsts are source IPs.
			// When destinations include a wildcard, add subnet
			// routes to companion SrcIPs (same as main rule).
			dstsHaveWildcard := sourcesHaveWildcard(grant.Destinations)
			if dstsHaveWildcard {
				dstIPStrings = append(dstIPStrings, approvedSubnetRoutes(nodes)...)
			}

			rules = append(
				rules,
				companionCapGrantRules(dstIPStrings, srcIPs.Prefixes(), grant.App)...,
			)
		}
	}

	return mergeFilterRules(rules), nil
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

		// autogroup:internet does not generate packet filters - it's handled
		// by exit node routing via AllowedIPs, not by packet filtering.
		if ag, isAutoGroup := dest.(*AutoGroup); isAutoGroup && ag.Is(AutoGroupInternet) {
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
) ([]tailcfg.FilterRule, error) {
	if pol == nil {
		return tailcfg.FilterAllowAll, nil
	}

	var rules []tailcfg.FilterRule

	grants := pol.Grants
	for _, acl := range pol.ACLs {
		grants = append(grants, aclToGrants(acl)...)
	}

	for _, grant := range grants {
		res, err := pol.compileGrantWithAutogroupSelf(grant, users, node, nodes)
		if err != nil {
			log.Trace().Err(err).Msgf("compiling ACL")
			continue
		}

		rules = append(rules, res...)
	}

	return mergeFilterRules(rules), nil
}

// compileViaGrant compiles a grant with a "via" field. Via grants
// produce filter rules ONLY on nodes matching a via tag that actually
// advertise (and have approved) the destination subnets. All other
// nodes receive no rules. App-only via grants (no ip field) produce
// no packet filter rules.
func (pol *Policy) compileViaGrant(
	grant Grant,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	// Check if the current node matches any of the via tags.
	matchesVia := false

	for _, viaTag := range grant.Via {
		if node.HasTag(string(viaTag)) {
			matchesVia = true

			break
		}
	}

	if !matchesVia {
		return nil, nil
	}

	// App-only via grants produce no packet filter rules.
	if len(grant.InternetProtocols) == 0 {
		return nil, nil
	}

	// Find which grant destination subnets this node actually advertises.
	nodeRoutes := node.SubnetRoutes()
	if len(nodeRoutes) == 0 {
		return nil, nil
	}

	// Collect destination prefixes that match the node's approved routes.
	var viaDstPrefixes []netip.Prefix

	for _, dst := range grant.Destinations {
		p, ok := dst.(*Prefix)
		if !ok {
			continue
		}

		dstPrefix := netip.Prefix(*p)
		if slices.Contains(nodeRoutes, dstPrefix) {
			viaDstPrefixes = append(viaDstPrefixes, dstPrefix)
		}
	}

	if len(viaDstPrefixes) == 0 {
		return nil, nil
	}

	// Resolve source IPs.
	var resolvedSrcs []ResolvedAddresses

	for _, src := range grant.Sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if ips != nil {
			resolvedSrcs = append(resolvedSrcs, ips)
		}
	}

	if len(resolvedSrcs) == 0 {
		return nil, nil
	}

	// Build merged SrcIPs from all sources.
	var srcIPs netipx.IPSetBuilder

	for _, ips := range resolvedSrcs {
		for _, pref := range ips.Prefixes() {
			srcIPs.AddPrefix(pref)
		}
	}

	srcResolved, err := newResolved(&srcIPs)
	if err != nil {
		return nil, err
	}

	if srcResolved.Empty() {
		return nil, nil
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)
	srcIPStrs := srcIPsWithRoutes(srcResolved, hasWildcard, hasDangerAll, nodes)

	// Build DstPorts from the matching via prefixes.
	var rules []tailcfg.FilterRule

	for _, ipp := range grant.InternetProtocols {
		var destPorts []tailcfg.NetPortRange

		for _, prefix := range viaDstPrefixes {
			for _, port := range ipp.Ports {
				destPorts = append(destPorts, tailcfg.NetPortRange{
					IP:    prefix.String(),
					Ports: port,
				})
			}
		}

		if len(destPorts) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcIPStrs,
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	return rules, nil
}

// compileGrantWithAutogroupSelf compiles a single Grant rule, handling
// autogroup:self per-node while supporting all other alias types normally.
// It returns a slice of filter rules because when an Grant has both autogroup:self
// and other destinations, they need to be split into separate rules with different
// source filtering logic.
//
//nolint:gocyclo,cyclop // complex ACL compilation logic
func (pol *Policy) compileGrantWithAutogroupSelf(
	grant Grant,
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) ([]tailcfg.FilterRule, error) {
	// Handle via route grants — filter rules only go to the node
	// matching the via tag that actually advertises the destination subnets.
	if len(grant.Via) > 0 {
		return pol.compileViaGrant(grant, users, node, nodes)
	}

	var (
		autogroupSelfDests []Alias
		otherDests         []Alias
	)

	for _, dest := range grant.Destinations {
		if ag, ok := dest.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			autogroupSelfDests = append(autogroupSelfDests, dest)
		} else {
			otherDests = append(otherDests, dest)
		}
	}

	var rules []tailcfg.FilterRule

	var resolvedSrcs []ResolvedAddresses
	// Track non-wildcard source IPs separately. When the grant has a
	// wildcard (*) source plus explicit sources (tags, groups, etc.),
	// Tailscale preserves the explicit IPs alongside the wildcard
	// CGNAT ranges rather than merging them into the IPSet.
	var nonWildcardSrcs []ResolvedAddresses

	for i, src := range grant.Sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).Msgf("resolving source ips")
		}

		if ips != nil {
			resolvedSrcs = append(resolvedSrcs, ips)
			if _, isWildcard := grant.Sources[i].(Asterix); !isWildcard {
				nonWildcardSrcs = append(nonWildcardSrcs, ips)
			}
		}
	}

	// When the grant has literally empty src=[] or dst=[], produce no rules
	// at all — Tailscale returns null for these. This is distinct from sources
	// that resolve to empty (e.g., group:empty) where Tailscale still produces
	// CapGrant rules with empty SrcIPs.
	if len(grant.Sources) == 0 || len(grant.Destinations) == 0 {
		return rules, nil
	}

	if len(resolvedSrcs) == 0 && grant.App == nil {
		return rules, nil
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)

	for _, ipp := range grant.InternetProtocols {
		// Handle non-self destinations first to match Tailscale's
		// rule ordering in the FilterRule wire format.
		if len(otherDests) > 0 {
			var srcIPs netipx.IPSetBuilder

			for _, ips := range resolvedSrcs {
				for _, pref := range ips.Prefixes() {
					srcIPs.AddPrefix(pref)
				}
			}

			srcResolved, err := newResolved(&srcIPs)
			if err != nil {
				return nil, err
			}

			if !srcResolved.Empty() {
				destPorts := pol.destinationsToNetPortRange(users, nodes, otherDests, ipp.Ports)

				if len(destPorts) > 0 {
					srcIPStrs := srcIPsWithRoutes(srcResolved, hasWildcard, hasDangerAll, nodes)

					// When sources include a wildcard (*) alongside
					// explicit sources (tags, groups, etc.), Tailscale
					// preserves the individual IPs from non-wildcard
					// sources alongside the merged wildcard CGNAT
					// ranges rather than absorbing them.
					if hasWildcard && len(nonWildcardSrcs) > 0 {
						seen := make(map[string]bool, len(srcIPStrs))
						for _, s := range srcIPStrs {
							seen[s] = true
						}

						for _, ips := range nonWildcardSrcs {
							for _, s := range ips.Strings() {
								if !seen[s] {
									seen[s] = true
									srcIPStrs = append(srcIPStrs, s)
								}
							}
						}
					}

					rules = append(rules, tailcfg.FilterRule{
						SrcIPs:   srcIPStrs,
						DstPorts: destPorts,
						IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
					})
				}
			}
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

				for _, ips := range resolvedSrcs {
					for _, n := range sameUserNodes {
						// Check if any of this node's IPs are in the source set
						if slices.ContainsFunc(n.IPs(), ips.Contains) {
							n.AppendToIPSet(&srcIPs)
						}
					}
				}

				srcResolved, err := newResolved(&srcIPs)
				if err != nil {
					return nil, err
				}

				if !srcResolved.Empty() {
					var destPorts []tailcfg.NetPortRange

					for _, n := range sameUserNodes {
						for _, port := range ipp.Ports {
							for _, ip := range n.IPs() {
								destPorts = append(destPorts, tailcfg.NetPortRange{
									IP:    ip.String(),
									Ports: port,
								})
							}
						}
					}

					if len(destPorts) > 0 {
						rules = append(rules, tailcfg.FilterRule{
							SrcIPs:   srcResolved.Strings(),
							DstPorts: destPorts,
							IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
						})
					}
				}
			}
		}
	}

	// Handle app grants (CapGrant rules) — these are separate from
	// InternetProtocols and produce FilterRules with CapGrant instead
	// of DstPorts. A grant with both ip and app fields produces rules
	// for each independently.
	if grant.App != nil {
		// Handle non-self destinations for CapGrant
		if len(otherDests) > 0 {
			var srcIPStrs []string

			if len(resolvedSrcs) > 0 {
				var srcIPs netipx.IPSetBuilder

				for _, ips := range resolvedSrcs {
					for _, pref := range ips.Prefixes() {
						srcIPs.AddPrefix(pref)
					}
				}

				srcResolved, err := newResolved(&srcIPs)
				if err != nil {
					return nil, err
				}

				if !srcResolved.Empty() {
					srcIPStrs = srcIPsWithRoutes(srcResolved, hasWildcard, hasDangerAll, nodes)

					if hasWildcard && len(nonWildcardSrcs) > 0 {
						seen := make(map[string]bool, len(srcIPStrs))
						for _, s := range srcIPStrs {
							seen[s] = true
						}

						for _, ips := range nonWildcardSrcs {
							for _, s := range ips.Strings() {
								if !seen[s] {
									seen[s] = true
									srcIPStrs = append(srcIPStrs, s)
								}
							}
						}
					}
				}
			}

			var (
				capGrants    []tailcfg.CapGrant
				dstIPStrings []string
			)

			for _, dst := range otherDests {
				ips, err := dst.Resolve(pol, users, nodes)
				if err != nil {
					continue
				}

				capGrants = append(capGrants, tailcfg.CapGrant{
					Dsts:   ips.Prefixes(),
					CapMap: grant.App,
				})

				dstIPStrings = append(dstIPStrings, ips.Strings()...)
			}

			if len(capGrants) > 0 {
				// When sources resolved to empty (e.g. empty group),
				// Tailscale still produces the CapGrant rule with
				// empty SrcIPs.
				if srcIPStrs == nil {
					srcIPStrs = []string{}
				}

				// Collect source prefixes for reversed companion rules.
				var srcPrefixes []netip.Prefix
				for _, ips := range resolvedSrcs {
					srcPrefixes = append(srcPrefixes, ips.Prefixes()...)
				}

				rules = append(rules, tailcfg.FilterRule{
					SrcIPs:   srcIPStrs,
					CapGrant: capGrants,
				})

				// Companion rules use reversed direction: companion
				// SrcIPs are the destination IPs. When destinations
				// include a wildcard, add subnet routes to companion
				// SrcIPs to match main rule behavior.
				dstsHaveWildcard := sourcesHaveWildcard(otherDests)
				if dstsHaveWildcard {
					dstIPStrings = append(dstIPStrings, approvedSubnetRoutes(nodes)...)
				}

				rules = append(
					rules,
					companionCapGrantRules(dstIPStrings, srcPrefixes, grant.App)...,
				)
			}
		}

		// Handle autogroup:self destinations for CapGrant
		if len(autogroupSelfDests) > 0 && !node.IsTagged() {
			sameUserNodes := make([]types.NodeView, 0)

			for _, n := range nodes.All() {
				if !n.IsTagged() && n.User().ID() == node.User().ID() {
					sameUserNodes = append(sameUserNodes, n)
				}
			}

			if len(sameUserNodes) > 0 {
				var srcIPs netipx.IPSetBuilder

				for _, ips := range resolvedSrcs {
					for _, n := range sameUserNodes {
						if slices.ContainsFunc(n.IPs(), ips.Contains) {
							n.AppendToIPSet(&srcIPs)
						}
					}
				}

				srcResolved, err := newResolved(&srcIPs)
				if err != nil {
					return nil, err
				}

				if !srcResolved.Empty() {
					var (
						capGrants    []tailcfg.CapGrant
						dstIPStrings []string
					)

					for _, n := range sameUserNodes {
						var dsts []netip.Prefix
						for _, ip := range n.IPs() {
							dsts = append(
								dsts,
								netip.PrefixFrom(ip, ip.BitLen()),
							)
							dstIPStrings = append(dstIPStrings, ip.String())
						}

						capGrants = append(capGrants, tailcfg.CapGrant{
							Dsts:   dsts,
							CapMap: grant.App,
						})
					}

					if len(capGrants) > 0 {
						srcIPStrs := srcResolved.Strings()
						rules = append(rules, tailcfg.FilterRule{
							SrcIPs:   srcIPStrs,
							CapGrant: capGrants,
						})
						rules = append(
							rules,
							companionCapGrantRules(
								dstIPStrings,
								srcResolved.Prefixes(),
								grant.App,
							)...,
						)
					}
				}
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
					if principals := resolvedAddrsToPrincipals(srcIPs); len(principals) > 0 {
						rules = append(rules, &tailcfg.SSHRule{
							Principals: principals,
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

// resolvedAddrsToPrincipals converts ResolvedAddresses into SSH principals, one per address.
func resolvedAddrsToPrincipals(addrs ResolvedAddresses) []*tailcfg.SSHPrincipal {
	if addrs == nil {
		return nil
	}

	var principals []*tailcfg.SSHPrincipal

	for addr := range addrs.Iter() {
		principals = append(principals, &tailcfg.SSHPrincipal{
			NodeIP: addr.String(),
		})
	}

	return principals
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
	srcIPs ResolvedAddresses,
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
// CapGrant rules (which have no DstPorts) are passed through without merging
// since CapGrant and DstPorts are mutually exclusive in a FilterRule.
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
