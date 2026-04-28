package v2

import (
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// grantCategory classifies a grant by what per-node work it needs.
type grantCategory int

const (
	// grantCategoryRegular requires no per-node work. The pre-compiled
	// rules are complete and only need ReduceFilterRules.
	grantCategoryRegular grantCategory = iota

	// grantCategorySelf has autogroup:self destinations that must be
	// expanded per-node to same-user untagged device IPs.
	grantCategorySelf

	// grantCategoryVia has Via tags that route rules to specific
	// nodes based on their tags and advertised routes.
	grantCategoryVia
)

// compiledGrant is a grant with its sources already resolved to IP
// addresses. The expensive work (alias → IP resolution) is done once
// here. Extracting rules for a specific node reads from pre-resolved
// data without re-resolving.
type compiledGrant struct {
	category grantCategory

	// srcIPStrings is the final SrcIPs for non-self rules, with
	// nonWildcardSrcs appended to match Tailscale SaaS behavior.
	srcIPStrings []string

	hasWildcard  bool
	hasDangerAll bool

	// rules are the pre-compiled filter rules for non-self, non-via
	// destinations. For regular grants this is the complete output.
	// For self grants with mixed destinations (self + other), this
	// is the non-self portion only.
	rules []tailcfg.FilterRule

	// self is non-nil when the grant has autogroup:self destinations.
	self *selfGrantData

	// via is non-nil when the grant has Via tags.
	via *viaGrantData
}

// selfGrantData holds data needed for per-node autogroup:self
// compilation. Sources are already resolved.
type selfGrantData struct {
	resolvedSrcs      []ResolvedAddresses
	internetProtocols []ProtocolPort
	app               tailcfg.PeerCapMap
}

// viaGrantData holds data needed for per-node via-grant compilation.
// Sources are already resolved into srcIPStrings.
type viaGrantData struct {
	viaTags           []Tag
	destinations      Aliases
	internetProtocols []ProtocolPort
	srcIPStrings      []string
}

// userNodeIndex maps user IDs to their untagged nodes. Built once per
// policy or node-set change and read from many goroutines under
// PolicyManager.mu; readers must hold the lock (or the snapshot
// returned to them).
type userNodeIndex map[uint][]types.NodeView

func buildUserNodeIndex(
	nodes views.Slice[types.NodeView],
) userNodeIndex {
	idx := make(userNodeIndex)

	for _, n := range nodes.All() {
		if !n.IsTagged() && n.User().Valid() {
			uid := n.User().ID()
			idx[uid] = append(idx[uid], n)
		}
	}

	return idx
}

// compileGrants resolves all policy grants into compiledGrant structs.
// Source resolution and non-self destination resolution happens once
// here. This is the single resolution path that replaces the
// duplicated work in compileFilterRules and compileGrantWithAutogroupSelf.
func (pol *Policy) compileGrants(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []compiledGrant {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return nil
	}

	grants := pol.Grants
	for _, acl := range pol.ACLs {
		grants = append(grants, aclToGrants(acl)...)
	}

	compiled := make([]compiledGrant, 0, len(grants))

	for _, grant := range grants {
		cg, err := pol.compileOneGrant(grant, users, nodes)
		if err != nil {
			log.Trace().Err(err).Msg("compiling grant")

			continue
		}

		if cg != nil {
			compiled = append(compiled, *cg)
		}
	}

	return compiled
}

// compileOneGrant resolves a single grant into a compiledGrant.
// All source resolution happens here. Non-self, non-via destination
// resolution also happens here. Per-node data (self dests, via
// matching) is stored for deferred compilation.
//
//nolint:gocyclo,cyclop
func (pol *Policy) compileOneGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*compiledGrant, error) {
	// Via grants: resolve sources, store deferred data.
	if len(grant.Via) > 0 {
		return pol.compileOneViaGrant(grant, users, nodes)
	}

	// Split destinations into self vs other.
	var autogroupSelfDests, otherDests []Alias

	for _, dest := range grant.Destinations {
		if ag, ok := dest.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			autogroupSelfDests = append(autogroupSelfDests, dest)
		} else {
			otherDests = append(otherDests, dest)
		}
	}

	// Resolve sources per-alias, tracking non-wildcard sources
	// separately so we can preserve their IPs alongside the
	// wildcard CGNAT ranges (matching Tailscale SaaS behavior).
	resolvedSrcs, nonWildcardSrcs, err := resolveSources(
		pol, grant.Sources, users, nodes,
	)
	if err != nil {
		return nil, err
	}

	// Literally empty src=[] or dst=[] produces no rules.
	if len(grant.Sources) == 0 || len(grant.Destinations) == 0 {
		return nil, nil //nolint:nilnil
	}

	if len(resolvedSrcs) == 0 && grant.App == nil {
		return nil, nil //nolint:nilnil
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)
	srcIPStrings := buildSrcIPStrings(
		resolvedSrcs, nonWildcardSrcs,
		hasWildcard, hasDangerAll, nodes,
	)

	cg := &compiledGrant{
		srcIPStrings: srcIPStrings,
		hasWildcard:  hasWildcard,
		hasDangerAll: hasDangerAll,
	}

	// Compile non-self destination rules (done once, shared).
	if len(otherDests) > 0 {
		cg.rules = pol.compileOtherDests(
			users, nodes, grant, otherDests,
			resolvedSrcs, srcIPStrings,
		)
	}

	// Classify and store deferred self data.
	switch {
	case len(autogroupSelfDests) > 0:
		cg.category = grantCategorySelf
		cg.self = &selfGrantData{
			resolvedSrcs:      resolvedSrcs,
			internetProtocols: grant.InternetProtocols,
			app:               grant.App,
		}
	default:
		cg.category = grantCategoryRegular
	}

	return cg, nil
}

// compileOneViaGrant resolves sources for a via grant and stores the
// deferred per-node data. The actual via-node matching and route
// intersection happens in compileViaForNode.
func (pol *Policy) compileOneViaGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*compiledGrant, error) {
	if len(grant.InternetProtocols) == 0 {
		return nil, nil //nolint:nilnil
	}

	resolvedSrcs, _, err := resolveSources(
		pol, grant.Sources, users, nodes,
	)
	if err != nil {
		return nil, err
	}

	if len(resolvedSrcs) == 0 {
		return nil, nil //nolint:nilnil
	}

	// Build merged SrcIPs.
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
		return nil, nil //nolint:nilnil
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)

	return &compiledGrant{
		category: grantCategoryVia,
		via: &viaGrantData{
			viaTags:           grant.Via,
			destinations:      grant.Destinations,
			internetProtocols: grant.InternetProtocols,
			srcIPStrings: srcIPsWithRoutes(
				srcResolved, hasWildcard, hasDangerAll, nodes,
			),
		},
	}, nil
}

// resolveSources resolves grant sources per-alias, returning the
// resolved addresses and a separate slice of non-wildcard sources.
// This is the canonical source-resolution path. Its output lands in
// compiledGrant.srcIPStrings (among other places) and callers on the
// hot path should prefer reading that over calling Resolve again.
func resolveSources(
	pol *Policy,
	sources Aliases,
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]ResolvedAddresses, []ResolvedAddresses, error) {
	var all, nonWild []ResolvedAddresses

	for i, src := range sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).
				Msg("resolving source ips")
		}

		if ips != nil {
			all = append(all, ips)

			if _, isWildcard := sources[i].(Asterix); !isWildcard {
				nonWild = append(nonWild, ips)
			}
		}
	}

	return all, nonWild, nil
}

// buildSrcIPStrings builds the final SrcIPs string slice from
// resolved sources, preserving non-wildcard IPs alongside wildcard
// CGNAT ranges to match Tailscale SaaS behavior.
func buildSrcIPStrings(
	resolvedSrcs, nonWildcardSrcs []ResolvedAddresses,
	hasWildcard, hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	var merged netipx.IPSetBuilder

	for _, ips := range resolvedSrcs {
		for _, pref := range ips.Prefixes() {
			merged.AddPrefix(pref)
		}
	}

	srcResolved, err := newResolved(&merged)
	if err != nil {
		return nil
	}

	if srcResolved.Empty() {
		return nil
	}

	srcIPStrs := srcIPsWithRoutes(
		srcResolved, hasWildcard, hasDangerAll, nodes,
	)

	// When sources include a wildcard (*) alongside explicit
	// sources (tags, groups, etc.), Tailscale preserves the
	// individual IPs from non-wildcard sources alongside the
	// merged CGNAT ranges rather than absorbing them.
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

	return srcIPStrs
}

// compileOtherDests compiles filter rules for non-self, non-via
// destinations. This produces both DstPorts rules (from
// InternetProtocols) and CapGrant rules (from App).
func (pol *Policy) compileOtherDests(
	users types.Users,
	nodes views.Slice[types.NodeView],
	grant Grant,
	otherDests Aliases,
	resolvedSrcs []ResolvedAddresses,
	srcIPStrings []string,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	// DstPorts rules from InternetProtocols.
	for _, ipp := range grant.InternetProtocols {
		destPorts := pol.destinationsToNetPortRange(
			users, nodes, otherDests, ipp.Ports,
		)

		if len(destPorts) > 0 && len(srcIPStrings) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcIPStrings,
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	// CapGrant rules from App.
	if grant.App != nil {
		capSrcIPStrs := srcIPStrings

		// When sources resolved to empty but App is set,
		// Tailscale still produces the CapGrant rule with
		// empty SrcIPs.
		if capSrcIPStrs == nil {
			capSrcIPStrs = []string{}
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
			srcPrefixes := make([]netip.Prefix, 0, len(resolvedSrcs)*2)
			for _, ips := range resolvedSrcs {
				srcPrefixes = append(
					srcPrefixes, ips.Prefixes()...,
				)
			}

			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   capSrcIPStrs,
				CapGrant: capGrants,
			})

			dstsHaveWildcard := sourcesHaveWildcard(otherDests)
			if dstsHaveWildcard {
				dstIPStrings = append(
					dstIPStrings,
					approvedSubnetRoutes(nodes)...,
				)
			}

			rules = append(
				rules,
				companionCapGrantRules(
					dstIPStrings, srcPrefixes, grant.App,
				)...,
			)
		}
	}

	return rules
}

// hasPerNodeGrants reports whether any compiled grant requires
// per-node filter compilation (via grants or autogroup:self).
func hasPerNodeGrants(grants []compiledGrant) bool {
	for i := range grants {
		if grants[i].category != grantCategoryRegular {
			return true
		}
	}

	return false
}

// globalFilterRules extracts global filter rules from compiled
// grants. Via grants produce no global rules (they are per-node
// only); regular grants contribute their full pre-compiled ruleset;
// self grants contribute their non-self portion.
func globalFilterRules(grants []compiledGrant) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range grants {
		if grants[i].category == grantCategoryVia {
			continue
		}

		rules = append(rules, grants[i].rules...)
	}

	return mergeFilterRules(rules)
}

// filterRulesForNode produces unreduced filter rules for a specific
// node by combining pre-compiled global rules with per-node self and
// via rules. Regular grants emit their pre-compiled rules as-is.
// Self grants add autogroup:self expansion. Via grants add
// tag-matched, route-intersected rules.
func filterRulesForNode(
	grants []compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range grants {
		cg := &grants[i]

		// Pre-compiled rules apply to all grant categories
		// (empty for via-only grants).
		rules = append(rules, cg.rules...)

		switch cg.category {
		case grantCategoryRegular:
			// Nothing more to do.

		case grantCategorySelf:
			rules = append(
				rules,
				compileAutogroupSelf(cg, node, userIdx)...,
			)

		case grantCategoryVia:
			rules = append(
				rules,
				compileViaForNode(cg, node)...,
			)
		}
	}

	return mergeFilterRules(rules)
}

// compileAutogroupSelf produces filter rules for autogroup:self
// destinations for a specific node. Only called for grants with
// self destinations and only produces rules for untagged nodes.
func compileAutogroupSelf(
	cg *compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) []tailcfg.FilterRule {
	if node.IsTagged() || cg.self == nil {
		return nil
	}

	if !node.User().Valid() {
		return nil
	}

	sameUserNodes := userIdx[node.User().ID()]
	if len(sameUserNodes) == 0 {
		return nil
	}

	var rules []tailcfg.FilterRule

	// Filter sources to only same-user untagged devices.
	srcResolved := filterSourcesToSameUser(
		cg.self.resolvedSrcs, sameUserNodes,
	)
	if srcResolved == nil || srcResolved.Empty() {
		return nil
	}

	// DstPorts rules from InternetProtocols.
	for _, ipp := range cg.self.internetProtocols {
		var destPorts []tailcfg.NetPortRange

		for _, n := range sameUserNodes {
			for _, port := range ipp.Ports {
				for _, ip := range n.IPs() {
					destPorts = append(
						destPorts,
						tailcfg.NetPortRange{
							IP:    ip.String(),
							Ports: port,
						},
					)
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

	// CapGrant rules from App.
	if cg.self.app != nil {
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
				dstIPStrings = append(
					dstIPStrings, ip.String(),
				)
			}

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   dsts,
				CapMap: cg.self.app,
			})
		}

		if len(capGrants) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   srcResolved.Strings(),
				CapGrant: capGrants,
			})

			rules = append(
				rules,
				companionCapGrantRules(
					dstIPStrings,
					srcResolved.Prefixes(),
					cg.self.app,
				)...,
			)
		}
	}

	return rules
}

// filterSourcesToSameUser intersects resolved source addresses with
// same-user untagged device IPs, returning only the addresses that
// belong to those devices.
func filterSourcesToSameUser(
	resolvedSrcs []ResolvedAddresses,
	sameUserNodes []types.NodeView,
) ResolvedAddresses {
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
		return nil
	}

	return srcResolved
}

// compileViaForNode produces via-grant filter rules for a specific
// node. Only produces rules when the node matches one of the via
// tags and advertises routes that match the grant destinations.
func compileViaForNode(
	cg *compiledGrant,
	node types.NodeView,
) []tailcfg.FilterRule {
	if cg.via == nil {
		return nil
	}

	// Check if node matches any via tag.
	matchesVia := false

	for _, viaTag := range cg.via.viaTags {
		if node.HasTag(string(viaTag)) {
			matchesVia = true

			break
		}
	}

	if !matchesVia {
		return nil
	}

	// Find matching destination prefixes.
	nodeSubnetRoutes := node.SubnetRoutes()
	if len(nodeSubnetRoutes) == 0 {
		return nil
	}

	var viaDstPrefixes []netip.Prefix

	for _, dst := range cg.via.destinations {
		switch d := dst.(type) {
		case *Prefix:
			dstPrefix := netip.Prefix(*d)
			if slices.Contains(nodeSubnetRoutes, dstPrefix) {
				viaDstPrefixes = append(
					viaDstPrefixes, dstPrefix,
				)
			}
		case *AutoGroup:
			// autogroup:internet via grants do not produce
			// PacketFilter rules on exit nodes.
		}
	}

	if len(viaDstPrefixes) == 0 {
		return nil
	}

	// Build rules using pre-resolved srcIPStrings.
	var rules []tailcfg.FilterRule

	for _, ipp := range cg.via.internetProtocols {
		var destPorts []tailcfg.NetPortRange

		for _, prefix := range viaDstPrefixes {
			for _, port := range ipp.Ports {
				destPorts = append(
					destPorts,
					tailcfg.NetPortRange{
						IP:    prefix.String(),
						Ports: port,
					},
				)
			}
		}

		if len(destPorts) > 0 {
			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   cg.via.srcIPStrings,
				DstPorts: destPorts,
				IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
			})
		}
	}

	return rules
}
