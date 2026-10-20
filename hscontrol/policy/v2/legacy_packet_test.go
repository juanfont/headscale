package v2

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/ipset"
	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/views"
	"tailscale.com/util/set"
)

// legacyGrantCategory classifies a grant by what per-node work it needs.
type legacyGrantCategory int

const (
	// legacyGrantCategoryRegular requires no per-node work. The pre-compiled
	// rules are complete and only need [packetfilter.Reduce].
	legacyGrantCategoryRegular legacyGrantCategory = iota

	// legacyGrantCategorySelf has autogroup:self destinations that must be
	// expanded per-node to same-user untagged device IPs.
	legacyGrantCategorySelf

	// legacyGrantCategoryVia has Via tags that route rules to specific
	// nodes based on their tags and advertised routes.
	legacyGrantCategoryVia
)

// legacyCompiledGrant is a grant with its sources already resolved to IP
// addresses. The expensive work (alias → IP resolution) is done once
// here. Extracting rules for a specific node reads from pre-resolved
// data without re-resolving.
type legacyCompiledGrant struct {
	category legacyGrantCategory

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
	self *legacySelfGrantData

	// via is non-nil when the grant has Via tags.
	via *legacyViaGrantData
}

// legacySelfGrantData holds data needed for per-node autogroup:self
// compilation. Sources are already resolved.
type legacySelfGrantData struct {
	resolvedSrcs      []ipset.Set
	internetProtocols []ProtocolPort
	app               tailcfg.PeerCapMap
}

// legacyViaGrantData holds data needed for per-node via-grant compilation.
// Sources are already resolved into srcIPStrings; destinations are
// pre-resolved into prefixes plus a flag for autogroup:internet, which
// the consumers handle separately because its gate is per-node
// (IsExitNode()) rather than per-prefix overlap.
type legacyViaGrantData struct {
	viaTags              []Tag
	resolvedDsts         []netip.Prefix
	hasAutoGroupInternet bool
	internetProtocols    []ProtocolPort
	srcIPStrings         []string
}

// legacyResolveViaDestinations splits a via grant's destinations into the
// flat list of IP prefixes they resolve to plus a flag for
// autogroup:internet. Every alias kind goes through [Alias.Resolve] so
// adding a new alias type to the policy parser does not silently
// disappear from the via path. Non-IP alias kinds (tag, user, group,
// wildcard) resolve to /32 host IPs that never overlap with subnet
// route advertisements and therefore contribute nothing here.
func legacyResolveViaDestinations(
	pol *Policy,
	users types.Users,
	nodes views.Slice[types.NodeView],
	dsts Aliases,
) ([]netip.Prefix, bool) {
	var (
		prefixes             []netip.Prefix
		hasAutoGroupInternet bool
	)

	for _, d := range dsts {
		if ag, ok := d.(*AutoGroup); ok && ag.Is(AutoGroupInternet) {
			hasAutoGroupInternet = true

			continue
		}

		ips, err := d.Resolve(pol, users, nodes)
		if err != nil || ips.IsEmpty() {
			continue
		}

		prefixes = append(prefixes, slices.Collect(ips.Prefixes())...)
	}

	return prefixes, hasAutoGroupInternet
}

// legacyUserNodeIndex maps user IDs to their untagged nodes. Built once per
// policy or node-set change and read from many goroutines under
// [PolicyManager.mu]; readers must hold the lock (or the snapshot
// returned to them).
type legacyUserNodeIndex map[uint][]types.NodeView

func legacyBuildUserNodeIndex(
	nodes views.Slice[types.NodeView],
) legacyUserNodeIndex {
	idx := make(legacyUserNodeIndex)

	for _, n := range nodes.All() {
		if !n.IsTagged() && n.User().Valid() {
			uid := n.User().ID()
			idx[uid] = append(idx[uid], n)
		}
	}

	return idx
}

// legacyCompileGrants resolves all policy grants into [legacyCompiledGrant] structs.
// Source resolution and non-self destination resolution happens once
// here. This is the single resolution path that replaces the
// duplicated work in [Policy.legacyCompileFilterRules] and the autogroup:self
// expansion.
func (pol *Policy) legacyCompileGrants(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []legacyCompiledGrant {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return nil
	}

	grants := pol.Grants
	for _, acl := range pol.ACLs {
		grants = append(grants, aclToGrants(acl)...)
	}

	compiled := make([]legacyCompiledGrant, 0, len(grants))

	for _, grant := range grants {
		cg, err := pol.legacyCompileOneGrant(grant, users, nodes)
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

// legacyCompileOneGrant resolves a single grant into a [legacyCompiledGrant].
// All source resolution happens here. Non-self, non-via destination
// resolution also happens here. Per-node data (self dests, via
// matching) is stored for deferred compilation.
//
//nolint:gocyclo,cyclop
func (pol *Policy) legacyCompileOneGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*legacyCompiledGrant, error) {
	// Via grants: resolve sources, store deferred data.
	if len(grant.Via) > 0 {
		return pol.legacyCompileOneViaGrant(grant, users, nodes)
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
	resolvedSrcs, nonWildcardSrcs, err := legacyResolveSources(
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

	hasWildcard := legacySourcesHaveWildcard(grant.Sources)
	hasDangerAll := legacySourcesHaveDangerAll(grant.Sources)
	srcIPStrings := legacyBuildSrcIPStrings(
		resolvedSrcs, nonWildcardSrcs,
		hasWildcard, hasDangerAll, nodes,
	)

	cg := &legacyCompiledGrant{
		srcIPStrings: srcIPStrings,
		hasWildcard:  hasWildcard,
		hasDangerAll: hasDangerAll,
	}

	// Compile non-self destination rules (done once, shared).
	if len(otherDests) > 0 {
		cg.rules = pol.legacyCompileOtherDests(
			users, nodes, grant, otherDests,
			resolvedSrcs, srcIPStrings,
		)
	}

	// Classify and store deferred self data. The struct literal already
	// initializes category to legacyGrantCategoryRegular (the zero value).
	if len(autogroupSelfDests) > 0 {
		cg.category = legacyGrantCategorySelf
		cg.self = &legacySelfGrantData{
			resolvedSrcs:      resolvedSrcs,
			internetProtocols: grant.InternetProtocols,
			app:               grant.App,
		}
	}

	return cg, nil
}

// legacyMergeResolvedSrcs merges every prefix from the resolved sources into a
// single [ipset.Set] address set.
func legacyMergeResolvedSrcs(resolvedSrcs []ipset.Set) (ipset.Set, error) {
	var b ipset.Builder

	for _, ips := range resolvedSrcs {
		b.AddSet(ips)
	}

	return b.Build()
}

// legacyCompileOneViaGrant resolves sources for a via grant and stores the
// deferred per-node data. The actual via-node matching and route
// intersection happens in [legacyCompileViaForNode].
func (pol *Policy) legacyCompileOneViaGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*legacyCompiledGrant, error) {
	if len(grant.InternetProtocols) == 0 {
		return nil, nil //nolint:nilnil
	}

	resolvedSrcs, _, err := legacyResolveSources(
		pol, grant.Sources, users, nodes,
	)
	if err != nil {
		return nil, err
	}

	if len(resolvedSrcs) == 0 {
		return nil, nil //nolint:nilnil
	}

	// Build merged SrcIPs.
	srcResolved, err := legacyMergeResolvedSrcs(resolvedSrcs)
	if err != nil {
		return nil, err
	}

	if srcResolved.IsEmpty() {
		return nil, nil //nolint:nilnil
	}

	hasWildcard := legacySourcesHaveWildcard(grant.Sources)
	hasDangerAll := legacySourcesHaveDangerAll(grant.Sources)

	resolvedDsts, hasAutoGroupInternet := legacyResolveViaDestinations(
		pol, users, nodes, grant.Destinations,
	)

	return &legacyCompiledGrant{
		category: legacyGrantCategoryVia,
		via: &legacyViaGrantData{
			viaTags:              grant.Via,
			resolvedDsts:         resolvedDsts,
			hasAutoGroupInternet: hasAutoGroupInternet,
			internetProtocols:    grant.InternetProtocols,
			srcIPStrings: legacySrcIPsWithRoutes(
				srcResolved, hasWildcard, hasDangerAll, nodes,
			),
		},
	}, nil
}

// legacyResolveSources resolves grant sources per-alias, returning the
// resolved addresses and a separate slice of non-wildcard sources.
// This is the canonical source-resolution path. Its output lands in
// [legacyCompiledGrant.srcIPStrings] (among other places) and callers on the
// hot path should prefer reading that over calling [Alias.Resolve] again.
func legacyResolveSources(
	pol *Policy,
	sources Aliases,
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]ipset.Set, []ipset.Set, error) {
	var all, nonWild []ipset.Set

	for i, src := range sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).
				Msg("resolving source ips")
		}

		if !ips.IsEmpty() {
			all = append(all, ips)

			if _, isWildcard := sources[i].(Asterix); !isWildcard {
				nonWild = append(nonWild, ips)
			}
		}
	}

	return all, nonWild, nil
}

// legacyBuildSrcIPStrings builds the final SrcIPs string slice from
// resolved sources, preserving non-wildcard IPs alongside wildcard
// CGNAT ranges to match Tailscale SaaS behavior.
func legacyBuildSrcIPStrings(
	resolvedSrcs, nonWildcardSrcs []ipset.Set,
	hasWildcard, hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	srcResolved, err := legacyMergeResolvedSrcs(resolvedSrcs)
	if err != nil || srcResolved.IsEmpty() {
		return nil
	}

	srcIPStrs := legacySrcIPsWithRoutes(
		srcResolved, hasWildcard, hasDangerAll, nodes,
	)

	// When sources include a wildcard (*) alongside explicit
	// sources (tags, groups, etc.), Tailscale preserves the
	// individual IPs from non-wildcard sources alongside the
	// merged CGNAT ranges rather than absorbing them.
	if hasWildcard && len(nonWildcardSrcs) > 0 {
		seen := set.SetOf(srcIPStrs)

		for _, ips := range nonWildcardSrcs {
			for _, s := range legacyIpSetToStrings(ips) {
				if !seen.Contains(s) {
					seen.Add(s)
					srcIPStrs = append(srcIPStrs, s)
				}
			}
		}
	}

	return srcIPStrs
}

type legacyResolvedDestination struct {
	Alias

	addresses ipset.Set
	err       error
}

func (dst legacyResolvedDestination) Resolve(
	_ *Policy,
	_ types.Users,
	_ views.Slice[types.NodeView],
) (ipset.Set, error) {
	return dst.addresses, dst.err
}

func (dst legacyResolvedDestination) resolveInto(
	_ *Policy,
	_ types.Users,
	_ views.Slice[types.NodeView],
	b *ipset.Builder,
) error {
	b.AddSet(dst.addresses)
	return dst.err
}

// legacyCompileOtherDests compiles filter rules for non-self, non-via
// destinations. This produces both [tailcfg.FilterRule.DstPorts] rules
// (from [Grant.InternetProtocols]) and [tailcfg.CapGrant] rules (from
// [Grant.App]).
func (pol *Policy) legacyCompileOtherDests(
	users types.Users,
	nodes views.Slice[types.NodeView],
	grant Grant,
	otherDests Aliases,
	resolvedSrcs []ipset.Set,
	srcIPStrings []string,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	// Reuse resolutions while keeping the port encoder's partial-error handling
	// and logging. Wildcards must retain their special port and companion rules.
	if len(grant.InternetProtocols) > 1 ||
		(len(grant.InternetProtocols) > 0 && grant.App != nil) {
		resolvedDests := make(Aliases, len(otherDests))
		for i, dst := range otherDests {
			resolvedDests[i] = dst
			if _, wildcard := dst.(Asterix); wildcard {
				continue
			}

			addresses, err := dst.Resolve(pol, users, nodes)
			resolvedDests[i] = legacyResolvedDestination{
				Alias:     dst,
				addresses: addresses,
				err:       err,
			}
		}

		otherDests = resolvedDests
	}

	// DstPorts rules from InternetProtocols.
	for _, ipp := range grant.InternetProtocols {
		destPorts := pol.legacyDestinationsToNetPortRange(
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
				Dsts:   slices.Collect(ips.Prefixes()),
				CapMap: grant.App,
			})

			dstIPStrings = append(dstIPStrings, legacyIpSetToStrings(ips)...)
		}

		if len(capGrants) > 0 {
			srcPrefixes := make([]netip.Prefix, 0, len(resolvedSrcs)*2)
			for _, ips := range resolvedSrcs {
				srcPrefixes = append(
					srcPrefixes, slices.Collect(ips.Prefixes())...,
				)
			}

			rules = append(rules, tailcfg.FilterRule{
				SrcIPs:   capSrcIPStrs,
				CapGrant: capGrants,
			})

			dstsHaveWildcard := legacySourcesHaveWildcard(otherDests)
			if dstsHaveWildcard {
				dstIPStrings = append(
					dstIPStrings,
					legacyApprovedSubnetRoutes(nodes)...,
				)
			}

			rules = append(
				rules,
				legacyCompanionCapGrantRules(
					dstIPStrings, srcPrefixes, grant.App,
				)...,
			)
		}
	}

	return rules
}

// legacyGlobalFilterRules extracts global filter rules from [legacyCompiledGrant]s.
// Via grants produce no global rules (they are per-node only); regular
// grants contribute their full pre-compiled ruleset; self grants
// contribute their non-self portion.
func legacyGlobalFilterRules(grants []legacyCompiledGrant) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range grants {
		if grants[i].category == legacyGrantCategoryVia {
			continue
		}

		rules = append(rules, grants[i].rules...)
	}

	return legacyMergeFilterRules(rules)
}

// legacyFilterRulesForNode produces unreduced filter rules for a specific
// node by combining pre-compiled global rules with per-node self and
// via rules. Regular grants emit their pre-compiled rules as-is.
// Self grants add autogroup:self expansion. Via grants add
// tag-matched, route-intersected rules.
func legacyFilterRulesForNode(
	grants []legacyCompiledGrant,
	node types.NodeView,
	userIdx legacyUserNodeIndex,
) []tailcfg.FilterRule {
	var rules []tailcfg.FilterRule

	for i := range grants {
		cg := &grants[i]

		// Pre-compiled rules apply to all grant categories
		// (empty for via-only grants).
		rules = append(rules, cg.rules...)

		switch cg.category {
		case legacyGrantCategoryRegular:
			// Nothing more to do.

		case legacyGrantCategorySelf:
			rules = append(
				rules,
				legacyCompileAutogroupSelf(cg, node, userIdx)...,
			)

		case legacyGrantCategoryVia:
			rules = append(
				rules,
				legacyCompileViaForNode(cg, node)...,
			)
		}
	}

	return legacyMergeFilterRules(rules)
}

// legacyCompileAutogroupSelf produces filter rules for autogroup:self
// destinations for a specific node. Only called for grants with
// self destinations and only produces rules for untagged nodes.
func legacyCompileAutogroupSelf(
	cg *legacyCompiledGrant,
	node types.NodeView,
	userIdx legacyUserNodeIndex,
) []tailcfg.FilterRule {
	if node.IsTagged() || cg.self == nil || !node.User().Valid() {
		return nil
	}

	return legacyCompileSelfForUser(cg, userIdx[node.User().ID()])
}

// legacyCompileSelfForUser produces the autogroup:self rules for one user's
// untagged devices.
func legacyCompileSelfForUser(
	cg *legacyCompiledGrant,
	sameUserNodes []types.NodeView,
) []tailcfg.FilterRule {
	if len(sameUserNodes) == 0 {
		return nil
	}

	var rules []tailcfg.FilterRule

	// Filter sources to only same-user untagged devices.
	srcResolved := legacyFilterSourcesToSameUser(
		cg.self.resolvedSrcs, sameUserNodes,
	)
	if srcResolved.IsEmpty() {
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
				SrcIPs:   legacyIpSetToStrings(srcResolved),
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
				SrcIPs:   legacyIpSetToStrings(srcResolved),
				CapGrant: capGrants,
			})

			rules = append(
				rules,
				legacyCompanionCapGrantRules(
					dstIPStrings,
					slices.Collect(srcResolved.Prefixes()),
					cg.self.app,
				)...,
			)
		}
	}

	return rules
}

// legacyFilterSourcesToSameUser intersects resolved source addresses with
// same-user untagged device IPs, returning only the addresses that
// belong to those devices.
func legacyFilterSourcesToSameUser(
	resolvedSrcs []ipset.Set,
	sameUserNodes []types.NodeView,
) ipset.Set {
	var srcIPs ipset.Builder

	for _, ips := range resolvedSrcs {
		for _, n := range sameUserNodes {
			if slices.ContainsFunc(n.IPs(), ips.Contains) {
				n.AppendToIPSet(&srcIPs)
			}
		}
	}

	srcResolved, err := srcIPs.Build()
	if err != nil {
		return ipset.Set{}
	}

	return srcResolved
}

// legacyCompileViaForNode produces via-grant filter rules for a specific
// node. Only produces rules when the node matches one of the via
// tags and advertises routes that match the grant destinations.
func legacyCompileViaForNode(
	cg *legacyCompiledGrant,
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

	// [types.NodeView.SubnetRoutes] excludes exit routes, so the overlap
	// gate below sees only subnet advertisements. autogroup:internet on
	// a via-tagged exit advertiser is handled separately because its
	// eligibility is per-node ([types.NodeView.IsExitNode]) rather than
	// per-prefix overlap.
	nodeSubnetRoutes := node.SubnetRoutes()

	var viaDstPrefixes []netip.Prefix

	for _, dstPrefix := range cg.via.resolvedDsts {
		// Equality would reject any broader or narrower dst relative
		// to the advertised route. Containment in either direction
		// matches the operator's authorisation: a broader dst restricts
		// traffic to the subset the router serves; a narrower dst rides
		// on a router covering more than the operator asked for. The
		// rule emits the literal dst either way because that is what
		// the policy authorised.
		if slices.ContainsFunc(nodeSubnetRoutes, dstPrefix.Overlaps) {
			viaDstPrefixes = append(viaDstPrefixes, dstPrefix)
		}
	}

	// autogroup:internet on a via-tagged exit advertiser becomes a rule
	// whose DstPorts enumerate [util.TheInternet]. The matchers derived
	// from this rule let [types.NodeView.CanAccess] surface the exit node
	// to the grant source via [matcher.Match.DestsIsTheInternet].
	// [packetfilter.Reduce] strips the rule from the wire format
	// on non-exit advertisers, preserving SaaS PacketFilter encoding.
	if cg.via.hasAutoGroupInternet && node.IsExitNode() {
		viaDstPrefixes = append(
			viaDstPrefixes,
			slices.Collect(util.TheInternet().Prefixes())...,
		)
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

// legacyCompanionCap pairs a well-known Tailscale capability with its
// companion capability.
type legacyCompanionCap struct {
	original  peercap.Cap
	companion peercap.Cap
}

// legacyCompanionCaps lists certain well-known Tailscale capabilities and
// their companion capability. When a grant includes one of these
// capabilities, Tailscale automatically generates an additional
// [tailcfg.FilterRule] with the companion capability and a nil CapMap value.
// The slice is ordered by the original capability name so that
// generated companion rules are emitted deterministically.
var legacyCompanionCaps = []legacyCompanionCap{
	{peercap.Taildrive, peercap.TaildriveSharer},
	{peercap.Relay, peercap.RelayTarget},
}

// legacyCompanionCapGrantRules returns additional [tailcfg.FilterRule]s for any
// well-known capabilities that have companion caps. Companion rules
// are **reversed**: SrcIPs come from the original destinations and
// CapGrant Dsts come from the original sources. This allows
// [packetfilter.Reduce] to distribute companion rules to source
// nodes (e.g. drive-sharer goes to the member nodes, not the destination).
// Rules are ordered by the original capability name.
//
// dstIPStrings are the resolved destination IPs as strings (used as
// companion SrcIPs). srcPrefixes are the resolved source IPs as
// [netip.Prefix] (used as companion CapGrant Dsts).
func legacyCompanionCapGrantRules(
	dstIPStrings []string,
	srcPrefixes []netip.Prefix,
	capMap tailcfg.PeerCapMap,
) []tailcfg.FilterRule {
	companions := make([]tailcfg.FilterRule, 0, len(legacyCompanionCaps))

	for _, c := range legacyCompanionCaps {
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

// legacySourcesHaveWildcard returns true if any of the source aliases is
// a wildcard (*). Used to determine whether approved subnet routes
// should be appended to [tailcfg.FilterRule.SrcIPs].
func legacySourcesHaveWildcard(srcs Aliases) bool {
	for _, src := range srcs {
		if _, ok := src.(Asterix); ok {
			return true
		}
	}

	return false
}

// legacySourcesHaveDangerAll returns true if any of the source aliases is
// autogroup:danger-all. When present, [tailcfg.FilterRule.SrcIPs] should
// be ["*"] to represent all IP addresses including non-Tailscale addresses.
func legacySourcesHaveDangerAll(srcs Aliases) bool {
	for _, src := range srcs {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupDangerAll) {
			return true
		}
	}

	return false
}

// legacyIpSetToStrings preserves legacy wire address and range formatting.
func legacyIpSetToStrings(ips ipset.Set) []string {
	var result []string

	for r := range ips.Ranges() {
		first, last := r.Addrs()
		if first == last {
			result = append(result, first.String())
		} else if p, ok := r.Prefix(); ok {
			result = append(result, p.String())
		} else {
			result = append(result, r.String())
		}
	}

	return result
}

// legacySrcIPsWithRoutes returns the [tailcfg.FilterRule.SrcIPs] string slice,
// appending approved subnet routes when the sources include a wildcard.
// When hasDangerAll is true, returns ["*"] to represent all IPs.
func legacySrcIPsWithRoutes(
	resolved ipset.Set,
	hasWildcard bool,
	hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	if hasDangerAll {
		return []string{"*"}
	}

	ips := legacyIpSetToStrings(resolved)
	if hasWildcard {
		ips = append(ips, legacyApprovedSubnetRoutes(nodes)...)
	}

	return ips
}

// legacyCompileFilterRules takes a set of nodes and a [Policy] and generates a
// set of Tailscale compatible [tailcfg.FilterRule]s used to allow traffic
// on clients.
func (pol *Policy) legacyCompileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		return tailcfg.FilterAllowAll
	}

	return legacyGlobalFilterRules(pol.legacyCompileGrants(users, nodes))
}

func (pol *Policy) legacyDestinationsToNetPortRange(
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

		if ips.IsEmpty() {
			log.Debug().Caller().Msgf("destination resolved to nil ips: %v", dest)
			continue
		}

		prefixes := ips.Prefixes()

		for pref := range prefixes {
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

func legacyFilterRuleKey(rule tailcfg.FilterRule) string {
	return fmt.Sprintf("%s|%v", strings.Join(rule.SrcIPs, ","), rule.IPProto)
}

// legacyMergeFilterRules merges rules with identical [tailcfg.FilterRule.SrcIPs] and
// [tailcfg.FilterRule.IPProto] by combining their [tailcfg.FilterRule.DstPorts].
// DstPorts are NOT deduplicated to match Tailscale behavior.
// [tailcfg.CapGrant] rules (which have no [tailcfg.FilterRule.DstPorts]) are
// passed through without merging since [tailcfg.CapGrant] and
// [tailcfg.FilterRule.DstPorts] are mutually exclusive in a
// [tailcfg.FilterRule].
func legacyMergeFilterRules(rules []tailcfg.FilterRule) []tailcfg.FilterRule {
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

		key := legacyFilterRuleKey(rule)

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

func (pm *PolicyManager) legacyFilter() ([]tailcfg.FilterRule, []packetfilter.Rule) {
	rules := pm.PacketRules()
	return packetfilter.ToTailcfg(rules), rules
}

func (pm *PolicyManager) legacyFilterForNode(
	node types.NodeView,
) ([]tailcfg.FilterRule, error) {
	rules, err := pm.PacketRulesForNode(node)
	return packetfilter.ToTailcfg(rules), err
}

func (pm *PolicyManager) legacyMatchersForNode(
	node types.NodeView,
) ([]packetfilter.Rule, error) {
	return pm.PeerRulesForNode(node)
}

func (pol *Policy) compileFilterRules(
	users types.Users,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	return packetfilter.ToTailcfg(
		newReadView(
			pol,
			users,
			nodes,
			pol.compileGrants(users, nodes),
			nil,
		).PacketRules(),
	)
}

func (pol *Policy) compileFilterRulesForNode(
	users types.Users,
	node types.NodeView,
	nodes views.Slice[types.NodeView],
) []tailcfg.FilterRule {
	v := newReadView(pol, users, nodes, pol.compileGrants(users, nodes), nil)

	return packetfilter.ToTailcfg(
		v.generation.buildRuleIndex(views.SliceOf([]types.NodeView{node}), true).
			forNode(node.ID()),
	)
}

func rulesFromWireForTest(rules []tailcfg.FilterRule) []packetfilter.Rule {
	var result []packetfilter.Rule

	for _, wire := range rules {
		var sources ipset.Builder

		for _, raw := range wire.SrcIPs {
			addresses, _ := util.ParseIPSet(raw, nil)
			sources.AddSet(addresses)
		}

		src, _ := sources.Build()

		if len(wire.CapGrant) > 0 {
			var caps []packetfilter.CapabilityGrant

			for _, grant := range wire.CapGrant {
				var b ipset.Builder
				for _, prefix := range grant.Dsts {
					b.AddPrefix(prefix)
				}

				set, _ := b.Build()
				caps = append(
					caps,
					packetfilter.CapabilityGrant{Addresses: set, CapMap: grant.CapMap},
				)
			}

			result = append(result, packetfilter.NewCapabilityRule(src, caps))

			continue
		}

		var destinations []packetfilter.Destination

		for _, destination := range wire.DstPorts {
			set, _ := util.ParseIPSet(destination.IP, nil)
			destinations = append(
				destinations,
				packetfilter.Destination{Addresses: set, Ports: destination.Ports},
			)
		}

		var protocols []ipproto.Proto

		for _, protocol := range wire.IPProto {
			if protocol >= 0 && protocol <= 255 {
				protocols = append(protocols, ipproto.Proto(protocol))
			}
		}

		result = append(
			result,
			packetfilter.NewNetworkRule(src, destinations, protocols),
		)
	}

	return result
}

func mergeFilterRules(rules []tailcfg.FilterRule) []tailcfg.FilterRule {
	return legacyMergeFilterRules(rules)
}

func (pol *Policy) compileOtherDests(
	users types.Users,
	nodes views.Slice[types.NodeView],
	grant Grant,
	destinations Aliases,
	sources []ipset.Set,
	srcStrings []string,
) []tailcfg.FilterRule {
	cache := resolutionCache{pol, users, nodes, make(map[string]aliasResolution)}

	dsts := make([]resolvedDestination, 0, len(destinations))
	for _, alias := range destinations {
		result := cache.resolve(alias)
		_, wild := alias.(Asterix)
		dsts = append(dsts, resolvedDestination{result.addresses, result.err, wild})
	}

	var builder ipset.Builder
	for _, source := range sources {
		builder.AddSet(source)
	}

	raw, _ := builder.Build()

	var packet ipset.Builder

	for _, source := range srcStrings {
		set, _ := util.ParseIPSet(source, nil)
		packet.AddSet(set)
	}

	packetSet, _ := packet.Build()

	var companionExtra ipset.Builder

	if grant.App != nil && sourcesHaveWildcard(destinations) {
		for _, node := range nodes.All() {
			for _, prefix := range node.SubnetRoutes() {
				companionExtra.AddPrefix(prefix)
			}
		}
	}

	extra, _ := companionExtra.Build()
	fragments := compileDestinations(
		packetSet,
		raw,
		dsts,
		grant.InternetProtocols,
		grant.App,
		extra,
	)
	index := mergeFragments(wrapUnrestricted(fragments), nodes)

	return packetfilter.ToTailcfg(index.rules)
}

func wrapUnrestricted(fragments []ruleFragment) []ownedFragment {
	result := make([]ownedFragment, 0, len(fragments))
	for _, fragment := range fragments {
		result = append(
			result,
			ownedFragment{fragment, ownerApplicability{unrestricted: true}},
		)
	}

	return result
}

// referenceMatch deliberately retains netipx parsing and membership.
type referenceMatch struct{ srcs, dests *netipx.IPSet }

func referenceParse(raw string) *netipx.IPSet {
	var builder netipx.IPSetBuilder

	switch {
	case raw == "*":
		builder.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
		builder.AddPrefix(netip.MustParsePrefix("::/0"))
	case strings.Contains(raw, "-"):
		value, err := netipx.ParseIPRange(raw)
		if err == nil {
			builder.AddRange(value)
		}
	case strings.Contains(raw, "/"):
		value, err := netip.ParsePrefix(raw)
		if err == nil && value == value.Masked() {
			builder.AddPrefix(value)
		}
	default:
		value, err := netip.ParseAddr(raw)
		if err == nil {
			builder.Add(value)
		}
	}

	set, _ := builder.IPSet()

	return set
}

func referenceMatchesFromFilterRules(rules []tailcfg.FilterRule) []referenceMatch {
	result := make([]referenceMatch, 0, len(rules))
	for _, rule := range rules {
		var src, dst netipx.IPSetBuilder
		for _, raw := range rule.SrcIPs {
			src.AddSet(referenceParse(raw))
		}

		for _, entry := range rule.DstPorts {
			dst.AddSet(referenceParse(entry.IP))
		}

		for _, grant := range rule.CapGrant {
			for _, prefix := range grant.Dsts {
				dst.AddPrefix(prefix)
			}
		}

		s, _ := src.IPSet()
		d, _ := dst.IPSet()
		result = append(result, referenceMatch{s, d})
	}

	return result
}

func (m referenceMatch) SrcsContainsIPs(ips ...netip.Addr) bool {
	return slices.ContainsFunc(ips, m.srcs.Contains)
}

func (m referenceMatch) DestsContainsIP(ips ...netip.Addr) bool {
	return slices.ContainsFunc(ips, m.dests.Contains)
}

func (m referenceMatch) SrcsOverlapsPrefixes(prefixes ...netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, m.srcs.OverlapsPrefix)
}

func (m referenceMatch) DestsOverlapsPrefixes(prefixes ...netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, m.dests.OverlapsPrefix)
}

func (m referenceMatch) DestsIsTheInternet() bool {
	if m.dests.ContainsPrefix(netip.MustParsePrefix("0.0.0.0/0")) ||
		m.dests.ContainsPrefix(netip.MustParsePrefix("::/0")) {
		return true
	}
	// Freeze the internet exclusion domain independently from util's Set.
	var internet netipx.IPSetBuilder
	internet.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
	internet.AddPrefix(netip.MustParsePrefix("2000::/3"))

	for _, raw := range []string{"fc00::/7", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd7a:115c:a1e0::/48", "100.64.0.0/10", "fe80::/10", "169.254.0.0/16"} {
		internet.RemovePrefix(netip.MustParsePrefix(raw))
	}

	set, _ := internet.IPSet()
	for _, prefix := range set.Prefixes() {
		if !m.dests.ContainsPrefix(prefix) {
			return false
		}
	}

	return true
}

func referenceCanAccessWithRoutes(
	node types.NodeView,
	rules []referenceMatch,
	peer types.NodeView,
	srcRoutes, dstRoutes []netip.Prefix,
	exit bool,
) bool {
	if !node.Valid() || !peer.Valid() {
		return false
	}

	for _, rule := range rules {
		if !rule.SrcsContainsIPs(node.IPs()...) &&
			!rule.SrcsOverlapsPrefixes(srcRoutes...) {
			continue
		}

		if rule.DestsContainsIP(peer.IPs()...) ||
			rule.DestsOverlapsPrefixes(dstRoutes...) ||
			(exit && rule.DestsIsTheInternet()) {
			return true
		}
	}

	return false
}

func requireWireEqual(t *testing.T, want, got []tailcfg.FilterRule) {
	t.Helper()

	if diff := semanticFilterRulesDiff(t, want, got); diff != "" {
		t.Fatal(diff)
	}
}

func legacyApprovedSubnetRoutes(nodes views.Slice[types.NodeView]) []string {
	seen := make(set.Set[string])

	var routes []string

	for _, node := range nodes.All() {
		for _, route := range node.SubnetRoutes() {
			s := route.String()
			if !seen.Contains(s) {
				seen.Add(s)
				routes = append(routes, s)
			}
		}
	}

	return routes
}

func srcIPsWithRoutes(
	set ipset.Set,
	wild, danger bool,
	nodes views.Slice[types.NodeView],
) []string {
	return legacySrcIPsWithRoutes(set, wild, danger, nodes)
}

//nolint:nilnil // An empty grant emits no rules.
func (pol *Policy) compileOneGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*compiledGrant, error) {
	cache := resolutionCache{pol, users, nodes, make(map[string]aliasResolution)}

	_, err := cache.sources(grant.Sources)
	if err != nil {
		return nil, err
	}

	sandbox := *pol
	sandbox.Grants = []Grant{grant}
	sandbox.ACLs = nil

	grants := sandbox.compileGrants(users, nodes)
	if len(grants) == 0 {
		return nil, nil
	}

	return &grants[0], nil
}

func typedViaRulesForTest(
	grant *compiledGrant,
	node types.NodeView,
) []tailcfg.FilterRule {
	return packetfilter.ToTailcfg(
		mergeFragments(
			wrapUnrestricted(compileViaForNode(grant, node)),
			views.SliceOf([]types.NodeView{node}),
		).rules,
	)
}

func compileAutogroupSelf(
	grant *compiledGrant,
	node types.NodeView,
	index userNodeIndex,
) []tailcfg.FilterRule {
	if node.IsTagged() || !node.User().Valid() || grant.self == nil {
		return nil
	}

	return packetfilter.ToTailcfg(
		mergeFragments(
			wrapUnrestricted(compileSelfForUser(grant, index[node.User().ID()])),
			views.SliceOf([]types.NodeView{node}),
		).rules,
	)
}

func (p Protocol) toIANAProtocolNumbers() []int {
	if p == 0 {
		return nil
	}

	return []int{int(p)}
}
