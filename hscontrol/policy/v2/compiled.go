package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/views"
	"tailscale.com/util/mak"
)

// grantCategory classifies a grant by what per-node work it needs.
type grantCategory int

const (
	// grantCategoryRegular requires no per-node work. The pre-compiled
	// rules are complete and only need [policyutil.ReduceFilterRules].
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
	// ruleKeys are rules' merge keys, built once per compile so that
	// merging per node does not join long SrcIPs again.
	ruleKeys []string

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

	// byUser holds each user's rules, see [precomputeSelfRules].
	byUser map[uint]keyedRules
}

// keyedRules are filter rules with their merge keys, see [filterRuleKey],
// and their matchers.
type keyedRules struct {
	rules    []tailcfg.FilterRule
	keys     []string
	matchers []matcher.Match
}

func newKeyedRules(rules []tailcfg.FilterRule) keyedRules {
	return keyedRules{
		rules:    rules,
		keys:     ruleKeys(rules),
		matchers: matcher.MatchesFromFilterRules(rules),
	}
}

// viaGrantData holds data needed for per-node via-grant compilation.
// Sources are already resolved into srcIPStrings; destinations are
// pre-resolved into prefixes plus a flag for autogroup:internet, which
// the consumers handle separately because its gate is per-node
// (IsExitNode()) rather than per-prefix overlap.
type viaGrantData struct {
	viaTags              []Tag
	resolvedDsts         []netip.Prefix
	hasAutoGroupInternet bool
	internetProtocols    []ProtocolPort
	srcIPStrings         []string
	// srcSet is srcIPStrings parsed once for the matchers of the grant's
	// rules, which every router of the grant shares.
	srcSet *netipx.IPSet
	// keyPrefix and keys, by IPProto, build the merge keys of the grant's
	// rules once, see [viaRuleKey].
	keyPrefix string
	keys      map[string]string
}

// resolveViaDestinations splits a via grant's destinations into the
// flat list of IP prefixes they resolve to plus a flag for
// autogroup:internet. Every alias kind goes through [Alias.Resolve] so
// adding a new alias type to the policy parser does not silently
// disappear from the via path. Non-IP alias kinds (tag, user, group,
// wildcard) resolve to /32 host IPs that never overlap with subnet
// route advertisements and therefore contribute nothing here.
func resolveViaDestinations(
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
		if err != nil || ips == nil {
			continue
		}

		prefixes = append(prefixes, ips.Prefixes()...)
	}

	return prefixes, hasAutoGroupInternet
}

// userNodeIndex maps user IDs to their untagged nodes. Built once per
// policy or node-set change and read from many goroutines under
// [PolicyManager.mu]; readers must hold the lock (or the snapshot
// returned to them).
type userNodeIndex map[uint][]types.NodeView

func buildUserNodeIndex(
	nodes views.Slice[types.NodeView],
) userNodeIndex {
	idx := make(userNodeIndex)

	for _, n := range nodes.All() {
		if nodeHasUserIdentity(n) {
			uid := n.User().ID()
			idx[uid] = append(idx[uid], n)
		}
	}

	return idx
}

// ownerIndex is every untagged node's address with its user, sorted by
// address, and per family the users with a node of it: a route is looked up
// in it, not walked against every user's nodes.
type ownerIndex struct {
	addrs []ownerAddr
	fams  [2][]uint
}

type ownerAddr struct {
	addr netip.Addr
	uid  uint
	node types.NodeView
}

func buildOwnerIndex(userIdx userNodeIndex) ownerIndex {
	var (
		idx  ownerIndex
		fams [2]map[uint]bool
	)

	for uid, nodes := range userIdx {
		for _, n := range nodes {
			for _, ip := range n.IPs() {
				idx.addrs = append(idx.addrs, ownerAddr{addr: ip, uid: uid, node: n})

				f := 0
				if ip.Is6() {
					f = 1
				}

				mak.Set(&fams[f], uid, true)
			}
		}
	}

	slices.SortFunc(idx.addrs, func(a, b ownerAddr) int { return a.addr.Compare(b.addr) })

	for f := range fams {
		idx.fams[f] = slices.Sorted(maps.Keys(fams[f]))
	}

	return idx
}

// in calls fn with each indexed address inside p: an exit route, every
// user of its family once, with no node.
func (o ownerIndex) in(p netip.Prefix, fn func(ownerAddr)) {
	if p.Bits() == 0 {
		f := 0
		if p.Addr().Is6() {
			f = 1
		}

		for _, uid := range o.fams[f] {
			fn(ownerAddr{uid: uid})
		}

		return
	}

	p = p.Masked()

	i, _ := slices.BinarySearchFunc(o.addrs, p.Addr(), func(a ownerAddr, t netip.Addr) int { return a.addr.Compare(t) })
	for ; i < len(o.addrs) && p.Contains(o.addrs[i].addr); i++ {
		fn(o.addrs[i])
	}
}

// A user association alone does not establish ownership: tagged nodes may retain their creator.
func nodeHasUserIdentity(node types.NodeView) bool {
	return !node.IsTagged() && node.User().Valid()
}

// compileNodeAttrs returns the per-node CapMap derived from policy
// nodeAttrs plus the tailnet-wide [Policy.RandomizeClientPort] flag.
//
// Returns an error when a target alias fails to resolve so the caller
// surfaces a corrupt policy instead of silently granting a partial set
// of attrs.
func (pol *Policy) compileNodeAttrs(
	users types.Users,
	nodes views.Slice[types.NodeView],
) (map[types.NodeID]tailcfg.NodeCapMap, error) {
	empty := map[types.NodeID]tailcfg.NodeCapMap{}

	if pol == nil {
		return empty, nil
	}

	if len(pol.NodeAttrs) == 0 && !pol.RandomizeClientPort {
		return empty, nil
	}

	result := make(map[types.NodeID]tailcfg.NodeCapMap)
	stamp := func(id types.NodeID, attr nodecap.Cap) {
		capMap, ok := result[id]
		if !ok {
			capMap = tailcfg.NodeCapMap{}
			result[id] = capMap
		}

		// nil [tailcfg.RawMessage] matches the wire format from a
		// Tailscale-hosted control plane: capabilities without companion
		// data marshal as null rather than []. Storing nil keeps the
		// merge stable and lets the compat test diff cleanly against
		// captured netmaps.
		if _, exists := capMap[attr]; !exists {
			capMap[attr] = nil
		}
	}

	// Cache each node's IPs once per call. Without the cache, the
	// node-attr inner loop would call [types.NodeView.IPs] once per attr
	// per node — O(grants × nodes) allocations of a 2-element slice
	// for what is invariant per node within a single policy compile.
	type nodeIPs struct {
		id  types.NodeID
		ips []netip.Addr
	}

	nodeList := make([]nodeIPs, 0, nodes.Len())
	for _, n := range nodes.All() {
		nodeList = append(nodeList, nodeIPs{id: n.ID(), ips: n.IPs()})
	}

	if pol.RandomizeClientPort {
		for _, ni := range nodeList {
			stamp(ni.id, nodecap.RandomizeClientPort)
		}
	}

	for _, na := range pol.NodeAttrs {
		if len(na.Attrs) == 0 {
			continue
		}

		resolved, err := na.Targets.Resolve(pol, users, nodes)
		if err != nil {
			return nil, fmt.Errorf("nodeAttrs target %s: %w", na.Targets, err)
		}

		if resolved == nil {
			continue
		}

		for _, ni := range nodeList {
			if !slices.ContainsFunc(ni.ips, resolved.Contains) {
				continue
			}

			for _, attr := range na.Attrs {
				stamp(ni.id, attr)
			}
		}
	}

	return result, nil
}

// compileGrants resolves all policy grants into [compiledGrant] structs.
// Source resolution and non-self destination resolution happens once
// here. This is the single resolution path that replaces the
// duplicated work in [Policy.compileFilterRules] and the autogroup:self
// expansion.
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
	srcs := sourceCache{}

	compile := func(grant Grant) {
		cg, err := pol.compileOneGrant(grant, users, nodes, srcs)
		if err != nil {
			log.Trace().Err(err).Msg("compiling grant")

			return
		}

		if cg != nil {
			cg.ruleKeys = ruleKeys(cg.rules)
			compiled = append(compiled, *cg)
		}
	}

	for _, grant := range grants {
		compile(grant)

		if app, ok := grant.appPart(); ok {
			compile(app)
		}
	}

	return compiled
}

// compileOneGrant resolves a single grant into a [compiledGrant].
// All source resolution happens here. Non-self, non-via destination
// resolution also happens here. Per-node data (self dests, via
// matching) is stored for deferred compilation.
//
//nolint:gocyclo,cyclop
func (pol *Policy) compileOneGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
	srcs sourceCache,
) (*compiledGrant, error) {
	// Via grants: resolve sources, store deferred data.
	if grant.HasVia() {
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
	sources := srcs.get(pol, grant.Sources, users, nodes)

	resolvedSrcs, err := sources.all, sources.err
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
	srcIPStrings := sources.strings(hasWildcard, hasDangerAll, nodes)

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

	// Classify and store deferred self data. The struct literal already
	// initializes category to grantCategoryRegular (the zero value).
	if len(autogroupSelfDests) > 0 {
		cg.category = grantCategorySelf
		cg.self = &selfGrantData{
			resolvedSrcs:      resolvedSrcs,
			internetProtocols: grant.InternetProtocols,
			app:               grant.App,
		}
	}

	return cg, nil
}

// sourceCache holds each source list's resolution for one compile: an ACL
// compiles to one grant per destination, all sharing its sources, and
// resolving and merging them is most of a wide ACL's compile.
type sourceCache map[sourcesKey]*grantSources

// sourcesKey names a source list by its backing array, which the grants
// of one ACL share.
type sourcesKey struct {
	first *Alias
	n     int
}

// grantSources is a source list resolved per alias, and its SrcIPs once
// built.
type grantSources struct {
	all []ResolvedAddresses
	err error

	built bool
	strs  []string
}

// get resolves sources, once per source list; c may be nil.
func (c sourceCache) get(
	pol *Policy,
	sources Aliases,
	users types.Users,
	nodes views.Slice[types.NodeView],
) *grantSources {
	key := sourcesKey{n: len(sources)}
	if len(sources) > 0 {
		key.first = &sources[0]
	}

	if s, ok := c[key]; ok {
		return s
	}

	s := &grantSources{}
	s.all, s.err = resolveSources(pol, sources, users, nodes)

	if c != nil {
		c[key] = s
	}

	return s
}

// strings returns the SrcIPs of the sources. Both flags follow from the
// sources, so every grant sharing them asks the same. The slice is shared
// and clipped, so a caller appending to it copies.
func (s *grantSources) strings(hasWildcard, hasDangerAll bool, nodes views.Slice[types.NodeView]) []string {
	if !s.built {
		s.strs = slices.Clip(buildSrcIPStrings(s.all, hasWildcard, hasDangerAll, nodes))
		s.built = true
	}

	return s.strs
}

// compileOneViaGrant resolves sources for a via grant and stores the
// deferred per-node data. The actual via-node matching and route
// intersection happens in [viaDstsForNode].
func (pol *Policy) compileOneViaGrant(
	grant Grant,
	users types.Users,
	nodes views.Slice[types.NodeView],
) (*compiledGrant, error) {
	resolvedSrcs, err := resolveSources(
		pol, grant.Sources, users, nodes,
	)
	if err != nil {
		return nil, err
	}

	hasWildcard := sourcesHaveWildcard(grant.Sources)
	hasDangerAll := sourcesHaveDangerAll(grant.Sources)

	srcIPStrings := buildSrcIPStrings(resolvedSrcs, hasWildcard, hasDangerAll, nodes)
	if len(srcIPStrings) == 0 {
		return nil, nil //nolint:nilnil
	}

	resolvedDsts, hasAutoGroupInternet := resolveViaDestinations(
		pol, users, nodes, grant.Destinations,
	)

	via := &viaGrantData{
		viaTags:              grant.Via,
		resolvedDsts:         resolvedDsts,
		hasAutoGroupInternet: hasAutoGroupInternet,
		internetProtocols:    grant.InternetProtocols,
		srcIPStrings:         srcIPStrings,
		srcSet:               matcher.ParseSrcs(srcIPStrings),
		keyPrefix:            fmt.Sprintf("via:%v|%s|", grant.Via, strings.Join(srcIPStrings, ",")),
	}

	via.keys = map[string]string{"[]": via.keyPrefix + "[]"}

	for _, ipp := range grant.InternetProtocols {
		proto := fmt.Sprint(ipp.Protocol.toIANAProtocolNumbers())
		via.keys[proto] = via.keyPrefix + proto
	}

	return &compiledGrant{category: grantCategoryVia, via: via}, nil
}

// viaRuleKey returns the merge key of a rule of a via grant: Tailscale
// merges a via rule only with via rules through the same tags. Keys of
// the IPProtos the grant lists are built once; others on use.
func viaRuleKey(cg *compiledGrant, rule tailcfg.FilterRule) string {
	proto := fmt.Sprint(rule.IPProto)
	if key, ok := cg.via.keys[proto]; ok {
		return key
	}

	return cg.via.keyPrefix + proto
}

// resolveSources resolves grant sources per alias. This is the canonical
// source-resolution path. Its output lands in [compiledGrant.srcIPStrings]
// (among other places) and callers on the hot path should prefer reading
// that over calling [Alias.Resolve] again.
func resolveSources(
	pol *Policy,
	sources Aliases,
	users types.Users,
	nodes views.Slice[types.NodeView],
) ([]ResolvedAddresses, error) {
	var all []ResolvedAddresses

	for _, src := range sources {
		if ag, ok := src.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
			return nil, errSelfInSources
		}

		ips, err := src.Resolve(pol, users, nodes)
		if err != nil {
			log.Trace().Caller().Err(err).
				Msg("resolving source ips")
		}

		if ips != nil {
			all = append(all, ips)
		}
	}

	return all, nil
}

// buildSrcIPStrings writes sources as Tailscale does: each alias on its
// own, unioned and sorted as text, so a node address stays next to a
// wildcard range that contains it. A wildcard adds every approved subnet
// route; danger-all is "*".
func buildSrcIPStrings(
	resolvedSrcs []ResolvedAddresses,
	hasWildcard, hasDangerAll bool,
	nodes views.Slice[types.NodeView],
) []string {
	var strs []string
	for _, src := range resolvedSrcs {
		strs = append(strs, src.Strings()...)
	}

	if len(strs) == 0 {
		return nil
	}

	if hasDangerAll {
		return []string{"*"}
	}

	if hasWildcard {
		strs = append(strs, approvedSubnetRoutes(nodes)...)
	}

	slices.Sort(strs)

	return slices.Compact(strs)
}

type resolvedDestination struct {
	Alias

	addresses ResolvedAddresses
	err       error
}

func (dst resolvedDestination) Resolve(
	_ *Policy,
	_ types.Users,
	_ views.Slice[types.NodeView],
) (ResolvedAddresses, error) {
	return dst.addresses, dst.err
}

// compileOtherDests compiles filter rules for non-self, non-via
// destinations. This produces both [tailcfg.FilterRule.DstPorts] rules
// (from [Grant.InternetProtocols]) and [tailcfg.CapGrant] rules (from
// [Grant.App]).
func (pol *Policy) compileOtherDests(
	users types.Users,
	nodes views.Slice[types.NodeView],
	grant Grant,
	otherDests Aliases,
	resolvedSrcs []ResolvedAddresses,
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
			resolvedDests[i] = resolvedDestination{
				Alias:     dst,
				addresses: addresses,
				err:       err,
			}
		}

		otherDests = resolvedDests
	}

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

			prefixes := ips.Prefixes()

			// The wildcard takes in every approved subnet route, as it does
			// in a source. No route keeps the capability once the rule is
			// reduced to a node, but its sources are given the route.
			if _, wildcard := dst.(Asterix); wildcard {
				prefixes = append(prefixes, approvedSubnetPrefixes(nodes)...)
			}

			// Tailscale grants a capability once to a destination named twice.
			if slices.ContainsFunc(capGrants, func(cg tailcfg.CapGrant) bool {
				return slices.Equal(cg.Dsts, prefixes)
			}) {
				continue
			}

			capGrants = append(capGrants, tailcfg.CapGrant{
				Dsts:   prefixes,
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

// hasPerNodeGrants reports whether any [compiledGrant] requires
// per-node filter compilation (via grants or autogroup:self).
func hasPerNodeGrants(grants []compiledGrant) bool {
	for i := range grants {
		if grants[i].category != grantCategoryRegular {
			return true
		}
	}

	return false
}

// collectRelayTargetIPs returns the set of IPs that are destinations of a
// tailscale.com/cap/relay grant. A node whose IP is in this set is a relay
// target: when it goes offline, peers holding a PeerRelay allocation through
// it must recompute their netmap to drop the now-dead allocation. The relay
// cap is carried on each grant's [tailcfg.CapGrant] with Dsts set to the
// resolved relay destinations (see [Policy.compileOtherDests]); the reversed
// companion rule carries [tailcfg.PeerCapabilityRelayTarget] instead and is
// intentionally skipped.
func collectRelayTargetIPs(grants []compiledGrant) (*netipx.IPSet, error) {
	var b netipx.IPSetBuilder

	for i := range grants {
		for _, rule := range grants[i].rules {
			for _, cg := range rule.CapGrant {
				if _, ok := cg.CapMap[peercap.Relay]; !ok {
					continue
				}

				for _, dst := range cg.Dsts {
					b.AddPrefix(dst)
				}
			}
		}
	}

	return b.IPSet()
}

// collectViaTargetTags returns the set of tags used as via targets across all
// grants. A node carrying any of these tags is a via target: peers steering
// traffic through it must recompute when it goes offline. Returns nil when no
// via grants exist.
func collectViaTargetTags(grants []compiledGrant) map[Tag]struct{} {
	tags := make(map[Tag]struct{})

	for i := range grants {
		if grants[i].via == nil {
			continue
		}

		for _, t := range grants[i].via.viaTags {
			tags[t] = struct{}{}
		}
	}

	if len(tags) == 0 {
		return nil
	}

	return tags
}

// globalFilterRules extracts global filter rules from [compiledGrant]s.
// Via grants produce no global rules (they are per-node only); regular
// grants contribute their full pre-compiled ruleset; self grants
// contribute their non-self portion.
func globalFilterRules(grants []compiledGrant) []tailcfg.FilterRule {
	var (
		rules []tailcfg.FilterRule
		keys  []string
	)

	for i := range grants {
		if grants[i].category == grantCategoryVia {
			continue
		}

		rules = append(rules, grants[i].rules...)
		keys = append(keys, grants[i].ruleKeys...)
	}

	return mergeKeyedRules(rules, keys)
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
	owners ownerIndex,
) []tailcfg.FilterRule {
	selfRules := func(cg *compiledGrant, n types.NodeView, idx userNodeIndex) keyedRules {
		return filterSelfRules(cg, n, idx, owners)
	}

	return rulesForNode(grants, node, userIdx, selfRules, compileViaForNode)
}

// nodeOnlyMatchers returns the matchers of the self and via rules a node
// adds to the pre-compiled rules every node shares. Self matchers are
// shared per user; via rules reuse their grant's parsed sources.
func nodeOnlyMatchers(
	grants []compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
	viaRules func(*compiledGrant, types.NodeView) []tailcfg.FilterRule,
) []matcher.Match {
	var matchers []matcher.Match

	for i := range grants {
		cg := &grants[i]

		switch cg.category {
		case grantCategoryRegular:
		case grantCategorySelf:
			matchers = append(matchers, ownSelfRules(cg, node, userIdx).matchers...)
		case grantCategoryVia:
			for _, rule := range viaRules(cg, node) {
				matchers = append(matchers, matcher.MatchFromFilterRuleSrcs(rule, cg.via.srcSet))
			}
		}
	}

	return matchers
}

func rulesForNode(
	grants []compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
	selfRules func(*compiledGrant, types.NodeView, userNodeIndex) keyedRules,
	viaRules func(*compiledGrant, types.NodeView) []tailcfg.FilterRule,
) []tailcfg.FilterRule {
	var (
		rules []tailcfg.FilterRule
		keys  []string
	)

	for i := range grants {
		cg := &grants[i]

		// Pre-compiled rules apply to all grant categories
		// (empty for via-only grants).
		rules = append(rules, cg.rules...)
		keys = append(keys, cg.ruleKeys...)

		switch cg.category {
		case grantCategoryRegular:
			// Nothing more to do.

		case grantCategorySelf:
			self := selfRules(cg, node, userIdx)
			rules = append(rules, self.rules...)
			keys = append(keys, self.keys...)

		case grantCategoryVia:
			for _, rule := range viaRules(cg, node) {
				rules = append(rules, rule)
				keys = append(keys, viaRuleKey(cg, rule))
			}
		}
	}

	return mergeKeyedRules(rules, keys)
}

// ownSelfRules returns the autogroup:self rules of node's own user.
func ownSelfRules(
	cg *compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) keyedRules {
	if node.IsTagged() || cg.self == nil || !node.User().Valid() {
		return keyedRules{}
	}

	return userSelfRules(cg, node.User().ID(), userIdx)
}

// filterSelfRules returns the autogroup:self rules a node's packet filter
// holds: its own user's and, in user order as Tailscale sends them, those of
// every user with a device its approved routes cover, which on an exit node
// is every user. Reducing the rules to the node keeps the covered
// destinations. An exit route makes no peer of a user's device, so the peer
// paths use [ownSelfRules]; a subnet route does through the rule's
// destination.
func filterSelfRules(
	cg *compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
	owners ownerIndex,
) keyedRules {
	routes := slices.Concat(node.SubnetRoutes(), node.ExitRoutes())
	if len(routes) == 0 {
		return ownSelfRules(cg, node, userIdx)
	}

	if cg.self == nil {
		return keyedRules{}
	}

	users := map[uint]bool{}
	if nodeHasUserIdentity(node) {
		users[node.User().ID()] = true
	}

	for _, r := range routes {
		owners.in(r, func(o ownerAddr) { users[o.uid] = true })
	}

	var all keyedRules

	for _, uid := range slices.Sorted(maps.Keys(users)) {
		r := userSelfRules(cg, uid, userIdx)
		all.rules = append(all.rules, r.rules...)
		all.keys = append(all.keys, r.keys...)
	}

	return all
}

// userSelfRules returns uid's autogroup:self rules, shared from
// [precomputeSelfRules], or built now for a grant compiled without it.
func userSelfRules(cg *compiledGrant, uid uint, userIdx userNodeIndex) keyedRules {
	if r, ok := cg.self.byUser[uid]; ok {
		return r
	}

	return newKeyedRules(compileSelfForUser(cg, userIdx[uid]))
}

// precomputeSelfRules builds every user's autogroup:self rules once per
// compile. They depend only on the user, so all of a user's nodes share
// them instead of each node building them again.
func precomputeSelfRules(grants []compiledGrant, userIdx userNodeIndex) {
	for i := range grants {
		self := grants[i].self
		if self == nil {
			continue
		}

		self.byUser = make(map[uint]keyedRules, len(userIdx))

		for uid, nodes := range userIdx {
			self.byUser[uid] = newKeyedRules(compileSelfForUser(&grants[i], nodes))
		}
	}
}

// compileSelfForUser produces the autogroup:self rules for one user's
// untagged devices.
func compileSelfForUser(
	cg *compiledGrant,
	sameUserNodes []types.NodeView,
) []tailcfg.FilterRule {
	if len(sameUserNodes) == 0 {
		return nil
	}

	var rules []tailcfg.FilterRule

	// Tailscale writes autogroup:self once per source alias, each with the
	// same-user devices that alias names.
	perSrc, srcResolved := sameUserSources(cg.self.resolvedSrcs, sameUserNodes)
	if len(perSrc) == 0 {
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
			for _, src := range perSrc {
				rules = append(rules, tailcfg.FilterRule{
					SrcIPs:   src.Strings(),
					DstPorts: destPorts,
					IPProto:  ipp.Protocol.toIANAProtocolNumbers(),
				})
			}
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

// sameUserSources returns, per source alias, the same-user untagged
// devices it names, and all of them together.
func sameUserSources(
	resolvedSrcs []ResolvedAddresses,
	sameUserNodes []types.NodeView,
) ([]ResolvedAddresses, ResolvedAddresses) {
	var (
		perSrc []ResolvedAddresses
		all    netipx.IPSetBuilder
	)

	for _, ips := range resolvedSrcs {
		var named netipx.IPSetBuilder

		for _, n := range sameUserNodes {
			if slices.ContainsFunc(n.IPs(), ips.Contains) {
				n.AppendToIPSet(&named)
				n.AppendToIPSet(&all)
			}
		}

		set, err := named.IPSet()
		if err != nil || len(set.Ranges()) == 0 {
			continue
		}

		src, _ := newNodeAddresses(set, nil)
		perSrc = append(perSrc, src)
	}

	set, err := all.IPSet()
	if err != nil {
		return nil, nil
	}

	union, _ := newNodeAddresses(set, nil)

	return perSrc, union
}

// viaDstsForNode returns the destinations of a via grant that node's packet
// filter holds: none unless it matches a via tag and an approved route of
// its overlaps them, or it is an exit node under autogroup:internet. An exit
// route counts as it does when a rule is reduced to a node; whether the
// node then serves the sources is [viaServes].
func viaDstsForNode(
	cg *compiledGrant,
	node types.NodeView,
) ([]netip.Prefix, bool) {
	if cg.via == nil {
		return nil, false
	}

	if !slices.ContainsFunc(cg.via.viaTags, func(tag Tag) bool {
		return node.HasTag(string(tag))
	}) {
		return nil, false
	}

	routes := node.AllApprovedRoutes()

	var viaDstPrefixes []netip.Prefix

	for _, dstPrefix := range cg.via.resolvedDsts {
		// Equality would reject any broader or narrower dst relative
		// to the advertised route. Containment in either direction
		// matches the operator's authorisation: a broader dst restricts
		// traffic to the subset the router serves; a narrower dst rides
		// on a router covering more than the operator asked for. The
		// rule emits the literal dst either way because that is what
		// the policy authorised.
		if slices.ContainsFunc(routes, dstPrefix.Overlaps) {
			viaDstPrefixes = append(viaDstPrefixes, dstPrefix)
		}
	}

	// autogroup:internet on a via-tagged exit advertiser becomes a rule
	// whose DstPorts enumerate [util.TheInternet]. The matchers derived
	// from this rule let [types.NodeView.CanAccess] surface the exit node
	// to the grant source via [matcher.Match.DestsIsTheInternet].
	// [policyutil.ReduceFilterRules] strips the rule from the wire format
	// on non-exit advertisers, preserving SaaS PacketFilter encoding.
	return viaDstPrefixes, cg.via.hasAutoGroupInternet && node.IsExitNode()
}

// viaServes reports whether node carries the sources' traffic for a via
// grant, which makes it their peer: through a subnet route for any
// destination, through an exit route only for one on the internet, as for a
// rule without via.
func viaServes(cg *compiledGrant, node types.NodeView) bool {
	prefixes, internet := viaDstsForNode(cg, node)
	if internet {
		return true
	}

	subnets := node.SubnetRoutes()

	return slices.ContainsFunc(prefixes, func(dst netip.Prefix) bool {
		return slices.ContainsFunc(subnets, dst.Overlaps) || util.TheInternet().OverlapsPrefix(dst)
	})
}

// compileViaForNode produces via-grant filter rules for a specific
// node. Only produces rules when the node matches one of the via
// tags and advertises routes that match the grant destinations.
func compileViaForNode(
	cg *compiledGrant,
	node types.NodeView,
) []tailcfg.FilterRule {
	viaDstPrefixes, internet := viaDstsForNode(cg, node)
	if len(viaDstPrefixes) == 0 && !internet {
		return nil
	}

	dsts := make([]string, 0, len(viaDstPrefixes))
	for _, prefix := range viaDstPrefixes {
		dsts = append(dsts, filterIP(prefix))
	}

	if internet {
		dsts = append(dsts, internetStrings()...)
	}

	// Build rules using pre-resolved srcIPStrings.
	var rules []tailcfg.FilterRule

	for _, ipp := range cg.via.internetProtocols {
		var destPorts []tailcfg.NetPortRange

		for _, ip := range dsts {
			for _, port := range ipp.Ports {
				destPorts = append(
					destPorts,
					tailcfg.NetPortRange{
						IP:    ip,
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

// viaSources returns the sources of each via grant node serves, see
// [viaServes]. They link the router to those sources and to nothing else: a
// rule naming the router's addresses would also link a node that routes them,
// and one naming the route everything else serving it, and SaaS links neither
// (grant-via-router-covered, via-grant-v81).
func viaSources(grants []compiledGrant, node types.NodeView) []matcher.Match {
	var srcs []matcher.Match

	for i := range grants {
		if cg := &grants[i]; cg.via != nil && viaServes(cg, node) {
			srcs = append(srcs, matcher.MatchFromFilterRuleSrcs(tailcfg.FilterRule{}, cg.via.srcSet))
		}
	}

	return srcs
}

// noViaRules leaves via grants out of a node's matchers.
func noViaRules(*compiledGrant, types.NodeView) []tailcfg.FilterRule { return nil }

// siblingSelfSources returns, per user, the devices of other users that a
// subnet route of a device of the user covers and that are sources of their
// own user's autogroup:self rules. SaaS lists such a device on every device
// of the router's user; it lists the router alone.
func siblingSelfSources(
	grants []compiledGrant,
	nodes views.Slice[types.NodeView],
	userIdx userNodeIndex,
	owners ownerIndex,
) map[uint]map[types.NodeID]bool {
	out := map[uint]map[types.NodeID]bool{}

	if !slices.ContainsFunc(grants, func(cg compiledGrant) bool { return cg.self != nil }) {
		return out
	}

	for _, router := range nodes.All() {
		if !nodeHasUserIdentity(router) {
			continue
		}

		owner := router.User().ID()

		for _, r := range router.SubnetRoutes() {
			owners.in(r, func(o ownerAddr) {
				if o.uid == owner || out[owner][o.node.ID()] || !selfSource(grants, o.uid, o.node, userIdx) {
					return
				}

				if out[owner] == nil {
					out[owner] = map[types.NodeID]bool{}
				}

				out[owner][o.node.ID()] = true
			})
		}
	}

	return out
}

// selfSource reports whether d is a source of an autogroup:self rule of its
// user uid.
func selfSource(grants []compiledGrant, uid uint, d types.NodeView, userIdx userNodeIndex) bool {
	for i := range grants {
		if grants[i].self == nil {
			continue
		}

		if slices.ContainsFunc(userSelfRules(&grants[i], uid, userIdx).matchers, func(m matcher.Match) bool {
			return m.SrcsContainsIPs(d.IPs()...)
		}) {
			return true
		}
	}

	return false
}
