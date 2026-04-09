package v2

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/deephash"
)

// ErrInvalidTagOwner is returned when a tag owner is not an Alias type.
var ErrInvalidTagOwner = errors.New("tag owner is not an Alias")

type PolicyManager struct {
	mu    sync.Mutex
	pol   *Policy
	users []types.User
	nodes views.Slice[types.NodeView]

	filterHash deephash.Sum
	filter     []tailcfg.FilterRule
	matchers   []matcher.Match

	tagOwnerMapHash deephash.Sum
	tagOwnerMap     map[Tag]*netipx.IPSet

	exitSetHash        deephash.Sum
	exitSet            *netipx.IPSet
	autoApproveMapHash deephash.Sum
	autoApproveMap     map[netip.Prefix]*netipx.IPSet

	// Lazy map of SSH policies
	sshPolicyMap map[types.NodeID]*tailcfg.SSHPolicy

	// Lazy map of per-node compiled filter rules (unreduced, for autogroup:self)
	compiledFilterRulesMap map[types.NodeID][]tailcfg.FilterRule
	// Lazy map of per-node filter rules (reduced, for packet filters)
	filterRulesMap    map[types.NodeID][]tailcfg.FilterRule
	usesAutogroupSelf bool

	// Hash of the users list to short-circuit SetUsers when users haven't changed.
	// During bulk registration, SetUsers is called for every new node with the same
	// user list, triggering expensive O(rules * nodes) filter recompilation each time.
	usersHash deephash.Sum

	// filterDirty indicates that nodes have changed since the last filter compilation.
	// When true, the next call to Filter(), FilterForNode(), or MatchersForNode() will
	// trigger a full recompilation. This allows SetNodes to defer the expensive
	// O(rules * nodes) compilation during bulk registration.
	filterDirty bool

	// srcMatcherCache maps node IDs to the indices of matchers where that node's
	// IPs appear in the source set. This avoids iterating all matchers in CanAccess
	// when only a small subset are relevant. Invalidated when filters are recompiled.
	srcMatcherCache map[types.NodeID][]int

	// perNodeMatcherCache caches compiled []matcher.Match per node for autogroup:self.
	// Avoids repeated MatchesFromFilterRules allocations in ComputeNodePeers/BuildPeerMap.
	perNodeMatcherCache map[types.NodeID][]matcher.Match

	// globalMatcherCache caches []matcher.Match built from the global (non-autogroup:self)
	// filter rules. These are identical for every node and only need to be built once.
	globalMatcherCache []matcher.Match

	// perNodeSrcIdxCache maps (nodeID, matcherOwnerID) to source matcher indices
	// within that owner's per-node matcher set. This extends the srcMatcherCache
	// concept to per-node matchers used in the autogroup:self path.
	perNodeSrcIdxCache map[perNodeSrcKey][]int
}

// perNodeSrcKey is a composite key for caching source matcher indices
// within a specific node's per-node matcher set (autogroup:self path).
type perNodeSrcKey struct {
	srcNodeID     types.NodeID // the node whose IPs we check against sources
	matcherOwner  types.NodeID // the node whose matcher set we're indexing into
}

// filterAndPolicy combines the compiled filter rules with policy content for hashing.
// This ensures filterHash changes when policy changes, even for autogroup:self where
// the compiled filter is always empty.
type filterAndPolicy struct {
	Filter []tailcfg.FilterRule
	Policy *Policy
}

// NewPolicyManager creates a new PolicyManager from a policy file and a list of users and nodes.
// It returns an error if the policy file is invalid.
// The policy manager will update the filter rules based on the users and nodes.
func NewPolicyManager(b []byte, users []types.User, nodes views.Slice[types.NodeView]) (*PolicyManager, error) {
	policy, err := unmarshalPolicy(b)
	if err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	pm := PolicyManager{
		pol:                    policy,
		users:                  users,
		nodes:                  nodes,
		sshPolicyMap:           make(map[types.NodeID]*tailcfg.SSHPolicy, nodes.Len()),
		compiledFilterRulesMap: make(map[types.NodeID][]tailcfg.FilterRule, nodes.Len()),
		filterRulesMap:         make(map[types.NodeID][]tailcfg.FilterRule, nodes.Len()),
		usesAutogroupSelf:      policy.usesAutogroupSelf(),
	}

	_, err = pm.updateLocked()
	if err != nil {
		return nil, err
	}

	return &pm, nil
}

// updateLocked updates the filter rules based on the current policy and nodes.
// It must be called with the lock held.
func (pm *PolicyManager) updateLocked() (bool, error) {
	// Enable resolve cache and node IP indexes for the duration of this update.
	// Same Group/Username/Tag resolves identically within one update cycle
	// but may be referenced hundreds of times across 14K+ ACL rules.
	if pm.pol != nil {
		pm.pol.resolveCache = make(map[string]*netipx.IPSet)
		pm.pol.nodeIPsByUser, pm.pol.nodeIPsByTag = buildNodeIPIndexes(pm.nodes)
		defer func() {
			pm.pol.resolveCache = nil
			pm.pol.nodeIPsByUser = nil
			pm.pol.nodeIPsByTag = nil
		}()
	}

	// Check if policy uses autogroup:self
	pm.usesAutogroupSelf = pm.pol.usesAutogroupSelf()

	var filter []tailcfg.FilterRule

	var err error

	// Standard compilation for all policies
	filter, err = pm.pol.compileFilterRules(pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("compiling filter rules: %w", err)
	}

	// Hash both the compiled filter AND the policy content together.
	// This ensures filterHash changes when policy changes, even for autogroup:self
	// where the compiled filter is always empty. This eliminates the need for
	// a separate policyHash field.
	filterHash := deephash.Hash(&filterAndPolicy{
		Filter: filter,
		Policy: pm.pol,
	})

	filterChanged := filterHash != pm.filterHash
	if filterChanged {
		log.Debug().
			Str("filter.hash.old", pm.filterHash.String()[:8]).
			Str("filter.hash.new", filterHash.String()[:8]).
			Int("filter.rules", len(pm.filter)).
			Int("filter.rules.new", len(filter)).
			Msg("Policy filter hash changed")
	}

	pm.filter = filter

	pm.filterHash = filterHash
	if filterChanged {
		pm.matchers = matcher.MatchesFromFilterRules(pm.filter)
		pm.srcMatcherCache = nil // Invalidate cached source matcher indices
	}

	// Order matters, tags might be used in autoapprovers, so we need to ensure
	// that the map for tag owners is resolved before resolving autoapprovers.
	// TODO(kradalby): Order might not matter after #2417
	tagMap, err := resolveTagOwners(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving tag owners map: %w", err)
	}

	tagOwnerMapHash := deephash.Hash(&tagMap)

	tagOwnerChanged := tagOwnerMapHash != pm.tagOwnerMapHash
	if tagOwnerChanged {
		log.Debug().
			Str("tagOwner.hash.old", pm.tagOwnerMapHash.String()[:8]).
			Str("tagOwner.hash.new", tagOwnerMapHash.String()[:8]).
			Int("tagOwners.old", len(pm.tagOwnerMap)).
			Int("tagOwners.new", len(tagMap)).
			Msg("Tag owner hash changed")
	}

	pm.tagOwnerMap = tagMap
	pm.tagOwnerMapHash = tagOwnerMapHash

	autoMap, exitSet, err := resolveAutoApprovers(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving auto approvers map: %w", err)
	}

	autoApproveMapHash := deephash.Hash(&autoMap)

	autoApproveChanged := autoApproveMapHash != pm.autoApproveMapHash
	if autoApproveChanged {
		log.Debug().
			Str("autoApprove.hash.old", pm.autoApproveMapHash.String()[:8]).
			Str("autoApprove.hash.new", autoApproveMapHash.String()[:8]).
			Int("autoApprovers.old", len(pm.autoApproveMap)).
			Int("autoApprovers.new", len(autoMap)).
			Msg("Auto-approvers hash changed")
	}

	pm.autoApproveMap = autoMap
	pm.autoApproveMapHash = autoApproveMapHash

	exitSetHash := deephash.Hash(&exitSet)

	exitSetChanged := exitSetHash != pm.exitSetHash
	if exitSetChanged {
		log.Debug().
			Str("exitSet.hash.old", pm.exitSetHash.String()[:8]).
			Str("exitSet.hash.new", exitSetHash.String()[:8]).
			Msg("Exit node set hash changed")
	}

	pm.exitSet = exitSet
	pm.exitSetHash = exitSetHash

	// Determine if we need to send updates to nodes
	// filterChanged now includes policy content changes (via combined hash),
	// so it will detect changes even for autogroup:self where compiled filter is empty
	needsUpdate := filterChanged || tagOwnerChanged || autoApproveChanged || exitSetChanged

	// Only clear caches if we're actually going to send updates
	// This prevents clearing caches when nothing changed, which would leave nodes
	// with stale filters until they reconnect. This is critical for autogroup:self
	// where even reloading the same policy would clear caches but not send updates.
	if needsUpdate {
		// Clear the SSH policy map to ensure it's recalculated with the new policy.
		// TODO(kradalby): This could potentially be optimized by only clearing the
		// policies for nodes that have changed. Particularly if the only difference is
		// that nodes has been added or removed.
		clear(pm.sshPolicyMap)
		clear(pm.compiledFilterRulesMap)
		clear(pm.filterRulesMap)
		pm.perNodeMatcherCache = nil
		pm.perNodeSrcIdxCache = nil
		pm.globalMatcherCache = nil
		pm.clearResolveCache()
	}

	// If nothing changed, no need to update nodes
	if !needsUpdate {
		log.Trace().
			Msg("Policy evaluation detected no changes - all hashes match")

		return false, nil
	}

	log.Debug().
		Bool("filter.changed", filterChanged).
		Bool("tagOwners.changed", tagOwnerChanged).
		Bool("autoApprovers.changed", autoApproveChanged).
		Bool("exitNodes.changed", exitSetChanged).
		Msg("Policy changes require node updates")

	return true, nil
}

func (pm *PolicyManager) SSHPolicy(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if sshPol, ok := pm.sshPolicyMap[node.ID()]; ok {
		return sshPol, nil
	}

	sshPol, err := pm.pol.compileSSHPolicy(baseURL, pm.users, node, pm.nodes)
	if err != nil {
		return nil, fmt.Errorf("compiling SSH policy: %w", err)
	}

	pm.sshPolicyMap[node.ID()] = sshPol

	return sshPol, nil
}

// SSHCheckParams resolves the SSH check period for a source-destination
// node pair by looking up the current policy. This avoids trusting URL
// parameters that a client could tamper with.
// It returns the check period duration and whether a matching check
// rule was found.
func (pm *PolicyManager) SSHCheckParams(
	srcNodeID, dstNodeID types.NodeID,
) (time.Duration, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.pol == nil || len(pm.pol.SSHs) == 0 {
		return 0, false
	}

	// Find the source and destination node views.
	var srcNode, dstNode types.NodeView

	for _, n := range pm.nodes.All() {
		nid := n.ID()
		if nid == srcNodeID {
			srcNode = n
		}

		if nid == dstNodeID {
			dstNode = n
		}

		if srcNode.Valid() && dstNode.Valid() {
			break
		}
	}

	if !srcNode.Valid() || !dstNode.Valid() {
		return 0, false
	}

	// Iterate SSH rules to find the first matching check rule.
	for _, rule := range pm.pol.SSHs {
		if rule.Action != SSHActionCheck {
			continue
		}

		// Resolve sources and check if src node matches.
		srcIPs, err := rule.Sources.Resolve(pm.pol, pm.users, pm.nodes)
		if err != nil || srcIPs == nil {
			continue
		}

		if !slices.ContainsFunc(srcNode.IPs(), srcIPs.Contains) {
			continue
		}

		// Check if dst node matches any destination.
		for _, dst := range rule.Destinations {
			if ag, isAG := dst.(*AutoGroup); isAG && ag.Is(AutoGroupSelf) {
				if !srcNode.IsTagged() && !dstNode.IsTagged() &&
					srcNode.User().ID() == dstNode.User().ID() {
					return checkPeriodFromRule(rule), true
				}

				continue
			}

			dstIPs, err := dst.Resolve(pm.pol, pm.users, pm.nodes)
			if err != nil || dstIPs == nil {
				continue
			}

			if slices.ContainsFunc(dstNode.IPs(), dstIPs.Contains) {
				return checkPeriodFromRule(rule), true
			}
		}
	}

	return 0, false
}

func (pm *PolicyManager) SetPolicy(polB []byte) (bool, error) {
	if len(polB) == 0 {
		return false, nil
	}

	pol, err := unmarshalPolicy(polB)
	if err != nil {
		return false, fmt.Errorf("parsing policy: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Log policy metadata for debugging
	log.Debug().
		Int("policy.bytes", len(polB)).
		Int("acls.count", len(pol.ACLs)).
		Int("groups.count", len(pol.Groups)).
		Int("hosts.count", len(pol.Hosts)).
		Int("tagOwners.count", len(pol.TagOwners)).
		Int("autoApprovers.routes.count", len(pol.AutoApprovers.Routes)).
		Msg("Policy parsed successfully")

	pm.pol = pol

	return pm.updateLocked()
}

// ensureFilterCompiled compiles filter rules if the filterDirty flag is set.
// Must be called with pm.mu held.
//
// Only recompiles the filter rules and matchers. Does NOT re-resolve
// tagOwners/autoApprovers since SetNodes already resolved them eagerly
// when it marked filterDirty. This avoids redundant O(tags × nodes)
// work on every ComputeNodePeers call.
func (pm *PolicyManager) ensureFilterCompiled() error {
	if !pm.filterDirty {
		return nil
	}
	pm.filterDirty = false

	// Enable resolve cache and node IP indexes for filter compilation.
	// For autogroup:self policies, keep the cache alive after compilation
	// so per-node compilations (compileFilterRulesForNodeLocked) also benefit.
	// For non-autogroup:self, tear them down since only the global filter is used.
	if pm.pol != nil {
		pm.pol.resolveCache = make(map[string]*netipx.IPSet)
		pm.pol.nodeIPsByUser, pm.pol.nodeIPsByTag = buildNodeIPIndexes(pm.nodes)
		if !pm.pol.usesAutogroupSelf() {
			defer func() {
				pm.pol.resolveCache = nil
				pm.pol.nodeIPsByUser = nil
				pm.pol.nodeIPsByTag = nil
			}()
		}
	}

	pm.usesAutogroupSelf = pm.pol.usesAutogroupSelf()

	filter, err := pm.pol.compileFilterRules(pm.users, pm.nodes)
	if err != nil {
		return fmt.Errorf("compiling filter rules: %w", err)
	}

	filterHash := deephash.Hash(&filterAndPolicy{
		Filter: filter,
		Policy: pm.pol,
	})

	pm.filter = filter

	if filterHash != pm.filterHash {
		pm.filterHash = filterHash
		pm.matchers = matcher.MatchesFromFilterRules(pm.filter)
		pm.srcMatcherCache = nil
		pm.perNodeMatcherCache = nil
		pm.perNodeSrcIdxCache = nil
		pm.globalMatcherCache = nil
		matcher.ResetIPSetCache()
	}

	return nil
}

// buildNodeIPIndexes builds pre-computed IP sets indexed by UserID and tag.
// This allows Username.Resolve and Tag.Resolve to do O(1) lookups instead
// of scanning all N nodes. Built once per filter compilation cycle.
func buildNodeIPIndexes(nodes views.Slice[types.NodeView]) (
	map[uint]*netipx.IPSet,
	map[string]*netipx.IPSet,
) {
	userBuilders := make(map[uint]*netipx.IPSetBuilder)
	tagBuilders := make(map[string]*netipx.IPSetBuilder)

	for _, node := range nodes.All() {
		if node.IsTagged() {
			// Tagged nodes: index by each tag
			for _, tag := range node.Tags().All() {
				b, ok := tagBuilders[tag]
				if !ok {
					b = &netipx.IPSetBuilder{}
					tagBuilders[tag] = b
				}
				node.AppendToIPSet(b)
			}
		} else if node.User().Valid() {
			// User-owned nodes: index by user ID (uint from gorm.Model)
			uid := node.User().ID()
			b, ok := userBuilders[uid]
			if !ok {
				b = &netipx.IPSetBuilder{}
				userBuilders[uid] = b
			}
			node.AppendToIPSet(b)
		}
	}

	userSets := make(map[uint]*netipx.IPSet, len(userBuilders))
	for uid, b := range userBuilders {
		ipset, _ := b.IPSet()
		userSets[uid] = ipset
	}

	tagSets := make(map[string]*netipx.IPSet, len(tagBuilders))
	for tag, b := range tagBuilders {
		ipset, _ := b.IPSet()
		tagSets[tag] = ipset
	}

	return userSets, tagSets
}

// Filter returns the current filter rules for the entire tailnet and the associated matchers.
func (pm *PolicyManager) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.ensureFilterCompiled(); err != nil {
		log.Error().Err(err).Msg("Failed to compile filter rules on demand")
	}

	return pm.filter, pm.matchers
}

// BuildPeerMap constructs peer relationship maps for the given nodes.
// For global filters, it uses the global filter matchers for all nodes.
// For autogroup:self policies (empty global filter), it builds per-node
// peer maps using each node's specific filter rules.
func (pm *PolicyManager) BuildPeerMap(nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeView {
	if pm == nil {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.ensureFilterCompiled(); err != nil {
		log.Error().Err(err).Msg("Failed to compile filter rules for BuildPeerMap")
		return nil
	}

	// If we have a global filter, use it for all nodes (normal case)
	if !pm.usesAutogroupSelf {
		ret := make(map[types.NodeID][]types.NodeView, nodes.Len())

		// Build the map of all peers according to the matchers.
		// Compared to ReduceNodes, which builds the list per node, we end up with doing
		// the full work for every node O(n^2), while this will reduce the list as we see
		// relationships while building the map, making it O(n^2/2) in the end, but with less work per node.
		for i := range nodes.Len() {
			for j := i + 1; j < nodes.Len(); j++ {
				if nodes.At(i).ID() == nodes.At(j).ID() {
					continue
				}

				if nodes.At(i).CanAccess(pm.matchers, nodes.At(j)) || nodes.At(j).CanAccess(pm.matchers, nodes.At(i)) {
					ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j))
					ret[nodes.At(j).ID()] = append(ret[nodes.At(j).ID()], nodes.At(i))
				}
			}
		}

		return ret
	}

	// For autogroup:self (empty global filter), build per-node peer relationships
	ret := make(map[types.NodeID][]types.NodeView, nodes.Len())

	// Pre-compute per-node matchers using unreduced compiled rules
	// We need unreduced rules to determine peer relationships correctly.
	// Reduced rules only show destinations where the node is the target,
	// but peer relationships require the full bidirectional access rules.
	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	for _, node := range nodes.All() {
		// Use cached per-node matchers (same cache as ComputeNodePeers).
		m := pm.getNodeMatchers(node)
		// Include all nodes, even those with nil matchers (empty filters).
		nodeMatchers[node.ID()] = m
	}

	// Check each node pair for peer relationships using source-index optimization.
	// Start j at i+1 to avoid checking the same pair twice and creating duplicates.
	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]

			var canIAccessJ, canJAccessI bool
			if hasFilterI && len(matchersI) > 0 {
				srcIdx := pm.getPerNodeSrcIndices(nodeI, nodeI.ID(), matchersI)
				canIAccessJ = canAccessIndexed(matchersI, srcIdx, nodeJ)
			}
			if !canIAccessJ && hasFilterJ && len(matchersJ) > 0 {
				srcIdx := pm.getPerNodeSrcIndices(nodeJ, nodeJ.ID(), matchersJ)
				canJAccessI = canAccessIndexed(matchersJ, srcIdx, nodeI)
			}

			if canIAccessJ || canJAccessI {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ)
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI)
			}
		}
	}

	return ret
}

// getSrcMatcherIndices returns the indices of matchers where the given node's
// IPs appear in the source set. Results are cached per node ID and invalidated
// when filters are recompiled. This reduces CanAccess from O(M) to O(relevant)
// where relevant << M for large rule sets.
func (pm *PolicyManager) getSrcMatcherIndices(node types.NodeView) []int {
	if cached, ok := pm.srcMatcherCache[node.ID()]; ok {
		return cached
	}

	ips := node.IPs()
	indices := make([]int, 0, 32)
	for i := range pm.matchers {
		if pm.matchers[i].SrcsContainsIPs(ips...) {
			indices = append(indices, i)
		}
	}

	if pm.srcMatcherCache == nil {
		pm.srcMatcherCache = make(map[types.NodeID][]int)
	}
	pm.srcMatcherCache[node.ID()] = indices

	return indices
}

// canAccessIndexed checks if a source node can access a destination node,
// but only checks the matchers at the given indices (pre-filtered by source IP).
// This is equivalent to CanAccess but avoids iterating all matchers.
func canAccessIndexed(matchers []matcher.Match, srcIndices []int, dst types.NodeView) bool {
	dstIPs := dst.IPs()
	subnetRoutes := dst.SubnetRoutes()
	hasSubnets := len(subnetRoutes) > 0
	isExit := dst.IsExitNode()

	for _, mi := range srcIndices {
		m := &matchers[mi]
		if m.DestsContainsIP(dstIPs...) {
			return true
		}
		if hasSubnets && m.DestsOverlapsPrefixes(subnetRoutes...) {
			return true
		}
		if isExit && m.DestsIsTheInternet() {
			return true
		}
	}

	return false
}

// getNodeMatchers returns cached []matcher.Match for a node's filter rules.
// For autogroup:self policies, this combines cached global matchers (built once
// from the ~5000 non-autogroup:self rules) with per-node matchers (built from
// the ~2 autogroup:self rules). This avoids rebuilding matchers for the global
// rules on every node.
// Must be called with pm.mu held.
func (pm *PolicyManager) getNodeMatchers(node types.NodeView) []matcher.Match {
	if cached, ok := pm.perNodeMatcherCache[node.ID()]; ok {
		return cached
	}

	if !pm.usesAutogroupSelf {
		// Non-autogroup:self: all nodes share the same matchers (pm.matchers).
		// Just return those directly.
		return pm.matchers
	}

	// Build global matchers once from the pre-compiled global rules.
	if pm.globalMatcherCache == nil {
		pm.ensureResolveCacheForCompilation()
		if pm.pol.globalRulesForNode == nil {
			globalRules, err := pm.pol.compileNonAutogroupSelfRules(pm.users, pm.nodes)
			if err == nil {
				pm.pol.globalRulesForNode = globalRules
			}
		}
		pm.globalMatcherCache = matcher.MatchesFromFilterRules(pm.pol.globalRulesForNode)
	}

	// Build per-node matchers from only the autogroup:self ACLs (~2 rules).
	pm.ensureResolveCacheForCompilation()
	selfRules, err := pm.pol.compileAutogroupSelfRulesForNode(pm.users, node, pm.nodes)
	if err != nil {
		// Fall back to global matchers only
		return pm.globalMatcherCache
	}

	var combined []matcher.Match
	if len(selfRules) > 0 {
		selfMatchers := matcher.MatchesFromFilterRules(selfRules)
		combined = make([]matcher.Match, 0, len(pm.globalMatcherCache)+len(selfMatchers))
		combined = append(combined, pm.globalMatcherCache...)
		combined = append(combined, selfMatchers...)
	} else {
		combined = pm.globalMatcherCache
	}

	if pm.perNodeMatcherCache == nil {
		pm.perNodeMatcherCache = make(map[types.NodeID][]matcher.Match)
	}
	pm.perNodeMatcherCache[node.ID()] = combined

	return combined
}

// getPerNodeSrcIndices returns the indices within a node's per-node matcher set
// where srcNode's IPs appear in the source set. Cached per (srcNode, matcherOwner) pair.
// Must be called with pm.mu held.
func (pm *PolicyManager) getPerNodeSrcIndices(srcNode types.NodeView, matcherOwnerID types.NodeID, nodeMatchers []matcher.Match) []int {
	key := perNodeSrcKey{srcNodeID: srcNode.ID(), matcherOwner: matcherOwnerID}
	if cached, ok := pm.perNodeSrcIdxCache[key]; ok {
		return cached
	}

	ips := srcNode.IPs()
	indices := make([]int, 0, 16)
	for i := range nodeMatchers {
		if nodeMatchers[i].SrcsContainsIPs(ips...) {
			indices = append(indices, i)
		}
	}

	if pm.perNodeSrcIdxCache == nil {
		pm.perNodeSrcIdxCache = make(map[perNodeSrcKey][]int)
	}
	pm.perNodeSrcIdxCache[key] = indices

	return indices
}

// ComputeNodePeers computes the list of peers visible to a single node by
// checking it against all provided nodes. This is O(N) per new node instead of
// O(N²) for a full BuildPeerMap. Used by the NodeStore's incremental snapshot
// path when only new nodes are added (no identity changes).
//
// Uses a cached source matcher index to avoid iterating all matchers for each
// node pair. With 14K+ rules but only ~100 relevant per node, this reduces
// IPSet lookups by ~100x.
func (pm *PolicyManager) ComputeNodePeers(
	node types.NodeView,
	allNodes []types.NodeView,
) []types.NodeView {
	if pm == nil {
		return nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.ensureFilterCompiled(); err != nil {
		log.Error().Err(err).Msg("Failed to compile filter rules for ComputeNodePeers")
		return nil
	}

	var peers []types.NodeView

	if !pm.usesAutogroupSelf {
		// Pre-compute which matchers have the new node as a source.
		// Other nodes' source indices are cached across calls.
		nodeSrcIdx := pm.getSrcMatcherIndices(node)

		for _, other := range allNodes {
			if other.ID() == node.ID() {
				continue
			}
			otherSrcIdx := pm.getSrcMatcherIndices(other)
			if canAccessIndexed(pm.matchers, nodeSrcIdx, other) ||
				canAccessIndexed(pm.matchers, otherSrcIdx, node) {
				peers = append(peers, other)
			}
		}
	} else {
		// autogroup:self: use cached per-node matchers with source-index optimization.
		// Each node has its own matcher set (autogroup:self expands differently per user).
		// We cache both the matchers and source indices to avoid repeated compilation
		// and O(matchers) scans on every pair check.
		nodeMatcherList := pm.getNodeMatchers(node)
		if nodeMatcherList == nil {
			return nil
		}
		nodeSrcIdx := pm.getPerNodeSrcIndices(node, node.ID(), nodeMatcherList)

		for _, other := range allNodes {
			if other.ID() == node.ID() {
				continue
			}
			otherMatcherList := pm.getNodeMatchers(other)
			if otherMatcherList == nil {
				continue
			}
			otherSrcIdx := pm.getPerNodeSrcIndices(other, other.ID(), otherMatcherList)

			if canAccessIndexed(nodeMatcherList, nodeSrcIdx, other) ||
				canAccessIndexed(otherMatcherList, otherSrcIdx, node) {
				peers = append(peers, other)
			}
		}
	}

	return peers
}

// compileFilterRulesForNodeLocked returns the unreduced compiled filter rules for a node
// when using autogroup:self. This is used by BuildPeerMap to determine peer relationships.
// For packet filters sent to nodes, use filterForNodeLocked which returns reduced rules.
func (pm *PolicyManager) compileFilterRulesForNodeLocked(node types.NodeView) ([]tailcfg.FilterRule, error) {
	if pm == nil {
		return nil, nil
	}

	// Check if we have cached compiled rules
	if rules, ok := pm.compiledFilterRulesMap[node.ID()]; ok {
		return rules, nil
	}

	// Enable resolve cache and node IP indexes for per-node compilation.
	pm.ensureResolveCacheForCompilation()

	// Compile per-node rules with autogroup:self expanded
	rules, err := pm.pol.compileFilterRulesForNode(pm.users, node, pm.nodes)
	if err != nil {
		return nil, fmt.Errorf("compiling filter rules for node: %w", err)
	}

	// Cache the unreduced compiled rules
	pm.compiledFilterRulesMap[node.ID()] = rules

	return rules, nil
}

// ensureResolveCacheForCompilation sets up the resolve cache and node IP indexes
// on the policy if they aren't already set. Unlike ensureFilterCompiled which
// defers cleanup, these persist until the next filter invalidation cycle so that
// per-node compilations (autogroup:self) benefit from cached lookups across
// multiple compileFilterRulesForNodeLocked calls.
func (pm *PolicyManager) ensureResolveCacheForCompilation() {
	if pm.pol == nil {
		return
	}
	if pm.pol.resolveCache == nil {
		pm.pol.resolveCache = make(map[string]*netipx.IPSet)
	}
	if pm.pol.nodeIPsByUser == nil {
		pm.pol.nodeIPsByUser, pm.pol.nodeIPsByTag = buildNodeIPIndexes(pm.nodes)
	}
}

// clearResolveCache tears down the persistent resolve cache and node IP indexes.
// Called when users or nodes change in ways that invalidate cached resolutions.
func (pm *PolicyManager) clearResolveCache() {
	if pm.pol == nil {
		return
	}
	pm.pol.resolveCache = nil
	pm.pol.nodeIPsByUser = nil
	pm.pol.nodeIPsByTag = nil
	pm.pol.globalRulesForNode = nil
	matcher.ResetIPSetCache()
}

// filterForNodeLocked returns the filter rules for a specific node, already reduced
// to only include rules relevant to that node.
// This is a lock-free version of FilterForNode for internal use when the lock is already held.
// BuildPeerMap already holds the lock, so we need a version that doesn't re-acquire it.
func (pm *PolicyManager) filterForNodeLocked(node types.NodeView) ([]tailcfg.FilterRule, error) {
	if pm == nil {
		return nil, nil
	}

	if !pm.usesAutogroupSelf {
		// For global filters, reduce to only rules relevant to this node.
		// Cache the reduced filter per node for efficiency.
		if rules, ok := pm.filterRulesMap[node.ID()]; ok {
			return rules, nil
		}

		// Use policyutil.ReduceFilterRules for global filter reduction.
		reducedFilter := policyutil.ReduceFilterRules(node, pm.filter)

		pm.filterRulesMap[node.ID()] = reducedFilter

		return reducedFilter, nil
	}

	// For autogroup:self, compile per-node rules then reduce them.
	// Check if we have cached reduced rules for this node.
	if rules, ok := pm.filterRulesMap[node.ID()]; ok {
		return rules, nil
	}

	// Get unreduced compiled rules
	compiledRules, err := pm.compileFilterRulesForNodeLocked(node)
	if err != nil {
		return nil, err
	}

	// Reduce the compiled rules to only destinations relevant to this node
	reducedFilter := policyutil.ReduceFilterRules(node, compiledRules)

	// Cache the reduced filter
	pm.filterRulesMap[node.ID()] = reducedFilter

	return reducedFilter, nil
}

// FilterForNode returns the filter rules for a specific node, already reduced
// to only include rules relevant to that node.
// If the policy uses autogroup:self, this returns node-specific compiled rules.
// Otherwise, it returns the global filter reduced for this node.
func (pm *PolicyManager) FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.ensureFilterCompiled(); err != nil {
		return nil, err
	}

	return pm.filterForNodeLocked(node)
}

// MatchersForNode returns the matchers for peer relationship determination for a specific node.
// These are UNREDUCED matchers - they include all rules where the node could be either source or destination.
// This is different from FilterForNode which returns REDUCED rules for packet filtering.
//
// For global policies: returns the global matchers (same for all nodes)
// For autogroup:self: returns node-specific matchers from unreduced compiled rules.
func (pm *PolicyManager) MatchersForNode(node types.NodeView) ([]matcher.Match, error) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if err := pm.ensureFilterCompiled(); err != nil {
		return nil, err
	}

	// For global policies, return the shared global matchers
	if !pm.usesAutogroupSelf {
		return pm.matchers, nil
	}

	// For autogroup:self, get unreduced compiled rules and create matchers
	compiledRules, err := pm.compileFilterRulesForNodeLocked(node)
	if err != nil {
		return nil, err
	}

	// Create matchers from unreduced rules for peer relationship determination
	return matcher.MatchesFromFilterRules(compiledRules), nil
}

// SetUsers updates the users in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetUsers(users []types.User) (bool, error) {
	if pm == nil {
		return false, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Short-circuit: if users haven't changed, skip the expensive updateLocked.
	// During bulk registration the same user list is passed on every node add,
	// but updateLocked recompiles all filter rules O(rules * nodes) each time.
	newHash := deephash.Hash(&users)
	if newHash == pm.usersHash {
		return false, nil
	}
	pm.usersHash = newHash

	pm.users = users

	// Clear SSH policy map when users change to force SSH policy recomputation
	// This ensures that if SSH policy compilation previously failed due to missing users,
	// it will be retried with the new user list
	clear(pm.sshPolicyMap)
	pm.clearResolveCache()

	changed, err := pm.updateLocked()
	if err != nil {
		return false, err
	}

	// If SSH policies exist, force a policy change when users are updated
	// This ensures nodes get updated SSH policies even if other policy hashes didn't change
	if pm.pol != nil && pm.pol.SSHs != nil && len(pm.pol.SSHs) > 0 {
		return true, nil
	}

	return changed, nil
}

// SetNodes updates the nodes in the policy manager.
// Returns (changed, identityChanged, error):
//   - changed: true if the node list differs from the previous one
//   - identityChanged: true if an existing node's identity (tags, user, IPs) changed,
//     as opposed to just new nodes being added. This helps callers decide whether
//     a full peer map rebuild is needed (identity change) vs incremental update (addition).
func (pm *PolicyManager) SetNodes(nodes views.Slice[types.NodeView]) (bool, bool, []types.NodeID, error) {
	if pm == nil {
		return false, false, nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	identityChanged := pm.nodesHaveIdentityChanges(nodes)
	countChanged := pm.nodes.Len() != nodes.Len()

	// Track which nodes are new (added since last SetNodes).
	oldNodeSet := make(map[types.NodeID]struct{}, pm.nodes.Len())
	for _, n := range pm.nodes.All() {
		oldNodeSet[n.ID()] = struct{}{}
	}
	var newNodeIDs []types.NodeID
	for _, n := range nodes.All() {
		if _, exists := oldNodeSet[n.ID()]; !exists {
			newNodeIDs = append(newNodeIDs, n.ID())
		}
	}

	// Invalidate cache entries for nodes that changed.
	pm.invalidateNodeCache(nodes)

	pm.nodes = nodes

	if !identityChanged && !countChanged {
		return false, false, nil, nil
	}

	if identityChanged {
		// Existing node properties changed — must recompile filters eagerly
		// because matchers need to reflect the new identity immediately.
		_, err := pm.updateLocked()
		if err != nil {
			return false, false, nil, err
		}
	} else {
		// Only new nodes were added. Defer the expensive filter compilation
		// (O(rules * nodes)) until filters are actually accessed. Eagerly resolve
		// tag owners and auto-approvers since they're needed during registration
		// for route approval.
		pm.filterDirty = true

		// Clear per-node caches since the node list changed
		clear(pm.sshPolicyMap)
		clear(pm.compiledFilterRulesMap)
		clear(pm.filterRulesMap)
		pm.perNodeMatcherCache = nil
		pm.perNodeSrcIdxCache = nil
		pm.globalMatcherCache = nil
		pm.clearResolveCache()

		// Eagerly resolve tag owners (needed for NodeCanHaveTag during registration)
		tagMap, err := resolveTagOwners(pm.pol, pm.users, pm.nodes)
		if err != nil {
			return false, false, nil, fmt.Errorf("resolving tag owners: %w", err)
		}
		pm.tagOwnerMap = tagMap
		pm.tagOwnerMapHash = deephash.Hash(&tagMap)

		// Eagerly resolve auto-approvers (needed for route approval during registration)
		autoMap, exitSet, err := resolveAutoApprovers(pm.pol, pm.users, pm.nodes)
		if err != nil {
			return false, false, nil, fmt.Errorf("resolving auto approvers: %w", err)
		}
		pm.autoApproveMap = autoMap
		pm.autoApproveMapHash = deephash.Hash(&autoMap)
		pm.exitSet = exitSet
		pm.exitSetHash = deephash.Hash(&exitSet)
	}

	return true, identityChanged, newNodeIDs, nil
}

// nodesHaveIdentityChanges checks if any existing node changed its policy-affecting
// properties (tags, user, IPs, routes). Returns false for pure additions/removals.
func (pm *PolicyManager) nodesHaveIdentityChanges(newNodes views.Slice[types.NodeView]) bool {
	oldNodes := make(map[types.NodeID]types.NodeView, pm.nodes.Len())
	for _, node := range pm.nodes.All() {
		oldNodes[node.ID()] = node
	}

	for _, newNode := range newNodes.All() {
		oldNode, exists := oldNodes[newNode.ID()]
		if !exists {
			continue // new node, not an identity change
		}

		if newNode.HasPolicyChange(oldNode) {
			return true
		}
	}

	return false
}

// NodeCanHaveTag checks if a node can have the specified tag during client-initiated
// registration or reauth flows (e.g., tailscale up --advertise-tags).
//
// This function is NOT used by the admin API's SetNodeTags - admins can set any
// existing tag on any node by calling State.SetNodeTags directly, which bypasses
// this authorization check.
func (pm *PolicyManager) NodeCanHaveTag(node types.NodeView, tag string) bool {
	if pm == nil || pm.pol == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Check if tag exists in policy
	owners, exists := pm.pol.TagOwners[Tag(tag)]
	if !exists {
		return false
	}

	// Check if node's owner can assign this tag via the pre-resolved tagOwnerMap.
	// The tagOwnerMap contains IP sets built from resolving TagOwners entries
	// (usernames/groups) to their nodes' IPs, so checking if the node's IP
	// is in the set answers "does this node's owner own this tag?"
	if ips, ok := pm.tagOwnerMap[Tag(tag)]; ok {
		if slices.ContainsFunc(node.IPs(), ips.Contains) {
			return true
		}
	}

	// For new nodes being registered, their IP may not yet be in the tagOwnerMap.
	// Fall back to checking the node's user directly against the TagOwners.
	// This handles the case where a user registers a new node with --advertise-tags.
	if node.User().Valid() {
		for _, owner := range owners {
			if pm.userMatchesOwner(node.User(), owner) {
				return true
			}
		}
	}

	return false
}

// userMatchesOwner checks if a user matches a tag owner entry.
// This is used as a fallback when the node's IP is not in the tagOwnerMap.
func (pm *PolicyManager) userMatchesOwner(user types.UserView, owner Owner) bool {
	switch o := owner.(type) {
	case *Username:
		if o == nil {
			return false
		}
		// Resolve the username to find the user it refers to
		resolvedUser, err := o.resolveUser(pm.users)
		if err != nil {
			return false
		}

		return user.ID() == resolvedUser.ID

	case *Group:
		if o == nil || pm.pol == nil {
			return false
		}
		// Resolve the group to get usernames
		usernames, ok := pm.pol.Groups[*o]
		if !ok {
			return false
		}
		// Check if the user matches any username in the group
		for _, uname := range usernames {
			resolvedUser, err := uname.resolveUser(pm.users)
			if err != nil {
				continue
			}

			if user.ID() == resolvedUser.ID {
				return true
			}
		}

		return false

	default:
		return false
	}
}

// TagExists reports whether the given tag is defined in the policy.
func (pm *PolicyManager) TagExists(tag string) bool {
	if pm == nil || pm.pol == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	_, exists := pm.pol.TagOwners[Tag(tag)]

	return exists
}

func (pm *PolicyManager) NodeCanApproveRoute(node types.NodeView, route netip.Prefix) bool {
	if pm == nil {
		return false
	}

	// If the route to-be-approved is an exit route, then we need to check
	// if the node is in allowed to approve it. This is treated differently
	// than the auto-approvers, as the auto-approvers are not allowed to
	// approve the whole /0 range.
	// However, an auto approver might be /0, meaning that they can approve
	// all routes available, just not exit nodes.
	if tsaddr.IsExitRoute(route) {
		if pm.exitSet == nil {
			return false
		}

		if slices.ContainsFunc(node.IPs(), pm.exitSet.Contains) {
			return true
		}

		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// The fast path is that a node requests to approve a prefix
	// where there is an exact entry, e.g. 10.0.0.0/8, then
	// check and return quickly
	if approvers, ok := pm.autoApproveMap[route]; ok {
		canApprove := slices.ContainsFunc(node.IPs(), approvers.Contains)
		if canApprove {
			return true
		}
	}

	// The slow path is that the node tries to approve
	// 10.0.10.0/24, which is a part of 10.0.0.0/8, then we
	// cannot just lookup in the prefix map and have to check
	// if there is a "parent" prefix available.
	for prefix, approveAddrs := range pm.autoApproveMap {
		// Check if prefix is larger (so containing) and then overlaps
		// the route to see if the node can approve a subset of an autoapprover
		if prefix.Bits() <= route.Bits() && prefix.Overlaps(route) {
			canApprove := slices.ContainsFunc(node.IPs(), approveAddrs.Contains)
			if canApprove {
				return true
			}
		}
	}

	return false
}

func (pm *PolicyManager) Version() int {
	return 2
}

func (pm *PolicyManager) DebugString() string {
	if pm == nil {
		return "PolicyManager is not setup"
	}

	var sb strings.Builder

	fmt.Fprintf(&sb, "PolicyManager (v%d):\n\n", pm.Version())

	sb.WriteString("\n\n")

	if pm.pol != nil {
		pol, err := json.MarshalIndent(pm.pol, "", "  ")
		if err == nil {
			sb.WriteString("Policy:\n")
			sb.Write(pol)
			sb.WriteString("\n\n")
		}
	}

	fmt.Fprintf(&sb, "AutoApprover (%d):\n", len(pm.autoApproveMap))

	for prefix, approveAddrs := range pm.autoApproveMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range approveAddrs.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	fmt.Fprintf(&sb, "TagOwner (%d):\n", len(pm.tagOwnerMap))

	for prefix, tagOwners := range pm.tagOwnerMap {
		fmt.Fprintf(&sb, "\t%s:\n", prefix)

		for _, iprange := range tagOwners.Ranges() {
			fmt.Fprintf(&sb, "\t\t%s\n", iprange)
		}
	}

	sb.WriteString("\n\n")

	if pm.filter != nil {
		filter, err := json.MarshalIndent(pm.filter, "", "  ")
		if err == nil {
			sb.WriteString("Compiled filter:\n")
			sb.Write(filter)
			sb.WriteString("\n\n")
		}
	}

	sb.WriteString("\n\n")
	sb.WriteString("Matchers:\n")
	sb.WriteString("an internal structure used to filter nodes and routes\n")

	for _, match := range pm.matchers {
		sb.WriteString(match.DebugString())
		sb.WriteString("\n")
	}

	sb.WriteString("\n\n")
	sb.WriteString("Nodes:\n")

	for _, node := range pm.nodes.All() {
		sb.WriteString(node.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// invalidateAutogroupSelfCache intelligently clears only the cache entries that need to be
// invalidated when using autogroup:self policies. This is much more efficient than clearing
// the entire cache.
func (pm *PolicyManager) invalidateAutogroupSelfCache(oldNodes, newNodes views.Slice[types.NodeView]) {
	// Build maps for efficient lookup
	oldNodeMap := make(map[types.NodeID]types.NodeView)
	for _, node := range oldNodes.All() {
		oldNodeMap[node.ID()] = node
	}

	newNodeMap := make(map[types.NodeID]types.NodeView)
	for _, node := range newNodes.All() {
		newNodeMap[node.ID()] = node
	}

	// Track which users are affected by changes.
	// Tagged nodes don't participate in autogroup:self (identity is tag-based),
	// so we skip them when collecting affected users, except when tag status changes
	// (which affects the user's device set).
	affectedUsers := make(map[uint]struct{})

	// Check for removed nodes (only non-tagged nodes affect autogroup:self)
	for nodeID, oldNode := range oldNodeMap {
		if _, exists := newNodeMap[nodeID]; !exists {
			if !oldNode.IsTagged() {
				affectedUsers[oldNode.User().ID()] = struct{}{}
			}
		}
	}

	// Check for added nodes (only non-tagged nodes affect autogroup:self)
	for nodeID, newNode := range newNodeMap {
		if _, exists := oldNodeMap[nodeID]; !exists {
			if !newNode.IsTagged() {
				affectedUsers[newNode.User().ID()] = struct{}{}
			}
		}
	}

	// Check for modified nodes (user changes, tag changes, IP changes)
	for nodeID, newNode := range newNodeMap {
		if oldNode, exists := oldNodeMap[nodeID]; exists {
			// Check if tag status changed — this affects the user's autogroup:self device set.
			// Use the non-tagged version to get the user ID safely.
			if oldNode.IsTagged() != newNode.IsTagged() {
				if !oldNode.IsTagged() {
					// Was untagged, now tagged: user lost a device
					affectedUsers[oldNode.User().ID()] = struct{}{}
				} else {
					// Was tagged, now untagged: user gained a device
					affectedUsers[newNode.User().ID()] = struct{}{}
				}

				continue
			}

			// Skip tagged nodes for remaining checks — they don't participate in autogroup:self
			if newNode.IsTagged() {
				continue
			}

			// Check if user changed (both versions are non-tagged here)
			if oldNode.User().ID() != newNode.User().ID() {
				affectedUsers[oldNode.User().ID()] = struct{}{}
				affectedUsers[newNode.User().ID()] = struct{}{}
			}

			// Check if IPs changed (simple check - could be more sophisticated)
			oldIPs := oldNode.IPs()

			newIPs := newNode.IPs()
			if len(oldIPs) != len(newIPs) {
				affectedUsers[newNode.User().ID()] = struct{}{}
			} else {
				// Check if any IPs are different
				for i, oldIP := range oldIPs {
					if i >= len(newIPs) || oldIP != newIPs[i] {
						affectedUsers[newNode.User().ID()] = struct{}{}
						break
					}
				}
			}
		}
	}

	// Clear cache entries for affected users only.
	// For autogroup:self, we need to clear all nodes belonging to affected users
	// because autogroup:self rules depend on the entire user's device set.
	for nodeID := range pm.filterRulesMap {
		// Find the user for this cached node
		var nodeUserID uint

		found := false

		// Check in new nodes first
		for _, node := range newNodes.All() {
			if node.ID() == nodeID {
				// Tagged nodes don't participate in autogroup:self,
				// so their cache doesn't need user-based invalidation.
				if node.IsTagged() {
					found = true
					break
				}

				nodeUserID = node.User().ID()
				found = true

				break
			}
		}

		// If not found in new nodes, check old nodes
		if !found {
			for _, node := range oldNodes.All() {
				if node.ID() == nodeID {
					if node.IsTagged() {
						found = true
						break
					}

					nodeUserID = node.User().ID()
					found = true

					break
				}
			}
		}

		// If we found the user and they're affected, clear this cache entry
		if found {
			if _, affected := affectedUsers[nodeUserID]; affected {
				delete(pm.compiledFilterRulesMap, nodeID)
				delete(pm.filterRulesMap, nodeID)
				delete(pm.perNodeMatcherCache, nodeID)
			}
		} else {
			// Node not found in either old or new list, clear it
			delete(pm.compiledFilterRulesMap, nodeID)
			delete(pm.filterRulesMap, nodeID)
			delete(pm.perNodeMatcherCache, nodeID)
		}
	}

	// Clear per-node source index cache entries involving affected nodes.
	// Rather than iterating the entire cache to find entries involving affected users,
	// clear the whole per-node src index cache when any user is affected. This is safe
	// because the cache is rebuilt lazily and only used during ComputeNodePeers.
	if len(affectedUsers) > 0 {
		pm.perNodeSrcIdxCache = nil
		// Clear resolve cache since user's node sets changed, invalidating
		// Username.Resolve and Group.Resolve cached IP sets.
		pm.clearResolveCache()
	}

	if len(affectedUsers) > 0 {
		log.Debug().
			Int("affected_users", len(affectedUsers)).
			Int("remaining_cache_entries", len(pm.filterRulesMap)).
			Msg("Selectively cleared autogroup:self cache for affected users")
	}
}

// invalidateNodeCache invalidates cache entries based on what changed.
func (pm *PolicyManager) invalidateNodeCache(newNodes views.Slice[types.NodeView]) {
	if pm.usesAutogroupSelf {
		// For autogroup:self, a node's filter depends on its peers (same user).
		// When any node in a user changes, all nodes for that user need invalidation.
		pm.invalidateAutogroupSelfCache(pm.nodes, newNodes)
	} else {
		// For global policies, a node's filter depends only on its own properties.
		// Only invalidate nodes whose properties actually changed.
		pm.invalidateGlobalPolicyCache(newNodes)
	}
}

// invalidateGlobalPolicyCache invalidates only nodes whose properties affecting
// ReduceFilterRules changed. For global policies, each node's filter is independent.
func (pm *PolicyManager) invalidateGlobalPolicyCache(newNodes views.Slice[types.NodeView]) {
	oldNodeMap := make(map[types.NodeID]types.NodeView)
	for _, node := range pm.nodes.All() {
		oldNodeMap[node.ID()] = node
	}

	newNodeMap := make(map[types.NodeID]types.NodeView)
	for _, node := range newNodes.All() {
		newNodeMap[node.ID()] = node
	}

	// Invalidate nodes whose properties changed
	for nodeID, newNode := range newNodeMap {
		oldNode, existed := oldNodeMap[nodeID]
		if !existed {
			// New node - no cache entry yet, will be lazily calculated
			continue
		}

		if newNode.HasNetworkChanges(oldNode) {
			delete(pm.filterRulesMap, nodeID)
		}
	}

	// Remove deleted nodes from cache
	for nodeID := range pm.filterRulesMap {
		if _, exists := newNodeMap[nodeID]; !exists {
			delete(pm.filterRulesMap, nodeID)
		}
	}
}

// flattenTags flattens the TagOwners by resolving nested tags and detecting cycles.
// It will return a Owners list where all the Tag types have been resolved to their underlying Owners.
func flattenTags(tagOwners TagOwners, tag Tag, visiting map[Tag]bool, chain []Tag) (Owners, error) {
	if visiting[tag] {
		cycleStart := 0

		for i, t := range chain {
			if t == tag {
				cycleStart = i
				break
			}
		}

		cycleTags := make([]string, len(chain[cycleStart:]))
		for i, t := range chain[cycleStart:] {
			cycleTags[i] = string(t)
		}

		slices.Sort(cycleTags)

		return nil, fmt.Errorf("%w: %s", ErrCircularReference, strings.Join(cycleTags, " -> "))
	}

	visiting[tag] = true

	chain = append(chain, tag)
	defer delete(visiting, tag)

	var result Owners

	for _, owner := range tagOwners[tag] {
		switch o := owner.(type) {
		case *Tag:
			if _, ok := tagOwners[*o]; !ok {
				return nil, fmt.Errorf("tag %q %w %q", tag, ErrUndefinedTagReference, *o)
			}

			nested, err := flattenTags(tagOwners, *o, visiting, chain)
			if err != nil {
				return nil, err
			}

			result = append(result, nested...)
		default:
			result = append(result, owner)
		}
	}

	return result, nil
}

// flattenTagOwners flattens all TagOwners by resolving nested tags and detecting cycles.
// It will return a new TagOwners map where all the Tag types have been resolved to their underlying Owners.
func flattenTagOwners(tagOwners TagOwners) (TagOwners, error) {
	ret := make(TagOwners)

	for tag := range tagOwners {
		flattened, err := flattenTags(tagOwners, tag, make(map[Tag]bool), nil)
		if err != nil {
			return nil, err
		}

		slices.SortFunc(flattened, func(a, b Owner) int {
			return cmp.Compare(a.String(), b.String())
		})
		ret[tag] = slices.CompactFunc(flattened, func(a, b Owner) bool {
			return a.String() == b.String()
		})
	}

	return ret, nil
}

// resolveTagOwners resolves the TagOwners to a map of Tag to netipx.IPSet.
// The resulting map can be used to quickly look up the IPSet for a given Tag.
// It is intended for internal use in a PolicyManager.
func resolveTagOwners(p *Policy, users types.Users, nodes views.Slice[types.NodeView]) (map[Tag]*netipx.IPSet, error) {
	if p == nil {
		return make(map[Tag]*netipx.IPSet), nil
	}

	if len(p.TagOwners) == 0 {
		return make(map[Tag]*netipx.IPSet), nil
	}

	ret := make(map[Tag]*netipx.IPSet)

	tagOwners, err := flattenTagOwners(p.TagOwners)
	if err != nil {
		return nil, err
	}

	for tag, owners := range tagOwners {
		var ips netipx.IPSetBuilder

		for _, owner := range owners {
			switch o := owner.(type) {
			case *Tag:
				// After flattening, Tag types should not appear in the owners list.
				// If they do, skip them as they represent already-resolved references.

			case Alias:
				// If it does not resolve, that means the tag is not associated with any IP addresses.
				resolved, _ := o.Resolve(p, users, nodes)
				ips.AddSet(resolved)

			default:
				// Should never happen - after flattening, all owners should be Alias types
				return nil, fmt.Errorf("%w: %v", ErrInvalidTagOwner, owner)
			}
		}

		ipSet, err := ips.IPSet()
		if err != nil {
			return nil, err
		}

		ret[tag] = ipSet
	}

	return ret, nil
}
