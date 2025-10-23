package v2

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

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
	// Clear the SSH policy map to ensure it's recalculated with the new policy.
	// TODO(kradalby): This could potentially be optimized by only clearing the
	// policies for nodes that have changed. Particularly if the only difference is
	// that nodes has been added or removed.
	clear(pm.sshPolicyMap)
	clear(pm.compiledFilterRulesMap)
	clear(pm.filterRulesMap)

	// Check if policy uses autogroup:self
	pm.usesAutogroupSelf = pm.pol.usesAutogroupSelf()

	var filter []tailcfg.FilterRule

	var err error

	// Standard compilation for all policies
	filter, err = pm.pol.compileFilterRules(pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("compiling filter rules: %w", err)
	}

	filterHash := deephash.Hash(&filter)
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

	// If neither of the calculated values changed, no need to update nodes
	if !filterChanged && !tagOwnerChanged && !autoApproveChanged && !exitSetChanged {
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

func (pm *PolicyManager) SSHPolicy(node types.NodeView) (*tailcfg.SSHPolicy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if sshPol, ok := pm.sshPolicyMap[node.ID()]; ok {
		return sshPol, nil
	}

	sshPol, err := pm.pol.compileSSHPolicy(pm.users, node, pm.nodes)
	if err != nil {
		return nil, fmt.Errorf("compiling SSH policy: %w", err)
	}
	pm.sshPolicyMap[node.ID()] = sshPol

	return sshPol, nil
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

// Filter returns the current filter rules for the entire tailnet and the associated matchers.
func (pm *PolicyManager) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

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
		filter, err := pm.compileFilterRulesForNodeLocked(node)
		if err != nil || len(filter) == 0 {
			continue
		}
		nodeMatchers[node.ID()] = matcher.MatchesFromFilterRules(filter)
	}

	// Check each node pair for peer relationships.
	// Start j at i+1 to avoid checking the same pair twice and creating duplicates.
	// We check both directions (i->j and j->i) since ACLs can be asymmetric.
	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]

			// Check if nodeI can access nodeJ
			if hasFilterI && nodeI.CanAccess(matchersI, nodeJ) {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ)
			}

			// Check if nodeJ can access nodeI
			if hasFilterJ && nodeJ.CanAccess(matchersJ, nodeI) {
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI)
			}
		}
	}

	return ret
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

	// Compile per-node rules with autogroup:self expanded
	rules, err := pm.pol.compileFilterRulesForNode(pm.users, node, pm.nodes)
	if err != nil {
		return nil, fmt.Errorf("compiling filter rules for node: %w", err)
	}

	// Cache the unreduced compiled rules
	pm.compiledFilterRulesMap[node.ID()] = rules

	return rules, nil
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

	return pm.filterForNodeLocked(node)
}

// MatchersForNode returns the matchers for peer relationship determination for a specific node.
// These are UNREDUCED matchers - they include all rules where the node could be either source or destination.
// This is different from FilterForNode which returns REDUCED rules for packet filtering.
//
// For global policies: returns the global matchers (same for all nodes)
// For autogroup:self: returns node-specific matchers from unreduced compiled rules
func (pm *PolicyManager) MatchersForNode(node types.NodeView) ([]matcher.Match, error) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

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
	pm.users = users

	// Clear SSH policy map when users change to force SSH policy recomputation
	// This ensures that if SSH policy compilation previously failed due to missing users,
	// it will be retried with the new user list
	clear(pm.sshPolicyMap)

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

// SetNodes updates the nodes in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetNodes(nodes views.Slice[types.NodeView]) (bool, error) {
	if pm == nil {
		return false, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	oldNodeCount := pm.nodes.Len()
	newNodeCount := nodes.Len()

	// Invalidate cache entries for nodes that changed.
	// For autogroup:self: invalidate all nodes belonging to affected users (peer changes).
	// For global policies: invalidate only nodes whose properties changed (IPs, routes).
	pm.invalidateNodeCache(nodes)

	pm.nodes = nodes

	nodesChanged := oldNodeCount != newNodeCount

	// When nodes are added/removed, we must recompile filters because:
	// 1. User/group aliases (like "user1@") resolve to node IPs
	// 2. Filter compilation needs nodes to generate rules
	// 3. Without nodes, filters compile to empty (0 rules)
	//
	// For autogroup:self: return true when nodes change even if the global filter
	// hash didn't change. The global filter is empty for autogroup:self (each node
	// has its own filter), so the hash never changes. But peer relationships DO
	// change when nodes are added/removed, so we must signal this to trigger updates.
	// For global policies: the filter must be recompiled to include the new nodes.
	if nodesChanged {
		// Recompile filter with the new node list
		_, err := pm.updateLocked()
		if err != nil {
			return false, err
		}
		// Always return true when nodes changed, even if filter hash didn't change
		// (can happen with autogroup:self or when nodes are added but don't affect rules)
		return true, nil
	}

	return false, nil
}

func (pm *PolicyManager) NodeCanHaveTag(node types.NodeView, tag string) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if ips, ok := pm.tagOwnerMap[Tag(tag)]; ok {
		if slices.ContainsFunc(node.IPs(), ips.Contains) {
			return true
		}
	}

	return false
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

	// Track which users are affected by changes
	affectedUsers := make(map[uint]struct{})

	// Check for removed nodes
	for nodeID, oldNode := range oldNodeMap {
		if _, exists := newNodeMap[nodeID]; !exists {
			affectedUsers[oldNode.User().ID] = struct{}{}
		}
	}

	// Check for added nodes
	for nodeID, newNode := range newNodeMap {
		if _, exists := oldNodeMap[nodeID]; !exists {
			affectedUsers[newNode.User().ID] = struct{}{}
		}
	}

	// Check for modified nodes (user changes, tag changes, IP changes)
	for nodeID, newNode := range newNodeMap {
		if oldNode, exists := oldNodeMap[nodeID]; exists {
			// Check if user changed
			if oldNode.User().ID != newNode.User().ID {
				affectedUsers[oldNode.User().ID] = struct{}{}
				affectedUsers[newNode.User().ID] = struct{}{}
			}

			// Check if tag status changed
			if oldNode.IsTagged() != newNode.IsTagged() {
				affectedUsers[newNode.User().ID] = struct{}{}
			}

			// Check if IPs changed (simple check - could be more sophisticated)
			oldIPs := oldNode.IPs()
			newIPs := newNode.IPs()
			if len(oldIPs) != len(newIPs) {
				affectedUsers[newNode.User().ID] = struct{}{}
			} else {
				// Check if any IPs are different
				for i, oldIP := range oldIPs {
					if i >= len(newIPs) || oldIP != newIPs[i] {
						affectedUsers[newNode.User().ID] = struct{}{}
						break
					}
				}
			}
		}
	}

	// Clear cache entries for affected users only
	// For autogroup:self, we need to clear all nodes belonging to affected users
	// because autogroup:self rules depend on the entire user's device set
	for nodeID := range pm.filterRulesMap {
		// Find the user for this cached node
		var nodeUserID uint
		found := false

		// Check in new nodes first
		for _, node := range newNodes.All() {
			if node.ID() == nodeID {
				nodeUserID = node.User().ID
				found = true
				break
			}
		}

		// If not found in new nodes, check old nodes
		if !found {
			for _, node := range oldNodes.All() {
				if node.ID() == nodeID {
					nodeUserID = node.User().ID
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
			}
		} else {
			// Node not found in either old or new list, clear it
			delete(pm.compiledFilterRulesMap, nodeID)
			delete(pm.filterRulesMap, nodeID)
		}
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
