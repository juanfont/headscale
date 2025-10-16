package v2

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
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

	// Lazy map of per-node filter rules (when autogroup:self is used)
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
		pol:               policy,
		users:             users,
		nodes:             nodes,
		sshPolicyMap:      make(map[types.NodeID]*tailcfg.SSHPolicy, nodes.Len()),
		filterRulesMap:    make(map[types.NodeID][]tailcfg.FilterRule, nodes.Len()),
		usesAutogroupSelf: policy.usesAutogroupSelf(),
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

// FilterForNode returns the filter rules for a specific node.
// If the policy uses autogroup:self, this returns node-specific rules for security.
// Otherwise, it returns the global filter rules for efficiency.
func (pm *PolicyManager) FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error) {
	if pm == nil {
		return nil, nil
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.usesAutogroupSelf {
		return pm.filter, nil
	}

	if rules, ok := pm.filterRulesMap[node.ID()]; ok {
		return rules, nil
	}

	rules, err := pm.pol.compileFilterRulesForNode(pm.users, node, pm.nodes)
	if err != nil {
		return nil, fmt.Errorf("compiling filter rules for node: %w", err)
	}

	pm.filterRulesMap[node.ID()] = rules

	return rules, nil
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

	// Clear cache based on what actually changed
	if pm.usesAutogroupSelf {
		// For autogroup:self, we need granular invalidation since rules depend on:
		// - User ownership (node.User().ID)
		// - Tag status (node.IsTagged())
		// - IP addresses (node.IPs())
		// - Node existence (added/removed)
		pm.invalidateAutogroupSelfCache(pm.nodes, nodes)
	} else {
		// For non-autogroup:self policies, we can clear everything
		clear(pm.filterRulesMap)
	}

	pm.nodes = nodes

	return pm.updateLocked()
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
				delete(pm.filterRulesMap, nodeID)
			}
		} else {
			// Node not found in either old or new list, clear it
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
