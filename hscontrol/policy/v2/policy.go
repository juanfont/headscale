package v2

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/deephash"
)

type PolicyManager struct {
	mu    sync.Mutex
	pol   *Policy
	users []types.User
	nodes types.Nodes

	filterHash deephash.Sum
	filter     []tailcfg.FilterRule

	tagOwnerMapHash deephash.Sum
	tagOwnerMap     map[Tag]*netipx.IPSet

	autoApproveMapHash deephash.Sum
	autoApproveMap     map[netip.Prefix]*netipx.IPSet

	// TODO(kradalby): Implement so we can have a cached version of  this.
	// sshPolicy *tailcfg.SSHPolicy
}

// NewPolicyManager creates a new PolicyManager from a policy file and a list of users and nodes.
// It returns an error if the policy file is invalid.
// The policy manager will update the filter rules based on the users and nodes.
func NewPolicyManager(b []byte, users []types.User, nodes types.Nodes) (*PolicyManager, error) {
	policy, err := policyFromBytes(b)
	if err != nil {
		return nil, fmt.Errorf("parsing policy: %w", err)
	}

	pm := PolicyManager{
		pol:   policy,
		users: users,
		nodes: nodes,
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
	filter, err := pm.pol.CompileFilterRules(pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("compiling filter rules: %w", err)
	}

	filterHash := deephash.Hash(&filter)
	if filterHash == pm.filterHash {
		return false, nil
	}

	pm.filter = filter
	pm.filterHash = filterHash

	autoMap, err := resolveAutoApprovers(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving auto approvers map: %w", err)
	}

	autoApproveMapHash := deephash.Hash(&autoMap)
	if autoApproveMapHash == pm.autoApproveMapHash {
		return false, nil
	}

	pm.autoApproveMap = autoMap
	pm.autoApproveMapHash = autoApproveMapHash

	tagMap, err := resolveTagOwners(pm.pol, pm.users, pm.nodes)
	if err != nil {
		return false, fmt.Errorf("resolving tag owners map: %w", err)
	}

	tagOwnerMapHash := deephash.Hash(&tagMap)
	if tagOwnerMapHash == pm.tagOwnerMapHash {
		return false, nil
	}

	pm.tagOwnerMap = tagMap
	pm.tagOwnerMapHash = tagOwnerMapHash

	return true, nil
}

func (pm *PolicyManager) SSHPolicy(node *types.Node) (*tailcfg.SSHPolicy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.pol.CompileSSHPolicy(pm.users, node, pm.nodes)
}

func (pm *PolicyManager) SetPolicy(polB []byte) (bool, error) {
	if len(polB) == 0 {
		return false, nil
	}

	pol, err := policyFromBytes(polB)
	if err != nil {
		return false, fmt.Errorf("parsing policy: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.pol = pol

	return pm.updateLocked()
}

// Filter returns the current filter rules for the entire tailnet.
func (pm *PolicyManager) Filter() []tailcfg.FilterRule {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.filter
}

// SetUsers updates the users in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetUsers(users []types.User) (bool, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.users = users
	return pm.updateLocked()
}

// SetNodes updates the nodes in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetNodes(nodes types.Nodes) (bool, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.nodes = nodes
	return pm.updateLocked()
}

func (pm *PolicyManager) NodeCanHaveTag(node *types.Node, tag string) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if ips, ok := pm.tagOwnerMap[Tag(tag)]; ok {
		for _, nodeAddr := range node.IPs() {
			if ips.Contains(nodeAddr) {
				return true
			}
		}
	}

	return false
}

func (pm *PolicyManager) NodeCanApproveRoute(node *types.Node, route netip.Prefix) bool {
	if pm == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// The fast path is that a node requests to approve a prefix
	// where there is an exact entry, e.g. 10.0.0.0/8, then
	// check and return quickly
	if _, ok := pm.autoApproveMap[route]; ok {
		for _, nodeAddr := range node.IPs() {
			if pm.autoApproveMap[route].Contains(nodeAddr) {
				return true
			}
		}
	}

	// The slow path is that the node tries to approve
	// 10.0.10.0/24, which is a part of 10.0.0.0/8, then we
	// cannot just lookup in the prefix map and have to check
	// if there is a "parent" prefix available.
	for prefix, approveAddrs := range pm.autoApproveMap {
		// We do not want the exit node entry to approve all
		// sorts of routes. The logic here is that it would be
		// unexpected behaviour to have specific routes approved
		// just because the node is allowed to designate itself as
		// an exit.
		if tsaddr.IsExitRoute(prefix) {
			continue
		}

		// Check if prefix is larger (so containing) and then overlaps
		// the route to see if the node can approve a subset of an autoapprover
		if prefix.Bits() <= route.Bits() && prefix.Overlaps(route) {
			for _, nodeAddr := range node.IPs() {
				if approveAddrs.Contains(nodeAddr) {
					return true
				}
			}
		}
	}

	return false
}

func (pm *PolicyManager) Version() int {
	return 2
}
