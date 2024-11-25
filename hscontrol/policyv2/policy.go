package policyv2

import (
	"fmt"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

type PolicyManager struct {
	mu    sync.Mutex
	pol   *Policy
	users []types.User
	nodes types.Nodes

	filter []tailcfg.FilterRule

	// TODO(kradalby): Implement SSH policy
	sshPolicy *tailcfg.SSHPolicy
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

	err = pm.updateLocked()
	if err != nil {
		return nil, err
	}

	return &pm, nil
}

// Filter returns the current filter rules for the entire tailnet.
func (pm *PolicyManager) Filter() []tailcfg.FilterRule {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.filter
}

// updateLocked updates the filter rules based on the current policy and nodes.
// It must be called with the lock held.
func (pm *PolicyManager) updateLocked() error {
	filter, err := pm.pol.CompileFilterRules(pm.users, pm.nodes)
	if err != nil {
		return fmt.Errorf("compiling filter rules: %w", err)
	}

	pm.filter = filter

	return nil
}

// SetUsers updates the users in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetUsers(users []types.User) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.users = users
	return pm.updateLocked()
}

// SetNodes updates the nodes in the policy manager and updates the filter rules.
func (pm *PolicyManager) SetNodes(nodes types.Nodes) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.nodes = nodes
	return pm.updateLocked()
}
