package policyv2

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
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

	// TODO(kradalby): Implement SSH policy
	sshPolicy *tailcfg.SSHPolicy
}

// NewPolicyManager creates a new PolicyManager from a policy file and a list of users and nodes.
// It returns an error if the policy file is invalid.
// The policy manager will update the filter rules based on the users and nodes.
func NewPolicyManager(b []byte, users []types.User, nodes types.Nodes) (policy.PolicyManager, error) {
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

func (pm *PolicyManager) Tags(node *types.Node) []string {
	// if pm == nil {
	// 	return nil
	// }

	// tags, invalid := pm.pol.TagsOfNode(pm.users, node)
	// log.Debug().Strs("authorised_tags", tags).Strs("unauthorised_tags", invalid).Uint64("node.id", node.ID.Uint64()).Msg("tags provided by policy")
	// return tags

	// TODO(kradalby): Implement this or ideally, or potentially make it unnecessary.
	// It is used to determine the tags of the nodes at mapresponse time.
	// And to validate that they are allowed to have the tags they have in gRPC.
	// We might be able to do this when the node request set them so we at least dont have
	// check it everytime we use the tags (like in filter checks or mapresponse)
	return []string{}
}

func (pm *PolicyManager) ApproversForRoute(route netip.Prefix) []string {
	// TODO(kradalby): This can be a parse error of the address in the policy,
	// in the new policy this will be typed and not a problem, in this policy
	// we will just return empty list
	// if pm.pol == nil {
	// 	return nil
	// }
	// approvers, _ := pm.pol.AutoApprovers.GetRouteApprovers(route)
	// return approvers

	// TODO(kradalby): Implement this or ideally, make it unnecessary.
	// It is used in the routes to determine if they can auto approve or not.
	return nil
}

func (pm *PolicyManager) ExpandAlias(alias string) (*netipx.IPSet, error) {
	// ips, err := pm.pol.ExpandAlias(pm.nodes, pm.users, alias)
	// if err != nil {
	// 	return nil, err
	// }
	// return ips, nil

	// TODO(kradalby): Implement this or ideally, make it unnecessary.
	// It is used in the routes to determine if they can auto approve or not.
	var s netipx.IPSetBuilder
	return s.IPSet()
}
