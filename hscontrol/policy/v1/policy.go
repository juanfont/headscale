package v1

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/util/deephash"
)

func NewPolicyManagerFromPath(path string, users []types.User, nodes types.Nodes) (*PolicyManager, error) {
	policyFile, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer policyFile.Close()

	policyBytes, err := io.ReadAll(policyFile)
	if err != nil {
		return nil, err
	}

	return NewPolicyManager(policyBytes, users, nodes)
}

func NewPolicyManager(polB []byte, users []types.User, nodes types.Nodes) (*PolicyManager, error) {
	var pol *ACLPolicy
	var err error
	if polB != nil && len(polB) > 0 {
		pol, err = LoadACLPolicyFromBytes(polB)
		if err != nil {
			return nil, fmt.Errorf("parsing policy: %w", err)
		}
	}

	pm := PolicyManager{
		pol:   pol,
		users: users,
		nodes: nodes,
	}

	_, err = pm.updateLocked()
	if err != nil {
		return nil, err
	}

	return &pm, nil
}

type PolicyManager struct {
	mu  sync.Mutex
	pol *ACLPolicy

	users []types.User
	nodes types.Nodes

	filterHash deephash.Sum
	filter     []tailcfg.FilterRule
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

func (pm *PolicyManager) Filter() []tailcfg.FilterRule {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.filter
}

func (pm *PolicyManager) SSHPolicy(node *types.Node) (*tailcfg.SSHPolicy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.pol.CompileSSHPolicy(node, pm.users, pm.nodes)
}

func (pm *PolicyManager) SetPolicy(polB []byte) (bool, error) {
	if len(polB) == 0 {
		return false, nil
	}

	pol, err := LoadACLPolicyFromBytes(polB)
	if err != nil {
		return false, fmt.Errorf("parsing policy: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.pol = pol

	return pm.updateLocked()
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
	if pm == nil || pm.pol == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	tags, invalid := pm.pol.TagsOfNode(pm.users, node)
	log.Debug().Strs("authorised_tags", tags).Strs("unauthorised_tags", invalid).Uint64("node.id", node.ID.Uint64()).Msg("tags provided by policy")

	for _, t := range tags {
		if t == tag {
			return true
		}
	}

	return false
}

func (pm *PolicyManager) NodeCanApproveRoute(node *types.Node, route netip.Prefix) bool {
	if pm == nil || pm.pol == nil {
		return false
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	approvers, _ := pm.pol.AutoApprovers.GetRouteApprovers(route)

	for _, approvedAlias := range approvers {
		if approvedAlias == node.User.Username() {
			return true
		} else {
			ips, err := pm.pol.ExpandAlias(pm.nodes, pm.users, approvedAlias)
			if err != nil {
				return false
			}

			// approvedIPs should contain all of node's IPs if it matches the rule, so check for first
			if ips.Contains(*node.IPv4) {
				return true
			}
		}
	}
	return false
}

func (pm *PolicyManager) Version() int {
	return 1
}

func (pm *PolicyManager) DebugString() string {
	return "not implemented for v1"
}
