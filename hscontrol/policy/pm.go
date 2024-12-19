package policy

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/util/deephash"
)

type PolicyManager interface {
	Filter() []tailcfg.FilterRule
	SSHPolicy(*types.Node) (*tailcfg.SSHPolicy, error)
	Tags(*types.Node) []string
	ApproversForRoute(netip.Prefix) []string
	ExpandAlias(string) (*netipx.IPSet, error)
	SetPolicy([]byte) (bool, error)
	SetUsers(users []types.User) (bool, error)
	SetNodes(nodes types.Nodes) (bool, error)
}

func NewPolicyManagerFromPath(path string, users []types.User, nodes types.Nodes) (PolicyManager, error) {
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

func NewPolicyManager(polB []byte, users []types.User, nodes types.Nodes) (PolicyManager, error) {
	var pol *ACLPolicy
	var err error
	if polB != nil && len(polB) > 0 {
		pol, err = LoadACLPolicyFromBytes(polB)
		if err != nil {
			return nil, fmt.Errorf("parsing policy: %w", err)
		}
	}

	pm := PolicyManagerV1{
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

func NewPolicyManagerForTest(pol *ACLPolicy, users []types.User, nodes types.Nodes) (PolicyManager, error) {
	pm := PolicyManagerV1{
		pol:   pol,
		users: users,
		nodes: nodes,
	}

	_, err := pm.updateLocked()
	if err != nil {
		return nil, err
	}

	return &pm, nil
}

type PolicyManagerV1 struct {
	mu  sync.Mutex
	pol *ACLPolicy

	users []types.User
	nodes types.Nodes

	filterHash deephash.Sum
	filter     []tailcfg.FilterRule
}

// updateLocked updates the filter rules based on the current policy and nodes.
// It must be called with the lock held.
func (pm *PolicyManagerV1) updateLocked() (bool, error) {
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

func (pm *PolicyManagerV1) Filter() []tailcfg.FilterRule {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.filter
}

func (pm *PolicyManagerV1) SSHPolicy(node *types.Node) (*tailcfg.SSHPolicy, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	return pm.pol.CompileSSHPolicy(node, pm.users, pm.nodes)
}

func (pm *PolicyManagerV1) SetPolicy(polB []byte) (bool, error) {
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
func (pm *PolicyManagerV1) SetUsers(users []types.User) (bool, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.users = users
	return pm.updateLocked()
}

// SetNodes updates the nodes in the policy manager and updates the filter rules.
func (pm *PolicyManagerV1) SetNodes(nodes types.Nodes) (bool, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.nodes = nodes
	return pm.updateLocked()
}

func (pm *PolicyManagerV1) Tags(node *types.Node) []string {
	if pm == nil {
		return nil
	}

	tags, invalid := pm.pol.TagsOfNode(pm.users, node)
	log.Debug().Strs("authorised_tags", tags).Strs("unauthorised_tags", invalid).Uint64("node.id", node.ID.Uint64()).Msg("tags provided by policy")
	return tags
}

func (pm *PolicyManagerV1) ApproversForRoute(route netip.Prefix) []string {
	// TODO(kradalby): This can be a parse error of the address in the policy,
	// in the new policy this will be typed and not a problem, in this policy
	// we will just return empty list
	if pm.pol == nil {
		return nil
	}
	approvers, _ := pm.pol.AutoApprovers.GetRouteApprovers(route)
	return approvers
}

func (pm *PolicyManagerV1) ExpandAlias(alias string) (*netipx.IPSet, error) {
	ips, err := pm.pol.ExpandAlias(pm.nodes, pm.users, alias)
	if err != nil {
		return nil, err
	}
	return ips, nil
}
