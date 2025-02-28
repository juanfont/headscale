package policy

import (
	"net/netip"

	policyv1 "github.com/juanfont/headscale/hscontrol/policy/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

var (
	polv2 = envknob.Bool("HEADSCALE_EXPERIMENTAL_POLICY_V2")
)

type PolicyManager interface {
	Filter() []tailcfg.FilterRule
	SSHPolicy(*types.Node) (*tailcfg.SSHPolicy, error)
	SetPolicy([]byte) (bool, error)
	SetUsers(users []types.User) (bool, error)
	SetNodes(nodes types.Nodes) (bool, error)
	// NodeCanHaveTag reports whether the given node can have the given tag.
	NodeCanHaveTag(*types.Node, string) bool

	// NodeCanApproveRoute reports whether the given node can approve the given route.
	NodeCanApproveRoute(*types.Node, netip.Prefix) bool

	Version() int
	DebugString() string
}

// NewPolicyManager returns a new policy manager, the version is determined by
// the environment flag "HEADSCALE_EXPERIMENTAL_POLICY_V2".
func NewPolicyManager(pol []byte, users []types.User, nodes types.Nodes) (PolicyManager, error) {
	var polMan PolicyManager
	var err error
	if polv2 {
		polMan, err = policyv2.NewPolicyManager(pol, users, nodes)
		if err != nil {
			return nil, err
		}
	} else {
		polMan, err = policyv1.NewPolicyManager(pol, users, nodes)
		if err != nil {
			return nil, err
		}
	}

	return polMan, err
}

// PolicyManagersForTest returns all available PostureManagers to be used
// in tests to validate them in tests that try to determine that they
// behave the same.
func PolicyManagersForTest(pol []byte, users []types.User, nodes types.Nodes) ([]PolicyManager, error) {
	var polMans []PolicyManager

	for _, pmf := range PolicyManagerFuncsForTest(pol) {
		pm, err := pmf(users, nodes)
		if err != nil {
			return nil, err
		}
		polMans = append(polMans, pm)
	}

	return polMans, nil
}

func PolicyManagerFuncsForTest(pol []byte) []func([]types.User, types.Nodes) (PolicyManager, error) {
	var polmanFuncs []func([]types.User, types.Nodes) (PolicyManager, error)

	polmanFuncs = append(polmanFuncs, func(u []types.User, n types.Nodes) (PolicyManager, error) {
		return policyv1.NewPolicyManager(pol, u, n)
	})
	polmanFuncs = append(polmanFuncs, func(u []types.User, n types.Nodes) (PolicyManager, error) {
		return policyv2.NewPolicyManager(pol, u, n)
	})

	return polmanFuncs
}
