package policy

import (
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
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
}
