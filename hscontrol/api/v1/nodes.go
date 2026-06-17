package apiv1

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// RegisterNode registers a node to a user using a registration id, then
// auto-approves its routes.
func (s *Server) RegisterNode(
	_ context.Context,
	params oas.RegisterNodeParams,
) (*oas.RegisterNodeOK, error) {
	registrationID, err := types.AuthIDFromString(params.Key.Or(""))
	if err != nil {
		return nil, badRequest(err.Error())
	}

	user, err := s.state.GetUserByName(params.User.Or(""))
	if err != nil {
		return nil, mapStateError(fmt.Errorf("looking up user: %w", err))
	}

	node, nodeChange, err := s.state.HandleNodeFromAuthPath(
		registrationID,
		types.UserID(user.ID),
		nil,
		util.RegisterMethodCLI,
	)
	if err != nil {
		return nil, mapStateError(err)
	}

	routeChange, err := s.state.AutoApproveRoutes(node)
	if err != nil {
		return nil, internalError("auto approving routes: " + err.Error())
	}

	s.change(nodeChange, routeChange)

	return &oas.RegisterNodeOK{Node: oas.NewOptNode(oasNode(node.Proto()))}, nil
}

// GetNode returns a node by id.
func (s *Server) GetNode(_ context.Context, params oas.GetNodeParams) (*oas.GetNodeOK, error) {
	node, ok := s.state.GetNodeByID(types.NodeID(params.NodeID))
	if !ok {
		return nil, notFound("node not found")
	}

	return &oas.GetNodeOK{Node: oas.NewOptNode(oasNode(node.Proto()))}, nil
}

// SetTags sets the ACL tags of a node, converting it to a tagged node.
func (s *Server) SetTags(
	_ context.Context,
	req *oas.SetTagsReq,
	params oas.SetTagsParams,
) (*oas.SetTagsOK, error) {
	if len(req.Tags) == 0 {
		return nil, badRequest(
			"cannot remove all tags from a node - tagged nodes must have at least one tag",
		)
	}

	for _, tag := range req.Tags {
		err := validateTag(tag)
		if err != nil {
			return nil, badRequest(err.Error())
		}
	}

	_, found := s.state.GetNodeByID(types.NodeID(params.NodeID))
	if !found {
		return nil, notFound("node not found")
	}

	node, nodeChange, err := s.state.SetNodeTags(types.NodeID(params.NodeID), req.Tags)
	if err != nil {
		return nil, badRequest(err.Error())
	}

	s.change(nodeChange)

	return &oas.SetTagsOK{Node: oas.NewOptNode(oasNode(node.Proto()))}, nil
}

// SetApprovedRoutes sets the approved subnet routes of a node, expanding exit
// routes to cover both address families.
func (s *Server) SetApprovedRoutes(
	_ context.Context,
	req *oas.SetApprovedRoutesReq,
	params oas.SetApprovedRoutesParams,
) (*oas.SetApprovedRoutesOK, error) {
	var newApproved []netip.Prefix

	for _, route := range req.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, badRequest("parsing route: " + err.Error())
		}

		// An exit route is annotated by both v4 and v6 default routes.
		if prefix == tsaddr.AllIPv4() || prefix == tsaddr.AllIPv6() {
			newApproved = append(newApproved, tsaddr.AllIPv4(), tsaddr.AllIPv6())
		} else {
			newApproved = append(newApproved, prefix)
		}
	}

	slices.SortFunc(newApproved, netip.Prefix.Compare)
	newApproved = slices.Compact(newApproved)

	node, nodeChange, err := s.state.SetApprovedRoutes(types.NodeID(params.NodeID), newApproved)
	if err != nil {
		return nil, badRequest(err.Error())
	}

	s.change(nodeChange)

	proto := node.Proto()
	// SubnetRoutes carries only the routes actively served from the node.
	proto.SubnetRoutes = util.PrefixesToString(s.state.GetNodePrimaryRoutes(node.ID()))

	return &oas.SetApprovedRoutesOK{Node: oas.NewOptNode(oasNode(proto))}, nil
}

// DeleteNode deletes a node.
func (s *Server) DeleteNode(_ context.Context, params oas.DeleteNodeParams) error {
	node, ok := s.state.GetNodeByID(types.NodeID(params.NodeID))
	if !ok {
		return notFound("node not found")
	}

	nodeChange, err := s.state.DeleteNode(node)
	if err != nil {
		return mapStateError(err)
	}

	s.change(nodeChange)

	return nil
}

// ExpireNode expires a node, or disables its expiry.
func (s *Server) ExpireNode(
	_ context.Context,
	params oas.ExpireNodeParams,
) (*oas.ExpireNodeOK, error) {
	_, hasExpiry := params.Expiry.Get()
	if params.DisableExpiry.Or(false) && hasExpiry {
		return nil, badRequest("cannot set both disable_expiry and expiry")
	}

	var expiry *time.Time

	if !params.DisableExpiry.Or(false) {
		t := time.Now()
		if v, ok := params.Expiry.Get(); ok {
			t = v
		}

		expiry = &t
	}

	node, nodeChange, err := s.state.SetNodeExpiry(types.NodeID(params.NodeID), expiry)
	if err != nil {
		return nil, mapStateError(err)
	}

	s.change(nodeChange)

	return &oas.ExpireNodeOK{Node: oas.NewOptNode(oasNode(node.Proto()))}, nil
}

// RenameNode renames a node.
func (s *Server) RenameNode(
	_ context.Context,
	params oas.RenameNodeParams,
) (*oas.RenameNodeOK, error) {
	node, nodeChange, err := s.state.RenameNode(types.NodeID(params.NodeID), params.NewName)
	if err != nil {
		return nil, mapStateError(err)
	}

	s.change(nodeChange)

	return &oas.RenameNodeOK{Node: oas.NewOptNode(oasNode(node.Proto()))}, nil
}

// ListNodes lists nodes, optionally filtered by user, sorted by id.
func (s *Server) ListNodes(
	_ context.Context,
	params oas.ListNodesParams,
) (*oas.ListNodesOK, error) {
	var nodes views.Slice[types.NodeView]

	if params.User.Or("") != "" {
		user, err := s.state.GetUserByName(params.User.Or(""))
		if err != nil {
			return nil, mapStateError(err)
		}

		nodes = s.state.ListNodesByUser(types.UserID(user.ID))
	} else {
		nodes = s.state.ListNodes()
	}

	return &oas.ListNodesOK{Nodes: s.nodesToOAS(nodes)}, nil
}

// nodesToOAS converts a slice of node views to API nodes, presenting tagged
// nodes as the TaggedDevices user and populating SubnetRoutes with the routes
// actively served from each node.
func (s *Server) nodesToOAS(nodes views.Slice[types.NodeView]) []oas.Node {
	out := make([]oas.Node, nodes.Len())

	for index, node := range nodes.All() {
		proto := node.Proto()

		if node.IsTagged() {
			proto.User = types.TaggedDevices.Proto()
		}

		proto.SubnetRoutes = util.PrefixesToString(
			append(s.state.GetNodePrimaryRoutes(node.ID()), node.ExitRoutes()...),
		)

		out[index] = oasNode(proto)
	}

	slices.SortFunc(out, func(a, b oas.Node) int { return cmp.Compare(a.ID.Or(0), b.ID.Or(0)) })

	return out
}

// BackfillNodeIPs backfills missing IP addresses for all nodes. It must be
// explicitly confirmed.
func (s *Server) BackfillNodeIPs(
	_ context.Context,
	params oas.BackfillNodeIPsParams,
) (*oas.BackfillNodeIPsOK, error) {
	if !params.Confirmed.Or(false) {
		return nil, badRequest("not confirmed, aborting")
	}

	changes, err := s.state.BackfillNodeIPs()
	if err != nil {
		return nil, mapStateError(err)
	}

	return &oas.BackfillNodeIPsOK{Changes: changes}, nil
}

// DebugCreateNode caches a synthetic node registration for testing and echoes
// back a node describing it. The real node is created later via AuthApprove.
func (s *Server) DebugCreateNode(
	_ context.Context,
	req *oas.DebugCreateNodeReq,
) (*oas.DebugCreateNodeOK, error) {
	user, err := s.state.GetUserByName(req.User.Or(""))
	if err != nil {
		return nil, mapStateError(err)
	}

	routes, err := util.StringToIPPrefix(req.Routes)
	if err != nil {
		return nil, badRequest(err.Error())
	}

	registrationID, err := types.AuthIDFromString(req.Key.Or(""))
	if err != nil {
		return nil, badRequest(err.Error())
	}

	regData := &types.RegistrationData{
		NodeKey:    key.NewNode().Public(),
		MachineKey: key.NewMachine().Public(),
		Hostname:   req.Name.Or(""),
		Expiry:     &time.Time{},
	}

	s.state.SetAuthCacheEntry(registrationID, types.NewRegisterAuthRequest(regData))

	echoNode := types.Node{
		NodeKey:    regData.NodeKey,
		MachineKey: regData.MachineKey,
		Hostname:   regData.Hostname,
		User:       user,
		Expiry:     &time.Time{},
		LastSeen:   &time.Time{},
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    req.Name.Or(""),
			OS:          "TestOS",
			RoutableIPs: routes,
		},
	}

	return &oas.DebugCreateNodeOK{Node: oas.NewOptNode(oasNode(echoNode.Proto()))}, nil
}
