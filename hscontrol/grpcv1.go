//go:generate buf generate --template ../buf.gen.yaml -o .. ../proto

// nolint
package hscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
)

type headscaleV1APIServer struct { // v1.HeadscaleServiceServer
	v1.UnimplementedHeadscaleServiceServer
	h *Headscale
}

func newHeadscaleV1APIServer(h *Headscale) v1.HeadscaleServiceServer {
	return headscaleV1APIServer{
		h: h,
	}
}

func (api headscaleV1APIServer) CreateUser(
	ctx context.Context,
	request *v1.CreateUserRequest,
) (*v1.CreateUserResponse, error) {
	newUser := types.User{
		Name:          request.GetName(),
		DisplayName:   request.GetDisplayName(),
		Email:         request.GetEmail(),
		ProfilePicURL: request.GetPictureUrl(),
	}
	user, policyChanged, err := api.h.state.CreateUser(newUser)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "creating user: %s", err)
	}

	// CreateUser returns a policy change response if the user creation affected policy.
	// This triggers a full policy re-evaluation for all connected nodes.
	api.h.Change(policyChanged)

	return &v1.CreateUserResponse{User: user.Proto()}, nil
}

func (api headscaleV1APIServer) RenameUser(
	ctx context.Context,
	request *v1.RenameUserRequest,
) (*v1.RenameUserResponse, error) {
	oldUser, err := api.h.state.GetUserByID(types.UserID(request.GetOldId()))
	if err != nil {
		return nil, err
	}

	_, c, err := api.h.state.RenameUser(types.UserID(oldUser.ID), request.GetNewName())
	if err != nil {
		return nil, err
	}

	// Send policy update notifications if needed
	api.h.Change(c)

	newUser, err := api.h.state.GetUserByName(request.GetNewName())
	if err != nil {
		return nil, err
	}

	return &v1.RenameUserResponse{User: newUser.Proto()}, nil
}

func (api headscaleV1APIServer) DeleteUser(
	ctx context.Context,
	request *v1.DeleteUserRequest,
) (*v1.DeleteUserResponse, error) {
	user, err := api.h.state.GetUserByID(types.UserID(request.GetId()))
	if err != nil {
		return nil, err
	}

	policyChanged, err := api.h.state.DeleteUser(types.UserID(user.ID))
	if err != nil {
		return nil, err
	}

	// Use the change returned from DeleteUser which includes proper policy updates
	api.h.Change(policyChanged)

	return &v1.DeleteUserResponse{}, nil
}

func (api headscaleV1APIServer) ListUsers(
	ctx context.Context,
	request *v1.ListUsersRequest,
) (*v1.ListUsersResponse, error) {
	var err error
	var users []types.User

	switch {
	case request.GetName() != "":
		users, err = api.h.state.ListUsersWithFilter(&types.User{Name: request.GetName()})
	case request.GetEmail() != "":
		users, err = api.h.state.ListUsersWithFilter(&types.User{Email: request.GetEmail()})
	case request.GetId() != 0:
		users, err = api.h.state.ListUsersWithFilter(&types.User{Model: gorm.Model{ID: uint(request.GetId())}})
	default:
		users, err = api.h.state.ListAllUsers()
	}
	if err != nil {
		return nil, err
	}

	response := make([]*v1.User, len(users))
	for index, user := range users {
		response[index] = user.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListUsersResponse{Users: response}, nil
}

func (api headscaleV1APIServer) CreatePreAuthKey(
	ctx context.Context,
	request *v1.CreatePreAuthKeyRequest,
) (*v1.CreatePreAuthKeyResponse, error) {
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	for _, tag := range request.AclTags {
		err := validateTag(tag)
		if err != nil {
			return &v1.CreatePreAuthKeyResponse{
				PreAuthKey: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	var userID *types.UserID
	if request.GetUser() != 0 {
		user, err := api.h.state.GetUserByID(types.UserID(request.GetUser()))
		if err != nil {
			return nil, err
		}
		userID = user.TypedID()
	}

	preAuthKey, err := api.h.state.CreatePreAuthKey(
		userID,
		request.GetReusable(),
		request.GetEphemeral(),
		&expiration,
		request.AclTags,
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreatePreAuthKeyResponse{PreAuthKey: preAuthKey.Proto()}, nil
}

func (api headscaleV1APIServer) ExpirePreAuthKey(
	ctx context.Context,
	request *v1.ExpirePreAuthKeyRequest,
) (*v1.ExpirePreAuthKeyResponse, error) {
	err := api.h.state.ExpirePreAuthKey(request.GetId())
	if err != nil {
		return nil, err
	}

	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (api headscaleV1APIServer) DeletePreAuthKey(
	ctx context.Context,
	request *v1.DeletePreAuthKeyRequest,
) (*v1.DeletePreAuthKeyResponse, error) {
	err := api.h.state.DeletePreAuthKey(request.GetId())
	if err != nil {
		return nil, err
	}

	return &v1.DeletePreAuthKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListPreAuthKeys(
	ctx context.Context,
	request *v1.ListPreAuthKeysRequest,
) (*v1.ListPreAuthKeysResponse, error) {
	preAuthKeys, err := api.h.state.ListPreAuthKeys()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.PreAuthKey, len(preAuthKeys))
	for index, key := range preAuthKeys {
		response[index] = key.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListPreAuthKeysResponse{PreAuthKeys: response}, nil
}

func (api headscaleV1APIServer) RegisterNode(
	ctx context.Context,
	request *v1.RegisterNodeRequest,
) (*v1.RegisterNodeResponse, error) {
	// Generate ephemeral registration key for tracking this registration flow in logs
	registrationKey, err := util.GenerateRegistrationKey()
	if err != nil {
		log.Warn().Err(err).Msg("failed to generate registration key")
		registrationKey = "" // Continue without key if generation fails
	}

	log.Trace().
		Caller().
		Str(zf.UserName, request.GetUser()).
		Str(zf.RegistrationID, request.GetKey()).
		Str(zf.RegistrationKey, registrationKey).
		Msg("registering node")

	registrationId, err := types.RegistrationIDFromString(request.GetKey())
	if err != nil {
		return nil, err
	}

	user, err := api.h.state.GetUserByName(request.GetUser())
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}

	node, nodeChange, err := api.h.state.HandleNodeFromAuthPath(
		registrationId,
		types.UserID(user.ID),
		nil,
		util.RegisterMethodCLI,
	)
	if err != nil {
		log.Error().
			Str(zf.RegistrationKey, registrationKey).
			Err(err).
			Msg("failed to register node")
		return nil, err
	}

	log.Info().
		Str(zf.RegistrationKey, registrationKey).
		EmbedObject(node).
		Msg("node registered successfully")

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// SaveNode (which automatically updates the policy manager) and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	routeChange, err := api.h.state.AutoApproveRoutes(node)
	if err != nil {
		return nil, fmt.Errorf("auto approving routes: %w", err)
	}

	// Send both changes. Empty changes are ignored by Change().
	api.h.Change(nodeChange, routeChange)

	return &v1.RegisterNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) GetNode(
	ctx context.Context,
	request *v1.GetNodeRequest,
) (*v1.GetNodeResponse, error) {
	node, ok := api.h.state.GetNodeByID(types.NodeID(request.GetNodeId()))
	if !ok {
		return nil, status.Errorf(codes.NotFound, "node not found")
	}

	resp := node.Proto()

	return &v1.GetNodeResponse{Node: resp}, nil
}

func (api headscaleV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	// Validate tags not empty - tagged nodes must have at least one tag
	if len(request.GetTags()) == 0 {
		return &v1.SetTagsResponse{
				Node: nil,
			}, status.Error(
				codes.InvalidArgument,
				"cannot remove all tags from a node - tagged nodes must have at least one tag",
			)
	}

	// Validate tag format
	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			return nil, err
		}
	}

	// User XOR Tags: nodes are either tagged or user-owned, never both.
	// Setting tags on a user-owned node converts it to a tagged node.
	// Once tagged, a node cannot be converted back to user-owned.
	_, found := api.h.state.GetNodeByID(types.NodeID(request.GetNodeId()))
	if !found {
		return &v1.SetTagsResponse{
			Node: nil,
		}, status.Error(codes.NotFound, "node not found")
	}

	node, nodeChange, err := api.h.state.SetNodeTags(types.NodeID(request.GetNodeId()), request.GetTags())
	if err != nil {
		return &v1.SetTagsResponse{
			Node: nil,
		}, status.Error(codes.InvalidArgument, err.Error())
	}

	api.h.Change(nodeChange)

	log.Trace().
		Caller().
		EmbedObject(node).
		Strs("tags", request.GetTags()).
		Msg("changing tags of node")

	return &v1.SetTagsResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) SetApprovedRoutes(
	ctx context.Context,
	request *v1.SetApprovedRoutesRequest,
) (*v1.SetApprovedRoutesResponse, error) {
	log.Debug().
		Caller().
		Uint64(zf.NodeID, request.GetNodeId()).
		Strs("requestedRoutes", request.GetRoutes()).
		Msg("gRPC SetApprovedRoutes called")

	var newApproved []netip.Prefix
	for _, route := range request.GetRoutes() {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return nil, fmt.Errorf("parsing route: %w", err)
		}

		// If the prefix is an exit route, add both. The client expect both
		// to annotate the node as an exit node.
		if prefix == tsaddr.AllIPv4() || prefix == tsaddr.AllIPv6() {
			newApproved = append(newApproved, tsaddr.AllIPv4(), tsaddr.AllIPv6())
		} else {
			newApproved = append(newApproved, prefix)
		}
	}
	slices.SortFunc(newApproved, netip.Prefix.Compare)
	newApproved = slices.Compact(newApproved)

	node, nodeChange, err := api.h.state.SetApprovedRoutes(types.NodeID(request.GetNodeId()), newApproved)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Always propagate node changes from SetApprovedRoutes
	api.h.Change(nodeChange)

	proto := node.Proto()
	// Populate SubnetRoutes with PrimaryRoutes to ensure it includes only the
	// routes that are actively served from the node (per architectural requirement in types/node.go)
	primaryRoutes := api.h.state.GetNodePrimaryRoutes(node.ID())
	proto.SubnetRoutes = util.PrefixesToString(primaryRoutes)

	log.Debug().
		Caller().
		EmbedObject(node).
		Strs("approvedRoutes", util.PrefixesToString(node.ApprovedRoutes().AsSlice())).
		Strs("primaryRoutes", util.PrefixesToString(primaryRoutes)).
		Strs("finalSubnetRoutes", proto.SubnetRoutes).
		Msg("gRPC SetApprovedRoutes completed")

	return &v1.SetApprovedRoutesResponse{Node: proto}, nil
}

func validateTag(tag string) error {
	if strings.Index(tag, "tag:") != 0 {
		return errors.New("tag must start with the string 'tag:'")
	}
	if strings.ToLower(tag) != tag {
		return errors.New("tag should be lowercase")
	}
	if len(strings.Fields(tag)) > 1 {
		return errors.New("tags must not contain spaces")
	}
	return nil
}

func (api headscaleV1APIServer) DeleteNode(
	ctx context.Context,
	request *v1.DeleteNodeRequest,
) (*v1.DeleteNodeResponse, error) {
	nodeID := request.GetNodeId()

	if nodeID >= types.WireGuardOnlyPeerIDOffset {
		nodeChange, err := api.h.state.DeleteWireGuardOnlyPeer(nodeID)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to delete wireguard-only peer: %s", err)
		}

		api.h.Change(nodeChange)

		return &v1.DeleteNodeResponse{}, nil
	} else {
		node, ok := api.h.state.GetNodeByID(types.NodeID(nodeID))
		if !ok {
			return nil, status.Errorf(codes.NotFound, "node not found")
		}

		nodeChange, err := api.h.state.DeleteNode(node)
		if err != nil {
			return nil, err
		}

		api.h.Change(nodeChange)

		return &v1.DeleteNodeResponse{}, nil
	}
}

func (api headscaleV1APIServer) ExpireNode(
	ctx context.Context,
	request *v1.ExpireNodeRequest,
) (*v1.ExpireNodeResponse, error) {
	if request.GetDisableExpiry() && request.GetExpiry() != nil {
		return nil, status.Error(
			codes.InvalidArgument,
			"cannot set both disable_expiry and expiry",
		)
	}

	// Handle disable expiry request - node will never expire.
	if request.GetDisableExpiry() {
		node, nodeChange, err := api.h.state.SetNodeExpiry(
			types.NodeID(request.GetNodeId()), nil,
		)
		if err != nil {
			return nil, err
		}

		api.h.Change(nodeChange)

		log.Trace().
			Caller().
			EmbedObject(node).
			Msg("node expiry disabled")

		return &v1.ExpireNodeResponse{Node: node.Proto()}, nil
	}

	expiry := time.Now()
	if request.GetExpiry() != nil {
		expiry = request.GetExpiry().AsTime()
	}

	node, nodeChange, err := api.h.state.SetNodeExpiry(
		types.NodeID(request.GetNodeId()), &expiry,
	)
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): Ensure that both the selfupdate and peer updates are sent
	api.h.Change(nodeChange)

	log.Trace().
		Caller().
		EmbedObject(node).
		Time(zf.ExpiresAt, expiry).
		Msg("node expired")

	return &v1.ExpireNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) RenameNode(
	ctx context.Context,
	request *v1.RenameNodeRequest,
) (*v1.RenameNodeResponse, error) {
	node, nodeChange, err := api.h.state.RenameNode(types.NodeID(request.GetNodeId()), request.GetNewName())
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): investigate if we need selfupdate
	api.h.Change(nodeChange)

	log.Trace().
		Caller().
		EmbedObject(node).
		Str(zf.NewName, request.GetNewName()).
		Msg("node renamed")

	return &v1.RenameNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) ListNodes(
	ctx context.Context,
	request *v1.ListNodesRequest,
) (*v1.ListNodesResponse, error) {
	// TODO(kradalby): it looks like this can be simplified a lot,
	// the filtering of nodes by user, vs nodes as a whole can
	// probably be done once.
	// TODO(kradalby): This should be done in one tx.
	var nodeProtos []*v1.Node
	var wgPeerProtos []*v1.WireGuardOnlyPeer

	if request.GetUser() != "" {
		user, err := api.h.state.GetUserByName(request.GetUser())
		if err != nil {
			return nil, err
		}

		nodes := api.h.state.ListNodesByUser(types.UserID(user.ID))
		nodeProtos = nodesToProto(api.h.state, nodes)

		userID := uint(user.ID)
		wgPeers, err := api.h.state.ListWireGuardOnlyPeers(&userID)
		if err != nil {
			return nil, err
		}
		wgPeerProtos = wgPeersToProto(wgPeers)
	} else {
		nodes := api.h.state.ListNodes()
		nodeProtos = nodesToProto(api.h.state, nodes)

		wgPeers, err := api.h.state.ListWireGuardOnlyPeers(nil)
		if err != nil {
			return nil, err
		}
		wgPeerProtos = wgPeersToProto(wgPeers)
	}

	connections := api.h.state.ListAllWireGuardConnections()
	connectionProtos := make([]*v1.WireGuardConnection, len(connections))
	for i, conn := range connections {
		connectionProtos[i] = conn.ToProto()
	}

	return &v1.ListNodesResponse{
		Nodes:                nodeProtos,
		WireguardOnlyPeers:   wgPeerProtos,
		WireguardConnections: connectionProtos,
	}, nil
}

func nodesToProto(state *state.State, nodes views.Slice[types.NodeView]) []*v1.Node {
	response := make([]*v1.Node, nodes.Len())
	for index, node := range nodes.All() {
		resp := node.Proto()

		// Tags-as-identity: tagged nodes show as TaggedDevices user in API responses
		// (UserID may be set internally for "created by" tracking)
		if node.IsTagged() {
			resp.User = types.TaggedDevices.Proto()
		}

		resp.SubnetRoutes = util.PrefixesToString(append(state.GetNodePrimaryRoutes(node.ID()), node.ExitRoutes()...))
		response[index] = resp
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return response
}

func wgPeersToProto(peers types.WireGuardOnlyPeers) []*v1.WireGuardOnlyPeer {
	response := make([]*v1.WireGuardOnlyPeer, len(peers))
	for i, peer := range peers {
		response[i] = peer.Proto()
	}
	return response
}

func (api headscaleV1APIServer) BackfillNodeIPs(
	ctx context.Context,
	request *v1.BackfillNodeIPsRequest,
) (*v1.BackfillNodeIPsResponse, error) {
	log.Trace().Caller().Msg("backfill called")

	if !request.Confirmed {
		return nil, errors.New("not confirmed, aborting")
	}

	changes, err := api.h.state.BackfillNodeIPs()
	if err != nil {
		return nil, err
	}

	return &v1.BackfillNodeIPsResponse{Changes: changes}, nil
}

func (api headscaleV1APIServer) CreateApiKey(
	ctx context.Context,
	request *v1.CreateApiKeyRequest,
) (*v1.CreateApiKeyResponse, error) {
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	apiKey, _, err := api.h.state.CreateAPIKey(&expiration)
	if err != nil {
		return nil, err
	}

	return &v1.CreateApiKeyResponse{ApiKey: apiKey}, nil
}

// apiKeyIdentifier is implemented by requests that identify an API key.
type apiKeyIdentifier interface {
	GetId() uint64
	GetPrefix() string
}

// getAPIKey retrieves an API key by ID or prefix from the request.
// Returns InvalidArgument if neither or both are provided.
func (api headscaleV1APIServer) getAPIKey(req apiKeyIdentifier) (*types.APIKey, error) {
	hasID := req.GetId() != 0
	hasPrefix := req.GetPrefix() != ""

	switch {
	case hasID && hasPrefix:
		return nil, status.Error(codes.InvalidArgument, "provide either id or prefix, not both")
	case hasID:
		return api.h.state.GetAPIKeyByID(req.GetId())
	case hasPrefix:
		return api.h.state.GetAPIKey(req.GetPrefix())
	default:
		return nil, status.Error(codes.InvalidArgument, "must provide id or prefix")
	}
}

func (api headscaleV1APIServer) ExpireApiKey(
	ctx context.Context,
	request *v1.ExpireApiKeyRequest,
) (*v1.ExpireApiKeyResponse, error) {
	apiKey, err := api.getAPIKey(request)
	if err != nil {
		return nil, err
	}

	err = api.h.state.ExpireAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return &v1.ExpireApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListApiKeys(
	ctx context.Context,
	request *v1.ListApiKeysRequest,
) (*v1.ListApiKeysResponse, error) {
	apiKeys, err := api.h.state.ListAPIKeys()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.ApiKey, len(apiKeys))
	for index, key := range apiKeys {
		response[index] = key.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListApiKeysResponse{ApiKeys: response}, nil
}

func (api headscaleV1APIServer) DeleteApiKey(
	ctx context.Context,
	request *v1.DeleteApiKeyRequest,
) (*v1.DeleteApiKeyResponse, error) {
	apiKey, err := api.getAPIKey(request)
	if err != nil {
		return nil, err
	}

	if err := api.h.state.DestroyAPIKey(*apiKey); err != nil {
		return nil, err
	}

	return &v1.DeleteApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) GetPolicy(
	_ context.Context,
	_ *v1.GetPolicyRequest,
) (*v1.GetPolicyResponse, error) {
	switch api.h.cfg.Policy.Mode {
	case types.PolicyModeDB:
		p, err := api.h.state.GetPolicy()
		if err != nil {
			return nil, fmt.Errorf("loading ACL from database: %w", err)
		}

		return &v1.GetPolicyResponse{
			Policy:    p.Data,
			UpdatedAt: timestamppb.New(p.UpdatedAt),
		}, nil
	case types.PolicyModeFile:
		// Read the file and return the contents as-is.
		absPath := util.AbsolutePathFromConfigPath(api.h.cfg.Policy.Path)
		f, err := os.Open(absPath)
		if err != nil {
			return nil, fmt.Errorf("reading policy from path %q: %w", absPath, err)
		}

		defer f.Close()

		b, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("reading policy from file: %w", err)
		}

		return &v1.GetPolicyResponse{Policy: string(b)}, nil
	}

	return nil, fmt.Errorf("no supported policy mode found in configuration, policy.mode: %q", api.h.cfg.Policy.Mode)
}

func (api headscaleV1APIServer) SetPolicy(
	_ context.Context,
	request *v1.SetPolicyRequest,
) (*v1.SetPolicyResponse, error) {
	if api.h.cfg.Policy.Mode != types.PolicyModeDB {
		return nil, types.ErrPolicyUpdateIsDisabled
	}

	p := request.GetPolicy()

	// Validate and reject configuration that would error when applied
	// when creating a map response. This requires nodes, so there is still
	// a scenario where they might be allowed if the server has no nodes
	// yet, but it should help for the general case and for hot reloading
	// configurations.
	nodes := api.h.state.ListNodes()

	_, err := api.h.state.SetPolicy([]byte(p))
	if err != nil {
		return nil, fmt.Errorf("setting policy: %w", err)
	}

	if nodes.Len() > 0 {
		_, err = api.h.state.SSHPolicy(nodes.At(0))
		if err != nil {
			return nil, fmt.Errorf("verifying SSH rules: %w", err)
		}
	}

	updated, err := api.h.state.SetPolicyInDB(p)
	if err != nil {
		return nil, err
	}

	// Always reload policy to ensure route re-evaluation, even if policy content hasn't changed.
	// This ensures that routes are re-evaluated for auto-approval in cases where routes
	// were manually disabled but could now be auto-approved with the current policy.
	cs, err := api.h.state.ReloadPolicy()
	if err != nil {
		return nil, fmt.Errorf("reloading policy: %w", err)
	}

	if len(cs) > 0 {
		api.h.Change(cs...)
	} else {
		log.Debug().
			Caller().
			Msg("No policy changes to distribute because ReloadPolicy returned empty changeset")
	}

	response := &v1.SetPolicyResponse{
		Policy:    updated.Data,
		UpdatedAt: timestamppb.New(updated.UpdatedAt),
	}

	log.Debug().
		Caller().
		Msg("gRPC SetPolicy completed successfully because response prepared")

	return response, nil
}

// The following service calls are for testing and debugging
func (api headscaleV1APIServer) DebugCreateNode(
	ctx context.Context,
	request *v1.DebugCreateNodeRequest,
) (*v1.DebugCreateNodeResponse, error) {
	user, err := api.h.state.GetUserByName(request.GetUser())
	if err != nil {
		return nil, err
	}

	routes, err := util.StringToIPPrefix(request.GetRoutes())
	if err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Interface("route-prefix", routes).
		Interface("route-str", request.GetRoutes()).
		Msg("Creating routes for node")

	hostinfo := tailcfg.Hostinfo{
		RoutableIPs: routes,
		OS:          "TestOS",
		Hostname:    request.GetName(),
	}

	registrationId, err := types.RegistrationIDFromString(request.GetKey())
	if err != nil {
		return nil, err
	}

	newNode := types.NewRegisterNode(
		types.Node{
			NodeKey:    key.NewNode().Public(),
			MachineKey: key.NewMachine().Public(),
			Hostname:   request.GetName(),
			User:       user,

			Expiry:   &time.Time{},
			LastSeen: &time.Time{},

			Hostinfo: &hostinfo,
		},
	)

	log.Debug().
		Caller().
		Str("registration_id", registrationId.String()).
		Msg("adding debug machine via CLI, appending to registration cache")

	api.h.state.SetRegistrationCacheEntry(registrationId, newNode)

	return &v1.DebugCreateNodeResponse{Node: newNode.Node.Proto()}, nil
}

func parseWireGuardOnlyPeerFromRequest(
	name string,
	userID uint,
	publicKeyStr string,
	allowedIPsStr []string,
	endpointsStr []string,
	extraConfigJSON *string,
) (*types.WireGuardOnlyPeer, error) {
	var publicKey key.NodePublic
	if err := publicKey.UnmarshalText([]byte(publicKeyStr)); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	allowedIPs := make([]netip.Prefix, 0, len(allowedIPsStr))
	for _, ipStr := range allowedIPsStr {
		prefix, err := netip.ParsePrefix(ipStr)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed IP %q: %w", ipStr, err)
		}
		allowedIPs = append(allowedIPs, prefix)
	}

	endpoints := make([]netip.AddrPort, 0, len(endpointsStr))
	for _, epStr := range endpointsStr {
		addrPort, err := netip.ParseAddrPort(epStr)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint %q: %w", epStr, err)
		}
		endpoints = append(endpoints, addrPort)
	}

	// Parse and validate extra config JSON
	var extraConfig *types.WireGuardOnlyPeerExtraConfig
	if extraConfigJSON != nil && *extraConfigJSON != "" {
		extraConfig = &types.WireGuardOnlyPeerExtraConfig{}
		if err := json.Unmarshal([]byte(*extraConfigJSON), extraConfig); err != nil {
			return nil, fmt.Errorf("invalid extra-config JSON: %w", err)
		}
	}

	peer := &types.WireGuardOnlyPeer{
		Name:        name,
		UserID:      types.UserID(userID),
		PublicKey:   publicKey,
		AllowedIPs:  allowedIPs,
		Endpoints:   endpoints,
		ExtraConfig: extraConfig,
	}

	return peer, nil
}

func (api headscaleV1APIServer) RegisterWireGuardOnlyPeer(
	ctx context.Context,
	request *v1.RegisterWireGuardOnlyPeerRequest,
) (*v1.RegisterWireGuardOnlyPeerResponse, error) {
	peer, err := parseWireGuardOnlyPeerFromRequest(
		request.GetName(),
		uint(request.GetUserId()),
		request.GetPublicKey(),
		request.GetAllowedIps(),
		request.GetEndpoints(),
		request.ExtraConfig,
	)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %s", err)
	}

	// Create the peer (this allocates IPs and stores in database)
	if err := api.h.state.CreateWireGuardOnlyPeer(peer); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create wireguard-only peer: %s", err)
	}

	log.Info().
		Str("name", peer.Name).
		Uint64("id", uint64(peer.ID)).
		Uint64("user_id", uint64(peer.UserID)).
		Msg("WireGuard-only peer registered")

	api.h.Change(change.WireGuardPeerAdded(peer.ID))

	return &v1.RegisterWireGuardOnlyPeerResponse{
		Peer: peer.Proto(),
	}, nil
}

// GetWireGuardOnlyPeer retrieves a WireGuard-only peer by ID.
func (api headscaleV1APIServer) GetWireGuardOnlyPeer(
	ctx context.Context,
	request *v1.GetWireGuardOnlyPeerRequest,
) (*v1.GetWireGuardOnlyPeerResponse, error) {
	peer, err := api.h.state.GetWireGuardOnlyPeerByID(request.GetPeerId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "peer not found: %s", err)
	}

	return &v1.GetWireGuardOnlyPeerResponse{
		Peer: peer.Proto(),
	}, nil
}

// ListWireGuardOnlyPeers lists all WireGuard-only peers, optionally filtered by user.
func (api headscaleV1APIServer) ListWireGuardOnlyPeers(
	ctx context.Context,
	request *v1.ListWireGuardOnlyPeersRequest,
) (*v1.ListWireGuardOnlyPeersResponse, error) {
	var userID *uint
	if request.UserId != nil && *request.UserId != 0 {
		uid := uint(*request.UserId)
		userID = &uid
	}

	peers, err := api.h.state.ListWireGuardOnlyPeers(userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list wireguard-only peers: %s", err)
	}

	response := make([]*v1.WireGuardOnlyPeer, len(peers))
	for i, peer := range peers {
		response[i] = peer.Proto()
	}

	sort.Slice(response, func(i, j int) bool {
		return response[i].Id < response[j].Id
	})

	return &v1.ListWireGuardOnlyPeersResponse{
		Peers: response,
	}, nil
}

// CreateWireGuardConnection creates a connection between a node and a WireGuard-only peer.
func (api headscaleV1APIServer) CreateWireGuardConnection(
	ctx context.Context,
	request *v1.CreateWireGuardConnectionRequest,
) (*v1.CreateWireGuardConnectionResponse, error) {
	var ipv4MasqAddr *netip.Addr
	if request.Ipv4MasqAddr != nil && *request.Ipv4MasqAddr != "" {
		addr, err := netip.ParseAddr(*request.Ipv4MasqAddr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid IPv4 masquerade address: %s", err)
		}
		if !addr.Is4() {
			return nil, status.Errorf(codes.InvalidArgument, "IPv4 masquerade address must be an IPv4 address")
		}
		ipv4MasqAddr = &addr
	}

	var ipv6MasqAddr *netip.Addr
	if request.Ipv6MasqAddr != nil && *request.Ipv6MasqAddr != "" {
		addr, err := netip.ParseAddr(*request.Ipv6MasqAddr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid IPv6 masquerade address: %s", err)
		}
		if !addr.Is6() {
			return nil, status.Errorf(codes.InvalidArgument, "IPv6 masquerade address must be an IPv6 address")
		}
		ipv6MasqAddr = &addr
	}

	if ipv4MasqAddr == nil && ipv6MasqAddr == nil {
		return nil, status.Errorf(codes.InvalidArgument, "at least one masquerade address (IPv4 or IPv6) must be specified")
	}

	conn := &types.WireGuardConnection{
		NodeID:       types.NodeID(request.GetNodeId()),
		WGPeerID:     types.NodeID(request.GetWgPeerId()),
		IPv4MasqAddr: ipv4MasqAddr,
		IPv6MasqAddr: ipv6MasqAddr,
	}

	changeSet, err := api.h.state.CreateWireGuardConnection(conn)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create connection: %s", err)
	}

	log.Info().
		Uint64("node_id", uint64(conn.NodeID)).
		Uint64("wg_peer_id", uint64(conn.WGPeerID)).
		Msg("WireGuard connection created")

	api.h.Change(changeSet)

	return &v1.CreateWireGuardConnectionResponse{
		Connection: conn.ToProto(),
	}, nil
}

// DeleteWireGuardConnection removes a connection between a node and a WireGuard-only peer.
func (api headscaleV1APIServer) DeleteWireGuardConnection(
	ctx context.Context,
	request *v1.DeleteWireGuardConnectionRequest,
) (*v1.DeleteWireGuardConnectionResponse, error) {
	nodeID := types.NodeID(request.GetNodeId())
	wgPeerID := types.NodeID(request.GetWgPeerId())

	changeSet, err := api.h.state.DeleteWireGuardConnection(nodeID, wgPeerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete connection: %s", err)
	}

	log.Info().
		Uint64("node_id", uint64(nodeID)).
		Uint64("wg_peer_id", uint64(wgPeerID)).
		Msg("WireGuard connection deleted")

	api.h.Change(changeSet)

	return &v1.DeleteWireGuardConnectionResponse{}, nil
}

func (api headscaleV1APIServer) Health(
	ctx context.Context,
	request *v1.HealthRequest,
) (*v1.HealthResponse, error) {
	var healthErr error
	response := &v1.HealthResponse{}

	if err := api.h.state.PingDB(ctx); err != nil {
		healthErr = fmt.Errorf("pinging database: %w", err)
	} else {
		response.DatabaseConnectivity = true
	}

	if healthErr != nil {
		log.Error().Err(healthErr).Msg("health check failed")
	}

	return response, healthErr
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
