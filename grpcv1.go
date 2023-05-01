// nolint
package headscale

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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

func (api headscaleV1APIServer) GetUser(
	ctx context.Context,
	request *v1.GetUserRequest,
) (*v1.GetUserResponse, error) {
	user, err := api.h.GetUser(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.GetUserResponse{User: user.toProto()}, nil
}

func (api headscaleV1APIServer) CreateUser(
	ctx context.Context,
	request *v1.CreateUserRequest,
) (*v1.CreateUserResponse, error) {
	user, err := api.h.CreateUser(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.CreateUserResponse{User: user.toProto()}, nil
}

func (api headscaleV1APIServer) RenameUser(
	ctx context.Context,
	request *v1.RenameUserRequest,
) (*v1.RenameUserResponse, error) {
	err := api.h.RenameUser(request.GetOldName(), request.GetNewName())
	if err != nil {
		return nil, err
	}

	user, err := api.h.GetUser(request.GetNewName())
	if err != nil {
		return nil, err
	}

	return &v1.RenameUserResponse{User: user.toProto()}, nil
}

func (api headscaleV1APIServer) DeleteUser(
	ctx context.Context,
	request *v1.DeleteUserRequest,
) (*v1.DeleteUserResponse, error) {
	err := api.h.DestroyUser(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.DeleteUserResponse{}, nil
}

func (api headscaleV1APIServer) ListUsers(
	ctx context.Context,
	request *v1.ListUsersRequest,
) (*v1.ListUsersResponse, error) {
	users, err := api.h.ListUsers()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.User, len(users))
	for index, user := range users {
		response[index] = user.toProto()
	}

	log.Trace().Caller().Interface("users", response).Msg("")

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

	preAuthKey, err := api.h.CreatePreAuthKey(
		request.GetUser(),
		request.GetReusable(),
		request.GetEphemeral(),
		&expiration,
		request.AclTags,
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreatePreAuthKeyResponse{PreAuthKey: preAuthKey.toProto()}, nil
}

func (api headscaleV1APIServer) ExpirePreAuthKey(
	ctx context.Context,
	request *v1.ExpirePreAuthKeyRequest,
) (*v1.ExpirePreAuthKeyResponse, error) {
	preAuthKey, err := api.h.GetPreAuthKey(request.GetUser(), request.Key)
	if err != nil {
		return nil, err
	}

	err = api.h.ExpirePreAuthKey(preAuthKey)
	if err != nil {
		return nil, err
	}

	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListPreAuthKeys(
	ctx context.Context,
	request *v1.ListPreAuthKeysRequest,
) (*v1.ListPreAuthKeysResponse, error) {
	preAuthKeys, err := api.h.ListPreAuthKeys(request.GetUser())
	if err != nil {
		return nil, err
	}

	response := make([]*v1.PreAuthKey, len(preAuthKeys))
	for index, key := range preAuthKeys {
		response[index] = key.toProto()
	}

	return &v1.ListPreAuthKeysResponse{PreAuthKeys: response}, nil
}

func (api headscaleV1APIServer) RegisterNode(
	ctx context.Context,
	request *v1.RegisterNodeRequest,
) (*v1.RegisterNodeResponse, error) {
	log.Trace().
		Str("user", request.GetUser()).
		Str("node_key", request.GetKey()).
		Msg("Registering node")

	node, err := api.h.RegisterNodeFromAuthCallback(
		request.GetKey(),
		request.GetUser(),
		nil,
		RegisterMethodCLI,
	)
	if err != nil {
		return nil, err
	}

	return &v1.RegisterNodeResponse{Node: node.toProto()}, nil
}

func (api headscaleV1APIServer) GetNode(
	ctx context.Context,
	request *v1.GetNodeRequest,
) (*v1.GetNodeResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	return &v1.GetNodeResponse{Node: node.toProto()}, nil
}

func (api headscaleV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			return &v1.SetTagsResponse{
				Node: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	err = api.h.SetTags(node, request.GetTags())
	if err != nil {
		return &v1.SetTagsResponse{
			Node: nil,
		}, status.Error(codes.Internal, err.Error())
	}

	log.Trace().
		Str("node", node.Hostname).
		Strs("tags", request.GetTags()).
		Msg("Changing tags of node")

	return &v1.SetTagsResponse{Node: node.toProto()}, nil
}

func validateTag(tag string) error {
	if strings.Index(tag, "tag:") != 0 {
		return fmt.Errorf("tag must start with the string 'tag:'")
	}
	if strings.ToLower(tag) != tag {
		return fmt.Errorf("tag should be lowercase")
	}
	if len(strings.Fields(tag)) > 1 {
		return fmt.Errorf("tag should not contains space")
	}
	return nil
}

func (api headscaleV1APIServer) DeleteNode(
	ctx context.Context,
	request *v1.DeleteNodeRequest,
) (*v1.DeleteNodeResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	err = api.h.DeleteNode(
		node,
	)
	if err != nil {
		return nil, err
	}

	return &v1.DeleteNodeResponse{}, nil
}

func (api headscaleV1APIServer) ExpireNode(
	ctx context.Context,
	request *v1.ExpireNodeRequest,
) (*v1.ExpireNodeResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	api.h.ExpireNode(
		node,
	)

	log.Trace().
		Str("node", node.Hostname).
		Time("expiry", *node.Expiry).
		Msg("node expired")

	return &v1.ExpireNodeResponse{Node: node.toProto()}, nil
}

func (api headscaleV1APIServer) RenameNode(
	ctx context.Context,
	request *v1.RenameNodeRequest,
) (*v1.RenameNodeResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	err = api.h.RenameNode(
		node,
		request.GetNewName(),
	)
	if err != nil {
		return nil, err
	}

	log.Trace().
		Str("node", node.Hostname).
		Str("new_name", request.GetNewName()).
		Msg("node renamed")

	return &v1.RenameNodeResponse{Node: node.toProto()}, nil
}

func (api headscaleV1APIServer) ListNodes(
	ctx context.Context,
	request *v1.ListNodesRequest,
) (*v1.ListNodesResponse, error) {
	if request.GetUser() != "" {
		nodes, err := api.h.ListNodesByUser(request.GetUser())
		if err != nil {
			return nil, err
		}

		response := make([]*v1.Node, len(nodes))
		for index, node := range nodes {
			response[index] = node.toProto()
		}

		return &v1.ListNodesResponse{Nodes: response}, nil
	}

	nodes, err := api.h.ListNodes()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.Node, len(nodes))
	for index, node := range nodes {
		m := node.toProto()
		validTags, invalidTags := getTags(
			api.h.aclPolicy,
			node,
			api.h.cfg.OIDC.StripEmaildomain,
		)
		m.InvalidTags = invalidTags
		m.ValidTags = validTags
		response[index] = m
	}

	return &v1.ListNodesResponse{Nodes: response}, nil
}

func (api headscaleV1APIServer) MoveNode(
	ctx context.Context,
	request *v1.MoveNodeRequest,
) (*v1.MoveNodeResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	err = api.h.SetNodeUser(node, request.GetUser())
	if err != nil {
		return nil, err
	}

	return &v1.MoveNodeResponse{Node: node.toProto()}, nil
}

func (api headscaleV1APIServer) GetRoutes(
	ctx context.Context,
	request *v1.GetRoutesRequest,
) (*v1.GetRoutesResponse, error) {
	routes, err := api.h.GetRoutes()
	if err != nil {
		return nil, err
	}

	return &v1.GetRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
}

func (api headscaleV1APIServer) EnableRoute(
	ctx context.Context,
	request *v1.EnableRouteRequest,
) (*v1.EnableRouteResponse, error) {
	err := api.h.EnableRoute(request.GetRouteId())
	if err != nil {
		return nil, err
	}

	return &v1.EnableRouteResponse{}, nil
}

func (api headscaleV1APIServer) DisableRoute(
	ctx context.Context,
	request *v1.DisableRouteRequest,
) (*v1.DisableRouteResponse, error) {
	err := api.h.DisableRoute(request.GetRouteId())
	if err != nil {
		return nil, err
	}

	return &v1.DisableRouteResponse{}, nil
}

func (api headscaleV1APIServer) GetNodeRoutes(
	ctx context.Context,
	request *v1.GetNodeRoutesRequest,
) (*v1.GetNodeRoutesResponse, error) {
	node, err := api.h.GetNodeByID(request.GetNodeId())
	if err != nil {
		return nil, err
	}

	routes, err := api.h.GetNodeRoutes(node)
	if err != nil {
		return nil, err
	}

	return &v1.GetNodeRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
}

func (api headscaleV1APIServer) DeleteRoute(
	ctx context.Context,
	request *v1.DeleteRouteRequest,
) (*v1.DeleteRouteResponse, error) {
	err := api.h.DeleteRoute(request.GetRouteId())
	if err != nil {
		return nil, err
	}

	return &v1.DeleteRouteResponse{}, nil
}

func (api headscaleV1APIServer) CreateApiKey(
	ctx context.Context,
	request *v1.CreateApiKeyRequest,
) (*v1.CreateApiKeyResponse, error) {
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	apiKey, _, err := api.h.CreateAPIKey(
		&expiration,
	)
	if err != nil {
		return nil, err
	}

	return &v1.CreateApiKeyResponse{ApiKey: apiKey}, nil
}

func (api headscaleV1APIServer) ExpireApiKey(
	ctx context.Context,
	request *v1.ExpireApiKeyRequest,
) (*v1.ExpireApiKeyResponse, error) {
	var apiKey *APIKey
	var err error

	apiKey, err = api.h.GetAPIKey(request.Prefix)
	if err != nil {
		return nil, err
	}

	err = api.h.ExpireAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return &v1.ExpireApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListApiKeys(
	ctx context.Context,
	request *v1.ListApiKeysRequest,
) (*v1.ListApiKeysResponse, error) {
	apiKeys, err := api.h.ListAPIKeys()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.ApiKey, len(apiKeys))
	for index, key := range apiKeys {
		response[index] = key.toProto()
	}

	return &v1.ListApiKeysResponse{ApiKeys: response}, nil
}

// The following service calls are for testing and debugging
func (api headscaleV1APIServer) DebugCreateNode(
	ctx context.Context,
	request *v1.DebugCreateNodeRequest,
) (*v1.DebugCreateNodeResponse, error) {
	user, err := api.h.GetUser(request.GetUser())
	if err != nil {
		return nil, err
	}

	routes, err := stringToIPPrefix(request.GetRoutes())
	if err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Interface("route-prefix", routes).
		Interface("route-str", request.GetRoutes()).
		Msg("")

	hostinfo := tailcfg.Hostinfo{
		RoutableIPs: routes,
		OS:          "TestOS",
		Hostname:    "DebugTestNode",
	}

	givenName, err := api.h.GenerateGivenName(request.GetKey(), request.GetName())
	if err != nil {
		return nil, err
	}

	newNode := Node{
		MachineKey: request.GetKey(),
		Hostname:   request.GetName(),
		GivenName:  givenName,
		User:       *user,

		Expiry:               &time.Time{},
		LastSeen:             &time.Time{},
		LastSuccessfulUpdate: &time.Time{},

		HostInfo: HostInfo(hostinfo),
	}

	nodeKey := key.NodePublic{}
	err = nodeKey.UnmarshalText([]byte(request.GetKey()))
	if err != nil {
		log.Panic().Msg("can not add node for debug. invalid node key")
	}

	api.h.registrationCache.Set(
		NodePublicKeyStripPrefix(nodeKey),
		newNode,
		registerCacheExpiration,
	)

	return &v1.DebugCreateNodeResponse{Node: newNode.toProto()}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
