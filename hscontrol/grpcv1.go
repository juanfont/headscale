// nolint
package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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
	user, err := api.h.db.CreateUser(newUser)
	if err != nil {
		return nil, err
	}

	err = usersChangedHook(api.h.db, api.h.polMan, api.h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using user: %w", err)
	}

	return &v1.CreateUserResponse{User: user.Proto()}, nil
}

func (api headscaleV1APIServer) RenameUser(
	ctx context.Context,
	request *v1.RenameUserRequest,
) (*v1.RenameUserResponse, error) {
	oldUser, err := api.h.db.GetUserByID(types.UserID(request.GetOldId()))
	if err != nil {
		return nil, err
	}

	err = api.h.db.RenameUser(types.UserID(oldUser.ID), request.GetNewName())
	if err != nil {
		return nil, err
	}

	newUser, err := api.h.db.GetUserByName(request.GetNewName())
	if err != nil {
		return nil, err
	}

	return &v1.RenameUserResponse{User: newUser.Proto()}, nil
}

func (api headscaleV1APIServer) DeleteUser(
	ctx context.Context,
	request *v1.DeleteUserRequest,
) (*v1.DeleteUserResponse, error) {
	user, err := api.h.db.GetUserByID(types.UserID(request.GetId()))
	if err != nil {
		return nil, err
	}

	err = api.h.db.DestroyUser(types.UserID(user.ID))
	if err != nil {
		return nil, err
	}

	err = usersChangedHook(api.h.db, api.h.polMan, api.h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using user: %w", err)
	}

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
		users, err = api.h.db.ListUsers(&types.User{Name: request.GetName()})
	case request.GetEmail() != "":
		users, err = api.h.db.ListUsers(&types.User{Email: request.GetEmail()})
	case request.GetId() != 0:
		users, err = api.h.db.ListUsers(&types.User{Model: gorm.Model{ID: uint(request.GetId())}})
	default:
		users, err = api.h.db.ListUsers()
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

	user, err := api.h.db.GetUserByName(request.GetUser())
	if err != nil {
		return nil, err
	}

	preAuthKey, err := api.h.db.CreatePreAuthKey(
		types.UserID(user.ID),
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
	err := api.h.db.Write(func(tx *gorm.DB) error {
		preAuthKey, err := db.GetPreAuthKey(tx, request.GetUser(), request.Key)
		if err != nil {
			return err
		}

		return db.ExpirePreAuthKey(tx, preAuthKey)
	})
	if err != nil {
		return nil, err
	}

	return &v1.ExpirePreAuthKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListPreAuthKeys(
	ctx context.Context,
	request *v1.ListPreAuthKeysRequest,
) (*v1.ListPreAuthKeysResponse, error) {
	user, err := api.h.db.GetUserByName(request.GetUser())
	if err != nil {
		return nil, err
	}

	preAuthKeys, err := api.h.db.ListPreAuthKeys(types.UserID(user.ID))
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
	log.Trace().
		Str("user", request.GetUser()).
		Str("registration_id", request.GetKey()).
		Msg("Registering node")

	registrationId, err := types.RegistrationIDFromString(request.GetKey())
	if err != nil {
		return nil, err
	}

	ipv4, ipv6, err := api.h.ipAlloc.Next()
	if err != nil {
		return nil, err
	}

	user, err := api.h.db.GetUserByName(request.GetUser())
	if err != nil {
		return nil, fmt.Errorf("looking up user: %w", err)
	}

	node, _, err := api.h.db.HandleNodeFromAuthPath(
		registrationId,
		types.UserID(user.ID),
		nil,
		util.RegisterMethodCLI,
		ipv4, ipv6,
	)
	if err != nil {
		return nil, err
	}

	err = nodesChangedHook(api.h.db, api.h.polMan, api.h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("updating resources using node: %w", err)
	}

	return &v1.RegisterNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) GetNode(
	ctx context.Context,
	request *v1.GetNodeRequest,
) (*v1.GetNodeResponse, error) {
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	resp := node.Proto()

	// Populate the online field based on
	// currently connected nodes.
	resp.Online = api.h.nodeNotifier.IsConnected(node.ID)

	return &v1.GetNodeResponse{Node: resp}, nil
}

func (api headscaleV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			return nil, err
		}
	}

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.SetTags(tx, types.NodeID(request.GetNodeId()), request.GetTags())
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return &v1.SetTagsResponse{
			Node: nil,
		}, status.Error(codes.InvalidArgument, err.Error())
	}

	ctx = types.NotifyCtx(ctx, "cli-settags", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: []types.NodeID{node.ID},
		Message:     "called from api.SetTags",
	}, node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Strs("tags", request.GetTags()).
		Msg("Changing tags of node")

	return &v1.SetTagsResponse{Node: node.Proto()}, nil
}

func validateTag(tag string) error {
	if strings.Index(tag, "tag:") != 0 {
		return errors.New("tag must start with the string 'tag:'")
	}
	if strings.ToLower(tag) != tag {
		return errors.New("tag should be lowercase")
	}
	if len(strings.Fields(tag)) > 1 {
		return errors.New("tag should not contains space")
	}
	return nil
}

func (api headscaleV1APIServer) DeleteNode(
	ctx context.Context,
	request *v1.DeleteNodeRequest,
) (*v1.DeleteNodeResponse, error) {
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	changedNodes, err := api.h.db.DeleteNode(
		node,
		api.h.nodeNotifier.LikelyConnectedMap(),
	)
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-deletenode", node.Hostname)
	api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
		Type:    types.StatePeerRemoved,
		Removed: []types.NodeID{node.ID},
	})

	if changedNodes != nil {
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: changedNodes,
		})
	}

	return &v1.DeleteNodeResponse{}, nil
}

func (api headscaleV1APIServer) ExpireNode(
	ctx context.Context,
	request *v1.ExpireNodeRequest,
) (*v1.ExpireNodeResponse, error) {
	now := time.Now()

	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		db.NodeSetExpiry(
			tx,
			types.NodeID(request.GetNodeId()),
			now,
		)

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-expirenode-self", node.Hostname)
	api.h.nodeNotifier.NotifyByNodeID(
		ctx,
		types.StateUpdate{
			Type:        types.StateSelfUpdate,
			ChangeNodes: []types.NodeID{node.ID},
		},
		node.ID)

	ctx = types.NotifyCtx(ctx, "cli-expirenode-peers", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdateExpire(node.ID, now), node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Time("expiry", *node.Expiry).
		Msg("node expired")

	return &v1.ExpireNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) RenameNode(
	ctx context.Context,
	request *v1.RenameNodeRequest,
) (*v1.RenameNodeResponse, error) {
	node, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.RenameNode(
			tx,
			types.NodeID(request.GetNodeId()),
			request.GetNewName(),
		)
		if err != nil {
			return nil, err
		}

		return db.GetNodeByID(tx, types.NodeID(request.GetNodeId()))
	})
	if err != nil {
		return nil, err
	}

	ctx = types.NotifyCtx(ctx, "cli-renamenode", node.Hostname)
	api.h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: []types.NodeID{node.ID},
		Message:     "called from api.RenameNode",
	}, node.ID)

	log.Trace().
		Str("node", node.Hostname).
		Str("new_name", request.GetNewName()).
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

	isLikelyConnected := api.h.nodeNotifier.LikelyConnectedMap()
	if request.GetUser() != "" {
		user, err := api.h.db.GetUserByName(request.GetUser())
		if err != nil {
			return nil, err
		}

		nodes, err := db.Read(api.h.db.DB, func(rx *gorm.DB) (types.Nodes, error) {
			return db.ListNodesByUser(rx, types.UserID(user.ID))
		})
		if err != nil {
			return nil, err
		}

		response := nodesToProto(api.h.polMan, isLikelyConnected, nodes)
		return &v1.ListNodesResponse{Nodes: response}, nil
	}

	nodes, err := api.h.db.ListNodes()
	if err != nil {
		return nil, err
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})

	response := nodesToProto(api.h.polMan, isLikelyConnected, nodes)
	return &v1.ListNodesResponse{Nodes: response}, nil
}

func nodesToProto(polMan policy.PolicyManager, isLikelyConnected *xsync.MapOf[types.NodeID, bool], nodes types.Nodes) []*v1.Node {
	response := make([]*v1.Node, len(nodes))
	for index, node := range nodes {
		resp := node.Proto()

		// Populate the online field based on
		// currently connected nodes.
		if val, ok := isLikelyConnected.Load(node.ID); ok && val {
			resp.Online = true
		}

		tags := polMan.Tags(node)
		resp.ValidTags = lo.Uniq(append(tags, node.ForcedTags...))
		response[index] = resp
	}

	return response
}

func (api headscaleV1APIServer) MoveNode(
	ctx context.Context,
	request *v1.MoveNodeRequest,
) (*v1.MoveNodeResponse, error) {
	// TODO(kradalby): This should be done in one tx.
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	user, err := api.h.db.GetUserByName(request.GetUser())
	if err != nil {
		return nil, err
	}

	err = api.h.db.AssignNodeToUser(node, types.UserID(user.ID))
	if err != nil {
		return nil, err
	}

	return &v1.MoveNodeResponse{Node: node.Proto()}, nil
}

func (api headscaleV1APIServer) BackfillNodeIPs(
	ctx context.Context,
	request *v1.BackfillNodeIPsRequest,
) (*v1.BackfillNodeIPsResponse, error) {
	log.Trace().Msg("Backfill called")

	if !request.Confirmed {
		return nil, errors.New("not confirmed, aborting")
	}

	changes, err := api.h.db.BackfillNodeIPs(api.h.ipAlloc)
	if err != nil {
		return nil, err
	}

	return &v1.BackfillNodeIPsResponse{Changes: changes}, nil
}

func (api headscaleV1APIServer) GetRoutes(
	ctx context.Context,
	request *v1.GetRoutesRequest,
) (*v1.GetRoutesResponse, error) {
	routes, err := db.Read(api.h.db.DB, func(rx *gorm.DB) (types.Routes, error) {
		return db.GetRoutes(rx)
	})
	if err != nil {
		return nil, err
	}

	return &v1.GetRoutesResponse{
		Routes: types.Routes(routes).Proto(),
	}, nil
}

func (api headscaleV1APIServer) EnableRoute(
	ctx context.Context,
	request *v1.EnableRouteRequest,
) (*v1.EnableRouteResponse, error) {
	update, err := db.Write(api.h.db.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return db.EnableRoute(tx, request.GetRouteId())
	})
	if err != nil {
		return nil, err
	}

	if update != nil {
		ctx := types.NotifyCtx(ctx, "cli-enableroute", "unknown")
		api.h.nodeNotifier.NotifyAll(
			ctx, *update)
	}

	return &v1.EnableRouteResponse{}, nil
}

func (api headscaleV1APIServer) DisableRoute(
	ctx context.Context,
	request *v1.DisableRouteRequest,
) (*v1.DisableRouteResponse, error) {
	update, err := db.Write(api.h.db.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return db.DisableRoute(tx, request.GetRouteId(), api.h.nodeNotifier.LikelyConnectedMap())
	})
	if err != nil {
		return nil, err
	}

	if update != nil {
		ctx := types.NotifyCtx(ctx, "cli-disableroute", "unknown")
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: update,
		})
	}

	return &v1.DisableRouteResponse{}, nil
}

func (api headscaleV1APIServer) GetNodeRoutes(
	ctx context.Context,
	request *v1.GetNodeRoutesRequest,
) (*v1.GetNodeRoutesResponse, error) {
	node, err := api.h.db.GetNodeByID(types.NodeID(request.GetNodeId()))
	if err != nil {
		return nil, err
	}

	routes, err := api.h.db.GetNodeRoutes(node)
	if err != nil {
		return nil, err
	}

	return &v1.GetNodeRoutesResponse{
		Routes: types.Routes(routes).Proto(),
	}, nil
}

func (api headscaleV1APIServer) DeleteRoute(
	ctx context.Context,
	request *v1.DeleteRouteRequest,
) (*v1.DeleteRouteResponse, error) {
	isConnected := api.h.nodeNotifier.LikelyConnectedMap()
	update, err := db.Write(api.h.db.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return db.DeleteRoute(tx, request.GetRouteId(), isConnected)
	})
	if err != nil {
		return nil, err
	}

	if update != nil {
		ctx := types.NotifyCtx(ctx, "cli-deleteroute", "unknown")
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: update,
		})
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

	apiKey, _, err := api.h.db.CreateAPIKey(
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
	var apiKey *types.APIKey
	var err error

	apiKey, err = api.h.db.GetAPIKey(request.Prefix)
	if err != nil {
		return nil, err
	}

	err = api.h.db.ExpireAPIKey(apiKey)
	if err != nil {
		return nil, err
	}

	return &v1.ExpireApiKeyResponse{}, nil
}

func (api headscaleV1APIServer) ListApiKeys(
	ctx context.Context,
	request *v1.ListApiKeysRequest,
) (*v1.ListApiKeysResponse, error) {
	apiKeys, err := api.h.db.ListAPIKeys()
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
	var (
		apiKey *types.APIKey
		err    error
	)

	apiKey, err = api.h.db.GetAPIKey(request.Prefix)
	if err != nil {
		return nil, err
	}

	if err := api.h.db.DestroyAPIKey(*apiKey); err != nil {
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
		p, err := api.h.db.GetPolicy()
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
	nodes, err := api.h.db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes from database to validate policy: %w", err)
	}
	changed, err := api.h.polMan.SetPolicy([]byte(p))
	if err != nil {
		return nil, fmt.Errorf("setting policy: %w", err)
	}

	if len(nodes) > 0 {
		_, err = api.h.polMan.SSHPolicy(nodes[0])
		if err != nil {
			return nil, fmt.Errorf("verifying SSH rules: %w", err)
		}
	}

	updated, err := api.h.db.SetPolicy(p)
	if err != nil {
		return nil, err
	}

	// Only send update if the packet filter has changed.
	if changed {
		ctx := types.NotifyCtx(context.Background(), "acl-update", "na")
		api.h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type: types.StateFullUpdate,
		})
	}

	response := &v1.SetPolicyResponse{
		Policy:    updated.Data,
		UpdatedAt: timestamppb.New(updated.UpdatedAt),
	}

	return response, nil
}

// The following service calls are for testing and debugging
func (api headscaleV1APIServer) DebugCreateNode(
	ctx context.Context,
	request *v1.DebugCreateNodeRequest,
) (*v1.DebugCreateNodeResponse, error) {
	user, err := api.h.db.GetUserByName(request.GetUser())
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
		Msg("")

	hostinfo := tailcfg.Hostinfo{
		RoutableIPs: routes,
		OS:          "TestOS",
		Hostname:    "DebugTestNode",
	}

	registrationId, err := types.RegistrationIDFromString(request.GetKey())
	if err != nil {
		return nil, err
	}

	newNode := types.RegisterNode{
		Node: types.Node{
			NodeKey:    key.NewNode().Public(),
			MachineKey: key.NewMachine().Public(),
			Hostname:   request.GetName(),
			User:       *user,

			Expiry:   &time.Time{},
			LastSeen: &time.Time{},

			Hostinfo: &hostinfo,
		},
		Registered: make(chan struct{}),
	}

	log.Debug().
		Str("registration_id", registrationId.String()).
		Msg("adding debug machine via CLI, appending to registration cache")

	api.h.registrationCache.Set(
		registrationId,
		newNode,
	)

	return &v1.DebugCreateNodeResponse{Node: newNode.Node.Proto()}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
