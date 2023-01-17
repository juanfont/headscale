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

func (api headscaleV1APIServer) RegisterMachine(
	ctx context.Context,
	request *v1.RegisterMachineRequest,
) (*v1.RegisterMachineResponse, error) {
	log.Trace().
		Str("user", request.GetUser()).
		Str("node_key", request.GetKey()).
		Msg("Registering machine")

	machine, err := api.h.RegisterMachineFromAuthCallback(
		request.GetKey(),
		request.GetUser(),
		nil,
		RegisterMethodCLI,
	)
	if err != nil {
		return nil, err
	}

	return &v1.RegisterMachineResponse{Machine: machine.toProto()}, nil
}

func (api headscaleV1APIServer) GetMachine(
	ctx context.Context,
	request *v1.GetMachineRequest,
) (*v1.GetMachineResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	return &v1.GetMachineResponse{Machine: machine.toProto()}, nil
}

func (api headscaleV1APIServer) SetTags(
	ctx context.Context,
	request *v1.SetTagsRequest,
) (*v1.SetTagsResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	for _, tag := range request.GetTags() {
		err := validateTag(tag)
		if err != nil {
			return &v1.SetTagsResponse{
				Machine: nil,
			}, status.Error(codes.InvalidArgument, err.Error())
		}
	}

	err = api.h.SetTags(machine, request.GetTags())
	if err != nil {
		return &v1.SetTagsResponse{
			Machine: nil,
		}, status.Error(codes.Internal, err.Error())
	}

	log.Trace().
		Str("machine", machine.Hostname).
		Strs("tags", request.GetTags()).
		Msg("Changing tags of machine")

	return &v1.SetTagsResponse{Machine: machine.toProto()}, nil
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

func (api headscaleV1APIServer) DeleteMachine(
	ctx context.Context,
	request *v1.DeleteMachineRequest,
) (*v1.DeleteMachineResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	err = api.h.DeleteMachine(
		machine,
	)
	if err != nil {
		return nil, err
	}

	return &v1.DeleteMachineResponse{}, nil
}

func (api headscaleV1APIServer) ExpireMachine(
	ctx context.Context,
	request *v1.ExpireMachineRequest,
) (*v1.ExpireMachineResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	api.h.ExpireMachine(
		machine,
	)

	log.Trace().
		Str("machine", machine.Hostname).
		Time("expiry", *machine.Expiry).
		Msg("machine expired")

	return &v1.ExpireMachineResponse{Machine: machine.toProto()}, nil
}

func (api headscaleV1APIServer) RenameMachine(
	ctx context.Context,
	request *v1.RenameMachineRequest,
) (*v1.RenameMachineResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	err = api.h.RenameMachine(
		machine,
		request.GetNewName(),
	)
	if err != nil {
		return nil, err
	}

	log.Trace().
		Str("machine", machine.Hostname).
		Str("new_name", request.GetNewName()).
		Msg("machine renamed")

	return &v1.RenameMachineResponse{Machine: machine.toProto()}, nil
}

func (api headscaleV1APIServer) ListMachines(
	ctx context.Context,
	request *v1.ListMachinesRequest,
) (*v1.ListMachinesResponse, error) {
	if request.GetUser() != "" {
		machines, err := api.h.ListMachinesByUser(request.GetUser())
		if err != nil {
			return nil, err
		}

		response := make([]*v1.Machine, len(machines))
		for index, machine := range machines {
			response[index] = machine.toProto()
		}

		return &v1.ListMachinesResponse{Machines: response}, nil
	}

	machines, err := api.h.ListMachines()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.Machine, len(machines))
	for index, machine := range machines {
		m := machine.toProto()
		validTags, invalidTags := getTags(
			api.h.aclPolicy,
			machine,
			api.h.cfg.OIDC.StripEmaildomain,
		)
		m.InvalidTags = invalidTags
		m.ValidTags = validTags
		response[index] = m
	}

	return &v1.ListMachinesResponse{Machines: response}, nil
}

func (api headscaleV1APIServer) MoveMachine(
	ctx context.Context,
	request *v1.MoveMachineRequest,
) (*v1.MoveMachineResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	err = api.h.SetMachineUser(machine, request.GetUser())
	if err != nil {
		return nil, err
	}

	return &v1.MoveMachineResponse{Machine: machine.toProto()}, nil
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

func (api headscaleV1APIServer) GetMachineRoutes(
	ctx context.Context,
	request *v1.GetMachineRoutesRequest,
) (*v1.GetMachineRoutesResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	routes, err := api.h.GetMachineRoutes(machine)
	if err != nil {
		return nil, err
	}

	return &v1.GetMachineRoutesResponse{
		Routes: Routes(routes).toProto(),
	}, nil
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
func (api headscaleV1APIServer) DebugCreateMachine(
	ctx context.Context,
	request *v1.DebugCreateMachineRequest,
) (*v1.DebugCreateMachineResponse, error) {
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
		Hostname:    "DebugTestMachine",
	}

	givenName, err := api.h.GenerateGivenName(request.GetKey(), request.GetName())
	if err != nil {
		return nil, err
	}

	newMachine := Machine{
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
		log.Panic().Msg("can not add machine for debug. invalid node key")
	}

	api.h.registrationCache.Set(
		NodePublicKeyStripPrefix(nodeKey),
		newMachine,
		registerCacheExpiration,
	)

	return &v1.DebugCreateMachineResponse{Machine: newMachine.toProto()}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
