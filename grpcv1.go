//nolint
package headscale

import (
	"context"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"
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

func (api headscaleV1APIServer) GetNamespace(
	ctx context.Context,
	request *v1.GetNamespaceRequest,
) (*v1.GetNamespaceResponse, error) {
	namespace, err := api.h.GetNamespace(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.GetNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api headscaleV1APIServer) CreateNamespace(
	ctx context.Context,
	request *v1.CreateNamespaceRequest,
) (*v1.CreateNamespaceResponse, error) {
	namespace, err := api.h.CreateNamespace(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.CreateNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api headscaleV1APIServer) RenameNamespace(
	ctx context.Context,
	request *v1.RenameNamespaceRequest,
) (*v1.RenameNamespaceResponse, error) {
	err := api.h.RenameNamespace(request.GetOldName(), request.GetNewName())
	if err != nil {
		return nil, err
	}

	namespace, err := api.h.GetNamespace(request.GetNewName())
	if err != nil {
		return nil, err
	}

	return &v1.RenameNamespaceResponse{Namespace: namespace.toProto()}, nil
}

func (api headscaleV1APIServer) DeleteNamespace(
	ctx context.Context,
	request *v1.DeleteNamespaceRequest,
) (*v1.DeleteNamespaceResponse, error) {
	err := api.h.DestroyNamespace(request.GetName())
	if err != nil {
		return nil, err
	}

	return &v1.DeleteNamespaceResponse{}, nil
}

func (api headscaleV1APIServer) ListNamespaces(
	ctx context.Context,
	request *v1.ListNamespacesRequest,
) (*v1.ListNamespacesResponse, error) {
	namespaces, err := api.h.ListNamespaces()
	if err != nil {
		return nil, err
	}

	response := make([]*v1.Namespace, len(namespaces))
	for index, namespace := range namespaces {
		response[index] = namespace.toProto()
	}

	log.Trace().Caller().Interface("namespaces", response).Msg("")

	return &v1.ListNamespacesResponse{Namespaces: response}, nil
}

func (api headscaleV1APIServer) CreatePreAuthKey(
	ctx context.Context,
	request *v1.CreatePreAuthKeyRequest,
) (*v1.CreatePreAuthKeyResponse, error) {
	var expiration time.Time
	if request.GetExpiration() != nil {
		expiration = request.GetExpiration().AsTime()
	}

	preAuthKey, err := api.h.CreatePreAuthKey(
		request.GetNamespace(),
		request.GetReusable(),
		request.GetEphemeral(),
		&expiration,
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
	preAuthKey, err := api.h.GetPreAuthKey(request.GetNamespace(), request.Key)
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
	preAuthKeys, err := api.h.ListPreAuthKeys(request.GetNamespace())
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
		Str("namespace", request.GetNamespace()).
		Str("machine_key", request.GetKey()).
		Msg("Registering machine")

	machine, err := api.h.RegisterMachineFromAuthCallback(
		request.GetKey(),
		request.GetNamespace(),
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
		if strings.Index(tag, "tag:") != 0 {
			return &v1.SetTagsResponse{
					Machine: nil,
				}, status.Error(
					codes.InvalidArgument,
					"Invalid tag detected. Each tag must start with the string 'tag:'",
				)
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
	if request.GetNamespace() != "" {
		machines, err := api.h.ListMachinesInNamespace(request.GetNamespace())
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

	err = api.h.SetMachineNamespace(machine, request.GetNamespace())
	if err != nil {
		return nil, err
	}

	return &v1.MoveMachineResponse{Machine: machine.toProto()}, nil
}

func (api headscaleV1APIServer) GetMachineRoute(
	ctx context.Context,
	request *v1.GetMachineRouteRequest,
) (*v1.GetMachineRouteResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	return &v1.GetMachineRouteResponse{
		Routes: machine.RoutesToProto(),
	}, nil
}

func (api headscaleV1APIServer) EnableMachineRoutes(
	ctx context.Context,
	request *v1.EnableMachineRoutesRequest,
) (*v1.EnableMachineRoutesResponse, error) {
	machine, err := api.h.GetMachineByID(request.GetMachineId())
	if err != nil {
		return nil, err
	}

	err = api.h.EnableRoutes(machine, request.GetRoutes()...)
	if err != nil {
		return nil, err
	}

	return &v1.EnableMachineRoutesResponse{
		Routes: machine.RoutesToProto(),
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
	namespace, err := api.h.GetNamespace(request.GetNamespace())
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

	givenName, err := api.h.GenerateGivenName(request.GetName())
	if err != nil {
		return nil, err
	}

	newMachine := Machine{
		MachineKey: request.GetKey(),
		Hostname:   request.GetName(),
		GivenName:  givenName,
		Namespace:  *namespace,

		Expiry:               &time.Time{},
		LastSeen:             &time.Time{},
		LastSuccessfulUpdate: &time.Time{},

		HostInfo: HostInfo(hostinfo),
	}

	api.h.registrationCache.Set(
		request.GetKey(),
		newMachine,
		registerCacheExpiration,
	)

	return &v1.DebugCreateMachineResponse{Machine: newMachine.toProto()}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
