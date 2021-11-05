//nolint
package headscale

import (
	"context"

	apiV1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

type headscaleV1APIServer struct { // apiV1.HeadscaleServiceServer
	apiV1.UnimplementedHeadscaleServiceServer
	h *Headscale
}

func newHeadscaleV1APIServer(h *Headscale) apiV1.HeadscaleServiceServer {
	return headscaleV1APIServer{
		h: h,
	}
}

func (api headscaleV1APIServer) GetMachine(
	ctx context.Context,
	request *apiV1.GetMachineRequest,
) (*apiV1.GetMachineResponse, error) {
	// m, err := api.h.GetMachineByID(request.MachineId)
	// if err != nil {
	// 	return nil, err
	// }

	// TODO(kradalby): Make this function actually do something
	return &apiV1.GetMachineResponse{Name: "test"}, nil
}

func (api headscaleV1APIServer) CreateNamespace(
	ctx context.Context,
	request *apiV1.CreateNamespaceRequest,
) (*apiV1.CreateNamespaceResponse, error) {
	namespace, err := api.h.CreateNamespace(request.Name)
	if err != nil {
		return nil, err
	}

	return &apiV1.CreateNamespaceResponse{Name: namespace.Name}, nil
}

func (api headscaleV1APIServer) DeleteNamespace(
	ctx context.Context,
	request *apiV1.DeleteNamespaceRequest,
) (*apiV1.DeleteNamespaceResponse, error) {
	err := api.h.DestroyNamespace(request.Name)
	if err != nil {
		return nil, err
	}

	return &apiV1.DeleteNamespaceResponse{}, nil
}

func (api headscaleV1APIServer) ListNamespaces(
	ctx context.Context,
	request *apiV1.ListNamespacesRequest,
) (*apiV1.ListNamespacesResponse, error) {
	namespaces, err := api.h.ListNamespaces()
	if err != nil {
		return nil, err
	}

	response := make([]string, len(*namespaces))
	for index, namespace := range *namespaces {
		response[index] = namespace.Name
	}

	return &apiV1.ListNamespacesResponse{Namespaces: response}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
