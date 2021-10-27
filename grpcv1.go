//nolint
package headscale

import (
	"context"

	apiV1 "github.com/juanfont/headscale/gen/go/v1"
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
) (*apiV1.Machine, error) {
	m, err := api.h.GetMachineByID(request.MachineId)
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): Make this function actually do something
	return &apiV1.Machine{Name: m.Name}, nil
}

func (api headscaleV1APIServer) mustEmbedUnimplementedHeadscaleServiceServer() {}
