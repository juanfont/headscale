package types

import (
	"fmt"
	"net/netip"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
)

var (
	ExitRouteV4 = netip.MustParsePrefix("0.0.0.0/0")
	ExitRouteV6 = netip.MustParsePrefix("::/0")
)

type Route struct {
	gorm.Model

	MachineID uint64
	Machine   Machine
	Prefix    IPPrefix

	Advertised bool
	Enabled    bool
	IsPrimary  bool
}

type Routes []Route

func (r *Route) String() string {
	return fmt.Sprintf("%s:%s", r.Machine, netip.Prefix(r.Prefix).String())
}

func (r *Route) IsExitRoute() bool {
	return netip.Prefix(r.Prefix) == ExitRouteV4 || netip.Prefix(r.Prefix) == ExitRouteV6
}

func (rs Routes) Prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		prefixes[i] = netip.Prefix(r.Prefix)
	}

	return prefixes
}

func (r *Route) Proto() *v1.Route {
	return &v1.Route{
		Id:         uint64(r.ID),
		Machine:    r.Machine.Proto(),
		Prefix:     netip.Prefix(r.Prefix).String(),
		Advertised: r.Advertised,
		Enabled:    r.Enabled,
		IsPrimary:  r.IsPrimary,
		CreatedAt:  timestamppb.New(r.CreatedAt),
		UpdatedAt:  timestamppb.New(r.UpdatedAt),
	}
}

func (rs Routes) Proto() []*v1.Route {
	protoRoutes := []*v1.Route{}

	for _, route := range rs {
		protoRoute := route.Proto()

		if route.DeletedAt.Valid {
			protoRoute.DeletedAt = timestamppb.New(route.DeletedAt.Time)
		}

		protoRoutes = append(protoRoutes, protoRoute)
	}

	return protoRoutes
}
