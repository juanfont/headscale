package types

import (
	"fmt"
	"net/netip"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
)

type Route struct {
	gorm.Model

	NodeID uint64
	Node   Node

	// TODO(kradalby): change this custom type to netip.Prefix
	Prefix IPPrefix

	Advertised bool
	Enabled    bool
	IsPrimary  bool
}

type Routes []Route

func (r *Route) String() string {
	return fmt.Sprintf("%s:%s", r.Node.Hostname, netip.Prefix(r.Prefix).String())
}

func (r *Route) IsExitRoute() bool {
	return tsaddr.IsExitRoute(netip.Prefix(r.Prefix))
}

func (r *Route) IsAnnouncable() bool {
	return r.Advertised && r.Enabled
}

func (rs Routes) Prefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		prefixes[i] = netip.Prefix(r.Prefix)
	}

	return prefixes
}

// Primaries returns Primary routes from a list of routes.
func (rs Routes) Primaries() Routes {
	res := make(Routes, 0)
	for _, route := range rs {
		if route.IsPrimary {
			res = append(res, route)
		}
	}

	return res
}

func (rs Routes) PrefixMap() map[IPPrefix][]Route {
	res := map[IPPrefix][]Route{}

	for _, route := range rs {
		if _, ok := res[route.Prefix]; ok {
			res[route.Prefix] = append(res[route.Prefix], route)
		} else {
			res[route.Prefix] = []Route{route}
		}
	}

	return res
}

func (rs Routes) Proto() []*v1.Route {
	protoRoutes := []*v1.Route{}

	for _, route := range rs {
		protoRoute := v1.Route{
			Id:         uint64(route.ID),
			Node:       route.Node.Proto(),
			Prefix:     netip.Prefix(route.Prefix).String(),
			Advertised: route.Advertised,
			Enabled:    route.Enabled,
			IsPrimary:  route.IsPrimary,
			CreatedAt:  timestamppb.New(route.CreatedAt),
			UpdatedAt:  timestamppb.New(route.UpdatedAt),
		}

		if route.DeletedAt.Valid {
			protoRoute.DeletedAt = timestamppb.New(route.DeletedAt.Time)
		}

		protoRoutes = append(protoRoutes, &protoRoute)
	}

	return protoRoutes
}
