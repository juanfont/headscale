package headscale

import (
	"encoding/json"
	"errors"

	"gorm.io/datatypes"
	"inet.af/netaddr"
)

// GetNodeRoutes returns the subnet routes advertised by a node (identified by
// namespace and node name)
func (h *Headscale) GetNodeRoutes(namespace string, nodeName string) (*[]netaddr.IPPrefix, error) {
	m, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return nil, err
	}

	hi, err := m.GetHostInfo()
	if err != nil {
		return nil, err
	}
	return &hi.RoutableIPs, nil
}

// EnableNodeRoute enables a subnet route advertised by a node (identified by
// namespace and node name)
func (h *Headscale) EnableNodeRoute(namespace string, nodeName string, routeStr string) (*netaddr.IPPrefix, error) {
	m, err := h.GetMachine(namespace, nodeName)
	if err != nil {
		return nil, err
	}
	hi, err := m.GetHostInfo()
	if err != nil {
		return nil, err
	}
	route, err := netaddr.ParseIPPrefix(routeStr)
	if err != nil {
		return nil, err
	}

	for _, rIP := range hi.RoutableIPs {
		if rIP == route {
			routes, _ := json.Marshal([]string{routeStr}) // TODO: only one for the time being, so overwriting the rest
			m.EnabledRoutes = datatypes.JSON(routes)
			h.db.Save(&m)

			err = h.RequestMapUpdates(m.NamespaceID)
			if err != nil {
				return nil, err
			}
			return &rIP, nil
		}
	}
	return nil, errors.New("could not find routable range")
}
