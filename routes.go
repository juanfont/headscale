package headscale

import (
	"fmt"
	"net/netip"

	"gorm.io/gorm"
)

const (
	ErrRouteIsNotAvailable = Error("route is not available")
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

func (rs Routes) toPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		prefixes[i] = netip.Prefix(r.Prefix)
	}
	return prefixes
}

// getMachinePrimaryRoutes returns the routes that are enabled and marked as primary (for subnet failover)
// Exit nodes are not considered for this, as they are never marked as Primary
func (h *Headscale) getMachinePrimaryRoutes(m *Machine) ([]Route, error) {
	var routes []Route
	err := h.db.
		Preload("Machine").
		Where("machine_id = ? AND advertised = ? AND enabled = ? AND is_primary = ?", m.ID, true, true, true).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (h *Headscale) processMachineRoutes(machine *Machine) error {
	currentRoutes := []Route{}
	err := h.db.Where("machine_id = ?", machine.ID).Find(&currentRoutes).Error
	if err != nil {
		return err
	}

	advertisedRoutes := map[netip.Prefix]bool{}
	for _, prefix := range machine.HostInfo.RoutableIPs {
		advertisedRoutes[prefix] = false
	}

	for _, route := range currentRoutes {
		if _, ok := advertisedRoutes[netip.Prefix(route.Prefix)]; ok {
			if !route.Advertised {
				route.Advertised = true
				err := h.db.Save(&route).Error
				if err != nil {
					return err
				}
			}
			advertisedRoutes[netip.Prefix(route.Prefix)] = true
		} else {
			if route.Advertised {
				route.Advertised = false
				route.Enabled = false
				err := h.db.Save(&route).Error
				if err != nil {
					return err
				}
			}
		}
	}

	for prefix, exists := range advertisedRoutes {
		if !exists {
			route := Route{
				MachineID:  machine.ID,
				Prefix:     IPPrefix(prefix),
				Advertised: true,
				Enabled:    false,
			}
			err := h.db.Create(&route).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}
