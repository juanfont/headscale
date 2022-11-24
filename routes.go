package headscale

import (
	"fmt"
	"net/netip"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const (
	ErrRouteIsNotAvailable = Error("route is not available")
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

func (r *Route) isExitRoute() bool {
	return netip.Prefix(r.Prefix) == ExitRouteV4 || netip.Prefix(r.Prefix) == ExitRouteV6
}

func (rs Routes) toPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, len(rs))
	for i, r := range rs {
		prefixes[i] = netip.Prefix(r.Prefix)
	}
	return prefixes
}

// isUniquePrefix returns if there is another machine providing the same route already
func (h *Headscale) isUniquePrefix(route Route) bool {
	var count int64
	h.db.
		Model(&Route{}).
		Where("prefix = ? AND machine_id != ? AND advertised = ? AND enabled = ?",
			route.Prefix,
			route.MachineID,
			true, true).Count(&count)
	return count == 0
}

func (h *Headscale) getPrimaryRoute(prefix netip.Prefix) (*Route, error) {
	var route Route
	err := h.db.
		Preload("Machine").
		Where("prefix = ? AND advertised = ? AND enabled = ? AND is_primary = ?", IPPrefix(prefix), true, true, true).
		First(&route).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}

	if err == gorm.ErrRecordNotFound {
		return nil, gorm.ErrRecordNotFound
	}

	return &route, nil
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

func (h *Headscale) handlePrimarySubnetFailover() error {
	// first, get all the enabled routes
	var routes []Route
	err := h.db.
		Preload("Machine").
		Where("advertised = ? AND enabled = ?", true, true).
		Find(&routes).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		log.Error().Err(err).Msg("error getting routes")
	}

	for _, route := range routes {
		if route.isExitRoute() {
			continue
		}

		if !route.IsPrimary {
			_, err := h.getPrimaryRoute(netip.Prefix(route.Prefix))
			if h.isUniquePrefix(route) || err == gorm.ErrRecordNotFound {
				route.IsPrimary = true
				err := h.db.Save(&route).Error
				if err != nil {
					log.Error().Err(err).Msg("error marking route as primary")

					return err
				}
				continue
			}
		}

		if route.IsPrimary {
			if route.Machine.isOnline() {
				continue
			}

			// machine offline, find a new primary
			log.Info().
				Str("machine", route.Machine.Hostname).
				Str("prefix", netip.Prefix(route.Prefix).String()).
				Msgf("machine offline, finding a new primary subnet")

			// find a new primary route
			var newPrimaryRoutes []Route
			err := h.db.
				Preload("Machine").
				Where("prefix = ? AND machine_id != ? AND advertised = ? AND enabled = ?",
					route.Prefix,
					route.MachineID,
					true, true).
				Find(&newPrimaryRoutes).Error
			if err != nil && err != gorm.ErrRecordNotFound {
				log.Error().Err(err).Msg("error finding new primary route")

				return err
			}

			var newPrimaryRoute *Route
			for _, r := range newPrimaryRoutes {
				if r.Machine.isOnline() {
					newPrimaryRoute = &r
					break
				}
			}

			if newPrimaryRoute == nil {
				log.Warn().
					Str("machine", route.Machine.Hostname).
					Str("prefix", netip.Prefix(route.Prefix).String()).
					Msgf("no alternative primary route found")
				continue
			}

			log.Info().
				Str("old_machine", route.Machine.Hostname).
				Str("prefix", netip.Prefix(route.Prefix).String()).
				Str("new_machine", newPrimaryRoute.Machine.Hostname).
				Msgf("found new primary route")

			// disable the old primary route
			route.IsPrimary = false
			err = h.db.Save(&route).Error
			if err != nil {
				log.Error().Err(err).Msg("error disabling old primary route")

				return err
			}

			// enable the new primary route
			newPrimaryRoute.IsPrimary = true
			err = h.db.Save(&newPrimaryRoute).Error
			if err != nil {
				log.Error().Err(err).Msg("error enabling new primary route")

				return err
			}
		}
	}

	return nil
}
