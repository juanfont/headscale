package db

import (
	"errors"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

var ErrRouteIsNotAvailable = errors.New("route is not available")

func (hsdb *HSDatabase) GetRoutes() (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.Preload("Machine").Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) GetMachineAdvertisedRoutes(machine *types.Machine) (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Machine").
		Where("machine_id = ? AND advertised = true", machine.ID).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) GetMachineRoutes(m *types.Machine) (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Machine").
		Where("machine_id = ?", m.ID).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) GetRoute(id uint64) (*types.Route, error) {
	var route types.Route
	err := hsdb.db.Preload("Machine").First(&route, id).Error
	if err != nil {
		return nil, err
	}

	return &route, nil
}

func (hsdb *HSDatabase) EnableRoute(id uint64) error {
	route, err := hsdb.GetRoute(id)
	if err != nil {
		return err
	}

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if route.IsExitRoute() {
		return hsdb.enableRoutes(
			&route.Machine,
			types.ExitRouteV4.String(),
			types.ExitRouteV6.String(),
		)
	}

	return hsdb.enableRoutes(&route.Machine, netip.Prefix(route.Prefix).String())
}

func (hsdb *HSDatabase) DisableRoute(id uint64) error {
	route, err := hsdb.GetRoute(id)
	if err != nil {
		return err
	}

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if !route.IsExitRoute() {
		route.Enabled = false
		route.IsPrimary = false
		err = hsdb.db.Save(route).Error
		if err != nil {
			return err
		}

		return hsdb.HandlePrimarySubnetFailover()
	}

	routes, err := hsdb.GetMachineRoutes(&route.Machine)
	if err != nil {
		return err
	}

	for i := range routes {
		if routes[i].IsExitRoute() {
			routes[i].Enabled = false
			routes[i].IsPrimary = false
			err = hsdb.db.Save(&routes[i]).Error
			if err != nil {
				return err
			}
		}
	}

	return hsdb.HandlePrimarySubnetFailover()
}

func (hsdb *HSDatabase) DeleteRoute(id uint64) error {
	route, err := hsdb.GetRoute(id)
	if err != nil {
		return err
	}

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if !route.IsExitRoute() {
		if err := hsdb.db.Unscoped().Delete(&route).Error; err != nil {
			return err
		}

		return hsdb.HandlePrimarySubnetFailover()
	}

	routes, err := hsdb.GetMachineRoutes(&route.Machine)
	if err != nil {
		return err
	}

	routesToDelete := types.Routes{}
	for _, r := range routes {
		if r.IsExitRoute() {
			routesToDelete = append(routesToDelete, r)
		}
	}

	if err := hsdb.db.Unscoped().Delete(&routesToDelete).Error; err != nil {
		return err
	}

	return hsdb.HandlePrimarySubnetFailover()
}

func (hsdb *HSDatabase) DeleteMachineRoutes(m *types.Machine) error {
	routes, err := hsdb.GetMachineRoutes(m)
	if err != nil {
		return err
	}

	for i := range routes {
		if err := hsdb.db.Unscoped().Delete(&routes[i]).Error; err != nil {
			return err
		}
	}

	return hsdb.HandlePrimarySubnetFailover()
}

// isUniquePrefix returns if there is another machine providing the same route already.
func (hsdb *HSDatabase) isUniquePrefix(route types.Route) bool {
	var count int64
	hsdb.db.
		Model(&types.Route{}).
		Where("prefix = ? AND machine_id != ? AND advertised = ? AND enabled = ?",
			route.Prefix,
			route.MachineID,
			true, true).Count(&count)

	return count == 0
}

func (hsdb *HSDatabase) getPrimaryRoute(prefix netip.Prefix) (*types.Route, error) {
	var route types.Route
	err := hsdb.db.
		Preload("Machine").
		Where("prefix = ? AND advertised = ? AND enabled = ? AND is_primary = ?", types.IPPrefix(prefix), true, true, true).
		First(&route).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, gorm.ErrRecordNotFound
	}

	return &route, nil
}

// getMachinePrimaryRoutes returns the routes that are enabled and marked as primary (for subnet failover)
// Exit nodes are not considered for this, as they are never marked as Primary.
func (hsdb *HSDatabase) GetMachinePrimaryRoutes(m *types.Machine) (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Machine").
		Where("machine_id = ? AND advertised = ? AND enabled = ? AND is_primary = ?", m.ID, true, true, true).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) ProcessMachineRoutes(machine *types.Machine) error {
	currentRoutes := types.Routes{}
	err := hsdb.db.Where("machine_id = ?", machine.ID).Find(&currentRoutes).Error
	if err != nil {
		return err
	}

	advertisedRoutes := map[netip.Prefix]bool{}
	for _, prefix := range machine.HostInfo.RoutableIPs {
		advertisedRoutes[prefix] = false
	}

	for pos, route := range currentRoutes {
		if _, ok := advertisedRoutes[netip.Prefix(route.Prefix)]; ok {
			if !route.Advertised {
				currentRoutes[pos].Advertised = true
				err := hsdb.db.Save(&currentRoutes[pos]).Error
				if err != nil {
					return err
				}
			}
			advertisedRoutes[netip.Prefix(route.Prefix)] = true
		} else if route.Advertised {
			currentRoutes[pos].Advertised = false
			currentRoutes[pos].Enabled = false
			err := hsdb.db.Save(&currentRoutes[pos]).Error
			if err != nil {
				return err
			}
		}
	}

	for prefix, exists := range advertisedRoutes {
		if !exists {
			route := types.Route{
				MachineID:  machine.ID,
				Prefix:     types.IPPrefix(prefix),
				Advertised: true,
				Enabled:    false,
			}
			err := hsdb.db.Create(&route).Error
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (hsdb *HSDatabase) HandlePrimarySubnetFailover() error {
	// first, get all the enabled routes
	var routes types.Routes
	err := hsdb.db.
		Preload("Machine").
		Where("advertised = ? AND enabled = ?", true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().Err(err).Msg("error getting routes")
	}

	routesChanged := false
	for pos, route := range routes {
		if route.IsExitRoute() {
			continue
		}

		if !route.IsPrimary {
			_, err := hsdb.getPrimaryRoute(netip.Prefix(route.Prefix))
			if hsdb.isUniquePrefix(route) || errors.Is(err, gorm.ErrRecordNotFound) {
				log.Info().
					Str("prefix", netip.Prefix(route.Prefix).String()).
					Str("machine", route.Machine.GivenName).
					Msg("Setting primary route")
				routes[pos].IsPrimary = true
				err := hsdb.db.Save(&routes[pos]).Error
				if err != nil {
					log.Error().Err(err).Msg("error marking route as primary")

					return err
				}

				routesChanged = true

				continue
			}
		}

		if route.IsPrimary {
			if route.Machine.IsOnline() {
				continue
			}

			// machine offline, find a new primary
			log.Info().
				Str("machine", route.Machine.Hostname).
				Str("prefix", netip.Prefix(route.Prefix).String()).
				Msgf("machine offline, finding a new primary subnet")

			// find a new primary route
			var newPrimaryRoutes types.Routes
			err := hsdb.db.
				Preload("Machine").
				Where("prefix = ? AND machine_id != ? AND advertised = ? AND enabled = ?",
					route.Prefix,
					route.MachineID,
					true, true).
				Find(&newPrimaryRoutes).Error
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				log.Error().Err(err).Msg("error finding new primary route")

				return err
			}

			var newPrimaryRoute *types.Route
			for pos, r := range newPrimaryRoutes {
				if r.Machine.IsOnline() {
					newPrimaryRoute = &newPrimaryRoutes[pos]

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
			routes[pos].IsPrimary = false
			err = hsdb.db.Save(&routes[pos]).Error
			if err != nil {
				log.Error().Err(err).Msg("error disabling old primary route")

				return err
			}

			// enable the new primary route
			newPrimaryRoute.IsPrimary = true
			err = hsdb.db.Save(&newPrimaryRoute).Error
			if err != nil {
				log.Error().Err(err).Msg("error enabling new primary route")

				return err
			}

			routesChanged = true
		}
	}

	if routesChanged {
		hsdb.notifyStateChange()
	}

	return nil
}

// EnableAutoApprovedRoutes enables any routes advertised by a machine that match the ACL autoApprovers policy.
func (hsdb *HSDatabase) EnableAutoApprovedRoutes(
	aclPolicy *policy.ACLPolicy,
	machine *types.Machine,
) error {
	if len(machine.IPAddresses) == 0 {
		return nil // This machine has no IPAddresses, so can't possibly match any autoApprovers ACLs
	}

	routes, err := hsdb.GetMachineAdvertisedRoutes(machine)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Could not get advertised routes for machine")

		return err
	}

	approvedRoutes := types.Routes{}

	for _, advertisedRoute := range routes {
		if advertisedRoute.Enabled {
			continue
		}

		routeApprovers, err := aclPolicy.AutoApprovers.GetRouteApprovers(
			netip.Prefix(advertisedRoute.Prefix),
		)
		if err != nil {
			log.Err(err).
				Str("advertisedRoute", advertisedRoute.String()).
				Uint64("machineId", machine.ID).
				Msg("Failed to resolve autoApprovers for advertised route")

			return err
		}

		for _, approvedAlias := range routeApprovers {
			if approvedAlias == machine.User.Name {
				approvedRoutes = append(approvedRoutes, advertisedRoute)
			} else {
				// TODO(kradalby): figure out how to get this to depend on less stuff
				approvedIps, err := aclPolicy.ExpandAlias(*machine, types.Machines{}, approvedAlias)
				if err != nil {
					log.Err(err).
						Str("alias", approvedAlias).
						Msg("Failed to expand alias when processing autoApprovers policy")

					return err
				}

				// approvedIPs should contain all of machine's IPs if it matches the rule, so check for first
				if approvedIps.Contains(machine.IPAddresses[0]) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	for _, approvedRoute := range approvedRoutes {
		err := hsdb.EnableRoute(uint64(approvedRoute.ID))
		if err != nil {
			log.Err(err).
				Str("approvedRoute", approvedRoute.String()).
				Uint64("machineId", machine.ID).
				Msg("Failed to enable approved route")

			return err
		}
	}

	return nil
}
