package db

import (
	"errors"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/types/key"
)

var ErrRouteIsNotAvailable = errors.New("route is not available")

func GetRoutes(tx *gorm.DB) (types.Routes, error) {
	var routes types.Routes
	err := tx.
		Preload("Node").
		Preload("Node.User").
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func getAdvertisedAndEnabledRoutes(tx *gorm.DB) (types.Routes, error) {
	var routes types.Routes
	err := tx.
		Preload("Node").
		Preload("Node.User").
		Where("advertised = ? AND enabled = ?", true, true).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func getRoutesByPrefix(tx *gorm.DB, pref netip.Prefix) (types.Routes, error) {
	var routes types.Routes
	err := tx.
		Preload("Node").
		Preload("Node.User").
		Where("prefix = ?", types.IPPrefix(pref)).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func GetNodeAdvertisedRoutes(tx *gorm.DB, node *types.Node) (types.Routes, error) {
	var routes types.Routes
	err := tx.
		Preload("Node").
		Preload("Node.User").
		Where("node_id = ? AND advertised = true", node.ID).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) GetNodeRoutes(node *types.Node) (types.Routes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Routes, error) {
		return GetNodeRoutes(rx, node)
	})
}

func GetNodeRoutes(tx *gorm.DB, node *types.Node) (types.Routes, error) {
	var routes types.Routes
	err := tx.
		Preload("Node").
		Preload("Node.User").
		Where("node_id = ?", node.ID).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return routes, nil
}

func GetRoute(tx *gorm.DB, id uint64) (*types.Route, error) {
	var route types.Route
	err := tx.
		Preload("Node").
		Preload("Node.User").
		First(&route, id).Error
	if err != nil {
		return nil, err
	}

	return &route, nil
}

func EnableRoute(tx *gorm.DB, id uint64) (*types.StateUpdate, error) {
	route, err := GetRoute(tx, id)
	if err != nil {
		return nil, err
	}

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if route.IsExitRoute() {
		return enableRoutes(
			tx,
			&route.Node,
			types.ExitRouteV4.String(),
			types.ExitRouteV6.String(),
		)
	}

	return enableRoutes(tx, &route.Node, netip.Prefix(route.Prefix).String())
}

func DisableRoute(tx *gorm.DB,
	id uint64,
	isConnected map[key.MachinePublic]bool,
) (*types.StateUpdate, error) {
	route, err := GetRoute(tx, id)
	if err != nil {
		return nil, err
	}

	var routes types.Routes
	node := route.Node

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	var update *types.StateUpdate
	if !route.IsExitRoute() {
		update, err = failoverRouteReturnUpdate(tx, isConnected, route)
		if err != nil {
			return nil, err
		}

		route.Enabled = false
		route.IsPrimary = false
		err = tx.Save(route).Error
		if err != nil {
			return nil, err
		}
	} else {
		routes, err = GetNodeRoutes(tx, &node)
		if err != nil {
			return nil, err
		}

		for i := range routes {
			if routes[i].IsExitRoute() {
				routes[i].Enabled = false
				routes[i].IsPrimary = false
				err = tx.Save(&routes[i]).Error
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if routes == nil {
		routes, err = GetNodeRoutes(tx, &node)
		if err != nil {
			return nil, err
		}
	}

	node.Routes = routes

	// If update is empty, it means that one was not created
	// by failover (as a failover was not necessary), create
	// one and return to the caller.
	if update == nil {
		update = &types.StateUpdate{
			Type: types.StatePeerChanged,
			ChangeNodes: types.Nodes{
				&node,
			},
			Message: "called from db.DisableRoute",
		}
	}

	return update, nil
}

func (hsdb *HSDatabase) DeleteRoute(
	id uint64,
	isConnected map[key.MachinePublic]bool,
) (*types.StateUpdate, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return DeleteRoute(tx, id, isConnected)
	})
}

func DeleteRoute(
	tx *gorm.DB,
	id uint64,
	isConnected map[key.MachinePublic]bool,
) (*types.StateUpdate, error) {
	route, err := GetRoute(tx, id)
	if err != nil {
		return nil, err
	}

	var routes types.Routes
	node := route.Node

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	var update *types.StateUpdate
	if !route.IsExitRoute() {
		update, err = failoverRouteReturnUpdate(tx, isConnected, route)
		if err != nil {
			return nil, nil
		}

		if err := tx.Unscoped().Delete(&route).Error; err != nil {
			return nil, err
		}
	} else {
		routes, err := GetNodeRoutes(tx, &node)
		if err != nil {
			return nil, err
		}

		routesToDelete := types.Routes{}
		for _, r := range routes {
			if r.IsExitRoute() {
				routesToDelete = append(routesToDelete, r)
			}
		}

		if err := tx.Unscoped().Delete(&routesToDelete).Error; err != nil {
			return nil, err
		}
	}

	// If update is empty, it means that one was not created
	// by failover (as a failover was not necessary), create
	// one and return to the caller.
	if routes == nil {
		routes, err = GetNodeRoutes(tx, &node)
		if err != nil {
			return nil, err
		}
	}

	node.Routes = routes

	if update == nil {
		update = &types.StateUpdate{
			Type: types.StatePeerChanged,
			ChangeNodes: types.Nodes{
				&node,
			},
			Message: "called from db.DeleteRoute",
		}
	}

	return update, nil
}

func deleteNodeRoutes(tx *gorm.DB, node *types.Node, isConnected map[key.MachinePublic]bool) error {
	routes, err := GetNodeRoutes(tx, node)
	if err != nil {
		return err
	}

	for i := range routes {
		if err := tx.Unscoped().Delete(&routes[i]).Error; err != nil {
			return err
		}

		// TODO(kradalby): This is a bit too aggressive, we could probably
		// figure out which routes needs to be failed over rather than all.
		failoverRouteReturnUpdate(tx, isConnected, &routes[i])
	}

	return nil
}

// isUniquePrefix returns if there is another node providing the same route already.
func isUniquePrefix(tx *gorm.DB, route types.Route) bool {
	var count int64
	tx.Model(&types.Route{}).
		Where("prefix = ? AND node_id != ? AND advertised = ? AND enabled = ?",
			route.Prefix,
			route.NodeID,
			true, true).Count(&count)

	return count == 0
}

func getPrimaryRoute(tx *gorm.DB, prefix netip.Prefix) (*types.Route, error) {
	var route types.Route
	err := tx.
		Preload("Node").
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

func (hsdb *HSDatabase) GetNodePrimaryRoutes(node *types.Node) (types.Routes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Routes, error) {
		return GetNodePrimaryRoutes(rx, node)
	})
}

// getNodePrimaryRoutes returns the routes that are enabled and marked as primary (for subnet failover)
// Exit nodes are not considered for this, as they are never marked as Primary.
func GetNodePrimaryRoutes(tx *gorm.DB, node *types.Node) (types.Routes, error) {
	var routes types.Routes
	err := tx.
		Preload("Node").
		Where("node_id = ? AND advertised = ? AND enabled = ? AND is_primary = ?", node.ID, true, true, true).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) SaveNodeRoutes(node *types.Node) (bool, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (bool, error) {
		return SaveNodeRoutes(tx, node)
	})
}

// SaveNodeRoutes takes a node and updates the database with
// the new routes.
// It returns a bool whether an update should be sent as the
// saved route impacts nodes.
func SaveNodeRoutes(tx *gorm.DB, node *types.Node) (bool, error) {
	sendUpdate := false

	currentRoutes := types.Routes{}
	err := tx.Where("node_id = ?", node.ID).Find(&currentRoutes).Error
	if err != nil {
		return sendUpdate, err
	}

	advertisedRoutes := map[netip.Prefix]bool{}
	for _, prefix := range node.Hostinfo.RoutableIPs {
		advertisedRoutes[prefix] = false
	}

	log.Trace().
		Str("node", node.Hostname).
		Interface("advertisedRoutes", advertisedRoutes).
		Interface("currentRoutes", currentRoutes).
		Msg("updating routes")

	for pos, route := range currentRoutes {
		if _, ok := advertisedRoutes[netip.Prefix(route.Prefix)]; ok {
			if !route.Advertised {
				currentRoutes[pos].Advertised = true
				err := tx.Save(&currentRoutes[pos]).Error
				if err != nil {
					return sendUpdate, err
				}

				// If a route that is newly "saved" is already
				// enabled, set sendUpdate to true as it is now
				// available.
				if route.Enabled {
					sendUpdate = true
				}
			}
			advertisedRoutes[netip.Prefix(route.Prefix)] = true
		} else if route.Advertised {
			currentRoutes[pos].Advertised = false
			currentRoutes[pos].Enabled = false
			err := tx.Save(&currentRoutes[pos]).Error
			if err != nil {
				return sendUpdate, err
			}
		}
	}

	for prefix, exists := range advertisedRoutes {
		if !exists {
			route := types.Route{
				NodeID:     node.ID,
				Prefix:     types.IPPrefix(prefix),
				Advertised: true,
				Enabled:    false,
			}
			err := tx.Create(&route).Error
			if err != nil {
				return sendUpdate, err
			}
		}
	}

	return sendUpdate, nil
}

// EnsureFailoverRouteIsAvailable takes a node and checks if the node's route
// currently have a functioning host that exposes the network.
func EnsureFailoverRouteIsAvailable(
	tx *gorm.DB,
	isConnected map[key.MachinePublic]bool,
	node *types.Node,
) (*types.StateUpdate, error) {
	nodeRoutes, err := GetNodeRoutes(tx, node)
	if err != nil {
		return nil, nil
	}

	var changedNodes types.Nodes
	for _, nodeRoute := range nodeRoutes {
		routes, err := getRoutesByPrefix(tx, netip.Prefix(nodeRoute.Prefix))
		if err != nil {
			return nil, err
		}

		for _, route := range routes {
			if route.IsPrimary {
				// if we have a primary route, and the node is connected
				// nothing needs to be done.
				if isConnected[route.Node.MachineKey] {
					continue
				}

				// if not, we need to failover the route
				update, err := failoverRouteReturnUpdate(tx, isConnected, &route)
				if err != nil {
					return nil, err
				}

				if update != nil {
					changedNodes = append(changedNodes, update.ChangeNodes...)
				}
			}
		}
	}

	if len(changedNodes) != 0 {
		return &types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: changedNodes,
			Message:     "called from db.EnsureFailoverRouteIsAvailable",
		}, nil
	}

	return nil, nil
}

func failoverRouteReturnUpdate(
	tx *gorm.DB,
	isConnected map[key.MachinePublic]bool,
	r *types.Route,
) (*types.StateUpdate, error) {
	changedKeys, err := failoverRoute(tx, isConnected, r)
	if err != nil {
		return nil, err
	}

	log.Trace().
		Interface("isConnected", isConnected).
		Interface("changedKeys", changedKeys).
		Msg("building route failover")

	if len(changedKeys) == 0 {
		return nil, nil
	}

	var nodes types.Nodes
	for _, key := range changedKeys {
		node, err := GetNodeByMachineKey(tx, key)
		if err != nil {
			return nil, err
		}

		nodes = append(nodes, node)
	}

	return &types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: nodes,
		Message:     "called from db.failoverRouteReturnUpdate",
	}, nil
}

// failoverRoute takes a route that is no longer available,
// this can be either from:
// - being disabled
// - being deleted
// - host going offline
//
// and tries to find a new route to take over its place.
// If the given route was not primary, it returns early.
func failoverRoute(
	tx *gorm.DB,
	isConnected map[key.MachinePublic]bool,
	r *types.Route,
) ([]key.MachinePublic, error) {
	if r == nil {
		return nil, nil
	}

	// This route is not a primary route, and it is not
	// being served to nodes.
	if !r.IsPrimary {
		return nil, nil
	}

	// We do not have to failover exit nodes
	if r.IsExitRoute() {
		return nil, nil
	}

	routes, err := getRoutesByPrefix(tx, netip.Prefix(r.Prefix))
	if err != nil {
		return nil, err
	}

	var newPrimary *types.Route

	// Find a new suitable route
	for idx, route := range routes {
		if r.ID == route.ID {
			continue
		}

		if !route.Enabled {
			continue
		}

		if isConnected[route.Node.MachineKey] {
			newPrimary = &routes[idx]
			break
		}
	}

	// If a new route was not found/available,
	// return without an error.
	// We do not want to update the database as
	// the one currently marked as primary is the
	// best we got.
	if newPrimary == nil {
		return nil, nil
	}

	log.Trace().
		Str("hostname", newPrimary.Node.Hostname).
		Msg("found new primary, updating db")

	// Remove primary from the old route
	r.IsPrimary = false
	err = tx.Save(&r).Error
	if err != nil {
		log.Error().Err(err).Msg("error disabling new primary route")

		return nil, err
	}

	log.Trace().
		Str("hostname", newPrimary.Node.Hostname).
		Msg("removed primary from old route")

	// Set primary for the new primary
	newPrimary.IsPrimary = true
	err = tx.Save(&newPrimary).Error
	if err != nil {
		log.Error().Err(err).Msg("error enabling new primary route")

		return nil, err
	}

	log.Trace().
		Str("hostname", newPrimary.Node.Hostname).
		Msg("set primary to new route")

	// Return a list of the machinekeys of the changed nodes.
	return []key.MachinePublic{r.Node.MachineKey, newPrimary.Node.MachineKey}, nil
}

func (hsdb *HSDatabase) EnableAutoApprovedRoutes(
	aclPolicy *policy.ACLPolicy,
	node *types.Node,
) (*types.StateUpdate, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return EnableAutoApprovedRoutes(tx, aclPolicy, node)
	})
}

// EnableAutoApprovedRoutes enables any routes advertised by a node that match the ACL autoApprovers policy.
func EnableAutoApprovedRoutes(
	tx *gorm.DB,
	aclPolicy *policy.ACLPolicy,
	node *types.Node,
) (*types.StateUpdate, error) {
	if len(node.IPAddresses) == 0 {
		return nil, nil // This node has no IPAddresses, so can't possibly match any autoApprovers ACLs
	}

	routes, err := GetNodeAdvertisedRoutes(tx, node)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get advertised routes for node")

		return nil, err
	}

	log.Trace().Interface("routes", routes).Msg("routes for autoapproving")

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
				Uint64("nodeId", node.ID).
				Msg("Failed to resolve autoApprovers for advertised route")

			return nil, err
		}

		log.Trace().
			Str("node", node.Hostname).
			Str("user", node.User.Name).
			Strs("routeApprovers", routeApprovers).
			Str("prefix", netip.Prefix(advertisedRoute.Prefix).String()).
			Msg("looking up route for autoapproving")

		for _, approvedAlias := range routeApprovers {
			if approvedAlias == node.User.Name {
				approvedRoutes = append(approvedRoutes, advertisedRoute)
			} else {
				// TODO(kradalby): figure out how to get this to depend on less stuff
				approvedIps, err := aclPolicy.ExpandAlias(types.Nodes{node}, approvedAlias)
				if err != nil {
					log.Err(err).
						Str("alias", approvedAlias).
						Msg("Failed to expand alias when processing autoApprovers policy")

					return nil, err
				}

				// approvedIPs should contain all of node's IPs if it matches the rule, so check for first
				if approvedIps.Contains(node.IPAddresses[0]) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	update := &types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: types.Nodes{},
		Message:     "created in db.EnableAutoApprovedRoutes",
	}

	for _, approvedRoute := range approvedRoutes {
		perHostUpdate, err := EnableRoute(tx, uint64(approvedRoute.ID))
		if err != nil {
			log.Err(err).
				Str("approvedRoute", approvedRoute.String()).
				Uint64("nodeId", node.ID).
				Msg("Failed to enable approved route")

			return nil, err
		}

		update.ChangeNodes = append(update.ChangeNodes, perHostUpdate.ChangeNodes...)
	}

	return update, nil
}
