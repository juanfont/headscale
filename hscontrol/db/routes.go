package db

import (
	"errors"
	"net/netip"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"gorm.io/gorm"
	"tailscale.com/types/key"
)

var ErrRouteIsNotAvailable = errors.New("route is not available")

func (hsdb *HSDatabase) GetRoutes() (types.Routes, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getRoutes()
}

func (hsdb *HSDatabase) getRoutes() (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Node").
		Preload("Node.User").
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) getAdvertisedAndEnabledRoutes() (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Node").
		Preload("Node.User").
		Where("advertised = ? AND enabled = ?", true, true).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) getRoutesByPrefix(pref netip.Prefix) (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Node").
		Preload("Node.User").
		Where("prefix = ?", types.IPPrefix(pref)).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) GetNodeAdvertisedRoutes(node *types.Node) (types.Routes, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getNodeAdvertisedRoutes(node)
}

func (hsdb *HSDatabase) getNodeAdvertisedRoutes(node *types.Node) (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
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
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getNodeRoutes(node)
}

func (hsdb *HSDatabase) getNodeRoutes(node *types.Node) (types.Routes, error) {
	var routes types.Routes
	err := hsdb.db.
		Preload("Node").
		Preload("Node.User").
		Where("node_id = ?", node.ID).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	return routes, nil
}

func (hsdb *HSDatabase) GetRoute(id uint64) (*types.Route, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getRoute(id)
}

func (hsdb *HSDatabase) getRoute(id uint64) (*types.Route, error) {
	var route types.Route
	err := hsdb.db.
		Preload("Node").
		Preload("Node.User").
		First(&route, id).Error
	if err != nil {
		return nil, err
	}

	return &route, nil
}

func (hsdb *HSDatabase) EnableRoute(id uint64) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.enableRoute(id)
}

func (hsdb *HSDatabase) enableRoute(id uint64) error {
	route, err := hsdb.getRoute(id)
	if err != nil {
		return err
	}

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if route.IsExitRoute() {
		return hsdb.enableRoutes(
			&route.Node,
			types.ExitRouteV4.String(),
			types.ExitRouteV6.String(),
		)
	}

	return hsdb.enableRoutes(&route.Node, netip.Prefix(route.Prefix).String())
}

func (hsdb *HSDatabase) DisableRoute(id uint64) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	route, err := hsdb.getRoute(id)
	if err != nil {
		return err
	}

	var routes types.Routes
	node := route.Node

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if !route.IsExitRoute() {
		err = hsdb.failoverRouteWithNotify(route)
		if err != nil {
			return err
		}

		route.Enabled = false
		route.IsPrimary = false
		err = hsdb.db.Save(route).Error
		if err != nil {
			return err
		}
	} else {
		routes, err = hsdb.getNodeRoutes(&node)
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
	}

	if routes == nil {
		routes, err = hsdb.getNodeRoutes(&node)
		if err != nil {
			return err
		}
	}

	node.Routes = routes

	stateUpdate := types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: types.Nodes{&node},
		Message:     "called from db.DisableRoute",
	}
	if stateUpdate.Valid() {
		hsdb.notifier.NotifyAll(stateUpdate)
	}

	return nil
}

func (hsdb *HSDatabase) DeleteRoute(id uint64) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	route, err := hsdb.getRoute(id)
	if err != nil {
		return err
	}

	var routes types.Routes
	node := route.Node

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	if !route.IsExitRoute() {
		err := hsdb.failoverRouteWithNotify(route)
		if err != nil {
			return nil
		}

		if err := hsdb.db.Unscoped().Delete(&route).Error; err != nil {
			return err
		}
	} else {
		routes, err := hsdb.getNodeRoutes(&node)
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
	}

	if routes == nil {
		routes, err = hsdb.getNodeRoutes(&node)
		if err != nil {
			return err
		}
	}

	node.Routes = routes

	stateUpdate := types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: types.Nodes{&node},
		Message:     "called from db.DeleteRoute",
	}
	if stateUpdate.Valid() {
		hsdb.notifier.NotifyAll(stateUpdate)
	}

	return nil
}

func (hsdb *HSDatabase) deleteNodeRoutes(node *types.Node) error {
	routes, err := hsdb.getNodeRoutes(node)
	if err != nil {
		return err
	}

	for i := range routes {
		if err := hsdb.db.Unscoped().Delete(&routes[i]).Error; err != nil {
			return err
		}

		// TODO(kradalby): This is a bit too aggressive, we could probably
		// figure out which routes needs to be failed over rather than all.
		hsdb.failoverRouteWithNotify(&routes[i])
	}

	return nil
}

// isUniquePrefix returns if there is another node providing the same route already.
func (hsdb *HSDatabase) isUniquePrefix(route types.Route) bool {
	var count int64
	hsdb.db.
		Model(&types.Route{}).
		Where("prefix = ? AND node_id != ? AND advertised = ? AND enabled = ?",
			route.Prefix,
			route.NodeID,
			true, true).Count(&count)

	return count == 0
}

func (hsdb *HSDatabase) getPrimaryRoute(prefix netip.Prefix) (*types.Route, error) {
	var route types.Route
	err := hsdb.db.
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

// getNodePrimaryRoutes returns the routes that are enabled and marked as primary (for subnet failover)
// Exit nodes are not considered for this, as they are never marked as Primary.
func (hsdb *HSDatabase) GetNodePrimaryRoutes(node *types.Node) (types.Routes, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	var routes types.Routes
	err := hsdb.db.
		Preload("Node").
		Where("node_id = ? AND advertised = ? AND enabled = ? AND is_primary = ?", node.ID, true, true, true).
		Find(&routes).Error
	if err != nil {
		return nil, err
	}

	return routes, nil
}

// SaveNodeRoutes takes a node and updates the database with
// the new routes.
// It returns a bool whether an update should be sent as the
// saved route impacts nodes.
func (hsdb *HSDatabase) SaveNodeRoutes(node *types.Node) (bool, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.saveNodeRoutes(node)
}

func (hsdb *HSDatabase) saveNodeRoutes(node *types.Node) (bool, error) {
	sendUpdate := false

	currentRoutes := types.Routes{}
	err := hsdb.db.Where("node_id = ?", node.ID).Find(&currentRoutes).Error
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
				err := hsdb.db.Save(&currentRoutes[pos]).Error
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
			err := hsdb.db.Save(&currentRoutes[pos]).Error
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
			err := hsdb.db.Create(&route).Error
			if err != nil {
				return sendUpdate, err
			}
		}
	}

	return sendUpdate, nil
}

// EnsureFailoverRouteIsAvailable takes a node and checks if the node's route
// currently have a functioning host that exposes the network.
func (hsdb *HSDatabase) EnsureFailoverRouteIsAvailable(node *types.Node) error {
	nodeRoutes, err := hsdb.getNodeRoutes(node)
	if err != nil {
		return nil
	}

	for _, nodeRoute := range nodeRoutes {
		routes, err := hsdb.getRoutesByPrefix(netip.Prefix(nodeRoute.Prefix))
		if err != nil {
			return err
		}

		for _, route := range routes {
			if route.IsPrimary {
				// if we have a primary route, and the node is connected
				// nothing needs to be done.
				if hsdb.notifier.IsConnected(route.Node.MachineKey) {
					continue
				}

				// if not, we need to failover the route
				err := hsdb.failoverRouteWithNotify(&route)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (hsdb *HSDatabase) FailoverNodeRoutesWithNotify(node *types.Node) error {
	routes, err := hsdb.getNodeRoutes(node)
	if err != nil {
		return nil
	}

	var changedKeys []key.MachinePublic

	for _, route := range routes {
		changed, err := hsdb.failoverRoute(&route)
		if err != nil {
			return err
		}

		changedKeys = append(changedKeys, changed...)
	}

	changedKeys = lo.Uniq(changedKeys)

	var nodes types.Nodes

	for _, key := range changedKeys {
		node, err := hsdb.GetNodeByMachineKey(key)
		if err != nil {
			return err
		}

		nodes = append(nodes, node)
	}

	if nodes != nil {
		stateUpdate := types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: nodes,
			Message:     "called from db.FailoverNodeRoutesWithNotify",
		}
		if stateUpdate.Valid() {
			hsdb.notifier.NotifyAll(stateUpdate)
		}
	}

	return nil
}

func (hsdb *HSDatabase) failoverRouteWithNotify(r *types.Route) error {
	changedKeys, err := hsdb.failoverRoute(r)
	if err != nil {
		return err
	}

	if len(changedKeys) == 0 {
		return nil
	}

	var nodes types.Nodes

	log.Trace().
		Str("hostname", r.Node.Hostname).
		Msg("loading machines with new primary routes from db")

	for _, key := range changedKeys {
		node, err := hsdb.getNodeByMachineKey(key)
		if err != nil {
			return err
		}

		nodes = append(nodes, node)
	}

	log.Trace().
		Str("hostname", r.Node.Hostname).
		Msg("notifying peers about primary route change")

	if nodes != nil {
		stateUpdate := types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: nodes,
			Message:     "called from db.failoverRouteWithNotify",
		}
		if stateUpdate.Valid() {
			hsdb.notifier.NotifyAll(stateUpdate)
		}
	}

	log.Trace().
		Str("hostname", r.Node.Hostname).
		Msg("notified peers about primary route change")

	return nil
}

// failoverRoute takes a route that is no longer available,
// this can be either from:
// - being disabled
// - being deleted
// - host going offline
//
// and tries to find a new route to take over its place.
// If the given route was not primary, it returns early.
func (hsdb *HSDatabase) failoverRoute(r *types.Route) ([]key.MachinePublic, error) {
	if r == nil {
		return nil, nil
	}

	// This route is not a primary route, and it isnt
	// being served to nodes.
	if !r.IsPrimary {
		return nil, nil
	}

	// We do not have to failover exit nodes
	if r.IsExitRoute() {
		return nil, nil
	}

	routes, err := hsdb.getRoutesByPrefix(netip.Prefix(r.Prefix))
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

		if hsdb.notifier.IsConnected(route.Node.MachineKey) {
			newPrimary = &routes[idx]
			break
		}
	}

	// If a new route was not found/available,
	// return with an error.
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
	err = hsdb.db.Save(&r).Error
	if err != nil {
		log.Error().Err(err).Msg("error disabling new primary route")

		return nil, err
	}

	log.Trace().
		Str("hostname", newPrimary.Node.Hostname).
		Msg("removed primary from old route")

	// Set primary for the new primary
	newPrimary.IsPrimary = true
	err = hsdb.db.Save(&newPrimary).Error
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

// EnableAutoApprovedRoutes enables any routes advertised by a node that match the ACL autoApprovers policy.
func (hsdb *HSDatabase) EnableAutoApprovedRoutes(
	aclPolicy *policy.ACLPolicy,
	node *types.Node,
) error {
	if len(aclPolicy.AutoApprovers.ExitNode) == 0 && len(aclPolicy.AutoApprovers.Routes) == 0 {
		// No autoapprovers configured
		return nil
	}

	if len(node.IPAddresses) == 0 {
		// This node has no IPAddresses, so can't possibly match any autoApprovers ACLs
		return nil
	}

	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	routes, err := hsdb.getNodeAdvertisedRoutes(node)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get advertised routes for node")

		return err
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

			return err
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

					return err
				}

				// approvedIPs should contain all of node's IPs if it matches the rule, so check for first
				if approvedIps.Contains(node.IPAddresses[0]) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	for _, approvedRoute := range approvedRoutes {
		err := hsdb.enableRoute(uint64(approvedRoute.ID))
		if err != nil {
			log.Err(err).
				Str("approvedRoute", approvedRoute.String()).
				Uint64("nodeId", node.ID).
				Msg("Failed to enable approved route")

			return err
		}
	}

	return nil
}
