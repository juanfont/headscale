package db

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/util/set"
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
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
) ([]types.NodeID, error) {
	route, err := GetRoute(tx, id)
	if err != nil {
		return nil, err
	}

	var routes types.Routes
	node := route.Node

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	var update []types.NodeID
	if !route.IsExitRoute() {
		route.Enabled = false
		err = tx.Save(route).Error
		if err != nil {
			return nil, err
		}

		update, err = failoverRouteTx(tx, isLikelyConnected, route)
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

	// If update is empty, it means that one was not created
	// by failover (as a failover was not necessary), create
	// one and return to the caller.
	if update == nil {
		update = []types.NodeID{node.ID}
	}

	return update, nil
}

func (hsdb *HSDatabase) DeleteRoute(
	id uint64,
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
) ([]types.NodeID, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return DeleteRoute(tx, id, isLikelyConnected)
	})
}

func DeleteRoute(
	tx *gorm.DB,
	id uint64,
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
) ([]types.NodeID, error) {
	route, err := GetRoute(tx, id)
	if err != nil {
		return nil, err
	}

	var routes types.Routes
	node := route.Node

	// Tailscale requires both IPv4 and IPv6 exit routes to
	// be enabled at the same time, as per
	// https://github.com/juanfont/headscale/issues/804#issuecomment-1399314002
	var update []types.NodeID
	if !route.IsExitRoute() {
		update, err = failoverRouteTx(tx, isLikelyConnected, route)
		if err != nil {
			return nil, nil
		}

		if err := tx.Unscoped().Delete(&route).Error; err != nil {
			return nil, err
		}
	} else {
		routes, err = GetNodeRoutes(tx, &node)
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
		update = []types.NodeID{node.ID}
	}

	return update, nil
}

func deleteNodeRoutes(tx *gorm.DB, node *types.Node, isLikelyConnected *xsync.MapOf[types.NodeID, bool]) ([]types.NodeID, error) {
	routes, err := GetNodeRoutes(tx, node)
	if err != nil {
		return nil, fmt.Errorf("getting node routes: %w", err)
	}

	var changed []types.NodeID
	for i := range routes {
		if err := tx.Unscoped().Delete(&routes[i]).Error; err != nil {
			return nil, fmt.Errorf("deleting route(%d): %w", &routes[i].ID, err)
		}

		// TODO(kradalby): This is a bit too aggressive, we could probably
		// figure out which routes needs to be failed over rather than all.
		chn, err := failoverRouteTx(tx, isLikelyConnected, &routes[i])
		if err != nil {
			return changed, fmt.Errorf("failing over route after delete: %w", err)
		}

		if chn != nil {
			changed = append(changed, chn...)
		}
	}

	return changed, nil
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
				NodeID:     node.ID.Uint64(),
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

// FailoverNodeRoutesIfNeccessary takes a node and checks if the node's route
// need to be failed over to another host.
// If needed, the failover will be attempted.
func FailoverNodeRoutesIfNeccessary(
	tx *gorm.DB,
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
	node *types.Node,
) (*types.StateUpdate, error) {
	nodeRoutes, err := GetNodeRoutes(tx, node)
	if err != nil {
		return nil, nil
	}

	changedNodes := make(set.Set[types.NodeID])

nodeRouteLoop:
	for _, nodeRoute := range nodeRoutes {
		routes, err := getRoutesByPrefix(tx, netip.Prefix(nodeRoute.Prefix))
		if err != nil {
			return nil, fmt.Errorf("getting routes by prefix: %w", err)
		}

		for _, route := range routes {
			if route.IsPrimary {
				// if we have a primary route, and the node is connected
				// nothing needs to be done.
				if val, ok := isLikelyConnected.Load(route.Node.ID); ok && val {
					continue nodeRouteLoop
				}

				// if not, we need to failover the route
				failover := failoverRoute(isLikelyConnected, &route, routes)
				if failover != nil {
					err := failover.save(tx)
					if err != nil {
						return nil, fmt.Errorf("saving failover routes: %w", err)
					}

					changedNodes.Add(failover.old.Node.ID)
					changedNodes.Add(failover.new.Node.ID)

					continue nodeRouteLoop
				}
			}
		}
	}

	chng := changedNodes.Slice()
	sort.SliceStable(chng, func(i, j int) bool {
		return chng[i] < chng[j]
	})

	if len(changedNodes) != 0 {
		return &types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: chng,
			Message:     "called from db.FailoverNodeRoutesIfNeccessary",
		}, nil
	}

	return nil, nil
}

// failoverRouteTx takes a route that is no longer available,
// this can be either from:
// - being disabled
// - being deleted
// - host going offline
//
// and tries to find a new route to take over its place.
// If the given route was not primary, it returns early.
func failoverRouteTx(
	tx *gorm.DB,
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
	r *types.Route,
) ([]types.NodeID, error) {
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
		return nil, fmt.Errorf("getting routes by prefix: %w", err)
	}

	fo := failoverRoute(isLikelyConnected, r, routes)
	if fo == nil {
		return nil, nil
	}

	err = fo.save(tx)
	if err != nil {
		return nil, fmt.Errorf("saving failover route: %w", err)
	}

	log.Trace().
		Str("hostname", fo.new.Node.Hostname).
		Msgf("set primary to new route, was: id(%d), host(%s), now: id(%d), host(%s)", fo.old.ID, fo.old.Node.Hostname, fo.new.ID, fo.new.Node.Hostname)

	// Return a list of the machinekeys of the changed nodes.
	return []types.NodeID{fo.old.Node.ID, fo.new.Node.ID}, nil
}

type failover struct {
	old *types.Route
	new *types.Route
}

func (f *failover) save(tx *gorm.DB) error {
	err := tx.Save(f.old).Error
	if err != nil {
		return fmt.Errorf("saving old primary: %w", err)
	}

	err = tx.Save(f.new).Error
	if err != nil {
		return fmt.Errorf("saving new primary: %w", err)
	}

	return nil
}

func failoverRoute(
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
	routeToReplace *types.Route,
	altRoutes types.Routes,

) *failover {
	if routeToReplace == nil {
		return nil
	}

	// This route is not a primary route, and it is not
	// being served to nodes.
	if !routeToReplace.IsPrimary {
		return nil
	}

	// We do not have to failover exit nodes
	if routeToReplace.IsExitRoute() {
		return nil
	}

	var newPrimary *types.Route

	// Find a new suitable route
	for idx, route := range altRoutes {
		if routeToReplace.ID == route.ID {
			continue
		}

		if !route.Enabled {
			continue
		}

		if isLikelyConnected != nil {
			if val, ok := isLikelyConnected.Load(route.Node.ID); ok && val {
				newPrimary = &altRoutes[idx]
				break
			}
		}
	}

	// If a new route was not found/available,
	// return without an error.
	// We do not want to update the database as
	// the one currently marked as primary is the
	// best we got.
	if newPrimary == nil {
		return nil
	}

	routeToReplace.IsPrimary = false
	newPrimary.IsPrimary = true

	return &failover{
		old: routeToReplace,
		new: newPrimary,
	}
}

func (hsdb *HSDatabase) EnableAutoApprovedRoutes(
	aclPolicy *policy.ACLPolicy,
	node *types.Node,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return EnableAutoApprovedRoutes(tx, aclPolicy, node)
	})
}

// EnableAutoApprovedRoutes enables any routes advertised by a node that match the ACL autoApprovers policy.
func EnableAutoApprovedRoutes(
	tx *gorm.DB,
	aclPolicy *policy.ACLPolicy,
	node *types.Node,
) error {
	if node.IPv4 == nil && node.IPv6 == nil {
		return nil // This node has no IPAddresses, so can't possibly match any autoApprovers ACLs
	}

	routes, err := GetNodeAdvertisedRoutes(tx, node)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("getting advertised routes for node(%s %d): %w", node.Hostname, node.ID, err)
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
			return fmt.Errorf("failed to resolve autoApprovers for route(%d) for node(%s %d): %w", advertisedRoute.ID, node.Hostname, node.ID, err)
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
					return fmt.Errorf("expanding alias %q for autoApprovers: %w", approvedAlias, err)
				}

				// approvedIPs should contain all of node's IPs if it matches the rule, so check for first
				if approvedIps.Contains(*node.IPv4) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	for _, approvedRoute := range approvedRoutes {
		_, err := EnableRoute(tx, uint64(approvedRoute.ID))
		if err != nil {
			return fmt.Errorf("enabling approved route(%d): %w", approvedRoute.ID, err)
		}
	}

	return nil
}
