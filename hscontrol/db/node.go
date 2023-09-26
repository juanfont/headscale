package db

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	NodeGivenNameHashLength = 8
	NodeGivenNameTrimSize   = 2
)

var (
	ErrNodeNotFound                  = errors.New("node not found")
	ErrNodeRouteIsNotAvailable       = errors.New("route is not available on node")
	ErrNodeNotFoundRegistrationCache = errors.New(
		"node not found in registration cache",
	)
	ErrCouldNotConvertNodeInterface = errors.New("failed to convert node interface")
	ErrDifferentRegisteredUser      = errors.New(
		"node was previously registered with a different user",
	)
)

// ListPeers returns all peers of node, regardless of any Policy or if the node is expired.
func (hsdb *HSDatabase) ListPeers(node *types.Node) (types.Nodes, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listPeers(node)
}

func (hsdb *HSDatabase) listPeers(node *types.Node) (types.Nodes, error) {
	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msg("Finding direct peers")

	nodes := types.Nodes{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("node_key <> ?",
			node.NodeKey).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msgf("Found peers: %s", nodes.String())

	return nodes, nil
}

func (hsdb *HSDatabase) ListNodes() ([]types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listNodes()
}

func (hsdb *HSDatabase) listNodes() ([]types.Node, error) {
	nodes := []types.Node{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) ListNodesByGivenName(givenName string) (types.Nodes, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.listNodesByGivenName(givenName)
}

func (hsdb *HSDatabase) listNodesByGivenName(givenName string) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("given_name = ?", givenName).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

// GetNode finds a Node by name and user and returns the Node struct.
func (hsdb *HSDatabase) GetNode(user string, name string) (*types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	nodes, err := hsdb.ListNodesByUser(user)
	if err != nil {
		return nil, err
	}

	for _, m := range nodes {
		if m.Hostname == name {
			return m, nil
		}
	}

	return nil, ErrNodeNotFound
}

// GetNodeByGivenName finds a Node by given name and user and returns the Node struct.
func (hsdb *HSDatabase) GetNodeByGivenName(
	user string,
	givenName string,
) (*types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	node := types.Node{}
	if err := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("given_name = ?", givenName).First(&node).Error; err != nil {
		return nil, err
	}

	return nil, ErrNodeNotFound
}

// GetNodeByID finds a Node by ID and returns the Node struct.
func (hsdb *HSDatabase) GetNodeByID(id uint64) (*types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	mach := types.Node{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&types.Node{ID: id}).First(&mach); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

// GetNodeByMachineKey finds a Node by its MachineKey and returns the Node struct.
func (hsdb *HSDatabase) GetNodeByMachineKey(
	machineKey key.MachinePublic,
) (*types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	mach := types.Node{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&mach, "machine_key = ?", util.MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

// GetNodeByNodeKey finds a Node by its current NodeKey.
func (hsdb *HSDatabase) GetNodeByNodeKey(
	nodeKey key.NodePublic,
) (*types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	node := types.Node{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&node, "node_key = ?",
			util.NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &node, nil
}

// GetNodeByAnyKey finds a Node by its MachineKey, its current NodeKey or the old one, and returns the Node struct.
func (hsdb *HSDatabase) GetNodeByAnyKey(
	machineKey key.MachinePublic, nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*types.Node, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	node := types.Node{}
	if result := hsdb.db.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&node, "machine_key = ? OR node_key = ? OR node_key = ?",
			util.MachinePublicKeyStripPrefix(machineKey),
			util.NodePublicKeyStripPrefix(nodeKey),
			util.NodePublicKeyStripPrefix(oldNodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &node, nil
}

func (hsdb *HSDatabase) NodeReloadFromDatabase(node *types.Node) error {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	if result := hsdb.db.Find(node).First(&node); result.Error != nil {
		return result.Error
	}

	return nil
}

// SetTags takes a Node struct pointer and update the forced tags.
func (hsdb *HSDatabase) SetTags(
	node *types.Node,
	tags []string,
) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	newTags := []string{}
	for _, tag := range tags {
		if !util.StringOrPrefixListContains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}

	if err := hsdb.db.Model(node).Updates(types.Node{
		ForcedTags: newTags,
	}).Error; err != nil {
		return fmt.Errorf("failed to update tags for node in the database: %w", err)
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Nodes{node},
	}, node.MachineKey)

	return nil
}

// RenameNode takes a Node struct and a new GivenName for the nodes
// and renames it.
func (hsdb *HSDatabase) RenameNode(node *types.Node, newName string) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	err := util.CheckForFQDNRules(
		newName,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "RenameNode").
			Str("node", node.Hostname).
			Str("newName", newName).
			Err(err).
			Msg("failed to rename node")

		return err
	}
	node.GivenName = newName

	if err := hsdb.db.Model(node).Updates(types.Node{
		GivenName: newName,
	}).Error; err != nil {
		return fmt.Errorf("failed to rename node in the database: %w", err)
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Nodes{node},
	}, node.MachineKey)

	return nil
}

// NodeSetExpiry takes a Node struct and  a new expiry time.
func (hsdb *HSDatabase) NodeSetExpiry(node *types.Node, expiry time.Time) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.nodeSetExpiry(node, expiry)
}

func (hsdb *HSDatabase) nodeSetExpiry(node *types.Node, expiry time.Time) error {
	if err := hsdb.db.Model(node).Updates(types.Node{
		Expiry: &expiry,
	}).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh node (update expiration) in the database: %w",
			err,
		)
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Nodes{node},
	}, node.MachineKey)

	return nil
}

// DeleteNode deletes a Node from the database.
func (hsdb *HSDatabase) DeleteNode(node *types.Node) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.deleteNode(node)
}

func (hsdb *HSDatabase) deleteNode(node *types.Node) error {
	err := hsdb.deleteNodeRoutes(node)
	if err != nil {
		return err
	}

	// Unscoped causes the node to be fully removed from the database.
	if err := hsdb.db.Unscoped().Delete(&types.Node{}, node.ID).Error; err != nil {
		return err
	}

	hsdb.notifier.NotifyAll(types.StateUpdate{
		Type:    types.StatePeerRemoved,
		Removed: []tailcfg.NodeID{tailcfg.NodeID(node.ID)},
	})

	return nil
}

// UpdateLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
// This is mostly used to indicate if a node is online and is not
// extremely important to make sure is fully correct and to avoid
// holding up the hot path, does not contain any locks and isnt
// concurrency safe. But that should be ok.
func (hsdb *HSDatabase) UpdateLastSeen(node *types.Node) error {
	return hsdb.db.Model(node).Updates(types.Node{
		LastSeen: node.LastSeen,
	}).Error
}

func (hsdb *HSDatabase) RegisterNodeFromAuthCallback(
	cache *cache.Cache,
	nodeKeyStr string,
	userName string,
	nodeExpiry *time.Time,
	registrationMethod string,
) (*types.Node, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	nodeKey := key.NodePublic{}
	err := nodeKey.UnmarshalText([]byte(nodeKeyStr))
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("nodeKey", nodeKey.ShortString()).
		Str("userName", userName).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", nodeExpiry)).
		Msg("Registering node from API/CLI or auth callback")

	if nodeInterface, ok := cache.Get(util.NodePublicKeyStripPrefix(nodeKey)); ok {
		if registrationNode, ok := nodeInterface.(types.Node); ok {
			user, err := hsdb.getUser(userName)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to find user in register node from auth callback, %w",
					err,
				)
			}

			// Registration of expired node with different user
			if registrationNode.ID != 0 &&
				registrationNode.UserID != user.ID {
				return nil, ErrDifferentRegisteredUser
			}

			registrationNode.UserID = user.ID
			registrationNode.RegisterMethod = registrationMethod

			if nodeExpiry != nil {
				registrationNode.Expiry = nodeExpiry
			}

			node, err := hsdb.registerNode(
				registrationNode,
			)

			if err == nil {
				cache.Delete(nodeKeyStr)
			}

			return node, err
		} else {
			return nil, ErrCouldNotConvertNodeInterface
		}
	}

	return nil, ErrNodeNotFoundRegistrationCache
}

// RegisterNode is executed from the CLI to register a new Node using its MachineKey.
func (hsdb *HSDatabase) RegisterNode(node types.Node) (*types.Node, error) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	return hsdb.registerNode(node)
}

func (hsdb *HSDatabase) registerNode(node types.Node) (*types.Node, error) {
	log.Debug().
		Str("node", node.Hostname).
		Str("machine_key", node.MachineKey).
		Str("node_key", node.NodeKey).
		Str("user", node.User.Name).
		Msg("Registering node")

	// If the node exists and we had already IPs for it, we just save it
	// so we store the node.Expire and node.Nodekey that has been set when
	// adding it to the registrationCache
	if len(node.IPAddresses) > 0 {
		if err := hsdb.db.Save(&node).Error; err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}

		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Str("machine_key", node.MachineKey).
			Str("node_key", node.NodeKey).
			Str("user", node.User.Name).
			Msg("Node authorized again")

		return &node, nil
	}

	hsdb.ipAllocationMutex.Lock()
	defer hsdb.ipAllocationMutex.Unlock()

	ips, err := hsdb.getAvailableIPs()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not find IP for the new node")

		return nil, err
	}

	node.IPAddresses = ips

	if err := hsdb.db.Save(&node).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) node in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Str("ip", strings.Join(ips.StringSlice(), ",")).
		Msg("Node registered with the database")

	return &node, nil
}

// NodeSetNodeKey sets the node key of a node and saves it to the database.
func (hsdb *HSDatabase) NodeSetNodeKey(node *types.Node, nodeKey key.NodePublic) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Model(node).Updates(types.Node{
		NodeKey: util.NodePublicKeyStripPrefix(nodeKey),
	}).Error; err != nil {
		return err
	}

	return nil
}

// NodeSetMachineKey sets the node key of a node and saves it to the database.
func (hsdb *HSDatabase) NodeSetMachineKey(
	node *types.Node,
	machineKey key.MachinePublic,
) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Model(node).Updates(types.Node{
		MachineKey: util.MachinePublicKeyStripPrefix(machineKey),
	}).Error; err != nil {
		return err
	}

	return nil
}

// NodeSave saves a node object to the database, prefer to use a specific save method rather
// than this. It is intended to be used when we are changing or.
func (hsdb *HSDatabase) NodeSave(node *types.Node) error {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	if err := hsdb.db.Save(node).Error; err != nil {
		return err
	}

	return nil
}

// GetAdvertisedRoutes returns the routes that are be advertised by the given node.
func (hsdb *HSDatabase) GetAdvertisedRoutes(node *types.Node) ([]netip.Prefix, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getAdvertisedRoutes(node)
}

func (hsdb *HSDatabase) getAdvertisedRoutes(node *types.Node) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := hsdb.db.
		Preload("Node").
		Where("node_id = ? AND advertised = ?", node.ID, true).Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get advertised routes for node")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

// GetEnabledRoutes returns the routes that are enabled for the node.
func (hsdb *HSDatabase) GetEnabledRoutes(node *types.Node) ([]netip.Prefix, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	return hsdb.getEnabledRoutes(node)
}

func (hsdb *HSDatabase) getEnabledRoutes(node *types.Node) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := hsdb.db.
		Preload("Node").
		Where("node_id = ? AND advertised = ? AND enabled = ?", node.ID, true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get enabled routes for node")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func (hsdb *HSDatabase) IsRoutesEnabled(node *types.Node, routeStr string) bool {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := hsdb.getEnabledRoutes(node)
	if err != nil {
		log.Error().Err(err).Msg("Could not get enabled routes")

		return false
	}

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

func (hsdb *HSDatabase) ListOnlineNodes(
	node *types.Node,
) (map[tailcfg.NodeID]bool, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	peers, err := hsdb.listPeers(node)
	if err != nil {
		return nil, err
	}

	return peers.OnlineNodeMap(), nil
}

// enableRoutes enables new routes based on a list of new routes.
func (hsdb *HSDatabase) enableRoutes(node *types.Node, routeStrs ...string) error {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return err
		}

		newRoutes[index] = route
	}

	advertisedRoutes, err := hsdb.getAdvertisedRoutes(node)
	if err != nil {
		return err
	}

	for _, newRoute := range newRoutes {
		if !util.StringOrPrefixListContains(advertisedRoutes, newRoute) {
			return fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				node.Hostname,
				newRoute, ErrNodeRouteIsNotAvailable,
			)
		}
	}

	// Separate loop so we don't leave things in a half-updated state
	for _, prefix := range newRoutes {
		route := types.Route{}
		err := hsdb.db.Preload("Node").
			Where("node_id = ? AND prefix = ?", node.ID, types.IPPrefix(prefix)).
			First(&route).Error
		if err == nil {
			route.Enabled = true

			// Mark already as primary if there is only this node offering this subnet
			// (and is not an exit route)
			if !route.IsExitRoute() {
				route.IsPrimary = hsdb.isUniquePrefix(route)
			}

			err = hsdb.db.Save(&route).Error
			if err != nil {
				return fmt.Errorf("failed to enable route: %w", err)
			}
		} else {
			return fmt.Errorf("failed to find route: %w", err)
		}
	}

	hsdb.notifier.NotifyWithIgnore(types.StateUpdate{
		Type:    types.StatePeerChanged,
		Changed: types.Nodes{node},
	}, node.MachineKey)

	return nil
}

func generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	normalizedHostname, err := util.NormalizeToFQDNRulesConfigFromViper(
		suppliedName,
	)
	if err != nil {
		return "", err
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := util.LabelHostnameLength - NodeGivenNameHashLength - NodeGivenNameTrimSize
		if len(normalizedHostname) > trimmedHostnameLength {
			normalizedHostname = normalizedHostname[:trimmedHostnameLength]
		}

		suffix, err := util.GenerateRandomStringDNSSafe(NodeGivenNameHashLength)
		if err != nil {
			return "", err
		}

		normalizedHostname += "-" + suffix
	}

	return normalizedHostname, nil
}

func (hsdb *HSDatabase) GenerateGivenName(machineKey string, suppliedName string) (string, error) {
	hsdb.mu.RLock()
	defer hsdb.mu.RUnlock()

	givenName, err := generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	nodes, err := hsdb.listNodesByGivenName(givenName)
	if err != nil {
		return "", err
	}

	for _, node := range nodes {
		if node.MachineKey != machineKey && node.GivenName == givenName {
			postfixedName, err := generateGivenName(suppliedName, true)
			if err != nil {
				return "", err
			}

			givenName = postfixedName
		}
	}

	return givenName, nil
}

func (hsdb *HSDatabase) ExpireEphemeralNodes(inactivityThreshhold time.Duration) {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	users, err := hsdb.listUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error listing users")

		return
	}

	for _, user := range users {
		nodes, err := hsdb.listNodesByUser(user.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", user.Name).
				Msg("Error listing nodes in user")

			return
		}

		expired := make([]tailcfg.NodeID, 0)
		for idx, node := range nodes {
			if node.IsEphemeral() && node.LastSeen != nil &&
				time.Now().
					After(node.LastSeen.Add(inactivityThreshhold)) {
				expired = append(expired, tailcfg.NodeID(node.ID))

				log.Info().
					Str("node", node.Hostname).
					Msg("Ephemeral client removed from database")

				err = hsdb.deleteNode(nodes[idx])
				if err != nil {
					log.Error().
						Err(err).
						Str("node", node.Hostname).
						Msg("🤮 Cannot delete ephemeral node from the database")
				}
			}
		}

		if len(expired) > 0 {
			hsdb.notifier.NotifyAll(types.StateUpdate{
				Type:    types.StatePeerRemoved,
				Removed: expired,
			})
		}
	}
}

func (hsdb *HSDatabase) ExpireExpiredNodes(lastCheck time.Time) time.Time {
	hsdb.mu.Lock()
	defer hsdb.mu.Unlock()

	// use the time of the start of the function to ensure we
	// dont miss some nodes by returning it _after_ we have
	// checked everything.
	started := time.Now()

	users, err := hsdb.listUsers()
	if err != nil {
		log.Error().Err(err).Msg("Error listing users")

		return time.Unix(0, 0)
	}

	for _, user := range users {
		nodes, err := hsdb.listNodesByUser(user.Name)
		if err != nil {
			log.Error().
				Err(err).
				Str("user", user.Name).
				Msg("Error listing nodes in user")

			return time.Unix(0, 0)
		}

		expired := make([]tailcfg.NodeID, 0)
		for index, node := range nodes {
			if node.IsExpired() &&
				node.Expiry.After(lastCheck) {
				expired = append(expired, tailcfg.NodeID(node.ID))

				now := time.Now()
				err := hsdb.nodeSetExpiry(nodes[index], now)
				if err != nil {
					log.Error().
						Err(err).
						Str("node", node.Hostname).
						Str("name", node.GivenName).
						Msg("🤮 Cannot expire node")
				} else {
					log.Info().
						Str("node", node.Hostname).
						Str("name", node.GivenName).
						Msg("Node successfully expired")
				}
			}
		}

		if len(expired) > 0 {
			hsdb.notifier.NotifyAll(types.StateUpdate{
				Type:    types.StatePeerRemoved,
				Removed: expired,
			})
		}
	}

	return started
}
