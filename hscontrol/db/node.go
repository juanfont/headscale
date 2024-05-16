package db

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/patrickmn/go-cache"
	"github.com/puzpuzpuz/xsync/v3"
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

func (hsdb *HSDatabase) ListPeers(nodeID types.NodeID) (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListPeers(rx, nodeID)
	})
}

// ListPeers returns all peers of node, regardless of any Policy or if the node is expired.
func ListPeers(tx *gorm.DB, nodeID types.NodeID) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("id <> ?",
			nodeID).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return nodes, nil
}

func (hsdb *HSDatabase) ListNodes() (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListNodes(rx)
	})
}

func ListNodes(tx *gorm.DB) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func listNodesByGivenName(tx *gorm.DB, givenName string) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Where("given_name = ?", givenName).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) getNode(user string, name string) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return getNode(rx, user, name)
	})
}

// getNode finds a Node by name and user and returns the Node struct.
func getNode(tx *gorm.DB, user string, name string) (*types.Node, error) {
	nodes, err := ListNodesByUser(tx, user)
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

func (hsdb *HSDatabase) GetNodeByID(id types.NodeID) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByID(rx, id)
	})
}

// GetNodeByID finds a Node by ID and returns the Node struct.
func GetNodeByID(tx *gorm.DB, id types.NodeID) (*types.Node, error) {
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		Find(&types.Node{ID: id}).First(&mach); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) GetNodeByMachineKey(machineKey key.MachinePublic) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByMachineKey(rx, machineKey)
	})
}

// GetNodeByMachineKey finds a Node by its MachineKey and returns the Node struct.
func GetNodeByMachineKey(
	tx *gorm.DB,
	machineKey key.MachinePublic,
) (*types.Node, error) {
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&mach, "machine_key = ?", machineKey.String()); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) GetNodeByAnyKey(
	machineKey key.MachinePublic,
	nodeKey key.NodePublic,
	oldNodeKey key.NodePublic,
) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return GetNodeByAnyKey(rx, machineKey, nodeKey, oldNodeKey)
	})
}

// GetNodeByAnyKey finds a Node by its MachineKey, its current NodeKey or the old one, and returns the Node struct.
// TODO(kradalby): see if we can remove this.
func GetNodeByAnyKey(
	tx *gorm.DB,
	machineKey key.MachinePublic, nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*types.Node, error) {
	node := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Preload("Routes").
		First(&node, "machine_key = ? OR node_key = ? OR node_key = ?",
			machineKey.String(),
			nodeKey.String(),
			oldNodeKey.String()); result.Error != nil {
		return nil, result.Error
	}

	return &node, nil
}

func (hsdb *HSDatabase) SetTags(
	nodeID types.NodeID,
	tags []string,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return SetTags(tx, nodeID, tags)
	})
}

// SetTags takes a Node struct pointer and update the forced tags.
func SetTags(
	tx *gorm.DB,
	nodeID types.NodeID,
	tags []string,
) error {
	if len(tags) == 0 {
		// if no tags are provided, we remove all forced tags
		if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("forced_tags", types.StringList{}).Error; err != nil {
			return fmt.Errorf("failed to remove tags for node in the database: %w", err)
		}

		return nil
	}

	newTags := types.StringList{}
	for _, tag := range tags {
		if !util.StringOrPrefixListContains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("forced_tags", newTags).Error; err != nil {
		return fmt.Errorf("failed to update tags for node in the database: %w", err)
	}

	return nil
}

// RenameNode takes a Node struct and a new GivenName for the nodes
// and renames it.
func RenameNode(tx *gorm.DB,
	nodeID uint64, newName string,
) error {
	err := util.CheckForFQDNRules(
		newName,
	)
	if err != nil {
		return fmt.Errorf("renaming node: %w", err)
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("given_name", newName).Error; err != nil {
		return fmt.Errorf("failed to rename node in the database: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) NodeSetExpiry(nodeID types.NodeID, expiry time.Time) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return NodeSetExpiry(tx, nodeID, expiry)
	})
}

// NodeSetExpiry takes a Node struct and  a new expiry time.
func NodeSetExpiry(tx *gorm.DB,
	nodeID types.NodeID, expiry time.Time,
) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("expiry", expiry).Error
}

func (hsdb *HSDatabase) DeleteNode(node *types.Node, isLikelyConnected *xsync.MapOf[types.NodeID, bool]) ([]types.NodeID, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) ([]types.NodeID, error) {
		return DeleteNode(tx, node, isLikelyConnected)
	})
}

// DeleteNode deletes a Node from the database.
// Caller is responsible for notifying all of change.
func DeleteNode(tx *gorm.DB,
	node *types.Node,
	isLikelyConnected *xsync.MapOf[types.NodeID, bool],
) ([]types.NodeID, error) {
	changed, err := deleteNodeRoutes(tx, node, isLikelyConnected)
	if err != nil {
		return changed, err
	}

	// Unscoped causes the node to be fully removed from the database.
	if err := tx.Unscoped().Delete(&types.Node{}, node.ID).Error; err != nil {
		return changed, err
	}

	return changed, nil
}

// SetLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
func SetLastSeen(tx *gorm.DB, nodeID types.NodeID, lastSeen time.Time) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("last_seen", lastSeen).Error
}

func RegisterNodeFromAuthCallback(
	tx *gorm.DB,
	cache *cache.Cache,
	mkey key.MachinePublic,
	userName string,
	nodeExpiry *time.Time,
	registrationMethod string,
	ipv4 *netip.Addr,
	ipv6 *netip.Addr,
) (*types.Node, error) {
	log.Debug().
		Str("machine_key", mkey.ShortString()).
		Str("userName", userName).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", nodeExpiry)).
		Msg("Registering node from API/CLI or auth callback")

	if nodeInterface, ok := cache.Get(mkey.String()); ok {
		if registrationNode, ok := nodeInterface.(types.Node); ok {
			user, err := GetUser(tx, userName)
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
			registrationNode.User = *user
			registrationNode.RegisterMethod = registrationMethod

			if nodeExpiry != nil {
				registrationNode.Expiry = nodeExpiry
			}

			node, err := RegisterNode(
				tx,
				registrationNode,
				ipv4, ipv6,
			)

			if err == nil {
				cache.Delete(mkey.String())
			}

			return node, err
		} else {
			return nil, ErrCouldNotConvertNodeInterface
		}
	}

	return nil, ErrNodeNotFoundRegistrationCache
}

func (hsdb *HSDatabase) RegisterNode(node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr) (*types.Node, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.Node, error) {
		return RegisterNode(tx, node, ipv4, ipv6)
	})
}

// RegisterNode is executed from the CLI to register a new Node using its MachineKey.
func RegisterNode(tx *gorm.DB, node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr) (*types.Node, error) {
	log.Debug().
		Str("node", node.Hostname).
		Str("machine_key", node.MachineKey.ShortString()).
		Str("node_key", node.NodeKey.ShortString()).
		Str("user", node.User.Name).
		Msg("Registering node")

	// If the node exists and it already has IP(s), we just save it
	// so we store the node.Expire and node.Nodekey that has been set when
	// adding it to the registrationCache
	if node.IPv4 != nil || node.IPv6 != nil {
		if err := tx.Save(&node).Error; err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}

		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Str("machine_key", node.MachineKey.ShortString()).
			Str("node_key", node.NodeKey.ShortString()).
			Str("user", node.User.Name).
			Msg("Node authorized again")

		return &node, nil
	}

	node.IPv4 = ipv4
	node.IPv6 = ipv6

	if err := tx.Save(&node).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) node in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msg("Node registered with the database")

	return &node, nil
}

// NodeSetNodeKey sets the node key of a node and saves it to the database.
func NodeSetNodeKey(tx *gorm.DB, node *types.Node, nodeKey key.NodePublic) error {
	return tx.Model(node).Updates(types.Node{
		NodeKey: nodeKey,
	}).Error
}

func (hsdb *HSDatabase) NodeSetMachineKey(
	node *types.Node,
	machineKey key.MachinePublic,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return NodeSetMachineKey(tx, node, machineKey)
	})
}

// NodeSetMachineKey sets the node key of a node and saves it to the database.
func NodeSetMachineKey(
	tx *gorm.DB,
	node *types.Node,
	machineKey key.MachinePublic,
) error {
	return tx.Model(node).Updates(types.Node{
		MachineKey: machineKey,
	}).Error
}

// NodeSave saves a node object to the database, prefer to use a specific save method rather
// than this. It is intended to be used when we are changing or.
// TODO(kradalby): Remove this func, just use Save.
func NodeSave(tx *gorm.DB, node *types.Node) error {
	return tx.Save(node).Error
}

func (hsdb *HSDatabase) GetAdvertisedRoutes(node *types.Node) ([]netip.Prefix, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]netip.Prefix, error) {
		return GetAdvertisedRoutes(rx, node)
	})
}

// GetAdvertisedRoutes returns the routes that are be advertised by the given node.
func GetAdvertisedRoutes(tx *gorm.DB, node *types.Node) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := tx.
		Preload("Node").
		Where("node_id = ? AND advertised = ?", node.ID, true).Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("getting advertised routes for node(%d): %w", node.ID, err)
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func (hsdb *HSDatabase) GetEnabledRoutes(node *types.Node) ([]netip.Prefix, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) ([]netip.Prefix, error) {
		return GetEnabledRoutes(rx, node)
	})
}

// GetEnabledRoutes returns the routes that are enabled for the node.
func GetEnabledRoutes(tx *gorm.DB, node *types.Node) ([]netip.Prefix, error) {
	routes := types.Routes{}

	err := tx.
		Preload("Node").
		Where("node_id = ? AND advertised = ? AND enabled = ?", node.ID, true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("getting enabled routes for node(%d): %w", node.ID, err)
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func IsRoutesEnabled(tx *gorm.DB, node *types.Node, routeStr string) bool {
	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := GetEnabledRoutes(tx, node)
	if err != nil {
		return false
	}

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

func (hsdb *HSDatabase) enableRoutes(
	node *types.Node,
	routeStrs ...string,
) (*types.StateUpdate, error) {
	return Write(hsdb.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return enableRoutes(tx, node, routeStrs...)
	})
}

// enableRoutes enables new routes based on a list of new routes.
func enableRoutes(tx *gorm.DB,
	node *types.Node, routeStrs ...string,
) (*types.StateUpdate, error) {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return nil, err
		}

		newRoutes[index] = route
	}

	advertisedRoutes, err := GetAdvertisedRoutes(tx, node)
	if err != nil {
		return nil, err
	}

	for _, newRoute := range newRoutes {
		if !util.StringOrPrefixListContains(advertisedRoutes, newRoute) {
			return nil, fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				node.Hostname,
				newRoute, ErrNodeRouteIsNotAvailable,
			)
		}
	}

	// Separate loop so we don't leave things in a half-updated state
	for _, prefix := range newRoutes {
		route := types.Route{}
		err := tx.Preload("Node").
			Where("node_id = ? AND prefix = ?", node.ID, types.IPPrefix(prefix)).
			First(&route).Error
		if err == nil {
			route.Enabled = true

			// Mark already as primary if there is only this node offering this subnet
			// (and is not an exit route)
			if !route.IsExitRoute() {
				route.IsPrimary = isUniquePrefix(tx, route)
			}

			err = tx.Save(&route).Error
			if err != nil {
				return nil, fmt.Errorf("failed to enable route: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to find route: %w", err)
		}
	}

	// Ensure the node has the latest routes when notifying the other
	// nodes
	nRoutes, err := GetNodeRoutes(tx, node)
	if err != nil {
		return nil, fmt.Errorf("failed to read back routes: %w", err)
	}

	node.Routes = nRoutes

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Strs("routes", routeStrs).
		Msg("enabling routes")

	return &types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: []types.NodeID{node.ID},
		Message:     "created in db.enableRoutes",
	}, nil
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

func (hsdb *HSDatabase) GenerateGivenName(
	mkey key.MachinePublic,
	suppliedName string,
) (string, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (string, error) {
		return GenerateGivenName(rx, mkey, suppliedName)
	})
}

func GenerateGivenName(
	tx *gorm.DB,
	mkey key.MachinePublic,
	suppliedName string,
) (string, error) {
	givenName, err := generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	nodes, err := listNodesByGivenName(tx, givenName)
	if err != nil {
		return "", err
	}

	var nodeFound *types.Node
	for idx, node := range nodes {
		if node.GivenName == givenName {
			nodeFound = nodes[idx]
		}
	}

	if nodeFound != nil && nodeFound.MachineKey.String() != mkey.String() {
		postfixedName, err := generateGivenName(suppliedName, true)
		if err != nil {
			return "", err
		}

		givenName = postfixedName
	}

	return givenName, nil
}

func DeleteExpiredEphemeralNodes(tx *gorm.DB,
	inactivityThreshhold time.Duration,
) ([]types.NodeID, []types.NodeID) {
	users, err := ListUsers(tx)
	if err != nil {
		return nil, nil
	}

	var expired []types.NodeID
	var changedNodes []types.NodeID
	for _, user := range users {
		nodes, err := ListNodesByUser(tx, user.Name)
		if err != nil {
			return nil, nil
		}

		for idx, node := range nodes {
			if node.IsEphemeral() && node.LastSeen != nil &&
				time.Now().
					After(node.LastSeen.Add(inactivityThreshhold)) {
				expired = append(expired, node.ID)

				log.Info().
					Str("node", node.Hostname).
					Msg("Ephemeral client removed from database")

					// empty isConnected map as ephemeral nodes are not routes
				changed, err := DeleteNode(tx, nodes[idx], nil)
				if err != nil {
					log.Error().
						Err(err).
						Str("node", node.Hostname).
						Msg("🤮 Cannot delete ephemeral node from the database")
				}

				changedNodes = append(changedNodes, changed...)
			}
		}

		// TODO(kradalby): needs to be moved out of transaction
	}

	return expired, changedNodes
}

func ExpireExpiredNodes(tx *gorm.DB,
	lastCheck time.Time,
) (time.Time, types.StateUpdate, bool) {
	// use the time of the start of the function to ensure we
	// dont miss some nodes by returning it _after_ we have
	// checked everything.
	started := time.Now()

	expired := make([]*tailcfg.PeerChange, 0)

	nodes, err := ListNodes(tx)
	if err != nil {
		return time.Unix(0, 0), types.StateUpdate{}, false
	}
	for _, node := range nodes {
		if node.IsExpired() && node.Expiry.After(lastCheck) {
			expired = append(expired, &tailcfg.PeerChange{
				NodeID:    tailcfg.NodeID(node.ID),
				KeyExpiry: node.Expiry,
			})
		}
	}

	if len(expired) > 0 {
		return started, types.StateUpdate{
			Type:          types.StatePeerChangedPatch,
			ChangePatches: expired,
		}, true
	}

	return started, types.StateUpdate{}, false
}
