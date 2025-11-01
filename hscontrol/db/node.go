package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

const (
	NodeGivenNameHashLength = 8
	NodeGivenNameTrimSize   = 2
)

var invalidDNSRegex = regexp.MustCompile("[^a-z0-9-.]+")

var (
	ErrNodeNotFound                  = errors.New("node not found")
	ErrNodeRouteIsNotAvailable       = errors.New("route is not available on node")
	ErrNodeNotFoundRegistrationCache = errors.New(
		"node not found in registration cache",
	)
	ErrCouldNotConvertNodeInterface = errors.New("failed to convert node interface")
)

// ListPeers returns peers of node, regardless of any Policy or if the node is expired.
// If no peer IDs are given, all peers are returned.
// If at least one peer ID is given, only these peer nodes will be returned.
func (hsdb *HSDatabase) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	return ListPeers(hsdb.DB, nodeID, peerIDs...)
}

// ListPeers returns peers of node, regardless of any Policy or if the node is expired.
// If no peer IDs are given, all peers are returned.
// If at least one peer ID is given, only these peer nodes will be returned.
func ListPeers(tx *gorm.DB, nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Where("id <> ?", nodeID).
		Where(peerIDs).Find(&nodes).Error; err != nil {
		return types.Nodes{}, err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	return nodes, nil
}

// ListNodes queries the database for either all nodes if no parameters are given
// or for the given nodes if at least one node ID is given as parameter.
func (hsdb *HSDatabase) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	return ListNodes(hsdb.DB, nodeIDs...)
}

// ListNodes queries the database for either all nodes if no parameters are given
// or for the given nodes if at least one node ID is given as parameter.
func ListNodes(tx *gorm.DB, nodeIDs ...types.NodeID) (types.Nodes, error) {
	nodes := types.Nodes{}
	if err := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Where(nodeIDs).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) ListEphemeralNodes() (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		nodes := types.Nodes{}
		if err := rx.Joins("AuthKey").Where(`"AuthKey"."ephemeral" = true`).Find(&nodes).Error; err != nil {
			return nil, err
		}

		return nodes, nil
	})
}

func (hsdb *HSDatabase) getNode(uid types.UserID, name string) (*types.Node, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (*types.Node, error) {
		return getNode(rx, uid, name)
	})
}

// getNode finds a Node by name and user and returns the Node struct.
func getNode(tx *gorm.DB, uid types.UserID, name string) (*types.Node, error) {
	nodes, err := ListNodesByUser(tx, uid)
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
	return GetNodeByID(hsdb.DB, id)
}

// GetNodeByID finds a Node by ID and returns the Node struct.
func GetNodeByID(tx *gorm.DB, id types.NodeID) (*types.Node, error) {
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		Find(&types.Node{ID: id}).First(&mach); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) GetNodeByMachineKey(machineKey key.MachinePublic) (*types.Node, error) {
	return GetNodeByMachineKey(hsdb.DB, machineKey)
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
		First(&mach, "machine_key = ?", machineKey.String()); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) GetNodeByNodeKey(nodeKey key.NodePublic) (*types.Node, error) {
	return GetNodeByNodeKey(hsdb.DB, nodeKey)
}

// GetNodeByNodeKey finds a Node by its NodeKey and returns the Node struct.
func GetNodeByNodeKey(
	tx *gorm.DB,
	nodeKey key.NodePublic,
) (*types.Node, error) {
	mach := types.Node{}
	if result := tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User").
		First(&mach, "node_key = ?", nodeKey.String()); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) SetTags(
	nodeID types.NodeID,
	tags []string,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return SetTags(tx, nodeID, tags)
	})
}

// SetTags takes a NodeID and update the forced tags.
// It will overwrite any tags with the new list.
func SetTags(
	tx *gorm.DB,
	nodeID types.NodeID,
	tags []string,
) error {
	if len(tags) == 0 {
		// if no tags are provided, we remove all forced tags
		if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("forced_tags", "[]").Error; err != nil {
			return fmt.Errorf("removing tags: %w", err)
		}

		return nil
	}

	slices.Sort(tags)
	tags = slices.Compact(tags)
	b, err := json.Marshal(tags)
	if err != nil {
		return err
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("forced_tags", string(b)).Error; err != nil {
		return fmt.Errorf("updating tags: %w", err)
	}

	return nil
}

// SetTags takes a Node struct pointer and update the forced tags.
func SetApprovedRoutes(
	tx *gorm.DB,
	nodeID types.NodeID,
	routes []netip.Prefix,
) error {
	if len(routes) == 0 {
		// if no routes are provided, we remove all
		if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", "[]").Error; err != nil {
			return fmt.Errorf("removing approved routes: %w", err)
		}

		return nil
	}

	// When approving exit routes, ensure both IPv4 and IPv6 are included
	// If either 0.0.0.0/0 or ::/0 is being approved, both should be approved
	hasIPv4Exit := slices.Contains(routes, tsaddr.AllIPv4())
	hasIPv6Exit := slices.Contains(routes, tsaddr.AllIPv6())

	if hasIPv4Exit && !hasIPv6Exit {
		routes = append(routes, tsaddr.AllIPv6())
	} else if hasIPv6Exit && !hasIPv4Exit {
		routes = append(routes, tsaddr.AllIPv4())
	}

	b, err := json.Marshal(routes)
	if err != nil {
		return err
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("approved_routes", string(b)).Error; err != nil {
		return fmt.Errorf("updating approved routes: %w", err)
	}

	return nil
}

// SetLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
func (hsdb *HSDatabase) SetLastSeen(nodeID types.NodeID, lastSeen time.Time) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return SetLastSeen(tx, nodeID, lastSeen)
	})
}

// SetLastSeen sets a node's last seen field indicating that we
// have recently communicating with this node.
func SetLastSeen(tx *gorm.DB, nodeID types.NodeID, lastSeen time.Time) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("last_seen", lastSeen).Error
}

// RenameNode takes a Node struct and a new GivenName for the nodes
// and renames it. Validation should be done in the state layer before calling this function.
func RenameNode(tx *gorm.DB,
	nodeID types.NodeID, newName string,
) error {
	if err := util.ValidateHostname(newName); err != nil {
		return fmt.Errorf("renaming node: %w", err)
	}

	// Check if the new name is unique
	var count int64
	if err := tx.Model(&types.Node{}).Where("given_name = ? AND id != ?", newName, nodeID).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check name uniqueness: %w", err)
	}

	if count > 0 {
		return errors.New("name is not unique")
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

func (hsdb *HSDatabase) DeleteNode(node *types.Node) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteNode(tx, node)
	})
}

// DeleteNode deletes a Node from the database.
// Caller is responsible for notifying all of change.
func DeleteNode(tx *gorm.DB,
	node *types.Node,
) error {
	// Unscoped causes the node to be fully removed from the database.
	if err := tx.Unscoped().Delete(&types.Node{}, node.ID).Error; err != nil {
		return err
	}

	return nil
}

// DeleteEphemeralNode deletes a Node from the database, note that this method
// will remove it straight, and not notify any changes or consider any routes.
// It is intended for Ephemeral nodes.
func (hsdb *HSDatabase) DeleteEphemeralNode(
	nodeID types.NodeID,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		if err := tx.Unscoped().Delete(&types.Node{}, nodeID).Error; err != nil {
			return err
		}
		return nil
	})
}

// RegisterNodeForTest is used only for testing purposes to register a node directly in the database.
// Production code should use state.HandleNodeFromAuthPath or state.HandleNodeFromPreAuthKey.
func RegisterNodeForTest(tx *gorm.DB, node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr) (*types.Node, error) {
	if !testing.Testing() {
		panic("RegisterNodeForTest can only be called during tests")
	}

	log.Debug().
		Str("node", node.Hostname).
		Str("machine_key", node.MachineKey.ShortString()).
		Str("node_key", node.NodeKey.ShortString()).
		Str("user", node.User.Username()).
		Msg("Registering test node")

	// If the a new node is registered with the same machine key, to the same user,
	// update the existing node.
	// If the same node is registered again, but to a new user, then that is considered
	// a new node.
	oldNode, _ := GetNodeByMachineKey(tx, node.MachineKey)
	if oldNode != nil && oldNode.UserID == node.UserID {
		node.ID = oldNode.ID
		node.GivenName = oldNode.GivenName
		node.ApprovedRoutes = oldNode.ApprovedRoutes
		// Don't overwrite the provided IPs with old ones when they exist
		if ipv4 == nil {
			ipv4 = oldNode.IPv4
		}
		if ipv6 == nil {
			ipv6 = oldNode.IPv6
		}
	}

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
			Str("user", node.User.Username()).
			Msg("Test node authorized again")

		return &node, nil
	}

	node.IPv4 = ipv4
	node.IPv6 = ipv6

	var err error
	node.Hostname, err = util.NormaliseHostname(node.Hostname)
	if err != nil {
		newHostname := util.InvalidString()
		log.Info().Err(err).Str("invalid-hostname", node.Hostname).Str("new-hostname", newHostname).Msgf("Invalid hostname, replacing")
		node.Hostname = newHostname
	}

	if node.GivenName == "" {
		givenName, err := EnsureUniqueGivenName(tx, node.Hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to ensure unique given name: %w", err)
		}

		node.GivenName = givenName
	}

	if err := tx.Save(&node).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) node in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msg("Test node registered with the database")

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

func generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	// Strip invalid DNS characters for givenName
	suppliedName = strings.ToLower(suppliedName)
	suppliedName = invalidDNSRegex.ReplaceAllString(suppliedName, "")

	if len(suppliedName) > util.LabelHostnameLength {
		return "", types.ErrHostnameTooLong
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := util.LabelHostnameLength - NodeGivenNameHashLength - NodeGivenNameTrimSize
		if len(suppliedName) > trimmedHostnameLength {
			suppliedName = suppliedName[:trimmedHostnameLength]
		}

		suffix, err := util.GenerateRandomStringDNSSafe(NodeGivenNameHashLength)
		if err != nil {
			return "", err
		}

		suppliedName += "-" + suffix
	}

	return suppliedName, nil
}

func isUniqueName(tx *gorm.DB, name string) (bool, error) {
	nodes := types.Nodes{}
	if err := tx.
		Where("given_name = ?", name).Find(&nodes).Error; err != nil {
		return false, err
	}

	return len(nodes) == 0, nil
}

// EnsureUniqueGivenName generates a unique given name for a node based on its hostname.
func EnsureUniqueGivenName(
	tx *gorm.DB,
	name string,
) (string, error) {
	givenName, err := generateGivenName(name, false)
	if err != nil {
		return "", err
	}

	unique, err := isUniqueName(tx, givenName)
	if err != nil {
		return "", err
	}

	if !unique {
		postfixedName, err := generateGivenName(name, true)
		if err != nil {
			return "", err
		}

		givenName = postfixedName
	}

	return givenName, nil
}

// EphemeralGarbageCollector is a garbage collector that will delete nodes after
// a certain amount of time.
// It is used to delete ephemeral nodes that have disconnected and should be
// cleaned up.
type EphemeralGarbageCollector struct {
	mu sync.Mutex

	deleteFunc  func(types.NodeID)
	toBeDeleted map[types.NodeID]*time.Timer

	deleteCh chan types.NodeID
	cancelCh chan struct{}
}

// NewEphemeralGarbageCollector creates a new EphemeralGarbageCollector, it takes
// a deleteFunc that will be called when a node is scheduled for deletion.
func NewEphemeralGarbageCollector(deleteFunc func(types.NodeID)) *EphemeralGarbageCollector {
	return &EphemeralGarbageCollector{
		toBeDeleted: make(map[types.NodeID]*time.Timer),
		deleteCh:    make(chan types.NodeID, 10),
		cancelCh:    make(chan struct{}),
		deleteFunc:  deleteFunc,
	}
}

// Close stops the garbage collector.
func (e *EphemeralGarbageCollector) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop all timers
	for _, timer := range e.toBeDeleted {
		timer.Stop()
	}

	// Close the cancel channel to signal all goroutines to exit
	close(e.cancelCh)
}

// Schedule schedules a node for deletion after the expiry duration.
// If the garbage collector is already closed, this is a no-op.
func (e *EphemeralGarbageCollector) Schedule(nodeID types.NodeID, expiry time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Don't schedule new timers if the garbage collector is already closed
	select {
	case <-e.cancelCh:
		// The cancel channel is closed, meaning the GC is shutting down
		// or already shut down, so we shouldn't schedule anything new
		return
	default:
		// Continue with scheduling
	}

	// If a timer already exists for this node, stop it first
	if oldTimer, exists := e.toBeDeleted[nodeID]; exists {
		oldTimer.Stop()
	}

	timer := time.NewTimer(expiry)
	e.toBeDeleted[nodeID] = timer
	// Start a goroutine to handle the timer completion
	go func() {
		select {
		case <-timer.C:
			// This is to handle the situation where the GC is shutting down and
			// we are trying to schedule a new node for deletion at the same time
			// i.e. We don't want to send to deleteCh if the GC is shutting down
			// So, we try to send to deleteCh, but also watch for cancelCh
			select {
			case e.deleteCh <- nodeID:
				// Successfully sent to deleteCh
			case <-e.cancelCh:
				// GC is shutting down, don't send to deleteCh
				return
			}
		case <-e.cancelCh:
			// If the GC is closed, exit the goroutine
			return
		}
	}()
}

// Cancel cancels the deletion of a node.
func (e *EphemeralGarbageCollector) Cancel(nodeID types.NodeID) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if timer, ok := e.toBeDeleted[nodeID]; ok {
		timer.Stop()
		delete(e.toBeDeleted, nodeID)
	}
}

// Start starts the garbage collector.
func (e *EphemeralGarbageCollector) Start() {
	for {
		select {
		case <-e.cancelCh:
			return
		case nodeID := <-e.deleteCh:
			e.mu.Lock()
			delete(e.toBeDeleted, nodeID)
			e.mu.Unlock()

			go e.deleteFunc(nodeID)
		}
	}
}

func (hsdb *HSDatabase) CreateNodeForTest(user *types.User, hostname ...string) *types.Node {
	if !testing.Testing() {
		panic("CreateNodeForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateNodeForTest requires a valid user")
	}

	nodeName := "testnode"
	if len(hostname) > 0 && hostname[0] != "" {
		nodeName = hostname[0]
	}

	// Create a preauth key for the node
	pak, err := hsdb.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create preauth key for test node: %v", err))
	}

	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	discoKey := key.NewDisco()

	node := &types.Node{
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		DiscoKey:       discoKey.Public(),
		Hostname:       nodeName,
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(pak.ID),
	}

	err = hsdb.DB.Save(node).Error
	if err != nil {
		panic(fmt.Sprintf("failed to create test node: %v", err))
	}

	return node
}

func (hsdb *HSDatabase) CreateRegisteredNodeForTest(user *types.User, hostname ...string) *types.Node {
	if !testing.Testing() {
		panic("CreateRegisteredNodeForTest can only be called during tests")
	}

	node := hsdb.CreateNodeForTest(user, hostname...)

	// Allocate IPs for the test node using the database's IP allocator
	// This is a simplified allocation for testing - in production this would use State.ipAlloc
	ipv4, ipv6, err := hsdb.allocateTestIPs(node.ID)
	if err != nil {
		panic(fmt.Sprintf("failed to allocate IPs for test node: %v", err))
	}

	var registeredNode *types.Node
	err = hsdb.DB.Transaction(func(tx *gorm.DB) error {
		var err error
		registeredNode, err = RegisterNodeForTest(tx, *node, ipv4, ipv6)
		return err
	})
	if err != nil {
		panic(fmt.Sprintf("failed to register test node: %v", err))
	}

	return registeredNode
}

func (hsdb *HSDatabase) CreateNodesForTest(user *types.User, count int, hostnamePrefix ...string) []*types.Node {
	if !testing.Testing() {
		panic("CreateNodesForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateNodesForTest requires a valid user")
	}

	prefix := "testnode"
	if len(hostnamePrefix) > 0 && hostnamePrefix[0] != "" {
		prefix = hostnamePrefix[0]
	}

	nodes := make([]*types.Node, count)
	for i := range count {
		hostname := prefix + "-" + strconv.Itoa(i)
		nodes[i] = hsdb.CreateNodeForTest(user, hostname)
	}

	return nodes
}

func (hsdb *HSDatabase) CreateRegisteredNodesForTest(user *types.User, count int, hostnamePrefix ...string) []*types.Node {
	if !testing.Testing() {
		panic("CreateRegisteredNodesForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateRegisteredNodesForTest requires a valid user")
	}

	prefix := "testnode"
	if len(hostnamePrefix) > 0 && hostnamePrefix[0] != "" {
		prefix = hostnamePrefix[0]
	}

	nodes := make([]*types.Node, count)
	for i := range count {
		hostname := prefix + "-" + strconv.Itoa(i)
		nodes[i] = hsdb.CreateRegisteredNodeForTest(user, hostname)
	}

	return nodes
}

// allocateTestIPs allocates sequential test IPs for nodes during testing.
func (hsdb *HSDatabase) allocateTestIPs(nodeID types.NodeID) (*netip.Addr, *netip.Addr, error) {
	if !testing.Testing() {
		panic("allocateTestIPs can only be called during tests")
	}

	// Use simple sequential allocation for tests
	// IPv4: 100.64.0.x (where x is nodeID)
	// IPv6: fd7a:115c:a1e0::x (where x is nodeID)

	if nodeID > 254 {
		return nil, nil, fmt.Errorf("test node ID %d too large for simple IP allocation", nodeID)
	}

	ipv4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(nodeID)})
	ipv6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(nodeID)})

	return &ipv4, &ipv6, nil
}
