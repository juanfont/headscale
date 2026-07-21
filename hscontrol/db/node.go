package db

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

const (
	NodeGivenNameHashLength = 8
	NodeGivenNameTrimSize   = 2

	// defaultTestNodePrefix is the default hostname prefix for nodes created in tests.
	defaultTestNodePrefix = "testnode"
)

// ErrNodeNameNotUnique is returned when a node name is not unique.
var ErrNodeNameNotUnique = errors.New("node name is not unique")

// preloadNode returns a session that eager-loads a node's AuthKey, the
// AuthKey's User, and the node's User.
func preloadNode(tx *gorm.DB) *gorm.DB {
	return tx.
		Preload("AuthKey").
		Preload("AuthKey.User").
		Preload("User")
}

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

	err := preloadNode(tx).
		Where("id <> ?", nodeID).
		Where(peerIDs).Find(&nodes).Error
	if err != nil {
		return types.Nodes{}, err
	}

	slices.SortFunc(nodes, func(a, b *types.Node) int { return cmp.Compare(a.ID, b.ID) })

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

	err := preloadNode(tx).
		Where(nodeIDs).Find(&nodes).Error
	if err != nil {
		return nil, err
	}

	return nodes, nil
}

func (hsdb *HSDatabase) ListEphemeralNodes() (types.Nodes, error) {
	return Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		nodes := types.Nodes{}

		err := rx.Joins("AuthKey").Where(`"AuthKey"."ephemeral" = true`).Find(&nodes).Error
		if err != nil {
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

// getNode finds a [types.Node] by name and user and returns the [types.Node] struct.
func getNode(tx *gorm.DB, uid types.UserID, name string) (*types.Node, error) {
	uidPtr := uint(uid)

	node := types.Node{}

	err := preloadNode(tx).
		Where(&types.Node{UserID: &uidPtr, Hostname: name}).
		First(&node).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNodeNotFound
		}

		return nil, err
	}

	return &node, nil
}

func (hsdb *HSDatabase) GetNodeByID(id types.NodeID) (*types.Node, error) {
	return GetNodeByID(hsdb.DB, id)
}

// GetNodeByID finds a [types.Node] by ID and returns the [types.Node] struct.
func GetNodeByID(tx *gorm.DB, id types.NodeID) (*types.Node, error) {
	mach := types.Node{}
	if result := preloadNode(tx).
		First(&mach, "id = ?", id); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
}

func (hsdb *HSDatabase) GetNodeByNodeKey(nodeKey key.NodePublic) (*types.Node, error) {
	return GetNodeByNodeKey(hsdb.DB, nodeKey)
}

// GetNodeByNodeKey finds a [types.Node] by its [key.NodePublic] and returns the [types.Node] struct.
func GetNodeByNodeKey(
	tx *gorm.DB,
	nodeKey key.NodePublic,
) (*types.Node, error) {
	mach := types.Node{}
	if result := preloadNode(tx).
		First(&mach, "node_key = ?", nodeKey.String()); result.Error != nil {
		return nil, result.Error
	}

	return &mach, nil
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

// RenameNode takes a [types.Node] struct and a new [types.Node.GivenName] for the nodes
// and renames it. Validation should be done in the state layer before calling this function.
func RenameNode(tx *gorm.DB,
	nodeID types.NodeID, newName string,
) error {
	err := dnsname.ValidLabel(newName)
	if err != nil {
		return fmt.Errorf("renaming node: %w", err)
	}

	// Check if the new name is unique
	var count int64

	if err := tx.Model(&types.Node{}).Where("given_name = ? AND id != ?", newName, nodeID).Count(&count).Error; err != nil { //nolint:noinlineerr
		return fmt.Errorf("checking name uniqueness: %w", err)
	}

	if count > 0 {
		return ErrNodeNameNotUnique
	}

	if err := tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("given_name", newName).Error; err != nil { //nolint:noinlineerr
		return fmt.Errorf("renaming node in database: %w", err)
	}

	return nil
}

func (hsdb *HSDatabase) NodeSetExpiry(nodeID types.NodeID, expiry *time.Time) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return NodeSetExpiry(tx, nodeID, expiry)
	})
}

// NodeSetExpiry sets a new expiry time for a node.
// If expiry is nil, the node's expiry is disabled (node will never expire).
func NodeSetExpiry(tx *gorm.DB, nodeID types.NodeID, expiry *time.Time) error {
	return tx.Model(&types.Node{}).Where("id = ?", nodeID).Update("expiry", expiry).Error
}

func (hsdb *HSDatabase) DeleteNode(node *types.Node) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		return DeleteNode(tx, node)
	})
}

// DeleteNode deletes a [types.Node] from the database.
// Caller is responsible for notifying all of change.
func DeleteNode(tx *gorm.DB,
	node *types.Node,
) error {
	// Unscoped causes the node to be fully removed from the database.
	err := tx.Unscoped().Delete(&types.Node{}, node.ID).Error
	if err != nil {
		return err
	}

	return nil
}

// DeleteEphemeralNode deletes a [types.Node] from the database, note that this method
// will remove it straight, and not notify any changes or consider any routes.
// It is intended for Ephemeral nodes.
func (hsdb *HSDatabase) DeleteEphemeralNode(
	nodeID types.NodeID,
) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		err := tx.Unscoped().Delete(&types.Node{}, nodeID).Error
		if err != nil {
			return err
		}

		return nil
	})
}

// RegisterNodeForTest is used only for testing purposes to register a node directly in the database.
// Production code should use [state.State.HandleNodeFromAuthPath] or [state.State.HandleNodeFromPreAuthKey].
func RegisterNodeForTest(tx *gorm.DB, node types.Node, ipv4 *netip.Addr, ipv6 *netip.Addr) (*types.Node, error) {
	if !testing.Testing() {
		panic("RegisterNodeForTest can only be called during tests")
	}

	logEvent := log.Debug().
		Str(zf.NodeHostname, node.Hostname).
		Str(zf.MachineKey, node.MachineKey.ShortString()).
		Str(zf.NodeKey, node.NodeKey.ShortString())

	if node.User != nil {
		logEvent = logEvent.Str(zf.UserName, node.User.Username())
	} else if node.UserID != nil {
		logEvent = logEvent.Uint(zf.UserID, *node.UserID)
	} else {
		logEvent = logEvent.Str(zf.UserName, "none")
	}

	logEvent.Msg("registering test node")

	// Reuse the existing node's identity only when the same machine
	// re-registers for the same user; a different user is a new node. Match on
	// (machine_key, user_id) precisely - a machine key can map to several nodes
	// (one per user), so a machine-key-only lookup would be ambiguous.
	var oldNode types.Node

	err := tx.
		Where("machine_key = ? AND user_id = ?", node.MachineKey.String(), node.UserID).
		First(&oldNode).Error
	if err == nil {
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
		err := tx.Save(&node).Error
		if err != nil {
			return nil, fmt.Errorf("registering existing node in database: %w", err)
		}

		log.Trace().
			Caller().
			Str(zf.NodeHostname, node.Hostname).
			Str(zf.MachineKey, node.MachineKey.ShortString()).
			Str(zf.NodeKey, node.NodeKey.ShortString()).
			Str(zf.UserName, node.User.Username()).
			Msg("Test node authorized again")

		return &node, nil
	}

	node.IPv4 = ipv4
	node.IPv6 = ipv6

	if node.GivenName == "" {
		node.GivenName = dnsname.SanitizeHostname(node.Hostname)
		if node.GivenName == "" {
			node.GivenName = "node"
		}
	}

	if err := tx.Save(&node).Error; err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("saving node to database: %w", err)
	}

	log.Trace().
		Caller().
		Str(zf.NodeHostname, node.Hostname).
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

// EphemeralGarbageCollector is a garbage collector that will delete nodes after
// a certain amount of time.
// It is used to delete ephemeral nodes ([types.Node.IsEphemeral]) that have disconnected and should be
// cleaned up.
type EphemeralGarbageCollector struct {
	mu sync.Mutex

	deleteFunc  func(types.NodeID)
	toBeDeleted map[types.NodeID]ephemeralTimer
	// gen is bumped for every scheduled deletion so a queued deletion that
	// was superseded by a Cancel or reschedule can be recognised and dropped.
	gen uint64

	deleteCh chan pendingDeletion
	cancelCh chan struct{}
}

// ephemeralTimer pairs a node's pending-deletion timer with a done channel
// used to reap its watcher goroutine on Cancel or reschedule, plus the
// generation identifying this particular scheduling. Without the done channel
// a stopped timer never fires and the goroutine leaks until Close.
type ephemeralTimer struct {
	timer *time.Timer
	done  chan struct{}
	gen   uint64
}

// pendingDeletion is the generation-stamped deletion a watcher enqueues when
// its timer fires. Start drops it if the node's current generation no longer
// matches, i.e. it was cancelled or rescheduled in the meantime.
type pendingDeletion struct {
	nodeID types.NodeID
	gen    uint64
}

// NewEphemeralGarbageCollector creates a new [EphemeralGarbageCollector], it takes
// a deleteFunc that will be called when a node is scheduled for deletion.
func NewEphemeralGarbageCollector(deleteFunc func(types.NodeID)) *EphemeralGarbageCollector {
	return &EphemeralGarbageCollector{
		toBeDeleted: make(map[types.NodeID]ephemeralTimer),
		deleteCh:    make(chan pendingDeletion, 10),
		cancelCh:    make(chan struct{}),
		deleteFunc:  deleteFunc,
	}
}

// Close stops the garbage collector.
func (e *EphemeralGarbageCollector) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stop all timers
	for _, t := range e.toBeDeleted {
		t.timer.Stop()
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

	// If a timer already exists for this node, stop it and reap its
	// watcher goroutine before scheduling a fresh one.
	if old, exists := e.toBeDeleted[nodeID]; exists {
		old.timer.Stop()
		close(old.done)
	}

	e.gen++
	gen := e.gen
	timer := time.NewTimer(expiry)
	done := make(chan struct{})
	e.toBeDeleted[nodeID] = ephemeralTimer{timer: timer, done: done, gen: gen}
	// Start a goroutine to handle the timer completion
	go func() {
		select {
		case <-timer.C:
			// This is to handle the situation where the GC is shutting down and
			// we are trying to schedule a new node for deletion at the same time
			// i.e. We don't want to send to deleteCh if the GC is shutting down
			// So, we try to send to deleteCh, but also watch for cancelCh
			select {
			case e.deleteCh <- pendingDeletion{nodeID: nodeID, gen: gen}:
				// Successfully sent to deleteCh
			case <-e.cancelCh:
				// GC is shutting down, don't send to deleteCh
				return
			case <-done:
				// Cancelled or rescheduled before the send landed.
				return
			}
		case <-done:
			// Cancelled or rescheduled before the timer fired.
			return
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

	if t, ok := e.toBeDeleted[nodeID]; ok {
		t.timer.Stop()
		close(t.done)
		delete(e.toBeDeleted, nodeID)
	}
}

// IsScheduled reports whether a deletion timer is currently armed for nodeID.
func (e *EphemeralGarbageCollector) IsScheduled(nodeID types.NodeID) bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	_, ok := e.toBeDeleted[nodeID]

	return ok
}

// Start starts the garbage collector.
func (e *EphemeralGarbageCollector) Start() {
	for {
		select {
		case <-e.cancelCh:
			return
		case pd := <-e.deleteCh:
			e.mu.Lock()

			entry, ok := e.toBeDeleted[pd.nodeID]
			if !ok || entry.gen != pd.gen {
				// Cancelled or rescheduled after this deletion was queued;
				// drop it so a reconnected node is not removed.
				e.mu.Unlock()

				continue
			}

			delete(e.toBeDeleted, pd.nodeID)
			e.mu.Unlock()

			go e.deleteFunc(pd.nodeID)
		}
	}
}

// firstOr returns the first non-empty option, or def if none is provided.
func firstOr(def string, opt []string) string {
	if len(opt) > 0 && opt[0] != "" {
		return opt[0]
	}

	return def
}

func (hsdb *HSDatabase) CreateNodeForTest(user *types.User, hostname ...string) *types.Node {
	if !testing.Testing() {
		panic("CreateNodeForTest can only be called during tests")
	}

	if user == nil {
		panic("CreateNodeForTest requires a valid user")
	}

	nodeName := firstOr(defaultTestNodePrefix, hostname)

	// Create a preauth key for the node
	pak, err := hsdb.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	if err != nil {
		panic(fmt.Sprintf("failed to create preauth key for test node: %v", err))
	}

	pakID := pak.ID
	nodeKey := key.NewNode()
	machineKey := key.NewMachine()
	discoKey := key.NewDisco()

	node := &types.Node{
		MachineKey:     machineKey.Public(),
		NodeKey:        nodeKey.Public(),
		DiscoKey:       discoKey.Public(),
		Hostname:       nodeName,
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      &pakID,
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

	prefix := firstOr(defaultTestNodePrefix, hostnamePrefix)

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

	prefix := firstOr(defaultTestNodePrefix, hostnamePrefix)

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
	// IPv4: 100.64.x.y (where x = nodeID/256, y = nodeID%256)
	// IPv6: fd7a:115c:a1e0::x:y (where x = high byte, y = low byte)
	// This supports up to 65535 nodes
	const (
		maxTestNodes    = 65535
		ipv4ByteDivisor = 256
	)

	if nodeID > maxTestNodes {
		return nil, nil, ErrCouldNotAllocateIP
	}

	// Split nodeID into high and low bytes for IPv4 (100.64.high.low)
	highByte := byte(nodeID / ipv4ByteDivisor)
	lowByte := byte(nodeID % ipv4ByteDivisor)
	ipv4 := netip.AddrFrom4([4]byte{100, 64, highByte, lowByte})

	// For IPv6, use the last two bytes of the address (fd7a:115c:a1e0::high:low)
	ipv6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, highByte, lowByte})

	return &ipv4, &ipv6, nil
}
