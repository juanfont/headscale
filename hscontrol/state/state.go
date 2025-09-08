// Package state provides core state management for Headscale, coordinating
// between subsystems like database, IP allocation, policy management, and DERP routing.

package state

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
	zcache "zgo.at/zcache/v2"
)

const (
	// registerCacheExpiration defines how long node registration entries remain in cache.
	registerCacheExpiration = time.Minute * 15

	// registerCacheCleanup defines the interval for cleaning up expired cache entries.
	registerCacheCleanup = time.Minute * 20
)

// ErrUnsupportedPolicyMode is returned for invalid policy modes. Valid modes are "file" and "db".
var ErrUnsupportedPolicyMode = errors.New("unsupported policy mode")

// State manages Headscale's core state, coordinating between database, policy management,
// IP allocation, and DERP routing. All methods are thread-safe.
type State struct {
	// mu protects all in-memory data structures from concurrent access
	mu deadlock.RWMutex
	// cfg holds the current Headscale configuration
	cfg *types.Config

	// nodeStore provides an in-memory cache for nodes.
	nodeStore *NodeStore

	// subsystem keeping state
	// db provides persistent storage and database operations
	db *hsdb.HSDatabase
	// ipAlloc manages IP address allocation for nodes
	ipAlloc *hsdb.IPAllocator
	// derpMap contains the current DERP relay configuration
	derpMap atomic.Pointer[tailcfg.DERPMap]
	// polMan handles policy evaluation and management
	polMan policy.PolicyManager
	// registrationCache caches node registration data to reduce database load
	registrationCache *zcache.Cache[types.RegistrationID, types.RegisterNode]
	// primaryRoutes tracks primary route assignments for nodes
	primaryRoutes *routes.PrimaryRoutes
}

// NewState creates and initializes a new State instance, setting up the database,
// IP allocator, DERP map, policy manager, and loading existing users and nodes.
func NewState(cfg *types.Config) (*State, error) {
	registrationCache := zcache.New[types.RegistrationID, types.RegisterNode](
		registerCacheExpiration,
		registerCacheCleanup,
	)

	db, err := hsdb.NewHeadscaleDatabase(
		cfg.Database,
		cfg.BaseDomain,
		registrationCache,
	)
	if err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	ipAlloc, err := hsdb.NewIPAllocator(db, cfg.PrefixV4, cfg.PrefixV6, cfg.IPAllocation)
	if err != nil {
		return nil, fmt.Errorf("init ip allocatior: %w", err)
	}

	nodes, err := db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes: %w", err)
	}

	// On startup, all nodes should be marked as offline until they reconnect
	// This ensures we don't have stale online status from previous runs
	for _, node := range nodes {
		node.IsOnline = ptr.To(false)
	}
	users, err := db.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	pol, err := policyBytes(db, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	polMan, err := policy.NewPolicyManager(pol, users, nodes.ViewSlice())
	if err != nil {
		return nil, fmt.Errorf("init policy manager: %w", err)
	}

	nodeStore := NewNodeStore(nodes, func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
		_, matchers := polMan.Filter()
		return policy.BuildPeerMap(views.SliceOf(nodes), matchers)
	})
	nodeStore.Start()

	return &State{
		cfg: cfg,

		db:                db,
		ipAlloc:           ipAlloc,
		polMan:            polMan,
		registrationCache: registrationCache,
		primaryRoutes:     routes.New(),
		nodeStore:         nodeStore,
	}, nil
}

// Close gracefully shuts down the State instance and releases all resources.
func (s *State) Close() error {
	s.nodeStore.Stop()

	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	return nil
}

// policyBytes loads policy configuration from file or database based on the configured mode.
// Returns nil if no policy is configured, which is valid.
func policyBytes(db *hsdb.HSDatabase, cfg *types.Config) ([]byte, error) {
	switch cfg.Policy.Mode {
	case types.PolicyModeFile:
		path := cfg.Policy.Path

		// It is fine to start headscale without a policy file.
		if len(path) == 0 {
			return nil, nil
		}

		absPath := util.AbsolutePathFromConfigPath(path)
		policyFile, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}
		defer policyFile.Close()

		return io.ReadAll(policyFile)

	case types.PolicyModeDB:
		p, err := db.GetPolicy()
		if err != nil {
			if errors.Is(err, types.ErrPolicyNotFound) {
				return nil, nil
			}

			return nil, err
		}

		if p.Data == "" {
			return nil, nil
		}

		return []byte(p.Data), err
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedPolicyMode, cfg.Policy.Mode)
}

// SetDERPMap updates the DERP relay configuration.
func (s *State) SetDERPMap(dm *tailcfg.DERPMap) {
	s.derpMap.Store(dm)
}

// DERPMap returns the current DERP relay configuration for peer-to-peer connectivity.
func (s *State) DERPMap() tailcfg.DERPMapView {
	return s.derpMap.Load().View()
}

// ReloadPolicy reloads the access control policy and triggers auto-approval if changed.
// Returns true if the policy changed.
func (s *State) ReloadPolicy() ([]change.ChangeSet, error) {
	pol, err := policyBytes(s.db, s.cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	policyChanged, err := s.polMan.SetPolicy(pol)
	if err != nil {
		return nil, fmt.Errorf("setting policy: %w", err)
	}

	cs := []change.ChangeSet{change.PolicyChange()}

	// Always call autoApproveNodes during policy reload, regardless of whether
	// the policy content has changed. This ensures that routes are re-evaluated
	// when they might have been manually disabled but could now be auto-approved
	// with the current policy.
	rcs, err := s.autoApproveNodes()
	if err != nil {
		return nil, fmt.Errorf("auto approving nodes: %w", err)
	}

	// TODO(kradalby): These changes can probably be safely ignored.
	// If the PolicyChange is happening, that will lead to a full update
	// meaning that we do not need to send individual route changes.
	cs = append(cs, rcs...)

	if len(rcs) > 0 || policyChanged {
		log.Info().
			Bool("policy.changed", policyChanged).
			Int("route.changes", len(rcs)).
			Int("total.changes", len(cs)).
			Msg("Policy reload completed with changes")
	}

	return cs, nil
}

// CreateUser creates a new user and updates the policy manager.
// Returns the created user, change set, and any error.
func (s *State) CreateUser(user types.User) (*types.User, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(&user).Error; err != nil {
		return nil, change.EmptySet, fmt.Errorf("creating user: %w", err)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		// Log the error but don't fail the user creation
		return &user, change.EmptySet, fmt.Errorf("failed to update policy manager after user creation: %w", err)
	}

	// Even if the policy manager doesn't detect a filter change, SSH policies
	// might now be resolvable when they weren't before. If there are existing
	// nodes, we should send a policy change to ensure they get updated SSH policies.
	// TODO(kradalby): detect this, or rebuild all SSH policies so we can determine
	// this upstream.
	if c.Empty() {
		c = change.PolicyChange()
	}

	log.Info().Str("user.name", user.Name).Msg("User created")

	return &user, c, nil
}

// UpdateUser modifies an existing user using the provided update function within a transaction.
// Returns the updated user, change set, and any error.
func (s *State) UpdateUser(userID types.UserID, updateFn func(*types.User) error) (*types.User, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	user, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		user, err := hsdb.GetUserByID(tx, userID)
		if err != nil {
			return nil, err
		}

		if err := updateFn(user); err != nil {
			return nil, err
		}

		if err := tx.Save(user).Error; err != nil {
			return nil, fmt.Errorf("updating user: %w", err)
		}

		return user, nil
	})
	if err != nil {
		return nil, change.EmptySet, err
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return user, change.EmptySet, fmt.Errorf("failed to update policy manager after user update: %w", err)
	}

	// TODO(kradalby): We might want to update nodestore with the user data

	return user, c, nil
}

// DeleteUser permanently removes a user and all associated data (nodes, API keys, etc).
// This operation is irreversible.
func (s *State) DeleteUser(userID types.UserID) error {
	return s.db.DestroyUser(userID)
}

// RenameUser changes a user's name. The new name must be unique.
func (s *State) RenameUser(userID types.UserID, newName string) (*types.User, change.ChangeSet, error) {
	return s.UpdateUser(userID, func(user *types.User) error {
		user.Name = newName
		return nil
	})
}

// GetUserByID retrieves a user by ID.
func (s *State) GetUserByID(userID types.UserID) (*types.User, error) {
	return s.db.GetUserByID(userID)
}

// GetUserByName retrieves a user by name.
func (s *State) GetUserByName(name string) (*types.User, error) {
	return s.db.GetUserByName(name)
}

// GetUserByOIDCIdentifier retrieves a user by their OIDC identifier.
func (s *State) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return s.db.GetUserByOIDCIdentifier(id)
}

// ListUsersWithFilter retrieves users matching the specified filter criteria.
func (s *State) ListUsersWithFilter(filter *types.User) ([]types.User, error) {
	return s.db.ListUsers(filter)
}

// ListAllUsers retrieves all users in the system.
func (s *State) ListAllUsers() ([]types.User, error) {
	return s.db.ListUsers()
}

// updateNodeTx performs a database transaction to update a node and refresh the policy manager.
// IMPORTANT: This function does NOT update the NodeStore. The caller MUST update the NodeStore
// BEFORE calling this function with the EXACT same changes that the database update will make.
// This ensures the NodeStore is the source of truth for the batcher and maintains consistency.
// Returns error only; callers should get the updated NodeView from NodeStore to maintain consistency.
func (s *State) updateNodeTx(nodeID types.NodeID, updateFn func(tx *gorm.DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		if err := updateFn(tx); err != nil {
			return nil, err
		}

		node, err := hsdb.GetNodeByID(tx, nodeID)
		if err != nil {
			return nil, err
		}

		if err := tx.Save(node).Error; err != nil {
			return nil, fmt.Errorf("updating node: %w", err)
		}

		return node, nil
	})
	return err
}

// persistNodeToDB saves the current state of a node from NodeStore to the database.
// CRITICAL: This function MUST get the latest node from NodeStore to ensure consistency.
func (s *State) persistNodeToDB(nodeID types.NodeID) (types.NodeView, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// CRITICAL: Always get the latest node from NodeStore to ensure we save the current state
	node, found := s.nodeStore.GetNode(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	nodePtr := node.AsStruct()

	if err := s.db.DB.Save(nodePtr).Error; err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("saving node: %w", err)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return nodePtr.View(), change.EmptySet, fmt.Errorf("failed to update policy manager after node save: %w", err)
	}

	if c.Empty() {
		c = change.NodeAdded(node.ID())
	}

	return node, c, nil
}

func (s *State) SaveNode(node types.NodeView) (types.NodeView, change.ChangeSet, error) {
	// Update NodeStore first
	nodePtr := node.AsStruct()

	s.nodeStore.PutNode(*nodePtr)

	// Then save to database
	return s.persistNodeToDB(node.ID())
}

// DeleteNode permanently removes a node and cleans up associated resources.
// Returns whether policies changed and any error. This operation is irreversible.
func (s *State) DeleteNode(node types.NodeView) (change.ChangeSet, error) {
	s.nodeStore.DeleteNode(node.ID())

	err := s.db.DeleteNode(node.AsStruct())
	if err != nil {
		return change.EmptySet, err
	}

	c := change.NodeRemoved(node.ID())

	// Check if policy manager needs updating after node deletion
	policyChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return change.EmptySet, fmt.Errorf("failed to update policy manager after node deletion: %w", err)
	}

	if !policyChange.Empty() {
		c = policyChange
	}

	return c, nil
}

// Connect marks a node as connected and updates its primary routes in the state.
func (s *State) Connect(id types.NodeID) []change.ChangeSet {
	// CRITICAL FIX: Update the online status in NodeStore BEFORE creating change notification
	// This ensures that when the NodeCameOnline change is distributed and processed by other nodes,
	// the NodeStore already reflects the correct online status for full map generation.
	// now := time.Now()
	s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = ptr.To(true)
		// n.LastSeen = ptr.To(now)
	})
	c := []change.ChangeSet{change.NodeOnline(id)}

	// Get fresh node data from NodeStore after the online status update
	node, found := s.GetNodeByID(id)
	if !found {
		return nil
	}

	log.Info().Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Node connected")

	// Use the node's current routes for primary route update
	// SubnetRoutes() returns only the intersection of announced AND approved routes
	// We MUST use SubnetRoutes() to maintain the security model
	routeChange := s.primaryRoutes.SetRoutes(id, node.SubnetRoutes()...)

	if routeChange {
		c = append(c, change.NodeAdded(id))
	}

	return c
}

// Disconnect marks a node as disconnected and updates its primary routes in the state.
func (s *State) Disconnect(id types.NodeID) ([]change.ChangeSet, error) {
	now := time.Now()

	// Get node info before updating for logging
	node, found := s.GetNodeByID(id)
	var nodeName string
	if found {
		nodeName = node.Hostname()
	}

	s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.LastSeen = ptr.To(now)
		// NodeStore is the source of truth for all node state including online status.
		n.IsOnline = ptr.To(false)
	})

	if found {
		log.Info().Uint64("node.id", id.Uint64()).Str("node.name", nodeName).Msg("Node disconnected")
	}

	err := s.updateNodeTx(id, func(tx *gorm.DB) error {
		// Update last_seen in the database
		// Note: IsOnline is managed only in NodeStore (marked with gorm:"-"), not persisted to database
		return hsdb.SetLastSeen(tx, id, now)
	})
	if err != nil {
		// Log error but don't fail the disconnection - NodeStore is already updated
		// and we need to send change notifications to peers
		log.Error().Err(err).Uint64("node.id", id.Uint64()).Str("node.name", nodeName).Msg("Failed to update last seen in database")
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		// Log error but continue - disconnection must proceed
		log.Error().Err(err).Uint64("node.id", id.Uint64()).Str("node.name", nodeName).Msg("Failed to update policy manager after node disconnect")
		c = change.EmptySet
	}

	// The node is disconnecting so make sure that none of the routes it
	// announced are served to any nodes.
	routeChange := s.primaryRoutes.SetRoutes(id)

	cs := []change.ChangeSet{change.NodeOffline(id), c}

	// If we have a policy change or route change, return that as it's more comprehensive
	// Otherwise, return the NodeOffline change to ensure nodes are notified
	if c.IsFull() || routeChange {
		cs = append(cs, change.PolicyChange())
	}

	return cs, nil
}

// GetNodeByID retrieves a node by ID.
// GetNodeByID retrieves a node by its ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByID(nodeID types.NodeID) (types.NodeView, bool) {
	return s.nodeStore.GetNode(nodeID)
}

// GetNodeByNodeKey retrieves a node by its Tailscale public key.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	return s.nodeStore.GetNodeByNodeKey(nodeKey)
}

// GetNodeByMachineKey retrieves a node by its machine key.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByMachineKey(machineKey key.MachinePublic) (types.NodeView, bool) {
	return s.nodeStore.GetNodeByMachineKey(machineKey)
}

// ListNodes retrieves specific nodes by ID, or all nodes if no IDs provided.
func (s *State) ListNodes(nodeIDs ...types.NodeID) views.Slice[types.NodeView] {
	if len(nodeIDs) == 0 {
		return s.nodeStore.ListNodes()
	}

	// Filter nodes by the requested IDs
	allNodes := s.nodeStore.ListNodes()
	nodeIDSet := make(map[types.NodeID]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		nodeIDSet[id] = struct{}{}
	}

	var filteredNodes []types.NodeView
	for _, node := range allNodes.All() {
		if _, exists := nodeIDSet[node.ID()]; exists {
			filteredNodes = append(filteredNodes, node)
		}
	}

	return views.SliceOf(filteredNodes)
}

// ListNodesByUser retrieves all nodes belonging to a specific user.
func (s *State) ListNodesByUser(userID types.UserID) views.Slice[types.NodeView] {
	return s.nodeStore.ListNodesByUser(userID)
}

// ListPeers retrieves nodes that can communicate with the specified node based on policy.
func (s *State) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) views.Slice[types.NodeView] {
	if len(peerIDs) == 0 {
		return s.nodeStore.ListPeers(nodeID)
	}

	// For specific peerIDs, filter from all nodes
	allNodes := s.nodeStore.ListNodes()
	nodeIDSet := make(map[types.NodeID]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		nodeIDSet[id] = struct{}{}
	}

	var filteredNodes []types.NodeView
	for _, node := range allNodes.All() {
		if _, exists := nodeIDSet[node.ID()]; exists {
			filteredNodes = append(filteredNodes, node)
		}
	}

	return views.SliceOf(filteredNodes)
}

// ListEphemeralNodes retrieves all ephemeral (temporary) nodes in the system.
func (s *State) ListEphemeralNodes() views.Slice[types.NodeView] {
	allNodes := s.nodeStore.ListNodes()
	var ephemeralNodes []types.NodeView

	for _, node := range allNodes.All() {
		// Check if node is ephemeral by checking its AuthKey
		if node.AuthKey().Valid() && node.AuthKey().Ephemeral() {
			ephemeralNodes = append(ephemeralNodes, node)
		}
	}

	return views.SliceOf(ephemeralNodes)
}

// SetNodeExpiry updates the expiration time for a node.
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry time.Time) (types.NodeView, change.ChangeSet, error) {
	// CRITICAL: Update NodeStore BEFORE database to ensure consistency.
	// The NodeStore update is blocking and will be the source of truth for the batcher.
	// The database update MUST make the EXACT same change.
	// If the database update fails, the NodeStore change will remain, but since we return
	// an error, no change notification will be sent to the batcher.
	expiryPtr := expiry
	s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.Expiry = &expiryPtr
	})

	err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.NodeSetExpiry(tx, nodeID, expiry)
	})
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("setting node expiry: %w", err)
	}

	// Get the updated node from NodeStore to ensure consistency
	// TODO(kradalby): Validate if this NodeStore read makes sense after database update
	n, found := s.GetNodeByID(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return n, change.EmptySet, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	if !c.IsFull() {
		c = change.KeyExpiry(nodeID)
	}

	return n, c, nil
}

// SetNodeTags assigns tags to a node for use in access control policies.
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (types.NodeView, change.ChangeSet, error) {
	// CRITICAL: Update NodeStore BEFORE database to ensure consistency.
	// The NodeStore update is blocking and will be the source of truth for the batcher.
	// The database update MUST make the EXACT same change.
	s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.ForcedTags = tags
	})

	err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetTags(tx, nodeID, tags)
	})
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("setting node tags: %w", err)
	}

	// Get the updated node from NodeStore to ensure consistency
	// TODO(kradalby): Validate if this NodeStore read makes sense after database update
	n, found := s.GetNodeByID(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return n, change.EmptySet, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	if !c.IsFull() {
		c = change.NodeAdded(nodeID)
	}

	return n, c, nil
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (types.NodeView, change.ChangeSet, error) {
	// TODO(kradalby): In principle we should call the AutoApprove logic here
	// because even if the CLI removes an auto-approved route, it will be added
	// back automatically.
	s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.ApprovedRoutes = routes
	})

	err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetApprovedRoutes(tx, nodeID, routes)
	})
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("setting approved routes: %w", err)
	}

	// Get the updated node from NodeStore to ensure consistency
	// TODO(kradalby): Validate if this NodeStore read makes sense after database update
	n, found := s.GetNodeByID(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return n, change.EmptySet, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	// Get the node from NodeStore to ensure we have the latest state
	nodeView, ok := s.GetNodeByID(nodeID)
	if !ok {
		return n, change.EmptySet, fmt.Errorf("node %d not found in NodeStore", nodeID)
	}
	// Use SubnetRoutes() instead of ApprovedRoutes() to ensure we only set
	// primary routes for routes that are both announced AND approved
	routeChange := s.primaryRoutes.SetRoutes(nodeID, nodeView.SubnetRoutes()...)

	if routeChange || !c.IsFull() {
		c = change.PolicyChange()
	}

	return n, c, nil
}

// RenameNode changes the display name of a node.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (types.NodeView, change.ChangeSet, error) {
	// Validate the new name before making any changes
	if err := util.CheckForFQDNRules(newName); err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("renaming node: %w", err)
	}

	// Check name uniqueness
	nodes, err := s.db.ListNodes()
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("checking name uniqueness: %w", err)
	}
	for _, node := range nodes {
		if node.ID != nodeID && node.GivenName == newName {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("name is not unique: %s", newName)
		}
	}

	// CRITICAL: Update NodeStore BEFORE database to ensure consistency.
	// The NodeStore update is blocking and will be the source of truth for the batcher.
	// The database update MUST make the EXACT same change.
	s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.GivenName = newName
	})

	err = s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.RenameNode(tx, nodeID, newName)
	})
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("renaming node: %w", err)
	}

	// Get the updated node from NodeStore to ensure consistency
	// TODO(kradalby): Validate if this NodeStore read makes sense after database update
	n, found := s.GetNodeByID(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return n, change.EmptySet, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	if !c.IsFull() {
		c = change.NodeAdded(nodeID)
	}

	return n, c, nil
}

// AssignNodeToUser transfers a node to a different user.
func (s *State) AssignNodeToUser(nodeID types.NodeID, userID types.UserID) (types.NodeView, change.ChangeSet, error) {
	// Validate that both node and user exist
	_, found := s.GetNodeByID(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found: %d", nodeID)
	}

	user, err := s.GetUserByID(userID)
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("user not found: %w", err)
	}

	// CRITICAL: Update NodeStore BEFORE database to ensure consistency.
	// The NodeStore update is blocking and will be the source of truth for the batcher.
	// The database update MUST make the EXACT same change.
	s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.User = *user
		n.UserID = uint(userID)
	})

	err = s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.AssignNodeToUser(tx, nodeID, userID)
	})
	if err != nil {
		return types.NodeView{}, change.EmptySet, err
	}

	// Get the updated node from NodeStore to ensure consistency
	// TODO(kradalby): Validate if this NodeStore read makes sense after database update
	n, found := s.GetNodeByID(nodeID)
	if !found {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return n, change.EmptySet, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	if !c.IsFull() {
		c = change.NodeAdded(nodeID)
	}

	return n, c, nil
}

// BackfillNodeIPs assigns IP addresses to nodes that don't have them.
func (s *State) BackfillNodeIPs() ([]string, error) {
	changes, err := s.db.BackfillNodeIPs(s.ipAlloc)
	if err != nil {
		return nil, err
	}

	// Refresh NodeStore after IP changes to ensure consistency
	if len(changes) > 0 {
		nodes, err := s.db.ListNodes()
		if err != nil {
			return changes, fmt.Errorf("failed to refresh NodeStore after IP backfill: %w", err)
		}

		for _, node := range nodes {
			// Preserve online status and NetInfo when refreshing from database
			existingNode, exists := s.nodeStore.GetNode(node.ID)
			if exists && existingNode.Valid() {
				node.IsOnline = ptr.To(existingNode.IsOnline().Get())

				// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
				// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

				// Preserve NetInfo from existing node to prevent loss during backfill
				netInfo := NetInfoFromMapRequest(node.ID, existingNode.AsStruct().Hostinfo, node.Hostinfo)
				if netInfo != nil {
					if node.Hostinfo != nil {
						hostinfoCopy := *node.Hostinfo
						hostinfoCopy.NetInfo = netInfo
						node.Hostinfo = &hostinfoCopy
					} else {
						node.Hostinfo = &tailcfg.Hostinfo{NetInfo: netInfo}
					}
				}
			}
			// TODO(kradalby): This should just update the IP addresses, nothing else in the node store.
			// We should avoid PutNode here.
			s.nodeStore.PutNode(*node)
		}
	}

	return changes, nil
}

// ExpireExpiredNodes finds and processes expired nodes since the last check.
// Returns next check time, state update with expired nodes, and whether any were found.
func (s *State) ExpireExpiredNodes(lastCheck time.Time) (time.Time, []change.ChangeSet, bool) {
	// Why capture start time: We need to ensure we don't miss nodes that expire
	// while this function is running by using a consistent timestamp for the next check
	started := time.Now()

	var updates []change.ChangeSet

	for _, node := range s.nodeStore.ListNodes().All() {
		if !node.Valid() {
			continue
		}

		// Why check After(lastCheck): We only want to notify about nodes that
		// expired since the last check to avoid duplicate notifications
		if node.IsExpired() && node.Expiry().Valid() && node.Expiry().Get().After(lastCheck) {
			updates = append(updates, change.KeyExpiry(node.ID()))
		}
	}

	if len(updates) > 0 {
		return started, updates, true
	}

	return started, nil, false
}

// SSHPolicy returns the SSH access policy for a node.
func (s *State) SSHPolicy(node types.NodeView) (*tailcfg.SSHPolicy, error) {
	return s.polMan.SSHPolicy(node)
}

// Filter returns the current network filter rules and matches.
func (s *State) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	return s.polMan.Filter()
}

// NodeCanHaveTag checks if a node is allowed to have a specific tag.
func (s *State) NodeCanHaveTag(node types.NodeView, tag string) bool {
	return s.polMan.NodeCanHaveTag(node, tag)
}

// SetPolicy updates the policy configuration.
func (s *State) SetPolicy(pol []byte) (bool, error) {
	return s.polMan.SetPolicy(pol)
}

// AutoApproveRoutes checks if a node's routes should be auto-approved.
// AutoApproveRoutes checks if any routes should be auto-approved for a node and updates them.
func (s *State) AutoApproveRoutes(nv types.NodeView) bool {
	approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
	if changed {
		log.Debug().
			Uint64("node.id", nv.ID().Uint64()).
			Str("node.name", nv.Hostname()).
			Strs("routes.announced", util.PrefixesToString(nv.AnnouncedRoutes())).
			Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
			Strs("routes.approved.new", util.PrefixesToString(approved)).
			Msg("Single node auto-approval detected route changes")

		// Persist the auto-approved routes to database and NodeStore via SetApprovedRoutes
		// This ensures consistency between database and NodeStore
		_, _, err := s.SetApprovedRoutes(nv.ID(), approved)
		if err != nil {
			log.Error().
				Uint64("node.id", nv.ID().Uint64()).
				Str("node.name", nv.Hostname()).
				Err(err).
				Msg("Failed to persist auto-approved routes")

			return false
		}

		log.Info().Uint64("node.id", nv.ID().Uint64()).Str("node.name", nv.Hostname()).Strs("routes.approved", util.PrefixesToString(approved)).Msg("Routes approved")
	}

	return changed
}

// GetPolicy retrieves the current policy from the database.
func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy()
}

// SetPolicyInDB stores policy data in the database.
func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data)
}

// SetNodeRoutes sets the primary routes for a node.
func (s *State) SetNodeRoutes(nodeID types.NodeID, routes ...netip.Prefix) change.ChangeSet {
	if s.primaryRoutes.SetRoutes(nodeID, routes...) {
		// Route changes affect packet filters for all nodes, so trigger a policy change
		// to ensure filters are regenerated across the entire network
		return change.PolicyChange()
	}

	return change.EmptySet
}

// GetNodePrimaryRoutes returns the primary routes for a node.
func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.primaryRoutes.PrimaryRoutes(nodeID)
}

// PrimaryRoutesString returns a string representation of all primary routes.
func (s *State) PrimaryRoutesString() string {
	return s.primaryRoutes.String()
}

// ValidateAPIKey checks if an API key is valid and active.
func (s *State) ValidateAPIKey(keyStr string) (bool, error) {
	return s.db.ValidateAPIKey(keyStr)
}

// CreateAPIKey generates a new API key with optional expiration.
func (s *State) CreateAPIKey(expiration *time.Time) (string, *types.APIKey, error) {
	return s.db.CreateAPIKey(expiration)
}

// GetAPIKey retrieves an API key by its prefix.
func (s *State) GetAPIKey(prefix string) (*types.APIKey, error) {
	return s.db.GetAPIKey(prefix)
}

// ExpireAPIKey marks an API key as expired.
func (s *State) ExpireAPIKey(key *types.APIKey) error {
	return s.db.ExpireAPIKey(key)
}

// ListAPIKeys returns all API keys in the system.
func (s *State) ListAPIKeys() ([]types.APIKey, error) {
	return s.db.ListAPIKeys()
}

// DestroyAPIKey permanently removes an API key.
func (s *State) DestroyAPIKey(key types.APIKey) error {
	return s.db.DestroyAPIKey(key)
}

// CreatePreAuthKey generates a new pre-authentication key for a user.
func (s *State) CreatePreAuthKey(userID types.UserID, reusable bool, ephemeral bool, expiration *time.Time, aclTags []string) (*types.PreAuthKey, error) {
	return s.db.CreatePreAuthKey(userID, reusable, ephemeral, expiration, aclTags)
}

// GetPreAuthKey retrieves a pre-authentication key by ID.
func (s *State) GetPreAuthKey(id string) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKey(id)
}

// ListPreAuthKeys returns all pre-authentication keys for a user.
func (s *State) ListPreAuthKeys(userID types.UserID) ([]types.PreAuthKey, error) {
	return s.db.ListPreAuthKeys(userID)
}

// ExpirePreAuthKey marks a pre-authentication key as expired.
func (s *State) ExpirePreAuthKey(preAuthKey *types.PreAuthKey) error {
	return s.db.ExpirePreAuthKey(preAuthKey)
}

// GetRegistrationCacheEntry retrieves a node registration from cache.
func (s *State) GetRegistrationCacheEntry(id types.RegistrationID) (*types.RegisterNode, bool) {
	entry, found := s.registrationCache.Get(id)
	if !found {
		return nil, false
	}

	return &entry, true
}

// SetRegistrationCacheEntry stores a node registration in cache.
func (s *State) SetRegistrationCacheEntry(id types.RegistrationID, entry types.RegisterNode) {
	s.registrationCache.Set(id, entry)
}

// HandleNodeFromAuthPath handles node registration through authentication flow (like OIDC).
func (s *State) HandleNodeFromAuthPath(
	registrationID types.RegistrationID,
	userID types.UserID,
	expiry *time.Time,
	registrationMethod string,
) (types.NodeView, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the registration entry from cache
	regEntry, ok := s.GetRegistrationCacheEntry(registrationID)
	if !ok {
		return types.NodeView{}, change.EmptySet, hsdb.ErrNodeNotFoundRegistrationCache
	}

	// Get the user
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("failed to find user: %w", err)
	}

	// Check if node already exists by node key
	existingNodeView, exists := s.nodeStore.GetNodeByNodeKey(regEntry.Node.NodeKey)
	if exists && existingNodeView.Valid() {
		// Node exists - this is a refresh/re-registration
		log.Debug().
			Caller().
			Str("registration_id", registrationID.String()).
			Str("user.name", user.Username()).
			Str("registrationMethod", registrationMethod).
			Str("node.name", existingNodeView.Hostname()).
			Uint64("node.id", existingNodeView.ID().Uint64()).
			Msg("Refreshing existing node registration")

		// Update NodeStore first with the new expiry
		s.nodeStore.UpdateNode(existingNodeView.ID(), func(node *types.Node) {
			if expiry != nil {
				node.Expiry = expiry
			}
			// Mark as offline since node is reconnecting
			node.IsOnline = ptr.To(false)
			node.LastSeen = ptr.To(time.Now())
		})

		// Save to database
		_, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			err := hsdb.NodeSetExpiry(tx, existingNodeView.ID(), *expiry)
			if err != nil {
				return nil, err
			}
			// Return the node to satisfy the Write signature
			return hsdb.GetNodeByID(tx, existingNodeView.ID())
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("failed to update node expiry: %w", err)
		}

		// Get updated node from NodeStore
		updatedNode, _ := s.nodeStore.GetNode(existingNodeView.ID())

		return updatedNode, change.KeyExpiry(existingNodeView.ID()), nil
	}

	// New node registration
	log.Debug().
		Caller().
		Str("registration_id", registrationID.String()).
		Str("user.name", user.Username()).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", expiry)).
		Msg("Registering new node from auth callback")

	// Check if node exists with same machine key
	var existingMachineNode *types.Node
	if nv, exists := s.nodeStore.GetNodeByMachineKey(regEntry.Node.MachineKey); exists && nv.Valid() {
		existingMachineNode = nv.AsStruct()
	}

	// Prepare the node for registration
	nodeToRegister := regEntry.Node
	nodeToRegister.UserID = uint(userID)
	nodeToRegister.User = *user
	nodeToRegister.RegisterMethod = registrationMethod
	if expiry != nil {
		nodeToRegister.Expiry = expiry
	}

	// Handle IP allocation
	var ipv4, ipv6 *netip.Addr
	if existingMachineNode != nil && existingMachineNode.UserID == uint(userID) {
		// Reuse existing IPs and properties
		nodeToRegister.ID = existingMachineNode.ID
		nodeToRegister.GivenName = existingMachineNode.GivenName
		nodeToRegister.ApprovedRoutes = existingMachineNode.ApprovedRoutes
		ipv4 = existingMachineNode.IPv4
		ipv6 = existingMachineNode.IPv6
	} else {
		// Allocate new IPs
		ipv4, ipv6, err = s.ipAlloc.Next()
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("allocating IPs: %w", err)
		}
	}

	nodeToRegister.IPv4 = ipv4
	nodeToRegister.IPv6 = ipv6

	// Ensure unique given name if not set
	if nodeToRegister.GivenName == "" {
		givenName, err := hsdb.EnsureUniqueGivenName(s.db.DB, nodeToRegister.Hostname)
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("failed to ensure unique given name: %w", err)
		}
		nodeToRegister.GivenName = givenName
	}

	var savedNode *types.Node
	if existingMachineNode != nil && existingMachineNode.UserID == uint(userID) {
		// Update existing node - NodeStore first, then database
		s.nodeStore.UpdateNode(existingMachineNode.ID, func(node *types.Node) {
			node.NodeKey = nodeToRegister.NodeKey
			node.DiscoKey = nodeToRegister.DiscoKey
			node.Hostname = nodeToRegister.Hostname

			// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
			// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

			// Preserve NetInfo from existing node when re-registering
			netInfo := NetInfoFromMapRequest(existingMachineNode.ID, existingMachineNode.Hostinfo, nodeToRegister.Hostinfo)
			if netInfo != nil {
				if nodeToRegister.Hostinfo != nil {
					hostinfoCopy := *nodeToRegister.Hostinfo
					hostinfoCopy.NetInfo = netInfo
					node.Hostinfo = &hostinfoCopy
				} else {
					node.Hostinfo = &tailcfg.Hostinfo{NetInfo: netInfo}
				}
			} else {
				node.Hostinfo = nodeToRegister.Hostinfo
			}

			node.Endpoints = nodeToRegister.Endpoints
			node.RegisterMethod = nodeToRegister.RegisterMethod
			if expiry != nil {
				node.Expiry = expiry
			}
			node.IsOnline = ptr.To(false)
			node.LastSeen = ptr.To(time.Now())
		})

		// Save to database
		savedNode, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			if err := tx.Save(&nodeToRegister).Error; err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}
			return &nodeToRegister, nil
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, err
		}
	} else {
		// New node - database first to get ID, then NodeStore
		savedNode, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			if err := tx.Save(&nodeToRegister).Error; err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}
			return &nodeToRegister, nil
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, err
		}

		// Add to NodeStore after database creates the ID
		s.nodeStore.PutNode(*savedNode)
	}

	// Delete from registration cache
	s.registrationCache.Delete(registrationID)

	// Signal to waiting clients
	select {
	case regEntry.Registered <- savedNode:
	default:
	}
	close(regEntry.Registered)

	// Update policy manager
	nodesChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return savedNode.View(), change.NodeAdded(savedNode.ID), fmt.Errorf("failed to update policy manager: %w", err)
	}

	if !nodesChange.Empty() {
		return savedNode.View(), nodesChange, nil
	}

	return savedNode.View(), change.NodeAdded(savedNode.ID), nil
}

// HandleNodeFromPreAuthKey handles node registration using a pre-authentication key.
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (types.NodeView, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return types.NodeView{}, change.EmptySet, err
	}

	err = pak.Validate()
	if err != nil {
		return types.NodeView{}, change.EmptySet, err
	}

	// Check if this is a logout request for an ephemeral node
	if !regReq.Expiry.IsZero() && regReq.Expiry.Before(time.Now()) && pak.Ephemeral {
		// Find the node to delete
		var nodeToDelete types.NodeView
		for _, nv := range s.nodeStore.ListNodes().All() {
			if nv.Valid() && nv.MachineKey() == machineKey {
				nodeToDelete = nv
				break
			}
		}
		if nodeToDelete.Valid() {
			c, err := s.DeleteNode(nodeToDelete)
			if err != nil {
				return types.NodeView{}, change.EmptySet, fmt.Errorf("deleting ephemeral node during logout: %w", err)
			}

			return types.NodeView{}, c, nil
		}

		return types.NodeView{}, change.EmptySet, nil
	}

	log.Debug().
		Caller().
		Str("node.name", regReq.Hostinfo.Hostname).
		Str("machine.key", machineKey.ShortString()).
		Str("node.key", regReq.NodeKey.ShortString()).
		Str("user.name", pak.User.Username()).
		Msg("Registering node with pre-auth key")

	// Check if node already exists with same machine key
	var existingNode *types.Node
	if nv, exists := s.nodeStore.GetNodeByMachineKey(machineKey); exists && nv.Valid() {
		existingNode = nv.AsStruct()
	}

	// Prepare the node for registration
	nodeToRegister := types.Node{
		Hostname:       regReq.Hostinfo.Hostname,
		UserID:         pak.User.ID,
		User:           pak.User,
		MachineKey:     machineKey,
		NodeKey:        regReq.NodeKey,
		Hostinfo:       regReq.Hostinfo,
		LastSeen:       ptr.To(time.Now()),
		RegisterMethod: util.RegisterMethodAuthKey,
		ForcedTags:     pak.Proto().GetAclTags(),
		AuthKey:        pak,
		AuthKeyID:      &pak.ID,
	}

	if !regReq.Expiry.IsZero() {
		nodeToRegister.Expiry = &regReq.Expiry
	}

	// Handle IP allocation and existing node properties
	var ipv4, ipv6 *netip.Addr
	if existingNode != nil && existingNode.UserID == pak.User.ID {
		// Reuse existing node properties
		nodeToRegister.ID = existingNode.ID
		nodeToRegister.GivenName = existingNode.GivenName
		nodeToRegister.ApprovedRoutes = existingNode.ApprovedRoutes
		ipv4 = existingNode.IPv4
		ipv6 = existingNode.IPv6
	} else {
		// Allocate new IPs
		ipv4, ipv6, err = s.ipAlloc.Next()
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("allocating IPs: %w", err)
		}
	}

	nodeToRegister.IPv4 = ipv4
	nodeToRegister.IPv6 = ipv6

	// Ensure unique given name if not set
	if nodeToRegister.GivenName == "" {
		givenName, err := hsdb.EnsureUniqueGivenName(s.db.DB, nodeToRegister.Hostname)
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("failed to ensure unique given name: %w", err)
		}
		nodeToRegister.GivenName = givenName
	}

	var savedNode *types.Node
	if existingNode != nil && existingNode.UserID == pak.User.ID {
		// Update existing node - NodeStore first, then database
		s.nodeStore.UpdateNode(existingNode.ID, func(node *types.Node) {
			node.NodeKey = nodeToRegister.NodeKey
			node.Hostname = nodeToRegister.Hostname

			// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
			// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

			// Preserve NetInfo from existing node when re-registering
			netInfo := NetInfoFromMapRequest(existingNode.ID, existingNode.Hostinfo, nodeToRegister.Hostinfo)
			if netInfo != nil {
				if nodeToRegister.Hostinfo != nil {
					hostinfoCopy := *nodeToRegister.Hostinfo
					hostinfoCopy.NetInfo = netInfo
					node.Hostinfo = &hostinfoCopy
				} else {
					node.Hostinfo = &tailcfg.Hostinfo{NetInfo: netInfo}
				}
			} else {
				node.Hostinfo = nodeToRegister.Hostinfo
			}

			node.Endpoints = nodeToRegister.Endpoints
			node.RegisterMethod = nodeToRegister.RegisterMethod
			node.ForcedTags = nodeToRegister.ForcedTags
			node.AuthKey = nodeToRegister.AuthKey
			node.AuthKeyID = nodeToRegister.AuthKeyID
			if nodeToRegister.Expiry != nil {
				node.Expiry = nodeToRegister.Expiry
			}
			node.IsOnline = ptr.To(false)
			node.LastSeen = ptr.To(time.Now())
		})

		log.Trace().
			Caller().
			Str("node.name", nodeToRegister.Hostname).
			Uint64("node.id", existingNode.ID.Uint64()).
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", regReq.NodeKey.ShortString()).
			Str("user.name", pak.User.Username()).
			Msg("Node re-authorized")

		// Save to database
		savedNode, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			if err := tx.Save(&nodeToRegister).Error; err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}

			if !pak.Reusable {
				err = hsdb.UsePreAuthKey(tx, pak)
				if err != nil {
					return nil, fmt.Errorf("using pre auth key: %w", err)
				}
			}

			return &nodeToRegister, nil
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("writing node to database: %w", err)
		}
	} else {
		// New node - database first to get ID, then NodeStore
		savedNode, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			if err := tx.Save(&nodeToRegister).Error; err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}

			if !pak.Reusable {
				err = hsdb.UsePreAuthKey(tx, pak)
				if err != nil {
					return nil, fmt.Errorf("using pre auth key: %w", err)
				}
			}

			return &nodeToRegister, nil
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("writing node to database: %w", err)
		}

		// Add to NodeStore after database creates the ID
		s.nodeStore.PutNode(*savedNode)
	}

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return savedNode.View(), change.NodeAdded(savedNode.ID), fmt.Errorf("failed to update policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return savedNode.View(), change.NodeAdded(savedNode.ID), fmt.Errorf("failed to update policy manager nodes: %w", err)
	}

	var c change.ChangeSet
	if !usersChange.Empty() || !nodesChange.Empty() {
		c = change.PolicyChange()
	} else {
		c = change.NodeAdded(savedNode.ID)
	}

	return savedNode.View(), c, nil
}

// updatePolicyManagerUsers updates the policy manager with current users.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for users.
// updatePolicyManagerUsers refreshes the policy manager with current user data.
func (s *State) updatePolicyManagerUsers() (change.ChangeSet, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return change.EmptySet, fmt.Errorf("listing users for policy update: %w", err)
	}

	log.Debug().Caller().Int("user.count", len(users)).Msg("Policy manager user update initiated because user list modification detected")

	changed, err := s.polMan.SetUsers(users)
	if err != nil {
		return change.EmptySet, fmt.Errorf("updating policy manager users: %w", err)
	}

	log.Debug().Caller().Bool("policy.changed", changed).Msg("Policy manager user update completed because SetUsers operation finished")

	if changed {
		return change.PolicyChange(), nil
	}

	return change.EmptySet, nil
}

// updatePolicyManagerNodes updates the policy manager with current nodes.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for nodes.
// updatePolicyManagerNodes refreshes the policy manager with current node data.
func (s *State) updatePolicyManagerNodes() (change.ChangeSet, error) {
	nodes := s.ListNodes()

	changed, err := s.polMan.SetNodes(nodes)
	if err != nil {
		return change.EmptySet, fmt.Errorf("updating policy manager nodes: %w", err)
	}

	if changed {
		return change.PolicyChange(), nil
	}

	return change.EmptySet, nil
}

// PingDB checks if the database connection is healthy.
func (s *State) PingDB(ctx context.Context) error {
	return s.db.PingDB(ctx)
}

// autoApproveNodes mass approves routes on all nodes. It is _only_ intended for
// use when the policy is replaced. It is not sending or reporting any changes
// or updates as we send full updates after replacing the policy.
// TODO(kradalby): This is kind of messy, maybe this is another +1
// for an event bus. See example comments here.
// autoApproveNodes automatically approves nodes based on policy rules.
func (s *State) autoApproveNodes() ([]change.ChangeSet, error) {
	nodes := s.ListNodes()

	// Approve routes concurrently, this should make it likely
	// that the writes end in the same batch in the nodestore write.
	var errg errgroup.Group
	var cs []change.ChangeSet
	var mu sync.Mutex
	for _, nv := range nodes.All() {
		errg.Go(func() error {
			approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
			if changed {
				log.Debug().
					Uint64("node.id", nv.ID().Uint64()).
					Str("node.name", nv.Hostname()).
					Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
					Strs("routes.approved.new", util.PrefixesToString(approved)).
					Msg("Routes auto-approved by policy")

				_, c, err := s.SetApprovedRoutes(nv.ID(), approved)
				if err != nil {
					return err
				}

				mu.Lock()
				cs = append(cs, c)
				mu.Unlock()
			}

			return nil
		})
	}

	err := errg.Wait()
	if err != nil {
		return nil, err
	}

	return cs, nil
}

// UpdateNodeFromMapRequest processes a MapRequest and updates the node.
// TODO(kradalby): This is essentially a patch update that could be sent directly to nodes,
// which means we could shortcut the whole change thing if there are no other important updates.
// When a field is added to this function, remember to also add it to:
// - node.PeerChangeFromMapRequest
// - node.ApplyPeerChange
// - logTracePeerChange in poll.go.
func (s *State) UpdateNodeFromMapRequest(id types.NodeID, req tailcfg.MapRequest) (change.ChangeSet, error) {
	log.Trace().
		Caller().
		Uint64("node.id", id.Uint64()).
		Interface("request", req).
		Msg("Processing MapRequest for node")

	var routeChange bool
	var hostinfoChanged bool
	var needsRouteApproval bool
	// We need to ensure we update the node as it is in the NodeStore at
	// the time of the request.
	s.nodeStore.UpdateNode(id, func(currentNode *types.Node) {
		peerChange := currentNode.PeerChangeFromMapRequest(req)
		hostinfoChanged = !hostinfoEqual(currentNode.View(), req.Hostinfo)

		// Get the correct NetInfo to use
		netInfo := NetInfoFromMapRequest(id, currentNode.Hostinfo, req.Hostinfo)

		// Apply NetInfo to request Hostinfo
		if req.Hostinfo != nil {
			if netInfo != nil {
				// Create a copy to avoid modifying the original
				hostinfoCopy := *req.Hostinfo
				hostinfoCopy.NetInfo = netInfo
				req.Hostinfo = &hostinfoCopy
			}
		} else if netInfo != nil {
			// Create minimal Hostinfo with NetInfo
			req.Hostinfo = &tailcfg.Hostinfo{
				NetInfo: netInfo,
			}
		}

		// Re-check hostinfoChanged after potential NetInfo preservation
		hostinfoChanged = !hostinfoEqual(currentNode.View(), req.Hostinfo)

		// If there is no changes and nothing to save,
		// return early.
		if peerChangeEmpty(peerChange) && !hostinfoChanged {
			return
		}

		// Calculate route approval before NodeStore update to avoid calling View() inside callback
		var autoApprovedRoutes []netip.Prefix
		var hasNewRoutes bool
		if hi := req.Hostinfo; hi != nil {
			hasNewRoutes = len(hi.RoutableIPs) > 0
		}
		needsRouteApproval = hostinfoChanged && (routesChanged(currentNode.View(), req.Hostinfo) || (hasNewRoutes && len(currentNode.ApprovedRoutes) == 0))
		if needsRouteApproval {
			// Extract announced routes from request
			var announcedRoutes []netip.Prefix
			if req.Hostinfo != nil {
				announcedRoutes = req.Hostinfo.RoutableIPs
			}

			// Apply policy-based auto-approval if routes are announced
			if len(announcedRoutes) > 0 {
				autoApprovedRoutes, routeChange = policy.ApproveRoutesWithPolicy(
					s.polMan,
					currentNode.View(),
					currentNode.ApprovedRoutes,
					announcedRoutes,
				)
			}
		}

		// Log when routes change but approval doesn't
		if hostinfoChanged && !routeChange {
			if hi := req.Hostinfo; hi != nil {
				if routesChanged(currentNode.View(), hi) {
					log.Debug().
						Caller().
						Uint64("node.id", id.Uint64()).
						Strs("oldAnnouncedRoutes", util.PrefixesToString(currentNode.AnnouncedRoutes())).
						Strs("newAnnouncedRoutes", util.PrefixesToString(hi.RoutableIPs)).
						Strs("approvedRoutes", util.PrefixesToString(currentNode.ApprovedRoutes)).
						Bool("routeChange", routeChange).
						Msg("announced routes changed but approved routes did not")
				}
			}
		}

		currentNode.ApplyPeerChange(&peerChange)

		if hostinfoChanged {
			// The node might not set NetInfo if it has not changed and if
			// the full HostInfo object is overwritten, the information is lost.
			// If there is no NetInfo, keep the previous one.
			// From 1.66 the client only sends it if changed:
			// https://github.com/tailscale/tailscale/commit/e1011f138737286ecf5123ff887a7a5800d129a2
			// TODO(kradalby): evaluate if we need better comparing of hostinfo
			// before we take the changes.
			// NetInfo preservation has already been handled above before early return check
			currentNode.Hostinfo = req.Hostinfo
			currentNode.ApplyHostnameFromHostInfo(req.Hostinfo)

			if routeChange {
				// Apply pre-calculated route approval
				// Always apply the route approval result to ensure consistency,
				// regardless of whether the policy evaluation detected changes.
				// This fixes the bug where routes weren't properly cleared when
				// auto-approvers were removed from the policy.
				log.Info().
					Uint64("node.id", id.Uint64()).
					Strs("oldApprovedRoutes", util.PrefixesToString(currentNode.ApprovedRoutes)).
					Strs("newApprovedRoutes", util.PrefixesToString(autoApprovedRoutes)).
					Bool("routeChanged", routeChange).
					Msg("applying route approval results")
				currentNode.ApprovedRoutes = autoApprovedRoutes
			}
		}
	})

	nodeRouteChange := change.EmptySet

	// Handle route changes after NodeStore update
	// We need to update node routes if either:
	// 1. The approved routes changed (routeChange is true), OR
	// 2. The announced routes changed (even if approved routes stayed the same)
	// This is because SubnetRoutes is the intersection of announced AND approved routes.
	needsRouteUpdate := false
	var routesChangedButNotApproved bool
	if hostinfoChanged && needsRouteApproval && !routeChange {
		if hi := req.Hostinfo; hi != nil {
			routesChangedButNotApproved = true
		}
	}
	if routeChange {
		needsRouteUpdate = true
		log.Debug().
			Caller().
			Uint64("node.id", id.Uint64()).
			Msg("updating routes because approved routes changed")
	} else if routesChangedButNotApproved {
		needsRouteUpdate = true
		log.Debug().
			Caller().
			Uint64("node.id", id.Uint64()).
			Msg("updating routes because announced routes changed but approved routes did not")
	}

	if needsRouteUpdate {
		// Get the updated node to access its subnet routes
		updatedNode, exists := s.GetNodeByID(id)
		if !exists {
			return change.EmptySet, fmt.Errorf("node disappeared during update: %d", id)
		}

		// SetNodeRoutes sets the active/distributed routes, so we must use SubnetRoutes()
		// which returns only the intersection of announced AND approved routes.
		// Using AnnouncedRoutes() would bypass the security model and auto-approve everything.
		log.Debug().
			Caller().
			Uint64("node.id", id.Uint64()).
			Strs("announcedRoutes", util.PrefixesToString(updatedNode.AnnouncedRoutes())).
			Strs("approvedRoutes", util.PrefixesToString(updatedNode.ApprovedRoutes().AsSlice())).
			Strs("subnetRoutes", util.PrefixesToString(updatedNode.SubnetRoutes())).
			Msg("updating node routes for distribution")
		nodeRouteChange = s.SetNodeRoutes(id, updatedNode.SubnetRoutes()...)
	}

	_, policyChange, err := s.persistNodeToDB(id)
	if err != nil {
		return change.EmptySet, fmt.Errorf("saving to database: %w", err)
	}

	if policyChange.IsFull() {
		return policyChange, nil
	}
	if !nodeRouteChange.Empty() {
		return nodeRouteChange, nil
	}

	return change.NodeAdded(id), nil
}

func hostinfoEqual(oldNode types.NodeView, new *tailcfg.Hostinfo) bool {
	if !oldNode.Valid() && new == nil {
		return true
	}
	if !oldNode.Valid() || new == nil {
		return false
	}
	old := oldNode.AsStruct().Hostinfo

	return old.Equal(new)
}

func routesChanged(oldNode types.NodeView, new *tailcfg.Hostinfo) bool {
	var oldRoutes []netip.Prefix
	if oldNode.Valid() && oldNode.AsStruct().Hostinfo != nil {
		oldRoutes = oldNode.AsStruct().Hostinfo.RoutableIPs
	}

	newRoutes := new.RoutableIPs
	if newRoutes == nil {
		newRoutes = []netip.Prefix{}
	}

	tsaddr.SortPrefixes(oldRoutes)
	tsaddr.SortPrefixes(newRoutes)

	return !slices.Equal(oldRoutes, newRoutes)
}

func peerChangeEmpty(peerChange tailcfg.PeerChange) bool {
	return peerChange.Key == nil &&
		peerChange.DiscoKey == nil &&
		peerChange.Online == nil &&
		peerChange.Endpoints == nil &&
		peerChange.DERPRegion == 0 &&
		peerChange.LastSeen == nil &&
		peerChange.KeyExpiry == nil
}
