// Package state provides core state management for Headscale, coordinating
// between subsystems like database, IP allocation, policy management, and DERP routing.

package state

import (
	"cmp"
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
	cacheExpiration := registerCacheExpiration
	if cfg.Tuning.RegisterCacheExpiration != 0 {
		cacheExpiration = cfg.Tuning.RegisterCacheExpiration
	}

	cacheCleanup := registerCacheCleanup
	if cfg.Tuning.RegisterCacheCleanup != 0 {
		cacheCleanup = cfg.Tuning.RegisterCacheCleanup
	}

	registrationCache := zcache.New[types.RegistrationID, types.RegisterNode](
		cacheExpiration,
		cacheCleanup,
	)

	registrationCache.OnEvicted(
		func(id types.RegistrationID, rn types.RegisterNode) {
			rn.SendAndClose(nil)
		},
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

	// PolicyManager.BuildPeerMap handles both global and per-node filter complexity.
	// This moves the complex peer relationship logic into the policy package where it belongs.
	nodeStore := NewNodeStore(nodes, func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
		return polMan.BuildPeerMap(views.SliceOf(nodes))
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

	// Rebuild peer maps after policy changes because the peersFunc in NodeStore
	// uses the PolicyManager's filters. Without this, nodes won't see newly allowed
	// peers until a node is added/removed, causing autogroup:self policies to not
	// propagate correctly when switching between policy types.
	s.nodeStore.RebuildPeerMaps()

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

// persistNodeToDB saves the given node state to the database.
// This function must receive the exact node state to save to ensure consistency between
// NodeStore and the database. It verifies the node still exists in NodeStore to prevent
// race conditions where a node might be deleted between UpdateNode returning and
// persistNodeToDB being called.
func (s *State) persistNodeToDB(node types.NodeView) (types.NodeView, change.ChangeSet, error) {
	if !node.Valid() {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("invalid node view provided")
	}

	// Verify the node still exists in NodeStore before persisting to database.
	// Without this check, we could hit a race condition where UpdateNode returns a valid
	// node from a batch update, then the node gets deleted (e.g., ephemeral node logout),
	// and persistNodeToDB would incorrectly re-insert the deleted node into the database.
	_, exists := s.nodeStore.GetNode(node.ID())
	if !exists {
		log.Warn().
			Uint64("node.id", node.ID().Uint64()).
			Str("node.name", node.Hostname()).
			Bool("is_ephemeral", node.IsEphemeral()).
			Msg("Node no longer exists in NodeStore, skipping database persist to prevent race condition")
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node %d no longer exists in NodeStore, skipping database persist", node.ID())
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

	resultNode := s.nodeStore.PutNode(*nodePtr)

	// Then save to database using the result from PutNode
	return s.persistNodeToDB(resultNode)
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
	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.IsOnline = ptr.To(true)
		// n.LastSeen = ptr.To(now)
	})
	if !ok {
		return nil
	}
	c := []change.ChangeSet{change.NodeOnline(id)}

	log.Info().Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Node connected")

	// Use the node's current routes for primary route update
	// AllApprovedRoutes() returns only the intersection of announced AND approved routes
	// We MUST use AllApprovedRoutes() to maintain the security model
	routeChange := s.primaryRoutes.SetRoutes(id, node.AllApprovedRoutes()...)

	if routeChange {
		c = append(c, change.NodeAdded(id))
	}

	return c
}

// Disconnect marks a node as disconnected and updates its primary routes in the state.
func (s *State) Disconnect(id types.NodeID) ([]change.ChangeSet, error) {
	now := time.Now()

	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.LastSeen = ptr.To(now)
		// NodeStore is the source of truth for all node state including online status.
		n.IsOnline = ptr.To(false)
	})

	if !ok {
		return nil, fmt.Errorf("node not found: %d", id)
	}

	log.Info().Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Node disconnected")

	// Special error handling for disconnect - we log errors but continue
	// because NodeStore is already updated and we need to notify peers
	_, c, err := s.persistNodeToDB(node)
	if err != nil {
		// Log error but don't fail the disconnection - NodeStore is already updated
		// and we need to send change notifications to peers
		log.Error().Err(err).Uint64("node.id", id.Uint64()).Str("node.name", node.Hostname()).Msg("Failed to update last seen in database")
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

// GetNodeByMachineKey retrieves a node by its machine key and user ID.
// The bool indicates if the node exists or is available (like "err not found").
// The NodeView might be invalid, so it must be checked with .Valid(), which must be used to ensure
// it isn't an invalid node (this is more of a node error or node is broken).
func (s *State) GetNodeByMachineKey(machineKey key.MachinePublic, userID types.UserID) (types.NodeView, bool) {
	return s.nodeStore.GetNodeByMachineKey(machineKey, userID)
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
	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change. If the database update fails, the NodeStore change will
	// remain, but since we return an error, no change notification will be sent to the
	// batcher, preventing inconsistent state propagation.
	expiryPtr := expiry
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.Expiry = &expiryPtr
	})

	if !ok {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	return s.persistNodeToDB(n)
}

// SetNodeTags assigns tags to a node for use in access control policies.
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (types.NodeView, change.ChangeSet, error) {
	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.ForcedTags = tags
	})

	if !ok {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	return s.persistNodeToDB(n)
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (types.NodeView, change.ChangeSet, error) {
	// TODO(kradalby): In principle we should call the AutoApprove logic here
	// because even if the CLI removes an auto-approved route, it will be added
	// back automatically.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.ApprovedRoutes = routes
	})

	if !ok {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	// Persist the node changes to the database
	nodeView, c, err := s.persistNodeToDB(n)
	if err != nil {
		return types.NodeView{}, change.EmptySet, err
	}

	// Update primary routes table based on SubnetRoutes (intersection of announced and approved).
	// The primary routes table is what the mapper uses to generate network maps, so updating it
	// here ensures that route changes are distributed to peers.
	routeChange := s.primaryRoutes.SetRoutes(nodeID, nodeView.AllApprovedRoutes()...)

	// If routes changed or the changeset isn't already a full update, trigger a policy change
	// to ensure all nodes get updated network maps
	if routeChange || !c.IsFull() {
		c = change.PolicyChange()
	}

	return nodeView, c, nil
}

// RenameNode changes the display name of a node.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (types.NodeView, change.ChangeSet, error) {
	if err := util.ValidateHostname(newName); err != nil {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("renaming node: %w", err)
	}

	// Check name uniqueness against NodeStore
	allNodes := s.nodeStore.ListNodes()
	for i := 0; i < allNodes.Len(); i++ {
		node := allNodes.At(i)
		if node.ID() != nodeID && node.AsStruct().GivenName == newName {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("name is not unique: %s", newName)
		}
	}

	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.GivenName = newName
	})

	if !ok {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	return s.persistNodeToDB(n)
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

	// Update NodeStore before database to ensure consistency. The NodeStore update is
	// blocking and will be the source of truth for the batcher. The database update must
	// make the exact same change.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.User = *user
		n.UserID = uint(userID)
	})

	if !ok {
		return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", nodeID)
	}

	return s.persistNodeToDB(n)
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
				netInfo := netInfoFromMapRequest(node.ID, existingNode.Hostinfo().AsStruct(), node.Hostinfo)
				node.Hostinfo = existingNode.Hostinfo().AsStruct()
				node.Hostinfo.NetInfo = netInfo
			}
			// TODO(kradalby): This should just update the IP addresses, nothing else in the node store.
			// We should avoid PutNode here.
			_ = s.nodeStore.PutNode(*node)
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
			updates = append(updates, change.KeyExpiry(node.ID(), node.Expiry().Get()))
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

// FilterForNode returns filter rules for a specific node, handling autogroup:self per-node.
func (s *State) FilterForNode(node types.NodeView) ([]tailcfg.FilterRule, error) {
	return s.polMan.FilterForNode(node)
}

// MatchersForNode returns matchers for peer relationship determination (unreduced).
func (s *State) MatchersForNode(node types.NodeView) ([]matcher.Match, error) {
	return s.polMan.MatchersForNode(node)
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

// Test helpers for the state layer

// CreateUserForTest creates a test user. This is a convenience wrapper around the database layer.
func (s *State) CreateUserForTest(name ...string) *types.User {
	return s.db.CreateUserForTest(name...)
}

// CreateNodeForTest creates a test node. This is a convenience wrapper around the database layer.
func (s *State) CreateNodeForTest(user *types.User, hostname ...string) *types.Node {
	return s.db.CreateNodeForTest(user, hostname...)
}

// CreateRegisteredNodeForTest creates a test node with allocated IPs. This is a convenience wrapper around the database layer.
func (s *State) CreateRegisteredNodeForTest(user *types.User, hostname ...string) *types.Node {
	return s.db.CreateRegisteredNodeForTest(user, hostname...)
}

// CreateNodesForTest creates multiple test nodes. This is a convenience wrapper around the database layer.
func (s *State) CreateNodesForTest(user *types.User, count int, namePrefix ...string) []*types.Node {
	return s.db.CreateNodesForTest(user, count, namePrefix...)
}

// CreateUsersForTest creates multiple test users. This is a convenience wrapper around the database layer.
func (s *State) CreateUsersForTest(count int, namePrefix ...string) []*types.User {
	return s.db.CreateUsersForTest(count, namePrefix...)
}

// DB returns the underlying database for testing purposes.
func (s *State) DB() *hsdb.HSDatabase {
	return s.db
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

// logHostinfoValidation logs warnings when hostinfo is nil or has empty hostname.
func logHostinfoValidation(machineKey, nodeKey, username, hostname string, hostinfo *tailcfg.Hostinfo) {
	if hostinfo == nil {
		log.Warn().
			Caller().
			Str("machine.key", machineKey).
			Str("node.key", nodeKey).
			Str("user.name", username).
			Str("generated.hostname", hostname).
			Msg("Registration had nil hostinfo, generated default hostname")
	} else if hostinfo.Hostname == "" {
		log.Warn().
			Caller().
			Str("machine.key", machineKey).
			Str("node.key", nodeKey).
			Str("user.name", username).
			Str("generated.hostname", hostname).
			Msg("Registration had empty hostname, generated default")
	}
}

// preserveNetInfo preserves NetInfo from an existing node for faster DERP connectivity.
// If no existing node is provided, it creates new netinfo from the provided hostinfo.
func preserveNetInfo(existingNode types.NodeView, nodeID types.NodeID, validHostinfo *tailcfg.Hostinfo) *tailcfg.NetInfo {
	var existingHostinfo *tailcfg.Hostinfo
	if existingNode.Valid() {
		existingHostinfo = existingNode.Hostinfo().AsStruct()
	}
	return netInfoFromMapRequest(nodeID, existingHostinfo, validHostinfo)
}

// newNodeParams contains parameters for creating a new node.
type newNodeParams struct {
	User           types.User
	MachineKey     key.MachinePublic
	NodeKey        key.NodePublic
	DiscoKey       key.DiscoPublic
	Hostname       string
	Hostinfo       *tailcfg.Hostinfo
	Endpoints      []netip.AddrPort
	Expiry         *time.Time
	RegisterMethod string

	// Optional: Pre-auth key specific fields
	PreAuthKey *types.PreAuthKey

	// Optional: Existing node for netinfo preservation
	ExistingNodeForNetinfo types.NodeView
}

// createAndSaveNewNode creates a new node, allocates IPs, saves to DB, and adds to NodeStore.
// It preserves netinfo from an existing node if one is provided (for faster DERP connectivity).
func (s *State) createAndSaveNewNode(params newNodeParams) (types.NodeView, error) {
	// Preserve NetInfo from existing node if available
	if params.Hostinfo != nil {
		params.Hostinfo.NetInfo = preserveNetInfo(
			params.ExistingNodeForNetinfo,
			types.NodeID(0),
			params.Hostinfo,
		)
	}

	// Prepare the node for registration
	nodeToRegister := types.Node{
		Hostname:       params.Hostname,
		UserID:         params.User.ID,
		User:           params.User,
		MachineKey:     params.MachineKey,
		NodeKey:        params.NodeKey,
		DiscoKey:       params.DiscoKey,
		Hostinfo:       params.Hostinfo,
		Endpoints:      params.Endpoints,
		LastSeen:       ptr.To(time.Now()),
		RegisterMethod: params.RegisterMethod,
		Expiry:         params.Expiry,
	}

	// Pre-auth key specific fields
	if params.PreAuthKey != nil {
		nodeToRegister.ForcedTags = params.PreAuthKey.Proto().GetAclTags()
		nodeToRegister.AuthKey = params.PreAuthKey
		nodeToRegister.AuthKeyID = &params.PreAuthKey.ID
	}

	// Allocate new IPs
	ipv4, ipv6, err := s.ipAlloc.Next()
	if err != nil {
		return types.NodeView{}, fmt.Errorf("allocating IPs: %w", err)
	}

	nodeToRegister.IPv4 = ipv4
	nodeToRegister.IPv6 = ipv6

	// Ensure unique given name if not set
	if nodeToRegister.GivenName == "" {
		givenName, err := hsdb.EnsureUniqueGivenName(s.db.DB, nodeToRegister.Hostname)
		if err != nil {
			return types.NodeView{}, fmt.Errorf("failed to ensure unique given name: %w", err)
		}
		nodeToRegister.GivenName = givenName
	}

	// New node - database first to get ID, then NodeStore
	savedNode, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		if err := tx.Save(&nodeToRegister).Error; err != nil {
			return nil, fmt.Errorf("failed to save node: %w", err)
		}

		if params.PreAuthKey != nil && !params.PreAuthKey.Reusable {
			err := hsdb.UsePreAuthKey(tx, params.PreAuthKey)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return &nodeToRegister, nil
	})
	if err != nil {
		return types.NodeView{}, err
	}

	// Add to NodeStore after database creates the ID
	return s.nodeStore.PutNode(*savedNode), nil
}

// HandleNodeFromAuthPath handles node registration through authentication flow (like OIDC).
func (s *State) HandleNodeFromAuthPath(
	registrationID types.RegistrationID,
	userID types.UserID,
	expiry *time.Time,
	registrationMethod string,
) (types.NodeView, change.ChangeSet, error) {
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

	// Ensure we have a valid hostname from the registration cache entry
	hostname := util.EnsureHostname(
		regEntry.Node.Hostinfo,
		regEntry.Node.MachineKey.String(),
		regEntry.Node.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regEntry.Node.Hostinfo, &tailcfg.Hostinfo{})
	validHostinfo.Hostname = hostname

	logHostinfoValidation(
		regEntry.Node.MachineKey.ShortString(),
		regEntry.Node.NodeKey.String(),
		user.Username(),
		hostname,
		regEntry.Node.Hostinfo,
	)

	var finalNode types.NodeView

	// Check if node already exists with same machine key for this user
	existingNodeSameUser, existsSameUser := s.nodeStore.GetNodeByMachineKey(regEntry.Node.MachineKey, types.UserID(user.ID))

	// If this node exists for this user, update the node in place.
	if existsSameUser && existingNodeSameUser.Valid() {
		log.Debug().
			Caller().
			Str("registration_id", registrationID.String()).
			Str("user.name", user.Username()).
			Str("registrationMethod", registrationMethod).
			Str("node.name", existingNodeSameUser.Hostname()).
			Uint64("node.id", existingNodeSameUser.ID().Uint64()).
			Msg("Updating existing node registration")

		// Update existing node - NodeStore first, then database
		updatedNodeView, ok := s.nodeStore.UpdateNode(existingNodeSameUser.ID(), func(node *types.Node) {
			node.NodeKey = regEntry.Node.NodeKey
			node.DiscoKey = regEntry.Node.DiscoKey
			node.Hostname = hostname

			// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
			// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

			// Preserve NetInfo from existing node when re-registering
			node.Hostinfo = validHostinfo
			node.Hostinfo.NetInfo = preserveNetInfo(existingNodeSameUser, existingNodeSameUser.ID(), validHostinfo)

			node.Endpoints = regEntry.Node.Endpoints
			node.RegisterMethod = regEntry.Node.RegisterMethod
			node.IsOnline = ptr.To(false)
			node.LastSeen = ptr.To(time.Now())

			if expiry != nil {
				node.Expiry = expiry
			} else {
				node.Expiry = regEntry.Node.Expiry
			}
		})

		if !ok {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", existingNodeSameUser.ID())
		}

		// Use the node from UpdateNode to save to database
		_, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			if err := tx.Save(updatedNodeView.AsStruct()).Error; err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}
			return nil, nil
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, err
		}

		log.Trace().
			Caller().
			Str("node.name", updatedNodeView.Hostname()).
			Uint64("node.id", updatedNodeView.ID().Uint64()).
			Str("machine.key", regEntry.Node.MachineKey.ShortString()).
			Str("node.key", updatedNodeView.NodeKey().ShortString()).
			Str("user.name", user.Name).
			Msg("Node re-authorized")

		finalNode = updatedNodeView
	} else {
		// Node does not exist for this user with this machine key
		// Check if node exists with this machine key for a different user (for netinfo preservation)
		existingNodeAnyUser, existsAnyUser := s.nodeStore.GetNodeByMachineKeyAnyUser(regEntry.Node.MachineKey)

		if existsAnyUser && existingNodeAnyUser.Valid() && existingNodeAnyUser.UserID() != user.ID {
			// Node exists but belongs to a different user
			// Create a NEW node for the new user (do not transfer)
			// This allows the same machine to have separate node identities per user
			oldUser := existingNodeAnyUser.User()
			log.Info().
				Caller().
				Str("existing.node.name", existingNodeAnyUser.Hostname()).
				Uint64("existing.node.id", existingNodeAnyUser.ID().Uint64()).
				Str("machine.key", regEntry.Node.MachineKey.ShortString()).
				Str("old.user", oldUser.Username()).
				Str("new.user", user.Username()).
				Str("method", registrationMethod).
				Msg("Creating new node for different user (same machine key exists for another user)")
		}

		// Create a completely new node
		log.Debug().
			Caller().
			Str("registration_id", registrationID.String()).
			Str("user.name", user.Username()).
			Str("registrationMethod", registrationMethod).
			Str("expiresAt", fmt.Sprintf("%v", expiry)).
			Msg("Registering new node from auth callback")

		// Create and save new node
		var err error
		finalNode, err = s.createAndSaveNewNode(newNodeParams{
			User:                   *user,
			MachineKey:             regEntry.Node.MachineKey,
			NodeKey:                regEntry.Node.NodeKey,
			DiscoKey:               regEntry.Node.DiscoKey,
			Hostname:               hostname,
			Hostinfo:               validHostinfo,
			Endpoints:              regEntry.Node.Endpoints,
			Expiry:                 cmp.Or(expiry, regEntry.Node.Expiry),
			RegisterMethod:         registrationMethod,
			ExistingNodeForNetinfo: cmp.Or(existingNodeAnyUser, types.NodeView{}),
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, err
		}
	}

	// Signal to waiting clients
	regEntry.SendAndClose(finalNode.AsStruct())

	// Delete from registration cache
	s.registrationCache.Delete(registrationID)

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager nodes: %w", err)
	}

	var c change.ChangeSet
	if !usersChange.Empty() || !nodesChange.Empty() {
		c = change.PolicyChange()
	} else {
		c = change.NodeAdded(finalNode.ID())
	}

	return finalNode, c, nil
}

// HandleNodeFromPreAuthKey handles node registration using a pre-authentication key.
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (types.NodeView, change.ChangeSet, error) {
	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return types.NodeView{}, change.EmptySet, err
	}

	err = pak.Validate()
	if err != nil {
		return types.NodeView{}, change.EmptySet, err
	}

	// Ensure we have a valid hostname - handle nil/empty cases
	hostname := util.EnsureHostname(
		regReq.Hostinfo,
		machineKey.String(),
		regReq.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regReq.Hostinfo, &tailcfg.Hostinfo{})
	validHostinfo.Hostname = hostname

	logHostinfoValidation(
		machineKey.ShortString(),
		regReq.NodeKey.ShortString(),
		pak.User.Username(),
		hostname,
		regReq.Hostinfo,
	)

	log.Debug().
		Caller().
		Str("node.name", hostname).
		Str("machine.key", machineKey.ShortString()).
		Str("node.key", regReq.NodeKey.ShortString()).
		Str("user.name", pak.User.Username()).
		Msg("Registering node with pre-auth key")

	var finalNode types.NodeView

	// Check if node already exists with same machine key for this user
	existingNodeSameUser, existsSameUser := s.nodeStore.GetNodeByMachineKey(machineKey, types.UserID(pak.User.ID))

	// If this node exists for this user, update the node in place.
	if existsSameUser && existingNodeSameUser.Valid() {
		log.Trace().
			Caller().
			Str("node.name", existingNodeSameUser.Hostname()).
			Uint64("node.id", existingNodeSameUser.ID().Uint64()).
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", existingNodeSameUser.NodeKey().ShortString()).
			Str("user.name", pak.User.Username()).
			Msg("Node re-registering with existing machine key and user, updating in place")

		// Update existing node - NodeStore first, then database
		updatedNodeView, ok := s.nodeStore.UpdateNode(existingNodeSameUser.ID(), func(node *types.Node) {
			node.NodeKey = regReq.NodeKey
			node.Hostname = hostname

			// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
			// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

			// Preserve NetInfo from existing node when re-registering
			node.Hostinfo = validHostinfo
			node.Hostinfo.NetInfo = preserveNetInfo(existingNodeSameUser, existingNodeSameUser.ID(), validHostinfo)

			node.RegisterMethod = util.RegisterMethodAuthKey

			// TODO(kradalby): This might need a rework as part of #2417
			node.ForcedTags = pak.Proto().GetAclTags()
			node.AuthKey = pak
			node.AuthKeyID = &pak.ID
			node.IsOnline = ptr.To(false)
			node.LastSeen = ptr.To(time.Now())

			// Update expiry, if it is zero, it means that the node will
			// not have an expiry anymore. If it is non-zero, we set that.
			node.Expiry = &regReq.Expiry
		})

		if !ok {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", existingNodeSameUser.ID())
		}

		// Use the node from UpdateNode to save to database
		_, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			if err := tx.Save(updatedNodeView.AsStruct()).Error; err != nil {
				return nil, fmt.Errorf("failed to save node: %w", err)
			}

			if !pak.Reusable {
				err = hsdb.UsePreAuthKey(tx, pak)
				if err != nil {
					return nil, fmt.Errorf("using pre auth key: %w", err)
				}
			}

			return nil, nil
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("writing node to database: %w", err)
		}

		log.Trace().
			Caller().
			Str("node.name", updatedNodeView.Hostname()).
			Uint64("node.id", updatedNodeView.ID().Uint64()).
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", updatedNodeView.NodeKey().ShortString()).
			Str("user.name", pak.User.Username()).
			Msg("Node re-authorized")

		finalNode = updatedNodeView
	} else {
		// Node does not exist for this user with this machine key
		// Check if node exists with this machine key for a different user
		existingNodeAnyUser, existsAnyUser := s.nodeStore.GetNodeByMachineKeyAnyUser(machineKey)

		if existsAnyUser && existingNodeAnyUser.Valid() && existingNodeAnyUser.UserID() != pak.User.ID {
			// Node exists but belongs to a different user
			// Create a NEW node for the new user (do not transfer)
			// This allows the same machine to have separate node identities per user
			oldUser := existingNodeAnyUser.User()
			log.Info().
				Caller().
				Str("existing.node.name", existingNodeAnyUser.Hostname()).
				Uint64("existing.node.id", existingNodeAnyUser.ID().Uint64()).
				Str("machine.key", machineKey.ShortString()).
				Str("old.user", oldUser.Username()).
				Str("new.user", pak.User.Username()).
				Msg("Creating new node for different user (same machine key exists for another user)")
		}

		// This is a new node for this user - create it
		// (Either completely new, or new for this user while existing for another user)

		// Create and save new node
		var err error
		finalNode, err = s.createAndSaveNewNode(newNodeParams{
			User:                   pak.User,
			MachineKey:             machineKey,
			NodeKey:                regReq.NodeKey,
			DiscoKey:               key.DiscoPublic{}, // DiscoKey not available in RegisterRequest
			Hostname:               hostname,
			Hostinfo:               validHostinfo,
			Endpoints:              nil, // Endpoints not available in RegisterRequest
			Expiry:                 &regReq.Expiry,
			RegisterMethod:         util.RegisterMethodAuthKey,
			PreAuthKey:             pak,
			ExistingNodeForNetinfo: cmp.Or(existingNodeAnyUser, types.NodeView{}),
		})
		if err != nil {
			return types.NodeView{}, change.EmptySet, fmt.Errorf("creating new node: %w", err)
		}
	}

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("failed to update policy manager nodes: %w", err)
	}

	var c change.ChangeSet
	if !usersChange.Empty() || !nodesChange.Empty() {
		c = change.PolicyChange()
	} else {
		c = change.NodeAdded(finalNode.ID())
	}

	return finalNode, c, nil
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
	updatedNode, ok := s.nodeStore.UpdateNode(id, func(currentNode *types.Node) {
		peerChange := currentNode.PeerChangeFromMapRequest(req)
		hostinfoChanged = !hostinfoEqual(currentNode.View(), req.Hostinfo)

		// Get the correct NetInfo to use
		netInfo := netInfoFromMapRequest(id, currentNode.Hostinfo, req.Hostinfo)
		if req.Hostinfo != nil {
			req.Hostinfo.NetInfo = netInfo
		} else {
			req.Hostinfo = &tailcfg.Hostinfo{NetInfo: netInfo}
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

	if !ok {
		return change.EmptySet, fmt.Errorf("node not found in NodeStore: %d", id)
	}

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
		// SetNodeRoutes sets the active/distributed routes, so we must use AllApprovedRoutes()
		// which returns only the intersection of announced AND approved routes.
		// Using AnnouncedRoutes() would bypass the security model and auto-approve everything.
		log.Debug().
			Caller().
			Uint64("node.id", id.Uint64()).
			Strs("announcedRoutes", util.PrefixesToString(updatedNode.AnnouncedRoutes())).
			Strs("approvedRoutes", util.PrefixesToString(updatedNode.ApprovedRoutes().AsSlice())).
			Strs("allApprovedRoutes", util.PrefixesToString(updatedNode.AllApprovedRoutes())).
			Msg("updating node routes for distribution")
		nodeRouteChange = s.SetNodeRoutes(id, updatedNode.AllApprovedRoutes()...)
	}

	_, policyChange, err := s.persistNodeToDB(updatedNode)
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
