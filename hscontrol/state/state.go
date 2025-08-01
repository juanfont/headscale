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
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	xslices "golang.org/x/exp/slices"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
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

	// subsystem keeping state
	// db provides persistent storage and database operations
	db *hsdb.HSDatabase
	// ipAlloc manages IP address allocation for nodes
	ipAlloc *hsdb.IPAllocator
	// derpMap contains the current DERP relay configuration
	derpMap *tailcfg.DERPMap
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

	derpMap := derp.GetDERPMap(cfg.DERP)

	nodes, err := db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes: %w", err)
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

	return &State{
		cfg: cfg,

		db:      db,
		ipAlloc: ipAlloc,
		// TODO(kradalby): Update DERPMap
		derpMap:           derpMap,
		polMan:            polMan,
		registrationCache: registrationCache,
		primaryRoutes:     routes.New(),
	}, nil
}

// Close gracefully shuts down the State instance and releases all resources.
func (s *State) Close() error {
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

// DERPMap returns the current DERP relay configuration for peer-to-peer connectivity.
func (s *State) DERPMap() *tailcfg.DERPMap {
	return s.derpMap
}

// ReloadPolicy reloads the access control policy and triggers auto-approval if changed.
// Returns true if the policy changed.
func (s *State) ReloadPolicy() (bool, error) {
	pol, err := policyBytes(s.db, s.cfg)
	if err != nil {
		return false, fmt.Errorf("loading policy: %w", err)
	}

	changed, err := s.polMan.SetPolicy(pol)
	if err != nil {
		return false, fmt.Errorf("setting policy: %w", err)
	}

	if changed {
		err := s.autoApproveNodes()
		if err != nil {
			return false, fmt.Errorf("auto approving nodes: %w", err)
		}
	}

	return changed, nil
}

// AutoApproveNodes processes pending nodes and auto-approves those meeting policy criteria.
func (s *State) AutoApproveNodes() error {
	return s.autoApproveNodes()
}

// CreateUser creates a new user and updates the policy manager.
// Returns the created user, whether policies changed, and any error.
func (s *State) CreateUser(user types.User) (*types.User, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()


	if err := s.db.DB.Save(&user).Error; err != nil {
		return nil, false, fmt.Errorf("creating user: %w", err)
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerUsers()
	if err != nil {
		// Log the error but don't fail the user creation
		return &user, false, fmt.Errorf("failed to update policy manager after user creation: %w", err)
	}

	// Even if the policy manager doesn't detect a filter change, SSH policies
	// might now be resolvable when they weren't before. If there are existing
	// nodes, we should send a policy change to ensure they get updated SSH policies.
	if !policyChanged {
		nodes, err := s.ListNodes()
		if err == nil && len(nodes) > 0 {
			policyChanged = true
		}
	}

	log.Info().Str("user", user.Name).Bool("policyChanged", policyChanged).Msg("User created, policy manager updated")

	// TODO(kradalby): implement the user in-memory cache

	return &user, policyChanged, nil
}

// UpdateUser modifies an existing user using the provided update function within a transaction.
// Returns the updated user, whether policies changed, and any error.
func (s *State) UpdateUser(userID types.UserID, updateFn func(*types.User) error) (*types.User, bool, error) {
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
		return nil, false, err
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerUsers()
	if err != nil {
		return user, false, fmt.Errorf("failed to update policy manager after user update: %w", err)
	}

	// TODO(kradalby): implement the user in-memory cache

	return user, policyChanged, nil
}

// DeleteUser permanently removes a user and all associated data (nodes, API keys, etc).
// This operation is irreversible.
func (s *State) DeleteUser(userID types.UserID) error {
	return s.db.DestroyUser(userID)
}

// RenameUser changes a user's name. The new name must be unique.
func (s *State) RenameUser(userID types.UserID, newName string) (*types.User, bool, error) {
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

// CreateNode creates a new node and updates the policy manager.
// Returns the created node, whether policies changed, and any error.
func (s *State) CreateNode(node *types.Node) (*types.Node, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(node).Error; err != nil {
		return nil, false, fmt.Errorf("creating node: %w", err)
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return node, false, fmt.Errorf("failed to update policy manager after node creation: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache

	return node, policyChanged, nil
}

// updateNodeTx performs a database transaction to update a node and refresh the policy manager.
func (s *State) updateNodeTx(nodeID types.NodeID, updateFn func(tx *gorm.DB) error) (*types.Node, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	node, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
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
	if err != nil {
		return nil, change.EmptySet, err
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return node, change.EmptySet, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache

	var c change.ChangeSet
	if policyChanged {
		c = change.PolicyChange()
	} else {
		// Basic node change without specific details since this is a generic update
		c = change.NodeAdded(node.ID)
	}

	return node, c, nil
}

// SaveNode persists an existing node to the database and updates the policy manager.
func (s *State) SaveNode(node *types.Node) (*types.Node, change.ChangeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(node).Error; err != nil {
		return nil, change.EmptySet, fmt.Errorf("saving node: %w", err)
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return node, change.EmptySet, fmt.Errorf("failed to update policy manager after node save: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache

	if policyChanged {
		return node, change.PolicyChange(), nil
	}

	return node, change.EmptySet, nil
}

// DeleteNode permanently removes a node and cleans up associated resources.
// Returns whether policies changed and any error. This operation is irreversible.
func (s *State) DeleteNode(node *types.Node) (change.ChangeSet, error) {
	err := s.db.DeleteNode(node)
	if err != nil {
		return change.EmptySet, err
	}

	c := change.NodeRemoved(node.ID)

	// Check if policy manager needs updating after node deletion
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return change.EmptySet, fmt.Errorf("failed to update policy manager after node deletion: %w", err)
	}

	if policyChanged {
		c = change.PolicyChange()
	}

	return c, nil
}

func (s *State) Connect(node *types.Node) change.ChangeSet {
	c := change.NodeOnline(node.ID)
	routeChange := s.primaryRoutes.SetRoutes(node.ID, node.SubnetRoutes()...)

	if routeChange {
		c = change.NodeAdded(node.ID)
	}

	return c
}

func (s *State) Disconnect(node *types.Node) (change.ChangeSet, error) {
	c := change.NodeOffline(node.ID)

	_, _, err := s.SetLastSeen(node.ID, time.Now())
	if err != nil {
		return c, fmt.Errorf("disconnecting node: %w", err)
	}

	if routeChange := s.primaryRoutes.SetRoutes(node.ID); routeChange {
		c = change.PolicyChange()
	}

	// TODO(kradalby): This node should update the in memory state
	return c, nil
}

// GetNodeByID retrieves a node by ID.
func (s *State) GetNodeByID(nodeID types.NodeID) (*types.Node, error) {
	return s.db.GetNodeByID(nodeID)
}

// GetNodeViewByID retrieves a node view by ID.
func (s *State) GetNodeViewByID(nodeID types.NodeID) (types.NodeView, error) {
	node, err := s.db.GetNodeByID(nodeID)
	if err != nil {
		return types.NodeView{}, err
	}

	return node.View(), nil
}

// GetNodeByNodeKey retrieves a node by its Tailscale public key.
func (s *State) GetNodeByNodeKey(nodeKey key.NodePublic) (*types.Node, error) {
	return s.db.GetNodeByNodeKey(nodeKey)
}

// GetNodeViewByNodeKey retrieves a node view by its Tailscale public key.
func (s *State) GetNodeViewByNodeKey(nodeKey key.NodePublic) (types.NodeView, error) {
	node, err := s.db.GetNodeByNodeKey(nodeKey)
	if err != nil {
		return types.NodeView{}, err
	}

	return node.View(), nil
}

// ListNodes retrieves specific nodes by ID, or all nodes if no IDs provided.
func (s *State) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	if len(nodeIDs) == 0 {
		return s.db.ListNodes()
	}

	return s.db.ListNodes(nodeIDs...)
}

// ListNodesByUser retrieves all nodes belonging to a specific user.
func (s *State) ListNodesByUser(userID types.UserID) (types.Nodes, error) {
	return hsdb.Read(s.db.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return hsdb.ListNodesByUser(rx, userID)
	})
}

// ListPeers retrieves nodes that can communicate with the specified node based on policy.
func (s *State) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	return s.db.ListPeers(nodeID, peerIDs...)
}

// ListEphemeralNodes retrieves all ephemeral (temporary) nodes in the system.
func (s *State) ListEphemeralNodes() (types.Nodes, error) {
	return s.db.ListEphemeralNodes()
}

// SetNodeExpiry updates the expiration time for a node.
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry time.Time) (*types.Node, change.ChangeSet, error) {
	n, c, err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.NodeSetExpiry(tx, nodeID, expiry)
	})
	if err != nil {
		return nil, change.EmptySet, fmt.Errorf("setting node expiry: %w", err)
	}

	if !c.IsFull() {
		c = change.KeyExpiry(nodeID)
	}

	return n, c, nil
}

// SetNodeTags assigns tags to a node for use in access control policies.
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (*types.Node, change.ChangeSet, error) {
	n, c, err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetTags(tx, nodeID, tags)
	})
	if err != nil {
		return nil, change.EmptySet, fmt.Errorf("setting node tags: %w", err)
	}

	if !c.IsFull() {
		c = change.NodeAdded(nodeID)
	}

	return n, c, nil
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (*types.Node, change.ChangeSet, error) {
	n, c, err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetApprovedRoutes(tx, nodeID, routes)
	})
	if err != nil {
		return nil, change.EmptySet, fmt.Errorf("setting approved routes: %w", err)
	}

	// Update primary routes after changing approved routes
	routeChange := s.primaryRoutes.SetRoutes(nodeID, n.SubnetRoutes()...)

	if routeChange || !c.IsFull() {
		c = change.PolicyChange()
	}

	return n, c, nil
}

// RenameNode changes the display name of a node.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (*types.Node, change.ChangeSet, error) {
	n, c, err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.RenameNode(tx, nodeID, newName)
	})
	if err != nil {
		return nil, change.EmptySet, fmt.Errorf("renaming node: %w", err)
	}

	if !c.IsFull() {
		c = change.NodeAdded(nodeID)
	}

	return n, c, nil
}

// SetLastSeen updates when a node was last seen, used for connectivity monitoring.
func (s *State) SetLastSeen(nodeID types.NodeID, lastSeen time.Time) (*types.Node, change.ChangeSet, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetLastSeen(tx, nodeID, lastSeen)
	})
}

// AssignNodeToUser transfers a node to a different user.
func (s *State) AssignNodeToUser(nodeID types.NodeID, userID types.UserID) (*types.Node, change.ChangeSet, error) {
	n, c, err := s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.AssignNodeToUser(tx, nodeID, userID)
	})
	if err != nil {
		return nil, change.EmptySet, fmt.Errorf("assigning node to user: %w", err)
	}

	if !c.IsFull() {
		c = change.NodeAdded(nodeID)
	}

	return n, c, nil
}

// BackfillNodeIPs assigns IP addresses to nodes that don't have them.
func (s *State) BackfillNodeIPs() ([]string, error) {
	return s.db.BackfillNodeIPs(s.ipAlloc)
}

// ExpireExpiredNodes finds and processes expired nodes since the last check.
// Returns next check time, state update with expired nodes, and whether any were found.
func (s *State) ExpireExpiredNodes(lastCheck time.Time) (time.Time, []change.ChangeSet, bool) {
	return hsdb.ExpireExpiredNodes(s.db.DB, lastCheck)
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
func (s *State) AutoApproveRoutes(node *types.Node) bool {
	return policy.AutoApproveRoutes(s.polMan, node)
}

// PolicyDebugString returns a debug representation of the current policy.
func (s *State) PolicyDebugString() string {
	return s.polMan.DebugString()
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
) (*types.Node, change.ChangeSet, error) {
	ipv4, ipv6, err := s.ipAlloc.Next()
	if err != nil {
		return nil, change.EmptySet, err
	}

	return s.db.HandleNodeFromAuthPath(
		registrationID,
		userID,
		expiry,
		util.RegisterMethodOIDC,
		ipv4, ipv6,
	)
}

// HandleNodeFromPreAuthKey handles node registration using a pre-authentication key.
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*types.Node, change.ChangeSet, bool, error) {
	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return nil, change.EmptySet, false, err
	}

	err = pak.Validate()
	if err != nil {
		return nil, change.EmptySet, false, err
	}

	nodeToRegister := types.Node{
		Hostname:       regReq.Hostinfo.Hostname,
		UserID:         pak.User.ID,
		User:           pak.User,
		MachineKey:     machineKey,
		NodeKey:        regReq.NodeKey,
		Hostinfo:       regReq.Hostinfo,
		LastSeen:       ptr.To(time.Now()),
		RegisterMethod: util.RegisterMethodAuthKey,

		// TODO(kradalby): This should not be set on the node,
		// they should be looked up through the key, which is
		// attached to the node.
		ForcedTags: pak.Proto().GetAclTags(),
		AuthKey:    pak,
		AuthKeyID:  &pak.ID,
	}

	if !regReq.Expiry.IsZero() {
		nodeToRegister.Expiry = &regReq.Expiry
	}

	ipv4, ipv6, err := s.ipAlloc.Next()
	if err != nil {
		return nil, change.EmptySet, false, fmt.Errorf("allocating IPs: %w", err)
	}

	node, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		node, err := hsdb.RegisterNode(tx,
			nodeToRegister,
			ipv4, ipv6,
		)
		if err != nil {
			return nil, fmt.Errorf("registering node: %w", err)
		}

		if !pak.Reusable {
			err = hsdb.UsePreAuthKey(tx, pak)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return node, nil
	})
	if err != nil {
		return nil, change.EmptySet, false, fmt.Errorf("writing node to database: %w", err)
	}

	// Check if this is a logout request for an ephemeral node
	if !regReq.Expiry.IsZero() && regReq.Expiry.Before(time.Now()) && pak.Ephemeral {
		// This is a logout request for an ephemeral node, delete it immediately
		c, err := s.DeleteNode(node)
		if err != nil {
			return nil, change.EmptySet, false, fmt.Errorf("deleting ephemeral node during logout: %w", err)
		}
		return nil, c, false, nil
	}

	// Check if policy manager needs updating
	// This is necessary because we just created a new node.
	// We need to ensure that the policy manager is aware of this new node.
	// Also update users to ensure all users are known when evaluating policies.
	usersChanged, err := s.updatePolicyManagerUsers()
	if err != nil {
		return nil, change.EmptySet, false, fmt.Errorf("failed to update policy manager users after node registration: %w", err)
	}

	nodesChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return nil, change.EmptySet, false, fmt.Errorf("failed to update policy manager nodes after node registration: %w", err)
	}

	policyChanged := usersChanged || nodesChanged

	c := change.NodeAdded(node.ID)

	return node, c, policyChanged, nil
}

// AllocateNextIPs allocates the next available IPv4 and IPv6 addresses.
func (s *State) AllocateNextIPs() (*netip.Addr, *netip.Addr, error) {
	return s.ipAlloc.Next()
}

// updatePolicyManagerUsers updates the policy manager with current users.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for users.
// updatePolicyManagerUsers refreshes the policy manager with current user data.
func (s *State) updatePolicyManagerUsers() (bool, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return false, fmt.Errorf("listing users for policy update: %w", err)
	}

	log.Debug().Int("userCount", len(users)).Msg("Updating policy manager with users")

	changed, err := s.polMan.SetUsers(users)
	if err != nil {
		return false, fmt.Errorf("updating policy manager users: %w", err)
	}

	log.Debug().Bool("changed", changed).Msg("Policy manager users updated")

	return changed, nil
}

// updatePolicyManagerNodes updates the policy manager with current nodes.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for nodes.
// updatePolicyManagerNodes refreshes the policy manager with current node data.
func (s *State) updatePolicyManagerNodes() (bool, error) {
	nodes, err := s.ListNodes()
	if err != nil {
		return false, fmt.Errorf("listing nodes for policy update: %w", err)
	}

	changed, err := s.polMan.SetNodes(nodes.ViewSlice())
	if err != nil {
		return false, fmt.Errorf("updating policy manager nodes: %w", err)
	}

	return changed, nil
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
func (s *State) autoApproveNodes() error {
	err := s.db.Write(func(tx *gorm.DB) error {
		nodes, err := hsdb.ListNodes(tx)
		if err != nil {
			return err
		}

		for _, node := range nodes {
			// TODO(kradalby): This change should probably be sent to the rest of the system.
			changed := policy.AutoApproveRoutes(s.polMan, node)
			if changed {
				err = tx.Save(node).Error
				if err != nil {
					return err
				}

				// TODO(kradalby): This should probably be done outside of the transaction,
				// and the result of this should be propagated to the system.
				s.primaryRoutes.SetRoutes(node.ID, node.SubnetRoutes()...)
			}
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("auto approving routes for nodes: %w", err)
	}

	return nil
}

// TODO(kradalby): This should just take the node ID?
func (s *State) UpdateNodeFromMapRequest(node *types.Node, req tailcfg.MapRequest) (change.ChangeSet, error) {
	// TODO(kradalby): This is essentially a patch update that could be sent directly to nodes,
	// which means we could shortcut the whole change thing if there are no other important updates.
	peerChange := node.PeerChangeFromMapRequest(req)

	node.ApplyPeerChange(&peerChange)

	sendUpdate, routesChanged := hostInfoChanged(node.Hostinfo, req.Hostinfo)

	// The node might not set NetInfo if it has not changed and if
	// the full HostInfo object is overwritten, the information is lost.
	// If there is no NetInfo, keep the previous one.
	// From 1.66 the client only sends it if changed:
	// https://github.com/tailscale/tailscale/commit/e1011f138737286ecf5123ff887a7a5800d129a2
	// TODO(kradalby): evaluate if we need better comparing of hostinfo
	// before we take the changes.
	if req.Hostinfo.NetInfo == nil && node.Hostinfo != nil {
		req.Hostinfo.NetInfo = node.Hostinfo.NetInfo
	}
	node.Hostinfo = req.Hostinfo

	// If there is no changes and nothing to save,
	// return early.
	if peerChangeEmpty(peerChange) && !sendUpdate {
		// mapResponseEndpointUpdates.WithLabelValues("noop").Inc()
		return change.EmptySet, nil
	}

	c := change.EmptySet

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		// Auto approve any routes that have been defined in policy as
		// auto approved. Check if this actually changed the node.
		_ = s.AutoApproveRoutes(node)

		// Update the routes of the given node in the route manager to
		// see if an update needs to be sent.
		c = s.SetNodeRoutes(node.ID, node.SubnetRoutes()...)
	}

	// Check if there has been a change to Hostname and update them
	// in the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the hostname change.
	node.ApplyHostnameFromHostInfo(req.Hostinfo)

	_, policyChange, err := s.SaveNode(node)
	if err != nil {
		return change.EmptySet, err
	}

	if policyChange.IsFull() {
		c = policyChange
	}

	if c.Empty() {
		c = change.NodeAdded(node.ID)
	}

	return c, nil
}

// hostInfoChanged reports if hostInfo has changed in two ways,
// - first bool reports if an update needs to be sent to nodes
// - second reports if there has been changes to routes
// the caller can then use this info to save and update nodes
// and routes as needed.
func hostInfoChanged(old, new *tailcfg.Hostinfo) (bool, bool) {
	if old.Equal(new) {
		return false, false
	}

	if old == nil && new != nil {
		return true, true
	}

	// Routes
	oldRoutes := make([]netip.Prefix, 0)
	if old != nil {
		oldRoutes = old.RoutableIPs
	}
	newRoutes := new.RoutableIPs

	tsaddr.SortPrefixes(oldRoutes)
	tsaddr.SortPrefixes(newRoutes)

	if !xslices.Equal(oldRoutes, newRoutes) {
		return true, true
	}

	// Services is mostly useful for discovery and not critical,
	// except for peerapi, which is how nodes talk to each other.
	// If peerapi was not part of the initial mapresponse, we
	// need to make sure its sent out later as it is needed for
	// Taildrop.
	// TODO(kradalby): Length comparison is a bit naive, replace.
	if len(old.Services) != len(new.Services) {
		return true, false
	}

	return false, false
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
