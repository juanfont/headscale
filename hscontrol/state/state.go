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
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/sasha-s/go-deadlock"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	zcache "zgo.at/zcache/v2"
)

const (
	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20
)

var ErrUnsupportedPolicyMode = errors.New("unsupported policy mode")

type State struct {
	mu  deadlock.RWMutex
	cfg *types.Config

	// in-memory data, protected by mu
	nodes types.Nodes
	users types.Users

	// subsystem keeping state
	db                *hsdb.HSDatabase
	ipAlloc           *hsdb.IPAllocator
	derpMap           *tailcfg.DERPMap
	polMan            policy.PolicyManager
	registrationCache *zcache.Cache[types.RegistrationID, types.RegisterNode]
	primaryRoutes     *routes.PrimaryRoutes
}

// =============================================================================
// Core State Management
// =============================================================================

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

	polMan, err := policy.NewPolicyManager(pol, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("init policy manager: %w", err)
	}

	return &State{
		cfg: cfg,

		nodes: nodes,
		users: users,

		db:      db,
		ipAlloc: ipAlloc,
		// TODO(kradalby): Update DERPMap
		derpMap:           derpMap,
		polMan:            polMan,
		registrationCache: registrationCache,
		primaryRoutes:     routes.New(),
	}, nil
}

func (s *State) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	return nil
}

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

func (s *State) DERPMap() *tailcfg.DERPMap {
	return s.derpMap
}

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

func (s *State) AutoApproveNodes() error {
	return s.autoApproveNodes()
}

// Deprecated: Use specific database operation methods instead.
func (s *State) Write(fn func(tx *gorm.DB) error) error {
	return s.db.Write(fn)
}

// Deprecated: Use specific database operation methods instead.
func (s *State) WriteWithReturn(fn func(tx *gorm.DB) (*types.Node, error)) (*types.Node, error) {
	return hsdb.Write(s.db.DB, fn)
}

// =============================================================================
// User Management
// =============================================================================

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

	// TODO(kradalby): implement the user in-memory cache

	return &user, policyChanged, nil
}

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

func (s *State) DeleteUser(userID types.UserID) error {
	return s.db.DestroyUser(userID)
}

func (s *State) RenameUser(userID types.UserID, newName string) (*types.User, bool, error) {
	return s.UpdateUser(userID, func(user *types.User) error {
		user.Name = newName
		return nil
	})
}

func (s *State) GetUserByID(userID types.UserID) (*types.User, error) {
	return s.db.GetUserByID(userID)
}

func (s *State) GetUserByName(name string) (*types.User, error) {
	return s.db.GetUserByName(name)
}

func (s *State) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return s.db.GetUserByOIDCIdentifier(id)
}

func (s *State) ListUsersWithFilter(filter *types.User) ([]types.User, error) {
	return s.db.ListUsers(filter)
}

func (s *State) ListAllUsers() ([]types.User, error) {
	return s.db.ListUsers()
}

// =============================================================================
// Node Management
// =============================================================================

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

// updateNodeTx performs a transaction to update a node and returns the updated node.
// It also checks if the policy manager needs updating after the node update.
// Returns the updated node, a boolean indicating if the policy changed, and an error if any.
func (s *State) updateNodeTx(nodeID types.NodeID, updateFn func(tx *gorm.DB) error) (*types.Node, bool, error) {
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
		return nil, false, err
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return node, false, fmt.Errorf("failed to update policy manager after node update: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache

	return node, policyChanged, nil
}

func (s *State) SaveNode(node *types.Node) (*types.Node, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(node).Error; err != nil {
		return nil, false, fmt.Errorf("saving node: %w", err)
	}

	// Check if policy manager needs updating
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return node, false, fmt.Errorf("failed to update policy manager after node save: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache

	return node, policyChanged, nil
}

func (s *State) DeleteNode(node *types.Node) (bool, error) {
	err := s.db.DeleteNode(node)
	if err != nil {
		return false, err
	}

	// Check if policy manager needs updating after node deletion
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return false, fmt.Errorf("failed to update policy manager after node deletion: %w", err)
	}

	return policyChanged, nil
}

func (s *State) GetNodeByID(nodeID types.NodeID) (*types.Node, error) {
	return s.db.GetNodeByID(nodeID)
}

func (s *State) GetNodeByNodeKey(nodeKey key.NodePublic) (*types.Node, error) {
	return s.db.GetNodeByNodeKey(nodeKey)
}

func (s *State) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	if len(nodeIDs) == 0 {
		return s.db.ListNodes()
	}

	return s.db.ListNodes(nodeIDs...)
}

func (s *State) ListNodesByUser(userID types.UserID) (types.Nodes, error) {
	return hsdb.Read(s.db.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return hsdb.ListNodesByUser(rx, userID)
	})
}

func (s *State) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	return s.db.ListPeers(nodeID, peerIDs...)
}

func (s *State) ListEphemeralNodes() (types.Nodes, error) {
	return s.db.ListEphemeralNodes()
}

// Node convenience methods.
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry time.Time) (*types.Node, bool, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.NodeSetExpiry(tx, nodeID, expiry)
	})
}

func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (*types.Node, bool, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetTags(tx, nodeID, tags)
	})
}

func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (*types.Node, bool, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetApprovedRoutes(tx, nodeID, routes)
	})
}

func (s *State) RenameNode(nodeID types.NodeID, newName string) (*types.Node, bool, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.RenameNode(tx, nodeID, newName)
	})
}

func (s *State) SetLastSeen(nodeID types.NodeID, lastSeen time.Time) (*types.Node, bool, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.SetLastSeen(tx, nodeID, lastSeen)
	})
}

func (s *State) AssignNodeToUser(nodeID types.NodeID, userID types.UserID) (*types.Node, bool, error) {
	return s.updateNodeTx(nodeID, func(tx *gorm.DB) error {
		return hsdb.AssignNodeToUser(tx, nodeID, userID)
	})
}

func (s *State) BackfillNodeIPs() ([]string, error) {
	return s.db.BackfillNodeIPs(s.ipAlloc)
}

// =============================================================================
// Policy Management
// =============================================================================

func (s *State) SSHPolicy(node *types.Node) (*tailcfg.SSHPolicy, error) {
	return s.polMan.SSHPolicy(node)
}

func (s *State) Filter() ([]tailcfg.FilterRule, []matcher.Match) {
	return s.polMan.Filter()
}

func (s *State) NodeCanHaveTag(node *types.Node, tag string) bool {
	return s.polMan.NodeCanHaveTag(node, tag)
}

func (s *State) SetPolicy(pol []byte) (bool, error) {
	return s.polMan.SetPolicy(pol)
}

func (s *State) AutoApproveRoutes(node *types.Node) bool {
	return policy.AutoApproveRoutes(s.polMan, node)
}

func (s *State) PolicyDebugString() string {
	return s.polMan.DebugString()
}

func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy()
}

func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data)
}

// =============================================================================
// Routes Management
// =============================================================================

func (s *State) SetNodeRoutes(nodeID types.NodeID, routes ...netip.Prefix) bool {
	return s.primaryRoutes.SetRoutes(nodeID, routes...)
}

func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.primaryRoutes.PrimaryRoutes(nodeID)
}

func (s *State) PrimaryRoutesString() string {
	return s.primaryRoutes.String()
}

// =============================================================================
// Authentication & Authorization
// =============================================================================

func (s *State) ValidateAPIKey(key string) (bool, error) {
	return s.db.ValidateAPIKey(key)
}

func (s *State) CreateAPIKey(expiration *time.Time) (string, *types.APIKey, error) {
	return s.db.CreateAPIKey(expiration)
}

func (s *State) GetAPIKey(prefix string) (*types.APIKey, error) {
	return s.db.GetAPIKey(prefix)
}

func (s *State) ExpireAPIKey(key *types.APIKey) error {
	return s.db.ExpireAPIKey(key)
}

func (s *State) ListAPIKeys() ([]types.APIKey, error) {
	return s.db.ListAPIKeys()
}

func (s *State) DestroyAPIKey(key types.APIKey) error {
	return s.db.DestroyAPIKey(key)
}

// =============================================================================
// PreAuth Key Management
// =============================================================================

func (s *State) CreatePreAuthKey(userID types.UserID, reusable bool, ephemeral bool, expiration *time.Time, aclTags []string) (*types.PreAuthKey, error) {
	return s.db.CreatePreAuthKey(userID, reusable, ephemeral, expiration, aclTags)
}

func (s *State) GetPreAuthKey(key string) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKey(key)
}

func (s *State) ListPreAuthKeys(userID types.UserID) ([]types.PreAuthKey, error) {
	return s.db.ListPreAuthKeys(userID)
}

func (s *State) ExpirePreAuthKey(key *types.PreAuthKey) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return hsdb.ExpirePreAuthKey(tx, key)
	})
}

// =============================================================================
// Registration Cache Management
// =============================================================================

func (s *State) GetRegistrationCacheEntry(registrationID types.RegistrationID) (*types.RegisterNode, bool) {
	entry, found := s.registrationCache.Get(registrationID)
	if !found {
		return nil, false
	}

	return &entry, true
}

func (s *State) SetRegistrationCacheEntry(registrationID types.RegistrationID, entry types.RegisterNode) {
	s.registrationCache.Set(registrationID, entry)
}

func (s *State) HandleNodeFromAuthPath(
	registrationID types.RegistrationID,
	userID types.UserID,
	expiry *time.Time,
	registrationMethod string,
) (*types.Node, bool, error) {
	ipv4, ipv6, err := s.ipAlloc.Next()
	if err != nil {
		return nil, false, err
	}

	return s.db.HandleNodeFromAuthPath(
		registrationID,
		userID,
		expiry,
		util.RegisterMethodOIDC,
		ipv4, ipv6,
	)
}

func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*types.Node, bool, error) {
	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)

	err = pak.Validate()
	if err != nil {
		return nil, false, err
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
		return nil, false, fmt.Errorf("allocating IPs: %w", err)
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
		return nil, false, fmt.Errorf("writing node to database: %w", err)
	}

	// Check if policy manager needs updating
	// This is necessary because we just created a new node.
	// We need to ensure that the policy manager is aware of this new node.
	policyChanged, err := s.updatePolicyManagerNodes()
	if err != nil {
		return nil, false, fmt.Errorf("failed to update policy manager after node registration: %w", err)
	}

	return node, policyChanged, nil
}

// =============================================================================
// IP Allocation
// =============================================================================

func (s *State) AllocateNextIPs() (*netip.Addr, *netip.Addr, error) {
	return s.ipAlloc.Next()
}

// =============================================================================
// Policy Manager Update Hooks
// =============================================================================

// updatePolicyManagerUsers updates the policy manager with current users.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for users.
func (s *State) updatePolicyManagerUsers() (bool, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return false, fmt.Errorf("listing users for policy update: %w", err)
	}

	changed, err := s.polMan.SetUsers(users)
	if err != nil {
		return false, fmt.Errorf("updating policy manager users: %w", err)
	}

	return changed, nil
}

// updatePolicyManagerNodes updates the policy manager with current nodes.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for nodes.
func (s *State) updatePolicyManagerNodes() (bool, error) {
	nodes, err := s.ListNodes()
	if err != nil {
		return false, fmt.Errorf("listing nodes for policy update: %w", err)
	}

	changed, err := s.polMan.SetNodes(nodes)
	if err != nil {
		return false, fmt.Errorf("updating policy manager nodes: %w", err)
	}

	return changed, nil
}

// =============================================================================
// Database Utilities
// =============================================================================

func (s *State) PingDB(ctx context.Context) error {
	return s.db.PingDB(ctx)
}

// autoApproveNodes mass approves routes on all nodes. It is _only_ intended for
// use when the policy is replaced. It is not sending or reporting any changes
// or updates as we send full updates after replacing the policy.
// TODO(kradalby): This is kind of messy, maybe this is another +1
// for an event bus. See example comments here.
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
