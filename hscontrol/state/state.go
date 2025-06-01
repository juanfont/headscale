package state

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
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
	zcache "zgo.at/zcache/v2"
)

const (
	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20
)

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

	return nil, fmt.Errorf("unsupported policy mode: %s", cfg.Policy.Mode)
}

func (s *State) DERPMap() *tailcfg.DERPMap {
	return s.derpMap
}

func (s *State) ValidateAPIKey(key string) (bool, error) {
	return s.db.ValidateAPIKey(key)
}

func (s *State) ListEphemeralNodes() (types.Nodes, error) {
	return s.db.ListEphemeralNodes()
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

// autoApproveNodes mass approves routes on all nodes. It is _only_ intended for
// use when the policy is replaced. It is not sending or reporting any changes
// or updates as we send full updates after replacing the policy.
// TODO(kradalby): This is kind of messy, maybe this is another +1
// for an event bus. See example comments here.
func (s *State) autoApproveNodes() error {
	err := s.db.Write(func(tx *gorm.DB) error {
		nodes, err := db.ListNodes(tx)
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

func (s *State) GetUserByOIDCIdentifier(id string) (*types.User, error) {
	return s.db.GetUserByOIDCIdentifier(id)
}

// Deprecated: Use specific database operation methods instead
func (s *State) Write(fn func(tx *gorm.DB) error) error {
	return s.db.Write(fn)
}

// Deprecated: Use specific database operation methods instead
func (s *State) WriteWithReturn(fn func(tx *gorm.DB) (*types.Node, error)) (*types.Node, error) {
	return db.Write(s.db.DB, fn)
}

func (s *State) GetNodeByNodeKey(nodeKey key.NodePublic) (*types.Node, error) {
	return s.db.GetNodeByNodeKey(nodeKey)
}

func (s *State) DeleteNode(node *types.Node) error {
	return s.db.DeleteNode(node)
}

func (s *State) NodeSetExpiry(nodeID types.NodeID, expiry time.Time) error {
	return s.db.NodeSetExpiry(nodeID, expiry)
}

func (s *State) GetPreAuthKey(key string) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKey(key)
}

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

func (s *State) AllocateNextIPs() (*netip.Addr, *netip.Addr, error) {
	return s.ipAlloc.Next()
}

func (s *State) AddUser(user *types.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(user).Error; err != nil {
		return fmt.Errorf("adding user: %w", err)
	}

	// TODO(kradalby): implement the user in-memory cache
	// TODO(kradalby): update policy manager with the new user

	return nil
}

func (s *State) UpdateUser(user *types.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(user).Error; err != nil {
		return fmt.Errorf("adding user: %w", err)
	}

	// TODO(kradalby): implement the user in-memory cache
	// TODO(kradalby): update policy manager with the update user

	return nil
}

func (s *State) AddNode(node *types.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(node).Error; err != nil {
		return fmt.Errorf("adding node: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache
	// TODO(kradalby): update policy manager with the new node

	return nil
}

func (s *State) UpdateNode(node *types.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.DB.Save(node).Error; err != nil {
		return fmt.Errorf("updating node: %w", err)
	}

	// TODO(kradalby): implement the node in-memory cache
	// TODO(kradalby): update policy manager with the updated node

	return nil
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

func (s *State) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	if len(nodeIDs) == 0 {
		return s.db.ListNodes()
	}
	return s.db.ListNodes(nodeIDs...)
}

func (s *State) CreateUser(user types.User) (*types.User, error) {
	return s.db.CreateUser(user)
}

func (s *State) GetUserByID(userID types.UserID) (*types.User, error) {
	return s.db.GetUserByID(userID)
}

func (s *State) GetUserByName(name string) (*types.User, error) {
	return s.db.GetUserByName(name)
}

func (s *State) RenameUser(userID types.UserID, newName string) error {
	return s.db.RenameUser(userID, newName)
}

func (s *State) DestroyUser(userID types.UserID) error {
	return s.db.DestroyUser(userID)
}

func (s *State) ListUsersWithFilter(filter *types.User) ([]types.User, error) {
	return s.db.ListUsers(filter)
}

func (s *State) ListAllUsers() ([]types.User, error) {
	return s.db.ListUsers()
}

func (s *State) CreatePreAuthKey(userID types.UserID, reusable bool, ephemeral bool, expiration *time.Time, aclTags []string) (*types.PreAuthKey, error) {
	return s.db.CreatePreAuthKey(userID, reusable, ephemeral, expiration, aclTags)
}

func (s *State) ListPreAuthKeys(userID types.UserID) ([]types.PreAuthKey, error) {
	return s.db.ListPreAuthKeys(userID)
}

func (s *State) GetNodeByID(nodeID types.NodeID) (*types.Node, error) {
	return s.db.GetNodeByID(nodeID)
}

// Policy methods that don't expose the PolicyManager
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

func (s *State) DebugString() string {
	return s.polMan.DebugString()
}

// PrimaryRoutes methods that don't expose the PrimaryRoutes
func (s *State) SetNodeRoutes(nodeID types.NodeID, routes ...netip.Prefix) bool {
	return s.primaryRoutes.SetRoutes(nodeID, routes...)
}

func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.primaryRoutes.PrimaryRoutes(nodeID)
}

func (s *State) PrimaryRoutesString() string {
	return s.primaryRoutes.String()
}

// Additional database methods needed by grpcv1
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return db.SetTags(tx, nodeID, tags)
	})
}

func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return db.SetApprovedRoutes(tx, nodeID, routes)
	})
}

func (s *State) RenameNode(nodeID types.NodeID, newName string) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return db.RenameNode(tx, nodeID, newName)
	})
}

func (s *State) AssignNodeToUser(node *types.Node, userID types.UserID) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return db.AssignNodeToUser(tx, node, userID)
	})
}

func (s *State) ListNodesByUser(userID types.UserID) (types.Nodes, error) {
	return db.Read(s.db.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return db.ListNodesByUser(rx, userID)
	})
}

func (s *State) BackfillNodeIPs() ([]string, error) {
	return s.db.BackfillNodeIPs(s.ipAlloc)
}

func (s *State) ExpirePreAuthKey(key *types.PreAuthKey) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return db.ExpirePreAuthKey(tx, key)
	})
}

// API Key methods
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

// Policy database methods
func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy()
}

func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data)
}

func (s *State) PolicyManagerDebugString() string {
	return s.polMan.DebugString()
}

// Operations that return nodes with database transaction
func (s *State) SetNodeTagsAndReturn(nodeID types.NodeID, tags []string) (*types.Node, error) {
	return db.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.SetTags(tx, nodeID, tags)
		if err != nil {
			return nil, err
		}
		return db.GetNodeByID(tx, nodeID)
	})
}

func (s *State) SetApprovedRoutesAndReturn(nodeID types.NodeID, routes []netip.Prefix) (*types.Node, error) {
	return db.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.SetApprovedRoutes(tx, nodeID, routes)
		if err != nil {
			return nil, err
		}
		return db.GetNodeByID(tx, nodeID)
	})
}

func (s *State) NodeSetExpiryAndReturn(nodeID types.NodeID, expiry time.Time) (*types.Node, error) {
	return db.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		db.NodeSetExpiry(tx, nodeID, expiry)
		return db.GetNodeByID(tx, nodeID)
	})
}

func (s *State) RenameNodeAndReturn(nodeID types.NodeID, newName string) (*types.Node, error) {
	return db.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := db.RenameNode(tx, nodeID, newName)
		if err != nil {
			return nil, err
		}
		return db.GetNodeByID(tx, nodeID)
	})
}

func (s *State) AssignNodeToUserAndReturn(nodeID types.NodeID, userID types.UserID) (*types.Node, error) {
	return db.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		node, err := db.GetNodeByID(tx, nodeID)
		if err != nil {
			return nil, err
		}
		err = db.AssignNodeToUser(tx, node, userID)
		if err != nil {
			return nil, err
		}
		return node, nil
	})
}

func (s *State) AutoApproveNodes() error {
	return s.autoApproveNodes()
}

// ListPeers returns peers of node from database
func (s *State) ListPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	return s.db.ListPeers(nodeID, peerIDs...)
}

// PingDB pings the database to check connectivity
func (s *State) PingDB(ctx context.Context) error {
	return s.db.PingDB(ctx)
}

// SetLastSeen updates the LastSeen timestamp for a node
func (s *State) SetLastSeen(nodeID types.NodeID, lastSeen time.Time) error {
	return s.db.Write(func(tx *gorm.DB) error {
		return db.SetLastSeen(tx, nodeID, lastSeen)
	})
}
