// Package state provides core state management for Headscale,
// coordinating between subsystems like database, IP allocation,
// policy management, and DERP routing.
//
// The central type [State] owns a copy-on-write [NodeStore]
// (node_store.go), a PrimaryRoutes HA ledger, the [policy.PolicyManager],
// and a [pingTracker] for [tailcfg.PingRequest] correlation.
// Cross-subsystem operations (node updates, policy evaluation, IP
// allocation) go through [State] rather than directly to the database.

package state

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/set"
)

const (
	// registerCacheExpiration defines how long node registration entries remain in cache.
	registerCacheExpiration = time.Minute * 15

	// defaultRegisterCacheMaxEntries is the default upper bound on the number
	// of pending registration entries the auth cache will hold. With a 15-minute
	// TTL and a stripped-down RegistrationData payload (~200 bytes per entry),
	// 1024 entries cap the worst-case cache footprint at well under 1 MiB even
	// under sustained unauthenticated cache-fill attempts.
	defaultRegisterCacheMaxEntries = 1024

	// defaultNodeStoreBatchSize is the default number of write operations to batch
	// before rebuilding the in-memory node snapshot.
	defaultNodeStoreBatchSize = 100

	// defaultNodeStoreBatchTimeout is the default maximum time to wait before
	// processing a partial batch of node operations.
	defaultNodeStoreBatchTimeout = 500 * time.Millisecond
)

// ErrUnsupportedPolicyMode is returned for invalid policy modes. Valid modes are "file" and "db".
var ErrUnsupportedPolicyMode = errors.New("unsupported policy mode")

// ErrInvalidPolicy is returned by [State.UpdatePolicy] and
// [State.ValidatePolicy] for a policy they refuse.
var ErrInvalidPolicy = errors.New("invalid policy")

// invalidPolicyError marks a refusal as [ErrInvalidPolicy] and keeps the
// reason's own text, which API answers show as is.
type invalidPolicyError struct{ reason error }

func (e invalidPolicyError) Error() string   { return e.reason.Error() }
func (e invalidPolicyError) Unwrap() []error { return []error{ErrInvalidPolicy, e.reason} }

// ErrNodeNotFound is returned when a node cannot be found by its ID.
var ErrNodeNotFound = errors.New("node not found")

// ErrInvalidNodeView is returned when an invalid node view is provided.
var ErrInvalidNodeView = errors.New("invalid node view provided")

// ErrNodeNotInNodeStore is returned when a node no longer exists in the [NodeStore].
var ErrNodeNotInNodeStore = errors.New("node no longer exists in NodeStore")

// ErrNodeNameNotUnique is returned when a node name is not unique.
var ErrNodeNameNotUnique = errors.New("node name is not unique")

// nodeUpdateColumns lists all Node columns that should be written
// during a struct-based GORM Updates() call.  Listing them explicitly
// forces GORM to include nil/zero-value fields (e.g. UserID=nil when
// converting a user-owned node to tagged) that struct-based Updates()
// would otherwise silently skip.
//
// Excluded columns:
//   - AuthKeyID, AuthKey: prevents GORM from persisting stale
//     PreAuthKey references after a key has been deleted (#2862).
//   - User: GORM association, not a real column.
//   - IsOnline: runtime-only field (gorm:"-").
var nodeUpdateColumns = []string{
	"MachineKey",
	"NodeKey",
	"DiscoKey",
	"Endpoints",
	"Hostinfo",
	"IPv4",
	"IPv6",
	"Hostname",
	"GivenName",
	"UserID",
	"RegisterMethod",
	"Tags",
	"Expiry",
	"LastSeen",
	"ApprovedRoutes",
	"AutoApprovedRoutes",
	"UpdatedAt",
}

// ErrRegistrationExpired is returned when a registration has expired.
var ErrRegistrationExpired = errors.New("registration expired")

// ErrNodeKeyExpired is returned when an expired node logs in again under its
// old node key; the client answers it by rotating the key.
var ErrNodeKeyExpired = errors.New("node key expired")

// ErrNodeKeyInUse is returned when a registration or re-auth claims a NodeKey
// already bound to a different machine, enforcing the 1:1 NodeKey<->MachineKey
// binding.
var ErrNodeKeyInUse = errors.New("node key already in use by another machine")

// ErrExpiryExtension is returned when a client asks for an expiry no earlier
// than its node's, or under a node key the node no longer holds.
var ErrExpiryExtension = errors.New("extending key is not allowed")

// ErrNodeKeyNotCurrent is returned when a map request uses a replaced node key.
var ErrNodeKeyNotCurrent = errors.New("node key is no longer current")

// ErrAmbiguousNodeOwnership is returned when a machine key maps to a set of
// nodes from which the correct one to update or convert cannot be determined:
// multiple user-owned candidates for a tagged conversion, or a tagged node and
// a user-owned node coexisting (impossible per validateNodeOwnership). The
// registration is rejected rather than mutating an arbitrarily-picked node.
var ErrAmbiguousNodeOwnership = errors.New("machine key maps to ambiguous node ownership")

// sshCheckPair identifies a (source, destination) node pair for
// SSH check auth tracking.
type sshCheckPair struct {
	Src types.NodeID
	Dst types.NodeID
}

type sshCheckAuthRecord struct {
	at  time.Time
	src types.NodeView
}

// State manages Headscale's core state, coordinating between database, policy management,
// IP allocation, and DERP routing. All methods are thread-safe.
//
// See [policy.PolicyManager] for policy evaluation and [NodeStore] for the
// in-memory node cache.
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

	// policyMu makes storing, loading and installing a policy one step, so
	// policies land in the database in the order they are installed.
	policyMu sync.Mutex

	// authCache holds any pending authentication requests from either auth
	// type (Web and OIDC). It is a bounded LRU keyed by AuthID; oldest
	// entries are evicted once the size cap is reached, and entries that
	// time out have their auth verdict resolved with ErrRegistrationExpired
	// via the eviction callback so any waiting goroutines wake.
	authCache *expirable.LRU[types.AuthID, *types.AuthRequest]

	// pings tracks pending ping requests and their response channels.
	pings *pingTracker

	// sshCheckAuth tracks when source nodes last completed SSH check auth.
	//
	// For rules without explicit checkPeriod (default 12h), auth covers any
	// destination — keyed by (src, Dst=0) where 0 is a sentinel meaning "any".
	// Ref: "Once re-authenticated to a destination, the user can access the
	// device and any other device in the tailnet without re-verification
	// for the next 12 hours." — https://tailscale.com/docs/features/tailscale-ssh
	//
	// For rules with explicit checkPeriod, auth covers only that specific
	// destination — keyed by (src, dst).
	// Ref: "If a different check period is specified for the connection,
	// then the user can access specifically this device without
	// re-verification for the duration of the check period."
	//
	// Ref: https://github.com/tailscale/tailscale/issues/10480
	// Ref: https://github.com/tailscale/tailscale/issues/7125
	sshCheckAuth map[sshCheckPair]sshCheckAuthRecord
	sshCheckMu   sync.RWMutex

	// persistMu serialises node-row persistence and deletion so the database
	// always converges on [NodeStore] rather than being clobbered by a stale
	// caller snapshot or resurrected by an update racing with deletion.
	persistMu sync.Mutex

	// selfRefresh holds nodes whose own DNS config inputs changed (NextDNS
	// device metadata, given name), drained by [State.DrainSelfRefreshes].
	selfRefresh   []types.NodeID
	selfRefreshMu sync.Mutex

	// registerLocks serialises registration per machine key so concurrent
	// registrations of the same machine resolve to a single node instead of
	// racing the find-then-create section and each creating their own.
	// ponytail: entries are never pruned; bounded by distinct machine keys
	// seen, add cleanup on node delete only if it ever matters.
	registerLocks *xsync.Map[key.MachinePublic, *sync.Mutex]

	// singleUseKeyLocks orders first uses across machines without retaining
	// a lock for every key.
	singleUseKeyLocks [64]sync.Mutex
}

// lockRegistration serialises registration for a single machine key and
// returns the unlock function.
func (s *State) lockRegistration(machineKey key.MachinePublic) func() {
	mu, _ := s.registerLocks.LoadOrStore(machineKey, &sync.Mutex{})
	mu.Lock()

	return mu.Unlock
}

// NewState creates and initializes a new [State] instance, setting up the database,
// IP allocator, DERP map, policy manager, and loading existing users and nodes.
func NewState(cfg *types.Config) (*State, error) {
	cacheExpiration := cmp.Or(cfg.Tuning.RegisterCacheExpiration, registerCacheExpiration)

	cacheMaxEntries := defaultRegisterCacheMaxEntries
	if cfg.Tuning.RegisterCacheMaxEntries > 0 {
		cacheMaxEntries = cfg.Tuning.RegisterCacheMaxEntries
	}

	db, err := hsdb.NewHeadscaleDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("initializing database: %w", err)
	}

	ipAlloc, err := hsdb.NewIPAllocator(db, cfg.PrefixV4, cfg.PrefixV6, cfg.IPAllocation)
	if err != nil {
		return nil, fmt.Errorf("initializing IP allocator: %w", err)
	}

	nodes, err := db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes: %w", err)
	}

	// On startup, all nodes should be marked as offline until they reconnect
	// This ensures we don't have stale online status from previous runs
	for _, node := range nodes {
		node.IsOnline = new(false)

		// PostgreSQL returns the server's zone, where the latest accepted
		// expiry is in the year 10000 and cannot be encoded.
		if node.Expiry != nil {
			node.Expiry = new(node.Expiry.UTC())
		}
	}

	users, err := db.ListUsers(nil)
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	pol, err := hsdb.PolicyBytes(db.DB, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	polMan, err := policy.NewPolicyManager(pol, users, nodes.ViewSlice())
	if err != nil {
		return nil, fmt.Errorf("initializing policy manager: %w", err)
	}

	// Apply defaults for [NodeStore] batch configuration if not set.
	// This ensures tests that create Config directly (without viper) still work.
	batchSize := cmp.Or(cfg.Tuning.NodeStoreBatchSize, defaultNodeStoreBatchSize)

	batchTimeout := cmp.Or(cfg.Tuning.NodeStoreBatchTimeout, defaultNodeStoreBatchTimeout)

	nodeStore := NewNodeStore(nodes, policyPeersFunc(polMan), batchSize, batchTimeout)
	polMan.SetRouterSession(nodeStore.RouterSession)
	nodeStore.Start()

	// Last: NewLRU starts the TTL sweeper goroutine, which only Close stops.
	authCache := expirable.NewLRU[types.AuthID, *types.AuthRequest](
		cacheMaxEntries,
		func(id types.AuthID, rn *types.AuthRequest) {
			rn.FinishAuth(types.AuthVerdict{Err: ErrRegistrationExpired})
		},
		cacheExpiration,
	)

	s := &State{
		cfg: cfg,

		db:        db,
		ipAlloc:   ipAlloc,
		polMan:    polMan,
		authCache: authCache,
		nodeStore: nodeStore,
		pings:     newPingTracker(),

		sshCheckAuth:  make(map[sshCheckPair]sshCheckAuthRecord),
		registerLocks: xsync.NewMap[key.MachinePublic, *sync.Mutex](),
	}

	// Surface nodes whose stored data would break map generation (e.g. an
	// invalid given name from a legacy row) so an operator can fix them. This
	// only logs; it never mutates a node's stored name at boot.
	s.logNodeHealth()

	return s, nil
}

// policyPeersFunc is the [PeersFunc] [State] runs its [NodeStore] with.
// It feeds the nodes being built to the policy manager first, so the
// build already uses the matchers they imply; building with the old
// matchers would serve stale adjacency until a second full rebuild.
// [policy.PolicyManager.NodesGeneration] tells the writing caller the
// SetNodes happened here.
//
// It runs on the NodeStore writer goroutine and takes the policy
// manager's lock, which is safe only while the policy manager never
// waits on a NodeStore write while holding it.
func policyPeersFunc(pm policy.PolicyManager) PeersFunc {
	return func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
		slice := views.SliceOf(nodes)

		// A failed recompile keeps the old nodes, so a caller that
		// refreshes the policy retries it and returns the error.
		_, err := pm.SetNodes(slice)
		if err != nil {
			log.Error().Err(err).Msg("refreshing policy nodes before peer map build")
		}

		return pm.BuildPeerMap(slice)
	}
}

// Close gracefully shuts down the [State] instance and releases all resources.
func (s *State) Close() error {
	s.pings.drain()
	s.nodeStore.Stop()
	// Purge before Close: Close stops the sweeper, so anything still cached
	// would never expire and its WaitForAuth caller would hang.
	s.authCache.Purge()
	s.authCache.Close()

	err := s.db.Close()
	if err != nil {
		return fmt.Errorf("closing database: %w", err)
	}

	return nil
}

// SetDERPMap updates the DERP relay configuration.
func (s *State) SetDERPMap(dm *tailcfg.DERPMap) {
	s.derpMap.Store(dm)
}

// DERPMap returns the current DERP relay configuration for peer-to-peer connectivity.
func (s *State) DERPMap() tailcfg.DERPMapView {
	return s.derpMap.Load().View()
}

// ReloadPolicy reloads the access control policy.
//
// It approves no routes: auto-approval waits for a node's next change to
// its announced routes or its next node key rotation, as on Tailscale SaaS,
// so a reload cannot undo an admin's revoke.
func (s *State) ReloadPolicy() ([]change.Change, error) {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	return s.reloadPolicyLocked()
}

// reloadPolicyLocked is [State.ReloadPolicy] for callers holding policyMu.
func (s *State) reloadPolicyLocked() ([]change.Change, error) {
	pol, err := hsdb.PolicyBytes(s.db.DB, s.cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	// nil means no policy is configured: nothing to install.
	var policyChanged bool
	if pol != nil {
		policyChanged, err = s.polMan.SetPolicy(pol)
		if err != nil {
			return nil, fmt.Errorf("setting policy: %w", err)
		}
	}

	// Clear SSH check auth times when policy changes to ensure stale
	// approvals don't persist if checkPeriod rules are modified or removed.
	s.ClearSSHCheckAuth()

	// Rebuild peer maps after policy changes because the peersFunc in [NodeStore]
	// uses the [policy.PolicyManager]'s filters. Without this, nodes won't see
	// newly allowed peers until a node is added/removed, causing autogroup:self
	// policies to not propagate correctly when switching between policy types.
	//
	// An unchanged policy leaves the matchers as they were, and the other
	// inputs of the peer map rebuild it themselves (node writes in the
	// [NodeStore], [State.updatePolicyManagerNodes] and
	// [State.updatePolicyManagerUsers]), so the O(n^2) rebuild is skipped
	// then. The policy API handlers always get here that way: they apply
	// the policy with [State.SetPolicy], which rebuilds, store it, and
	// reload the very same bytes.
	if policyChanged {
		s.nodeStore.RebuildPeerMaps()
	}

	if policyChanged {
		log.Info().Msg("Policy reload completed with changes")
	}

	// Nodes whose CapMap shifted get their self refresh from
	// [State.DrainSelfRefreshes] when these changes are dispatched.
	return []change.Change{change.PolicyChange()}, nil
}

// CreateUser creates a new user and updates the policy manager.
// Returns the created user, change set, and any error.
func (s *State) CreateUser(user types.User) (*types.User, change.Change, error) {
	if err := s.db.DB.Save(&user).Error; err != nil { //nolint:noinlineerr
		return nil, change.Change{}, fmt.Errorf("creating user: %w", err)
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		// Log the error but don't fail the user creation
		return &user, change.Change{}, fmt.Errorf("updating policy manager after user creation: %w", err)
	}

	// Even if the policy manager doesn't detect a filter change, SSH policies
	// might now be resolvable when they weren't before. If there are existing
	// nodes, we should send a policy change to ensure they get updated SSH policies.
	// TODO(kradalby): detect this, or rebuild all SSH policies so we can determine
	// this upstream.
	if c.IsEmpty() {
		c = change.PolicyChange()
	}

	log.Info().Str(zf.UserName, user.Name).Msg("user created")

	return &user, c, nil
}

// UpdateUser modifies an existing user using the provided update function within a transaction.
// Returns the updated user, change set, and any error.
func (s *State) UpdateUser(userID types.UserID, updateFn func(*types.User) error) (*types.User, change.Change, error) {
	user, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.User, error) {
		user, err := hsdb.GetUserByID(tx, userID)
		if err != nil {
			return nil, err
		}

		if err := updateFn(user); err != nil { //nolint:noinlineerr
			return nil, err
		}

		// Use Updates() to only update modified fields, preserving unchanged values.
		err = tx.Updates(user).Error
		if err != nil {
			return nil, fmt.Errorf("updating user: %w", err)
		}

		return user, nil
	})
	if err != nil {
		return nil, change.Change{}, err
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return user, change.Change{}, fmt.Errorf("updating policy manager after user update: %w", err)
	}

	// TODO(kradalby): We might want to update nodestore with the user data

	return user, c, nil
}

// DeleteUser permanently removes a user and all associated data (nodes, API keys, etc).
// This operation is irreversible.
// It also updates the policy manager to ensure ACL policies referencing the deleted
// user are re-evaluated immediately, fixing issue #2967.
func (s *State) DeleteUser(userID types.UserID) (change.Change, error) {
	err := s.db.DestroyUser(userID)
	if err != nil {
		return change.Change{}, err
	}

	// Update policy manager with the new user list (without the deleted user)
	// This ensures that if the policy references the deleted user, it gets
	// re-evaluated immediately rather than when some other operation triggers it.
	c, err := s.updatePolicyManagerUsers()
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy after user deletion: %w", err)
	}

	// If the policy manager doesn't detect changes, still return UserRemoved
	// to ensure peer lists are refreshed
	if c.IsEmpty() {
		c = change.UserRemoved()
	}

	return c, nil
}

// RenameUser changes a user's name. The new name must be unique.
func (s *State) RenameUser(userID types.UserID, newName string) (*types.User, change.Change, error) {
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
	return s.db.ListUsers(nil)
}

// persistNode writes the node's database row, re-reading the
// authoritative copy from [NodeStore], without touching the policy manager.
func (s *State) persistNode(node types.NodeView) (types.NodeView, error) {
	return s.persistNodeWith(node, nodeUpdateColumns, nil)
}

// persistNodeWith writes the current node and any related change in one
// transaction. inTx runs inside it, with persistMu held.
func (s *State) persistNodeWith(
	node types.NodeView,
	columns []string,
	inTx func(*gorm.DB) error,
) (types.NodeView, error) {
	if !node.Valid() {
		return types.NodeView{}, ErrInvalidNodeView
	}

	// [NodeStore] is the source of truth and every caller updates it before
	// persisting. Re-read the authoritative node under persistMu and write
	// that, rather than the caller's `node` view which may have been captured
	// earlier (e.g. at the top of UpdateNodeFromMapRequest) and gone stale
	// behind a concurrent admin write such as SetNodeTags. Serialising the
	// read+write keeps the database row converging on [NodeStore] instead of
	// reverting it to an out-of-date column set.
	//
	// The same re-read also guards against the node having been deleted (e.g.
	// ephemeral logout) between the caller's update and this persist: a missing
	// node means we must not re-insert it.
	s.persistMu.Lock()
	defer s.persistMu.Unlock()

	fresh, exists := s.nodeStore.GetNode(node.ID())
	if !exists {
		log.Warn().
			EmbedObject(node).
			Bool("is_ephemeral", node.IsEphemeral()).
			Msg("Node no longer exists in NodeStore, skipping database persist to prevent race condition")

		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, node.ID())
	}

	nodePtr := fresh.AsStruct()

	// Explicitly select all node columns so GORM includes nil/zero-value
	// fields (e.g. UserID=nil when converting a user-owned node to tagged).
	err := s.db.Write(func(tx *gorm.DB) error {
		err := tx.Select(columns).Updates(nodePtr).Error
		if err != nil {
			return err
		}

		if inTx != nil {
			return inTx(tx)
		}

		return nil
	})
	if err != nil {
		return types.NodeView{}, fmt.Errorf("saving node: %w", err)
	}

	return fresh, nil
}

// persistNodeAndRefreshPolicy saves the given node state to the database and refreshes the
// policy manager. The exact row written comes from [NodeStore]; see
// [State.persistNode].
// genBefore is as for [State.updatePolicyManagerNodes].
func (s *State) persistNodeAndRefreshPolicy(node types.NodeView, genBefore uint64) (types.NodeView, change.Change, error) {
	fresh, err := s.persistNode(node)
	if err != nil {
		return types.NodeView{}, nodeWriteFailed(node.ID(), s.policyChangeSince(genBefore)), err
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes(genBefore)
	if err != nil {
		return fresh, nodeWriteFailed(node.ID(), c), fmt.Errorf("updating policy manager after node save: %w", err)
	}

	return fresh, c, nil
}

func (s *State) SaveNode(node types.NodeView) (types.NodeView, change.Change, error) {
	// Update [NodeStore] first
	nodePtr := node.AsStruct()

	genBefore := s.polMan.NodesGeneration()
	resultNode := s.nodeStore.PutNode(*nodePtr)

	// Then save to database using the result from [NodeStore.PutNode]
	return s.persistNodeAndRefreshPolicy(resultNode, genBefore)
}

// DeleteNode permanently removes a node and cleans up associated resources.
// Once the database deletion commits, the returned changes always start with
// the node-removal notification, even if a later policy refresh fails. Callers
// must publish the changes before handling the error so live sessions are
// still torn down after a committed deletion.
func (s *State) DeleteNode(node types.NodeView) ([]change.Change, error) {
	genBefore := s.polMan.NodesGeneration()

	s.persistMu.Lock()

	err := s.db.DeleteNode(node.AsStruct())
	s.persistMu.Unlock()

	if err != nil {
		return nil, err
	}

	// The database is the durable source of truth. Only remove the in-memory
	// node after its row is gone so a failed database write cannot make a live
	// node look deleted until the next restart. persistMu stays out of this
	// write: a persist that still finds the node updates no row, and holding
	// it would give every concurrent delete a NodeStore batch of its own.
	s.nodeStore.DeleteNode(node.ID())

	s.ipAlloc.FreeIPs(node.IPs())

	// An explicit removal of its own, ahead of the policy refresh, so peers
	// learn of the deletion without depending on their sent-peers tracking.
	removed := change.NodeRemoved(node.ID())

	policyChange, err := s.updatePolicyManagerNodes(genBefore)
	if err != nil {
		return []change.Change{removed, policyChange}, fmt.Errorf("updating policy manager after node deletion: %w", err)
	}

	return []change.Change{removed, policyChange}, nil
}

// Connect acquires a control session and returns the resulting changes
// plus a session epoch identifying this poll session. Every Connect
// acquires one live session; the caller must release it with exactly
// one [State.Disconnect] call once the session ends (see poll.go).
// An expired key can keep polling control, but cannot make the node online.
func (s *State) Connect(id types.NodeID) ([]change.Change, uint64) {
	prevRoutes := s.nodeStore.PrimaryRoutes()

	// Reconnecting clears Unhealthy: the node just proved basic
	// connectivity by completing the Noise handshake.
	var epoch uint64

	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.SessionEpoch++
		epoch = n.SessionEpoch

		// A reconnect within poll.go's offline grace keeps the age: peers
		// never saw the node leave, so a blip does not move its routes.
		if n.ActiveSessions == 0 {
			n.SessionStart = time.Now()
		}

		n.ActiveSessions++
		n.IsOnline = new(n.ShouldBeOnline())
		n.Unhealthy = false
	})
	if !ok {
		return nil, 0
	}

	// A node coming online sends a lightweight online peer patch. Subnet
	// routers, relay targets, and via targets get their full peer recompute
	// from the gated PolicyChange below, so no full update is needed here.
	c := []change.Change{change.NodeOnline(node.ID())}
	if !node.Online() {
		c[0] = change.NodeAdded(node.ID())
	}

	log.Info().EmbedObject(node).Msg("node connected")

	if !maps.Equal(prevRoutes, s.nodeStore.PrimaryRoutes()) {
		c = append(c, change.NodeAdded(id))
	}

	// Only a node whose online state changes what peers compute (a subnet
	// router, relay target, or via target) needs a full peer recompute.
	// An ordinary node coming online just sends the lightweight online
	// patch above; emitting a PolicyChange for it would force every peer
	// to rebuild its netmap on every reconnect.
	if s.polMan.NodeNeedsPeerRecompute(node) {
		c = append(c, change.PolicyChange())
	}

	return c, epoch
}

// Disconnect releases one poll session previously acquired by
// [State.Connect] and marks the node offline when that was its
// last live session. Sessions are counted rather than compared by
// epoch: overlapping sessions for one node — a rapid reconnect, or a
// cancelled map request whose handler ran late — release in any order
// without stranding the node. An epoch-equality gate here loses when a
// dead-on-arrival session's Connect steals the latest epoch and its
// cleanup skips the release: the surviving session's Disconnect was
// then rejected as stale and the node stayed online forever.
// The count check and the IsOnline write share a
// [NodeStore.UpdateNode] closure, making them atomic against
// concurrent connects. epoch identifies the session for logging only.
func (s *State) Disconnect(id types.NodeID, epoch uint64) ([]change.Change, error) {
	var wentOffline bool

	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		if n.ActiveSessions > 0 {
			n.ActiveSessions--
		}

		if n.ActiveSessions > 0 {
			return
		}

		wentOffline = true

		now := time.Now()
		n.LastSeen = &now
		n.IsOnline = new(n.ShouldBeOnline())
		// Offline nodes are not HA candidates; drop any stale
		// Unhealthy bit so it does not surface in DebugRoutes.
		n.Unhealthy = false
	})

	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrNodeNotFound, id)
	}

	if !wentOffline {
		log.Debug().
			Uint64("disconnect_epoch", epoch).
			Int("active_sessions", node.ActiveSessions()).
			Msg("session released, other control sessions remain")

		return nil, nil
	}

	log.Info().EmbedObject(node).Msg("node disconnected")

	// Persist LastSeen best-effort: [NodeStore] already reflects offline
	// and peers still need the change notifications below. Going offline
	// changes nothing the policy reads, so the row write skips the policy
	// manager refresh.
	_, err := s.persistNode(node)
	if err != nil {
		log.Error().Err(err).EmbedObject(node).Msg("failed to update last seen in database")
	}

	// An ordinary node going offline only needs the lightweight offline
	// patch. Subnet routers, relay targets, and via targets change what
	// peers compute, so they additionally force a peer recompute.
	cs := []change.Change{change.NodeOffline(node.ID())}
	if s.polMan.NodeNeedsPeerRecompute(node) {
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

// GetNodesByMachineKeyAllUsers returns every node sharing the machine key,
// keyed by owning UserID (tagged nodes under UserID(0)). See
// [NodeStore.GetNodesByMachineKeyAllUsers].
func (s *State) GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView {
	return s.nodeStore.GetNodesByMachineKeyAllUsers(machineKey)
}

// ResolveNode looks up a node by numeric ID, IPv4/IPv6 address, given
// name, or hostname. It tries ID first, then IP, then GivenName
// (unique per tailnet), then Hostname (client-reported, may collide).
// Within the name passes, the lowest NodeID wins so repeated calls
// are deterministic across snapshot iterations.
func (s *State) ResolveNode(query string) (types.NodeView, bool) {
	// Try numeric ID first.
	id, idErr := types.ParseNodeID(query)
	if idErr == nil {
		return s.GetNodeByID(id)
	}

	// keepLowest returns whichever node has the lower ID, so repeated
	// calls resolve deterministically across snapshot iterations.
	keepLowest := func(cur, cand types.NodeView) types.NodeView {
		if !cur.Valid() || cand.ID() < cur.ID() {
			return cand
		}

		return cur
	}

	// Try IP address.
	addr, addrErr := netip.ParseAddr(query)
	if addrErr == nil {
		var match types.NodeView

		for _, n := range s.ListNodes().All() {
			if !slices.Contains(n.IPs(), addr) {
				continue
			}

			match = keepLowest(match, n)
		}

		return match, match.Valid()
	}

	// Try GivenName then Hostname, each with a stable tie-break on
	// lowest NodeID.
	var givenMatch, hostMatch types.NodeView

	for _, n := range s.ListNodes().All() {
		if n.GivenName() == query {
			givenMatch = keepLowest(givenMatch, n)
		} else if n.Hostname() == query {
			hostMatch = keepLowest(hostMatch, n)
		}
	}

	if givenMatch.Valid() {
		return givenMatch, true
	}

	return hostMatch, hostMatch.Valid()
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

	// Incremental updates (NodeAdded, NodeChanged) name the peers involved.
	// Resolve them through the recipient's adjacency so a changed node the
	// policy hides from this recipient is never delivered; the mapper still
	// applies the live matchers on top.
	nodeIDSet := make(map[types.NodeID]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		nodeIDSet[id] = struct{}{}
	}

	var filteredNodes []types.NodeView

	// Adjacency is built from node pairs, so it never contains the
	// recipient: a change batch naming it cannot return it as its own peer.
	for _, peer := range s.nodeStore.ListPeers(nodeID).All() {
		if _, exists := nodeIDSet[peer.ID()]; exists {
			filteredNodes = append(filteredNodes, peer)
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
// If expiry is nil, the node's expiry is disabled (node will never expire).
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry *time.Time) (types.NodeView, change.Change, error) {
	return s.setNodeExpiry(nodeID, expiry, nil)
}

// BringNodeExpiryForward stores the expiry a client asks for when the node
// still holds nodeKey and has no expiry or a later one. The NodeStore writer
// decides, so an expiry that lands meanwhile, such as an admin's, is never
// pushed back.
func (s *State) BringNodeExpiryForward(
	nodeID types.NodeID,
	nodeKey key.NodePublic,
	expiry time.Time,
) (types.NodeView, change.Change, error) {
	return s.setNodeExpiry(nodeID, &expiry, func(node *types.Node) bool {
		return node.NodeKey == nodeKey &&
			(node.Expiry == nil || node.Expiry.IsZero() || expiry.Before(*node.Expiry))
	})
}

// setNodeExpiry sets the node's expiry. A non-nil allow decides on the node
// as the writer holds it; a refusal writes nothing.
func (s *State) setNodeExpiry(
	nodeID types.NodeID,
	expiry *time.Time,
	allow func(*types.Node) bool,
) (types.NodeView, change.Change, error) {
	if expiry != nil {
		utc, err := types.ValidateExpiry(*expiry)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}

		expiry = &utc
	}

	var onlineChanged, expired, refused bool

	genBefore := s.polMan.NodesGeneration()

	// Update [NodeStore] before database to ensure consistency. The [NodeStore] update
	// is blocking and will be the source of truth for the batcher. The database update
	// must make the exact same change. If the database update fails, the [NodeStore]
	// change will remain, and the change describing it is returned with the error.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		if allow != nil && !allow(node) {
			refused = true

			return
		}

		wasOnline := node.Online()
		node.Expiry = expiry
		// Control stays connected in NeedsLogin so an expiry extension can
		// recover the client, but an expired key is not online.
		node.IsOnline = new(node.ShouldBeOnline())
		onlineChanged = wasOnline != node.Online()
		// A relogin later in the batch can renew the node before n is read.
		expired = node.IsExpired()
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	if refused {
		return types.NodeView{}, change.Change{}, ErrExpiryExtension
	}

	if expired {
		// Expiry revokes the human check even if a pre-auth key renews the node.
		s.sshCheckMu.Lock()
		for pair := range s.sshCheckAuth {
			if pair.Src == nodeID {
				delete(s.sshCheckAuth, pair)
			}
		}
		s.sshCheckMu.Unlock()
	}

	// The online flip already re-elected primaries in the NodeStore, so
	// peers need it even when the database write below fails.
	var recompute change.Change
	if onlineChanged && s.polMan.NodeNeedsPeerRecompute(n) {
		recompute = change.PolicyChange()
	}

	_, err := s.persistNode(n)
	if err != nil {
		c := nodeWriteFailed(nodeID, s.policyChangeSince(genBefore).Merge(recompute))

		return types.NodeView{}, c, fmt.Errorf("setting node expiry in database: %w", err)
	}

	// Update policy manager and generate change notification.
	c, err := s.updatePolicyManagerNodes(genBefore)
	if err != nil {
		return n, nodeWriteFailed(nodeID, c.Merge(recompute)), fmt.Errorf("updating policy manager after setting expiry: %w", err)
	}

	// Resolve expiry and online status together from the current snapshot
	// when the mapper sends the change, including after a rapid restoration.
	c = c.Merge(change.NodeAdded(n.ID())).Merge(recompute)

	return n, c, nil
}

// SetNodeTags assigns tags to a node, making it a "tagged node".
// Once a node is tagged, it cannot be un-tagged (only tags can be changed).
// Setting tags clears UserID since tagged nodes are owned by their tags.
func (s *State) SetNodeTags(nodeID types.NodeID, tags []string) (types.NodeView, change.Change, error) {
	if len(tags) == 0 {
		return types.NodeView{}, change.Change{}, types.ErrCannotRemoveAllTags
	}

	// Get node for validation
	existingNode, exists := s.nodeStore.GetNode(nodeID)
	if !exists {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotFound, nodeID)
	}

	// Validate tags: must have correct format and exist in policy
	validatedTags := make([]string, 0, len(tags))
	invalidTags := make([]string, 0)

	for _, tag := range tags {
		if !strings.HasPrefix(tag, "tag:") || !s.polMan.TagExists(tag) {
			invalidTags = append(invalidTags, tag)

			continue
		}

		validatedTags = append(validatedTags, tag)
	}

	if len(invalidTags) > 0 {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, invalidTags)
	}

	slices.Sort(validatedTags)
	validatedTags = slices.Compact(validatedTags)

	// Log the operation
	logTagOperation(existingNode, validatedTags)

	genBefore := s.polMan.NodesGeneration()

	// Update [NodeStore] before database to ensure consistency. The [NodeStore] update
	// is blocking and will be the source of truth for the batcher. The database update
	// must make the exact same change.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.Tags = validatedTags
		// Tagged nodes are owned by their tags, not a user.
		node.UserID = nil
		node.User = nil
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	nodeView, c, err := s.persistNodeAndRefreshPolicy(n, genBefore)
	if err != nil {
		return nodeView, c, err
	}

	if c.IsEmpty() {
		// Tags are peer visible (tag owner resolution, ACLs); resend the
		// whole node even when re-applying the same tags didn't move policy.
		c = change.NodeAdded(nodeID)
	}

	// Set OriginNode so the mapper knows to include self info for this node.
	// When tags change, persistNodeAndRefreshPolicy returns PolicyChange which doesn't set OriginNode,
	// so the mapper's self-update check fails and the node never sees its new tags.
	// Setting OriginNode ensures the node gets a self-update with the new tags.
	c.OriginNode = nodeID

	// The new tags may approve announced routes, as on Tailscale SaaS. This
	// runs after the policy refresh above, which teaches the policy manager
	// the node's new owner.
	routesChange, err := s.AutoApproveRoutes(nodeView)
	c = c.Merge(routesChange)

	if fresh, ok := s.nodeStore.GetNode(nodeID); ok {
		nodeView = fresh
	}

	if err != nil {
		return nodeView, c, fmt.Errorf("auto approving routes: %w", err)
	}

	return nodeView, c, nil
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
// It returns a PolicyChange when a primary moved, the policy manager saw a
// policy input change, or the node's peers changed; otherwise NodeAdded.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (types.NodeView, change.Change, error) {
	// Every route an admin sets is the admin's, even one autoApprovers
	// cover, so a withdrawal keeps it.
	return s.updateApprovedRoutes(nodeID, func(node *types.Node) {
		node.ApprovedRoutes = routes
		node.AutoApprovedRoutes = nil
	})
}

func (s *State) updateApprovedRoutes(nodeID types.NodeID, set UpdateNodeFunc) (types.NodeView, change.Change, error) {
	prevRoutes := s.nodeStore.PrimaryRoutes()
	prevPeers := s.nodeStore.ListPeerIDs(nodeID)
	genBefore := s.polMan.NodesGeneration()

	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		set(node)
		// A node with no approved routes is no longer an HA
		// candidate; drop any stale Unhealthy bit (mirrors the
		// legacy routes.SetRoutes(empty) auto-clear).
		if len(node.AllApprovedRoutes()) == 0 {
			node.Unhealthy = false
		}
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	// Persist the node changes to the database
	nodeView, c, err := s.persistNodeAndRefreshPolicy(n, genBefore)

	// The reads around the write can also see concurrent writers; that
	// only turns a whole-peer update into a policy change, never back.
	routeChange := !maps.Equal(prevRoutes, s.nodeStore.PrimaryRoutes())
	peersChanged := !slices.Equal(prevPeers, s.nodeStore.ListPeerIDs(nodeID))

	if err != nil {
		// The NodeStore holds the new routes either way.
		if routeChange || peersChanged {
			c = c.Merge(change.PolicyChange())
		}

		return nodeView, c, err
	}

	if routeChange || peersChanged || !c.IsEmpty() {
		c = change.PolicyChange()
	} else {
		// No visibility or effective route moved; resend the node so
		// peers hold its current state.
		c = change.NodeAdded(nodeID)
	}

	return nodeView, c, nil
}

// RenameNode changes the display name of a node. The admin supplies
// the exact DNS label they want; malformed input is rejected (no
// auto-sanitisation) and collisions error out rather than silently
// bumping a user-facing label. See HOSTNAME.md for the CLI contract.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (types.NodeView, change.Change, error) {
	// DNS is case-insensitive but uniqueness and the client's certificate
	// name match are not, so "Foo" and "foo" would share one name.
	newName = strings.ToLower(newName)

	// Validate the label AND that the resulting FQDN fits MaxHostnameLength:
	// a valid 63-char label can still overflow under a long base_domain, and
	// an unmappable name would break this node and its peers (issue #3346).
	err := types.ValidateGivenName(newName, s.cfg.BaseDomain)
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %w", ErrGivenNameInvalid, err)
	}

	genBefore := s.polMan.NodesGeneration()

	view, err := s.nodeStore.SetGivenName(nodeID, newName)
	if err != nil {
		switch {
		case errors.Is(err, ErrGivenNameTaken):
			return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %s", ErrNodeNameNotUnique, newName)
		case errors.Is(err, ErrNodeNotFound):
			return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
		default:
			return types.NodeView{}, change.Change{}, fmt.Errorf("renaming node: %w", err)
		}
	}

	nodeView, c, err := s.persistNodeAndRefreshPolicy(view, genBefore)
	if err != nil {
		return nodeView, c, err
	}

	if c.IsEmpty() {
		// A rename is peer visible; resend the whole node.
		c = change.NodeAdded(nodeID)
	}

	// The node's own DNS config carries its name (CertDomains), and the
	// change above does not resend DNS config to the renamed node itself.
	s.selfRefreshMu.Lock()
	s.selfRefresh = append(s.selfRefresh, nodeID)
	s.selfRefreshMu.Unlock()

	return nodeView, c, nil
}

// BackfillNodeIPs assigns IP addresses to nodes that don't have them. The
// returned changes tell clients about the new addresses.
// Like the other writes, it returns the changes alongside an error once the
// NodeStore holds new addresses; callers publish them before handling it.
func (s *State) BackfillNodeIPs() ([]string, []change.Change, error) {
	genBefore := s.polMan.NodesGeneration()

	// Hold persistMu until NodeStore has the new addresses, or a concurrent
	// persist writes the old ones back from NodeStore in between.
	s.persistMu.Lock()

	changes, err := s.db.BackfillNodeIPs(s.ipAlloc)
	if err != nil {
		s.persistMu.Unlock()

		return nil, nil, err
	}

	var readdressed []types.NodeID

	// Copy only the IPs into [NodeStore]: the database rows lack
	// runtime-only state such as sessions and online status.
	if len(changes) > 0 {
		nodes, err := s.db.ListNodes()
		if err != nil {
			s.persistMu.Unlock()

			return changes, nil, fmt.Errorf("refreshing NodeStore after IP backfill: %w", err)
		}

		updates := make(map[types.NodeID]UpdateNodeFunc, len(nodes))
		for _, node := range nodes {
			existingNode, exists := s.nodeStore.GetNode(node.ID)
			if exists && !slices.Equal(existingNode.IPs(), node.IPs()) {
				readdressed = append(readdressed, node.ID)
			}

			updates[node.ID] = func(n *types.Node) {
				n.IPv4 = node.IPv4
				n.IPv6 = node.IPv6
			}
		}

		s.nodeStore.UpdateNodes(updates)
	}

	s.persistMu.Unlock()

	// IPs are policy inputs: without this, clients only learned the new
	// addresses from whichever unrelated write next refreshed the policy.
	c, err := s.updatePolicyManagerNodes(genBefore)

	// A policy change carries no self node, so a readdressed node would
	// not learn its own new addresses from it.
	cs := make([]change.Change, 0, len(readdressed)+1)
	if !c.IsEmpty() {
		cs = append(cs, c)
	}

	for _, id := range readdressed {
		cs = append(cs, change.NodeAdded(id))
	}

	return changes, cs, err
}

// ExpireExpiredNodes finds and processes expired nodes since the last check.
// Returns next check time, state update with expired nodes, and whether any were found.
func (s *State) ExpireExpiredNodes(lastCheck time.Time) (time.Time, []change.Change, bool) {
	// Why capture start time: We need to ensure we don't miss nodes that expire
	// while this function is running by using a consistent timestamp for the next check
	started := time.Now()

	nodeUpdates := make(map[types.NodeID]UpdateNodeFunc)
	expiredNodes := make(map[types.NodeID]bool)

	for _, node := range s.nodeStore.ListNodes().All() { //nolint:unqueryvet // NodeStore.ListNodes not a SQL query
		if !node.Valid() {
			continue
		}

		// Why check After(lastCheck): We only want to notify about nodes that
		// expired since the last check to avoid duplicate notifications
		if !node.IsExpired() || !node.Expiry().Get().After(lastCheck) {
			continue
		}

		nodeUpdates[node.ID()] = func(n *types.Node) {
			// The key may have been restored since the snapshot was read.
			if !n.IsExpired() || !n.Expiry.After(lastCheck) {
				return
			}

			expiredNodes[n.ID] = n.Online()
			n.IsOnline = new(n.ShouldBeOnline())
		}
	}

	// Publish simultaneous expirations together so route election sees all
	// unavailable nodes in one snapshot.
	s.nodeStore.UpdateNodes(nodeUpdates)

	updates := make([]change.Change, 0, len(expiredNodes))

	for id, wasOnline := range expiredNodes {
		c := change.NodeAdded(id)
		if current, ok := s.nodeStore.GetNode(id); ok && wasOnline && s.polMan.NodeNeedsPeerRecompute(current) {
			c = c.Merge(change.PolicyChange())
		}

		updates = append(updates, c)
	}

	if len(updates) > 0 {
		return started, updates, true
	}

	return started, nil, false
}

// SSHPolicy returns the SSH access policy for a node.
func (s *State) SSHPolicy(node types.NodeView) (*tailcfg.SSHPolicy, error) {
	return s.polMan.SSHPolicy(s.cfg.ServerURL, node)
}

// SSHCheckParams resolves the SSH check period for src logging in to dst
// as localUser from the current policy.
func (s *State) SSHCheckParams(
	srcNodeID, dstNodeID types.NodeID,
	localUser string,
) (time.Duration, bool) {
	return s.polMan.SSHCheckParams(srcNodeID, dstNodeID, localUser)
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

// NodeCapMap returns the policy-derived CapMap for the given node, suitable
// for merging into [tailcfg.Node.CapMap] when the node is rendered as self or
// as someone else's peer.
func (s *State) NodeCapMap(id types.NodeID) tailcfg.NodeCapMap {
	return s.polMan.NodeCapMap(id)
}

// NodeCapMaps returns a snapshot of every node's policy CapMap so
// callers can amortise lock acquisition over a peer loop.
func (s *State) NodeCapMaps() map[types.NodeID]tailcfg.NodeCapMap {
	return s.polMan.NodeCapMaps()
}

// NodeCapMapsForPeers returns one policy snapshot containing the requested peer caps.
// It may include other entries; inner maps are shared and read-only.
func (s *State) NodeCapMapsForPeers(peers views.Slice[types.NodeView]) map[types.NodeID]tailcfg.NodeCapMap {
	return s.polMan.NodeCapMapsForPeers(peers)
}

// NodeCanHaveTag checks if a node is allowed to have a specific tag.
func (s *State) NodeCanHaveTag(node types.NodeView, tag string) bool {
	return s.polMan.NodeCanHaveTag(node, tag)
}

// SetPolicy installs pol without storing it. Policy writes use
// [State.UpdatePolicy].
func (s *State) SetPolicy(pol []byte) (bool, error) {
	changed, err := s.polMan.SetPolicy(pol)
	if err != nil {
		return changed, err
	}

	// Clear SSH check auth times when policy changes.
	s.ClearSSHCheckAuth()

	// Payload-only writes reuse the cached adjacency, so a policy swap
	// must rebuild it here rather than wait for the next relation write.
	if changed {
		s.nodeStore.RebuildPeerMaps()
	}

	return changed, nil
}

// AutoApproveRoutes approves the announced routes the policy lets a node
// approve, and drops the auto-approved routes it no longer announces.
func (s *State) AutoApproveRoutes(nv types.NodeView) (change.Change, error) {
	approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
	withdrawn := slices.ContainsFunc(nv.AutoApprovedRoutes().AsSlice(), func(route netip.Prefix) bool {
		return !slices.Contains(nv.AnnouncedRoutes(), route)
	})

	if changed || withdrawn {
		log.Debug().
			EmbedObject(nv).
			Strs("routes.announced", util.PrefixesToString(nv.AnnouncedRoutes())).
			Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
			Strs("routes.approved.new", util.PrefixesToString(approved)).
			Msg("Single node auto-approval detected route changes")

		// Recompute on the current node so an older view cannot undo an admin write.
		_, c, err := s.updateApprovedRoutes(nv.ID(), func(n *types.Node) {
			dropWithdrawnAutoApprovals(n)
			s.approveAnnouncedRoutes(n)
		})
		if err != nil {
			log.Error().
				EmbedObject(nv).
				Err(err).
				Msg("Failed to persist auto-approved routes")

			return c, err
		}

		return c, nil
	}

	return change.Change{}, nil
}

// approveAnnouncedRoutes approves the announced routes the policy lets n
// approve, and records the ones it adds as auto-approved.
func (s *State) approveAnnouncedRoutes(n *types.Node) bool {
	approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, n.View(), n.ApprovedRoutes, n.AnnouncedRoutes())
	if !changed {
		return false
	}

	for _, route := range approved {
		if !slices.Contains(n.ApprovedRoutes, route) {
			n.AutoApprovedRoutes = append(n.AutoApprovedRoutes, route)
		}
	}

	n.ApprovedRoutes = approved

	return true
}

// dropWithdrawnAutoApprovals removes the auto-approved routes n no longer
// announces, as Tailscale SaaS does. Routes an admin approved stay.
func dropWithdrawnAutoApprovals(n *types.Node) bool {
	announced := n.AnnouncedRoutes()
	withdrawn := func(route netip.Prefix) bool {
		return slices.Contains(n.AutoApprovedRoutes, route) && !slices.Contains(announced, route)
	}

	if !slices.ContainsFunc(n.ApprovedRoutes, withdrawn) {
		return false
	}

	n.ApprovedRoutes = slices.DeleteFunc(slices.Clone(n.ApprovedRoutes), withdrawn)
	n.AutoApprovedRoutes = slices.DeleteFunc(slices.Clone(n.AutoApprovedRoutes), func(route netip.Prefix) bool {
		return !slices.Contains(announced, route)
	})

	return true
}

// GetPolicy retrieves the current policy from the database.
func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy()
}

// SetPolicyInDB stores policy data in the database.
func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data)
}

// ValidatePolicy reports whether [State.UpdatePolicy] would accept pol. It
// compiles pol against the current users and nodes on a throwaway policy
// manager; the live policy is not touched.
func (s *State) ValidatePolicy(pol []byte) error {
	users, err := s.ListAllUsers()
	if err != nil {
		return fmt.Errorf("loading users: %w", err)
	}

	nodes := s.ListNodes()

	pm, err := policy.NewPolicyManager(nil, users, nodes)
	if err != nil {
		return fmt.Errorf("creating policy manager: %w", err)
	}

	_, err = pm.SetPolicy(pol)
	if err != nil {
		return invalidPolicyError{err}
	}

	// SSH rules compile per node, so a server without nodes cannot catch
	// every case here.
	if nodes.Len() > 0 {
		_, err = pm.SSHPolicy(s.cfg.ServerURL, nodes.At(0))
		if err != nil {
			return invalidPolicyError{fmt.Errorf("verifying SSH rules: %w", err)}
		}
	}

	return nil
}

// UpdatePolicy validates, stores and installs pol. The live policy is only
// ever installed from what was stored, so a refused or unstored write leaves
// it untouched. The changes are returned alongside a reload error, as from
// [State.ReloadPolicy].
func (s *State) UpdatePolicy(pol []byte) (*types.Policy, []change.Change, error) {
	err := s.ValidatePolicy(pol)
	if err != nil {
		return nil, nil, err
	}

	// Held from store to install: on PostgreSQL a concurrent writer could
	// otherwise commit an older row after a newer one pruned the rest.
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	stored, err := s.db.SetPolicy(string(pol))
	if err != nil {
		return nil, nil, fmt.Errorf("storing policy: %w", err)
	}

	// Reload even when content is unchanged: routes manually disabled before
	// may now qualify for auto-approval, so they must be re-evaluated.
	cs, err := s.reloadPolicyLocked()

	return stored, cs, err
}

// GetNodePrimaryRoutes returns the primary routes for a node.
func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.nodeStore.PrimaryRoutesForNode(nodeID)
}

// RoutesForPeer computes the routes a peer should advertise in a viewer's
// AllowedIPs, combining primary routes (from HA election), approved exit
// routes, and via grant steering.
//
// Approved exit routes (0.0.0.0/0, ::/0) are reduced alongside subnet
// routes: a viewer gets them when its rules reach the internet.
func (s *State) RoutesForPeer(
	viewer, peer types.NodeView,
	matchers []matcher.Match,
) []netip.Prefix {
	viaResult := s.polMan.ViaRoutesForPeer(viewer, peer)
	globalPrimaries := s.nodeStore.PrimaryRoutesForNode(peer.ID())
	exitRoutes := peer.ExitRoutes()

	var reduced []netip.Prefix

	// Fast path: no via grants affect this pair.
	if len(viaResult.Include) == 0 && len(viaResult.Exclude) == 0 {
		allRoutes := slices.Concat(globalPrimaries, exitRoutes)

		reduced = policy.ReduceRoutes(viewer, allRoutes, matchers)
	} else {
		// Slow path: drop excluded routes, reduce, append via-included.
		routes := make([]netip.Prefix, 0, len(globalPrimaries)+len(exitRoutes))
		for _, p := range slices.Concat(globalPrimaries, exitRoutes) {
			if !slices.Contains(viaResult.Exclude, p) {
				routes = append(routes, p)
			}
		}

		reduced = policy.ReduceRoutes(viewer, routes, matchers)

		// Append via-included routes. The via grant IS the authorization
		// (no matcher filter needed), but HA primary election applies
		// when a regular (non-via) grant also covers the same prefix.
		//
		// Rules:
		//   - Peer is HA primary → always include
		//   - Peer is NOT primary, no regular grant → include
		//     (per-viewer via steering)
		//   - Peer is NOT primary, regular grant exists → exclude
		//     (HA primary wins)
		for _, p := range viaResult.Include {
			if slices.Contains(reduced, p) {
				continue
			}

			if slices.Contains(globalPrimaries, p) {
				reduced = append(reduced, p)
			} else if !slices.Contains(viaResult.UsePrimary, p) {
				reduced = append(reduced, p)
			}
		}
	}

	// Co-router visibility: when the viewer advertises the same prefix
	// that the peer is HA primary for, the viewer must see that route
	// regardless of matcher authorization. HA secondaries need this to
	// know which peer is primary for their shared prefix.
	if len(globalPrimaries) > 0 {
		viewerSubnets := set.SetOf(viewer.SubnetRoutes())
		if len(viewerSubnets) > 0 {
			seen := set.SetOf(reduced)
			for _, p := range globalPrimaries {
				if viewerSubnets.Contains(p) && !seen.Contains(p) {
					reduced = append(reduced, p)
					seen.Add(p)
				}
			}
		}
	}

	// Via inclusions come from the peer's routes, not the election, so
	// the serving rule is applied here, to everything the viewer gets.
	return slices.DeleteFunc(reduced, func(p netip.Prefix) bool {
		return !s.cfg.ServesRoute(p)
	})
}

// PrimaryRoutesString renders the current prefix→primary assignment
// for diagnostics.
func (s *State) PrimaryRoutesString() string {
	return s.nodeStore.PrimaryRoutesString()
}

// IsNodeHealthy reports the HA prober's view of id. Unknown nodes
// report healthy.
func (s *State) IsNodeHealthy(id types.NodeID) bool {
	return s.nodeStore.IsNodeHealthy(id)
}

// SetNodeHealth flips the runtime health bit for one node and reports
// whether peers need to recompute global or via routes, so the HA
// prober can decide whether to fan out a PolicyChange. true means
// healthy; false means unhealthy. An unhealthy mark is dropped when
// the node is no longer an HA candidate (offline or no approved
// routes) — between probe dispatch and result the node may have left
// candidacy, and the bit would just be stale. The check happens
// inside the writer goroutine so it serialises against the
// SetApprovedRoutes / Disconnect that removed candidacy. Single-node
// convenience wrapper around [State.BatchSetNodeHealth].
func (s *State) SetNodeHealth(id types.NodeID, healthy bool) bool {
	return s.BatchSetNodeHealth(map[types.NodeID]bool{id: healthy})
}

// BatchSetNodeHealth applies a set of health updates atomically: the
// election runs once after every flag has been flipped, so observers
// never see an intermediate snapshot. Returns true when the
// global primary routes or a via target's health changed, so callers
// can gate a single PolicyChange dispatch. Map value true = healthy;
// false = unhealthy (gated as in [State.SetNodeHealth]).
//
// Per-call publication would let a writer applying two flips
// back-to-back elect a node that the next snapshot demotes,
// momentarily pointing peers at the wrong primary; the batched form
// closes that window.
func (s *State) BatchSetNodeHealth(updates map[types.NodeID]bool) bool {
	if len(updates) == 0 {
		return false
	}

	prevRoutes := s.nodeStore.PrimaryRoutes()

	// Skip writes that would not change anything so an all-unchanged
	// probe cycle publishes no snapshot. healthSetter stays authoritative
	// for the candidacy and race checks under the writer.
	fns := make(map[types.NodeID]UpdateNodeFunc, len(updates))

	for id, healthy := range updates {
		if nv, ok := s.nodeStore.GetNode(id); ok && nv.Unhealthy() == !healthy {
			haHealthUpdates.WithLabelValues("unchanged").Inc()

			continue
		}

		fns[id] = healthSetter(healthy)
	}

	if len(fns) == 0 {
		return false
	}

	s.nodeStore.UpdateNodes(fns)

	if !maps.Equal(prevRoutes, s.nodeStore.PrimaryRoutes()) {
		return true
	}

	for id := range fns {
		nv, ok := s.nodeStore.GetNode(id)
		if ok && nv.Unhealthy() == !updates[id] && s.polMan.NodeIsViaTarget(nv) {
			return true
		}
	}

	return false
}

// healthSetter returns an UpdateNodeFunc that flips n.Unhealthy to
// the inverse of healthy, with the same gate as [State.SetNodeHealth]:
// an unhealthy mark only sticks when the node is still online and
// still advertises approved routes, so a node that left HA candidacy
// between probe dispatch and result does not carry a stale bit.
// Bounded labels only: every requested health update lands in exactly one
// outcome, so the series can be summed to the probe request count.
var haHealthUpdates = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: prometheusNamespace,
	Name:      "ha_health_updates_total",
	Help:      "HA health updates by outcome: unchanged and skipped, applied, or rejected because the node left candidacy.",
}, []string{"result"})

func healthSetter(healthy bool) UpdateNodeFunc {
	return func(n *types.Node) {
		if !healthy {
			if !n.Online() || len(n.AllApprovedRoutes()) == 0 {
				haHealthUpdates.WithLabelValues("rejected").Inc()

				return
			}
		}

		haHealthUpdates.WithLabelValues("changed").Inc()

		n.Unhealthy = !healthy
	}
}

// ValidateAPIKey checks if an API key is valid and active.
func (s *State) ValidateAPIKey(keyStr string) (bool, error) {
	return s.db.ValidateAPIKey(keyStr)
}

// AuthenticateAPIKey validates an API key and returns it (with its owning
// user), so callers like the v2 API can act as the key's owner.
func (s *State) AuthenticateAPIKey(keyStr string) (*types.APIKey, error) {
	return s.db.AuthenticateAPIKey(keyStr)
}

// SetAPIKeyUser sets the owning user of an API key by its database ID.
func (s *State) SetAPIKeyUser(keyID uint64, userID types.UserID) error {
	return s.db.SetAPIKeyUser(keyID, userID)
}

// CreateAPIKey generates a new API key with optional expiration.
func (s *State) CreateAPIKey(expiration *time.Time) (string, *types.APIKey, error) {
	return s.db.CreateAPIKey(expiration)
}

// GetAPIKey retrieves an API key by its prefix.
// Accepts both display format (hskey-api-{12chars}-***) and database format ({12chars}).
func (s *State) GetAPIKey(displayPrefix string) (*types.APIKey, error) {
	// Parse the display prefix to extract the database prefix
	prefix, err := hsdb.ParseAPIKeyPrefix(displayPrefix)
	if err != nil {
		return nil, err
	}

	return s.db.GetAPIKey(prefix)
}

// GetAPIKeyByID retrieves an API key by its database ID.
func (s *State) GetAPIKeyByID(id uint64) (*types.APIKey, error) {
	return s.db.GetAPIKeyByID(id)
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
// The userID parameter is now optional (can be nil) for system-created tagged keys.
func (s *State) CreatePreAuthKey(userID *types.UserID, reusable bool, ephemeral bool, expiration *time.Time, aclTags []string) (*types.PreAuthKeyNew, error) {
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

// PutNodeInStoreForTest writes a test node into the in-memory [NodeStore]
// so handlers backed by [NodeStore] lookups (e.g. [State.GetNodeByID]) can
// see it. [State.CreateNodeForTest] only saves to the database, which is
// fine for tests that exercise the DB layer directly but insufficient for
// handler tests that go through [State].
func (s *State) PutNodeInStoreForTest(node types.Node) types.NodeView {
	return s.nodeStore.PutNode(node)
}

// DeleteNodeFromStoreForTest removes a node from the in-memory [NodeStore]
// without touching the database. Used to force [State.UpdateNodeFromMapRequest]
// failures in poll-session tests while keeping the DB row intact for later restore.
func (s *State) DeleteNodeFromStoreForTest(id types.NodeID) {
	s.nodeStore.DeleteNode(id)
}

// WrapPolicyManagerForTest replaces the policy manager with wrap(current) so
// tests can fail a single method. The [NodeStore] keeps the original manager,
// so wrap must delegate to its argument. Call before any map is served.
func (s *State) WrapPolicyManagerForTest(wrap func(policy.PolicyManager) policy.PolicyManager) {
	s.polMan = wrap(s.polMan)
}

// UpdatePolicyManagerNodesForTest syncs the policy manager with the
// [NodeStore], for tests that stage nodes with [State.PutNodeInStoreForTest].
func (s *State) UpdatePolicyManagerNodesForTest() error {
	_, err := s.polMan.SetNodes(s.ListNodes())

	return err
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

// GetPreAuthKey retrieves a pre-authentication key by its secret. The caller is
// responsible for checking whether the key is usable (expired or used).
func (s *State) GetPreAuthKey(keyStr string) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKey(keyStr)
}

// GetPreAuthKeyByID retrieves a pre-authentication key by its database id.
func (s *State) GetPreAuthKeyByID(id uint64) (*types.PreAuthKey, error) {
	return s.db.GetPreAuthKeyByID(id)
}

// RevokePreAuthKey soft-revokes a pre-authentication key: it is kept and stays
// retrievable (invalid) until the collector reaps it after the retention window.
func (s *State) RevokePreAuthKey(id uint64) error {
	return s.db.RevokePreAuthKey(id)
}

// DestroyRevokedPreAuthKeysBefore hard-deletes pre-auth keys revoked before
// cutoff, returning how many were removed.
func (s *State) DestroyRevokedPreAuthKeysBefore(cutoff time.Time) (int, error) {
	return s.db.DestroyRevokedPreAuthKeysBefore(cutoff)
}

// ListPreAuthKeys returns all pre-authentication keys for a user.
func (s *State) ListPreAuthKeys() ([]types.PreAuthKey, error) {
	return s.db.ListPreAuthKeys()
}

// SetPreAuthKeyDescription sets the free-text description on a pre-auth key.
func (s *State) SetPreAuthKeyDescription(id uint64, description string) error {
	return s.db.SetPreAuthKeyDescription(id, description)
}

// ExpirePreAuthKey marks a pre-authentication key as expired.
func (s *State) ExpirePreAuthKey(id uint64) error {
	return s.db.ExpirePreAuthKey(id)
}

// DeletePreAuthKey permanently deletes a pre-authentication key.
func (s *State) DeletePreAuthKey(id uint64) error {
	return s.db.DeletePreAuthKey(id)
}

// CreateOAuthClient creates a new OAuth client-credentials client, returning the
// plaintext secret (shown once) and the stored client.
func (s *State) CreateOAuthClient(scopes, tags []string, description string, creatorUserID *uint) (string, *types.OAuthClient, error) {
	return s.db.CreateOAuthClient(scopes, tags, description, creatorUserID)
}

// AuthenticateOAuthClient validates a client secret and returns the client.
func (s *State) AuthenticateOAuthClient(secret string) (*types.OAuthClient, error) {
	return s.db.AuthenticateOAuthClient(secret)
}

// GetOAuthClientByClientID returns an OAuth client by its public client id.
func (s *State) GetOAuthClientByClientID(clientID string) (*types.OAuthClient, error) {
	return s.db.GetOAuthClientByClientID(clientID)
}

// ListOAuthClients returns every OAuth client.
func (s *State) ListOAuthClients() ([]types.OAuthClient, error) {
	return s.db.ListOAuthClients()
}

// RevokeOAuthClient deletes a client and the access tokens it issued.
func (s *State) RevokeOAuthClient(clientID string) error {
	return s.db.RevokeOAuthClient(clientID)
}

// MintAccessToken stores a new scoped access token for an OAuth client.
func (s *State) MintAccessToken(clientID string, scopes, tags []string, expiration *time.Time) (string, *types.OAuthAccessToken, error) {
	return s.db.MintAccessToken(clientID, scopes, tags, expiration)
}

// AuthenticateAccessToken validates a bearer access token and returns it with
// its granted scopes and tags.
func (s *State) AuthenticateAccessToken(token string) (*types.OAuthAccessToken, error) {
	return s.db.AuthenticateAccessToken(token)
}

// TagOwnedByTags reports whether a credential holding ownerTags may apply tag,
// per the policy's tag-to-tag ownership. Used to authorise the tags an OAuth
// access token sets on the auth keys it mints.
func (s *State) TagOwnedByTags(tag string, ownerTags []string) bool {
	return s.polMan.TagOwnedByTags(tag, ownerTags)
}

// TagExists reports whether tag is defined in the policy's tagOwners. Used to
// reject OAuth clients and auth keys carrying tags that no policy authorises,
// matching SetNodeTags.
func (s *State) TagExists(tag string) bool {
	return s.polMan.TagExists(tag)
}

// DeleteExpiredAccessTokens hard-deletes OAuth access tokens that expired before
// cutoff, returning how many were removed.
func (s *State) DeleteExpiredAccessTokens(cutoff time.Time) (int64, error) {
	return s.db.DeleteExpiredAccessTokens(cutoff)
}

// GetAuthCacheEntry retrieves a pending auth request from the cache.
func (s *State) GetAuthCacheEntry(id types.AuthID) (*types.AuthRequest, bool) {
	return s.authCache.Get(id)
}

// SetAuthCacheEntry stores a pending auth request in the cache.
func (s *State) SetAuthCacheEntry(id types.AuthID, entry *types.AuthRequest) {
	s.authCache.Add(id, entry)
}

// DeleteAuthCacheEntryForTest drops a pending auth request from the cache,
// exposed for testing so a test can reproduce a session that was lost
// (expired, evicted, or dropped on a control-plane restart) without faking an
// auth_id.
func (s *State) DeleteAuthCacheEntryForTest(id types.AuthID) {
	s.authCache.Remove(id)
}

// SetLastSSHAuth records a successful SSH check authentication
// for the given (src, dst) node pair.
func (s *State) SetLastSSHAuth(src, dst types.NodeID) {
	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	node, ok := s.nodeStore.GetNode(src)
	if !ok {
		return
	}

	s.sshCheckAuth[sshCheckPair{Src: src, Dst: dst}] = sshCheckAuthRecord{
		at: time.Now(), src: node,
	}
}

// GetLastSSHAuth returns when src last authenticated for SSH check
// to dst, while the source still has the owner that authenticated.
func (s *State) GetLastSSHAuth(src, dst types.NodeID) (time.Time, bool) {
	s.sshCheckMu.RLock()
	defer s.sshCheckMu.RUnlock()

	record, ok := s.sshCheckAuth[sshCheckPair{Src: src, Dst: dst}]
	if !ok {
		return time.Time{}, false
	}

	node, exists := s.nodeStore.GetNode(src)
	if !exists || !sameOwner(record.src, node) {
		return time.Time{}, false
	}

	return record.at, true
}

// ClearSSHCheckAuth clears all recorded SSH check auth times.
// Called when the policy changes to ensure stale auth times don't grant access.
func (s *State) ClearSSHCheckAuth() {
	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	s.sshCheckAuth = make(map[sshCheckPair]sshCheckAuthRecord)
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
	// Tags the key login was allowed to request; they replace the key's.
	Tags []string

	// Optional: Existing node for netinfo preservation
	ExistingNodeForNetinfo types.NodeView
}

// authNodeUpdateParams contains parameters for updating an existing node during auth.
type authNodeUpdateParams struct {
	// Node to update; must be valid and in [NodeStore].
	ExistingNode types.NodeView
	// Cached registration payload from the originating client request.
	RegData *types.RegistrationData
	// Pre-validated hostinfo; NetInfo preserved from ExistingNode.
	ValidHostinfo *tailcfg.Hostinfo
	// Hostname from hostinfo, or generated from keys if client omits it.
	Hostname string
	// Auth user; may differ from ExistingNode.User() on conversion.
	User *types.User
	// Overrides RegData.Expiry; ignored for tagged nodes.
	Expiry *time.Time
	// Only used when IsConvertFromTag=true.
	RegisterMethod string
	// Set true for tagged->user conversion. Affects RegisterMethod and expiry.
	IsConvertFromTag bool
}

// sameOwner reports whether a and b have one owner: the same tag set for
// tagged nodes, the same user otherwise.
func sameOwner(a, b types.NodeView) bool {
	if !a.Valid() || !b.Valid() || a.IsTagged() != b.IsTagged() {
		return false
	}

	if a.IsTagged() {
		return views.SliceEqualAnyOrder(a.Tags(), b.Tags())
	}

	return a.UserID().Valid() && b.UserID().Valid() && a.UserID().Get() == b.UserID().Get()
}

// applyAuthNodeUpdate applies common update logic for re-authenticating or converting
// an existing node. It updates the node in [NodeStore], processes RequestTags, and
// persists changes to the database. It also returns the node the NodeStore
// writer replaced.
func (s *State) applyAuthNodeUpdate(params authNodeUpdateParams) (types.NodeView, types.NodeView, error) {
	regData := params.RegData
	// Log the operation type
	if params.IsConvertFromTag {
		log.Info().
			EmbedObject(params.ExistingNode).
			Strs("old.tags", params.ExistingNode.Tags().AsSlice()).
			Msg("Converting tagged node to user-owned node")
	} else {
		log.Info().
			Object("existing", params.ExistingNode).
			Str("incoming.hostname", regData.Hostname).
			Str("incoming.machine_key", regData.MachineKey.ShortString()).
			Msg("Updating existing node registration via reauth")
	}

	// Process RequestTags during reauth (#2979).
	// Due to json:",omitempty", empty/nil from the cached Hostinfo
	// means "clear tags".
	var requestTags []string
	if regData.Hostinfo != nil {
		requestTags = regData.Hostinfo.RequestTags
	}

	oldTags := params.ExistingNode.Tags().AsSlice()

	// Validate tags BEFORE calling [NodeStore.UpdateNode] to ensure we don't modify
	// [NodeStore] if validation fails. This maintains consistency between [NodeStore]
	// and database.
	//
	// A tag-owned node carries no user and its IP is not in any tag owner's set,
	// so checking the node alone rejects every tag on re-auth (#3374). Authorise
	// against the authenticating user too: they are the one presenting the
	// credential and may own the requested tags.
	var authUser types.UserView
	if params.User != nil {
		authUser = params.User.View()
	}

	rejectedTags := s.validateRequestTagsForReauth(params.ExistingNode, authUser, requestTags)
	if len(rejectedTags) > 0 {
		return types.NodeView{}, types.NodeView{}, fmt.Errorf(
			"%w %v are invalid or not permitted",
			ErrRequestedTagsInvalidOrNotPermitted,
			rejectedTags,
		)
	}

	// Re-auth rotates the NodeKey to the client-supplied value. Enforce the
	// same 1:1 NodeKey<->MachineKey binding createAndSaveNewNode applies at
	// registration and getAndValidateNode enforces at poll time: a NodeKey
	// already bound to a different machine must not be claimed here, or a
	// re-authenticating node could rotate its key to a victim's and poison
	// the NodeStore NodeKey index (denying the victim service).
	if existing, ok := s.nodeStore.GetNodeByNodeKey(regData.NodeKey); ok &&
		existing.MachineKey() != regData.MachineKey {
		return types.NodeView{}, types.NodeView{}, ErrNodeKeyInUse
	}

	// Update existing node in [NodeStore] - validation passed, safe to mutate
	before, updatedNodeView, ok := s.nodeStore.UpdateNodeDiff(params.ExistingNode.ID(), func(node *types.Node) {
		node.NodeKey = regData.NodeKey
		node.DiscoKey = regData.DiscoKey
		node.Hostname = params.Hostname

		// Preserve NetInfo from existing node when re-registering
		node.Hostinfo = params.ValidHostinfo
		node.Hostinfo.NetInfo = preserveNetInfo(
			params.ExistingNode,
			params.ExistingNode.ID(),
			params.ValidHostinfo,
		)

		// Preserve the node's live endpoints when the register request carried
		// none. Web/OIDC relogins report endpoints via MapRequest, not register,
		// so RegData.Endpoints is empty; clearing the stored set would advertise
		// the re-keyed node with no way for peers to reach it. The first
		// MapRequest restores the live set.
		if len(regData.Endpoints) > 0 {
			node.Endpoints = regData.Endpoints
		}
		// Preserve online state during re-registration so a live node does
		// not appear offline before the client restarts its map stream.
		node.LastSeen = new(time.Now())

		// On conversion (tagged → user) we set the new register method.
		// On plain reauth we preserve the existing node.RegisterMethod;
		// the cached RegistrationData no longer carries it because the
		// producer never populated it.
		if params.IsConvertFromTag {
			node.RegisterMethod = params.RegisterMethod
		}

		// Track tagged status BEFORE processing tags
		wasTagged := node.IsTagged()

		// Process tags - may change node.Tags and node.UserID
		// Tags were pre-validated, so this will always succeed (no rejected tags)
		_ = s.processReauthTags(node, requestTags, params.User, oldTags)

		// Handle expiry AFTER tag processing, based on transition
		// This ensures expiry is correctly set/cleared based on the NEW tagged status
		isTagged := node.IsTagged()

		switch {
		case wasTagged && !isTagged:
			// Tagged → Personal: set expiry from client request
			if params.Expiry != nil {
				node.Expiry = params.Expiry
			} else {
				node.Expiry = regData.Expiry
			}
		case !wasTagged && isTagged:
			// Personal → Tagged: clear expiry; tagged nodes disable it by default.
			node.Expiry = nil
		case params.IsConvertFromTag && !isTagged:
			// Explicit conversion from tagged to user-owned: set expiry from client request
			if params.Expiry != nil {
				node.Expiry = params.Expiry
			} else {
				node.Expiry = regData.Expiry
			}
		case !isTagged:
			// Personal → Personal: update expiry from client
			if params.Expiry != nil {
				node.Expiry = params.Expiry
			} else {
				node.Expiry = regData.Expiry
			}
		case isTagged && node.IsExpired():
			// Tagged → Tagged and expired: a person re-authenticated it, so clear
			// the past expiry. A future administrative expiry has not taken
			// effect and falls through to the no-op below.
			node.Expiry = nil
		}
		// Tagged → Tagged and not expired: keep existing expiry - no action.

		// Apply default node expiry for non-tagged nodes when the
		// resolved expiry is still nil or zero (e.g., CLI registration
		// where the client did not request a specific expiry).
		needsDefaultExpiry := !node.IsTagged() &&
			(node.Expiry == nil || node.Expiry.IsZero()) &&
			s.cfg.Node.Expiry > 0
		if needsDefaultExpiry {
			exp := time.Now().Add(s.cfg.Node.Expiry)
			node.Expiry = &exp
		}

		// Route approvals stay on an owner change, as on Tailscale SaaS;
		// autoApprovers only add.
	})

	if !ok {
		return types.NodeView{}, types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, params.ExistingNode.ID())
	}

	// Persist to database.
	// Explicitly select all node columns so GORM includes nil/zero-value fields
	// (see nodeUpdateColumns comment).
	//
	// AuthKeyID is excluded from nodeUpdateColumns (#2862: never persist a
	// possibly-deleted key's stale reference on the shared update path). But
	// when a re-auth untags a node it clears AuthKeyID to nil (above), and that
	// must persist or the node reloads as tagged/ephemeral after a restart and
	// is garbage-collected. Writing NULL can never cause an FK error, so include
	// the column only in that clearing case; the other transitions keep the
	// #2862-safe column set untouched.
	updateColumns := nodeUpdateColumns
	if !updatedNodeView.AuthKeyID().Valid() {
		updateColumns = append(slices.Clone(nodeUpdateColumns), "AuthKeyID")
	}

	_, err := s.persistNodeWith(updatedNodeView, updateColumns, nil)
	if err != nil {
		return types.NodeView{}, types.NodeView{}, err
	}

	// Log completion
	if params.IsConvertFromTag {
		log.Trace().
			EmbedObject(updatedNodeView).
			Msg("Tagged node converted to user-owned")
	} else {
		log.Trace().
			EmbedObject(updatedNodeView).
			Msg("Node re-authorized")
	}

	return updatedNodeView, before, nil
}

// createAndSaveNewNode creates a new node, allocates IPs, saves to DB, and adds to [NodeStore].
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

	// Enforce NodeKey uniqueness across machines. NodeKeys are public
	// (peers learn them from the netmap), so an authenticated party could
	// otherwise register a node carrying a victim's NodeKey, poisoning the
	// NodeStore NodeKey index so the victim's MapRequest resolves to the
	// wrong node and is rejected by getAndValidateNode's MachineKey check
	// (a DoS). createAndSaveNewNode only runs for a machine that has no
	// existing node, so any current holder of this NodeKey is a different
	// machine; mirror the 1:1 binding getAndValidateNode enforces at poll
	// time and reject before allocating any resources.
	if existing, ok := s.nodeStore.GetNodeByNodeKey(params.NodeKey); ok &&
		existing.MachineKey() != params.MachineKey {
		return types.NodeView{}, ErrNodeKeyInUse
	}

	// Prepare the node for registration
	nodeToRegister := types.Node{
		Hostname:       params.Hostname,
		MachineKey:     params.MachineKey,
		NodeKey:        params.NodeKey,
		DiscoKey:       params.DiscoKey,
		Hostinfo:       params.Hostinfo,
		Endpoints:      params.Endpoints,
		LastSeen:       new(time.Now()),
		IsOnline:       new(false), // Explicitly offline until [State.Connect] is called
		RegisterMethod: params.RegisterMethod,
		Expiry:         params.Expiry,
	}

	// Assign ownership based on PreAuthKey
	if params.PreAuthKey != nil {
		tags := params.PreAuthKey.Tags
		if params.Tags != nil {
			tags = params.Tags
		}

		if len(tags) > 0 {
			// Tagged nodes are owned by their tags, not a user.
			// UserID is intentionally left nil.
			nodeToRegister.Tags = tags

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil
		} else {
			// USER-OWNED NODE
			nodeToRegister.UserID = &params.PreAuthKey.User.ID
			nodeToRegister.User = params.PreAuthKey.User
			nodeToRegister.Tags = nil
		}

		nodeToRegister.AuthKey = params.PreAuthKey.AsCredential()
		nodeToRegister.AuthKeyID = &params.PreAuthKey.ID
	} else {
		// Non-PreAuthKey registration (OIDC, CLI) - always user-owned
		nodeToRegister.UserID = &params.User.ID
		nodeToRegister.User = &params.User
		nodeToRegister.Tags = nil
	}

	// Process RequestTags (from tailscale up --advertise-tags) ONLY for non-PreAuthKey registrations.
	// Validate early before IP allocation to avoid resource leaks on failure.
	if params.PreAuthKey == nil && params.Hostinfo != nil && len(params.Hostinfo.RequestTags) > 0 {
		// Validate all tags before applying - reject if any tag is not permitted
		rejectedTags := s.validateRequestTags(nodeToRegister.View(), params.Hostinfo.RequestTags)
		if len(rejectedTags) > 0 {
			return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, rejectedTags)
		}

		// All tags are approved - apply them
		approvedTags := params.Hostinfo.RequestTags
		if len(approvedTags) > 0 {
			// Sort a copy: approvedTags is the node's reported Hostinfo.
			nodeToRegister.Tags = slices.Compact(slices.Sorted(slices.Values(approvedTags)))

			// Node is now tagged, so clear user ownership.
			// Tagged nodes are owned by their tags, not a user.
			nodeToRegister.UserID = nil
			nodeToRegister.User = nil

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil

			log.Info().
				Str(zf.NodeName, nodeToRegister.Hostname).
				Strs(zf.NodeTags, nodeToRegister.Tags).
				Msg("approved advertise-tags during registration")
		}
	}

	// Apply default node expiry for non-tagged nodes when the client
	// did not request a specific expiry.
	// Tagged nodes are exempt — they never expire.
	needsDefaultExpiry := !nodeToRegister.IsTagged() &&
		(nodeToRegister.Expiry == nil || nodeToRegister.Expiry.IsZero()) &&
		s.cfg.Node.Expiry > 0
	if needsDefaultExpiry {
		exp := time.Now().Add(s.cfg.Node.Expiry)
		nodeToRegister.Expiry = &exp
	}

	// Validate before saving
	err := validateNodeOwnership(&nodeToRegister)
	if err != nil {
		return types.NodeView{}, err
	}

	// Allocate new IPs
	ipv4, ipv6, err := s.ipAlloc.Next()
	if err != nil {
		return types.NodeView{}, fmt.Errorf("allocating IPs: %w", err)
	}

	nodeToRegister.IPv4 = ipv4
	nodeToRegister.IPv6 = ipv6

	// Seed GivenName from the sanitised raw hostname. [NodeStore.PutNode]
	// bumps on collision and falls back to "node" if the sanitised
	// result is empty (pure non-ASCII / punctuation input).
	if nodeToRegister.GivenName == "" {
		nodeToRegister.GivenName = dnsname.SanitizeHostname(nodeToRegister.Hostname)
	}

	// New node - database first to get ID, then [NodeStore]
	savedNode, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		// Omit the AuthKey association: only auth_key_id is persisted here, the
		// credential row is owned by the credential CRUD and must not be
		// upserted from this node's (possibly stale) in-memory copy (#2862).
		err := tx.Omit("AuthKey").Save(&nodeToRegister).Error
		if err != nil {
			return nil, fmt.Errorf("saving node: %w", err)
		}

		if params.PreAuthKey != nil && !params.PreAuthKey.Reusable {
			err := hsdb.UsePreAuthKey(tx, params.PreAuthKey)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}

			// UsePreAuthKey marked the key used; refresh the node's in-memory
			// AuthKey so the NodeStore copy matches the database.
			nodeToRegister.AuthKey = params.PreAuthKey.AsCredential()
		}

		return &nodeToRegister, nil
	})
	if err != nil {
		return types.NodeView{}, err
	}

	// Add to [NodeStore] after database creates the ID
	return s.nodeStore.PutNode(*savedNode), nil
}

// validateRequestTags validates that the requested tags are permitted for the node.
// This should be called BEFORE [NodeStore.UpdateNode] to ensure we don't modify [NodeStore]
// if validation fails. Returns the list of rejected tags (empty if all valid).
func (s *State) validateRequestTags(node types.NodeView, requestTags []string) []string {
	// Empty tags = clear tags, always permitted
	if len(requestTags) == 0 {
		return nil
	}

	var rejectedTags []string

	for _, tag := range requestTags {
		if !s.polMan.NodeCanHaveTag(node, tag) {
			rejectedTags = append(rejectedTags, tag)
		}
	}

	return rejectedTags
}

// validateRequestTagsForReauth authorises re-auth request tags against the
// existing node OR the authenticating user. A tag-owned node (#3374) has no
// user and its IP is in no owner set, so NodeCanHaveTag alone rejects every
// tag; the authenticating user who owns the tags must also be consulted.
// Tags neither the node nor the user owns are still rejected, so this
// authorises the user, it does not skip authorisation.
func (s *State) validateRequestTagsForReauth(node types.NodeView, authUser types.UserView, requestTags []string) []string {
	if len(requestTags) == 0 {
		return nil
	}

	var rejectedTags []string

	for _, tag := range requestTags {
		if s.polMan.NodeCanHaveTag(node, tag) {
			continue
		}

		if authUser.Valid() && s.polMan.UserCanHaveTag(authUser, tag) {
			continue
		}

		rejectedTags = append(rejectedTags, tag)
	}

	return rejectedTags
}

// processReauthTags handles tag changes during node re-authentication.
// It processes RequestTags from the client and updates node tags accordingly.
// Returns rejected tags (if any) for post-validation error handling.
func (s *State) processReauthTags(
	node *types.Node,
	requestTags []string,
	user *types.User,
	oldTags []string,
) []string {
	wasAuthKeyTagged := node.AuthKey != nil && node.AuthKey.IsTagged()

	logEvent := log.Debug().
		Uint64(zf.NodeID, uint64(node.ID)).
		Str(zf.NodeName, node.Hostname).
		Strs(zf.RequestTags, requestTags).
		Strs(zf.CurrentTags, node.Tags).
		Bool(zf.IsTagged, node.IsTagged()).
		Bool(zf.WasAuthKeyTagged, wasAuthKeyTagged)
	logEvent.Msg("processing RequestTags during reauth")

	// Empty RequestTags means untag node (transition to user-owned)
	if len(requestTags) == 0 {
		if node.IsTagged() {
			log.Info().
				Uint64(zf.NodeID, uint64(node.ID)).
				Str(zf.NodeName, node.Hostname).
				Strs(zf.RemovedTags, node.Tags).
				Str(zf.UserName, user.Name).
				Bool(zf.WasAuthKeyTagged, wasAuthKeyTagged).
				Msg("Reauth: removing all tags, returning node ownership to user")

			node.Tags = []string{}
			node.UserID = &user.ID
			node.User = user

			// The node is no longer tagged, so it must not keep a reference to
			// the tagged auth key. Leaving AuthKey set means a node created by a
			// tagged+ephemeral key stays IsEphemeral() after converting to
			// user-owned and is garbage-collected on its next disconnect,
			// silently deleting the user's just-claimed device. Clearing the
			// reference is persisted via the AuthKeyID column added to this
			// path's write below.
			node.AuthKey = nil
			node.AuthKeyID = nil
		}

		return nil
	}

	// Non-empty RequestTags: validate and apply. Authorise each tag against the
	// node OR the authenticating user, matching the pre-check in
	// validateRequestTagsForReauth. Without the user half, a tag-owned node
	// (#3374) has every tag rejected here even after the pre-check passed, so
	// this returns the tags as rejected and the re-advertised tag is silently
	// dropped despite a success response.
	authUser := user.View()

	var approvedTags, rejectedTags []string

	for _, tag := range requestTags {
		if s.polMan.NodeCanHaveTag(node.View(), tag) ||
			(authUser.Valid() && s.polMan.UserCanHaveTag(authUser, tag)) {
			approvedTags = append(approvedTags, tag)
		} else {
			rejectedTags = append(rejectedTags, tag)
		}
	}

	if len(rejectedTags) > 0 {
		log.Warn().
			Uint64(zf.NodeID, uint64(node.ID)).
			Str(zf.NodeName, node.Hostname).
			Strs(zf.RejectedTags, rejectedTags).
			Msg("Reauth: requested tags are not permitted")

		return rejectedTags
	}

	if len(approvedTags) > 0 {
		slices.Sort(approvedTags)
		approvedTags = slices.Compact(approvedTags)

		wasTagged := node.IsTagged()
		node.Tags = approvedTags

		// Tagged nodes are owned by their tags, not a user.
		node.UserID = nil
		node.User = nil

		if !wasTagged {
			log.Info().
				Uint64(zf.NodeID, uint64(node.ID)).
				Str(zf.NodeName, node.Hostname).
				Strs(zf.NewTags, approvedTags).
				Str(zf.OldUser, user.Name).
				Msg("Reauth: applying tags, transferring node to tagged-devices")
		} else {
			log.Info().
				Uint64(zf.NodeID, uint64(node.ID)).
				Str(zf.NodeName, node.Hostname).
				Strs(zf.OldTags, oldTags).
				Strs(zf.NewTags, approvedTags).
				Msg("Reauth: updating tags on already-tagged node")
		}
	}

	return nil
}

// HandleNodeFromAuthPath handles node registration through authentication flow (like OIDC).
func (s *State) HandleNodeFromAuthPath(
	authID types.AuthID,
	userID types.UserID,
	expiry *time.Time,
	registrationMethod string,
) (types.NodeView, change.Change, error) {
	// An OIDC token's expiry arrives here without passing handleRegister.
	if expiry != nil {
		utc, err := types.ValidateExpiry(*expiry)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}

		expiry = &utc
	}

	// Read before any NodeStore write below; see updatePolicyManagerNodes.
	genBefore := s.polMan.NodesGeneration()

	// Get the registration entry from cache
	regEntry, ok := s.GetAuthCacheEntry(authID)
	if !ok {
		return types.NodeView{}, s.policyChangeSince(genBefore), hsdb.ErrNodeNotFoundRegistrationCache
	}

	// Get the user
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return types.NodeView{}, s.policyChangeSince(genBefore), fmt.Errorf("finding user: %w", err)
	}

	regData := regEntry.RegistrationData()

	// Hostname was already validated/normalised at producer time. Build
	// the initial Hostinfo from the cached client-supplied Hostinfo (or
	// an empty stub if the client did not send one).
	hostname := regData.Hostname

	hostinfo := &tailcfg.Hostinfo{}
	if regData.Hostinfo != nil {
		hostinfo = regData.Hostinfo.Clone()
	}

	hostinfo.Hostname = hostname

	// Lookup existing nodes
	machineKey := regData.MachineKey

	// Serialise registration for this machine so concurrent auth callbacks
	// resolve to a single node rather than racing the find-then-create section.
	defer s.lockRegistration(machineKey)()

	all := s.nodeStore.GetNodesByMachineKeyAllUsers(machineKey)

	// Named conditions - describe WHAT we found, not HOW we check it.
	existingNode, nodeExists := loginNode(all, types.UserID(user.ID))

	var existingNodeOtherUser types.NodeView

	existingNodeOwnedByOtherUser := false

	for uid, n := range all {
		if uid != 0 && uid != types.UserID(user.ID) && !n.IsTagged() {
			existingNodeOtherUser = n
			existingNodeOwnedByOtherUser = true
		}
	}

	// Create logger with common fields for all auth operations
	logger := log.With().
		Str(zf.RegistrationID, authID.String()).
		Str(zf.UserName, user.Name).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.Method, registrationMethod).
		Logger()

	// Common params for update operations
	updateParams := authNodeUpdateParams{
		RegData:        regData,
		ValidHostinfo:  hostinfo,
		Hostname:       hostname,
		User:           user,
		Expiry:         expiry,
		RegisterMethod: registrationMethod,
	}

	var (
		finalNode types.NodeView
		before    types.NodeView
		keysOnly  bool
	)

	if nodeExists && !existingNode.IsTagged() {
		updateParams.ExistingNode = existingNode

		finalNode, before, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), err
		}

		keysOnly = onlyKeysChanged(before, finalNode, time.Now())
	} else if nodeExists {
		updateParams.ExistingNode = existingNode
		updateParams.IsConvertFromTag = true

		finalNode, before, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), err
		}
	} else if existingNodeOwnedByOtherUser {
		oldUser := existingNodeOtherUser.User()

		oldUserName := ""
		if oldUser.Valid() {
			oldUserName = oldUser.Name()
		}

		logger.Info().
			Str(zf.ExistingNodeName, existingNodeOtherUser.Hostname()).
			Uint64(zf.ExistingNodeID, existingNodeOtherUser.ID().Uint64()).
			Str(zf.OldUser, oldUserName).
			Msg("Creating new node for different user (same machine key exists for another user)")

		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regData, hostname, hostinfo,
			expiry, registrationMethod, existingNodeOtherUser,
		)
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), err
		}
	} else {
		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regData, hostname, hostinfo,
			expiry, registrationMethod, types.NodeView{},
		)
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), err
		}
	}

	// Signal to waiting clients
	regEntry.FinishAuth(types.AuthVerdict{Node: finalNode})

	// Remove from registration cache
	s.authCache.Remove(authID)

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()).Merge(s.policyChangeSince(genBefore)), fmt.Errorf("updating policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes(genBefore)
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()).Merge(nodesChange), fmt.Errorf("updating policy manager nodes: %w", err)
	}

	policyChanged := !usersChange.IsEmpty() || !nodesChange.IsEmpty()

	// keysOnly is set only for a same-user relogin; a tag->user conversion is
	// excluded, as it changes the peer's User — a structural change peers must
	// see in full, not a key-rotation patch.
	return s.approveRoutesAfterRegistration(before, finalNode, reauthChange(finalNode, keysOnly, policyChanged))
}

func sortedPrefixes(p []netip.Prefix) []netip.Prefix {
	return slices.SortedFunc(slices.Values(p), netip.Prefix.Compare)
}

// createNewNodeFromAuth creates a new node during auth callback.
// This is used for both new registrations and when a machine already has a node
// for a different user.
func (s *State) createNewNodeFromAuth(
	logger zerolog.Logger,
	user *types.User,
	regData *types.RegistrationData,
	hostname string,
	validHostinfo *tailcfg.Hostinfo,
	expiry *time.Time,
	registrationMethod string,
	existingNodeForNetinfo types.NodeView,
) (types.NodeView, error) {
	logger.Debug().
		Interface("expiry", expiry).
		Msg("Registering new node from auth callback")

	return s.createAndSaveNewNode(newNodeParams{
		User:                   *user,
		MachineKey:             regData.MachineKey,
		NodeKey:                regData.NodeKey,
		DiscoKey:               regData.DiscoKey,
		Hostname:               hostname,
		Hostinfo:               validHostinfo,
		Endpoints:              regData.Endpoints,
		Expiry:                 cmp.Or(expiry, regData.Expiry),
		RegisterMethod:         registrationMethod,
		ExistingNodeForNetinfo: existingNodeForNetinfo,
	})
}

// HandleNodeFromPreAuthKey handles node registration using a pre-authentication key.
// findExistingNodeForPAK looks up an existing node by machine key,
// matching the PAK's ownership. A key with a user finds that user's node,
// else the machine's tagged node; a tags-only key checks UserID(0) since
// tagged nodes have no owning user.
func (s *State) findExistingNodeForPAK(
	machineKey key.MachinePublic,
	pak *types.PreAuthKey,
	nodeKey key.NodePublic,
) (types.NodeView, bool, error) {
	all := s.nodeStore.GetNodesByMachineKeyAllUsers(machineKey)

	if pak.User != nil {
		node, ok := all[types.UserID(pak.User.ID)]
		if !ok {
			// The machine's tagged node, when the key speaks for it. Any other
			// key under its own node key is the device restarting (#3312);
			// pakReregister lets that key only wake it.
			node, ok = all[0]
			ok = ok && node.IsTagged() && (pak.CanReauthenticate(node) || node.NodeKey() == nodeKey)
		}

		return node, ok, nil
	}

	// A tagged key re-registers the same machine regardless of how it is
	// currently owned. An existing tagged node is a plain re-registration. A
	// single user-owned node is converted to tagged in place (handled by the
	// caller). More than one user-owned node is ambiguous - we cannot know
	// which to convert - so reject rather than convert an arbitrary one and
	// orphan the rest.
	if pak.IsTagged() {
		if node, ok := all[0]; ok && node.IsTagged() {
			return node, true, nil
		}

		var userOwned types.NodeView

		count := 0

		for uid, node := range all {
			if uid != 0 && !node.IsTagged() {
				userOwned = node
				count++
			}
		}

		switch count {
		case 0:
			return types.NodeView{}, false, nil
		case 1:
			return userOwned, true, nil
		default:
			return types.NodeView{}, false, ErrAmbiguousNodeOwnership
		}
	}

	return types.NodeView{}, false, nil
}

// LoginNode returns the node that a login by userID on machineKey
// re-authenticates. False means the login adds a new device.
func (s *State) LoginNode(machineKey key.MachinePublic, userID types.UserID) (types.NodeView, bool) {
	return loginNode(s.nodeStore.GetNodesByMachineKeyAllUsers(machineKey), userID)
}

// loginNode picks, from a machine's nodes, the one a login by userID
// re-authenticates: the user's own node, else the machine's tagged node when
// the user can claim it. A tagged node that joined by login records no former
// owner, so any login re-authenticates it, as before; the tags the login asks
// for decide whether it stays tagged. Otherwise another user's login on a
// tagged machine adds a device for that user beside it, as on Tailscale SaaS.
func loginNode(all map[types.UserID]types.NodeView, userID types.UserID) (types.NodeView, bool) {
	if node, ok := all[userID]; ok {
		return node, true
	}

	if node, ok := all[0]; ok && node.IsTagged() &&
		(node.ClaimableBy(userID) || node.RegisterMethod() != util.RegisterMethodAuthKey) {
		return node, true
	}

	return types.NodeView{}, false
}

// pakSkipsValidation reports whether re-registering n with pak may skip key
// validation at now. The machine key proves identity and a pre-auth key only
// authorises the initial join, so a plain restart (container "tailscale up
// --authkey=KEY") re-presents a spent key legitimately. Anything that
// authorises something new must present a valid key:
//   - a node key rotation;
//   - an expired node. Tagged nodes expire at logout, by an administrative
//     expiry, or keep the expiry they had when an admin tagged them;
//   - a tagged key converting a user-owned node to tagged;
//   - a tagged key other than the one the node last authed with, which retags
//     it.
//
// It is a pure function of the node so the NodeStore writer can decide again
// on the node it actually replaces.
func pakSkipsValidation(n types.NodeView, pak *types.PreAuthKey, nodeKey key.NodePublic, now time.Time) bool {
	if !n.Valid() {
		return false
	}

	isNodeKeyRotation := n.NodeKey() != nodeKey
	isExpired := n.IsExpiredAt(now)
	isOwnershipConversion := pak.ConvertsNodeToTagged(n)
	isRetag := pak.RetagsNode(n)
	ownershipMatches := n.IsTagged() ||
		(pak.User != nil && n.UserID().Valid() && n.UserID().Get() == pak.User.ID)

	return ownershipMatches && !isNodeKeyRotation && !isExpired &&
		!isOwnershipConversion && !isRetag
}

// pakReregister distinguishes re-authentication with a valid key from a
// wake-up that only refreshes a live node's reported metadata.
func pakReregister(n types.NodeView, pak *types.PreAuthKey, nodeKey key.NodePublic, now time.Time) (bool, error) {
	// As on Tailscale SaaS, an expired node is asked for a new node key before
	// any key is judged.
	if n.NodeKey() == nodeKey && n.IsExpiredAt(now) {
		return false, ErrNodeKeyExpired
	}

	err := pak.ValidAt(now)
	if err == nil {
		if pak.CanReauthenticate(n) {
			return true, nil
		}

		err = types.PAKError("authkey cannot re-authenticate this node")
	}

	if pakSkipsValidation(n, pak, nodeKey, now) {
		return false, nil
	}

	return false, err
}

//nolint:gocyclo // sequential validation/update/create paths with security-sensitive ordering
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (types.NodeView, change.Change, error) {
	// Serialise registration for this machine so concurrent restarts resolve
	// to a single node rather than racing the find-then-create section.
	defer s.lockRegistration(machineKey)()

	// Read before any NodeStore write below; see updatePolicyManagerNodes.
	genBefore := s.polMan.NodesGeneration()

	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return types.NodeView{}, s.policyChangeSince(genBefore), err
	}

	if !pak.Reusable && !pak.Used {
		mu := &s.singleUseKeyLocks[pak.ID%uint64(len(s.singleUseKeyLocks))]
		mu.Lock()
		defer mu.Unlock()

		// A different machine may have consumed the key while we waited.
		pak, err = s.GetPreAuthKeyByID(pak.ID)
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), err
		}
	}

	// Advertising a subset of the key's tags is redundant, not an escalation,
	// and the tailscale client's OAuth authkey flow always does it. Other
	// requested tags replace the key's when a tagged key's tags own each one,
	// or a user's key's user owns it directly, as on Tailscale SaaS; otherwise
	// they are refused, ahead of the key's own error, so new nodes and
	// re-registrations are held to the same rule.
	var (
		requestedTags []string
		tagsErr       error
	)

	if regReq.Hostinfo != nil && slices.ContainsFunc(regReq.Hostinfo.RequestTags, func(tag string) bool {
		return !slices.Contains(pak.Tags, tag)
	}) {
		var refused []string

		for _, tag := range regReq.Hostinfo.RequestTags {
			owned := s.polMan.TagOwnedByTags(tag, pak.Tags) ||
				(!pak.IsTagged() && pak.User != nil && s.polMan.UserCanHaveTag(pak.User.View(), tag))
			if !owned {
				refused = append(refused, tag)
			}
		}

		if len(refused) > 0 {
			tagsErr = fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, refused)
		} else {
			// Sort a copy: RequestTags is the node's reported Hostinfo.
			requestedTags = slices.Compact(slices.Sorted(slices.Values(regReq.Hostinfo.RequestTags)))
		}
	}

	existingNodeSameUser, existsSameUser, err := s.findExistingNodeForPAK(machineKey, pak, regReq.NodeKey)
	if err != nil {
		return types.NodeView{}, s.policyChangeSince(genBefore), err
	}

	// This decision is only an early reject that keeps a key error ahead of
	// ErrNodeKeyInUse. An in-place re-registration decides again in the
	// NodeStore writer, on the node it replaces; see reregisterNodeWithPAK.
	reauth := true
	if existsSameUser {
		reauth, err = pakReregister(existingNodeSameUser, pak, regReq.NodeKey, time.Now())
	} else {
		err = pak.Validate()
	}

	// A wake-up writes no tags, so the tags it asks for are not refused.
	if tagsErr != nil && !errors.Is(err, ErrNodeKeyExpired) && (reauth || err != nil) {
		return types.NodeView{}, s.policyChangeSince(genBefore), tagsErr
	}

	if err != nil {
		return types.NodeView{}, s.policyChangeSince(genBefore), err
	}

	// Preserve the raw hostname as reported by the client. Sanitisation
	// for the DNS label lives on node.GivenName, not on node.Hostname;
	// see HOSTNAME.md.
	var hostname string
	if regReq.Hostinfo != nil {
		hostname = regReq.Hostinfo.Hostname
	}

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regReq.Hostinfo.Clone(), &tailcfg.Hostinfo{})

	log.Debug().
		Caller().
		Str(zf.NodeName, hostname).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, regReq.NodeKey.ShortString()).
		Str(zf.UserName, pak.Username()).
		Msg("Registering node with pre-auth key")

	var (
		finalNode types.NodeView
		keysOnly  bool
	)

	var before types.NodeView

	// If this node exists for this user, update the node in place. For a
	// tags-only key (pak.User == nil) this is true when the machine already has
	// a tagged node (findExistingNodeForPAK matches it under UserID 0); for a
	// user-owned key it is true when the same user already has the node.
	if existsSameUser && existingNodeSameUser.Valid() {
		finalNode, before, err = s.reregisterNodeWithPAK(existingNodeSameUser, pak, requestedTags, regReq, machineKey, hostname, validHostinfo)
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), err
		}

		keysOnly = onlyKeysChanged(before, finalNode, time.Now())
	} else {
		// Node does not exist for this user with this machine key.
		// For a user-owned key, check whether the machine key is already held
		// by a node belonging to a different user (tags-only keys skip this;
		// tagged nodes have no owning user). Any such node yields the same
		// outcome - create a new node for the new user, do not transfer - so a
		// single representative is enough.
		var differentUserNode types.NodeView

		belongsToDifferentUser := false

		if pak.User != nil {
			for uid, node := range s.nodeStore.GetNodesByMachineKeyAllUsers(machineKey) {
				if uid != 0 && !node.IsTagged() && uid != types.UserID(pak.User.ID) {
					differentUserNode = node
					belongsToDifferentUser = true
				}
			}
		}

		if belongsToDifferentUser {
			// Node exists but belongs to a different user.
			// Create a new node for the new user (do not transfer).
			oldUser := differentUserNode.User()

			oldUserName := ""
			if oldUser.Valid() {
				oldUserName = oldUser.Name()
			}

			log.Info().
				Caller().
				Str(zf.ExistingNodeName, differentUserNode.Hostname()).
				Uint64(zf.ExistingNodeID, differentUserNode.ID().Uint64()).
				Str(zf.MachineKey, machineKey.ShortString()).
				Str(zf.OldUser, oldUserName).
				Str(zf.NewUser, pak.Username()).
				Msg("Creating new node for different user (same machine key exists for another user)")
		}

		// This is a new node - create it
		// For user-owned keys: create for the user
		// For tags-only keys: create as tagged node (createAndSaveNewNode handles this via PreAuthKey)

		// Create and save new node
		// Note: For tags-only keys, User is empty but createAndSaveNewNode uses PreAuthKey for ownership
		var pakUser types.User
		if pak.User != nil {
			pakUser = *pak.User
		}

		// Only pass the client-requested expiry when it is actually set.
		// A pointer to a zero time.Time gets persisted as "0001-01-01 00:00:00"
		// rather than NULL, which breaks downstream consumers that distinguish
		// "no expiry" from "expires at year 1".
		var reqExpiry *time.Time
		if !regReq.Expiry.IsZero() {
			reqExpiry = &regReq.Expiry
		}

		var err error

		finalNode, err = s.createAndSaveNewNode(newNodeParams{
			User:                   pakUser,
			MachineKey:             machineKey,
			NodeKey:                regReq.NodeKey,
			DiscoKey:               key.DiscoPublic{}, // DiscoKey not available in RegisterRequest
			Hostname:               hostname,
			Hostinfo:               validHostinfo,
			Endpoints:              nil, // Endpoints not available in RegisterRequest
			Expiry:                 reqExpiry,
			RegisterMethod:         util.RegisterMethodAuthKey,
			PreAuthKey:             pak,
			Tags:                   requestedTags,
			ExistingNodeForNetinfo: differentUserNode,
		})
		if err != nil {
			return types.NodeView{}, s.policyChangeSince(genBefore), fmt.Errorf("creating new node: %w", err)
		}
	}

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()).Merge(s.policyChangeSince(genBefore)), fmt.Errorf("updating policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes(genBefore)
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()).Merge(nodesChange), fmt.Errorf("updating policy manager nodes: %w", err)
	}

	policyChanged := !usersChange.IsEmpty() || !nodesChange.IsEmpty()

	return s.approveRoutesAfterRegistration(before, finalNode, reauthChange(finalNode, keysOnly, policyChanged))
}

// approveRoutesAfterRegistration runs route auto-approval after a
// registration whose NodeStore writer replaced before with node, merging its
// change into c. As on Tailscale SaaS it runs for a new node, a new node key
// or a change to the announced routes; a login that changes neither approves
// nothing. before is what the writer replaced, not the caller's lookup, so an
// announcement and an admin revoke landing in between do not count as a
// change. It waits for the registration: the policy manager must know the
// node's owner first.
func (s *State) approveRoutesAfterRegistration(
	before, node types.NodeView,
	c change.Change,
) (types.NodeView, change.Change, error) {
	if before.Valid() && before.NodeKey() == node.NodeKey() &&
		slices.Equal(sortedPrefixes(before.AnnouncedRoutes()), sortedPrefixes(node.AnnouncedRoutes())) {
		return node, c, nil
	}

	routesChange, err := s.AutoApproveRoutes(node)
	c = c.Merge(routesChange)

	if err != nil {
		return node, c, fmt.Errorf("auto approving routes: %w", err)
	}

	return node, c, nil
}

// reregisterNodeWithPAK updates an existing node in place for a pre-auth key
// re-registration: NodeStore first, then the database.
//
// The caller's lookup view goes stale before the NodeStore writer runs: an
// admin or logout expiry, a node key reconcile, a retag or a deletion can land
// in between, and the key or the node can expire. So the writer decides
// whether the key must be valid on the node it replaces, at its own clock, and
// leaves the node untouched when it is not. existingNodeSameUser is used only
// for its ID and for logging. It also returns the node the writer replaced.
func (s *State) reregisterNodeWithPAK(
	existingNodeSameUser types.NodeView,
	pak *types.PreAuthKey,
	requestedTags []string,
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	hostname string,
	validHostinfo *tailcfg.Hostinfo,
) (types.NodeView, types.NodeView, error) {
	log.Trace().
		Caller().
		Str(zf.NodeName, existingNodeSameUser.Hostname()).
		Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, existingNodeSameUser.NodeKey().ShortString()).
		Str(zf.UserName, pak.Username()).
		Msg("Node re-registering with existing machine key and user, updating in place")

	// Re-registration rotates the NodeKey to the client-supplied value.
	// Enforce the same 1:1 NodeKey<->MachineKey binding the auth path
	// (applyAuthNodeUpdate) and poll-time validation enforce: a NodeKey
	// already bound to a different machine must not be claimed here, or a
	// re-registering node could rotate its key to a victim's and poison the
	// NodeStore NodeKey index, denying the victim service.
	if existing, ok := s.nodeStore.GetNodeByNodeKey(regReq.NodeKey); ok &&
		existing.MachineKey() != machineKey {
		return types.NodeView{}, types.NodeView{}, ErrNodeKeyInUse
	}

	// prior is the node the writer replaced: the NetInfo source and the
	// rollback target if the database write below fails. written is what this
	// write left; the view after the batch can hold later writes.
	var (
		prior   *types.Node
		written *types.Node
		authErr error
		reauth  bool
	)

	// Update existing node - NodeStore first, then database
	before, updatedNodeView, ok := s.nodeStore.UpdateNodeDiff(existingNodeSameUser.ID(), func(node *types.Node) {
		// One clock read, so the whole mutation is decided at one instant.
		now := time.Now()

		prior = node.Clone()
		defer func() { written = node.Clone() }()

		reauth, authErr = pakReregister(node.View(), pak, regReq.NodeKey, now)
		if authErr != nil {
			return
		}

		node.Hostname = hostname

		// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
		// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

		// Preserve NetInfo from existing node when re-registering
		node.Hostinfo = validHostinfo
		node.Hostinfo.NetInfo = preserveNetInfo(prior.View(), prior.ID, validHostinfo)

		// Preserve online state during re-registration so a live node does
		// not appear offline before the client restarts its map stream.
		node.LastSeen = new(now)

		if !reauth {
			return
		}

		node.NodeKey = regReq.NodeKey

		node.RegisterMethod = util.RegisterMethodAuthKey

		// Tags from a PreAuthKey are applied on initial registration and
		// re-applied whenever a *different* key is presented on
		// re-registration: re-keying is Tailscale's documented way to change
		// an auth-key device's tags, replacing its existing ones. Presenting
		// the SAME key again (a container restart) preserves the node's
		// current tags and any admin override. A tagged key presented for a
		// user-owned node also converts it, dropping user ownership.
		// See https://tailscale.com/kb/1068/tags#apply-a-tag-to-a-device-with-the-cli.
		//
		// node.AuthKeyID still holds the prior key's ID here (it is reassigned
		// below), and SetNodeTags leaves AuthKeyID intact, so an admin retag
		// cannot masquerade as a new key.
		//
		// Tags the login was allowed to request replace the node's instead.
		tags := pak.Tags
		retag := pak.ConvertsNodeToTagged(node.View()) || pak.RetagsNode(node.View())

		if requestedTags != nil {
			tags, retag = requestedTags, !slices.Equal(node.Tags, requestedTags)
		}

		if retag {
			wasUserOwned := !node.IsTagged()

			node.Tags = tags
			node.UserID = nil
			node.User = nil

			// Converting a user-owned node to tagged drops the user's key
			// expiry (tagged nodes disable it by default). But retagging an
			// already-tagged node must preserve a deliberate FUTURE expiry
			// set via `headscale nodes expire` - that is a node property, not
			// tied to the auth key - and only clear a past expiry with a valid key. This
			// keeps the retag path symmetric with the same-key relogin path
			// below rather than silently overriding an admin decision.
			if wasUserOwned || node.IsExpiredAt(now) {
				node.Expiry = nil
			}
		} else if requestedTags == nil && node.IsTagged() && !pak.IsTagged() &&
			prior.NodeKey != regReq.NodeKey {
			// A user key that speaks for a tagged node, with a new node key,
			// takes it back as that user's device, as on Tailscale SaaS. A
			// relogin under the same node key keeps it tagged.
			node.Tags = nil
			node.UserID = &pak.User.ID
			node.User = pak.User
		}

		node.AuthKey = pak.AsCredential()
		node.AuthKeyID = &pak.ID
		// If this registration will consume a single-use key (the tx below
		// calls UsePreAuthKey under the same condition), reflect that in the
		// cached AuthKey so the NodeStore copy matches the database.
		if !pak.Reusable && !pak.Used {
			node.AuthKey.Used = true
		}

		// User-owned nodes update expiry from the client request,
		// falling back to the configured default if the client
		// did not request a specific expiry. If neither is set,
		// clear the expiry so the database holds NULL instead of
		// a pointer to zero time.
		switch {
		case node.IsTagged():
			// Tagged nodes keep their expiry; a valid key lifts a past one. A
			// future administrative expiry has not taken effect and stays.
			if node.IsExpiredAt(now) {
				node.Expiry = nil
			}
		case prior.NodeKey == regReq.NodeKey:
			// A node that keeps its node key keeps its expiry, as on Tailscale
			// SaaS: renewal comes with a new node key.
		case !regReq.Expiry.IsZero():
			node.Expiry = &regReq.Expiry
		case s.cfg.Node.Expiry > 0:
			exp := now.Add(s.cfg.Node.Expiry)
			node.Expiry = &exp
		default:
			node.Expiry = nil
		}

		// Route approvals stay on an owner change, as on Tailscale SaaS;
		// autoApprovers only add.
	})

	// A nil prior means the writer never saw the node (deleted, or the store
	// stopped), so nothing was decided and nothing may be persisted.
	if !ok || prior == nil {
		return types.NodeView{}, types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, existingNodeSameUser.ID())
	}

	if authErr != nil {
		log.Debug().
			Caller().
			Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
			Str(zf.MachineKey, machineKey.ShortString()).
			Uint64(zf.AuthKeyID, pak.ID).
			Err(authErr).
			Msg("Re-registration needs a valid auth key when it applies, rejecting")

		return types.NodeView{}, types.NodeView{}, authErr
	}

	// Only re-authentication writes a newly loaded key's reference. A wake-up
	// keeps the prior key, which may have been deleted (#2862).
	reregColumns := nodeUpdateColumns
	if reauth {
		reregColumns = append(slices.Clone(nodeUpdateColumns), "AuthKeyID")
	}

	_, err := s.persistNodeWith(updatedNodeView, reregColumns, func(tx *gorm.DB) error {
		// Only mark the key used on the *first* registration. On
		// re-registration the same key is already used and the
		// atomic compare-and-set in [hsdb.UsePreAuthKey] would otherwise
		// reject it as "authkey already used", locking out containers
		// that restart with the same one-shot key.
		if reauth && !pak.Reusable && !pak.Used {
			err := hsdb.UsePreAuthKey(tx, pak)
			if err != nil {
				return fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		s.undoReregistration(prior, written)

		return types.NodeView{}, types.NodeView{}, fmt.Errorf("writing node to database: %w", err)
	}

	log.Trace().
		Caller().
		Str(zf.NodeName, updatedNodeView.Hostname()).
		Uint64(zf.NodeID, updatedNodeView.ID().Uint64()).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, updatedNodeView.NodeKey().ShortString()).
		Str(zf.UserName, pak.Username()).
		Msg("Node re-authorized")

	return updatedNodeView, before, nil
}

// undoReregistration puts back the fields of a failed re-registration that
// still hold what it wrote, so later admin and map writes survive, and saves
// the result. LastSeen stays because the node did contact us; sessions,
// endpoints and health are not rolled back.
func (s *State) undoReregistration(prior, written *types.Node) {
	restored, exists := s.nodeStore.UpdateNode(prior.ID, func(n *types.Node) {
		if n.NodeKey == written.NodeKey {
			n.NodeKey = prior.NodeKey
		}

		if n.Hostname == written.Hostname {
			n.Hostname = prior.Hostname
		}

		if reflect.DeepEqual(n.Hostinfo, written.Hostinfo) {
			n.Hostinfo = prior.Hostinfo
		}

		if n.RegisterMethod == written.RegisterMethod {
			n.RegisterMethod = prior.RegisterMethod
		}

		if slices.Equal(n.Tags, written.Tags) &&
			reflect.DeepEqual(n.UserID, written.UserID) &&
			reflect.DeepEqual(n.User, written.User) {
			n.Tags = prior.Tags
			n.UserID = prior.UserID
			n.User = prior.User
		}

		if reflect.DeepEqual(n.Expiry, written.Expiry) {
			n.Expiry = prior.Expiry
		}

		if reflect.DeepEqual(n.AuthKeyID, written.AuthKeyID) &&
			reflect.DeepEqual(n.AuthKey, written.AuthKey) {
			n.AuthKey = prior.AuthKey
			n.AuthKeyID = prior.AuthKeyID
		}
	})
	if !exists {
		return
	}

	_, err := s.persistNode(restored)
	if err != nil {
		log.Error().Err(err).Uint64(zf.NodeID, prior.ID.Uint64()).Msg("Persisting re-registration rollback failed")
	}
}

// reauthChange returns the [change.Change] to broadcast after an authentication
// that updated or created a node. keysOnly marks a same-user relogin that
// changed nothing peers read besides its keys; see [onlyKeysChanged].
//
// Such a relogin is sent as the minimal peer patch [change.NodeKeyRotated].
// Anything else is a whole-node add, and a policy change forces a full
// recompute.
func reauthChange(node types.NodeView, keysOnly, policyChanged bool) change.Change {
	switch {
	case policyChanged:
		return change.PolicyChange()
	case keysOnly:
		return change.NodeKeyRotated(node)
	default:
		return change.NodeAdded(node.ID())
	}
}

// onlyKeysChanged reports whether peers read before and after the same, apart
// from what [change.NodeKeyRotated] patches. [tailcfg.PeerChange] carries
// neither [tailcfg.Node.Expired] nor Hostinfo: peers left holding an expired
// node drop its WireGuard handshakes, and the relogin stored the Hostinfo, so
// no later MapRequest shows the change.
func onlyKeysChanged(before, after types.NodeView, now time.Time) bool {
	return before.IsExpiredAt(now) == after.IsExpiredAt(now) &&
		peerHostinfoEqual(before.Hostinfo(), after.Hostinfo())
}

// updatePolicyManagerUsers pushes the current user list into the policy
// manager, rebuilds peer adjacency when user identity changed, and returns
// a PolicyChange when clients need a refresh.
func (s *State) updatePolicyManagerUsers() (change.Change, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return change.Change{}, fmt.Errorf("listing users for policy update: %w", err)
	}

	log.Debug().Caller().Int("user.count", len(users)).Msg("policy manager user update initiated because user list modification detected")

	changed, peerMapChanged, err := s.polMan.SetUsers(users)
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager users: %w", err)
	}

	log.Debug().Caller().Bool("policy.changed", changed).Msg("policy manager user update completed because SetUsers operation finished")

	if peerMapChanged {
		// User-driven matcher state changed: rebuild candidate adjacency
		// so peer visibility reflects the new policy. Without this, the
		// cached peersByNode stays stale until the next node write.
		s.nodeStore.RebuildPeerMaps()
	}

	if changed {
		return change.PolicyChange(), nil
	}

	return change.Change{}, nil
}

// UpdatePolicyManagerUsersForTest updates the policy manager's user cache.
// This is exposed for testing purposes to sync the policy manager after
// creating test users via CreateUserForTest().
func (s *State) UpdatePolicyManagerUsersForTest() error {
	_, err := s.updatePolicyManagerUsers()
	return err
}

// DrainSelfRefreshes returns a [change.SelfUpdate] for every node whose own
// entry or DNS config changed since the last call: its policy CapMap, from
// any policy, user or node update, or its NextDNS device metadata. Drained
// where changes are dispatched, so no path has to return the refresh itself.
func (s *State) DrainSelfRefreshes() []change.Change {
	ids := s.polMan.NodesWithChangedCapMap()

	s.selfRefreshMu.Lock()
	ids = append(ids, s.selfRefresh...)
	s.selfRefresh = nil
	s.selfRefreshMu.Unlock()

	slices.Sort(ids)
	ids = slices.Compact(ids)

	cs := make([]change.Change, 0, len(ids))
	for _, id := range ids {
		cs = append(cs, change.SelfUpdate(id))
	}

	return cs
}

// updatePolicyManagerNodes refreshes the policy manager with current node
// data and returns a PolicyChange when a node write since genBefore moved
// the policy. genBefore is [policy.PolicyManager.NodesGeneration] read
// before the caller's NodeStore write: the writer's [policyPeersFunc]
// usually applies the change, so the SetNodes here alone would miss it.
// On error the change is still returned; see [State.policyChangeSince].
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for nodes.
func (s *State) updatePolicyManagerNodes(genBefore uint64) (change.Change, error) {
	// A move since genBefore is the writer applying this write's nodes or a
	// later batch's, which it hands the policy manager before publishing.
	// The published snapshot read here can then be older, and SetNodes with
	// it would recompile the policy back. What is left to do here is retry a
	// recompile the writer failed, which leaves the generation where it was.
	if s.polMan.NodesGeneration() != genBefore {
		return change.PolicyChange(), nil
	}

	nodes := s.ListNodes()

	changed, err := s.polMan.SetNodes(nodes)
	if err != nil {
		return s.policyChangeSince(genBefore), fmt.Errorf("updating policy manager nodes: %w", err)
	}

	if changed {
		// The writer refreshes the policy before every relation build, so
		// a change here means this snapshot raced another writer and moved
		// the policy manager away from what adjacency was built with.
		s.nodeStore.RebuildPeerMaps()
	}

	return s.policyChangeSince(genBefore), nil
}

// nodeWriteFailed is the change a write returns with its error once its
// NodeStore write happened: the node's new state is live, so it goes out
// to the node itself and its peers even when the policy did not move.
func nodeWriteFailed(id types.NodeID, c change.Change) change.Change {
	if c.IsEmpty() {
		return change.NodeAdded(id)
	}

	c.OriginNode = id

	return c
}

// policyChangeSince returns a PolicyChange when a SetNodes since genBefore
// moved the policy. A caller whose NodeStore write already happened returns
// it even alongside an error, and callers publish it before handling the
// error: the writer applied the move to the policy manager, and no later
// caller will see it move again, so dropping it would leave clients on the
// filter and SSH policy the write replaced. Each caller reports its own
// window and never consumes another's, so a concurrent or failing caller
// can only add a report, not take one away.
func (s *State) policyChangeSince(genBefore uint64) change.Change {
	if s.polMan.NodesGeneration() != genBefore {
		return change.PolicyChange()
	}

	return change.Change{}
}

// PingDB checks if the database connection is healthy.
func (s *State) PingDB(ctx context.Context) error {
	return s.db.PingDB(ctx)
}

// isAutoDerivedGivenName reports whether given matches what
// dnsname.SanitizeHostname(hostname) would produce, optionally with a
// [NodeStore] collision-bump "-N" suffix. It is used to detect whether a
// GivenName has been admin-renamed (in which case it must not be
// overwritten by client-side hostname changes).
func isAutoDerivedGivenName(given, hostname string) bool {
	base := dnsname.SanitizeHostname(hostname)
	if given == base {
		return true
	}

	suffix, ok := strings.CutPrefix(given, base+"-")
	if !ok {
		return false
	}

	_, err := strconv.Atoi(suffix)

	return err == nil
}

// UpdateNodeFromMapRequest is the sync point where Hostinfo changes,
// endpoint updates, and route advertisements from a [tailcfg.MapRequest]
// land in the [NodeStore]. It produces a [change.Change] summarising
// what actually moved so downstream subsystems (mapper, policy, primary
// routes) can react accordingly.
//
// TODO(kradalby): This is essentially a patch update that could be sent directly to nodes,
// which means we could shortcut the whole change thing if there are no other important updates.
// When a field is added to a MapRequest that is stored on the node, also add
// it to [types.Node.PeerChangeFromMapRequest], [types.Node.ApplyPeerChange],
// the mapRequestDelta classification, and (if the policy reads it)
// [types.NodeView.HasPolicyChange].
func (s *State) UpdateNodeFromMapRequest(id types.NodeID, req tailcfg.MapRequest) (change.Change, error) { //nolint:gocyclo // central map-request reconciliation; the sequential branch flow reads clearer as one function than split across helpers
	log.Trace().
		Caller().
		Uint64(zf.NodeID, id.Uint64()).
		EmbedObject(zlog.MapRequest(&req)).
		Msg("Processing MapRequest for node")

	var (
		delta        mapRequestDelta
		routeChange  bool
		staleNodeKey bool
	)
	// Snapshot the primary assignment so we can tell whether the
	// Hostinfo + auto-approval that follows shifted any prefix.
	prevRoutes := s.nodeStore.PrimaryRoutes()
	genBefore := s.polMan.NodesGeneration()

	// We need to ensure we update the node as it is in the [NodeStore] at
	// the time of the request.
	updatedNode, ok := s.nodeStore.UpdateNode(id, func(currentNode *types.Node) {
		if currentNode.NodeKey != req.NodeKey {
			staleNodeKey = true
			return
		}

		// Capture the raw wire-level peer change. LastSeen is always
		// stamped here, so classification tests must not rely on it.
		delta.peerChange = currentNode.PeerChangeFromMapRequest(req)
		delta.discoKeyChanged = delta.peerChange.DiscoKey != nil

		// Normalize before classifying. A nil req.Hostinfo means the client
		// did not send one (e.g., endpoint-only/lite requests); we must NOT
		// clobber the stored Hostinfo with a shell containing only NetInfo.
		// When Hostinfo is present but NetInfo is omitted (Tailscale >= 1.66
		// sends NetInfo only when it changed), the stored NetInfo is carried
		// over. Every comparison below runs against this normalized value,
		// otherwise an omitted NetInfo reads as a Hostinfo change and turns
		// a routine map request into a whole-peer broadcast.
		var newHostinfo *tailcfg.Hostinfo

		if req.Hostinfo != nil {
			// Copy so the classification never mutates the caller's request.
			hi := *req.Hostinfo
			hi.NetInfo = netInfoFromMapRequest(id, currentNode.Hostinfo, req.Hostinfo)
			newHostinfo = &hi
		}

		// DERP comparison is independent of the rest of Hostinfo:
		// PreferredDERP has its own wire patch representation, and
		// DERP zero on the wire means "unchanged", so a clear-to-zero
		// must be detected here and escalated to a whole-peer update
		// during classification. A request without Hostinfo says nothing
		// about DERP, so it compares equal.
		storedDERP := hostinfoDERP(currentNode.Hostinfo)
		requestedDERP := storedDERP

		if newHostinfo != nil {
			requestedDERP = hostinfoDERP(newHostinfo)
		}

		delta.oldDERP = storedDERP
		delta.newDERP = requestedDERP
		delta.derpChanged = requestedDERP != storedDERP

		// Endpoint broadcast-worthiness is gated separately from storage:
		// the new set is always stored via ApplyPeerChange below, but only
		// newly-added useful (non-STUN) endpoints justify a peer broadcast.
		// STUN-only churn and pure shrinks are suppressed to keep peers'
		// views stable. See endpointBroadcastWorthy.
		delta.endpointBroadcast = delta.peerChange.Endpoints != nil &&
			endpointBroadcastWorthy(currentNode.Endpoints, req.Endpoints, req.EndpointTypes)

		// Routes are policy and election inputs, so they are compared on
		// their own. Any other Hostinfo change is stored, but only fields
		// peers read are worth resending the whole node for.
		delta.routesChanged = newHostinfo != nil &&
			routesChanged(currentNode.View(), newHostinfo)
		delta.hostinfoChanged = newHostinfo != nil &&
			!hostinfoEqual(currentNode.Hostinfo, newHostinfo)
		delta.peerHostinfoChanged = newHostinfo != nil &&
			!peerHostinfoEqual(currentNode.Hostinfo.View(), newHostinfo.View())
		delta.dnsMetadataChanged = newHostinfo != nil &&
			(currentNode.Hostinfo == nil ||
				currentNode.Hostinfo.Hostname != newHostinfo.Hostname ||
				currentNode.Hostinfo.OS != newHostinfo.OS)

		// A change carrying only an updated LastSeen is not worth a
		// full-row database UPDATE plus the O(n) policy rescan
		// persistNodeAndRefreshPolicy triggers: LastSeen is best-effort and rides
		// along the next substantive write. DERP is called out because
		// peerChangePersistWorthy cannot see a clear-to-zero.
		delta.persistWorthy = peerChangePersistWorthy(delta.peerChange) ||
			delta.hostinfoChanged ||
			delta.derpChanged

		hostinfoToStore := delta.hostinfoChanged || delta.derpChanged

		oldAnnounced := currentNode.AnnouncedRoutes()

		currentNode.ApplyPeerChange(&delta.peerChange)

		if hostinfoToStore {
			// The snapshot outlives the request; deep-copy so its slices and NetInfo are never shared.
			currentNode.Hostinfo = newHostinfo.Clone()
		}

		// Only a real hostname change may re-derive GivenName: it is peer
		// visible, so the whole node is resent and peers learn the name.
		if newHostinfo != nil && newHostinfo.Hostname != "" &&
			newHostinfo.Hostname != currentNode.Hostname {
			// Preserve an admin-renamed GivenName: only auto-derive
			// when the current GivenName is still what
			// SanitizeHostname of the old Hostname would produce
			// (possibly with a "-N" collision bump).
			autoDerived := isAutoDerivedGivenName(currentNode.GivenName, currentNode.Hostname)

			currentNode.Hostname = newHostinfo.Hostname
			if autoDerived {
				currentNode.GivenName = dnsname.SanitizeHostname(newHostinfo.Hostname)
				// [NodeStore.UpdateNode] auto-bumps GivenName on collision.
			}
		}

		// Approval follows the announced set, only when it changes: any
		// other report would re-grant a route an admin revoked. Deciding in
		// this write keeps one request at one NodeStore write, one peer
		// build and one row update; persisting is already due, as the
		// Hostinfo changed.
		if delta.routesChanged {
			oldApproved := currentNode.ApprovedRoutes
			dropped := dropWithdrawnAutoApprovals(currentNode)
			routeChange = s.approveAnnouncedRoutes(currentNode) || dropped

			log.Debug().
				Caller().
				Uint64(zf.NodeID, id.Uint64()).
				Strs(zf.OldAnnouncedRoutes, util.PrefixesToString(oldAnnounced)).
				Strs(zf.NewAnnouncedRoutes, util.PrefixesToString(currentNode.AnnouncedRoutes())).
				Strs(zf.RoutesApprovedOld, util.PrefixesToString(oldApproved)).
				Strs(zf.RoutesApprovedNew, util.PrefixesToString(currentNode.ApprovedRoutes)).
				Bool(zf.RouteChanged, routeChange).
				Msg("announced routes changed")
		}

		// AllApprovedRoutes is announced ∩ approved; a Hostinfo
		// update that shrinks the announced set can drop the node
		// out of HA candidacy without touching ApprovedRoutes.
		// Clear any stale Unhealthy bit in that case.
		if currentNode.Unhealthy && len(currentNode.AllApprovedRoutes()) == 0 {
			currentNode.Unhealthy = false
		}
	})

	if !ok {
		return change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	if staleNodeKey {
		return change.Change{}, ErrNodeKeyNotCurrent
	}

	if delta.dnsMetadataChanged {
		s.selfRefreshMu.Lock()
		s.selfRefresh = append(s.selfRefresh, id)
		s.selfRefreshMu.Unlock()
	}

	// SubnetRoutes = announced ∩ approved, so a Hostinfo update can
	// move a primary without ever touching ApprovedRoutes. The pre/post
	// snapshot diff catches that.
	nodeRouteChange := change.Change{}

	if !maps.Equal(prevRoutes, s.nodeStore.PrimaryRoutes()) {
		log.Debug().
			Caller().
			Uint64(zf.NodeID, id.Uint64()).
			Strs(zf.RoutesAnnounced, util.PrefixesToString(updatedNode.AnnouncedRoutes())).
			Strs(zf.ApprovedRoutes, util.PrefixesToString(updatedNode.ApprovedRoutes().AsSlice())).
			Strs(zf.AllApprovedRoutes, util.PrefixesToString(updatedNode.AllApprovedRoutes())).
			Msg("primary route assignment shifted after MapRequest")

		nodeRouteChange = change.PolicyChange()
	}

	// A no-op MapRequest (identical re-send / reconnect with matching state)
	// leaves the node untouched, so skip the full-row UPDATE and the O(n)
	// policy SetNodes scan that persistNodeAndRefreshPolicy performs.
	//
	// Otherwise we persist the row directly and refresh the policy manager
	// only when node inputs visible to the policy actually changed
	// (structural Hostinfo or routes), letting updatePolicyManagerNodes
	// decide whether matchers changed.
	policyChange := change.Change{}

	if delta.persistWorthy {
		var err error

		updatedNode, err = s.persistNode(updatedNode)
		if err != nil {
			return nodeWriteFailed(id, s.policyChangeSince(genBefore).Merge(nodeRouteChange)), fmt.Errorf("saving to database: %w", err)
		}

		// Only refresh the policy manager when something it depends on
		// might have moved. Endpoint/key/DERP/LastSeen-only updates do not
		// affect policy evaluation and are deliberately skipped here.
		if delta.peerHostinfoChanged || delta.routesChanged || routeChange {
			policyChange, err = s.updatePolicyManagerNodes(genBefore)
			if err != nil {
				return nodeWriteFailed(id, policyChange.Merge(nodeRouteChange)), fmt.Errorf("updating policy manager after node save: %w", err)
			}
		}
	}

	if !policyChange.IsEmpty() {
		return policyChange, nil
	}

	if !nodeRouteChange.IsEmpty() {
		return nodeRouteChange, nil
	}

	// Determine the most specific change type from the classified delta.
	// This allows us to send lightweight patch updates instead of full
	// map responses.
	c := buildMapRequestChangeResponse(id, updatedNode, delta)

	// Approval moved no effective route; resend the node so peers hold
	// its current state.
	if routeChange {
		c = c.Merge(change.NodeAdded(id))
	}

	// One trace line per classified request so a "peer cannot reach me"
	// report can be matched to the classification that narrowed it.
	log.Trace().
		Uint64(zf.NodeID, id.Uint64()).
		Str(zf.Type, c.Type()).
		EmbedObject(delta).
		Msg("classified MapRequest")

	return c, nil
}

// endpointBroadcastWorthy reports whether an endpoint-only delta is worth
// fanning out to peers as an incremental PeersChangedPatch. A delta that only
// adds STUN-derived endpoints — or only removes endpoints — is suppressed:
// bare STUN endpoints are unlikely to be open and churn a lot (the client
// re-derives those paths over disco anyway), and a pure shrink is not worth
// telling peers about. Suppressing this churn keeps peers' views stable.
//
// The decision is intentionally conservative: it gates the broadcast only,
// not storage. A suppressed delta is never resent on its own, so suppression
// is only safe once peers already hold an endpoint set to fall back on; the
// first set a node announces is therefore always broadcast.
//
// Limitation: headscale stores bare []netip.AddrPort with no per-endpoint
// type, so we can only classify the *new* request's endpoints (via the
// parallel newTypes slice). We therefore gate on whether any newly-added
// endpoint (present in new, absent from stored) is useful (non-STUN). When
// newTypes is absent or shorter than newEPs (older clients), the unknown
// endpoints are treated as useful, preserving the pre-existing always-broadcast
// behaviour and never hiding a genuinely new endpoint.
func endpointBroadcastWorthy(
	stored, newEPs []netip.AddrPort,
	newTypes []tailcfg.EndpointType,
) bool {
	// Peers hold no endpoints for this node yet, so the first set announced
	// is the only one they would ever get. Type does not matter here.
	if len(stored) == 0 {
		return len(newEPs) > 0
	}

	storedSet := make(map[netip.AddrPort]struct{}, len(stored))
	for _, ep := range stored {
		storedSet[ep] = struct{}{}
	}

	for i, ep := range newEPs {
		if _, ok := storedSet[ep]; ok {
			// Already known to peers; not a newly-added endpoint.
			continue
		}

		// A newly-added endpoint with no type information (older client)
		// is treated as useful so we never hide a genuinely new endpoint.
		t := tailcfg.EndpointUnknownType
		if i < len(newTypes) {
			t = newTypes[i]
		}

		if isUsefulEndpointType(t) {
			return true
		}
	}

	return false
}

// isUsefulEndpointType reports whether an endpoint type is worth eagerly
// broadcasting to peers. STUN-derived endpoints are excluded because they are
// churny and unlikely to be directly reachable; magicsock's disco handles
// establishing those paths.
func isUsefulEndpointType(t tailcfg.EndpointType) bool {
	return t != tailcfg.EndpointSTUN && t != tailcfg.EndpointSTUN4LocalPort
}

// buildMapRequestChangeResponse picks the narrowest broadcast for a processed
// MapRequest delta. Policy and route changes are handled by the caller.
//
// Two wire constraints shape the order: tailcfg.PeerChange.DERPRegion == 0
// means "unchanged", so clearing DERP cannot ride a patch and needs a whole
// peer; and a key patch already carries endpoints, key expiry, and DERP, so a
// key change subsumes an endpoint or DERP patch in the same request.
// The delta decides which fields to send; their values come from the fresh
// node because concurrent requests may have superseded the captured values.
func buildMapRequestChangeResponse(
	id types.NodeID,
	node types.NodeView,
	delta mapRequestDelta,
) change.Change {
	if delta.peerHostinfoChanged {
		return change.NodeAdded(id)
	}

	// Peers get an expired node without its endpoints or home DERP region.
	if node.IsExpired() {
		delta.endpointBroadcast, delta.derpChanged = false, false
	}

	var currentDERP tailcfg.DERPRegionID

	if delta.derpChanged {
		if hi := node.Hostinfo(); hi.Valid() && hi.NetInfo().Valid() {
			currentDERP = hi.NetInfo().PreferredDERP()
		}

		if currentDERP == 0 {
			return change.NodeAdded(id)
		}
	}

	if delta.discoKeyChanged {
		c := change.NodeKeyRotated(node)
		if delta.derpChanged {
			c.PeerPatches[0].DERPRegion = currentDERP
		}

		return c
	}

	if delta.endpointBroadcast || delta.derpChanged {
		patch := &tailcfg.PeerChange{NodeID: id.NodeID()}

		if delta.endpointBroadcast {
			patch.Endpoints = node.Endpoints().AsSlice()
		}

		if delta.derpChanged {
			patch.DERPRegion = currentDERP
		}

		return change.EndpointOrDERPUpdate(id, patch)
	}

	return change.Change{}
}

func routesChanged(oldNode types.NodeView, newHI *tailcfg.Hostinfo) bool {
	var oldRoutes []netip.Prefix
	if oldNode.Valid() && oldNode.AsStruct().Hostinfo != nil {
		oldRoutes = oldNode.AsStruct().Hostinfo.RoutableIPs
	}

	newRoutes := slices.Clone(newHI.RoutableIPs)
	if newRoutes == nil {
		newRoutes = []netip.Prefix{}
	}

	slices.SortFunc(oldRoutes, netip.Prefix.Compare)
	slices.SortFunc(newRoutes, netip.Prefix.Compare)

	return !slices.Equal(oldRoutes, newRoutes)
}

// peerChangePersistWorthy reports whether a peer change carries anything that
// warrants a database write. It deliberately ignores LastSeen, which
// [Node.PeerChangeFromMapRequest] always stamps: a keepalive that only bumps
// LastSeen should not trigger a full-row UPDATE and policy rescan.
func peerChangePersistWorthy(peerChange tailcfg.PeerChange) bool {
	return peerChange.DiscoKey != nil ||
		peerChange.Online != nil ||
		peerChange.Endpoints != nil ||
		peerChange.DERPRegion != 0 ||
		peerChange.KeyExpiry != nil
}
