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
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
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
//
// Expiry is included here but may be omitted at call sites that must
// not touch it (see persistNodeToDB).
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
	"UpdatedAt",
}

// ErrRegistrationExpired is returned when a registration has expired.
var ErrRegistrationExpired = errors.New("registration expired")

// ErrNodeKeyInUse is returned when a registration or re-auth claims a NodeKey
// already bound to a different machine, enforcing the 1:1 NodeKey<->MachineKey
// binding.
var ErrNodeKeyInUse = errors.New("node key already in use by another machine")

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
	sshCheckAuth map[sshCheckPair]time.Time
	sshCheckMu   sync.RWMutex

	// persistMu serialises the re-read-and-write critical section in
	// persistNodeToDB so the database row always converges on [NodeStore]
	// rather than being clobbered by a stale caller snapshot.
	persistMu sync.Mutex

	// registerLocks serialises registration per machine key so concurrent
	// registrations of the same machine resolve to a single node instead of
	// racing the find-then-create section and each creating their own.
	// ponytail: entries are never pruned; bounded by distinct machine keys
	// seen, add cleanup on node delete only if it ever matters.
	registerLocks *xsync.Map[key.MachinePublic, *sync.Mutex]
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

	authCache := expirable.NewLRU[types.AuthID, *types.AuthRequest](
		cacheMaxEntries,
		func(id types.AuthID, rn *types.AuthRequest) {
			rn.FinishAuth(types.AuthVerdict{Err: ErrRegistrationExpired})
		},
		cacheExpiration,
	)

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

	// [policy.PolicyManager.BuildPeerMap] handles both global and per-node filter complexity.
	// This moves the complex peer relationship logic into the policy package where it belongs.
	nodeStore := NewNodeStore(
		nodes,
		func(nodes []types.NodeView) map[types.NodeID][]types.NodeView {
			return polMan.BuildPeerMap(views.SliceOf(nodes))
		},
		batchSize,
		batchTimeout,
	)
	nodeStore.Start()

	s := &State{
		cfg: cfg,

		db:        db,
		ipAlloc:   ipAlloc,
		polMan:    polMan,
		authCache: authCache,
		nodeStore: nodeStore,
		pings:     newPingTracker(),

		sshCheckAuth:  make(map[sshCheckPair]time.Time),
		registerLocks: xsync.NewMap[key.MachinePublic, *sync.Mutex](),
	}

	// Surface nodes whose stored data would break map generation (e.g. an
	// invalid given name from a legacy row) so an operator can fix them. This
	// only logs; it never mutates a node's stored name at boot.
	s.logNodeHealth()

	return s, nil
}

// Close gracefully shuts down the [State] instance and releases all resources.
func (s *State) Close() error {
	s.pings.drain()
	s.nodeStore.Stop()

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

// ReloadPolicy reloads the access control policy and triggers auto-approval if changed.
// Returns the resulting [change.Change] slice when the policy or routes changed.
func (s *State) ReloadPolicy() ([]change.Change, error) {
	pol, err := hsdb.PolicyBytes(s.db.DB, s.cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	policyChanged, err := s.polMan.SetPolicy(pol)
	if err != nil {
		return nil, fmt.Errorf("setting policy: %w", err)
	}

	// Clear SSH check auth times when policy changes to ensure stale
	// approvals don't persist if checkPeriod rules are modified or removed.
	s.ClearSSHCheckAuth()

	// Rebuild peer maps after policy changes because the peersFunc in [NodeStore]
	// uses the [policy.PolicyManager]'s filters. Without this, nodes won't see
	// newly allowed peers until a node is added/removed, causing autogroup:self
	// policies to not propagate correctly when switching between policy types.
	s.nodeStore.RebuildPeerMaps()

	//nolint:prealloc // cs starts with one element and may grow
	cs := []change.Change{change.PolicyChange()}

	// Per-node selective self refresh for nodeAttrs. A broadcast
	// [change.PolicyChange] re-renders peer lists and packet filters
	// but never repopulates a node's own [tailcfg.Node.CapMap]; that
	// lives on the self entry only. The drain returns every node ID
	// whose cap output shifted across recent updateLocked calls —
	// refreshNodeAttrsLocked appends rather than overwrites so a
	// concurrent SetUsers/SetNodes between SetPolicy and the drain
	// cannot silently lose the policy-reload diff.
	for _, id := range s.polMan.NodesWithChangedCapMap() {
		cs = append(cs, change.SelfUpdate(id))
	}

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

// persistNodeRowToDB writes the node's database row, re-reading the
// authoritative copy from [NodeStore], without touching the policy manager.
// Batch callers (e.g. autoApproveNodes) use it to write many rows and then
// trigger a single policy rebuild instead of one per node.
func (s *State) persistNodeRowToDB(node types.NodeView) (types.NodeView, error) {
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

	fresh, exists := s.nodeStore.GetNode(node.ID())
	if !exists {
		s.persistMu.Unlock()

		log.Warn().
			EmbedObject(node).
			Bool("is_ephemeral", node.IsEphemeral()).
			Msg("Node no longer exists in NodeStore, skipping database persist to prevent race condition")

		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, node.ID())
	}

	nodePtr := fresh.AsStruct()

	// Explicitly select all node columns so GORM includes nil/zero-value
	// fields (e.g. UserID=nil when converting a user-owned node to tagged).
	// Omit "Expiry" here: expiry is only updated through explicit
	// SetNodeExpiry calls or re-registration, not during MapRequest updates.
	err := s.db.DB.Select(nodeUpdateColumns).Omit("Expiry").Updates(nodePtr).Error
	s.persistMu.Unlock()

	if err != nil {
		return types.NodeView{}, fmt.Errorf("saving node: %w", err)
	}

	return fresh, nil
}

// persistNodeToDB saves the given node state to the database and refreshes the
// policy manager. The exact row written comes from [NodeStore]; see
// [State.persistNodeRowToDB].
func (s *State) persistNodeToDB(node types.NodeView) (types.NodeView, change.Change, error) {
	fresh, err := s.persistNodeRowToDB(node)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	// Check if policy manager needs updating
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return fresh, change.Change{}, fmt.Errorf("updating policy manager after node save: %w", err)
	}

	if c.IsEmpty() {
		c = change.NodeAdded(node.ID())
	}

	return fresh, c, nil
}

func (s *State) SaveNode(node types.NodeView) (types.NodeView, change.Change, error) {
	// Update [NodeStore] first
	nodePtr := node.AsStruct()

	resultNode := s.nodeStore.PutNode(*nodePtr)

	// Then save to database using the result from [NodeStore.PutNode]
	return s.persistNodeToDB(resultNode)
}

// DeleteNode permanently removes a node and cleans up associated resources.
// Returns whether policies changed and any error. This operation is irreversible.
func (s *State) DeleteNode(node types.NodeView) (change.Change, error) {
	s.nodeStore.DeleteNode(node.ID())

	err := s.db.DeleteNode(node.AsStruct())
	if err != nil {
		return change.Change{}, err
	}

	s.ipAlloc.FreeIPs(node.IPs())

	c := change.NodeRemoved(node.ID())

	// Check if policy manager needs updating after node deletion
	policyChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager after node deletion: %w", err)
	}

	if !policyChange.IsEmpty() {
		// Merge policy change with NodeRemoved to preserve PeersRemoved info
		// This ensures the batcher cleans up the deleted node from its state
		c = c.Merge(policyChange)
	}

	return c, nil
}

// Connect marks a node connected and returns the resulting changes
// plus a session epoch identifying this poll session. Every Connect
// acquires one live session; the caller must release it with exactly
// one [State.Disconnect] call once the session ends (see poll.go).
func (s *State) Connect(id types.NodeID) ([]change.Change, uint64) {
	prevRoutes := s.nodeStore.PrimaryRoutes()

	// Reconnecting clears Unhealthy: the node just proved basic
	// connectivity by completing the Noise handshake.
	var epoch uint64

	node, ok := s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.SessionEpoch++
		epoch = n.SessionEpoch
		n.ActiveSessions++
		n.IsOnline = new(true)
		n.Unhealthy = false
	})
	if !ok {
		return nil, 0
	}

	// A node coming online sends a lightweight online peer patch. Subnet
	// routers, relay targets, and via targets get their full peer recompute
	// from the gated PolicyChange below, so no full update is needed here.
	c := []change.Change{change.NodeOnline(node.ID())}

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
// [State.Connect] and marks the node offline only when that was its
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
		n.IsOnline = new(false)
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
			Msg("session released, other sessions keep node online")

		return nil, nil
	}

	log.Info().EmbedObject(node).Msg("node disconnected")

	// Persist LastSeen best-effort: [NodeStore] already reflects offline
	// and peers still need the change notifications below.
	_, c, err := s.persistNodeToDB(node)
	if err != nil {
		log.Error().Err(err).EmbedObject(node).Msg("failed to update last seen in database")

		c = change.Change{}
	}

	// Only a node whose online state changes what peers compute (a subnet
	// router, relay target, or via target) needs a full peer recompute.
	// An ordinary node going offline just sends the lightweight offline
	// patch; emitting a PolicyChange for it would force every peer to
	// rebuild its netmap on every disconnect.
	// A node going offline sends a lightweight offline peer patch. Subnet
	// routers and other recompute-forcing nodes rely on the gated
	// PolicyChange below for the peer recompute, so no full update here.
	cs := []change.Change{change.NodeOffline(node.ID()), c}
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

	// For specific peerIDs, filter from all nodes.
	// This path is used for incremental updates (NodeAdded, NodeChanged)
	// where the caller already knows which peer IDs are involved.
	// Peer visibility filtering happens in the mapper against the live
	// policy (buildTailPeers and the shared visiblePeerIDs filter), because
	// the snapshot peer map is not rebuilt on policy changes.
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
// If expiry is nil, the node's expiry is disabled (node will never expire).
func (s *State) SetNodeExpiry(nodeID types.NodeID, expiry *time.Time) (types.NodeView, change.Change, error) {
	// Update [NodeStore] before database to ensure consistency. The [NodeStore] update
	// is blocking and will be the source of truth for the batcher. The database update
	// must make the exact same change. If the database update fails, the [NodeStore]
	// change will remain, but since we return an error, no change notification will be
	// sent to the batcher, preventing inconsistent state propagation.
	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.Expiry = expiry
	})

	if !ok {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, nodeID)
	}

	// Persist expiry change to database directly since persistNodeToDB omits expiry.
	err := s.db.NodeSetExpiry(nodeID, expiry)
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("setting node expiry in database: %w", err)
	}

	// Update policy manager and generate change notification.
	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return n, change.Change{}, fmt.Errorf("updating policy manager after setting expiry: %w", err)
	}

	if c.IsEmpty() {
		c = change.NodeAdded(n.ID())
	}

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

	nodeView, c, err := s.persistNodeToDB(n)
	if err != nil {
		return nodeView, c, err
	}

	// Set OriginNode so the mapper knows to include self info for this node.
	// When tags change, persistNodeToDB returns PolicyChange which doesn't set OriginNode,
	// so the mapper's self-update check fails and the node never sees its new tags.
	// Setting OriginNode ensures the node gets a self-update with the new tags.
	c.OriginNode = nodeID

	return nodeView, c, nil
}

// SetApprovedRoutes sets the network routes that a node is approved to advertise.
func (s *State) SetApprovedRoutes(nodeID types.NodeID, routes []netip.Prefix) (types.NodeView, change.Change, error) {
	// TODO(kradalby): In principle we should call the AutoApprove logic here
	// because even if the CLI removes an auto-approved route, it will be added
	// back automatically.
	prevRoutes := s.nodeStore.PrimaryRoutes()

	n, ok := s.nodeStore.UpdateNode(nodeID, func(node *types.Node) {
		node.ApprovedRoutes = routes
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
	nodeView, c, err := s.persistNodeToDB(n)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	// PolicyChange fans out a fresh netmap whenever the new approved
	// set shifted a primary advertiser.
	routeChange := !maps.Equal(prevRoutes, s.nodeStore.PrimaryRoutes())
	if routeChange || !c.IsFull() {
		c = change.PolicyChange()
	}

	return nodeView, c, nil
}

// RenameNode changes the display name of a node. The admin supplies
// the exact DNS label they want; malformed input is rejected (no
// auto-sanitisation) and collisions error out rather than silently
// bumping a user-facing label. See HOSTNAME.md for the CLI contract.
func (s *State) RenameNode(nodeID types.NodeID, newName string) (types.NodeView, change.Change, error) {
	// Validate the label AND that the resulting FQDN fits MaxHostnameLength:
	// a valid 63-char label can still overflow under a long base_domain, and
	// an unmappable name would break this node and its peers (issue #3346).
	err := types.ValidateGivenName(newName, s.cfg.BaseDomain)
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %w", ErrGivenNameInvalid, err)
	}

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

	return s.persistNodeToDB(view)
}

// BackfillNodeIPs assigns IP addresses to nodes that don't have them.
func (s *State) BackfillNodeIPs() ([]string, error) {
	changes, err := s.db.BackfillNodeIPs(s.ipAlloc)
	if err != nil {
		return nil, err
	}

	// Refresh [NodeStore] after IP changes to ensure consistency
	if len(changes) > 0 {
		nodes, err := s.db.ListNodes()
		if err != nil {
			return changes, fmt.Errorf("refreshing NodeStore after IP backfill: %w", err)
		}

		for _, node := range nodes {
			// Preserve online status and NetInfo when refreshing from database
			existingNode, exists := s.nodeStore.GetNode(node.ID)
			if exists && existingNode.Valid() {
				node.IsOnline = new(existingNode.IsOnline().Get())

				// TODO(kradalby): We should ensure we use the same hostinfo and node merge semantics
				// when a node re-registers as we do when it sends a map request (UpdateNodeFromMapRequest).

				// Preserve NetInfo from existing node to prevent loss during backfill
				netInfo := netInfoFromMapRequest(node.ID, existingNode.Hostinfo().AsStruct(), node.Hostinfo)
				node.Hostinfo = existingNode.Hostinfo().AsStruct()
				node.Hostinfo.NetInfo = netInfo
			}
			// TODO(kradalby): This should just update the IP addresses, nothing else in the node store.
			// We should avoid [NodeStore.PutNode] here.
			_ = s.nodeStore.PutNode(*node)
		}
	}

	return changes, nil
}

// ExpireExpiredNodes finds and processes expired nodes since the last check.
// Returns next check time, state update with expired nodes, and whether any were found.
func (s *State) ExpireExpiredNodes(lastCheck time.Time) (time.Time, []change.Change, bool) {
	// Why capture start time: We need to ensure we don't miss nodes that expire
	// while this function is running by using a consistent timestamp for the next check
	started := time.Now()

	var updates []change.Change

	for _, node := range s.nodeStore.ListNodes().All() { //nolint:unqueryvet // NodeStore.ListNodes not a SQL query
		if !node.Valid() {
			continue
		}

		// Why check After(lastCheck): We only want to notify about nodes that
		// expired since the last check to avoid duplicate notifications
		if node.IsExpired() && node.Expiry().Valid() && node.Expiry().Get().After(lastCheck) {
			updates = append(updates, change.KeyExpiryFor(node.ID(), node.Expiry().Get()))
		}
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

// SSHCheckParams resolves the SSH check period for a source-destination
// node pair from the current policy.
func (s *State) SSHCheckParams(
	srcNodeID, dstNodeID types.NodeID,
) (time.Duration, bool) {
	return s.polMan.SSHCheckParams(srcNodeID, dstNodeID)
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

// NodeCanHaveTag checks if a node is allowed to have a specific tag.
func (s *State) NodeCanHaveTag(node types.NodeView, tag string) bool {
	return s.polMan.NodeCanHaveTag(node, tag)
}

// SetPolicy updates the policy configuration.
func (s *State) SetPolicy(pol []byte) (bool, error) {
	changed, err := s.polMan.SetPolicy(pol)
	if err != nil {
		return changed, err
	}

	// Clear SSH check auth times when policy changes.
	s.ClearSSHCheckAuth()

	return changed, nil
}

// AutoApproveRoutes checks if a node's routes should be auto-approved.
// AutoApproveRoutes checks if any routes should be auto-approved for a node and updates them.
func (s *State) AutoApproveRoutes(nv types.NodeView) (change.Change, error) {
	approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
	if changed {
		log.Debug().
			EmbedObject(nv).
			Strs("routes.announced", util.PrefixesToString(nv.AnnouncedRoutes())).
			Strs("routes.approved.old", util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
			Strs("routes.approved.new", util.PrefixesToString(approved)).
			Msg("Single node auto-approval detected route changes")

		// Persist the auto-approved routes to database and [NodeStore] via
		// [State.SetApprovedRoutes]. This ensures consistency between database
		// and [NodeStore].
		_, c, err := s.SetApprovedRoutes(nv.ID(), approved)
		if err != nil {
			log.Error().
				EmbedObject(nv).
				Err(err).
				Msg("Failed to persist auto-approved routes")

			return change.Change{}, err
		}

		log.Info().EmbedObject(nv).Strs(zf.RoutesApproved, util.PrefixesToString(approved)).Msg("routes approved")

		return c, nil
	}

	return change.Change{}, nil
}

// GetPolicy retrieves the current policy from the database.
func (s *State) GetPolicy() (*types.Policy, error) {
	return s.db.GetPolicy()
}

// SetPolicyInDB stores policy data in the database.
func (s *State) SetPolicyInDB(data string) (*types.Policy, error) {
	return s.db.SetPolicy(data)
}

// GetNodePrimaryRoutes returns the primary routes for a node.
func (s *State) GetNodePrimaryRoutes(nodeID types.NodeID) []netip.Prefix {
	return s.nodeStore.PrimaryRoutesForNode(nodeID)
}

// RoutesForPeer computes the routes a peer should advertise in a viewer's
// AllowedIPs, combining primary routes (from HA election), approved exit
// routes, and via grant steering.
//
// Approved exit routes (0.0.0.0/0, ::/0) are included alongside subnet
// routes — they appear in every peer's AllowedIPs, while unapproved
// ones do not.
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
	viewerSubnets := viewer.SubnetRoutes()
	if len(viewerSubnets) > 0 {
		for _, p := range globalPrimaries {
			if slices.Contains(viewerSubnets, p) && !slices.Contains(reduced, p) {
				reduced = append(reduced, p)
			}
		}
	}

	return reduced
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
// whether the resulting primary-route assignment changed, so the HA
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
// primary-route assignment differs from before the batch so callers
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

	fns := make(map[types.NodeID]UpdateNodeFunc, len(updates))
	for id, healthy := range updates {
		fns[id] = healthSetter(healthy)
	}

	s.nodeStore.UpdateNodes(fns)

	return !maps.Equal(prevRoutes, s.nodeStore.PrimaryRoutes())
}

// healthSetter returns an UpdateNodeFunc that flips n.Unhealthy to
// the inverse of healthy, with the same gate as [State.SetNodeHealth]:
// an unhealthy mark only sticks when the node is still online and
// still advertises approved routes, so a node that left HA candidacy
// between probe dispatch and result does not carry a stale bit.
func healthSetter(healthy bool) UpdateNodeFunc {
	return func(n *types.Node) {
		if !healthy {
			online := n.IsOnline != nil && *n.IsOnline
			if !online || len(n.AllApprovedRoutes()) == 0 {
				return
			}
		}

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

	s.sshCheckAuth[sshCheckPair{Src: src, Dst: dst}] = time.Now()
}

// GetLastSSHAuth returns when src last authenticated for SSH check
// to dst.
func (s *State) GetLastSSHAuth(src, dst types.NodeID) (time.Time, bool) {
	s.sshCheckMu.RLock()
	defer s.sshCheckMu.RUnlock()

	t, ok := s.sshCheckAuth[sshCheckPair{Src: src, Dst: dst}]

	return t, ok
}

// ClearSSHCheckAuth clears all recorded SSH check auth times.
// Called when the policy changes to ensure stale auth times don't grant access.
func (s *State) ClearSSHCheckAuth() {
	s.sshCheckMu.Lock()
	defer s.sshCheckMu.Unlock()

	s.sshCheckAuth = make(map[sshCheckPair]time.Time)
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

// applyAuthNodeUpdate applies common update logic for re-authenticating or converting
// an existing node. It updates the node in [NodeStore], processes RequestTags, and
// persists changes to the database.
func (s *State) applyAuthNodeUpdate(params authNodeUpdateParams) (types.NodeView, error) {
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
	rejectedTags := s.validateRequestTags(params.ExistingNode, requestTags)
	if len(rejectedTags) > 0 {
		return types.NodeView{}, fmt.Errorf(
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
		return types.NodeView{}, ErrNodeKeyInUse
	}

	// Update existing node in [NodeStore] - validation passed, safe to mutate
	updatedNodeView, ok := s.nodeStore.UpdateNode(params.ExistingNode.ID(), func(node *types.Node) {
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
		// Do NOT reset IsOnline here. Online status is managed exclusively by
		// [State.Connect]/[State.Disconnect] in the poll session lifecycle.
		// Resetting it during re-registration causes a false offline blip: the
		// change notification triggers a map regeneration showing the node as
		// offline to peers, even though [State.Connect] will immediately set it
		// back to true.
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
			// Personal → Tagged: clear expiry (tagged nodes don't expire)
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
		}
		// Tagged → Tagged: keep existing expiry (nil) - no action needed

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
	})

	if !ok {
		return types.NodeView{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, params.ExistingNode.ID())
	}

	// Persist to database.
	// Explicitly select all node columns so GORM includes nil/zero-value fields
	// (see nodeUpdateColumns comment).
	_, err := hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		err := tx.Select(nodeUpdateColumns).Updates(updatedNodeView.AsStruct()).Error
		if err != nil {
			return nil, fmt.Errorf("saving node: %w", err)
		}

		return nil, nil //nolint:nilnil // side-effect only write
	})
	if err != nil {
		return types.NodeView{}, err
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

	return updatedNodeView, nil
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
		if params.PreAuthKey.IsTagged() {
			// Tagged nodes are owned by their tags, not a user.
			// UserID is intentionally left nil.
			nodeToRegister.Tags = params.PreAuthKey.Tags

			// Tagged nodes have key expiry disabled.
			nodeToRegister.Expiry = nil
		} else {
			// USER-OWNED NODE
			nodeToRegister.UserID = &params.PreAuthKey.User.ID
			nodeToRegister.User = params.PreAuthKey.User
			nodeToRegister.Tags = nil
		}

		nodeToRegister.AuthKey = params.PreAuthKey
		nodeToRegister.AuthKeyID = &params.PreAuthKey.ID
	} else {
		// Non-PreAuthKey registration (OIDC, CLI) - always user-owned
		nodeToRegister.UserID = &params.User.ID
		nodeToRegister.User = &params.User
		nodeToRegister.Tags = nil
	}

	// Reject advertise-tags for PreAuthKey registrations early, before any resource allocation.
	// PreAuthKey nodes get their tags from the key itself, not from client requests.
	if params.PreAuthKey != nil && params.Hostinfo != nil && len(params.Hostinfo.RequestTags) > 0 {
		return types.NodeView{}, fmt.Errorf("%w %v are invalid or not permitted", ErrRequestedTagsInvalidOrNotPermitted, params.Hostinfo.RequestTags)
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
			nodeToRegister.Tags = approvedTags
			slices.Sort(nodeToRegister.Tags)
			nodeToRegister.Tags = slices.Compact(nodeToRegister.Tags)

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
		err := tx.Save(&nodeToRegister).Error
		if err != nil {
			return nil, fmt.Errorf("saving node: %w", err)
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
		}

		return nil
	}

	// Non-empty RequestTags: validate and apply
	var approvedTags, rejectedTags []string

	for _, tag := range requestTags {
		if s.polMan.NodeCanHaveTag(node.View(), tag) {
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
	// Get the registration entry from cache
	regEntry, ok := s.GetAuthCacheEntry(authID)
	if !ok {
		return types.NodeView{}, change.Change{}, hsdb.ErrNodeNotFoundRegistrationCache
	}

	// Get the user
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return types.NodeView{}, change.Change{}, fmt.Errorf("finding user: %w", err)
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
	existingNodeSameUser, nodeExistsForSameUser := all[types.UserID(user.ID)]

	taggedNode, hasTagged := all[0]
	existingNodeIsTagged := hasTagged && taggedNode.IsTagged()

	var existingNodeOtherUser types.NodeView

	existingNodeOwnedByOtherUser := false

	for uid, n := range all {
		if uid != 0 && uid != types.UserID(user.ID) && !n.IsTagged() {
			existingNodeOtherUser = n
			existingNodeOwnedByOtherUser = true
		}
	}

	// A tagged node and a user-owned node cannot legitimately share a machine
	// key (validateNodeOwnership enforces tags XOR user ownership). If both are
	// present the machine key is in a corrupt/ambiguous state; reject rather
	// than converting an arbitrary node and orphaning the other.
	if existingNodeIsTagged && (nodeExistsForSameUser || existingNodeOwnedByOtherUser) {
		return types.NodeView{}, change.Change{}, ErrAmbiguousNodeOwnership
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

	var finalNode types.NodeView

	if nodeExistsForSameUser {
		updateParams.ExistingNode = existingNodeSameUser

		finalNode, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	} else if existingNodeIsTagged {
		updateParams.ExistingNode = taggedNode
		updateParams.IsConvertFromTag = true

		finalNode, err = s.applyAuthNodeUpdate(updateParams)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
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
			return types.NodeView{}, change.Change{}, err
		}
	} else {
		finalNode, err = s.createNewNodeFromAuth(
			logger, user, regData, hostname, hostinfo,
			expiry, registrationMethod, types.NodeView{},
		)
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	}

	// Signal to waiting clients
	regEntry.FinishAuth(types.AuthVerdict{Node: finalNode})

	// Remove from registration cache
	s.authCache.Remove(authID)

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("updating policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("updating policy manager nodes: %w", err)
	}

	policyChanged := !usersChange.IsEmpty() || !nodesChange.IsEmpty()

	// nodeExistsForSameUser is true only for a same-user relogin; a tag->user
	// conversion is excluded, as it changes the peer's User — a structural
	// change peers must see in full, not a key-rotation patch.
	return finalNode, reauthChange(finalNode, nodeExistsForSameUser, policyChanged), nil
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
// matching the PAK's ownership. For user-owned keys it checks the
// user's ID; for tagged keys it checks UserID(0) since tagged nodes
// have no owning user.
func (s *State) findExistingNodeForPAK(
	machineKey key.MachinePublic,
	pak *types.PreAuthKey,
) (types.NodeView, bool, error) {
	all := s.nodeStore.GetNodesByMachineKeyAllUsers(machineKey)

	if pak.User != nil {
		if node, ok := all[types.UserID(pak.User.ID)]; ok {
			return node, true, nil
		}

		// The node may have been converted to a tagged node since it first
		// registered (SetNodeTags clears UserID, re-indexing it under UserID(0)).
		// It is still the same machine, proven by the machine key, so recognise
		// it for re-registration instead of re-validating the spent key or
		// creating a duplicate node. Re-registration preserves the node's tagged
		// ownership. See https://github.com/juanfont/headscale/issues/3312.
		if node, ok := all[0]; ok && node.IsTagged() {
			return node, true, nil
		}

		return types.NodeView{}, false, nil
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

//nolint:gocyclo // sequential validation/update/create paths with security-sensitive ordering
func (s *State) HandleNodeFromPreAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (types.NodeView, change.Change, error) {
	// Serialise registration for this machine so concurrent restarts resolve
	// to a single node rather than racing the find-then-create section.
	defer s.lockRegistration(machineKey)()

	pak, err := s.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	// Helper to get username for logging (handles nil User for tags-only keys)
	pakUsername := func() string {
		if pak.User != nil {
			return pak.User.Username()
		}

		return types.TaggedDevices.Name
	}

	existingNodeSameUser, existsSameUser, err := s.findExistingNodeForPAK(machineKey, pak)
	if err != nil {
		return types.NodeView{}, change.Change{}, err
	}

	// For existing nodes, skip validation if:
	// 1. MachineKey matches (cryptographic proof of machine identity)
	// 2. User/tag ownership matches (from the PAK being used)
	// 3. Not a NodeKey rotation (rotation requires fresh validation)
	//
	// Security: MachineKey is the cryptographic identity. If someone has the MachineKey,
	// they control the machine. The PAK was only needed to authorize initial join.
	// We don't check which specific PAK was used originally because:
	// - Container restarts may use different PAKs (e.g., env var changed)
	// - Original PAK may be deleted
	// - MachineKey + ownership is sufficient to prove this is the same node
	isExistingNodeReregistering := existsSameUser && existingNodeSameUser.Valid()

	// Check if this is a NodeKey rotation (different NodeKey)
	isNodeKeyRotation := existsSameUser && existingNodeSameUser.Valid() &&
		existingNodeSameUser.NodeKey() != regReq.NodeKey

	// An expired node is genuinely re-authenticating, not just waking up, so it
	// must present a valid key. Without this a node that re-uses its NodeKey
	// after expiry would skip validation and be re-authorised with a spent or
	// expired key; the boundary must not depend on the client rotating its key.
	isExpired := existsSameUser && existingNodeSameUser.Valid() &&
		existingNodeSameUser.IsExpired()

	// A tagged key presented for a currently user-owned node converts that node
	// to tagged. That is an ownership change, not a plain refresh, so it must
	// present a valid key rather than ride the skip-validation fast-path.
	isOwnershipConversion := existsSameUser && existingNodeSameUser.Valid() &&
		pak.IsTagged() && !existingNodeSameUser.IsTagged()

	if isExistingNodeReregistering && !isNodeKeyRotation && !isExpired && !isOwnershipConversion {
		// Existing, still-valid node re-registering with same NodeKey: skip
		// validation. Pre-auth keys are only needed for initial authentication.
		// Critical for containers that run "tailscale up --authkey=KEY" on every
		// restart.
		log.Debug().
			Caller().
			Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
			Str(zf.NodeName, existingNodeSameUser.Hostname()).
			Str(zf.MachineKey, machineKey.ShortString()).
			Str(zf.NodeKeyExisting, existingNodeSameUser.NodeKey().ShortString()).
			Str(zf.NodeKeyRequest, regReq.NodeKey.ShortString()).
			Uint64(zf.AuthKeyID, pak.ID).
			Bool(zf.AuthKeyUsed, pak.Used).
			Bool(zf.AuthKeyExpired, pak.Expiration != nil && pak.Expiration.Before(time.Now())).
			Bool(zf.AuthKeyReusable, pak.Reusable).
			Bool(zf.NodeKeyRotation, isNodeKeyRotation).
			Msg("Existing node re-registering with same NodeKey and auth key, skipping validation")
	} else {
		// New node or NodeKey rotation: require valid auth key.
		err = pak.Validate()
		if err != nil {
			return types.NodeView{}, change.Change{}, err
		}
	}

	// Preserve the raw hostname as reported by the client. Sanitisation
	// for the DNS label lives on node.GivenName, not on node.Hostname;
	// see HOSTNAME.md.
	var hostname string
	if regReq.Hostinfo != nil {
		hostname = regReq.Hostinfo.Hostname
	}

	// Ensure we have valid hostinfo
	validHostinfo := cmp.Or(regReq.Hostinfo, &tailcfg.Hostinfo{})
	validHostinfo.Hostname = hostname

	log.Debug().
		Caller().
		Str(zf.NodeName, hostname).
		Str(zf.MachineKey, machineKey.ShortString()).
		Str(zf.NodeKey, regReq.NodeKey.ShortString()).
		Str(zf.UserName, pakUsername()).
		Msg("Registering node with pre-auth key")

	var finalNode types.NodeView

	// If this node exists for this user, update the node in place.
	// Note: For tags-only keys (pak.User == nil), existsSameUser is always false.
	if existsSameUser && existingNodeSameUser.Valid() {
		log.Trace().
			Caller().
			Str(zf.NodeName, existingNodeSameUser.Hostname()).
			Uint64(zf.NodeID, existingNodeSameUser.ID().Uint64()).
			Str(zf.MachineKey, machineKey.ShortString()).
			Str(zf.NodeKey, existingNodeSameUser.NodeKey().ShortString()).
			Str(zf.UserName, pakUsername()).
			Msg("Node re-registering with existing machine key and user, updating in place")

		// Re-registration rotates the NodeKey to the client-supplied value.
		// Enforce the same 1:1 NodeKey<->MachineKey binding the auth path
		// (applyAuthNodeUpdate) and poll-time validation enforce: a NodeKey
		// already bound to a different machine must not be claimed here, or a
		// re-registering node could rotate its key to a victim's and poison the
		// NodeStore NodeKey index, denying the victim service.
		if existing, ok := s.nodeStore.GetNodeByNodeKey(regReq.NodeKey); ok &&
			existing.MachineKey() != machineKey {
			return types.NodeView{}, change.Change{}, ErrNodeKeyInUse
		}

		// Snapshot the pre-update node so the NodeStore can be rolled back if
		// the database write below fails. The view points at the immutable
		// pre-update snapshot (UpdateNode swaps in a new one), so this stays
		// valid after the mutation.
		priorNode := existingNodeSameUser.AsStruct()

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

			// Tags from PreAuthKey are only applied during initial registration.
			// On re-registration the node keeps its existing tags and ownership,
			// except when a tagged key converts a user-owned node: that adopts
			// the key's tags and drops user ownership (tagged nodes are
			// user-less and never expire). Only update AuthKey reference
			// otherwise.
			if pak.IsTagged() && !node.IsTagged() {
				node.Tags = pak.Tags
				node.UserID = nil
				node.User = nil
				node.Expiry = nil
			}

			node.AuthKey = pak
			node.AuthKeyID = &pak.ID
			// Do NOT reset IsOnline here. Online status is managed exclusively by
			// [State.Connect]/[State.Disconnect] in the poll session lifecycle.
			// Resetting it during re-registration causes a false offline blip
			// to peers.
			node.LastSeen = new(time.Now())

			// Tagged nodes keep their existing expiry (disabled).
			// User-owned nodes update expiry from the client request,
			// falling back to the configured default if the client
			// did not request a specific expiry. If neither is set,
			// clear the expiry so the database holds NULL instead of
			// a pointer to zero time.
			if !node.IsTagged() {
				if !regReq.Expiry.IsZero() {
					node.Expiry = &regReq.Expiry
				} else if s.cfg.Node.Expiry > 0 {
					exp := time.Now().Add(s.cfg.Node.Expiry)
					node.Expiry = &exp
				} else {
					node.Expiry = nil
				}
			}
		})

		if !ok {
			return types.NodeView{}, change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, existingNodeSameUser.ID())
		}

		_, err = hsdb.Write(s.db.DB, func(tx *gorm.DB) (*types.Node, error) {
			// Explicitly select all node columns so GORM includes nil/zero-value fields
			// (see nodeUpdateColumns comment).
			err := tx.Select(nodeUpdateColumns).Updates(updatedNodeView.AsStruct()).Error
			if err != nil {
				return nil, fmt.Errorf("saving node: %w", err)
			}

			// Only mark the key used on the *first* registration. On
			// re-registration the same key is already used and the
			// atomic compare-and-set in [hsdb.UsePreAuthKey] would otherwise
			// reject it as "authkey already used". This is the path
			// behind issue #2830 where containers restart with the
			// same one-shot key.
			if !pak.Reusable && !pak.Used {
				err = hsdb.UsePreAuthKey(tx, pak)
				if err != nil {
					return nil, fmt.Errorf("using pre auth key: %w", err)
				}
			}

			return nil, nil //nolint:nilnil // intentional: transaction success
		})
		if err != nil {
			// The NodeStore was updated before the database write. Roll it back
			// so it does not advertise a registration the database rejected
			// (e.g. a node key that a restart would not reload).
			if priorNode != nil {
				s.nodeStore.PutNode(*priorNode)
			}

			return types.NodeView{}, change.Change{}, fmt.Errorf("writing node to database: %w", err)
		}

		log.Trace().
			Caller().
			Str(zf.NodeName, updatedNodeView.Hostname()).
			Uint64(zf.NodeID, updatedNodeView.ID().Uint64()).
			Str(zf.MachineKey, machineKey.ShortString()).
			Str(zf.NodeKey, updatedNodeView.NodeKey().ShortString()).
			Str(zf.UserName, pakUsername()).
			Msg("Node re-authorized")

		finalNode = updatedNodeView
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
				Str(zf.NewUser, pakUsername()).
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
			ExistingNodeForNetinfo: differentUserNode,
		})
		if err != nil {
			return types.NodeView{}, change.Change{}, fmt.Errorf("creating new node: %w", err)
		}
	}

	// Update policy managers
	usersChange, err := s.updatePolicyManagerUsers()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("updating policy manager users: %w", err)
	}

	nodesChange, err := s.updatePolicyManagerNodes()
	if err != nil {
		return finalNode, change.NodeAdded(finalNode.ID()), fmt.Errorf("updating policy manager nodes: %w", err)
	}

	policyChanged := !usersChange.IsEmpty() || !nodesChange.IsEmpty()

	return finalNode, reauthChange(finalNode, existsSameUser, policyChanged), nil
}

// reauthChange returns the [change.Change] to broadcast after an authentication
// that updated or created a node.
//
// A pure relogin (isRelogin: an existing node, same user, with only its NodeKey
// rotated) is sent as a minimal incremental peer patch via [change.NodeKeyRotated]
// rather than re-advertising the whole node. A policy change forces a full
// recompute; any other (new) node is a whole-node add.
func reauthChange(node types.NodeView, isRelogin, policyChanged bool) change.Change {
	switch {
	case policyChanged:
		return change.PolicyChange()
	case isRelogin:
		return change.NodeKeyRotated(node)
	default:
		return change.NodeAdded(node.ID())
	}
}

// updatePolicyManagerUsers updates the policy manager with current users.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for users.
// updatePolicyManagerUsers refreshes the policy manager with current user data.
func (s *State) updatePolicyManagerUsers() (change.Change, error) {
	users, err := s.ListAllUsers()
	if err != nil {
		return change.Change{}, fmt.Errorf("listing users for policy update: %w", err)
	}

	log.Debug().Caller().Int("user.count", len(users)).Msg("policy manager user update initiated because user list modification detected")

	changed, err := s.polMan.SetUsers(users)
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager users: %w", err)
	}

	log.Debug().Caller().Bool("policy.changed", changed).Msg("policy manager user update completed because SetUsers operation finished")

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

// updatePolicyManagerNodes updates the policy manager with current nodes.
// Returns true if the policy changed and notifications should be sent.
// TODO(kradalby): This is a temporary stepping stone, ultimately we should
// have the list already available so it could go much quicker. Alternatively
// the policy manager could have a remove or add list for nodes.
// updatePolicyManagerNodes refreshes the policy manager with current node data.
func (s *State) updatePolicyManagerNodes() (change.Change, error) {
	nodes := s.ListNodes()

	changed, err := s.polMan.SetNodes(nodes)
	if err != nil {
		return change.Change{}, fmt.Errorf("updating policy manager nodes: %w", err)
	}

	if changed {
		// Rebuild peer maps because policy-affecting node changes (tags, user, IPs)
		// affect ACL visibility. Without this, cached peer relationships use stale data.
		s.nodeStore.RebuildPeerMaps()
		return change.PolicyChange(), nil
	}

	return change.Change{}, nil
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
func (s *State) autoApproveNodes() ([]change.Change, error) {
	nodes := s.ListNodes()

	// Compute every node's approval first, then apply them all in a single
	// NodeStore batch and a single policy/peer-map rebuild. One
	// SetApprovedRoutes per node would otherwise drive an O(n) policy SetNodes
	// and O(n^2) peer-map rebuild for each changed node, i.e. O(m*n^2) per
	// policy reload.
	approvedByID := make(map[types.NodeID][]netip.Prefix)

	for _, nv := range nodes.All() {
		approved, changed := policy.ApproveRoutesWithPolicy(s.polMan, nv, nv.ApprovedRoutes().AsSlice(), nv.AnnouncedRoutes())
		if !changed {
			continue
		}

		log.Debug().
			Uint64(zf.NodeID, nv.ID().Uint64()).
			Str(zf.NodeName, nv.Hostname()).
			Strs(zf.RoutesApprovedOld, util.PrefixesToString(nv.ApprovedRoutes().AsSlice())).
			Strs(zf.RoutesApprovedNew, util.PrefixesToString(approved)).
			Msg("Routes auto-approved by policy")

		approvedByID[nv.ID()] = approved
	}

	if len(approvedByID) == 0 {
		return nil, nil
	}

	updates := make(map[types.NodeID]UpdateNodeFunc, len(approvedByID))
	for id, approved := range approvedByID {
		updates[id] = func(n *types.Node) {
			n.ApprovedRoutes = approved

			// A node with no approved routes is no longer an HA candidate;
			// drop any stale Unhealthy bit (mirrors SetApprovedRoutes).
			if len(n.AllApprovedRoutes()) == 0 {
				n.Unhealthy = false
			}
		}
	}

	s.nodeStore.UpdateNodes(updates)

	for id := range approvedByID {
		fresh, ok := s.nodeStore.GetNode(id)
		if !ok {
			continue
		}

		_, err := s.persistNodeRowToDB(fresh)
		if err != nil {
			return nil, err
		}
	}

	c, err := s.updatePolicyManagerNodes()
	if err != nil {
		return nil, err
	}

	if c.IsEmpty() {
		c = change.PolicyChange()
	}

	return []change.Change{c}, nil
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
// When a field is added to this function, remember to also add it to:
// - node.PeerChangeFromMapRequest
// - node.ApplyPeerChange
// - logTracePeerChange in poll.go.
func (s *State) UpdateNodeFromMapRequest(id types.NodeID, req tailcfg.MapRequest) (change.Change, error) { //nolint:gocyclo // central map-request reconciliation; the sequential branch flow reads clearer as one function than split across helpers
	log.Trace().
		Caller().
		Uint64(zf.NodeID, id.Uint64()).
		Interface("request", req).
		Msg("Processing MapRequest for node")

	var (
		routeChange        bool
		hostinfoChanged    bool
		needsRouteApproval bool
		autoApprovedRoutes []netip.Prefix
		endpointChanged    bool
		derpChanged        bool
		persistWorthy      bool
	)
	// Snapshot the primary assignment so we can tell whether the
	// Hostinfo + auto-approval that follows shifted any prefix.
	prevRoutes := s.nodeStore.PrimaryRoutes()

	// We need to ensure we update the node as it is in the [NodeStore] at
	// the time of the request.
	updatedNode, ok := s.nodeStore.UpdateNode(id, func(currentNode *types.Node) {
		peerChange := currentNode.PeerChangeFromMapRequest(req)

		// Track what specifically changed. An endpoint delta is only
		// broadcast-worthy when it adds a useful (non-STUN) endpoint;
		// STUN-only churn and pure shrinks are suppressed to reduce peer
		// churn (see endpointBroadcastWorthy). The new set is still stored
		// via ApplyPeerChange below regardless of this decision.
		endpointChanged = peerChange.Endpoints != nil &&
			endpointBroadcastWorthy(currentNode.Endpoints, req.Endpoints, req.EndpointTypes)
		derpChanged = peerChange.DERPRegion != 0
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

		// A change carrying only an updated LastSeen is not worth a full-row
		// database UPDATE plus the O(n) policy rescan persistNodeToDB triggers:
		// LastSeen is best-effort and rides along the next substantive write.
		// PeerChangeFromMapRequest always stamps LastSeen, so test the other
		// fields explicitly.
		persistWorthy = peerChangePersistWorthy(peerChange) || hostinfoChanged

		// If there is no changes and nothing to save,
		// return early.
		if peerChangeEmpty(peerChange) && !hostinfoChanged {
			return
		}

		// Calculate route approval before [NodeStore] update to avoid calling View() inside callback
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
						Uint64(zf.NodeID, id.Uint64()).
						Strs(zf.OldAnnouncedRoutes, util.PrefixesToString(currentNode.AnnouncedRoutes())).
						Strs(zf.NewAnnouncedRoutes, util.PrefixesToString(hi.RoutableIPs)).
						Strs(zf.ApprovedRoutes, util.PrefixesToString(currentNode.ApprovedRoutes)).
						Bool(zf.RouteChanged, routeChange).
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
			if req.Hostinfo != nil && req.Hostinfo.Hostname != "" {
				// Preserve an admin-renamed GivenName: only auto-derive when the
				// current GivenName is still what SanitizeHostname of the old
				// Hostname would produce (possibly with a "-N" collision bump).
				autoDerived := isAutoDerivedGivenName(currentNode.GivenName, currentNode.Hostname)

				currentNode.Hostname = req.Hostinfo.Hostname
				if autoDerived {
					currentNode.GivenName = dnsname.SanitizeHostname(req.Hostinfo.Hostname)
					// [NodeStore.UpdateNode] auto-bumps GivenName on collision.
				}
			}

			if routeChange {
				// Apply pre-calculated route approval
				// Always apply the route approval result to ensure consistency,
				// regardless of whether the policy evaluation detected changes.
				// This fixes the bug where routes weren't properly cleared when
				// auto-approvers were removed from the policy.
				log.Info().
					Uint64(zf.NodeID, id.Uint64()).
					Strs(zf.OldApprovedRoutes, util.PrefixesToString(currentNode.ApprovedRoutes)).
					Strs(zf.NewApprovedRoutes, util.PrefixesToString(autoApprovedRoutes)).
					Bool(zf.RouteChanged, routeChange).
					Msg("applying route approval results")
			}
		}

		// AllApprovedRoutes is announced ∩ approved; a Hostinfo
		// update that shrinks the announced set can drop the node
		// out of HA candidacy without touching ApprovedRoutes.
		// Clear any stale Unhealthy bit in that case.
		if len(currentNode.AllApprovedRoutes()) == 0 {
			currentNode.Unhealthy = false
		}
	})

	if !ok {
		return change.Change{}, fmt.Errorf("%w: %d", ErrNodeNotInNodeStore, id)
	}

	if routeChange {
		log.Debug().
			Uint64(zf.NodeID, id.Uint64()).
			Strs(zf.AutoApprovedRoutes, util.PrefixesToString(autoApprovedRoutes)).
			Msg("Persisting auto-approved routes from MapRequest")

		// [State.SetApprovedRoutes] will update both database and PrimaryRoutes table
		_, c, err := s.SetApprovedRoutes(id, autoApprovedRoutes)
		if err != nil {
			return change.Change{}, fmt.Errorf("persisting auto-approved routes: %w", err)
		}

		// If [State.SetApprovedRoutes] resulted in a policy change, return it
		if !c.IsEmpty() {
			return c, nil
		}
	} // Continue with the rest of the processing using the updated node

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
	// policy SetNodes scan that persistNodeToDB performs.
	policyChange := change.Change{}

	if persistWorthy {
		var err error

		_, policyChange, err = s.persistNodeToDB(updatedNode)
		if err != nil {
			return change.Change{}, fmt.Errorf("saving to database: %w", err)
		}
	}

	if !policyChange.IsEmpty() {
		return policyChange, nil
	}

	if !nodeRouteChange.IsEmpty() {
		return nodeRouteChange, nil
	}

	// Determine the most specific change type based on what actually changed.
	// This allows us to send lightweight patch updates instead of full map responses.
	return buildMapRequestChangeResponse(id, updatedNode, hostinfoChanged, endpointChanged, derpChanged)
}

// endpointBroadcastWorthy reports whether an endpoint-only delta is worth
// fanning out to peers as an incremental PeersChangedPatch. A delta that only
// adds STUN-derived endpoints — or only removes endpoints — is suppressed:
// bare STUN endpoints are unlikely to be open and churn a lot (the client
// re-derives those paths over disco anyway), and a pure shrink is not worth
// telling peers about. Suppressing this churn keeps peers' views stable.
//
// The decision is intentionally conservative: it gates the broadcast only,
// not storage. The node's full endpoint set (STUN included) is still stored
// and rides along the next substantive change or full MapResponse, so no
// reachable path is permanently hidden from peers.
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

// buildMapRequestChangeResponse determines the appropriate response type for a [tailcfg.MapRequest] update.
// Hostinfo changes require a full update, while endpoint/DERP changes can use lightweight patches.
func buildMapRequestChangeResponse(
	id types.NodeID,
	node types.NodeView,
	hostinfoChanged, endpointChanged, derpChanged bool,
) (change.Change, error) {
	// Hostinfo changes require NodeAdded (full update) as they may affect many fields.
	if hostinfoChanged {
		return change.NodeAdded(id), nil
	}

	// Return specific change types for endpoint and/or DERP updates.
	if endpointChanged || derpChanged {
		patch := &tailcfg.PeerChange{NodeID: id.NodeID()}

		if endpointChanged {
			patch.Endpoints = node.Endpoints().AsSlice()
		}

		if derpChanged {
			if hi := node.Hostinfo(); hi.Valid() {
				if ni := hi.NetInfo(); ni.Valid() {
					patch.DERPRegion = ni.PreferredDERP()
				}
			}
		}

		return change.EndpointOrDERPUpdate(id, patch), nil
	}

	return change.NodeAdded(id), nil
}

func hostinfoEqual(oldNode types.NodeView, newHI *tailcfg.Hostinfo) bool {
	if !oldNode.Valid() && newHI == nil {
		return true
	}

	if !oldNode.Valid() || newHI == nil {
		return false
	}

	old := oldNode.AsStruct().Hostinfo

	return old.Equal(newHI)
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

func peerChangeEmpty(peerChange tailcfg.PeerChange) bool {
	return peerChange.Key == nil &&
		peerChange.DiscoKey == nil &&
		peerChange.Online == nil &&
		peerChange.Endpoints == nil &&
		peerChange.DERPRegion == 0 &&
		peerChange.LastSeen == nil &&
		peerChange.KeyExpiry == nil
}

// peerChangePersistWorthy reports whether a peer change carries anything that
// warrants a database write. It deliberately ignores LastSeen, which
// [Node.PeerChangeFromMapRequest] always stamps: a keepalive that only bumps
// LastSeen should not trigger a full-row UPDATE and policy rescan.
func peerChangePersistWorthy(peerChange tailcfg.PeerChange) bool {
	return peerChange.Key != nil ||
		peerChange.DiscoKey != nil ||
		peerChange.Online != nil ||
		peerChange.Endpoints != nil ||
		peerChange.DERPRegion != 0 ||
		peerChange.KeyExpiry != nil
}
