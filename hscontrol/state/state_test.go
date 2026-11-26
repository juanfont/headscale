package state

import (
	"errors"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/set"
)

// eachDatabase runs test on a State on SQLite and on one on PostgreSQL.
func eachDatabase(t *testing.T, test func(t *testing.T, s *State)) {
	t.Helper()

	eachDatabaseWith(t, func(*types.Config) {}, test)
}

// eachDatabaseWith is [eachDatabase] with the configuration changed by tune.
func eachDatabaseWith(t *testing.T, tune func(*types.Config), test func(t *testing.T, s *State)) {
	t.Helper()

	run := func(t *testing.T, cfg *types.Config) {
		t.Helper()
		tune(cfg)

		s, err := NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		test(t, s)
	}

	t.Run("sqlite", func(t *testing.T) { run(t, persistTestConfig(t.TempDir()+"/headscale.db")) })
	t.Run("postgres", func(t *testing.T) { run(t, postgresTestConfig(t)) })
}

// usersPM records the users the policy manager was last given.
type usersPM struct {
	policy.PolicyManager

	mu    sync.Mutex
	users []types.User
}

func (p *usersPM) SetUsers(users []types.User) (bool, bool, error) {
	p.mu.Lock()
	p.users = slices.Clone(users)
	p.mu.Unlock()

	return p.PolicyManager.SetUsers(users)
}

func (p *usersPM) has(id uint) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	return slices.ContainsFunc(p.users, func(u types.User) bool { return u.ID == id })
}

func recordUsers(s *State) *usersPM {
	pm := &usersPM{}

	s.WrapPolicyManagerForTest(func(inner policy.PolicyManager) policy.PolicyManager {
		pm.PolicyManager = inner

		return pm
	})

	return pm
}

func registerWithKey(s *State, secret string) (types.NodeView, error) {
	nv, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "node"},
	}, key.NewMachine().Public())

	return nv, err
}

// requireUserGone holds that nothing of the user del removed is left: not
// in the database, the NodeStore, the address allocator or the policy
// manager; that every node it removed was announced as removed; and that
// every node that is left keeps its addresses.
func requireUserGone(t *testing.T, s *State, pm *usersPM, del *UserDeletion, changes []change.Change) {
	t.Helper()

	uid := del.User.ID

	_, err := s.GetUserByID(types.UserID(uid))
	require.Error(t, err, "the user is gone")

	var left int64

	require.NoError(t, s.db.DB.Model(&types.Node{}).Where("user_id = ? OR created_by_user_id = ?", uid, uid).Count(&left).Error)
	require.Zero(t, left, "no node row names the user")
	require.NoError(t, s.db.DB.Model(&types.Credential{}).Where("user_id = ? OR created_by_user_id = ?", uid, uid).Count(&left).Error)
	require.Zero(t, left, "no credential row names the user")

	require.Zero(t, s.ListNodesByUser(types.UserID(uid)).Len(), "the NodeStore has no node of the user")

	gone := set.SetOf(del.AuthKeys)
	for _, n := range s.ListNodes().All() {
		require.False(t, refersTo(n, uid, gone), "node %d names the user or a key of it", n.ID())

		for _, ip := range n.IPs() {
			require.True(t, s.ipAlloc.InUseForTesting(ip), "node %d keeps %s", n.ID(), ip)
		}
	}

	removed := set.Set[types.NodeID]{}

	for _, c := range changes {
		removed.AddSlice(c.DeletedNodes)
	}

	for _, n := range del.Nodes {
		_, ok := s.GetNodeByID(n.ID)
		require.False(t, ok, "node %d left the NodeStore", n.ID)
		require.True(t, removed.Contains(n.ID), "the delete of node %d is sent", n.ID)

		for _, ip := range n.IPs() {
			require.False(t, s.ipAlloc.InUseForTesting(ip), "node %d's %s is free", n.ID, ip)
		}
	}

	require.False(t, pm.has(uid), "the policy manager forgot the user")
}

// loginNewNode registers a new node for user through the login path.
func loginNewNode(s *State, user *types.User) (types.NodeView, error) {
	authID := types.MustAuthID()

	err := s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "login",
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "login"},
	}))
	if err != nil {
		return types.NodeView{}, err
	}

	nv, _, err := s.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, util.RegisterMethodOIDC)

	return nv, err
}

// TestDeleteUserTakesANodeThatRegisters: a node whose row is written for
// the user before the delete starts, and that is not yet in the NodeStore,
// holds the delete until it is; the delete then removes and reports it. No
// sleep: the registration waits inside, after its row committed, until the
// delete is queued on the lock. Both ways a node joins a user: an auth key
// and a login.
func TestDeleteUserTakesANodeThatRegisters(t *testing.T) {
	joins := map[string]func(s *State, user *types.User, secret string) (types.NodeView, error){
		"auth key": func(s *State, _ *types.User, secret string) (types.NodeView, error) {
			return registerWithKey(s, secret)
		},
		"login": func(s *State, user *types.User, _ string) (types.NodeView, error) { return loginNewNode(s, user) },
	}

	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		pm := recordUsers(s)

		for name, join := range joins {
			user := s.CreateUserForTest(strings.ReplaceAll(name, " ", "-"))

			pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			first, err := registerWithKey(s, pak.Key)
			require.NoError(t, err)

			type result struct {
				del     *UserDeletion
				changes []change.Change
				err     error
			}

			done := make(chan result, 1)

			s.SetNodeInsertedHookForTesting(func() {
				s.SetNodeInsertedHookForTesting(nil)

				// The registration holds the lock from its row to the
				// NodeStore, or a delete could run in between.
				if s.ownersMu.TryLock() {
					s.ownersMu.Unlock()
					t.Errorf("%s: a registration runs without the owners lock", name)
				}

				go func() {
					del, changes, err := s.DeleteUserIf(types.UserID(user.ID), true, false, "")
					done <- result{del, changes, err}
				}()

				// Until the delete waits for the lock, or, with no lock, ends.
				for len(done) == 0 {
					if !s.ownersMu.TryRLock() {
						return
					}

					s.ownersMu.RUnlock()
					runtime.Gosched()
				}
			})

			second, err := join(s, user, pak.Key)
			require.NoError(t, err, name)

			r := <-done
			require.NoError(t, r.err, name)
			require.Equal(t, []types.NodeID{first.ID(), second.ID()}, nodeIDs(r.del.Nodes), "%s: the delete reports both", name)
			requireUserGone(t, s, pm, r.del, r.changes)
		}
	})
}

// TestDeleteUserRaces: registrations, key creates and a node delete run
// at once with the delete of their user. Whatever won, nothing of the user
// is left, every node or key made for it is one the delete reports, and a
// node another delete removed is not reported.
func TestDeleteUserRaces(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		pm := recordUsers(s)

		for round := range 10 {
			user := s.CreateUserForTest("u" + strconv.Itoa(round))
			uid := types.UserID(user.ID)

			pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			first, err := registerWithKey(s, pak.Key)
			require.NoError(t, err)

			var (
				wg         sync.WaitGroup
				mu         sync.Mutex
				nodes      []types.NodeID
				keys       []uint64
				deleted    bool
				nodeErr    error
				del        *UserDeletion
				changes    []change.Change
				userDelErr error
			)

			start := make(chan struct{})

			for range 4 {
				wg.Go(func() {
					<-start

					nv, err := registerWithKey(s, pak.Key)
					if err == nil {
						mu.Lock()

						nodes = append(nodes, nv.ID())
						mu.Unlock()
					}
				})
				wg.Go(func() {
					<-start

					k, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
					if err == nil {
						mu.Lock()

						keys = append(keys, k.ID)
						mu.Unlock()
					}
				})
			}

			wg.Go(func() {
				<-start

				var cs []change.Change

				cs, nodeErr = s.DeleteNode(first)
				deleted = len(cs) > 0
			})
			wg.Go(func() {
				<-start

				del, changes, userDelErr = s.DeleteUserIf(uid, true, false, "")
			})

			close(start)
			wg.Wait()

			require.NoError(t, nodeErr)
			require.NoError(t, userDelErr)

			reported := nodeIDs(del.Nodes)
			require.Equal(t, !deleted, slices.Contains(reported, first.ID()), "round %d: the first node is removed once", round)

			for _, id := range nodes {
				require.Contains(t, reported, id, "round %d: a node that registered is reported", round)
			}

			for _, id := range keys {
				require.Contains(t, del.AuthKeys, id, "round %d: a key that was made is reported", round)
			}

			requireUserGone(t, s, pm, del, changes)
			require.Zero(t, s.ListNodes().Len(), "round %d: no node is left", round)
		}
	})
}

// TestDeleteUserHoldsOthersForATick: at the production tick of the
// NodeStore, the delete of a user with fifty nodes, and a registration of
// another user that waits for it, each take a few ticks, not one a node.
// The bound is in ticks, eight of them against fifty a node at a time, so
// a slow machine does not break it.
func TestDeleteUserHoldsOthersForATick(t *testing.T) {
	tick := config.Default().Tuning.NodeStoreBatchTimeout

	eachDatabaseWith(t, func(cfg *types.Config) {
		cfg.Tuning.NodeStoreBatchSize = config.Default().Tuning.NodeStoreBatchSize
		cfg.Tuning.NodeStoreBatchTimeout = tick
	}, func(t *testing.T, s *State) {
		t.Helper()

		pm := recordUsers(s)

		victim := s.CreateUserForTest("victim")
		pak, err := s.CreatePreAuthKey(victim.TypedID(), true, false, nil, nil)
		require.NoError(t, err)

		other := s.CreateUserForTest("other")
		otherKey, err := s.CreatePreAuthKey(other.TypedID(), true, false, nil, nil)
		require.NoError(t, err)

		// At once, so they share the writer's batches.
		var g errgroup.Group
		for range 50 {
			g.Go(func() error {
				_, err := registerWithKey(s, pak.Key)

				return err
			})
		}

		require.NoError(t, g.Wait())

		type result struct {
			del     *UserDeletion
			changes []change.Change
			err     error
			took    time.Duration
		}

		done := make(chan result, 1)

		go func() {
			start := time.Now()

			del, changes, err := s.DeleteUserIf(types.UserID(victim.ID), true, false, "")
			done <- result{del, changes, err, time.Since(start)}
		}()

		// Until the delete holds or waits for the owners lock, or ended.
		for len(done) == 0 && s.ownersMu.TryRLock() {
			s.ownersMu.RUnlock()
			runtime.Gosched()
		}

		start := time.Now()
		_, err = registerWithKey(s, otherKey.Key)
		registered := time.Since(start)

		require.NoError(t, err)

		r := <-done
		require.NoError(t, r.err)
		require.Len(t, r.del.Nodes, 50)
		requireUserGone(t, s, pm, r.del, r.changes)

		assert.Less(t, registered, 8*tick, "another user's registration")
		assert.Less(t, r.took, 8*tick, "the delete")
	})
}

// TestDeleteUserDryRunLocksNothing: a dry run reads; it answers while the
// owners lock, the user lock and, on PostgreSQL, the user's row are held,
// so a client that polls it holds up no registration.
func TestDeleteUserDryRunLocksNothing(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("dry")
		uid := types.UserID(user.ID)

		pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
		require.NoError(t, err)

		node, err := registerWithKey(s, pak.Key)
		require.NoError(t, err)

		s.ownersMu.Lock()
		s.userUpdateMu.Lock()

		// SQLite has one connection, which a held transaction would take.
		if s.db.DB.Name() == "postgres" {
			row := s.db.DB.Begin()
			require.NoError(t, row.Exec("SELECT id FROM users WHERE id = ? FOR UPDATE", uid).Error)

			defer row.Rollback()
		}

		done := make(chan *UserDeletion, 1)

		go func() {
			del, _, err := s.DeleteUserIf(uid, true, true, "")
			assert.NoError(t, err)

			done <- del
		}()

		select {
		case del := <-done:
			require.Equal(t, []types.NodeID{node.ID()}, nodeIDs(del.Nodes))
			require.Len(t, del.AuthKeys, 1)
		case <-time.After(30 * time.Second):
			t.Fatal("the dry run waits for a lock")
		}

		s.userUpdateMu.Unlock()
		s.ownersMu.Unlock()
	})
}

// TestDeleteUserBesideATagWrite: a tag write takes a node from its user, so
// it is ordered against the delete of the user. Tagged before the delete
// reads it, the node is the tags' and stays. A tag write sent while the
// delete is between its read and its DELETE waits, then finds the node
// gone; it once committed in that window and answered success for a node
// the delete then removed. A gorm callback holds the delete there; no
// timing.
func TestDeleteUserBesideATagWrite(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		pm := recordUsers(s)

		s.CreateUserForTest("keeper")

		_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:a":["keeper@"]}}`))
		require.NoError(t, err)

		owner := func(name string) (types.UserID, types.NodeView) {
			user := s.CreateUserForTest(name)

			pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			node, err := registerWithKey(s, pak.Key)
			require.NoError(t, err)

			return types.UserID(user.ID), node
		}

		t.Run("tagged before the read", func(t *testing.T) {
			uid, node := owner("tagged-first")

			_, _, err = s.SetNodeTags(node.ID(), []string{"tag:a"})
			require.NoError(t, err)

			del, changes, err := s.DeleteUserIf(uid, true, false, "")
			require.NoError(t, err)
			require.Empty(t, del.Nodes, "a node tagged before the delete is the tags'")
			requireUserGone(t, s, pm, del, changes)

			nv, ok := s.GetNodeByID(node.ID())
			require.True(t, ok, "the tagged node stays")
			require.True(t, nv.IsTagged())
		})

		t.Run("tagged between the read and the DELETE", func(t *testing.T) {
			uid, node := owner("tagged-between")

			tagged := make(chan error, 1)

			var once sync.Once

			const hook = "test:tag-between-read-and-delete"

			require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").Register(hook, func(db *gorm.DB) {
				if db.Statement.Table != "nodes" {
					return
				}

				once.Do(func() {
					go func() {
						_, _, err := s.SetNodeTags(node.ID(), []string{"tag:a"})
						tagged <- err
					}()

					// Until the tag write ended (PostgreSQL, once), waits
					// on the owners lock, or, on SQLite, which has one
					// connection, holds its persist with the node tagged.
					for len(tagged) == 0 && !parkedIn("(*State).SetNodeTagsIf", "sync.RWMutex.RLock") && !persistingTag(s, node.ID()) {
						runtime.Gosched()
					}
				})
			}))
			t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove(hook) })

			del, changes, err := s.DeleteUserIf(uid, true, false, "")
			require.NoError(t, err)
			require.Equal(t, []types.NodeID{node.ID()}, nodeIDs(del.Nodes), "the delete read the node as the user's")
			require.ErrorIs(t, <-tagged, ErrNodeNotFound, "the tag write finds the node gone")
			requireUserGone(t, s, pm, del, changes)

			var rows int64

			require.NoError(t, s.db.DB.Model(&types.Node{}).Where("id = ?", node.ID()).Count(&rows).Error)
			require.Zero(t, rows, "no row comes back")
		})
	})
}

// parkedIn reports whether a goroutine whose stack holds fn waits for
// reason, as a goroutine's header names it.
func parkedIn(fn, reason string) bool {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]

	for g := range strings.SplitSeq(string(buf), "\n\n") {
		header, _, _ := strings.Cut(g, "\n")
		if strings.Contains(header, "["+reason) && strings.Contains(g, fn) {
			return true
		}
	}

	return false
}

// persistingTag reports whether, on SQLite, a tag write of id is in the
// NodeStore and holds persistMu, so it waits for the connection.
func persistingTag(s *State, id types.NodeID) bool {
	if s.cfg.Database.Type != types.DatabaseSqlite {
		return false
	}

	nv, ok := s.nodeStore.GetNode(id)
	if !ok || !nv.IsTagged() {
		return false
	}

	if s.persistMu.TryLock() {
		s.persistMu.Unlock()

		return false
	}

	return true
}

// failingUsersPM fails every SetUsers.
type failingUsersPM struct {
	policy.PolicyManager
}

func (failingUsersPM) SetUsers([]types.User) (bool, bool, error) {
	return false, false, errors.New("policy manager down") //nolint:err113
}

// TestDeleteUserAfterTheCommit: a step that fails after the transaction
// committed is logged, not answered: the delete happened, and its answer
// is what it removed.
func TestDeleteUserAfterTheCommit(t *testing.T) {
	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("late")
	_, err = s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	s.WrapPolicyManagerForTest(func(inner policy.PolicyManager) policy.PolicyManager {
		return failingUsersPM{inner}
	})

	del, changes, err := s.DeleteUserIf(types.UserID(user.ID), false, false, "")
	require.NoError(t, err)
	require.Len(t, del.AuthKeys, 1)
	require.NotEmpty(t, changes)

	_, err = s.GetUserByID(types.UserID(user.ID))
	require.Error(t, err, "the user is gone")
}

// TestDeletePreAuthKeyForgetsItOnNodes: a hard delete of a key clears the
// reference of the nodes that joined with it in the NodeStore, as in their
// rows; an ephemeral key a node refers to is kept, and so is the reference.
func TestDeletePreAuthKeyForgetsItOnNodes(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("keys")

		join := func(ephemeral bool) (types.NodeView, uint64) {
			k, err := s.CreatePreAuthKey(user.TypedID(), true, ephemeral, nil, nil)
			require.NoError(t, err)

			n, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: k.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "joined"},
			}, key.NewMachine().Public())
			require.NoError(t, err)
			require.Equal(t, k.ID, n.AuthKeyID().Get())

			return n, k.ID
		}

		plain, plainKey := join(false)
		eph, ephKey := join(true)

		require.NoError(t, s.DeletePreAuthKey(plainKey))
		require.NoError(t, s.DeletePreAuthKey(ephKey))

		row, err := s.db.GetNodeByID(plain.ID())
		require.NoError(t, err)
		require.Nil(t, row.AuthKeyID)

		got, _ := s.GetNodeByID(plain.ID())
		require.False(t, got.AuthKeyID().Valid(), "the NodeStore forgets the key the row forgot")
		require.False(t, got.AuthKey().Valid())

		got, _ = s.GetNodeByID(eph.ID())
		require.Equal(t, ephKey, got.AuthKeyID().Get(), "control: the kept ephemeral key stays referred to")
	})
}

// TestNodeExpiryWriteThatChangesNothingSendsNothing: a key expiry write that
// leaves what peers see unchanged sends them nothing, as on Tailscale, but
// still stores the time.
func TestNodeExpiryWriteThatChangesNothingSendsNothing(t *testing.T) {
	s := newRetagTestState(t)
	node := s.CreateRegisteredNodeForTest(s.CreateUserForTest("alice"), "quiet")
	s.PutNodeInStoreForTest(*node)

	_, c, err := s.ExpireNodeAt(node.ID, time.Now().Add(time.Hour))
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "a new expiry reaches peers")

	_, c, err = s.SetNodeKeyExpiryDisabled(node.ID, false)
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "key expiry was already on")

	_, c, err = s.SetNodeKeyExpiryDisabled(node.ID, true)
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "turning key expiry off reaches peers")

	// An expire while key expiry is off writes the time only.
	now := time.Now()
	_, c, err = s.SetNodeExpiry(node.ID, &now)
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "peers still see no expiry")

	// v1 stores a literal zero expiry, which peers see as none: turning key
	// expiry off then changes nothing they see.
	zero := s.CreateRegisteredNodeForTest(s.CreateUserForTest("bob"), "zero")
	s.PutNodeInStoreForTest(*zero)

	_, _, err = s.ExpireNodeAt(zero.ID, time.Time{})
	require.NoError(t, err)

	_, c, err = s.SetNodeKeyExpiryDisabled(zero.ID, true)
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "a zero expiry and no expiry look the same to peers")

	stored, err := s.DB().GetNodeByID(node.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Expiry)
	assert.True(t, now.Truncate(time.Microsecond).Equal(stored.Expiry.Truncate(time.Microsecond)))
}

// TestRegistrationCachesFirstUse: the node's copy of its auth key holds the
// first use the claim stored, after a first registration and after a rekey
// onto another key, without a restart.
func TestRegistrationCachesFirstUse(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("first-use")
		machine := key.NewMachine().Public()

		register := func(reusable bool) types.NodeView {
			k, err := s.CreatePreAuthKey(user.TypedID(), reusable, false, nil, nil)
			require.NoError(t, err)

			n, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: k.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "first-use"},
			}, machine)
			require.NoError(t, err)

			stored, err := s.GetPreAuthKeyByID(k.ID)
			require.NoError(t, err)
			require.NotNil(t, stored.FirstUsed, "the claim stores the first use")

			cached, ok := s.GetNodeByID(n.ID())
			require.True(t, ok)
			require.Equal(t, k.ID, cached.AuthKeyID().Get())

			got, ok := cached.AuthKey().FirstUsed().GetOk()
			require.True(t, ok, "the NodeStore's key holds it")
			require.True(t, stored.FirstUsed.Equal(got), "as stored: %s, cached %s", stored.FirstUsed, got)

			return n
		}

		first := register(true)
		rekeyed := register(false)
		require.Equal(t, first.ID(), rekeyed.ID(), "a rekey keeps the node")
	})
}

// TestMergeWriteKeepsALoginsKeyOverACopyChange: a login committed a new key;
// before it was published, the node's copy of its old key changed, as a write
// of the key's own state would change it. The publish still takes the
// login's key; a write that replaced the key keeps its own.
func TestMergeWriteKeepsALoginsKeyOverACopyChange(t *testing.T) {
	oldID, newID, otherID := uint64(1), uint64(2), uint64(3)
	prior := &types.Node{AuthKeyID: &oldID, AuthKey: &types.Credential{ID: oldID}}
	candidate := &types.Node{AuthKeyID: &newID, AuthKey: &types.Credential{ID: newID}}

	stamped := &types.Node{AuthKeyID: &oldID, AuthKey: &types.Credential{ID: oldID, FirstUsed: new(time.Now())}}
	mergeWrite(stamped, prior, candidate)
	require.Equal(t, newID, *stamped.AuthKeyID, "a change to the old key's copy does not undo the login")

	replaced := &types.Node{AuthKeyID: &otherID, AuthKey: &types.Credential{ID: otherID}}
	mergeWrite(replaced, prior, candidate)
	require.Equal(t, otherID, *replaced.AuthKeyID, "a later login's key stays")
}
