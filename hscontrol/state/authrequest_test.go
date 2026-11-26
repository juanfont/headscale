package state

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// pendingRegistration is a waiting registration of a new machine.
func pendingRegistration(t *testing.T, s *State) (types.AuthID, *types.AuthRequest) {
	t.Helper()

	id := types.MustAuthID()
	req := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "pending",
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "pending"},
	})
	require.NoError(t, s.SetAuthCacheEntry(id, req))

	return id, req
}

// pendingSSHCheck is a waiting SSH check; its nodes need not exist.
func pendingSSHCheck(t *testing.T, s *State) (types.AuthID, *types.AuthRequest) {
	t.Helper()

	id := types.MustAuthID()
	req := types.NewSSHCheckAuthRequest(1, 2)
	require.NoError(t, s.SetAuthCacheEntry(id, req))

	return id, req
}

func register(s *State, id types.AuthID, user *types.User) (types.NodeView, error) {
	nv, _, err := s.HandleNodeFromAuthPath(id, types.UserID(user.ID), nil, util.RegisterMethodCLI)

	return nv, err
}

func verdict(t *testing.T, req *types.AuthRequest) types.AuthVerdict {
	t.Helper()

	select {
	case v := <-req.WaitForAuth():
		return v
	default:
		t.Fatal("the request has no verdict")

		return types.AuthVerdict{}
	}
}

func requireOpen(t *testing.T, s *State, id types.AuthID, req *types.AuthRequest) {
	t.Helper()

	got, ok := s.AuthRequest(id)
	require.True(t, ok, "the request still waits")
	require.Same(t, req, got)
}

// requireGone holds that a request reads as gone and that every answer to
// it is refused alike.
func requireGone(t *testing.T, s *State, id types.AuthID, user *types.User) {
	t.Helper()

	_, ok := s.AuthRequest(id)
	require.False(t, ok)
	require.ErrorIs(t, s.AnswerAuthRequest(id, true), hsdb.ErrNodeNotFoundRegistrationCache)
	require.ErrorIs(t, s.AnswerAuthRequest(id, false), hsdb.ErrNodeNotFoundRegistrationCache)
	_, err := register(s, id, user)
	require.ErrorIs(t, err, hsdb.ErrNodeNotFoundRegistrationCache)
}

func TestAuthRequestAnswers(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")

		t.Run("the wrong verb leaves the request waiting", func(t *testing.T) {
			regID, reg := pendingRegistration(t, s)
			sshID, ssh := pendingSSHCheck(t, s)

			require.ErrorIs(t, s.AnswerAuthRequest(regID, true), ErrAuthRequestKind)
			_, err := register(s, sshID, user)
			require.ErrorIs(t, err, ErrAuthRequestKind)

			requireOpen(t, s, regID, reg)
			requireOpen(t, s, sshID, ssh)
		})

		t.Run("approve an SSH check", func(t *testing.T) {
			id, req := pendingSSHCheck(t, s)

			require.NoError(t, s.AnswerAuthRequest(id, true))
			require.True(t, verdict(t, req).Accept())
			requireGone(t, s, id, user)
		})

		for _, kind := range []string{"registration", "ssh check"} {
			t.Run("reject a "+kind, func(t *testing.T) {
				id, req := pendingSSHCheck(t, s)
				if kind == "registration" {
					id, req = pendingRegistration(t, s)
				}

				before := s.ListNodes().Len()

				require.NoError(t, s.AnswerAuthRequest(id, false))
				require.ErrorIs(t, verdict(t, req).Err, ErrAuthRequestRejected)
				requireGone(t, s, id, user)
				require.Equal(t, before, s.ListNodes().Len(), "no node")
			})
		}

		t.Run("register", func(t *testing.T) {
			id, req := pendingRegistration(t, s)

			nv, err := register(s, id, user)
			require.NoError(t, err)
			require.Equal(t, nv.ID(), verdict(t, req).Node.ID())
			requireGone(t, s, id, user)
		})

		t.Run("register for a user that is gone keeps the request", func(t *testing.T) {
			gone := s.CreateUserForTest("gone")
			_, _, err := s.DeleteUserIf(types.UserID(gone.ID), false, false, "")
			require.NoError(t, err)

			id, req := pendingRegistration(t, s)

			_, err = register(s, id, gone)
			require.ErrorIs(t, err, hsdb.ErrUserNotFound)
			requireOpen(t, s, id, req)

			_, err = register(s, id, user)
			require.NoError(t, err)
		})
	})
}

// TestAuthRequestTimesOut: a request that timed out is gone for a read and
// for every answer. The cache measures its age on Go's monotonic clock, so
// no zone enters it.
func TestAuthRequestTimesOut(t *testing.T) {
	eachDatabaseWith(t, func(cfg *types.Config) {
		cfg.Tuning.RegisterCacheExpiration = 50 * time.Millisecond
	}, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")
		regID, _ := pendingRegistration(t, s)
		sshID, _ := pendingSSHCheck(t, s)

		require.Eventually(t, func() bool {
			_, reg := s.AuthRequest(regID)
			_, ssh := s.AuthRequest(sshID)

			return !reg && !ssh
		}, 10*time.Second, 10*time.Millisecond)

		requireGone(t, s, regID, user)
		requireGone(t, s, sshID, user)
	})
}

// TestAuthRequestAnsweredOnce: answers that meet end as one verdict and
// refusals. No sleep: a registration holds the request from its claim to
// its verdict, and the others are started inside it, after the node's row
// committed, and given every chance to run before it goes on.
func TestAuthRequestAnsweredOnce(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		alice := s.CreateUserForTest("alice")
		bob := s.CreateUserForTest("bob")

		t.Run("answers inside a registration", func(t *testing.T) {
			id, req := pendingRegistration(t, s)
			before := s.ListNodes().Len()

			others := make(chan error, 4)

			s.SetNodeInsertedHookForTesting(func() {
				s.SetNodeInsertedHookForTesting(nil)

				go func() { others <- s.AnswerAuthRequest(id, false) }()
				go func() { others <- s.AnswerAuthRequest(id, true) }()
				go func() { others <- s.ResolveAuthRequest(id, types.AuthVerdict{}) }()
				go func() {
					_, err := register(s, id, bob)
					others <- err
				}()

				for range 1000 {
					runtime.Gosched()
				}

				if len(others) > 0 {
					t.Error("an answer ran while the registration held the request")
				}
			})

			nv, err := register(s, id, alice)
			require.NoError(t, err)

			for range 4 {
				require.ErrorIs(t, <-others, hsdb.ErrNodeNotFoundRegistrationCache)
			}

			require.Equal(t, nv.ID(), verdict(t, req).Node.ID())
			require.Equal(t, before+1, s.ListNodes().Len(), "one node")
		})

		t.Run("answers at once", func(t *testing.T) {
			for range 20 {
				id, req := pendingRegistration(t, s)
				before := s.ListNodes().Len()

				var (
					wg     sync.WaitGroup
					mu     sync.Mutex
					wins   int
					winner string
				)

				start := make(chan struct{})
				answer := func(name string, f func() error) {
					wg.Go(func() {
						<-start

						err := f()
						if err == nil {
							mu.Lock()
							wins++
							winner = name
							mu.Unlock()

							return
						}

						if !errors.Is(err, hsdb.ErrNodeNotFoundRegistrationCache) && !errors.Is(err, ErrAuthRequestKind) {
							t.Errorf("unexpected error: %v", err)
						}
					})
				}

				for _, u := range []*types.User{alice, bob} {
					answer("register", func() error { _, err := register(s, id, u); return err })
				}

				answer("reject", func() error { return s.AnswerAuthRequest(id, false) })
				answer("approve", func() error { return s.AnswerAuthRequest(id, true) })
				answer("v1 approve", func() error { return s.ResolveAuthRequest(id, types.AuthVerdict{}) })
				wg.Go(func() {
					<-start
					s.authCache.Remove(id) // the timeout
				})

				close(start)
				wg.Wait()

				// One verdict, and the machine is told the one answer that
				// succeeded; the timeout won when none did.
				v := verdict(t, req)

				switch {
				case wins == 0:
					require.ErrorIs(t, v.Err, ErrRegistrationExpired)
				case winner == "register":
					require.True(t, v.Node.Valid())
				case winner == "reject":
					require.ErrorIs(t, v.Err, ErrAuthRequestRejected)
				case winner == "v1 approve":
					require.True(t, v.Accept())
					require.False(t, v.Node.Valid())
				}

				require.LessOrEqual(t, wins, 1, "one answer")

				if v.Node.Valid() {
					require.Equal(t, before+1, s.ListNodes().Len(), "the registered node")
				} else {
					require.Equal(t, before, s.ListNodes().Len(), "no node")
				}
			}
		})
	})
}

// TestAuthRequestTimesOutWhileHeld: a timeout never waits for an answer
// in progress. An answer that then fails gives the timeout's verdict, so
// the machine is told and no later answer acts on a request that is gone;
// an answer that succeeds stays the one answer.
func TestAuthRequestTimesOutWhileHeld(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")

		t.Run("the answer fails", func(t *testing.T) {
			id, req := pendingRegistration(t, s)

			release, ok := req.Claim()
			require.True(t, ok)

			s.authCache.Remove(id) // what the timeout does
			require.False(t, req.IsFinished(), "the answer still holds it")

			release()
			require.ErrorIs(t, verdict(t, req).Err, ErrRegistrationExpired)
			requireGone(t, s, id, user)
		})

		// The answer is told it timed out: the request no longer waits,
		// whatever made the answer fail.
		t.Run("a register that then fails", func(t *testing.T) {
			gone := s.CreateUserForTest("gone-meanwhile")
			_, _, err := s.DeleteUserIf(types.UserID(gone.ID), false, false, "")
			require.NoError(t, err)

			id, req := pendingRegistration(t, s)

			s.SetAuthRequestClaimedHookForTesting(func() {
				s.SetAuthRequestClaimedHookForTesting(nil)
				s.authCache.Remove(id)
			})

			_, err = register(s, id, gone)
			require.ErrorIs(t, err, hsdb.ErrNodeNotFoundRegistrationCache, "not: the user is gone and the request waits")
			require.ErrorIs(t, verdict(t, req).Err, ErrRegistrationExpired)
			requireGone(t, s, id, user)
		})

		t.Run("a registration succeeds", func(t *testing.T) {
			id, req := pendingRegistration(t, s)

			s.SetNodeInsertedHookForTesting(func() {
				s.SetNodeInsertedHookForTesting(nil)
				s.authCache.Remove(id)
			})

			nv, err := register(s, id, user)
			require.NoError(t, err)
			require.Equal(t, nv.ID(), verdict(t, req).Node.ID(), "the machine is told the node")
		})
	})
}

// TestAuthRequestPanicInTheHold: a register that panics before its verdict
// lets the claim go, as one that fails does: the request still waits and
// can be answered, or the timeout that fired meanwhile reaches the machine.
func TestAuthRequestPanicInTheHold(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")

		t.Run("the request still waits", func(t *testing.T) {
			id, req := pendingRegistration(t, s)

			s.SetAuthRequestClaimedHookForTesting(func() {
				s.SetAuthRequestClaimedHookForTesting(nil)
				panic("in the hold")
			})

			require.Panics(t, func() { _, _ = register(s, id, user) })

			requireOpen(t, s, id, req)

			claimed := make(chan bool, 1)

			go func() {
				release, ok := req.Claim()
				if ok {
					release()
				}

				claimed <- ok
			}()

			// Only a held claim waits here; a free one answers at once.
			select {
			case ok := <-claimed:
				require.True(t, ok, "the claim is free")
			case <-time.After(10 * time.Second):
				t.Fatal("the claim is still held after the panic")
			}

			nv, err := register(s, id, user)
			require.NoError(t, err)
			require.Equal(t, nv.ID(), verdict(t, req).Node.ID(), "a second answer is the one")
		})

		t.Run("a timeout meanwhile reaches the machine", func(t *testing.T) {
			id, req := pendingRegistration(t, s)

			s.SetAuthRequestClaimedHookForTesting(func() {
				s.SetAuthRequestClaimedHookForTesting(nil)
				s.authCache.Remove(id) // what the timeout does
				panic("in the hold")
			})

			require.Panics(t, func() { _, _ = register(s, id, user) })

			require.ErrorIs(t, verdict(t, req).Err, ErrRegistrationExpired)
			requireGone(t, s, id, user)
		})
	})
}

// TestAuthRequestFailsAfterCommit: a register whose node committed and
// then failed still tells the machine its node, and hands the node back
// with the error, as every failure after a commit does.
func TestAuthRequestFailsAfterCommit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")

		// The second node of one hostname gets a bumped name, which is
		// written after the commit.
		first, _ := pendingRegistration(t, s)
		_, err := register(s, first, user)
		require.NoError(t, err)

		id, req := pendingRegistration(t, s)

		s.SetNodeInsertedHookForTesting(func() {
			s.SetNodeInsertedHookForTesting(nil)
			require.NoError(t, s.db.DB.Exec("ALTER TABLE nodes RENAME TO nodes_away").Error)
		})

		nv, err := register(s, id, user)
		require.NoError(t, s.db.DB.Exec("ALTER TABLE nodes_away RENAME TO nodes").Error)

		require.Error(t, err)
		require.True(t, nv.Valid(), "the node is handed back with the error")
		require.Equal(t, nv.ID(), verdict(t, req).Node.ID(), "the machine is told its node")
		requireGone(t, s, id, user)
	})
}

// TestFailedReloginLeavesTheNode: a machine with a node logs in again and the
// node's write fails. The request still waits, and the node is as it was in
// the database, in the NodeStore and to its peers.
func TestFailedReloginLeavesTheNode(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")
		mk := key.NewMachine().Public()
		oldKey := key.NewNode().Public()

		first := types.MustAuthID()
		require.NoError(t, s.SetAuthCacheEntry(first, types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: mk, NodeKey: oldKey, Hostname: "old-host", Hostinfo: &tailcfg.Hostinfo{Hostname: "old-host"},
		})))
		nv, err := register(s, first, user)
		require.NoError(t, err)

		peerID, _ := pendingRegistration(t, s)
		peer, err := register(s, peerID, user)
		require.NoError(t, err)

		id := types.MustAuthID()
		req := types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: mk, NodeKey: key.NewNode().Public(), Hostname: "new-host", Hostinfo: &tailcfg.Hostinfo{Hostname: "new-host"},
		})
		require.NoError(t, s.SetAuthCacheEntry(id, req))

		s.SetAuthRequestClaimedHookForTesting(func() {
			s.SetAuthRequestClaimedHookForTesting(nil)
			require.NoError(t, s.db.DB.Exec("ALTER TABLE nodes RENAME TO nodes_away").Error)
		})

		_, err = register(s, id, user)
		require.NoError(t, s.db.DB.Exec("ALTER TABLE nodes_away RENAME TO nodes").Error)
		require.Error(t, err)
		requireOpen(t, s, id, req)

		row, err := s.db.GetNodeByID(nv.ID())
		require.NoError(t, err)
		require.Equal(t, "old-host", row.Hostname)
		require.Equal(t, oldKey, row.NodeKey)

		live, _ := s.GetNodeByID(nv.ID())
		require.Equal(t, "old-host", live.Hostname(), "the NodeStore agrees with the row")
		require.Equal(t, oldKey, live.NodeKey())

		for _, p := range s.ListPeers(peer.ID()).All() {
			if p.ID() == nv.ID() {
				require.Equal(t, oldKey, p.NodeKey(), "a peer")
			}
		}
	})
}

// TestAuthRequestReplacementSurvivesRegister: the request times out while its
// register holds it and a new one is admitted under the same (debug-chosen)
// ID; the register's removal must leave the replacement waiting.
func TestAuthRequestReplacementSurvivesRegister(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *State) {
		t.Helper()

		user := s.CreateUserForTest("alice")
		id, req := pendingRegistration(t, s)

		repl := types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: key.NewMachine().Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "replacement",
			Hostinfo:   &tailcfg.Hostinfo{Hostname: "replacement"},
		})

		s.SetNodeInsertedHookForTesting(func() {
			s.SetNodeInsertedHookForTesting(nil)
			s.authCache.Remove(id) // what the timeout does
			require.NoError(t, s.SetAuthCacheEntry(id, repl), "same ID admitted again, as debug create-node may")
		})

		nv, err := register(s, id, user)
		require.NoError(t, err)
		require.Equal(t, nv.ID(), verdict(t, req).Node.ID())

		got, ok := s.AuthRequest(id)
		require.True(t, ok, "the replacement still waits")
		require.Same(t, repl, got)
	})
}
