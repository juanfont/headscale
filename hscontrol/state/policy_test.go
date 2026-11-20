package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	policyOpen  = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
	policyOwner = `{"acls": [{"action": "accept", "src": ["persist-user@"], "dst": ["*:*"]}]}`
)

// TestPolicyWriteComparesUnderTheLock: the precondition of a policy write
// and the write run under one exclusive hold of the lock, so no other writer,
// check or registration comes between them. TryRLock shows it without
// timing; a compare before the lock fails it.
func TestPolicyWriteComparesUnderTheLock(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	excluded := func(where string) {
		if s.policyMu.TryRLock() {
			s.policyMu.RUnlock()
			t.Errorf("%s ran without the policy lock held exclusive", where)
		}
	}

	s.SetUpdatePolicyHookForTesting(func() { excluded("the write") })

	_, _, err := s.UpdatePolicyIf([]byte(policyOpen), func(PolicyDocument) bool {
		excluded("the precondition")

		return true
	})
	require.NoError(t, err)

	_, _, err = s.UpdatePolicyIf([]byte(policyOwner), func(PolicyDocument) bool { return false })
	require.ErrorIs(t, err, ErrPolicyPrecondition)
	require.JSONEq(t, policyOpen, s.Policy().Data, "a refused precondition writes nothing")

	_, _, err = s.UpdatePolicyIf([]byte(`{"acls": [`), func(PolicyDocument) bool { return false })
	require.ErrorIs(t, err, ErrPolicyPrecondition, "the precondition is answered before the policy is found invalid")
}

// TestPolicyWritesWithOneETag: writers that read the same policy race; one
// writes, every other is refused by its precondition.
func TestPolicyWritesWithOneETag(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, _, err := s.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	read := s.Policy()
	same := func(d PolicyDocument) bool { return d.Data == read.Data && d.Updated.Equal(*read.Updated) }

	const writers = 8

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		won     int
		refused int
	)

	for i := range writers {
		wg.Go(func() {
			pol := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:` + strconv.Itoa(i+1) + `"]}]}`
			_, _, err := s.UpdatePolicyIf([]byte(pol), same)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrPolicyPrecondition):
				refused++
			default:
				t.Errorf("write %d: %v", i, err)
			}
		})
	}

	wg.Wait()
	require.Equal(t, 1, won)
	require.Equal(t, writers-1, refused)
}

// TestPolicyRefusedAtInstallStoresNothing: a user that appears between the
// check of a write and its install makes a name of the policy ambiguous. The
// install refuses it, and nothing is stored, so a restart cannot install a
// policy that was never in force. Stored before it is installed, it is.
func TestPolicyRefusedAtInstallStoresNothing(t *testing.T) {
	dbPath, s, _ := persistTestSetup(t)

	_, _, err := s.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	before := s.Policy()

	s.SetUpdatePolicyHookForTesting(func() {
		_, _, err := s.CreateUser(types.User{
			Name: "persist-user", Provider: util.RegisterMethodOIDC,
			ProviderIdentifier: sql.NullString{String: "https://idp.example.com/2", Valid: true},
		})
		require.NoError(t, err)
	})

	_, _, err = s.UpdatePolicy([]byte(policyOwner))
	require.ErrorIs(t, err, ErrInvalidPolicy)

	var invalid *InvalidPolicyError
	require.ErrorAs(t, err, &invalid)
	require.JSONEq(t, policyOwner, string(invalid.Policy))

	require.Equal(t, before, s.Policy())
	require.NoError(t, s.Close())

	require.JSONEq(t, policyOpen, persistTestReopen(t, dbPath).Policy().Data, "the policy in force before is the stored one")
}

// TestCheckPolicyIfTakesNoLock: a dry run answers while a policy write holds
// the lock exclusive. With a lock it would wait for the write for ever.
func TestCheckPolicyIfTakesNoLock(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	s.SetUpdatePolicyHookForTesting(func() {
		require.NoError(t, s.CheckPolicyIf([]byte(policyOwner), func(PolicyDocument) bool { return true }))
		require.ErrorIs(t, s.CheckPolicyIf([]byte(policyOwner), func(PolicyDocument) bool { return false }), ErrPolicyPrecondition)
		require.ErrorIs(t, s.CheckPolicyIf([]byte(`{`), nil), ErrInvalidPolicy)
	})

	_, _, err := s.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)
}

// TestRegistrationHoldsThePolicy: a login checks the tags the node asks for
// against the policy and writes the node under the lock of every policy
// write, shared, by auth request and by auth key alike. TryLock inside the
// check and inside the write shows it without timing.
func TestRegistrationHoldsThePolicy(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	users, err := s.ListAllUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)

	user := &users[0]

	_, _, err = s.UpdatePolicy([]byte(`{"tagOwners": {"tag:ci": ["persist-user@"]}}`))
	require.NoError(t, err)

	// sub is the subtest running, which the hooks report to.
	var sub *testing.T

	requireShared := func(what string) {
		if s.policyMu.TryLock() {
			s.policyMu.Unlock()
			sub.Errorf("%s without the policy lock", what)
		}

		if !s.policyMu.TryRLock() {
			sub.Errorf("%s under the policy lock exclusive", what)
		} else {
			s.policyMu.RUnlock()
		}
	}

	var checked, inserted bool

	s.polMan = heldPM{PolicyManager: s.polMan, check: func() {
		checked = true

		requireShared("a tag was checked")
	}}
	s.SetNodeInsertedHookForTesting(func() {
		inserted = true

		requireShared("a node was written")
	})

	logins := map[string]func() error{
		"by auth request": func() error {
			authID := types.MustAuthID()
			require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
				MachineKey: key.NewMachine().Public(),
				NodeKey:    key.NewNode().Public(),
				Hostname:   "login-node",
				Hostinfo:   &tailcfg.Hostinfo{Hostname: "login-node", RequestTags: []string{"tag:ci"}},
			})))

			_, _, err := s.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, util.RegisterMethodCLI)

			return err
		},
		"by auth key": func() error {
			pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			_, _, err = s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "key-node", RequestTags: []string{"tag:ci"}},
			}, key.NewMachine().Public())

			return err
		},
	}

	for name, login := range logins {
		t.Run(name, func(t *testing.T) {
			sub, checked, inserted = t, false, false

			require.NoError(t, login())
			require.True(t, checked, "the tags were checked")
			require.True(t, inserted, "the node was written")
		})
	}
}

// heldPM runs check whenever a tag of a login is checked.
type heldPM struct {
	policy.PolicyManager

	check func()
}

func (p heldPM) NodeCanHaveTag(node types.NodeView, tag string) bool {
	p.check()

	return p.PolicyManager.NodeCanHaveTag(node, tag)
}

func (p heldPM) UserCanHaveTag(user types.UserView, tag string) bool {
	p.check()

	return p.PolicyManager.UserCanHaveTag(user, tag)
}

func (p heldPM) TagOwnedByTags(tag string, owners []string) bool {
	p.check()

	return p.PolicyManager.TagOwnedByTags(tag, owners)
}

// TestPolicyWriteHoldsTheLockBriefly: the peer maps are rebuilt after the
// lock is let go. The rebuild waits for a batch of the NodeStore's writer,
// which every tag write, key create and registration would wait for too.
// Measured at the production batch timeout.
func TestPolicyWriteHoldsTheLockBriefly(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)
	cfg.Tuning.NodeStoreBatchTimeout = 500 * time.Millisecond

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("brief")
	for range 3 {
		s.PutNodeInStoreForTest(*s.CreateRegisteredNodeForTest(user, ""))
	}

	var (
		held    time.Duration
		waiting = make(chan time.Time, 1)
		got     = make(chan time.Time, 1)
	)

	s.SetUpdatePolicyHookForTesting(func() {
		go func() {
			waiting <- time.Now()

			s.policyMu.RLock()

			got <- time.Now()

			s.policyMu.RUnlock()
		}()
	})

	start := time.Now()
	_, _, err = s.UpdatePolicy([]byte(policyOwner))
	require.NoError(t, err)

	asked := <-waiting
	held = (<-got).Sub(asked)
	t.Logf("a reader waited %v for the write; the write took %v", held, time.Since(start))
	require.Less(t, held, cfg.Tuning.NodeStoreBatchTimeout/2, "a policy write held the lock across a batch of the NodeStore")
}

// TestReloadPolicyFile: a file the server refuses leaves the policy in force,
// and says why until a file is installed. A file that cannot be read is
// refused too.
func TestReloadPolicyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(path, []byte(policyOpen), 0o600))

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	want := PolicyDocument{Data: policyOpen, Mode: types.PolicyModeFile, Path: path}
	require.Equal(t, want, s.Policy())
	require.NoError(t, s.PolicySourceError())

	refused := []byte(`{"acls": [`)
	require.NoError(t, os.WriteFile(path, refused, 0o600))

	_, err = s.ReloadPolicy()

	var invalid *InvalidPolicyError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, refused, invalid.Policy)
	require.Equal(t, want, s.Policy(), "the last valid policy stays in force")
	require.ErrorIs(t, s.PolicySourceError(), ErrInvalidPolicy)

	require.NoError(t, os.Remove(path))

	_, err = s.ReloadPolicy()
	require.ErrorIs(t, err, ErrPolicyFileUnreadable)
	require.ErrorIs(t, err, ErrInvalidPolicy)
	require.Equal(t, want, s.Policy())
	require.ErrorIs(t, s.PolicySourceError(), ErrPolicyFileUnreadable)

	require.NoError(t, os.WriteFile(path, []byte(policyOwner), 0o600))

	changes, err := s.ReloadPolicy()
	require.NoError(t, err)
	require.NotEmpty(t, changes)
	require.JSONEq(t, policyOwner, s.Policy().Data)
	require.NoError(t, s.PolicySourceError(), "a valid file clears the warning")
}

// TestPolicyWritesRaceTheirReaders: policy writes, reloads, tag writes and
// key creates run at once. Afterwards the policy in force is the stored
// one, and every write that read the policy succeeded.
func TestPolicyWritesRaceTheirReaders(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	tagged := func(i int) string {
		return `{"tagOwners": {"tag:ci": [], "tag:v` + strconv.Itoa(i) + `": []}}`
	}

	_, _, err := s.UpdatePolicy([]byte(tagged(0)))
	require.NoError(t, err)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	s.PutNodeInStoreForTest(*nv.AsStruct())

	var wg sync.WaitGroup

	for i := range 6 {
		wg.Go(func() {
			_, _, err := s.UpdatePolicy([]byte(tagged(i)))
			require.NoError(t, err)
		})
		wg.Go(func() {
			_, err := s.ReloadPolicy()
			require.NoError(t, err)
		})
		wg.Go(func() {
			_, _, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
			require.NoError(t, err)
		})
		wg.Go(func() {
			_, _, err := s.CreateAuthKeyIf(db.NewPreAuthKey{Tags: []string{"tag:ci"}}, func(TagPolicy) error { return nil })
			require.NoError(t, err)
		})
	}

	wg.Wait()

	stored, err := s.GetPolicy()
	require.NoError(t, err)
	require.Equal(t, stored.Data, s.Policy().Data)
	require.True(t, stored.UpdatedAt.Equal(*s.Policy().Updated))
}

// policyStores is each database a policy is stored in, as a config a test
// can open twice, for a restart. PostgreSQL is skipped where none starts.
func policyStores(t *testing.T, test func(t *testing.T, cfg *types.Config)) {
	t.Helper()

	t.Run("sqlite", func(t *testing.T) { test(t, persistTestConfig(t.TempDir()+"/headscale.db")) })
	t.Run("postgres", func(t *testing.T) {
		cfg := postgresTestConfig(t)
		t.Logf("a PostgreSQL server was made: %s:%d", cfg.Database.Postgres.Host, cfg.Database.Postgres.Port)
		test(t, cfg)
	})
}

// filterOf is the filter pol compiles to against the users and nodes of s,
// nil pol being no policy: what is in force if pol is.
func filterOf(t *testing.T, s *State, pol []byte) []tailcfg.FilterRule {
	t.Helper()

	users, err := s.ListAllUsers()
	require.NoError(t, err)

	pm, err := policy.NewPolicyManager(pol, users, s.ListNodes())
	require.NoError(t, err)

	filter, _ := pm.Filter()

	return filter
}

var errStoreRefused = errors.New("store refused")

// failStore makes every store of a policy fail without writing, as a lost
// database does; before runs inside the write, before its install. The
// returned func undoes it.
func failStore(t *testing.T, s *State, before func()) func() {
	t.Helper()

	s.storePolicy = func(context.Context, string) (*types.Policy, error) { return nil, errStoreRefused }

	if before != nil {
		s.SetUpdatePolicyHookForTesting(before)
	}

	return func() {
		s.SetUpdatePolicyHookForTesting(nil)
		s.storePolicy = s.db.SetPolicyContext
	}
}

// TestPolicyStoreFailsChangesNothing: a write whose store fails leaves in
// force exactly what was, restored as it was kept and not checked again,
// and tells the nodes; a restart installs the same.
func TestPolicyStoreFailsChangesNothing(t *testing.T) {
	policyStores(t, func(t *testing.T, cfg *types.Config) {
		t.Helper()

		s, err := NewState(cfg)
		require.NoError(t, err)

		_, _, err = s.CreateUser(types.User{Name: "persist-user"})
		require.NoError(t, err)

		// Nothing stored yet: "no policy" comes back.
		undo := failStore(t, s, nil)
		_, changes, err := s.UpdatePolicy([]byte(policyOpen))
		require.ErrorContains(t, err, "storing policy")
		require.NotErrorIs(t, err, ErrInvalidPolicy)
		undo()

		require.Equal(t, PolicyDocument{Mode: types.PolicyModeDB}, s.Policy())
		require.Equal(t, filterOf(t, s, nil), mustFilter(s), "no policy is in force again")
		require.Contains(t, changes, change.PolicyChange(), "the nodes are brought back to it")
		require.False(t, s.PolicyNotStored())

		_, _, err = s.UpdatePolicy([]byte(policyOwner))
		require.NoError(t, err)

		before := s.Policy()

		// A user that makes the stored policy ambiguous appears inside the
		// write: putting it back must not check it again.
		undo = failStore(t, s, func() {
			_, _, err := s.CreateUser(types.User{
				Name: "persist-user", Provider: util.RegisterMethodOIDC,
				ProviderIdentifier: sql.NullString{String: "https://idp.example.com/2", Valid: true},
			})
			require.NoError(t, err)
		})
		_, changes, err = s.UpdatePolicy([]byte(policyOpen))
		require.ErrorContains(t, err, "storing policy")
		undo()

		require.Equal(t, before, s.Policy())
		require.Equal(t, filterOf(t, s, []byte(policyOwner)), mustFilter(s), "the policy before is in force, not the open one")
		require.Contains(t, changes, change.PolicyChange())
		require.False(t, s.PolicyNotStored())

		stored, err := s.GetPolicy()
		require.NoError(t, err)
		require.JSONEq(t, policyOwner, stored.Data)

		require.NoError(t, s.Close())

		s, err = NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		require.JSONEq(t, policyOwner, s.Policy().Data, "a restart installs what was in force")
		require.Equal(t, filterOf(t, s, []byte(policyOwner)), mustFilter(s))
	})
}

func mustFilter(s *State) []tailcfg.FilterRule {
	filter, _ := s.Filter()

	return filter
}

// unrestorablePM cannot put a policy back.
type unrestorablePM struct{ policy.PolicyManager }

var errCannotRestore = errors.New("cannot restore")

func (unrestorablePM) RestorePolicy(*policyv2.PreparedPolicy) (bool, error) {
	return false, errCannotRestore
}

// TestPolicyNotStoredIsSaid: should a policy that failed to store not be
// put back, the server says that what is in force is not stored, until a
// write or a reload succeeds.
func TestPolicyNotStoredIsSaid(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, _, err := s.UpdatePolicy([]byte(policyOwner))
	require.NoError(t, err)

	pm := s.polMan
	s.polMan = unrestorablePM{pm}

	undo := failStore(t, s, nil)
	_, _, err = s.UpdatePolicy([]byte(policyOpen))
	require.Error(t, err)
	undo()

	require.True(t, s.PolicyNotStored())

	s.polMan = pm

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	require.False(t, s.PolicyNotStored(), "a reload installs the stored policy")

	s.policyNotStored.Store(true)
	_, _, err = s.UpdatePolicy([]byte(policyOwner))
	require.NoError(t, err)
	require.False(t, s.PolicyNotStored(), "a write stores what it installs")
}

// panickyPM panics inside an install.
type panickyPM struct{ policy.PolicyManager }

func (panickyPM) InstallPolicy(*policyv2.PreparedPolicy) (bool, error) {
	panic("install")
}

// TestPolicyLockSurvivesAPanic: every hold of the policy lock is let go
// when what runs inside it panics, as the server's recoverer keeps the
// process up; held, every login and policy check would wait for ever.
func TestPolicyLockSurvivesAPanic(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, _, err := s.UpdatePolicy([]byte(`{"tagOwners": {"tag:ci": []}}`))
	require.NoError(t, err)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	s.PutNodeInStoreForTest(*nv.AsStruct())

	user := s.CreateUserForTest("login")
	pm := s.polMan

	holds := map[string]func(){
		"write": func() {
			s.polMan = panickyPM{pm}
			defer func() { s.polMan = pm }()

			_, _, _ = s.UpdatePolicy([]byte(policyOpen))
		},
		"reload": func() {
			s.polMan = panickyPM{pm}
			defer func() { s.polMan = pm }()

			_, _ = s.ReloadPolicy()
		},
		"tag write": func() {
			_, _, _ = s.SetNodeTagsIf(nodeID, []string{"tag:ci"}, func(TagPolicy) (string, error) { panic("check") })
		},
		"key create": func() {
			_, _, _ = s.CreateAuthKeyIf(db.NewPreAuthKey{Tags: []string{"tag:ci"}}, func(TagPolicy) error { panic("check") })
		},
		"login": func() {
			s.SetNodeInsertedHookForTesting(func() { panic("insert") })
			defer s.SetNodeInsertedHookForTesting(nil)

			authID := types.MustAuthID()
			require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
				MachineKey: key.NewMachine().Public(),
				NodeKey:    key.NewNode().Public(),
				Hostname:   "panic-node",
			})))

			_, _, _ = s.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, util.RegisterMethodCLI)
		},
		"login by auth key": func() {
			pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			s.SetNodeInsertedHookForTesting(func() { panic("insert") })
			defer s.SetNodeInsertedHookForTesting(nil)

			_, _ = registerWithKey(s, pak.Key)
		},
	}

	for name, hold := range holds {
		// A lock left held would hang every later hold.
		ok := t.Run(name, func(t *testing.T) {
			require.Panics(t, hold)

			if !s.policyMu.TryLock() {
				t.Fatal("the policy lock is held after a panic inside it")
			}

			s.policyMu.Unlock()
		})
		if !ok {
			break
		}
	}
}

// TestPolicyTestsRunOnceBeforeTheLock: the tests of a write run once,
// before the lock; a user that appears between them and the install
// counts as appearing right after the write, but a name of the policy it
// makes ambiguous is refused at the install, which checks the users of
// that moment.
func TestPolicyTestsRunOnceBeforeTheLock(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	prep, err := s.PreparePolicy([]byte(`{
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
  "tests": [{"src": "persist-user@", "accept": ["persist-user@:22"]}]
}`))
	require.NoError(t, err)

	// The test would now fail to resolve its source, as two users match;
	// the install does not run it again.
	_, _, err = s.CreateUser(types.User{
		Name: "persist-user", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/2", Valid: true},
	})
	require.NoError(t, err)

	_, _, err = s.WritePolicyIf(prep, nil)
	require.NoError(t, err, "the tests ran before the lock and are not run under it")
}

// TestPolicyWriteHoldIsIndependentOfTests: the exclusive hold of a write of
// a policy with 4,000 tests over 100 nodes holds no test: it is about that
// of the same text with the tests in a comment, where the tests alone take
// far longer; and
// what one write costs a login that arrives while it waits for a login
// before it, at the production tick.
func TestPolicyWriteHoldIsIndependentOfTests(t *testing.T) {
	if testing.Short() {
		t.Skip("measures a policy of 4,000 tests")
	}

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)
	cfg.Tuning.NodeStoreBatchTimeout = 500 * time.Millisecond

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	for u := range 10 {
		user := database.CreateUserForTest("u" + strconv.Itoa(u))
		for n := range 10 {
			database.CreateRegisteredNodeForTest(user, "n"+strconv.Itoa(u)+"-"+strconv.Itoa(n))
		}
	}

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.Equal(t, 100, s.ListNodes().Len())

	var tests strings.Builder

	for i := range 4000 {
		if i > 0 {
			tests.WriteString(",")
		}

		fmt.Fprintf(&tests, `{"src": "u%d@", "accept": ["u%d@:22"]}`, i%10, (i+1)%10)
	}

	// Each write moves the rules, so each compiles; with and without the
	// tests, the same rules.
	policyOf := func(i int, tests string) []byte {
		return fmt.Appendf(nil, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}, {"action": "accept", "src": ["*"], "dst": ["*:%d"]}], "tests": [%s]}`, 1000+i, tests)
	}

	withTests := tests.String()
	pol := policyOf(0, withTests)

	checkStart := time.Now()

	require.NoError(t, s.ValidatePolicy(pol))

	checked := time.Since(checkStart)

	// hold is how long a write keeps the lock exclusive: from inside it
	// until a reader that asked there gets in.
	hold := func(pol []byte) time.Duration {
		var (
			waiting = make(chan time.Time, 1)
			got     = make(chan time.Time, 1)
		)

		s.SetUpdatePolicyHookForTesting(func() {
			go func() {
				waiting <- time.Now()

				s.policyMu.RLock()

				got <- time.Now()

				s.policyMu.RUnlock()
			}()
		})
		defer s.SetUpdatePolicyHookForTesting(nil)

		_, _, err := s.UpdatePolicy(pol)
		require.NoError(t, err)

		return (<-got).Sub(<-waiting)
	}

	// The same rules and the same bytes, the tests in a comment: what is
	// left between the two holds is the tests.
	commented := func(i int) []byte {
		return append(policyOf(i, ""), "\n// "+withTests+"\n"...)
	}

	// The least of three of each, written in turn, so a stall of the
	// machine counts against neither alone.
	held, bare := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)

	for i := range 3 {
		held = min(held, hold(policyOf(2*i+1, withTests)))
		bare = min(bare, hold(commented(2*i+2)))
	}

	t.Logf("exclusive hold of a write of 4,000 tests over 100 nodes: %v; of the same text with the tests in a comment: %v; their check, tests included, %v", held, bare, checked)
	require.Less(t, held, bare+checked/2, "the write held the lock across its tests")

	// A login holds the lock shared across its NodeStore tick; a write
	// waits for it, and a login after the write waits for both.
	user := s.CreateUserForTest("waiter")
	node := s.CreateRegisteredNodeForTest(user, "waiter-node")
	firstHolds := make(chan struct{})

	go func() {
		s.policyMu.RLock()
		defer s.policyMu.RUnlock()

		close(firstHolds)
		s.PutNodeInStoreForTest(*node)
	}()

	<-firstHolds

	written := make(chan error, 1)

	go func() {
		_, _, err := s.UpdatePolicy(pol)
		written <- err
	}()

	// A writer waiting for the lock keeps new readers out.
	require.Eventually(t, func() bool {
		if s.policyMu.TryRLock() {
			s.policyMu.RUnlock()

			return false
		}

		return true
	}, 10*time.Second, time.Millisecond)

	asked := time.Now()

	s.policyMu.RLock()

	waited := time.Since(asked)

	s.policyMu.RUnlock()

	require.NoError(t, <-written)
	t.Logf("a login that arrived while a write waited for another login waited %v (tick %v)", waited, cfg.Tuning.NodeStoreBatchTimeout)
	require.Less(t, waited, cfg.Tuning.NodeStoreBatchTimeout*3/2)
}

// TestPolicyFileRetriedWhenUsersChange: a refused policy file may have
// been refused because of the users; when they change, the file is to be
// read again, which the server's watch does on this signal.
func TestPolicyFileRetriedWhenUsersChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(path, []byte(policyOpen), 0o600))

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	signalled := func() bool {
		select {
		case <-s.PolicyFileRetry():
			return true
		default:
			return false
		}
	}

	refuse := func(text string) {
		t.Helper()
		require.NoError(t, os.WriteFile(path, []byte(text), 0o600))

		_, err := s.ReloadPolicy()
		require.Error(t, err)
	}

	first, _, err := s.CreateUser(types.User{Name: "first"})
	require.NoError(t, err)
	require.False(t, signalled(), "a file in force needs no second read")

	refuse(`{"acls": [`)

	_, _, err = s.CreateUser(types.User{Name: "second"})
	require.NoError(t, err)
	require.False(t, signalled(), "a file that does not parse cannot pass for other users")

	_, _, err = s.CreateUser(types.User{
		Name: "first", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/first", Valid: true},
	})
	require.NoError(t, err)

	refuse(`{"acls": [{"action": "accept", "src": ["first@"], "dst": ["*:*"]}]}`)

	// What a login does when it changes no user.
	_, err = s.updatePolicyManagerUsers()
	require.NoError(t, err)
	require.False(t, signalled(), "the users did not change")

	_, err = s.DeleteUser(types.UserID(first.ID))
	require.NoError(t, err)
	require.True(t, signalled(), "the users changed, and the refusal was about them")
}

// TestPolicyStoreLandsDespiteError: a store that wrote and then reported an
// error, as a commit the client lost the answer of: the row decides, so the
// policy it holds stays in force, and a restart installs the same.
func TestPolicyStoreLandsDespiteError(t *testing.T) {
	policyStores(t, func(t *testing.T, cfg *types.Config) {
		t.Helper()

		s, err := NewState(cfg)
		require.NoError(t, err)

		_, _, err = s.UpdatePolicy([]byte(policyOwner))
		require.NoError(t, err)

		s.storePolicy = func(ctx context.Context, data string) (*types.Policy, error) {
			_, err := s.db.SetPolicyContext(ctx, data)
			require.NoError(t, err)

			return nil, errStoreRefused
		}

		stored, _, err := s.UpdatePolicy([]byte(policyOpen))
		require.NoError(t, err, "the write landed")
		require.JSONEq(t, policyOpen, stored.Data)

		row, err := s.GetPolicy()
		require.NoError(t, err)
		require.JSONEq(t, policyOpen, row.Data)
		require.JSONEq(t, policyOpen, s.Policy().Data)
		require.True(t, row.UpdatedAt.Equal(*s.Policy().Updated))
		require.Equal(t, filterOf(t, s, []byte(policyOpen)), mustFilter(s))
		require.False(t, s.PolicyNotStored())

		require.NoError(t, s.Close())

		s, err = NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })
		require.JSONEq(t, policyOpen, s.Policy().Data)
	})
}

// TestPolicyStoreUnreadable: a store that failed, and a row that cannot be
// read: the policy before stays in force, and the server says that the
// stored one may differ.
func TestPolicyStoreUnreadable(t *testing.T) {
	policyStores(t, func(t *testing.T, cfg *types.Config) {
		t.Helper()

		s, err := NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		_, _, err = s.UpdatePolicy([]byte(policyOwner))
		require.NoError(t, err)

		before := s.Policy()

		s.storePolicy = func(context.Context, string) (*types.Policy, error) {
			require.NoError(t, s.db.DB.Exec("ALTER TABLE policies RENAME TO policies_gone").Error)

			return nil, errStoreRefused
		}

		_, changes, err := s.UpdatePolicy([]byte(policyOpen))
		require.ErrorIs(t, err, errStoreRefused)
		require.Contains(t, changes, change.PolicyChange())
		require.Equal(t, before, s.Policy())
		require.Equal(t, filterOf(t, s, []byte(policyOwner)), mustFilter(s))
		require.True(t, s.PolicyNotStored())
	})
}

// installPanicPM installs for real, then panics, as a fault after the swap.
type installPanicPM struct{ policy.PolicyManager }

func (p installPanicPM) InstallPolicy(pol *policyv2.PreparedPolicy) (bool, error) {
	_, _ = p.PolicyManager.InstallPolicy(pol)

	panic("after the install")
}

// storePanicPM is a manager whose writes panic in the store, after the
// install; see [TestPolicyPanicAfterInstall].
func TestPolicyPanicAfterInstall(t *testing.T) {
	policyStores(t, func(t *testing.T, cfg *types.Config) {
		t.Helper()

		s, err := NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		_, _, err = s.UpdatePolicy([]byte(policyOwner))
		require.NoError(t, err)

		before := s.Policy()
		pm := s.polMan

		check := func(what string) {
			t.Helper()
			require.Equal(t, before, s.Policy(), what)
			require.Equal(t, filterOf(t, s, []byte(policyOwner)), mustFilter(s), what)
			require.False(t, s.PolicyNotStored(), what)

			row, err := s.GetPolicy()
			require.NoError(t, err)
			require.JSONEq(t, policyOwner, row.Data, what)
		}

		s.polMan = installPanicPM{pm}

		require.Panics(t, func() { _, _, _ = s.UpdatePolicy([]byte(policyOpen)) })

		s.polMan = pm

		check("a panic in the install")

		s.storePolicy = func(context.Context, string) (*types.Policy, error) { panic("in the store") }

		require.Panics(t, func() { _, _, _ = s.UpdatePolicy([]byte(policyOpen)) })

		s.storePolicy = s.db.SetPolicyContext

		check("a panic in the store")
	})
}

// TestPolicyStoreHasADeadline: a store that the database does not answer
// ends at its deadline, under the lock every login waits for, and the
// policy before stays in force.
//
// PostgreSQL only: SQLite has one connection, which a second writer cannot
// hold, and its busy timeout bounds the wait for its file lock.
func TestPolicyStoreHasADeadline(t *testing.T) {
	policyStores(t, func(t *testing.T, cfg *types.Config) {
		t.Helper()

		if cfg.Database.Type != types.DatabasePostgres {
			t.Skip("PostgreSQL only")
		}

		s, err := NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		_, _, err = s.UpdatePolicy([]byte(policyOwner))
		require.NoError(t, err)

		before := policyStoreTimeout
		policyStoreTimeout = 200 * time.Millisecond

		t.Cleanup(func() { policyStoreTimeout = before })

		// Another writer holds the table, as a stalled connection does.
		hold := s.db.DB.Begin()
		require.NoError(t, hold.Error)
		require.NoError(t, hold.Exec("LOCK TABLE policies IN EXCLUSIVE MODE").Error)

		t.Cleanup(func() { hold.Rollback() })

		_, _, err = s.UpdatePolicy([]byte(policyOpen))
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.JSONEq(t, policyOwner, s.Policy().Data)
		require.False(t, s.PolicyNotStored())
	})
}

// windowPM runs window after a real install, as a node that joins while a
// write is between its install and its store.
type windowPM struct {
	policy.PolicyManager

	window func()
}

func (p windowPM) InstallPolicy(pol *policyv2.PreparedPolicy) (bool, error) {
	changed, err := p.PolicyManager.InstallPolicy(pol)
	p.window()

	return changed, err
}

// TestPolicyPutBackRebuildsPeers: a node that joins between the install of
// a write and its failed store has its peers made from the new policy; the
// put-back rebuilds them from the policy in force again.
func TestPolicyPutBackRebuildsPeers(t *testing.T) {
	_, s, ownerNode := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	closed := `{"acls": [{"action": "accept", "src": ["persist-user@"], "dst": ["persist-user@:*"]}]}`

	_, _, err := s.UpdatePolicy([]byte(closed))
	require.NoError(t, err)

	other := s.CreateUserForTest("other")
	node := s.CreateRegisteredNodeForTest(other, "other-node")
	node.User = other

	pm := s.polMan
	s.polMan = windowPM{PolicyManager: pm, window: func() { s.PutNodeInStoreForTest(*node) }}

	undo := failStore(t, s, nil)
	_, _, err = s.UpdatePolicy([]byte(policyOpen))
	require.ErrorIs(t, err, errStoreRefused)
	undo()

	s.polMan = pm

	require.Equal(t, 0, s.ListPeers(node.ID).Len(), "a peer of the open policy, which is not in force")
	require.Equal(t, 0, s.ListPeers(ownerNode).Len())
}

// TestPolicyTextTheSameEveryWay: a reload, the watch and a write of API v0
// refuse a text that is empty, only white space, or not an object, and
// leave the policy in force. Start-up does with each what it did before:
// zero bytes and not an object are in force as no policy, now refused where
// they are kept and said; only white space stops the server, in the words a
// reload uses, so a few newlines left by a deploy never open the tailnet.
func TestPolicyTextTheSameEveryWay(t *testing.T) {
	texts := []struct {
		name, text string
		want       error
		starts     bool
	}{
		{"empty", "", policyv2.ErrPolicyEmpty, true},
		{"white space", " \n\t\n", policyv2.ErrPolicyEmpty, false},
		{"not an object", "null", policyv2.ErrPolicyNotObject, true},
	}

	for _, tt := range texts {
		t.Run("file/"+tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.hujson")
			require.NoError(t, os.WriteFile(path, []byte(tt.text), 0o600))

			cfg := persistTestConfig(t.TempDir() + "/headscale.db")
			cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}

			s, err := NewState(cfg)
			if !tt.starts {
				require.ErrorIs(t, err, tt.want, "start-up stops, as it did")
				require.ErrorContains(t, err, `policy is empty, use "{}" to allow all`)

				require.NoError(t, os.WriteFile(path, []byte(policyOwner), 0o600))

				s, err = NewState(cfg)
			}

			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			if tt.starts {
				require.Equal(t, PolicyDocument{Mode: types.PolicyModeFile, Path: path}, s.Policy())
				require.Equal(t, filterOf(t, s, nil), mustFilter(s), "no policy, as before")
				require.ErrorIs(t, s.PolicySourceError(), tt.want, "start-up says so")

				_, err = s.ReloadPolicy()
				require.ErrorIs(t, err, tt.want, "a reload")

				require.NoError(t, os.WriteFile(path, []byte(policyOwner), 0o600))

				_, err = s.ReloadPolicy()
				require.NoError(t, err)
				require.NoError(t, s.PolicySourceError(), "a valid file ends it")
			}

			require.NoError(t, os.WriteFile(path, []byte(tt.text), 0o600))

			_, err = s.ReloadPolicy()
			require.ErrorIs(t, err, tt.want, "a reload")
			require.ErrorIs(t, s.PolicySourceError(), tt.want)
			require.JSONEq(t, policyOwner, s.Policy().Data, "the policy in force stays")

			require.ErrorIs(t, s.CheckPolicyIf([]byte(tt.text), nil), tt.want, "a dry run of API v0")
			_, _, err = s.UpdatePolicyTextIf([]byte(tt.text), nil)
			require.ErrorIs(t, err, tt.want, "a write of API v0")
		})

		t.Run("database/"+tt.name, func(t *testing.T) {
			cfg := persistTestConfig(t.TempDir() + "/headscale.db")

			s, err := NewState(cfg)
			require.NoError(t, err)
			_, err = s.SetPolicyInDB(tt.text)
			require.NoError(t, err)
			require.NoError(t, s.Close())

			s, err = NewState(cfg)
			if !tt.starts {
				require.ErrorIs(t, err, tt.want, "start-up stops, as it did")

				return
			}

			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			require.Empty(t, s.Policy().Data)
			require.Equal(t, filterOf(t, s, nil), mustFilter(s))
			require.ErrorIs(t, s.PolicySourceError(), tt.want, "start-up says so")

			_, err = s.ReloadPolicy()
			require.ErrorIs(t, err, tt.want, "a reload")

			_, _, err = s.UpdatePolicy([]byte(policyOwner))
			require.NoError(t, err)
			require.NoError(t, s.PolicySourceError(), "a write ends it")
		})
	}
}

// TestPolicyNULByte: a text with a NUL byte, here in a comment, which
// PostgreSQL cannot store. API v0 and a reload refuse it, placed; start-up
// keeps parsing it as it always did, and says so. The older APIs write it as
// before: SQLite stores it and says it is refused where it is kept, and
// PostgreSQL fails the store and keeps the policy before.
func TestPolicyNULByte(t *testing.T) {
	nul := policyOpen + "\n// a \x00\n"

	requireNUL := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, policyv2.ErrPolicyNUL)

		var invalid *InvalidPolicyError
		require.ErrorAs(t, err, &invalid)
		require.Equal(t, []policyv2.PolicyError{{Message: policyv2.ErrPolicyNUL.Error(), Line: 2, Column: 6}},
			policyv2.Explain(invalid.Policy, invalid.Err).Errors, "placed")
	}

	t.Run("start-up and a reload", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.hujson")
		require.NoError(t, os.WriteFile(path, []byte(nul), 0o600))

		cfg := persistTestConfig(t.TempDir() + "/headscale.db")
		cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}

		s, err := NewState(cfg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = s.Close() })

		require.Equal(t, nul, s.Policy().Data, "in force as before")
		require.Equal(t, filterOf(t, s, []byte(policyOpen)), mustFilter(s))
		requireNUL(t, s.PolicySourceError())

		_, err = s.ReloadPolicy()
		requireNUL(t, err)
		require.Equal(t, nul, s.Policy().Data, "the policy in force stays")

		requireNUL(t, s.CheckPolicyIf([]byte(nul), nil))

		_, _, err = s.UpdatePolicyTextIf([]byte(nul), nil)
		requireNUL(t, err)
	})

	t.Run("the older APIs", func(t *testing.T) {
		policyStores(t, func(t *testing.T, cfg *types.Config) {
			t.Helper()

			s, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			_, _, err = s.UpdatePolicy([]byte(policyOwner))
			require.NoError(t, err)

			_, _, err = s.UpdatePolicy([]byte(nul))
			if cfg.Database.Type == types.DatabasePostgres {
				require.ErrorContains(t, err, "invalid byte sequence")
				require.JSONEq(t, policyOwner, s.Policy().Data, "the policy before stays")
				require.NoError(t, s.PolicySourceError())

				return
			}

			require.NoError(t, err, "SQLite stores it")
			require.Equal(t, nul, s.Policy().Data)
			requireNUL(t, s.PolicySourceError())
		})
	})
}

// TestPolicyWriteWaitsForLogins measures, at the production tick, how long a
// login holds the policy lock, how long a policy write that arrives during
// one waits, and how long a login that arrives behind that write waits; by
// auth request and by auth key.
func TestPolicyWriteWaitsForLogins(t *testing.T) {
	if testing.Short() {
		t.Skip("measures at the production tick")
	}

	logins := map[string]func(s *State, user *types.User, name string) error{
		"by auth request": func(s *State, user *types.User, name string) error {
			authID := types.MustAuthID()
			require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
				MachineKey: key.NewMachine().Public(),
				NodeKey:    key.NewNode().Public(),
				Hostname:   name,
			})))

			_, _, err := s.HandleNodeFromAuthPath(authID, types.UserID(user.ID), nil, util.RegisterMethodCLI)

			return err
		},
		"by auth key": func(s *State, user *types.User, name string) error {
			pak, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
			require.NoError(t, err)

			_, _, err = s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: name},
			}, key.NewMachine().Public())

			return err
		},
	}

	for kind, register := range logins {
		t.Run(kind, func(t *testing.T) {
			cfg := persistTestConfig(t.TempDir() + "/headscale.db")
			cfg.Tuning.NodeStoreBatchTimeout = 500 * time.Millisecond

			s, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			user := s.CreateUserForTest("login")

			login := func(name string) time.Duration {
				start := time.Now()

				require.NoError(t, register(s, user, name))

				return time.Since(start)
			}

			for i := range 3 {
				t.Logf("login %d took %v under the shared lock", i+1, login("node-"+strconv.Itoa(i)))
			}

			inserted := make(chan struct{})

			var once sync.Once

			s.SetNodeInsertedHookForTesting(func() { once.Do(func() { close(inserted) }) })

			go login("held")

			<-inserted

			s.SetNodeInsertedHookForTesting(nil)

			wrote := make(chan time.Duration, 1)

			go func() {
				start := time.Now()
				_, _, err := s.UpdatePolicy([]byte(policyOpen))
				assert.NoError(t, err)

				wrote <- time.Since(start)
			}()

			require.Eventually(t, func() bool {
				if s.policyMu.TryRLock() {
					s.policyMu.RUnlock()

					return false
				}

				return true
			}, 10*time.Second, time.Millisecond)

			asked := time.Now()

			s.policyMu.RLock()

			behind := time.Since(asked)

			s.policyMu.RUnlock()

			t.Logf("a write that arrived during a login took %v; a login behind it waited %v for the lock", <-wrote, behind)
			require.Less(t, behind, 4*cfg.Tuning.NodeStoreBatchTimeout)
		})
	}
}
