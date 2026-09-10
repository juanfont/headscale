package state

import (
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStateForSSHCheck() *State {
	return &State{
		sshCheckAuth: make(map[sshCheckPair]time.Time),
	}
}

func newSSHPolicyTestState(t *testing.T) (*State, types.NodeID, types.NodeID) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	database, err := db.NewHeadscaleDatabase(persistTestConfig(dbPath))
	require.NoError(t, err)

	user := database.CreateUserForTest("ssh-source")
	src := database.CreateRegisteredNodeForTest(user, "ssh-source-node")
	dst := database.CreateRegisteredNodeForTest(user, "ssh-destination-node")
	require.NoError(t, database.Close())

	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	return s, src.ID, dst.ID
}

func TestSSHCheckAuth(t *testing.T) {
	s := newTestStateForSSHCheck()

	src := types.NodeID(1)
	dst := types.NodeID(2)
	otherDst := types.NodeID(3)
	otherSrc := types.NodeID(4)

	// No record initially
	_, ok := s.GetLastSSHAuth(src, dst)
	require.False(t, ok)

	// Record auth for (src, dst)
	s.SetLastSSHAuth(src, dst)

	// Same src+dst: found
	authTime, ok := s.GetLastSSHAuth(src, dst)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now(), authTime, time.Second)

	// Same src, different dst: not found (auth is per-pair)
	_, ok = s.GetLastSSHAuth(src, otherDst)
	require.False(t, ok)

	// Different src: not found
	_, ok = s.GetLastSSHAuth(otherSrc, dst)
	require.False(t, ok)
}

func TestSSHCheckAuthClear(t *testing.T) {
	s := newTestStateForSSHCheck()

	s.SetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	s.SetLastSSHAuth(types.NodeID(1), types.NodeID(3))

	_, ok := s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	require.True(t, ok)

	_, ok = s.GetLastSSHAuth(types.NodeID(1), types.NodeID(3))
	require.True(t, ok)

	// Clear
	s.ClearSSHCheckAuth()

	_, ok = s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	require.False(t, ok)

	_, ok = s.GetLastSSHAuth(types.NodeID(1), types.NodeID(3))
	require.False(t, ok)
}

func TestSSHCheckAuthConcurrent(t *testing.T) {
	s := newTestStateForSSHCheck()

	var wg sync.WaitGroup

	for i := range 100 {
		wg.Go(func() {
			src := types.NodeID(uint64(i % 10))   //nolint:gosec
			dst := types.NodeID(uint64(i%5 + 10)) //nolint:gosec

			s.SetLastSSHAuth(src, dst)
			s.GetLastSSHAuth(src, dst)
		})
	}

	wg.Wait()

	// Clear concurrently with reads
	wg.Go(func() {
		s.ClearSSHCheckAuth()
	})

	wg.Go(func() {
		s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	})

	wg.Wait()
}

func TestCompleteSSHCheckUsesCurrentPolicy(t *testing.T) {
	s, src, dst := newSSHPolicyTestState(t)

	checkRoot := []byte(`{
		"ssh": [{
			"action": "check",
			"checkPeriod": "2h",
			"src": ["ssh-source@"],
			"dst": ["autogroup:self"],
			"users": ["root"]
		}]
	}`)
	acceptRoot := []byte(`{
		"ssh": [{
			"action": "accept",
			"src": ["ssh-source@"],
			"dst": ["autogroup:self"],
			"users": ["root"]
		}]
	}`)
	checkUbuntu := []byte(`{
		"ssh": [{
			"action": "check",
			"src": ["ssh-source@"],
			"dst": ["autogroup:self"],
			"users": ["ubuntu"]
		}]
	}`)

	_, err := s.SetPolicy(checkRoot)
	require.NoError(t, err)

	evaluation := s.EvaluateSSHAccess(src, dst, "root")
	require.Equal(t, SSHAccessCheck, evaluation.Action)
	assert.Equal(t, SSHAccessAccept, s.CompleteSSHCheck(
		src, dst, "root", evaluation.PolicyGeneration,
	))
	_, ok := s.GetLastSSHAuth(src, dst)
	assert.True(t, ok, "unchanged check policy must record reusable approval")

	evaluation = s.EvaluateSSHAccess(src, dst, "root")
	require.Equal(t, SSHAccessAccept, evaluation.Action,
		"recorded approval should satisfy the current check period")

	_, err = s.SetPolicy(checkRoot)
	require.NoError(t, err)

	evaluation = s.EvaluateSSHAccess(src, dst, "root")
	require.Equal(t, SSHAccessCheck, evaluation.Action)

	_, err = s.SetPolicy(acceptRoot)
	require.NoError(t, err)
	assert.Equal(t, SSHAccessAccept, s.CompleteSSHCheck(
		src, dst, "root", evaluation.PolicyGeneration,
	), "a current direct-accept rule must not be rejected")
	_, ok = s.GetLastSSHAuth(src, dst)
	assert.False(t, ok, "direct accept must not create a reusable check approval")

	_, err = s.SetPolicy(checkRoot)
	require.NoError(t, err)

	evaluation = s.EvaluateSSHAccess(src, dst, "root")
	require.Equal(t, SSHAccessCheck, evaluation.Action)

	_, err = s.SetPolicy(checkUbuntu)
	require.NoError(t, err)
	assert.Equal(t, SSHAccessReject, s.CompleteSSHCheck(
		src, dst, "root", evaluation.PolicyGeneration,
	), "approval for a removed local-user rule must be rejected")
	_, ok = s.GetLastSSHAuth(src, dst)
	assert.False(t, ok, "stale approval must not be recorded")
}
