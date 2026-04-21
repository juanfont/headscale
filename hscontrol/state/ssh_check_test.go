package state

import (
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStateForSSHCheck() *State {
	return &State{
		sshCheckAuth: make(map[sshCheckPair]time.Time),
	}
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
	wg.Add(2)

	go func() {
		defer wg.Done()

		s.ClearSSHCheckAuth()
	}()

	go func() {
		defer wg.Done()

		s.GetLastSSHAuth(types.NodeID(1), types.NodeID(2))
	}()

	wg.Wait()
}
