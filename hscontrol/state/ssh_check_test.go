package state

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func newTestStateForSSHCheck(t *testing.T) *State {
	t.Helper()

	s := newRetagTestState(t)

	user := s.CreateUserForTest("ssh-user")
	for i := range 10 {
		node := s.CreateRegisteredNodeForTest(user, fmt.Sprintf("ssh-node-%d", i))
		node.User = user
		s.nodeStore.PutNode(*node)
	}

	return s
}

func TestSSHCheckAuth(t *testing.T) {
	s := newTestStateForSSHCheck(t)

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
	s := newTestStateForSSHCheck(t)

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
	s := newTestStateForSSHCheck(t)

	var wg sync.WaitGroup

	for i := range 100 {
		wg.Go(func() {
			src := types.NodeID(uint64(i%10 + 1)) //nolint:gosec
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

func TestSSHCheckAuthFollowsSourceOwner(t *testing.T) {
	for _, tt := range []struct {
		name   string
		tagged bool
		kept   bool
	}{
		{"convert", false, false},
		{"retag", true, false},
		{"user_change", false, false},
		{"delete", false, false},
		{"destination_change", false, true},
		{"rekey", false, true},
		{"same_tags", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStateForSSHCheck(t)
			_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:ci":["ssh-user@"],"tag:ops":["ssh-user@"]}}`))
			require.NoError(t, err)

			src, dst := types.NodeID(1), types.NodeID(2)
			if tt.tagged {
				_, _, err = s.SetNodeTags(src, []string{"tag:ci", "tag:ops"})
				require.NoError(t, err)
			}

			s.SetLastSSHAuth(src, dst)
			at, ok := s.GetLastSSHAuth(src, dst)
			require.True(t, ok)

			switch tt.name {
			case "convert", "destination_change":
				id := src
				if tt.name == "destination_change" {
					id = dst
				}

				_, _, err = s.SetNodeTags(id, []string{"tag:ci"})
				require.NoError(t, err)
			case "retag":
				_, _, err = s.SetNodeTags(src, []string{"tag:ops"})
				require.NoError(t, err)
			case "user_change":
				other := s.CreateUserForTest("other-user")
				_, ok = s.nodeStore.UpdateNode(src, func(n *types.Node) {
					n.UserID = &other.ID
					n.User = other
				})
				require.True(t, ok)
			case "delete":
				node, ok := s.GetNodeByID(src)
				require.True(t, ok)

				_, err = s.DeleteNode(node)
				require.NoError(t, err)
			case "rekey":
				_, ok = s.nodeStore.UpdateNode(src, func(n *types.Node) { n.NodeKey = key.NewNode().Public() })
				require.True(t, ok)
			case "same_tags":
				_, ok = s.nodeStore.UpdateNode(src, func(n *types.Node) {
					n.Tags = []string{"tag:ops", "tag:ci"}
				})
				require.True(t, ok)
			}

			last, ok := s.GetLastSSHAuth(src, dst)
			assert.Equal(t, tt.kept, ok)

			if tt.kept {
				assert.Equal(t, at, last)
			} else {
				assert.True(t, last.IsZero())
			}
		})
	}
}
