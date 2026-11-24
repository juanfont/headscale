package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
