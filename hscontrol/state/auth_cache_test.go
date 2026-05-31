package state

import (
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthCacheBoundedLRU verifies that the registration auth cache is
// bounded by a maximum entry count, that exceeding the maxEntries evicts the
// oldest entry, and that the eviction callback resolves the parked
// AuthRequest with ErrRegistrationExpired so any waiting goroutine wakes.
func TestAuthCacheBoundedLRU(t *testing.T) {
	const maxEntries = 4

	cache := expirable.NewLRU[types.AuthID, *types.AuthRequest](
		maxEntries,
		func(_ types.AuthID, rn *types.AuthRequest) {
			rn.FinishAuth(types.AuthVerdict{Err: ErrRegistrationExpired})
		},
		time.Hour, // long TTL — we test eviction by size, not by time
	)

	entries := make([]*types.AuthRequest, 0, maxEntries+1)
	ids := make([]types.AuthID, 0, maxEntries+1)

	for range maxEntries + 1 {
		id := types.MustAuthID()
		entry := types.NewAuthRequest()
		cache.Add(id, entry)
		ids = append(ids, id)
		entries = append(entries, entry)
	}

	// Cap should be respected.
	assert.Equal(t, maxEntries, cache.Len(), "cache must not exceed the configured maxEntries")

	// The oldest entry must have been evicted.
	_, ok := cache.Get(ids[0])
	assert.False(t, ok, "oldest entry must be evicted when maxEntries is exceeded")

	// The eviction callback must have woken the parked AuthRequest.
	select {
	case verdict := <-entries[0].WaitForAuth():
		require.False(t, verdict.Accept(), "evicted entry must not signal Accept")
		require.ErrorIs(t,
			verdict.Err, ErrRegistrationExpired,
			"evicted entry must surface ErrRegistrationExpired, got: %v",
			verdict.Err,
		)
	case <-time.After(time.Second):
		t.Fatal("eviction callback did not wake the parked AuthRequest")
	}

	// All non-evicted entries must still be retrievable.
	for i := 1; i <= maxEntries; i++ {
		_, ok := cache.Get(ids[i])
		assert.True(t, ok, "non-evicted entry %d should still be in the cache", i)
	}
}
