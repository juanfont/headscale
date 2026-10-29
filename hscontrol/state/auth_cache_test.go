package state

import (
	"bytes"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuthCache(t *testing.T, maxEntries int, ttl time.Duration) *expirable.LRU[types.AuthID, *types.AuthRequest] {
	t.Helper()

	cache := expirable.NewLRU[types.AuthID, *types.AuthRequest](
		maxEntries,
		func(_ types.AuthID, rn *types.AuthRequest) {
			rn.FinishAuth(types.AuthVerdict{Err: ErrRegistrationExpired})
		},
		ttl,
	)
	t.Cleanup(cache.Close)

	return cache
}

func requireExpiredVerdict(t *testing.T, entry *types.AuthRequest) {
	t.Helper()

	select {
	case verdict := <-entry.WaitForAuth():
		require.False(t, verdict.Accept(), "evicted entry must not signal Accept")
		require.ErrorIs(t,
			verdict.Err, ErrRegistrationExpired,
			"evicted entry must surface ErrRegistrationExpired, got: %v",
			verdict.Err,
		)
	case <-time.After(5 * time.Second):
		t.Fatal("eviction callback did not wake the parked AuthRequest")
	}
}

// TestAuthCacheBoundedLRU checks the underlying library's eviction callback.
// State admission prevents this eviction behavior for pending auth requests.
func TestAuthCacheBoundedLRU(t *testing.T) {
	const maxEntries = 4

	// Long TTL: eviction by size, not by time.
	cache := newTestAuthCache(t, maxEntries, time.Hour)

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

	requireExpiredVerdict(t, entries[0])

	// All non-evicted entries must still be retrievable.
	for i := 1; i <= maxEntries; i++ {
		_, ok := cache.Get(ids[i])
		assert.True(t, ok, "non-evicted entry %d should still be in the cache", i)
	}
}

// TestAuthCacheTTLExpiry verifies the TTL sweeper evicts an entry that timed
// out and that the eviction callback wakes its waiter.
func TestAuthCacheTTLExpiry(t *testing.T) {
	cache := newTestAuthCache(t, 4, 50*time.Millisecond)

	id := types.MustAuthID()
	entry := types.NewAuthRequest()
	cache.Add(id, entry)

	requireExpiredVerdict(t, entry)

	_, ok := cache.Get(id)
	assert.False(t, ok, "expired entry must be gone from the cache")
}

func TestAuthCacheAdmissionPreservesPending(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Tuning.RegisterCacheMaxEntries = 1
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	id := types.MustAuthID()
	pending := types.NewAuthRequest()
	require.NoError(t, s.SetAuthCacheEntry(id, pending))

	otherID := types.MustAuthID()
	require.ErrorIs(t, s.SetAuthCacheEntry(otherID, types.NewAuthRequest()), ErrAuthCacheFull)

	got, ok := s.GetAuthCacheEntry(id)
	require.True(t, ok, "new work must not displace an admitted authentication")
	require.Same(t, pending, got)

	_, ok = s.GetAuthCacheEntry(otherID)
	require.False(t, ok, "new work must be refused at capacity")

	select {
	case <-pending.WaitForAuth():
		t.Fatal("capacity refusal must not finish an existing authentication")
	default:
	}
}

func TestAuthCacheAdmissionPreservesIdentity(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	id := types.MustAuthID()
	pending := types.NewAuthRequest()
	require.NoError(t, s.SetAuthCacheEntry(id, pending))
	require.NoError(t, s.SetAuthCacheEntry(id, pending))
	require.ErrorIs(t, s.SetAuthCacheEntry(id, types.NewAuthRequest()), ErrAuthCacheEntryExists)

	got, ok := s.GetAuthCacheEntry(id)
	require.True(t, ok)
	require.Same(t, pending, got, "an existing auth ID must keep its original request and waiter")
}

func TestAuthCacheAdmissionConcurrent(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Tuning.RegisterCacheMaxEntries = 2
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	id := types.MustAuthID()
	pending := types.NewAuthRequest()
	require.NoError(t, s.SetAuthCacheEntry(id, pending))

	var wg sync.WaitGroup

	results := make(chan error, 4)

	for range 4 {
		wg.Go(func() {
			results <- s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest())
		})
	}

	wg.Wait()
	close(results)

	var accepted int

	for err := range results {
		if err == nil {
			accepted++
		} else {
			require.ErrorIs(t, err, ErrAuthCacheFull)
		}
	}

	require.Equal(t, 1, accepted)

	got, ok := s.GetAuthCacheEntry(id)
	require.True(t, ok, "concurrent admission must preserve existing transactions")
	require.Same(t, pending, got)
	require.Equal(t, 2, s.authCache.Len())
}

func TestAuthCacheAdmissionReservesSSHCapacity(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Tuning.RegisterCacheMaxEntries = 1
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	registrationID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(registrationID, types.NewAuthRequest()))

	sshID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(sshID, types.NewSSHCheckAuthRequest(1, 2)),
		"registration capacity must not consume the SSH reservation")
	require.ErrorIs(t, s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest()), ErrAuthCacheFull)
	_, ok := s.GetAuthCacheEntry(registrationID)
	require.True(t, ok)
	_, ok = s.GetAuthCacheEntry(sshID)
	require.True(t, ok)
}

func TestAuthCacheAdmissionBoundsRegistrationPayload(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	id := types.MustAuthID()
	request := types.NewRegisterAuthRequest(&types.RegistrationData{
		Hostname: strings.Repeat("x", types.MaxRegistrationPayloadBytes),
	})
	require.ErrorIs(t, s.SetAuthCacheEntry(id, request), types.ErrRegistrationPayloadTooLarge)
	_, ok := s.GetAuthCacheEntry(id)
	require.False(t, ok)
	require.Zero(t, s.authCache.Len())
	require.Zero(t, s.authCacheRegularEntries.Load())
}

func TestAuthCacheAdmissionDoesNotReuseExpiredRequest(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Tuning.RegisterCacheExpiration = 50 * time.Millisecond
	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	id := types.MustAuthID()
	request := types.NewAuthRequest()
	require.NoError(t, s.SetAuthCacheEntry(id, request))
	requireExpiredVerdict(t, request)
	require.Error(t, s.SetAuthCacheEntry(id, request), "expired waiters cannot be reused as new pending requests")
}

func TestAuthCacheAdmissionReleasesCapacity(t *testing.T) {
	for _, removal := range []string{"consumption", "expiry"} {
		t.Run(removal, func(t *testing.T) {
			cfg := persistTestConfig(t.TempDir() + "/headscale.db")
			cfg.Tuning.RegisterCacheMaxEntries = 1
			cfg.Tuning.RegisterCacheExpiration = 50 * time.Millisecond
			s, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, s.Close()) })

			id := types.MustAuthID()
			pending := types.NewAuthRequest()
			require.NoError(t, s.SetAuthCacheEntry(id, pending))

			if removal == "consumption" {
				pending.FinishAuth(types.AuthVerdict{})
				s.DeleteAuthCacheEntry(id)
			} else {
				requireExpiredVerdict(t, pending)
			}

			require.NoError(t, s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest()))
			require.Equal(t, int64(1), s.authCacheRegularEntries.Load())
		})
	}
}

func goroutineID() string {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)

	// "goroutine 123 [running]:"
	return strings.Fields(string(buf[:n]))[1]
}

// authCacheSweepers counts expirable LRU TTL sweeper goroutines started from
// goroutine gid, so caches other tests are still tearing down do not count.
func authCacheSweepers(t *testing.T, gid string) int {
	t.Helper()

	var buf bytes.Buffer

	require.NoError(t, pprof.Lookup("goroutine").WriteTo(&buf, 2))

	n := 0

	for g := range strings.SplitSeq(buf.String(), "\n\n") {
		if strings.Contains(g, "golang-lru/v2/expirable") &&
			strings.Contains(g, " in goroutine "+gid+"\n") {
			n++
		}
	}

	return n
}

// TestStateCloseStopsAuthCacheSweeper verifies that closing a State stops
// the auth cache's TTL sweeper goroutine instead of leaking it, and that a
// request still pending at that point gets its expiry verdict rather than
// waiting forever for a sweep that never comes.
func TestStateCloseStopsAuthCacheSweeper(t *testing.T) {
	gid := goroutineID()

	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	require.Equal(t, 1, authCacheSweepers(t, gid), "NewState must start a sweeper")

	pending := types.NewAuthRequest()
	require.NoError(t, s.SetAuthCacheEntry(types.MustAuthID(), pending))

	require.NoError(t, s.Close())

	requireExpiredVerdict(t, pending)
	require.ErrorIs(t, s.SetAuthCacheEntry(types.MustAuthID(), types.NewAuthRequest()), ErrAuthCacheClosed)

	assert.Eventually(t, func() bool {
		return authCacheSweepers(t, gid) == 0
	}, 5*time.Second, 10*time.Millisecond, "sweeper must stop on State.Close")
}
