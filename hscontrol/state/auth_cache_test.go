package state

import (
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPendingAuthCacheRejectsAtCapacity(t *testing.T) {
	const maxEntries = 4

	cache := newPendingAuthCache(maxEntries, time.Hour)
	ids := make([]types.AuthID, 0, maxEntries)

	for range maxEntries {
		id := types.MustAuthID()
		require.True(t, cache.add(id, types.NewRegisterAuthRequest(&types.RegistrationData{})))
		ids = append(ids, id)
	}

	require.False(t, cache.add(
		types.MustAuthID(),
		types.NewRegisterAuthRequest(&types.RegistrationData{}),
	))
	require.Equal(t, maxEntries, cache.entries.Len())

	for _, id := range ids {
		_, ok := cache.entries.Get(id)
		assert.True(t, ok, "existing request must remain available when admission is refused")
	}
}

func TestPendingAuthCacheRetiresCompletedEntryAtCapacity(t *testing.T) {
	cache := newPendingAuthCache(1, time.Hour)
	firstID := types.MustAuthID()
	first := types.NewSSHCheckAuthRequest(1, 2)
	require.True(t, cache.add(firstID, first))
	first.FinishAuth(types.AuthVerdict{})

	secondID := types.MustAuthID()
	require.True(t, cache.add(secondID, types.NewSSHCheckAuthRequest(1, 2)))

	_, ok := cache.entries.Get(firstID)
	require.False(t, ok)
	_, ok = cache.entries.Get(secondID)
	require.True(t, ok)
}

func TestPendingAuthPoolsHaveIndependentCapacity(t *testing.T) {
	const maxEntries = 2

	s := &State{
		registrationAuthCache: newPendingAuthCache(maxEntries, time.Hour),
		sshCheckAuthCache:     newPendingAuthCache(maxEntries, time.Hour),
	}

	registrationIDs := make([]types.AuthID, 0, maxEntries)
	for range maxEntries {
		id := types.MustAuthID()
		err := s.SetAuthCacheEntry(id, types.NewRegisterAuthRequest(&types.RegistrationData{}))
		require.NoError(t, err)

		registrationIDs = append(registrationIDs, id)
	}

	err := s.SetAuthCacheEntry(
		types.MustAuthID(),
		types.NewRegisterAuthRequest(&types.RegistrationData{}),
	)
	require.ErrorIs(t, err, ErrPendingAuthCapacity)

	sshIDs := make([]types.AuthID, 0, maxEntries)
	for range maxEntries {
		id := types.MustAuthID()
		err := s.SetAuthCacheEntry(id, types.NewSSHCheckAuthRequest(1, 2))
		require.NoError(t, err)

		sshIDs = append(sshIDs, id)
	}

	err = s.SetAuthCacheEntry(types.MustAuthID(), types.NewSSHCheckAuthRequest(1, 2))
	require.ErrorIs(t, err, ErrPendingAuthCapacity)

	for _, id := range append(registrationIDs, sshIDs...) {
		_, ok := s.GetAuthCacheEntry(id)
		assert.True(t, ok, "one full pool must not displace requests from either pool")
	}
}

func TestPendingAuthPoolsRejectDuplicateID(t *testing.T) {
	s := &State{
		registrationAuthCache: newPendingAuthCache(1, time.Hour),
		sshCheckAuthCache:     newPendingAuthCache(1, time.Hour),
	}

	id := types.MustAuthID()
	registration := types.NewRegisterAuthRequest(&types.RegistrationData{})
	require.NoError(t, s.SetAuthCacheEntry(id, registration))

	err := s.SetAuthCacheEntry(id, types.NewSSHCheckAuthRequest(1, 2))
	require.ErrorIs(t, err, ErrAuthRequestIDInUse)
	require.Zero(t, s.sshCheckAuthCache.entries.Len())

	got, ok := s.GetAuthCacheEntry(id)
	require.True(t, ok)
	require.Same(t, registration, got)
}

func TestPendingAuthPoolsAcceptGenericApprovalSession(t *testing.T) {
	s := &State{
		registrationAuthCache: newPendingAuthCache(1, time.Hour),
		sshCheckAuthCache:     newPendingAuthCache(1, time.Hour),
	}

	id := types.MustAuthID()
	request := types.NewAuthRequest()
	require.NoError(t, s.SetAuthCacheEntry(id, request))

	got, ok := s.GetAuthCacheEntry(id)
	require.True(t, ok)
	require.Same(t, request, got)
}

func TestPendingAuthCacheConcurrentAdmissionStopsAtCapacity(t *testing.T) {
	const (
		maxEntries = 8
		attempts   = 64
	)

	cache := newPendingAuthCache(maxEntries, time.Hour)
	accepted := make(chan types.AuthID, attempts)

	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			id := types.MustAuthID()
			if cache.add(id, types.NewRegisterAuthRequest(&types.RegistrationData{})) {
				accepted <- id
			}
		})
	}

	wg.Wait()
	close(accepted)

	require.Len(t, accepted, maxEntries)
	require.Equal(t, maxEntries, cache.entries.Len())

	for id := range accepted {
		_, ok := cache.entries.Get(id)
		assert.True(t, ok)
	}
}

func TestPendingAuthCacheExpirationFreesCapacity(t *testing.T) {
	const expiration = 20 * time.Millisecond

	cache := newPendingAuthCache(1, expiration)
	request := types.NewRegisterAuthRequest(&types.RegistrationData{})
	require.True(t, cache.add(types.MustAuthID(), request))

	select {
	case <-request.WaitForAuth():
		verdict, ok := request.AuthResult()
		require.True(t, ok)
		require.ErrorIs(t, verdict.Err, ErrRegistrationExpired)
	case <-time.After(time.Second):
		t.Fatal("expired request was not completed")
	}

	require.Eventually(t, func() bool {
		return cache.entries.Len() == 0
	}, time.Second, time.Millisecond)
	require.True(t, cache.add(
		types.MustAuthID(),
		types.NewRegisterAuthRequest(&types.RegistrationData{}),
	))
}

func TestPendingAuthCacheExpirationFinishesClaimedRequest(t *testing.T) {
	const expiration = 20 * time.Millisecond

	cache := newPendingAuthCache(1, expiration)
	request := types.NewRegisterAuthRequest(&types.RegistrationData{})
	require.True(t, cache.add(types.MustAuthID(), request))
	require.True(t, request.TryBeginAuth())

	select {
	case <-request.WaitForAuth():
		verdict, ok := request.AuthResult()
		require.True(t, ok)
		require.ErrorIs(t, verdict.Err, ErrRegistrationExpired)
		require.False(t, request.FinishClaimedAuth(types.AuthVerdict{}))
	case <-time.After(time.Second):
		t.Fatal("expired claimed request was not completed")
	}
}
