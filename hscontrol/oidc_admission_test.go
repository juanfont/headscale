package hscontrol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var errOIDCTestCancelled = errors.New("cancelled")

func newTestOIDCStateProvider(maxEntries int, expiration time.Duration) *AuthProviderOIDC {
	return &AuthProviderOIDC{
		serverURL:            "https://headscale.example.com",
		cfg:                  &types.OIDCConfig{},
		authCache:            expirable.NewLRU[string, AuthInfo](0, nil, expiration),
		sshAuthCache:         expirable.NewLRU[string, AuthInfo](0, nil, expiration),
		authCacheMaxEntries:  maxEntries,
		authStateByRequestID: make(map[types.AuthID]oidcAuthState),
		oauth2Config: &oauth2.Config{
			ClientID:    "client-id",
			RedirectURL: "https://headscale.example.com/oidc/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://issuer.example.com/authorize",
			},
		},
	}
}

func TestOIDCAuthStateCapacityPreservesActiveEntries(t *testing.T) {
	provider := newTestOIDCStateProvider(2, time.Hour)
	states := []string{"state-registration-one", "state-registration-two"}

	for _, state := range states {
		err := provider.addOIDCAuthState(state, AuthInfo{
			AuthID:       types.MustAuthID(),
			Registration: true,
		})
		require.NoError(t, err)
	}

	err := provider.addOIDCAuthState("state-registration-three", AuthInfo{
		AuthID:       types.MustAuthID(),
		Registration: true,
	})
	require.ErrorIs(t, err, errOIDCStateCapacity)

	for _, state := range states {
		_, ok := provider.peekOIDCAuthState(state)
		require.True(t, ok)
	}

	err = provider.addOIDCAuthState("state-ssh", AuthInfo{
		AuthID: types.MustAuthID(),
	})
	require.NoError(t, err, "registration capacity must not block SSH state")
}

func TestOIDCAuthStateDeduplicatesPendingRequest(t *testing.T) {
	provider := newTestOIDCStateProvider(2, time.Hour)
	authID := types.MustAuthID()
	require.NoError(t, provider.addOIDCAuthState("state-one", AuthInfo{
		AuthID:       authID,
		Registration: true,
	}))

	err := provider.addOIDCAuthState("state-two", AuthInfo{
		AuthID:       authID,
		Registration: true,
	})
	require.ErrorIs(t, err, errOIDCStateExists)
	require.Equal(t, 1, provider.authCache.Len())
}

func TestOIDCAuthStateConcurrentAdmissionStopsAtCapacity(t *testing.T) {
	const (
		maxEntries = 8
		attempts   = 64
	)

	provider := newTestOIDCStateProvider(maxEntries, time.Hour)

	var accepted atomic.Int32

	var wg sync.WaitGroup
	for idx := range attempts {
		wg.Go(func() {
			err := provider.addOIDCAuthState("state-"+strconv.Itoa(idx), AuthInfo{
				AuthID:       types.MustAuthID(),
				Registration: true,
			})
			if err == nil {
				accepted.Add(1)
			}
		})
	}

	wg.Wait()

	require.Equal(t, int32(maxEntries), accepted.Load())
	require.Equal(t, maxEntries, provider.authCache.Len())
}

func TestOIDCAuthStateExpirationFreesCapacity(t *testing.T) {
	provider := newTestOIDCStateProvider(1, 20*time.Millisecond)
	require.NoError(t, provider.addOIDCAuthState("state-expiring", AuthInfo{
		AuthID:       types.MustAuthID(),
		Registration: true,
	}))

	require.Eventually(t, func() bool {
		provider.authCacheMu.Lock()
		defer provider.authCacheMu.Unlock()

		provider.pruneExpiredOIDCAuthStatesLocked()

		return provider.authCache.Len() == 0
	}, time.Second, time.Millisecond)

	require.NoError(t, provider.addOIDCAuthState("state-new", AuthInfo{
		AuthID:       types.MustAuthID(),
		Registration: true,
	}))
}

func TestOIDCAuthStateTakeIsSingleUse(t *testing.T) {
	provider := newTestOIDCStateProvider(1, time.Hour)
	verifier := "pkce-verifier"
	authID := types.MustAuthID()
	require.NoError(t, provider.addOIDCAuthState("state-single-use", AuthInfo{
		AuthID:       authID,
		Verifier:     &verifier,
		Registration: true,
	}))

	peeked, ok := provider.peekOIDCAuthState("state-single-use")
	require.True(t, ok)
	require.Equal(t, verifier, *peeked.Verifier)

	var successes atomic.Int32

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, ok := provider.takeOIDCAuthState("state-single-use"); ok {
				successes.Add(1)
			}
		})
	}

	wg.Wait()

	require.Equal(t, int32(1), successes.Load())

	err := provider.addOIDCAuthState("state-repeated", AuthInfo{
		AuthID:       authID,
		Registration: true,
	})
	require.ErrorIs(t, err, errOIDCStateExists)

	provider.releaseOIDCAuthReservation(authID)
	require.NoError(t, provider.addOIDCAuthState("state-repeated", AuthInfo{
		AuthID:       authID,
		Registration: true,
	}))
}

func TestOIDCStartValidatesPendingRequestBeforeAllocation(t *testing.T) {
	provider := newTestOIDCStateProvider(2, time.Hour)
	provider.h = createTestApp(t)

	missingID := types.MustAuthID()
	response := serveOIDCStart(t, provider, true, missingID)
	require.Equal(t, http.StatusNotFound, response.Code)
	require.Empty(t, response.Header().Get("Location"))
	require.Empty(t, response.Result().Cookies())
	require.Zero(t, provider.authCache.Len())

	registrationID := types.MustAuthID()
	require.NoError(t, provider.h.state.SetAuthCacheEntry(
		registrationID,
		types.NewRegisterAuthRequest(&types.RegistrationData{}),
	))
	response = serveOIDCStart(t, provider, false, registrationID)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Empty(t, response.Header().Get("Location"))
	require.Empty(t, response.Result().Cookies())

	sshID := types.MustAuthID()
	require.NoError(t, provider.h.state.SetAuthCacheEntry(
		sshID,
		types.NewSSHCheckAuthRequest(1, 2),
	))
	response = serveOIDCStart(t, provider, true, sshID)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Empty(t, response.Header().Get("Location"))
	require.Empty(t, response.Result().Cookies())

	completedID := types.MustAuthID()
	completed := types.NewRegisterAuthRequest(&types.RegistrationData{})
	require.NoError(t, provider.h.state.SetAuthCacheEntry(completedID, completed))
	require.True(t, completed.FinishAuth(types.AuthVerdict{Err: errOIDCTestCancelled}))
	response = serveOIDCStart(t, provider, true, completedID)
	require.Equal(t, http.StatusGone, response.Code)
	require.Empty(t, response.Result().Cookies())

	pendingID := types.MustAuthID()
	pending := types.NewRegisterAuthRequest(&types.RegistrationData{})
	require.True(t, pending.SetPendingConfirmation(&types.PendingRegistrationConfirmation{
		CSRF: "pending",
	}))
	require.NoError(t, provider.h.state.SetAuthCacheEntry(pendingID, pending))
	response = serveOIDCStart(t, provider, true, pendingID)
	require.Equal(t, http.StatusConflict, response.Code)
	require.Empty(t, response.Result().Cookies())
}

func TestOIDCStartAdmissionPreservesExistingFlow(t *testing.T) {
	provider := newTestOIDCStateProvider(1, time.Hour)
	provider.h = createTestApp(t)

	registrationID := types.MustAuthID()
	secondRegistrationID := types.MustAuthID()
	sshID := types.MustAuthID()

	for _, authID := range []types.AuthID{registrationID, secondRegistrationID} {
		require.NoError(t, provider.h.state.SetAuthCacheEntry(
			authID,
			types.NewRegisterAuthRequest(&types.RegistrationData{}),
		))
	}

	require.NoError(t, provider.h.state.SetAuthCacheEntry(
		sshID,
		types.NewSSHCheckAuthRequest(1, 2),
	))

	response := serveOIDCStart(t, provider, true, registrationID)
	require.Equal(t, http.StatusFound, response.Code)
	require.NotEmpty(t, response.Header().Get("Location"))
	require.Len(t, response.Result().Cookies(), 2)

	states := provider.authCache.Keys()
	require.Len(t, states, 1)
	existingState := states[0]

	response = serveOIDCStart(t, provider, true, registrationID)
	require.Equal(t, http.StatusConflict, response.Code)
	require.Empty(t, response.Header().Get("Location"))
	require.Empty(t, response.Result().Cookies())

	response = serveOIDCStart(t, provider, true, secondRegistrationID)
	require.Equal(t, http.StatusServiceUnavailable, response.Code)
	require.Empty(t, response.Header().Get("Location"))
	require.Empty(t, response.Result().Cookies())

	info, ok := provider.peekOIDCAuthState(existingState)
	require.True(t, ok)
	require.Equal(t, registrationID, info.AuthID)

	response = serveOIDCStart(t, provider, false, sshID)
	require.Equal(t, http.StatusFound, response.Code)
	require.NotEmpty(t, response.Header().Get("Location"))
	require.Equal(t, 1, provider.sshAuthCache.Len())
}

func TestOIDCStartPrunesCompletedRequest(t *testing.T) {
	provider := newTestOIDCStateProvider(1, time.Hour)
	provider.h = createTestApp(t)

	completedID := types.MustAuthID()

	nextID := types.MustAuthID()
	for _, authID := range []types.AuthID{completedID, nextID} {
		require.NoError(t, provider.h.state.SetAuthCacheEntry(
			authID,
			types.NewRegisterAuthRequest(&types.RegistrationData{}),
		))
	}

	response := serveOIDCStart(t, provider, true, completedID)
	require.Equal(t, http.StatusFound, response.Code)

	completed, ok := provider.h.state.GetAuthCacheEntry(completedID)
	require.True(t, ok)
	require.True(t, completed.FinishAuth(types.AuthVerdict{Err: errOIDCTestCancelled}))

	response = serveOIDCStart(t, provider, true, nextID)
	require.Equal(t, http.StatusFound, response.Code)
	require.Equal(t, 1, provider.authCache.Len())
}

func TestHandleNodeFromAuthPathRejectsCompletedRequest(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("completed-registration")
	machineKey := key.NewMachine()
	authID := types.MustAuthID()
	authReq := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey.Public(),
		NodeKey:    key.NewNode().Public(),
		DiscoKey:   key.NewDisco().Public(),
		Hostname:   "completed-registration",
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "completed-registration"},
	})
	require.NoError(t, app.state.SetAuthCacheEntry(authID, authReq))
	require.True(t, authReq.FinishAuth(types.AuthVerdict{Err: errOIDCTestCancelled}))

	_, _, err := app.state.HandleNodeFromAuthPath(
		authID,
		types.UserID(user.ID),
		nil,
		util.RegisterMethodOIDC,
	)
	require.ErrorIs(t, err, db.ErrNodeNotFoundRegistrationCache)
	require.Empty(t, app.state.GetNodesByMachineKeyAllUsers(machineKey.Public()))
}

func serveOIDCStart(
	t *testing.T,
	provider *AuthProviderOIDC,
	registration bool,
	authID types.AuthID,
) *httptest.ResponseRecorder {
	t.Helper()

	path := "/auth/" + authID.String()
	if registration {
		path = "/register/" + authID.String()
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("auth_id", authID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeContext))

	response := httptest.NewRecorder()
	provider.authHandler(response, req, registration)

	return response
}

func TestOIDCAuthStateCapacityErrorUnwraps(t *testing.T) {
	provider := newTestOIDCStateProvider(0, time.Hour)
	err := provider.addOIDCAuthState("state", AuthInfo{
		AuthID:       types.MustAuthID(),
		Registration: true,
	})

	require.ErrorIs(t, err, errOIDCStateCapacity)
}
