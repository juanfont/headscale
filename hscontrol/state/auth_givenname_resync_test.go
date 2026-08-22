package state

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
	"tailscale.com/tailcfg"
)

// TestReauthResyncsGivenName is the reproduction for #3432: the re-auth and
// pre-auth-key re-registration paths overwrite Hostname (and Hostinfo) in one
// step, so the hostinfoChanged resync in UpdateNodeFromMapRequest can never
// fire afterwards — the GivenName (and with it the MagicDNS label) kept the
// old hostname forever. Admin renames must keep winning over both paths.
func TestReauthResyncsGivenName(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("givenname-user")
	node := database.CreateRegisteredNodeForTest(user, "old-host")
	machineKey := node.MachineKey

	pakNode := database.CreateRegisteredNodeForTest(user, "old-pak-host")
	pakMachineKey := pakNode.MachineKey

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	clientExpiry := time.Now().Add(24 * time.Hour)

	// --- Interactive/web re-auth path (applyAuthNodeUpdate) ---
	registrationID := types.MustAuthID()
	regEntry := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey,
		NodeKey:    key.NewNode().Public(),
		Hostname:   "new-host",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "new-host",
		},
		Expiry: &clientExpiry,
	})
	s.SetAuthCacheEntry(registrationID, regEntry)

	afterReauth, _, err := s.HandleNodeFromAuthPath(
		registrationID, types.UserID(user.ID), nil, "webauth",
	)
	require.NoError(t, err)
	require.Equal(t, "new-host", afterReauth.Hostname())
	require.Equal(t, "new-host", afterReauth.GivenName(),
		"#3432: GivenName must follow the new hostname when re-registering via re-auth")

	// --- Admin renames survive re-registration ---
	_, err = s.nodeStore.SetGivenName(afterReauth.ID(), "custom-label")
	require.NoError(t, err)

	registrationID2 := types.MustAuthID()
	regEntry2 := types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: machineKey,
		NodeKey:    key.NewNode().Public(),
		Hostname:   "another-host",
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "another-host",
		},
		Expiry: &clientExpiry,
	})
	s.SetAuthCacheEntry(registrationID2, regEntry2)

	afterRename, _, err := s.HandleNodeFromAuthPath(
		registrationID2, types.UserID(user.ID), nil, "webauth",
	)
	require.NoError(t, err)
	require.Equal(t, "another-host", afterRename.Hostname())
	require.Equal(t, "custom-label", afterRename.GivenName(),
		"an admin-set GivenName must not be overwritten by client hostname changes")

	// The rename survives pre-auth-key re-registration too.
	pakRegRenamed := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pakKeyFor(t, s, user)},
		NodeKey: key.NewNode().Public(),
		Expiry:  clientExpiry,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "yet-another-host",
		},
	}
	afterPAKRename, _, err := s.HandleNodeFromPreAuthKey(pakRegRenamed, machineKey)
	require.NoError(t, err)
	require.Equal(t, "yet-another-host", afterPAKRename.Hostname())
	require.Equal(t, "custom-label", afterPAKRename.GivenName(),
		"an admin-set GivenName must survive pre-auth-key re-registration")

	// --- Pre-auth-key re-registration on a node with an auto-derived label ---
	pakReg := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pakKeyFor(t, s, user)},
		NodeKey: key.NewNode().Public(),
		Expiry:  clientExpiry,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "pak-host",
		},
	}

	afterPAK, _, err := s.HandleNodeFromPreAuthKey(pakReg, pakMachineKey)
	require.NoError(t, err)
	require.Equal(t, "pak-host", afterPAK.Hostname())
	require.Equal(t, "pak-host", afterPAK.GivenName(),
		"#3432: GivenName must follow the new hostname when re-registering via pre-auth key")
}

func pakKeyFor(t *testing.T, s *State, user *types.User) string {
	t.Helper()

	userID := types.UserID(user.ID)
	pak, err := s.CreatePreAuthKey(&userID, true, false, nil, nil)
	require.NoError(t, err)

	return pak.Key
}
