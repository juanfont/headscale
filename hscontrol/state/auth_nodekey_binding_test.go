package state

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestPreAuthKeyReauthRejectsVictimNodeKey ensures the PAK re-registration
// rotation path enforces the same 1:1 NodeKey<->MachineKey binding the other
// registration paths do. NodeKeys are public (peers learn them from the
// netmap), so an authenticated attacker must not be able to rotate their own
// node's NodeKey onto a victim's NodeKey: doing so poisons the NodeStore
// NodeKey index and denies the victim service.
func TestPreAuthKeyReauthRejectsVictimNodeKey(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	// Attacker owns N_a under U_a with machine key M_a.
	attacker := database.CreateUserForTest("attacker")
	attackerNode := database.CreateRegisteredNodeForTest(attacker, "attacker-node")
	attackerMachineKey := attackerNode.MachineKey

	// Victim owns N_v under U_v with a distinct, public NodeKey K_v.
	victim := database.CreateUserForTest("victim")
	victimNode := database.CreateRegisteredNodeForTest(victim, "victim-node")
	victimNodeKey := victimNode.NodeKey

	require.NotEqual(t, attackerNode.NodeKey, victimNodeKey,
		"precondition: attacker and victim must have distinct NodeKeys")
	require.NotEqual(t, attackerNode.MachineKey, victimNode.MachineKey,
		"precondition: attacker and victim must have distinct MachineKeys")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Attacker mints their own valid pre-auth key for their own user.
	attackerUserID := types.UserID(attacker.ID)
	pak, err := s.CreatePreAuthKey(&attackerUserID, true, false, nil, nil)
	require.NoError(t, err)

	// Attacker re-registers over their own noise session (machine key M_a)
	// with a valid PAK but carries the victim's NodeKey K_v and a non-past
	// expiry (skipping the logout-first branch).
	clientExpiry := time.Now().Add(180 * 24 * time.Hour)
	regReq := tailcfg.RegisterRequest{
		Auth:    &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey: victimNodeKey,
		Expiry:  clientExpiry,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "attacker-node",
		},
	}

	_, _, err = s.HandleNodeFromPreAuthKey(regReq, attackerMachineKey)
	require.ErrorIs(t, err, ErrNodeKeyInUse,
		"attacker must not be able to claim the victim's NodeKey via PAK re-registration")

	// The victim's NodeKey index must still resolve to the victim's node.
	resolved, ok := s.nodeStore.GetNodeByNodeKey(victimNodeKey)
	require.True(t, ok, "victim NodeKey must still be present in the index")
	require.Equal(t, victimNode.MachineKey, resolved.MachineKey(),
		"victim NodeKey must remain bound to the victim's MachineKey")
}
