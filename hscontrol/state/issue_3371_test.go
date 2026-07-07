package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestIssue3371_TaggedNodeLogoutLocksOutSingleUseKey reproduces
// https://github.com/juanfont/headscale/issues/3371:
//
// A tagged node that runs `tailscale logout` can never log back in with an
// auth key. Two behaviours combine:
//
//  1. logout sets a past expiry even on a tagged node: handleLogout ->
//     SetNodeExpiry runs unconditionally, with no IsTagged guard, so a tagged
//     node (which is supposed to have key-expiry disabled) ends up Expired.
//  2. Re-registration does not clear it: the expiry-refresh block in
//     HandleNodeFromPreAuthKey is gated on `!node.IsTagged()`, so a tagged
//     node keeps its (now past) expiry.
//
// The node therefore stays expired, so re-registration takes the
// expired-node validation path (isExpired == true) and re-validates the
// already-spent one-shot key, rejecting it with "authkey already used".
func TestIssue3371_TaggedNodeLogoutLocksOutSingleUseKey(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{"tagOwners":{"tag:foo":["tagger@"]}}`))
	require.NoError(t, err)

	// Single-use, tags-only key: `headscale preauthkeys create --tags tag:foo`.
	pak, err := s.CreatePreAuthKey(nil, false, false, nil, []string{"tag:foo"})
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "tagged-node"},
	}

	first, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)
	require.True(t, first.IsTagged(), "precondition: node is tagged")
	require.Nil(t, first.AsStruct().Expiry, "precondition: tagged node starts with no expiry")

	// `tailscale logout`: the client sends a past expiry. handleLogout clamps it
	// to now and calls SetNodeExpiry with no IsTagged guard.
	logoutExpiry := time.Now()
	loggedOut, _, err := s.SetNodeExpiry(first.ID(), &logoutExpiry)
	require.NoError(t, err)
	require.True(t, loggedOut.IsExpired(), "after logout the tagged node is expired")

	// `tailscale up --auth-key <same key>`: the node re-registers with the same,
	// now-spent one-shot key. It must be able to log back in.
	second, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err,
		"tagged node must be able to log back in after logout (issue #3371)")
	require.True(t, second.Valid())
	require.True(t, second.IsTagged(), "node stays tagged")
	require.False(t, second.IsExpired(),
		"tagged node must not remain expired after re-authentication")
}
