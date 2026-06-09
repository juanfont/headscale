package servertest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestSSHCheckReDelegatesWhenSessionMissing exercises the fix for
// https://github.com/juanfont/headscale/issues/3305 with a real control
// client. The dst node runs the SSH-check poll over its actual Noise
// connection: it first obtains a genuine HoldAndDelegate auth_id, that auth
// session is then dropped from the cache (as it would be on expiry, eviction,
// or a control-plane restart), and the follow-up poll for the now-missing
// session must re-delegate a fresh HoldAndDelegate rather than dead-ending the
// client with an error it keeps retrying until the SSH connection times out.
func TestSSHCheckReDelegatesWhenSessionMissing(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 2)

	srcID := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec
	dstID := types.NodeID(h.Client(1).Netmap().SelfNode.ID()) //nolint:gosec

	// Subject the same-user (src, dst) pair to an SSH check.
	h.ChangePolicy(t, []byte(`{
		"ssh": [{
			"action": "check",
			"src": ["harness-default@"],
			"dst": ["autogroup:self"],
			"users": ["autogroup:nonroot"]
		}]
	}`))

	// Sanity: the policy must actually subject this pair to a check, otherwise
	// the test would pass for the wrong reason.
	_, checkFound := h.Server.State().SSHCheckParams(srcID, dstID)
	require.True(t, checkFound, "test setup: (src, dst) must be subject to an SSH check")

	// The dst node's first poll yields a real HoldAndDelegate carrying a real,
	// cached auth_id — nothing is fabricated.
	initial := pollSSHAction(t, h.Server.URL, h.Client(1), srcID, dstID, "")
	require.NotEmpty(t, initial.HoldAndDelegate, "initial poll must hold and delegate, got %+v", initial)

	authID := authIDFromHoldURL(t, initial.HoldAndDelegate)
	_, ok := h.Server.State().GetAuthCacheEntry(authID)
	require.True(t, ok, "the auth session must be cached after the initial poll")

	// Drop the session, reproducing a natural loss (expiry/eviction/restart).
	h.Server.State().DeleteAuthCacheEntryForTest(authID)
	_, ok = h.Server.State().GetAuthCacheEntry(authID)
	require.False(t, ok, "the auth session must be gone before the follow-up poll")

	// The follow-up poll carries the real auth_id whose session is now missing.
	// With an active check the server must re-delegate a fresh session.
	followUp := pollSSHAction(t, h.Server.URL, h.Client(1), srcID, dstID, authID.String())
	require.NotEmpty(t, followUp.HoldAndDelegate,
		"a missing session under an active check must re-delegate, got %+v", followUp)

	require.NotEqual(t, authID, authIDFromHoldURL(t, followUp.HoldAndDelegate),
		"re-delegation must mint a fresh auth_id")
}

// pollSSHAction issues an /machine/ssh/action poll from the given node over its
// real Noise connection, as tailscaled does. An empty authID is the initial
// poll; a non-empty one is a follow-up.
func pollSSHAction(
	t *testing.T,
	serverURL string,
	node *servertest.TestClient,
	srcID, dstID types.NodeID,
	authID string,
) tailcfg.SSHAction {
	t.Helper()

	actionURL := fmt.Sprintf("%s/machine/ssh/action/%d/to/%d", serverURL, srcID, dstID)
	if authID != "" {
		actionURL += "?auth_id=" + authID
	}

	// Noise requests are addressed with the https scheme; the control client
	// routes them over the established Noise connection (mirroring how
	// controlclient issues its own register/map calls).
	actionURL = strings.Replace(actionURL, "http://", "https://", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, actionURL, nil)
	require.NoError(t, err)

	resp, err := node.Direct().DoNoiseRequest(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "ssh action poll must return 200")

	var action tailcfg.SSHAction
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&action))

	return action
}

// authIDFromHoldURL extracts the auth_id query parameter from a HoldAndDelegate
// URL.
func authIDFromHoldURL(t *testing.T, holdURL string) types.AuthID {
	t.Helper()

	u, err := url.Parse(holdURL)
	require.NoError(t, err)

	authID, err := types.AuthIDFromString(u.Query().Get("auth_id"))
	require.NoError(t, err, "HoldAndDelegate URL missing a valid auth_id: %s", holdURL)

	return authID
}
