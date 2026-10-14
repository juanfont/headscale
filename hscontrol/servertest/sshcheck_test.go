package servertest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
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
	_, checkFound := h.Server.State().SSHCheckParams(srcID, dstID, sshCheckLocalUser)
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

// sshCheckLocalUser is the non-root local user the SSH-check polls log in as.
const sshCheckLocalUser = "alice"

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

	actionURL := fmt.Sprintf("%s/machine/ssh/action/%d/to/%d?local_user=%s",
		serverURL, srcID, dstID, sshCheckLocalUser)
	if authID != "" {
		actionURL += "&auth_id=" + authID
	}

	return pollSSHActionURL(t, node, actionURL)
}

// pollSSHActionURL polls actionURL from the given node over its real Noise
// connection.
func pollSSHActionURL(t *testing.T, node *servertest.TestClient, actionURL string) tailcfg.SSHAction {
	t.Helper()

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

// TestSSHCheckRejectedAfterRuleRemoved verifies that once a check rule is
// removed or turned into accept, a client still holding the check gets a
// Reject on both the initial and the follow-up poll, not a hold it could
// pass by authenticating.
// https://github.com/juanfont/headscale/issues/3508
func TestSSHCheckRejectedAfterRuleRemoved(t *testing.T) {
	t.Parallel()

	const check = `{"ssh": [{
		"action": "check",
		"src":    ["harness-default@"],
		"dst":    ["autogroup:self"],
		"users":  ["autogroup:nonroot"]
	}]}`

	for name, after := range map[string]string{
		"rule removed":    `{}`,
		"check to accept": strings.Replace(check, `"check"`, `"accept"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			h := servertest.NewHarness(t, 2)

			srcID := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec
			dstID := types.NodeID(h.Client(1).Netmap().SelfNode.ID()) //nolint:gosec

			h.ChangePolicy(t, []byte(check))

			initial := pollSSHAction(t, h.Server.URL, h.Client(1), srcID, dstID, "")
			require.NotEmpty(t, initial.HoldAndDelegate, "check must hold, got %+v", initial)

			authID := authIDFromHoldURL(t, initial.HoldAndDelegate)

			h.ChangePolicy(t, []byte(after))

			_, checkFound := h.Server.State().SSHCheckParams(srcID, dstID, sshCheckLocalUser)
			require.False(t, checkFound, "test setup: check must be gone")

			for poll, id := range map[string]string{"initial": "", "follow-up": authID.String()} {
				action := pollSSHAction(t, h.Server.URL, h.Client(1), srcID, dstID, id)
				assert.True(t, action.Reject, "%s poll must reject, got %+v", poll, action)
				assert.Empty(t, action.HoldAndDelegate, "%s poll must not delegate", poll)
			}
		})
	}
}

// expandHoldURL substitutes a HoldAndDelegate URL's variables literally, as
// tailssh does before polling it.
func expandHoldURL(holdURL string, srcID, dstID types.NodeID, localUser string) string {
	return strings.NewReplacer(
		"$SRC_NODE_ID", strconv.FormatUint(srcID.Uint64(), 10),
		"$DST_NODE_ID", strconv.FormatUint(dstID.Uint64(), 10),
		"$SSH_USER", url.QueryEscape(localUser),
		"$LOCAL_USER", url.QueryEscape(localUser),
	).Replace(holdURL)
}

// TestSSHCheckFollowsReturnedHoldURL walks a check the way tailssh does:
// expand the HoldAndDelegate URL from the netmap, poll it, then poll the
// URL the server returns. The follow-up must still carry the login user,
// or a root-only rule denies a user who already authenticated.
// https://github.com/juanfont/headscale/issues/3508
func TestSSHCheckFollowsReturnedHoldURL(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 2)

	srcID := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec
	dstID := types.NodeID(h.Client(1).Netmap().SelfNode.ID()) //nolint:gosec

	h.ChangePolicy(t, []byte(`{"ssh": [{
		"action": "check",
		"src":    ["harness-default@"],
		"dst":    ["autogroup:self"],
		"users":  ["root"]
	}]}`))

	var ruleURL string

	h.Client(1).WaitForCondition(t, "check rule in netmap", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			if nm.SSHPolicy == nil || len(nm.SSHPolicy.Rules) == 0 ||
				nm.SSHPolicy.Rules[0].Action == nil {
				return false
			}

			ruleURL = nm.SSHPolicy.Rules[0].Action.HoldAndDelegate

			return ruleURL != ""
		})

	initial := pollSSHActionURL(t, h.Client(1), expandHoldURL(ruleURL, srcID, dstID, "root"))
	require.NotEmpty(t, initial.HoldAndDelegate, "check must hold, got %+v", initial)

	auth, ok := h.Server.State().GetAuthCacheEntry(authIDFromHoldURL(t, initial.HoldAndDelegate))
	require.True(t, ok)
	auth.FinishAuth(types.AuthVerdict{})

	followUp := pollSSHActionURL(t, h.Client(1),
		expandHoldURL(initial.HoldAndDelegate, srcID, dstID, "root"))
	assert.True(t, followUp.Accept, "authenticated root login must be accepted, got %+v", followUp)
}
