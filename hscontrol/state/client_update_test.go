package state

import (
	"context"
	"encoding/json"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestRequestClientUpdate holds each reason a node gives for not starting
// an update; the node's c2n answer is played by the send func.
func TestRequestClientUpdate(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	setHostinfo := func(hi *tailcfg.Hostinfo) {
		s.nodeStore.UpdateNode(id, func(n *types.Node) { n.Hostinfo = hi })
	}

	// answer completes the c2n request of the ping with raw.
	answer := func(raw string) func(...change.Change) {
		return func(cs ...change.Change) {
			u, err := url.Parse(cs[0].PingRequest.URL)
			require.NoError(t, err)

			go s.CompleteC2N(u.Query().Get("id"), []byte(raw))
		}
	}

	never := func(...change.Change) {}

	reason := func(t *testing.T, err error) *ClientUpdateRefusedError {
		t.Helper()

		r, ok := err.(*ClientUpdateRefusedError) //nolint:errorlint // the type itself
		require.True(t, ok, "%v", err)

		return r
	}

	setHostinfo(nil)
	require.Equal(t, UpdateNotConnected, reason(t, s.RequestClientUpdate(t.Context(), id, true, never)).Reason, "a node that never reported")

	setHostinfo(&tailcfg.Hostinfo{IPNVersion: "1.80.0"})
	require.Equal(t, UpdateNotAllowed, reason(t, s.RequestClientUpdate(t.Context(), id, true, never)).Reason)

	setHostinfo(&tailcfg.Hostinfo{IPNVersion: "1.80.0", AllowsUpdate: true})
	require.Equal(t, UpdateNotConnected, reason(t, s.RequestClientUpdate(t.Context(), id, false, never)).Reason)

	refused := reason(t, s.RequestClientUpdate(t.Context(), id, true,
		answer("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"Started\":false,\"Err\":\"not on a package manager\"}")))
	require.Equal(t, UpdateRefusedByClient, refused.Reason)
	require.Equal(t, "not on a package manager", refused.ClientError)

	bad := reason(t, s.RequestClientUpdate(t.Context(), id, true, answer("HTTP/1.1 404 Not Found\r\n\r\n")))
	require.Equal(t, UpdateRefusedByClient, bad.Reason)
	require.ErrorIs(t, bad, ErrC2NBadAnswer)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.Equal(t, UpdateAnswerNotInTime, reason(t, s.RequestClientUpdate(ctx, id, true, never)).Reason)

	// The node's text is cleaned and clipped before an admin or a log
	// sees it.
	hostile := "\x1b]8;;https://evil\x07click\u202eexe.txt" + strings.Repeat("é", 40<<10)
	body, err := json.Marshal(tailcfg.C2NUpdateResponse{Err: hostile})
	require.NoError(t, err)

	clipped := reason(t, s.RequestClientUpdate(t.Context(), id, true,
		answer("HTTP/1.1 200 OK\r\n\r\n"+string(body))))
	require.Equal(t, UpdateRefusedByClient, clipped.Reason)
	require.NoError(t, types.ValidateUserText(clipped.ClientError))
	require.True(t, utf8.ValidString(clipped.ClientError))
	require.LessOrEqual(t, len(clipped.ClientError), maxClientText+len("…"))
	require.True(t, strings.HasPrefix(clipped.ClientError, "\uFFFD]8;;https://evil\uFFFDclick\uFFFDexe.txt"), clipped.ClientError)

	require.NoError(t, s.RequestClientUpdate(t.Context(), id, true,
		answer("HTTP/1.1 200 OK\r\n\r\n{\"Started\":true}")))
	require.True(t, s.ClientUpdating(id, "1.80.0"))

	require.ErrorIs(t, s.RequestClientUpdate(t.Context(), 999, true, never), ErrNodeNotInNodeStore)
}

// TestRequestClientUpdateOneAtATime: callers that ask one node at once share
// one request to it and its answer.
func TestRequestClientUpdateOneAtATime(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	s.nodeStore.UpdateNode(id, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{IPNVersion: "1.80.0", AllowsUpdate: true}
	})

	const callers = 10

	var pings atomic.Int32

	release := make(chan struct{})
	send := func(cs ...change.Change) {
		pings.Add(1)

		u, err := url.Parse(cs[0].PingRequest.URL)
		require.NoError(t, err)

		go func() {
			<-release
			s.CompleteC2N(u.Query().Get("id"), []byte("HTTP/1.1 200 OK\r\n\r\n{\"Started\":true}"))
		}()
	}

	errs := make(chan error, callers)

	for range callers {
		go func() { errs <- s.RequestClientUpdate(t.Context(), id, true, send) }()
	}

	// Every caller waits for the one answer before it is given.
	buf := make([]byte, 1<<22)

	require.Eventually(t, func() bool {
		waiting := 0

		for g := range strings.SplitSeq(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "[select") && strings.Contains(g, "(*State).RequestClientUpdate(") {
				waiting++
			}
		}

		return waiting == callers
	}, 5*time.Second, time.Millisecond)
	close(release)

	for range callers {
		require.NoError(t, <-errs)
	}

	require.Equal(t, int32(1), pings.Load(), "one ping for every caller")
}
