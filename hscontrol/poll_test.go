package hscontrol

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type delayedSuccessResponseWriter struct {
	header http.Header

	firstWriteDelay time.Duration

	firstWriteStarted     chan struct{}
	firstWriteStartedOnce sync.Once

	firstWriteFinished     chan struct{}
	firstWriteFinishedOnce sync.Once

	mu         sync.Mutex
	writeCount int
}

func newDelayedSuccessResponseWriter(firstWriteDelay time.Duration) *delayedSuccessResponseWriter {
	return &delayedSuccessResponseWriter{
		header:             make(http.Header),
		firstWriteDelay:    firstWriteDelay,
		firstWriteStarted:  make(chan struct{}),
		firstWriteFinished: make(chan struct{}),
	}
}

func (w *delayedSuccessResponseWriter) Header() http.Header {
	return w.header
}

func (w *delayedSuccessResponseWriter) WriteHeader(int) {}

func (w *delayedSuccessResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	w.writeCount++
	writeCount := w.writeCount
	w.mu.Unlock()

	if writeCount == 1 {
		// Only the first write is delayed. This simulates a transiently wedged map response:
		// long enough to make the batcher time out future sends,
		// but short enough that the old session can still recover if we leave it alive
		w.firstWriteStartedOnce.Do(func() {
			close(w.firstWriteStarted)
		})

		timer := time.NewTimer(w.firstWriteDelay)
		defer timer.Stop()

		<-timer.C

		w.firstWriteFinishedOnce.Do(func() {
			close(w.firstWriteFinished)
		})
	}

	return len(data), nil
}

func (w *delayedSuccessResponseWriter) Flush() {}

func (w *delayedSuccessResponseWriter) FirstWriteStarted() <-chan struct{} {
	return w.firstWriteStarted
}

func (w *delayedSuccessResponseWriter) FirstWriteFinished() <-chan struct{} {
	return w.firstWriteFinished
}

func (w *delayedSuccessResponseWriter) WriteCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.writeCount
}

// recordingResponseWriter records the status code and whether anything was
// written, so a test can tell an explicit error response apart from a handler
// that returned without writing (which net/http turns into an empty 200 the
// client reads as "unexpected EOF").
type recordingResponseWriter struct {
	mu     sync.Mutex
	header http.Header
	status int
	writes int
}

func (w *recordingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}

	return w.header
}

func (w *recordingResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.status == 0 {
		w.status = code
	}
}

func (w *recordingResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.status == 0 {
		w.status = http.StatusOK
	}

	w.writes++

	return len(data), nil
}

func (w *recordingResponseWriter) Flush() {}

func (w *recordingResponseWriter) statusCode() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.status
}

// TestServeLongPollWritesErrorWhenInitialMapFails proves that when the initial
// map cannot be generated (here: the node's own GivenName is invalid, so
// WithSelfNode fails and AddNode errors), serveLongPoll writes an explicit HTTP
// error instead of returning with no body. Returning empty leaves net/http to
// send an empty 200, which the Tailscale client reports as
// "PollNetMap: ... unexpected EOF" and retries forever (issue #3346).
func TestServeLongPollWritesErrorWhenInitialMapFails(t *testing.T) {
	app := createTestApp(t)
	user := app.state.CreateUserForTest("self-bad-name-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "self-bad-name-node")

	// Corrupt the node's stored name to empty so GetFQDN fails for itself,
	// then reload state so the bad row enters the NodeStore verbatim.
	app.mapBatcher.Close()
	require.NoError(t, app.state.Close())

	database, err := db.NewHeadscaleDatabase(app.cfg)
	require.NoError(t, err)
	require.NoError(t, database.DB.
		Model(&types.Node{}).
		Where("id = ?", createdNode.ID).
		Update("given_name", "").Error)
	require.NoError(t, database.Close())

	app.state, err = state.NewState(app.cfg)
	require.NoError(t, err)

	app.mapBatcher = mapper.NewBatcherAndMapper(app.cfg, app.state)
	app.mapBatcher.Start()

	t.Cleanup(func() {
		app.mapBatcher.Close()
		require.NoError(t, app.state.Close())
	})

	nodeView, ok := app.state.GetNodeByID(createdNode.ID)
	require.True(t, ok)

	node := nodeView.AsStruct()

	ctx, cancel := context.WithCancel(context.Background())
	writer := &recordingResponseWriter{}
	session := app.newMapSession(ctx, tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node)

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	t.Cleanup(func() {
		// Break the post-disconnect reconnect wait so the goroutine exits.
		dummyCh := make(chan *tailcfg.MapResponse, 1)
		_ = app.mapBatcher.AddNode(node.ID, dummyCh, tailcfg.CapabilityVersion(100), nil)

		cancel()

		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
		}

		_ = app.mapBatcher.RemoveNode(node.ID, dummyCh)
	})

	assert.Eventually(t, func() bool {
		return writer.statusCode() >= http.StatusInternalServerError
	}, 2*time.Second, 10*time.Millisecond,
		"serveLongPoll must write an HTTP error response when the initial map cannot be built, not an empty 200")
}

// TestFailedReconnectDoesNotCancelEphemeralGC proves that a
// long-poll reconnect attempt which fails before [state.State.Connect] must
// not cancel a previously armed ephemeral GC timer. Cancelling at the start of
// [mapSession.serveLongPoll] left departed ephemeral nodes stuck offline with
// no deletion scheduled (https://github.com/juanfont/headscale/issues/3382).
func TestFailedReconnectDoesNotCancelEphemeralGC(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-cancel-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "eph-gc-cancel-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}, machineKey.Public())
	require.NoError(t, err)

	nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, nodeView.IsEphemeral(), "node must be ephemeral so Cancel would arm on long-poll")

	node := nodeView.AsStruct()

	// Arm a long-lived deletion timer — the state after a normal disconnect
	// has called afterServeLongPoll. A long expiry avoids racing the
	// fail-before-Connect path below.
	app.ephemeralGC.Schedule(node.ID, time.Hour)
	require.True(t, app.ephemeralGC.IsScheduled(node.ID), "test sanity: GC timer must be armed")

	// Drop the node from the NodeStore so UpdateNodeFromMapRequest fails before
	// Connect, while the session still carries an ephemeral AuthKey (so the
	// old Cancel-on-entry path would clear the timer).
	app.state.DeleteNodeFromStoreForTest(node.ID)

	writer := &recordingResponseWriter{}
	session := app.newMapSession(context.Background(), tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node)

	session.serveLongPoll()

	assert.GreaterOrEqual(t, writer.statusCode(), http.StatusInternalServerError,
		"failed reconnect must write an HTTP error before Connect")
	assert.True(t, app.ephemeralGC.IsScheduled(node.ID),
		"failed reconnect must not cancel the ephemeral GC timer (issue #3382)")
}

// TestGitHubIssue3129_TransientlyBlockedWriteDoesNotLeaveLiveStaleSession
// tests the scenario reported in
// https://github.com/juanfont/headscale/issues/3129.
//
// Scenario:
//  1. Start a real long-poll session for one node.
//  2. Block the first map write long enough for the session to stop draining
//     its buffered map-response channel.
//  3. While that write is blocked, queue enough updates to fill the buffered
//     channel and make the next batcher send hit the stale-send timeout.
//  4. That stale-send path removes the session from the batcher, so without an
//     explicit teardown hook the old [mapSession.serveLongPoll] goroutine would stay alive
//     but stop receiving future updates.
//  5. Release the blocked write and verify the batcher-side stop signal makes
//     that stale session exit instead of lingering as an orphaned goroutine.
func TestGitHubIssue3129_TransientlyBlockedWriteDoesNotLeaveLiveStaleSession(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-stale-session-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-stale-session-node")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

	app.cfg.Tuning.BatchChangeDelay = 20 * time.Millisecond
	app.cfg.Tuning.NodeMapSessionBufferedChanSize = 1

	app.mapBatcher.Close()
	require.NoError(t, app.state.Close())

	reloadedState, err := state.NewState(app.cfg)
	require.NoError(t, err)

	app.state = reloadedState

	app.mapBatcher = mapper.NewBatcherAndMapper(app.cfg, app.state)
	app.mapBatcher.Start()

	t.Cleanup(func() {
		app.mapBatcher.Close()
		require.NoError(t, app.state.Close())
	})

	nodeView, ok := app.state.GetNodeByID(createdNode.ID)
	require.True(t, ok, "expected node to be present in NodeStore after reload")
	require.True(t, nodeView.Valid(), "expected valid node view after reload")
	node := nodeView.AsStruct()

	ctx, cancel := context.WithCancel(context.Background())
	writer := newDelayedSuccessResponseWriter(250 * time.Millisecond)
	session := app.newMapSession(ctx, tailcfg.MapRequest{
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node)

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	t.Cleanup(func() {
		dummyCh := make(chan *tailcfg.MapResponse, 1)
		_ = app.mapBatcher.AddNode(node.ID, dummyCh, tailcfg.CapabilityVersion(100), nil)

		cancel()

		select {
		case <-serveDone:
		case <-time.After(2 * time.Second):
		}

		_ = app.mapBatcher.RemoveNode(node.ID, dummyCh)
	})

	select {
	case <-writer.FirstWriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("expected initial map write to start")
	}

	streamsClosed := make(chan struct{})

	go func() {
		app.clientStreamsOpen.Wait()
		close(streamsClosed)
	}()

	// One update fills the buffered session channel while the first write is blocked.
	// The second update then hits the 50ms stale-send timeout, so the batcher prunes
	// the stale connection and triggers its stop hook.
	app.mapBatcher.AddWork(change.SelfUpdate(node.ID), change.SelfUpdate(node.ID))

	select {
	case <-writer.FirstWriteFinished():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the blocked write to eventually complete")
	}

	assert.Eventually(t, func() bool {
		select {
		case <-streamsClosed:
			return true
		default:
			return false
		}
	}, time.Second, 20*time.Millisecond, "after stale-send cleanup, the stale session should exit")
}
