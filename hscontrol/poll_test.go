package hscontrol

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
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

		time.Sleep(w.firstWriteDelay)

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
//     explicit teardown hook the old serveLongPoll goroutine would stay alive
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
