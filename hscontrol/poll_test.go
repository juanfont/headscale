package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

var (
	errRegistrationGCPolicy = errors.New("node policy update failed")
	errRegistrationGCName   = errors.New("node name persistence failed")
)

func TestEphemeralGCArmedAfterNamePersistFailure(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.cfg.Node.Ephemeral.InactivityTimeout = time.Hour
	app.StartEphemeralGCForTest(t)
	user := app.state.CreateUserForTest("gc-name-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)

	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "shared"},
	}
	_, err = app.handleRegisterWithAuthKey(req, key.NewMachine().Public())
	require.NoError(t, err)

	first, ok := app.state.GetNodeByNodeKey(req.NodeKey)
	require.True(t, ok)

	require.NoError(t, app.state.DB().DB.Callback().Update().Before("gorm:update").
		Register("fail_gc_name_persist", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errRegistrationGCName)
			}
		}))
	t.Cleanup(func() {
		_ = app.state.DB().DB.Callback().Update().Remove("fail_gc_name_persist")
	})

	app.cfg.Node.Ephemeral.InactivityTimeout = 200 * time.Millisecond
	req.NodeKey = key.NewNode().Public()
	_, err = app.handleRegisterWithAuthKey(req, key.NewMachine().Public())
	require.ErrorIs(t, err, errRegistrationGCName)

	second, ok := app.state.GetNodeByNodeKey(req.NodeKey)
	require.True(t, ok, "registration committed before the name UPDATE failed")
	require.Equal(t, "shared-1", second.GivenName())
	assert.True(t, app.ephemeralGC.IsScheduled(second.ID()))
	row, err := app.state.DB().GetNodeByID(second.ID())
	require.NoError(t, err)
	assert.Equal(t, "shared", row.GivenName)

	require.Eventually(t, func() bool {
		_, ok := app.state.GetNodeByID(second.ID())
		return !ok
	}, 5*time.Second, 10*time.Millisecond,
		"a committed registration must be collected after a name persistence error")

	_, err = app.state.DB().GetNodeByID(second.ID())
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	_, ok = app.state.GetNodeByID(first.ID())
	require.True(t, ok)
}

type registrationGCPolicyManager struct {
	policy.PolicyManager
}

func (registrationGCPolicyManager) SetNodes(views.Slice[types.NodeView]) (bool, error) {
	return false, errRegistrationGCPolicy
}

// NodesGeneration stays put, as after a writer recompile that failed, so
// the caller's own refresh runs and fails too.
func (registrationGCPolicyManager) NodesGeneration() uint64 { return 0 }

func TestEphemeralGCArmedAtRegistration(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"new", "reregister", "policy failure"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			app := createTestApp(t)
			app.cfg.Node.Ephemeral.InactivityTimeout = 50 * time.Millisecond
			app.StartEphemeralGCForTest(t)
			user := app.state.CreateUserForTest("gc-register-user")
			pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
			require.NoError(t, err)

			req := tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "gc-register-node"},
			}

			machineKey := key.NewMachine().Public()
			if name == "reregister" {
				_, _, err = app.state.HandleNodeFromPreAuthKey(req, machineKey)
				require.NoError(t, err)
			}

			if name == "policy failure" {
				app.state.WrapPolicyManagerForTest(
					func(pm policy.PolicyManager) policy.PolicyManager {
						return registrationGCPolicyManager{pm}
					},
				)
			}

			_, err = app.handleRegisterWithAuthKey(req, machineKey)
			if name == "policy failure" {
				require.ErrorIs(t, err, errRegistrationGCPolicy)
			} else {
				require.NoError(t, err)
			}

			node, ok := app.state.GetNodeByNodeKey(req.NodeKey)
			require.True(t, ok, "registration committed the node")
			require.True(t, node.IsEphemeral())
			assert.True(t, app.ephemeralGC.IsScheduled(node.ID()))
			require.Eventually(t, func() bool {
				_, ok := app.state.GetNodeByID(node.ID())
				return !ok
			}, 5*time.Second, 10*time.Millisecond,
				"a node that never polls must be collected")

			_, err = app.state.DB().GetNodeByID(node.ID())
			require.ErrorIs(t, err, gorm.ErrRecordNotFound)
		})
	}
}

type delayedSuccessResponseWriter struct {
	header http.Header

	firstWriteDelay time.Duration

	firstWriteStarted     chan struct{}
	firstWriteStartedOnce sync.Once

	firstWriteFinished     chan struct{}
	firstWriteFinishedOnce sync.Once

	mu         sync.Mutex
	writeCount int
	body       []byte
}

// deadlineResponseWriter simulates an HTTP/2 response blocked on flow control.
// The write only returns when the handler expires its per-stream write deadline.
type deadlineResponseWriter struct {
	header http.Header

	blockWrites atomic.Bool
	writeCount  atomic.Int64

	writeStarted     chan struct{}
	writeStartedOnce sync.Once
	deadlineSet      chan struct{}
	deadlineSetOnce  sync.Once
}

func newDeadlineResponseWriter() *deadlineResponseWriter {
	return &deadlineResponseWriter{
		header:       make(http.Header),
		writeStarted: make(chan struct{}),
		deadlineSet:  make(chan struct{}),
	}
}

func (w *deadlineResponseWriter) Header() http.Header {
	return w.header
}

func (w *deadlineResponseWriter) WriteHeader(int) {}

func (w *deadlineResponseWriter) Write(data []byte) (int, error) {
	w.writeCount.Add(1)

	if !w.blockWrites.Load() {
		return len(data), nil
	}

	w.writeStartedOnce.Do(func() { close(w.writeStarted) })
	<-w.deadlineSet

	return 0, context.DeadlineExceeded
}

func (w *deadlineResponseWriter) Flush() {}

func (w *deadlineResponseWriter) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		w.deadlineSetOnce.Do(func() { close(w.deadlineSet) })
	}

	return nil
}

func (w *deadlineResponseWriter) WriteStarted() <-chan struct{} {
	return w.writeStarted
}

func (w *deadlineResponseWriter) BlockWrites() {
	w.blockWrites.Store(true)
}

func (w *deadlineResponseWriter) WriteCount() int64 {
	return w.writeCount.Load()
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
		// Only the first write is delayed: once it returns the session drains its
		// backlog (transient) or observes the stop signal (evicted).
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

	w.mu.Lock()
	w.body = append(w.body, data...)
	w.mu.Unlock()

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

func (w *delayedSuccessResponseWriter) Body() string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return string(w.body)
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
		NodeKey: node.NodeKey,
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node.View())

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
	// Registration arms the timer too; it must not fire during the test.
	app.cfg.Node.Ephemeral.InactivityTimeout = time.Hour
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
		NodeKey: node.NodeKey,
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node.View())

	session.serveLongPoll()

	assert.GreaterOrEqual(t, writer.statusCode(), http.StatusInternalServerError,
		"failed reconnect must write an HTTP error before Connect")
	assert.True(t, app.ephemeralGC.IsScheduled(node.ID),
		"failed reconnect must not cancel the ephemeral GC timer (issue #3382)")
}

func TestStaleGCTimerSparesPermanentNode(t *testing.T) {
	t.Parallel()
	app := createTestApp(t)
	app.cfg.Node.Ephemeral.InactivityTimeout = time.Hour
	app.StartEphemeralGCForTest(t)
	user := app.state.CreateUserForTest("gc-permanent-user")
	ephemeral, err := app.state.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)
	permanent, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine().Public()
	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: ephemeral.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "gc-permanent-node"},
	}
	_, err = app.handleRegisterWithAuthKey(req, machineKey)
	require.NoError(t, err)

	node, ok := app.state.GetNodeByNodeKey(req.NodeKey)
	require.True(t, ok)
	require.True(t, node.IsEphemeral())
	session := app.newMapSession(t.Context(), tailcfg.MapRequest{},
		&recordingResponseWriter{}, node)
	_, epoch := app.state.Connect(node.ID())
	app.ephemeralGC.Cancel(node.ID())

	req.Auth.AuthKey = permanent.Key
	_, err = app.handleRegisterWithAuthKey(req, machineKey)
	require.NoError(t, err)

	fresh, ok := app.state.GetNodeByID(node.ID())
	require.True(t, ok)
	require.False(t, fresh.IsEphemeral())

	_, err = app.state.Disconnect(node.ID(), epoch)
	require.NoError(t, err)

	app.cfg.Node.Ephemeral.InactivityTimeout = 25 * time.Millisecond

	session.afterServeLongPoll()
	require.True(t, app.ephemeralGC.IsScheduled(node.ID()))

	require.Eventually(t, func() bool {
		return !app.ephemeralGC.IsScheduled(node.ID())
	}, time.Second, 5*time.Millisecond)
	assert.Never(t, func() bool {
		_, ok := app.state.GetNodeByID(node.ID())
		return !ok
	}, 2*time.Second, 5*time.Millisecond,
		"a stale session must not collect a node that became permanent")

	_, err = app.state.DB().GetNodeByID(node.ID())
	require.NoError(t, err)
}

// TestEphemeralGCDoesNotDeleteReconnectedNode replays, in order, the
// interleaving of two sessions from
// https://github.com/juanfont/headscale/issues/3535: the old session takes the
// node offline, a reconnect brings it back online and cancels the GC before
// the old session arms its timer. The armed timer is stale; firing it must not
// delete a node that has a live session.
func TestEphemeralGCDoesNotDeleteReconnectedNode(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	app.cfg.Node.Ephemeral.InactivityTimeout = time.Hour
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-reconnect-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth: &tailcfg.RegisterResponseAuth{
			AuthKey: pak.Key,
		},
		NodeKey: nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "eph-gc-reconnect-node",
		},
		Expiry: time.Now().Add(24 * time.Hour),
	}, key.NewMachine().Public())
	require.NoError(t, err)

	nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, nodeView.IsEphemeral(), "test sanity: node must be ephemeral")

	node := nodeView.AsStruct()
	session := app.newMapSession(context.Background(), tailcfg.MapRequest{
		NodeKey: node.NodeKey,
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, &recordingResponseWriter{}, node.View())

	_, oldGen := app.state.Connect(node.ID)
	app.ephemeralGC.Cancel(node.ID)
	app.cfg.Node.Ephemeral.InactivityTimeout = 50 * time.Millisecond

	// Old session's cleanup releases the last session.
	offline, err := app.state.Disconnect(node.ID, oldGen)
	require.NoError(t, err)
	require.NotEmpty(t, offline, "test sanity: old session must take the node offline")

	// Reconnect: what serveLongPoll does at Connect.
	_, newGen := app.state.Connect(node.ID)
	app.ephemeralGC.Cancel(node.ID)

	// Old session's cleanup continues and arms the GC.
	session.afterServeLongPoll()

	online, ok := app.state.GetNodeByID(node.ID)
	require.True(t, ok)
	require.True(t, online.Online(), "test sanity: reconnected node must be online")

	// The GC's delete lands only after a NodeStore batch flush, so watch
	// well past the inactivity timeout.
	assert.Never(t, func() bool {
		_, ok := app.state.GetNodeByID(node.ID)

		return !ok
	}, 2*time.Second, 10*time.Millisecond,
		"ephemeral GC must not delete a node with a live session (issue #3535)")

	// Once the reconnected session ends, the node is idle and must still be
	// collected.
	_, err = app.state.Disconnect(node.ID, newGen)
	require.NoError(t, err)
	session.afterServeLongPoll()

	assert.Eventually(t, func() bool {
		_, ok := app.state.GetNodeByID(node.ID)

		return !ok
	}, 5*time.Second, 10*time.Millisecond,
		"an idle ephemeral node must still be garbage collected")
}

// TestDeleteNodeCancelsEphemeralGC deletes a disconnected ephemeral node
// through the API while its inactivity timer is armed. The timer belongs to
// the deleted node, so the delete must disarm it rather than leave it to fire
// at a node that is no longer there.
func TestDeleteNodeCancelsEphemeralGC(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	// Registration arms the timer too; it must not fire during the test.
	app.cfg.Node.Ephemeral.InactivityTimeout = time.Hour
	app.StartEphemeralGCForTest(t)

	user := app.state.CreateUserForTest("eph-gc-delete-user")
	pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, true, nil, nil)
	require.NoError(t, err)

	nodeKey := key.NewNode()

	_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  nodeKey.Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "eph-gc-delete-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}, key.NewMachine().Public())
	require.NoError(t, err)

	node, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
	require.True(t, ok)
	require.True(t, node.IsEphemeral(), "test sanity: node must be ephemeral")

	// The state a disconnect leaves behind.
	app.ephemeralGC.Schedule(node.ID(), time.Hour)
	require.True(t, app.ephemeralGC.IsScheduled(node.ID()), "test sanity: GC timer must be armed")

	api := registerAPIV2(t, app)
	require.Equal(t, http.StatusOK, api.Delete("/api/v2/device/"+node.ID().String()).Code)

	assert.False(t, app.ephemeralGC.IsScheduled(node.ID()),
		"deleting a node must cancel its ephemeral GC timer")
}

// TestGitHubIssue3129_BlockedWriteSessionLifecycle
// tests the scenario reported in
// https://github.com/juanfont/headscale/issues/3129.
//
// Scenario:
//  1. Start a real long-poll session for one node.
//  2. Block the first map write long enough for the session to stop draining
//     its buffered map-response channel.
//  3. While that write is blocked, queue enough updates to fill the buffered
//     channel and make the next batcher send encounter backpressure.
//  4. A transient stall must keep the session registered and deliver the queued
//     updates once the write completes. A stall past the batcher's stall budget
//     must remove the connection and signal its owning session before shutdown.
//  5. After the stalled write completes, verify that [mapSession.serveLongPoll]
//     exits instead of lingering alive without receiving future updates.
func TestGitHubIssue3129_BlockedWriteSessionLifecycle(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		writeDelay time.Duration
		evicted    bool
	}{
		{name: "transient", writeDelay: 250 * time.Millisecond},
		// Well past the stall budget, so a starved runner still evicts before the write returns.
		{name: "stalled", writeDelay: 10 * time.Second, evicted: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
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
			writer := newDelayedSuccessResponseWriter(tt.writeDelay)
			session := app.newMapSession(ctx, tailcfg.MapRequest{
				NodeKey: node.NodeKey,
				Stream:  true,
				Version: tailcfg.CapabilityVersion(100),
			}, writer, node.View())

			serveDone := make(chan struct{})

			go func() {
				session.serveLongPoll()
				close(serveDone)
			}()

			t.Cleanup(func() {
				cancel()
				app.mapBatcher.Close()

				select {
				case <-serveDone:
				case <-time.After(2 * time.Second):
				}
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

			// Distinct pings cannot collapse into a state refresh on retry. Both must
			// reach a recovering client, including the one that encountered a full channel.
			const (
				firstPing  = "https://example.com/queued-first"
				secondPing = "https://example.com/queued-second"
			)
			app.mapBatcher.AddWork(
				change.PingNode(node.ID, &tailcfg.PingRequest{URL: firstPing}),
				change.PingNode(node.ID, &tailcfg.PingRequest{URL: secondPing}),
			)

			if tt.evicted {
				require.Eventually(t, func() bool {
					return app.mapBatcher.Debug()[node.ID].ActiveConnections == 0
				}, 8*time.Second, 10*time.Millisecond, "a stalled session must be pruned from the batcher")
				require.Eventually(t, session.cancelChClosed.Load, time.Second, 10*time.Millisecond,
					"stale eviction must stop the session before batcher shutdown")
			}

			select {
			case <-writer.FirstWriteFinished():
			case <-time.After(tt.writeDelay + time.Second):
				t.Fatal("expected the blocked write to eventually complete")
			}

			if !tt.evicted {
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					body := writer.Body()
					assert.Contains(c, body, firstPing)
					assert.Contains(c, body, secondPing)
				}, 2*time.Second, 10*time.Millisecond, "a transiently blocked session must receive both queued pings")
				assert.Equal(t, 1, app.mapBatcher.Debug()[node.ID].ActiveConnections,
					"transient backpressure must not evict the session")
				assert.False(t, session.cancelChClosed.Load(), "transient backpressure must not stop the session")

				return
			}

			// Shutdown skips reconnect grace; the stream wait includes disconnect cleanup.
			app.mapBatcher.Close()

			assert.Eventually(t, func() bool {
				select {
				case <-streamsClosed:
					return true
				default:
					return false
				}
			}, time.Second, 20*time.Millisecond, "after stale-send cleanup, the stale session should exit")
		})
	}
}

// TestDeletedNodeEndsLongPoll proves that deleting a node ends its long-poll
// session, rather than leaving the goroutine streaming to a node that no longer
// exists. An orphaned session blocks server shutdown on clientStreamsOpen and
// keeps the client polling instead of re-authenticating.
//
// It also pins the teardown latency: a deleted node cannot reconnect, so the
// session must not spend the reconnect grace period waiting for one.
//
// See: https://github.com/juanfont/headscale/issues/3410
func TestDeletedNodeEndsLongPoll(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-delete-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-delete-node")
	require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())

	app.cfg.Tuning.NodeMapSessionBufferedChanSize = 1

	// Reload so the NodeStore is populated from the database; the create
	// helpers only write to the database.
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
	require.True(t, ok)

	node := nodeView.AsStruct()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	writer := newDelayedSuccessResponseWriter(0)
	session := app.newMapSession(ctx, tailcfg.MapRequest{
		NodeKey: node.NodeKey,
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, node.View())

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	select {
	case <-writer.FirstWriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the initial map write to start")
	}

	cs, err := app.state.DeleteNode(nodeView)
	require.NoError(t, err)
	app.Change(cs...)

	// The reconnect grace period is 10s, so a generous bound here still fails
	// if teardown waits for a node that can never come back.
	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
		t.Fatal("deleting a node must promptly end its long-poll session")
	}

	streamsClosed := make(chan struct{})

	go func() {
		app.clientStreamsOpen.Wait()
		close(streamsClosed)
	}()

	select {
	case <-streamsClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("an orphaned session would block server shutdown on clientStreamsOpen")
	}
}

// TestDeletedNodeEndsStreamCleanly serves a long poll over HTTP/2, as the
// Noise server does, and deletes the node, a clean stop, so the stream must
// end with END_STREAM: an expired write deadline resets it with
// INTERNAL_ERROR, which the client reports as a server error. That holds
// with a write in flight too, as long as the client keeps reading; a client
// that stopped reading must still not keep the session past the grace.
func TestDeletedNodeEndsStreamCleanly(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name              string
		inFlight, stalled bool
	}{
		{name: "idle"},
		{name: "write_in_flight", inFlight: true},
		{name: "client_stalled", inFlight: true, stalled: true},
	} {
		inFlight := tt.inFlight

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			app := createTestApp(t)
			app.cfg.Tuning.NodeMapSessionBufferedChanSize = 30

			user := app.state.CreateUserForTest("poll-delete-clean-user")
			pak, err := app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
			require.NoError(t, err)

			nodeKey := key.NewNode()

			_, err = app.handleRegister(context.Background(), tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  nodeKey.Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "poll-delete-clean-node"},
				Expiry:   time.Now().Add(24 * time.Hour),
			}, key.NewMachine().Public())
			require.NoError(t, err)

			nodeView, ok := app.state.GetNodeByNodeKey(nodeKey.Public())
			require.True(t, ok)

			sessions := make(chan *mapSession, 1)
			served := make(chan struct{})
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				session := app.newMapSession(r.Context(), tailcfg.MapRequest{
					NodeKey: nodeView.NodeKey(),
					Stream:  true,
					Version: tailcfg.CapabilityVersion(100),
				}, w, nodeView)
				sessions <- session

				session.serveLongPoll()
				close(served)
			}))
			srv.Config.Protocols = new(http.Protocols)
			srv.Config.Protocols.SetUnencryptedHTTP2(true)
			srv.Start()
			t.Cleanup(srv.Close)

			h2c := new(http.Protocols)
			h2c.SetUnencryptedHTTP2(true)
			// A small window lets a client that pauses reading block a write.
			client := &http.Client{Transport: &http.Transport{
				Protocols: h2c,
				HTTP2:     &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10},
			}}

			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, nil)
			require.NoError(t, err)

			resp, err := client.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			var size [4]byte

			_, err = io.ReadFull(resp.Body, size[:])
			require.NoError(t, err, "expected the initial map")

			if inFlight {
				session := <-sessions
				session.ch <- &tailcfg.MapResponse{Domain: strings.Repeat("x", 1<<20)}

				require.Eventually(t, session.writing.Load, 2*time.Second, 10*time.Millisecond,
					"test sanity: the frame must outgrow the window and block")
			}

			cs, err := app.state.DeleteNode(nodeView)
			require.NoError(t, err)
			app.Change(cs...)

			if tt.stalled {
				select {
				case <-served:
				case <-time.After(stopWriteGrace + 3*time.Second):
					t.Fatal("a client that stopped reading must not keep a stopped session")
				}

				return
			}

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err, "a clean stop must end the stream, not reset it")
		})
	}
}

// TestLongPollShutdownWaitsForCleanup catches streams counted as closed before
// their disconnect cleanup finishes, including sessions already in reconnect grace.
func TestLongPollShutdownWaitsForCleanup(t *testing.T) {
	t.Parallel()

	for _, inGrace := range []bool{false, true} {
		t.Run(fmt.Sprintf("in_grace=%t", inGrace), func(t *testing.T) {
			t.Parallel()

			app := createTestApp(t)
			user := app.state.CreateUserForTest("poll-shutdown-user")
			createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-shutdown-node")
			require.NoError(t, app.state.UpdatePolicyManagerUsersForTest())
			app.cfg.Tuning.NodeMapSessionBufferedChanSize = 1

			app.mapBatcher.Close()
			require.NoError(t, app.state.Close())

			var err error

			app.state, err = state.NewState(app.cfg)
			require.NoError(t, err)

			app.mapBatcher = mapper.NewBatcherAndMapper(app.cfg, app.state)
			app.mapBatcher.Start()

			node, ok := app.state.GetNodeByID(createdNode.ID)
			require.True(t, ok)

			ctx, cancel := context.WithCancel(t.Context())
			writer := newDelayedSuccessResponseWriter(0)
			session := app.newMapSession(ctx, tailcfg.MapRequest{
				NodeKey: node.NodeKey(),
				Stream:  true,
				Version: tailcfg.CapabilityVersion(100),
			}, writer, node)

			serveDone := make(chan struct{})

			go func() {
				session.serveLongPoll()
				close(serveDone)
			}()

			t.Cleanup(func() {
				cancel()
				app.mapBatcher.Close()

				select {
				case <-serveDone:
				case <-time.After(15 * time.Second):
					t.Error("map session did not finish cleanup")
				}

				require.NoError(t, app.state.Close())
			})

			require.Eventually(t, func() bool {
				return writer.WriteCount() >= 2 && app.mapBatcher.IsConnected(node.ID())
			}, 2*time.Second, 10*time.Millisecond, "map session should connect")

			if inGrace {
				cancel()
				require.Eventually(t, func() bool {
					return !app.mapBatcher.IsConnected(node.ID())
				}, 2*time.Second, 10*time.Millisecond, "session should enter reconnect grace")

				pending, ok := app.state.GetNodeByID(node.ID())
				require.True(t, ok)
				require.Equal(t, 1, pending.ActiveSessions(), "reconnect grace should keep the node online")
			}

			streamsClosed := make(chan struct{})

			go func() {
				app.mapBatcher.Close()
				app.clientStreamsOpen.Wait()
				close(streamsClosed)
			}()

			select {
			case <-streamsClosed:
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown must interrupt reconnect grace and wait for cleanup")
			}

			disconnected, ok := app.state.GetNodeByID(node.ID())
			require.True(t, ok)
			assert.Zero(t, disconnected.ActiveSessions(), "shutdown must wait for the session to release")
			assert.False(t, disconnected.Online(), "the last session must take the node offline before shutdown returns")

			persisted, err := app.state.DB().GetNodeByID(node.ID())
			require.NoError(t, err)
			require.NotNil(t, persisted.LastSeen)
			assert.True(t, persisted.LastSeen.Equal(disconnected.LastSeen().Get()),
				"shutdown must wait for the disconnect write to finish")
		})
	}
}

func TestDeletedNodeInterruptsBlockedWrite(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("poll-delete-blocked-user")
	createdNode := app.state.CreateRegisteredNodeForTest(user, "poll-delete-blocked-node")
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
	require.True(t, ok)

	writer := newDeadlineResponseWriter()
	session := app.newMapSession(t.Context(), tailcfg.MapRequest{
		NodeKey: nodeView.NodeKey(),
		Stream:  true,
		Version: tailcfg.CapabilityVersion(100),
	}, writer, nodeView)

	serveDone := make(chan struct{})

	go func() {
		session.serveLongPoll()
		close(serveDone)
	}()

	require.Eventually(t, func() bool {
		return writer.WriteCount() >= 2 && app.mapBatcher.IsConnected(nodeView.ID())
	}, 2*time.Second, 10*time.Millisecond,
		"expected the initial map and connect update to be delivered")

	writer.BlockWrites()
	app.Change(change.SelfUpdate(nodeView.ID()))

	select {
	case <-writer.WriteStarted():
	case <-time.After(2 * time.Second):
		t.Fatal("expected the initial map write to block")
	}

	cs, err := app.state.DeleteNode(nodeView)
	require.NoError(t, err)
	app.Change(cs...)

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("deleting a node must interrupt its blocked map response write")
	}
}
