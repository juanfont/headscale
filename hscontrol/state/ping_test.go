package state

import (
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPingTracker_RegisterComplete(t *testing.T) {
	pt := newPingTracker()

	pingID, ch := pt.register(types.NodeID(1))
	assert.NotEmpty(t, pingID)

	// Complete in a goroutine since it sends on the channel.
	go func() {
		assert.True(t, pt.complete(pingID))
	}()

	select {
	case latency := <-ch:
		assert.GreaterOrEqual(t, latency, time.Duration(0), "latency should be non-negative")
		assert.Less(t, latency, 5*time.Second, "latency should be reasonable")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ping response")
	}
}

func TestPingTracker_CompleteUnknown(t *testing.T) {
	pt := newPingTracker()
	assert.False(t, pt.complete("nonexistent"))
}

func TestPingTracker_CancelThenComplete(t *testing.T) {
	pt := newPingTracker()

	pingID, ch := pt.register(types.NodeID(1))
	pt.cancel(pingID)
	assert.False(t, pt.complete(pingID))

	// Channel should never receive.
	select {
	case <-ch:
		t.Fatal("channel should not receive after cancel")
	case <-time.After(50 * time.Millisecond):
		// Expected: no response.
	}
}

func TestPingTracker_DoubleComplete(t *testing.T) {
	pt := newPingTracker()

	pingID, ch := pt.register(types.NodeID(1))
	assert.True(t, pt.complete(pingID))

	// Drain the channel.
	<-ch

	// Second complete should return false.
	assert.False(t, pt.complete(pingID))
}

func TestPingTracker_ConcurrentDifferentIDs(t *testing.T) {
	pt := newPingTracker()

	const count = 10

	ids := make([]string, count)
	chs := make([]<-chan time.Duration, count)

	for i := range count {
		ids[i], chs[i] = pt.register(types.NodeID(i + 1))
	}

	// Complete in reverse order concurrently.
	var wg sync.WaitGroup

	for _, id := range slices.Backward(ids) {
		wg.Go(func() {
			assert.True(t, pt.complete(id))
		})
	}

	// All channels should receive.
	for i := range count {
		select {
		case latency := <-chs[i]:
			assert.GreaterOrEqual(t, latency, time.Duration(0))
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for ping %d", i)
		}
	}

	wg.Wait()
}

func TestPingTracker_TwoToSameNode(t *testing.T) {
	pt := newPingTracker()
	nodeID := types.NodeID(42)

	id1, ch1 := pt.register(nodeID)
	id2, ch2 := pt.register(nodeID)

	require.NotEqual(t, id1, id2, "ping IDs should be unique")

	// Complete only the first.
	assert.True(t, pt.complete(id1))

	select {
	case latency := <-ch1:
		assert.GreaterOrEqual(t, latency, time.Duration(0))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first ping")
	}

	// Second should still be pending.
	select {
	case <-ch2:
		t.Fatal("second channel should not have received yet")
	default:
		// Expected.
	}

	// Now complete the second.
	assert.True(t, pt.complete(id2))

	select {
	case latency := <-ch2:
		assert.GreaterOrEqual(t, latency, time.Duration(0))
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for second ping")
	}
}

func TestPingTracker_Drain(t *testing.T) {
	pt := newPingTracker()

	_, ch1 := pt.register(types.NodeID(1))
	_, ch2 := pt.register(types.NodeID(2))

	pt.drain()

	// Drained channels must be closed so blocked readers unblock.
	for i, ch := range []<-chan time.Duration{ch1, ch2} {
		select {
		case _, ok := <-ch:
			assert.False(t, ok, "channel %d should be closed, got value", i)
		case <-time.After(time.Second):
			t.Fatalf("channel %d not closed by drain", i)
		}
	}

	assert.Empty(t, pt.pending, "pending map should be empty after drain")
}

func TestPingTracker_LatencyNonNegative(t *testing.T) {
	pt := newPingTracker()

	pingID, ch := pt.register(types.NodeID(1))
	assert.True(t, pt.complete(pingID))

	select {
	case latency := <-ch:
		assert.GreaterOrEqual(t, latency, time.Duration(0), "latency should be non-negative")
		assert.Less(t, latency, 5*time.Second, "latency should be reasonable")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestPingTracker_C2NRegisterComplete(t *testing.T) {
	pt := newPingTracker()

	c2nID, ch := pt.registerC2N(types.NodeID(7))
	assert.NotEmpty(t, c2nID)

	nodeID, ok := pt.c2nTarget(c2nID)
	require.True(t, ok)
	assert.Equal(t, types.NodeID(7), nodeID)

	assert.True(t, pt.completeC2N(c2nID, []byte("HTTP/1.1 200 OK\r\n\r\n")))

	select {
	case body, ok := <-ch:
		require.True(t, ok)
		assert.Equal(t, "HTTP/1.1 200 OK\r\n\r\n", string(body))
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for c2n response")
	}

	_, ok = pt.c2nTarget(c2nID)
	assert.False(t, ok, "completed c2n request should be forgotten")
	assert.False(t, pt.completeC2N(c2nID, nil), "second complete should return false")
}

func TestPingTracker_C2NCancel(t *testing.T) {
	pt := newPingTracker()

	c2nID, ch := pt.registerC2N(types.NodeID(1))
	pt.cancelC2N(c2nID)
	pt.cancelC2N(c2nID)

	_, ok := pt.c2nTarget(c2nID)
	assert.False(t, ok)
	assert.False(t, pt.completeC2N(c2nID, []byte("late")))

	select {
	case <-ch:
		t.Fatal("channel should not receive after cancel")
	case <-time.After(50 * time.Millisecond):
		// Expected: no response.
	}
}

func TestPingTracker_C2NSeparateFromPings(t *testing.T) {
	pt := newPingTracker()

	pingID, _ := pt.register(types.NodeID(1))
	c2nID, _ := pt.registerC2N(types.NodeID(1))

	assert.False(t, pt.completeC2N(pingID, nil), "ping ID must not complete a c2n request")
	assert.False(t, pt.complete(c2nID), "c2n ID must not complete a ping")
}

func TestPingTracker_DrainC2N(t *testing.T) {
	pt := newPingTracker()

	_, ch := pt.registerC2N(types.NodeID(1))

	pt.drain()

	select {
	case _, ok := <-ch:
		assert.False(t, ok, "c2n channel should be closed, got value")
	case <-time.After(time.Second):
		t.Fatal("c2n channel not closed by drain")
	}

	assert.Empty(t, pt.c2n, "c2n map should be empty after drain")
}
