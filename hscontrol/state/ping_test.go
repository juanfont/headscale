package state

import (
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

	for i := count - 1; i >= 0; i-- {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()

			assert.True(t, pt.complete(ids[idx]))
		}(i)
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
