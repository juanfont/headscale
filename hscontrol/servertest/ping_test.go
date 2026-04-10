package servertest_test

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestPingNode verifies the full ping round-trip: the server sends a
// PingRequest via MapResponse, the real controlclient.Direct handles it
// by making a HEAD request back over Noise, and the ping tracker records
// the latency.
func TestPingNode(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)
	require.True(t, nm.SelfNode.Valid())

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	st := h.Server.State()
	pingID, responseCh := st.RegisterPing(nodeID)

	defer st.CancelPing(pingID)

	callbackURL := h.Server.URL + "/machine/ping-response?id=" + pingID
	h.Server.App.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	}))

	select {
	case latency := <-responseCh:
		assert.Positive(t, latency, "latency should be positive, got %v", latency)
		assert.Less(t, latency, 10*time.Second, "latency should be reasonable, got %v", latency)
	case <-time.After(15 * time.Second):
		t.Fatal("ping response not received within 15s")
	}
}

// TestPingDisconnectedNode verifies that pinging a disconnected node
// results in no response (the channel never receives).
func TestPingDisconnectedNode(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	// Disconnect the client.
	h.Client(0).Disconnect(t)

	st := h.Server.State()
	pingID, responseCh := st.RegisterPing(nodeID)

	defer st.CancelPing(pingID)

	callbackURL := h.Server.URL + "/machine/ping-response?id=" + pingID
	h.Server.App.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	}))

	select {
	case <-responseCh:
		t.Fatal("should not receive response from disconnected node")
	case <-time.After(3 * time.Second):
		// Expected: no response.
	}
}

// TestPingTwoSameNode verifies that two concurrent pings to the same
// node complete independently.
func TestPingTwoSameNode(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	st := h.Server.State()

	pingID1, ch1 := st.RegisterPing(nodeID)
	defer st.CancelPing(pingID1)

	pingID2, ch2 := st.RegisterPing(nodeID)
	defer st.CancelPing(pingID2)

	require.NotEqual(t, pingID1, pingID2)

	// Send both PingRequests.
	url1 := h.Server.URL + "/machine/ping-response?id=" + pingID1
	url2 := h.Server.URL + "/machine/ping-response?id=" + pingID2

	h.Server.App.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL: url1,
	}))
	h.Server.App.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL: url2,
	}))

	timeout := time.After(15 * time.Second)

	var got1, got2 bool

	for !got1 || !got2 {
		select {
		case latency := <-ch1:
			assert.GreaterOrEqual(t, latency, time.Duration(0))

			got1 = true
		case latency := <-ch2:
			assert.GreaterOrEqual(t, latency, time.Duration(0))

			got2 = true
		case <-timeout:
			t.Fatalf("timed out: got1=%v got2=%v", got1, got2)
		}
	}
}

// TestPingResolveByHostname verifies that ResolveNode can find a node
// by hostname and that the resolved node can be pinged.
func TestPingResolveByHostname(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1, servertest.WithDefaultClientOptions(
		servertest.WithHostname("my-test-host"),
	))

	st := h.Server.State()

	// Resolve by hostname.
	node, ok := st.ResolveNode("my-test-host")
	require.True(t, ok, "should resolve node by hostname")

	nodeID := node.ID()

	pingID, responseCh := st.RegisterPing(nodeID)
	defer st.CancelPing(pingID)

	callbackURL := h.Server.URL + "/machine/ping-response?id=" + pingID
	h.Server.App.Change(change.PingNode(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	}))

	select {
	case latency := <-responseCh:
		assert.Positive(t, latency)
	case <-time.After(15 * time.Second):
		t.Fatal("ping response not received")
	}
}
