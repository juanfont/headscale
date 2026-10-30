package servertest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// fakeUpdater answers c2n "POST /update" the way tailscaled does, with a
// fixed [tailcfg.C2NUpdateResponse], and records the force query value
// of every request.
type fakeUpdater struct {
	res tailcfg.C2NUpdateResponse

	mu     sync.Mutex
	forces []string
}

func (f *fakeUpdater) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/update" {
		http.NotFound(w, r)
		return
	}

	f.mu.Lock()
	f.forces = append(f.forces, r.FormValue("force"))
	f.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(f.res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (f *fakeUpdater) seenForces() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.forces...)
}

type deviceClientUpdate struct {
	Enabled   bool   `json:"enabled"`
	Supported bool   `json:"supported"`
	Started   bool   `json:"started"`
	Error     string `json:"error"`
}

// updateDeviceClient calls POST /api/v2/device/{id}/update-client and
// returns the status code and decoded body.
func updateDeviceClient(t *testing.T, srv *servertest.TestServer, nodeID types.NodeID, force bool) (int, deviceClientUpdate) {
	t.Helper()

	body, err := json.Marshal(map[string]bool{"force": force})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.URL+"/api/v2/device/"+strconv.FormatUint(nodeID.Uint64(), 10)+"/update-client",
		bytes.NewReader(body))
	require.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+srv.CreateAPIKey(t, nil))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	var out deviceClientUpdate
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&out))
	}

	return resp.StatusCode, out
}

// TestAPIv2DeviceUpdateClient verifies the full c2n round-trip: the API sends a
// c2n [tailcfg.PingRequest] carrying "POST /update", the real
// [controlclient.Direct] runs it against its c2n handler and posts the
// response back over Noise, and the API returns the node's answer.
func TestAPIv2DeviceUpdateClient(t *testing.T) {
	t.Parallel()

	updater := &fakeUpdater{res: tailcfg.C2NUpdateResponse{
		Enabled:   true,
		Supported: true,
		Started:   true,
	}}

	h := servertest.NewHarness(t, 1,
		servertest.WithDefaultClientOptions(servertest.WithC2NHandler(updater)))

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	code, res := updateDeviceClient(t, h.Server, nodeID, false)
	require.Equal(t, http.StatusOK, code)
	assert.True(t, res.Enabled)
	assert.True(t, res.Supported)
	assert.True(t, res.Started)
	assert.Empty(t, res.Error)

	code, _ = updateDeviceClient(t, h.Server, nodeID, true)
	require.Equal(t, http.StatusOK, code)

	assert.Equal(t, []string{"", "true"}, updater.seenForces(),
		"force must reach the client as ?force=true only when requested")
}

// TestAPIv2DeviceUpdateClientRefused verifies that a client refusing the update
// (auto-updates off, unsupported platform, active SSH) is reported back
// as a successful call with started=false and the client's reason.
func TestAPIv2DeviceUpdateClientRefused(t *testing.T) {
	t.Parallel()

	updater := &fakeUpdater{res: tailcfg.C2NUpdateResponse{
		Supported: true,
		Err:       "not enabled",
	}}

	h := servertest.NewHarness(t, 1,
		servertest.WithDefaultClientOptions(servertest.WithC2NHandler(updater)))

	nodeID := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec

	code, res := updateDeviceClient(t, h.Server, nodeID, false)
	require.Equal(t, http.StatusOK, code)
	assert.False(t, res.Enabled)
	assert.False(t, res.Started)
	assert.Equal(t, "not enabled", res.Error)
}

// TestAPIv2DeviceUpdateClientNotConnected verifies that a disconnected device is
// rejected with 409 instead of waiting for an answer that cannot come.
func TestAPIv2DeviceUpdateClientNotConnected(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nodeID := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec

	h.Client(0).Disconnect(t)

	// The node is marked offline after the disconnect grace period.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		nv, ok := h.Server.State().GetNodeByID(nodeID)
		assert.True(c, ok)

		isOnline, known := nv.IsOnline().GetOk()
		assert.True(c, known && !isOnline, "node should be offline")
	}, 20*time.Second, 200*time.Millisecond)

	code, _ := updateDeviceClient(t, h.Server, nodeID, false)
	assert.Equal(t, http.StatusConflict, code)
}

// TestAPIv2DeviceUpdateClientUnknownDevice verifies that an unknown device ID is a 404.
func TestAPIv2DeviceUpdateClientUnknownDevice(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 0)

	code, _ := updateDeviceClient(t, h.Server, types.NodeID(9999), false)
	assert.Equal(t, http.StatusNotFound, code)
}
