package servertest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
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

// TestAPIv2DeviceUpdateClientDuringDisconnectGrace verifies that a node whose
// map stream is gone is refused at once, even while the disconnect grace
// period still reports it online: no stream can carry the c2n request.
func TestAPIv2DeviceUpdateClientDuringDisconnectGrace(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nodeID := types.NodeID(h.Client(0).Netmap().SelfNode.ID()) //nolint:gosec

	h.Client(0).Disconnect(t)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.False(c, h.Server.App.MapBatcher().IsConnected(nodeID))
	}, 5*time.Second, 50*time.Millisecond)

	nv, ok := h.Server.State().GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, nv.IsOnline().Get(), "the grace period should still report the node online")

	// SaaS answers a device it cannot reach 404 (testdata/steps/update-client.hujson).
	start := time.Now()
	code, _ := updateDeviceClient(t, h.Server, nodeID, false)
	assert.Equal(t, http.StatusNotFound, code)
	assert.Less(t, time.Since(start), 5*time.Second, "refusal should not wait for the c2n timeout")
}

// TestAPIv2DeviceUpdateClientUnknownDevice verifies that an unknown device ID is a 404.
func TestAPIv2DeviceUpdateClientUnknownDevice(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 0)

	code, _ := updateDeviceClient(t, h.Server, types.NodeID(9999), false)
	assert.Equal(t, http.StatusNotFound, code)
}

// TestAPIv2DeviceUpdateClientCompat replays SaaS's update-client answers for
// devices it would not update: plain has auto-updates off; remote allows
// remote updates on a platform that cannot update itself, then goes offline.
// SaaS answered every such row 404 "not found", whatever the body, method or
// node state, without asking the node.
//
// Test data source: testdata/steps/update-client.hujson. Rows by
// devices:core:read and dns:read tokens are not replayed: SaaS answers them
// 404 before any scope check, which shows its order, not this endpoint's shape.
func TestAPIv2DeviceUpdateClientCompat(t *testing.T) {
	t.Parallel()

	c := readStepCapture(t, "update-client")
	r := newStepReplay(t, c)
	r.setPolicy(t, "setup", c.Input.FullPolicy)

	// The probe's nodes ran on NixOS; each answers c2n POST /update as its
	// tailscaled would have, had SaaS asked.
	answers := map[string]tailcfg.C2NUpdateResponse{
		"plain":  {Err: "not enabled"},
		"remote": {Enabled: true, Err: "not supported"},
	}

	ids := map[string]string{}
	clients := map[string]*servertest.TestClient{}

	for alias, res := range answers {
		hi := &tailcfg.Hostinfo{
			BackendLogID: "servertest-" + alias,
			Hostname:     alias,
			AllowsUpdate: captureHostinfo(t, c, alias).AllowsUpdate,
		}
		cl := servertest.NewClient(t, r.srv, alias, servertest.WithUser(r.admin),
			servertest.WithHostinfo(hi), servertest.WithC2NHandler(&fakeUpdater{res: res}))
		cl.WaitForCondition(t, alias+" self", 10*time.Second, func(nm *netmap.NetworkMap) bool { return nm.SelfNode.Valid() })

		clients[alias] = cl
		ids["{device:"+alias+"}"] = types.NodeID(cl.Netmap().SelfNode.ID()).String() //nolint:gosec
	}

	token := captureToken(t, r, c, "C-core")
	skipped := map[string]bool{"token:C-coreread": true, "token:C-dnsread": true}
	ran := 0

	for _, step := range c.Steps {
		if step.Name == "setup-offline" {
			nodeID := types.NodeID(clients["remote"].Netmap().SelfNode.ID()) //nolint:gosec
			clients["remote"].Disconnect(t)

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				nv, ok := r.srv.State().GetNodeByID(nodeID)
				assert.True(c, ok)
				assert.False(c, nv.IsOnline().Get(), "remote should be offline")
			}, 20*time.Second, 200*time.Millisecond)
		}

		for _, a := range step.Actions {
			if a.Kind != "api" || !strings.Contains(a.Path, "/update-client") || skipped[a.Principal] {
				continue
			}

			ran++

			bearer := r.apiKey
			if a.Principal != "admin" {
				bearer = token
			}

			status, body := sendCaptureAction(t, r, a, ids, bearer)
			assert.Equalf(t, a.Status, status, "%s: %s %s: %s", step.Name, a.Method, a.Path, body)

			// unknown-id's message comes from the lookup every device route shares.
			if step.Name != "unknown-id" {
				assert.Equalf(t, errorMessage(a.Response), errorMessage(body), "%s: %s %s", step.Name, a.Method, a.Path)
			}
		}
	}

	require.Equal(t, 19, ran, "update-client rows replayed")
}

// TestAPIv2DeviceUpdateClientConsoleCompat replays the admin console's Start
// update on a device that can update itself: POST update-client answers at
// once, then update-status says updating until the device runs a new version.
// The console's /admin/api/public routes are the v2 API inside
// {"status","data"}, so headscale must answer the data.
//
// Test data source: testdata/steps/update-client-console.hujson, imported
// from a browser HAR. Its 304s are the browser's cache and are not replayed;
// its machine reads give the device's versions and auto-update state.
func TestAPIv2DeviceUpdateClientConsoleCompat(t *testing.T) {
	t.Parallel()

	c := readStepCapture(t, "update-client-console")
	before, after := consoleMachines(t, c)
	require.NotEqual(t, before.IPNVersion, after.IPNVersion, "the device should end on a new version")

	srv := servertest.NewServer(t)
	hi := &tailcfg.Hostinfo{
		BackendLogID: "servertest-updater",
		Hostname:     "updater",
		IPNVersion:   before.IPNVersion,
		AllowsUpdate: before.AutoUpdatesEnabled,
	}
	cl := servertest.NewClient(t, srv, "updater", servertest.WithHostinfo(hi.Clone()),
		servertest.WithC2NHandler(&fakeUpdater{res: tailcfg.C2NUpdateResponse{Enabled: true, Supported: true, Started: true}}))
	cl.WaitForCondition(t, "updater self", 10*time.Second, func(nm *netmap.NetworkMap) bool { return nm.SelfNode.Valid() })

	r := &stepReplay{srv: srv, apiKey: srv.CreateAPIKey(t, nil), http: &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}}
	ids := map[string]string{"{device:updater}": types.NodeID(cl.Netmap().SelfNode.ID()).String()} //nolint:gosec
	restarted := false
	ran := 0

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if !strings.HasPrefix(a.Path, "/admin/api/public/") || a.Status == http.StatusNotModified {
				continue
			}

			ran++

			var want struct {
				Data json.RawMessage `json:"data"`
			}
			require.NoError(t, json.Unmarshal(a.Response, &want))

			a.Path = strings.Replace(a.Path, "/admin/api/public", "", 1)

			// The device restarts on its new version between the last
			// "updating" and the first "not-updating".
			if strings.Contains(string(want.Data), `"not-updating"`) && !restarted {
				restarted = true
				hi.IPNVersion = after.IPNVersion
				require.NoError(t, cl.Restart(t.Context(), hi.Clone()))

				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					status, body := sendCaptureAction(t, r, a, ids, r.apiKey)
					assert.Equal(ct, a.Status, status)
					assert.True(ct, sameData(want.Data, body), "%s %s: %s, want %s", a.Method, a.Path, body, want.Data)
				}, 20*time.Second, 2*time.Second)

				continue
			}

			status, body := sendCaptureAction(t, r, a, ids, r.apiKey)
			assert.Equalf(t, a.Status, status, "%s: %s %s: %s", step.Name, a.Method, a.Path, body)
			assert.Truef(t, sameData(want.Data, body), "%s: %s %s: %s, want %s", step.Name, a.Method, a.Path, body, want.Data)
		}
	}

	require.Equal(t, 3, ran, "update-client and update-status answers replayed")
}

// captureHostinfo returns the Hostinfo of alias's first map request.
func captureHostinfo(t *testing.T, c *testcapture.Capture, alias string) *tailcfg.Hostinfo {
	t.Helper()

	for _, s := range c.Steps {
		for _, f := range s.Frames[alias] {
			if f.Request != nil && f.Request.Hostinfo != nil {
				return f.Request.Hostinfo
			}
		}
	}

	t.Fatalf("%s: no map request from %s", c.TestID, alias)

	return nil
}

// captureToken makes the capture's OAuth client with the admin's body, as
// the probe did, and returns an access token for it.
func captureToken(t *testing.T, r *stepReplay, c *testcapture.Capture, client string) string {
	t.Helper()

	for _, s := range c.Steps {
		for _, a := range s.Actions {
			if a.Kind != "api" || a.Client != client {
				continue
			}

			status, body := sendCaptureAction(t, r, a, nil, r.apiKey)
			require.Equal(t, http.StatusOK, status, "%s: %s", client, body)

			var created struct {
				Key string `json:"key"`
			}
			require.NoError(t, json.Unmarshal(body, &created))

			form := url.Values{"grant_type": {"client_credentials"}, "client_secret": {created.Key}}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.srv.URL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := r.http.Do(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			var tok struct {
				AccessToken string `json:"access_token"`
			}
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tok))
			require.NotEmpty(t, tok.AccessToken, "%s: token", client)

			return tok.AccessToken
		}
	}

	t.Fatalf("%s: no OAuth client %s", c.TestID, client)

	return ""
}

// sendCaptureAction sends a recorded API action to headscale's v2 API, its
// labels replaced by ids, with the body and headers SaaS received.
func sendCaptureAction(t *testing.T, r *stepReplay, a testcapture.Action, ids map[string]string, bearer string) (int, []byte) {
	t.Helper()

	path := a.Path
	for label, id := range ids {
		path = strings.ReplaceAll(path, label, id)
	}

	// A body that is not JSON is stored as a JSON string; "" is an empty one.
	body := []byte(a.Body)

	var s string
	if json.Unmarshal(a.Body, &s) == nil {
		body = []byte(s)
	}

	req, err := http.NewRequestWithContext(t.Context(), a.Method, r.srv.URL+"/api/v2"+path, bytes.NewReader(body))
	require.NoError(t, err)

	for k, v := range a.Header {
		req.Header.Set(k, v)
	}

	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := r.http.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, out
}

// sameData reports whether a v2 answer is the console's data. The console
// sent no data for a POST that succeeded: its v2 answer is empty, null or {}.
func sameData(want json.RawMessage, got []byte) bool {
	if len(want) == 0 {
		g := strings.TrimSpace(string(got))
		return g == "" || g == "null" || g == "{}"
	}

	var w, g any

	return json.Unmarshal(want, &w) == nil && json.Unmarshal(got, &g) == nil && assert.ObjectsAreEqual(w, g)
}

type consoleMachine struct {
	IPNVersion         string `json:"ipnVersion"`
	AutoUpdatesEnabled bool   `json:"autoUpdatesEnabled"`
}

// consoleMachines returns the device as the console's first and last machine
// reads show it.
func consoleMachines(t *testing.T, c *testcapture.Capture) (consoleMachine, consoleMachine) {
	t.Helper()

	var seen []consoleMachine

	for _, s := range c.Steps {
		for _, a := range s.Actions {
			if !strings.HasPrefix(a.Path, "/admin/api/machines") {
				continue
			}

			var env struct {
				Data struct {
					consoleMachine

					Machines []consoleMachine `json:"machines"`
				} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(a.Response, &env))

			seen = append(seen, append(env.Data.Machines, env.Data.consoleMachine)[0])
		}
	}

	require.NotEmpty(t, seen, "%s: no machine reads", c.TestID)

	return seen[0], seen[len(seen)-1]
}
