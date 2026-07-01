package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// newNoiseRouterWithBodyLimit builds a chi router with the same body-limit
// middleware used in the real Noise router but wired to a test handler that
// captures the [io.ReadAll] result. This lets us verify the limit without
// needing a full [Headscale] instance.
func newNoiseRouterWithBodyLimit(readBody *[]byte, readErr *error) http.Handler {
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, noiseBodyLimit)
			next.ServeHTTP(w, r)
		})
	})

	handler := func(w http.ResponseWriter, r *http.Request) {
		*readBody, *readErr = io.ReadAll(r.Body)
		if *readErr != nil {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)

			return
		}

		w.WriteHeader(http.StatusOK)
	}

	r.Post("/machine/map", handler)
	r.Post("/machine/register", handler)

	return r
}

func TestNoiseBodyLimit_MapEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("normal_map_request", func(t *testing.T) {
		t.Parallel()

		var body []byte

		var readErr error

		router := newNoiseRouterWithBodyLimit(&body, &readErr)

		mapReq := tailcfg.MapRequest{Version: 100, Stream: true}
		payload, err := json.Marshal(mapReq)
		require.NoError(t, err)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/map", bytes.NewReader(payload))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		require.NoError(t, readErr)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, body, len(payload))
	})

	t.Run("oversized_body_rejected", func(t *testing.T) {
		t.Parallel()

		var body []byte

		var readErr error

		router := newNoiseRouterWithBodyLimit(&body, &readErr)

		oversized := bytes.Repeat([]byte("x"), int(noiseBodyLimit)+1)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/map", bytes.NewReader(oversized))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		require.Error(t, readErr)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.LessOrEqual(t, len(body), int(noiseBodyLimit))
	})
}

func TestNoiseBodyLimit_RegisterEndpoint(t *testing.T) {
	t.Parallel()

	t.Run("normal_register_request", func(t *testing.T) {
		t.Parallel()

		var body []byte

		var readErr error

		router := newNoiseRouterWithBodyLimit(&body, &readErr)

		regReq := tailcfg.RegisterRequest{Version: 100}
		payload, err := json.Marshal(regReq)
		require.NoError(t, err)

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/register", bytes.NewReader(payload))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		require.NoError(t, readErr)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, body, len(payload))
	})

	t.Run("oversized_body_rejected", func(t *testing.T) {
		t.Parallel()

		var body []byte

		var readErr error

		router := newNoiseRouterWithBodyLimit(&body, &readErr)

		oversized := bytes.Repeat([]byte("x"), int(noiseBodyLimit)+1)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/register", bytes.NewReader(oversized))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		require.Error(t, readErr)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
		assert.LessOrEqual(t, len(body), int(noiseBodyLimit))
	})
}

func TestNoiseBodyLimit_AtExactLimit(t *testing.T) {
	t.Parallel()

	var body []byte

	var readErr error

	router := newNoiseRouterWithBodyLimit(&body, &readErr)

	payload := bytes.Repeat([]byte("a"), int(noiseBodyLimit))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/map", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.NoError(t, readErr)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Len(t, body, int(noiseBodyLimit))
}

// TestPollNetMapHandler_OversizedBody calls the real handler with a
// [http.MaxBytesReader]-wrapped body to verify it fails gracefully (json decode
// error on truncated data) rather than consuming unbounded memory.
func TestPollNetMapHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	ns := &noiseServer{}

	oversized := bytes.Repeat([]byte("x"), int(noiseBodyLimit)+1)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/map", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, noiseBodyLimit)

	ns.PollNetMapHandler(rec, req)

	// Body is truncated → [json.Decoder.Decode] fails → [httpError] returns 500.
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestRegistrationHandler_OversizedBody calls the real handler with a
// [http.MaxBytesReader]-wrapped body to verify it returns an error response
// rather than consuming unbounded memory.
func TestRegistrationHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	ns := &noiseServer{}

	oversized := bytes.Repeat([]byte("x"), int(noiseBodyLimit)+1)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/register", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, noiseBodyLimit)

	ns.RegistrationHandler(rec, req)

	// [json.Decoder.Decode] returns [http.MaxBytesError] → [regErr] wraps it → handler writes
	// a [tailcfg.RegisterResponse] with the error and then [rejectUnsupported] kicks in
	// for version 0 → returns 400.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestSSHActionRoute_OldPathReturns404 pins the wire-format shape of the
// SSH check-action endpoint. Pre-alignment headscale served
// /machine/ssh/action/from/{src}/to/{dst}?ssh_user=...; the current
// endpoint is /machine/ssh/action/{src}/to/{dst}?local_user=.... If
// someone re-adds the old route shape, this fails.
func TestSSHActionRoute_OldPathReturns404(t *testing.T) {
	t.Parallel()

	r := chi.NewRouter()
	r.Route("/machine", func(r chi.Router) {
		r.Get("/ssh/action/{src_node_id}/to/{dst_node_id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	cases := []struct {
		name string
		path string
		want int
	}{
		{"new", "/machine/ssh/action/1/to/2", http.StatusOK},
		{"old-with-from", "/machine/ssh/action/from/1/to/2", http.StatusNotFound},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			assert.Equal(t, tc.want, rec.Code)
		})
	}
}

// newSSHActionRequest builds an httptest request with the chi URL params
// [noiseServer.SSHActionHandler] reads (src_node_id and dst_node_id), so the handler
// can be exercised directly without going through the chi router.
func newSSHActionRequest(t *testing.T, src, dst types.NodeID) *http.Request {
	t.Helper()

	url := fmt.Sprintf("/machine/ssh/action/%d/to/%d", src.Uint64(), dst.Uint64())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("src_node_id", strconv.FormatUint(src.Uint64(), 10))
	rctx.URLParams.Add("dst_node_id", strconv.FormatUint(dst.Uint64(), 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	return req
}

// putTestNodeInStore creates a node via the database test helper and
// also stages it into the in-memory [state.NodeStore] so handlers that read
// [state.NodeStore]-backed APIs (e.g. [state.State.GetNodeByID]) can see it.
func putTestNodeInStore(t *testing.T, app *Headscale, user *types.User, hostname string) *types.Node {
	t.Helper()

	node := app.state.CreateNodeForTest(user, hostname)
	app.state.PutNodeInStoreForTest(*node)

	return node
}

// TestSSHActionHandler_RejectsRogueMachineKey verifies that the SSH
// check action endpoint rejects a Noise session whose machine key does
// not match the dst node.
func TestSSHActionHandler_RejectsRogueMachineKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("ssh-handler-user")

	src := putTestNodeInStore(t, app, user, "src-node")
	dst := putTestNodeInStore(t, app, user, "dst-node")

	// [noiseServer] carries the wrong machine key — a fresh throwaway key,
	// not dst.MachineKey.
	rogue := key.NewMachine().Public()
	require.NotEqual(t, dst.MachineKey, rogue, "test sanity: rogue key must differ from dst")

	ns := &noiseServer{
		headscale:  app,
		machineKey: rogue,
	}

	rec := httptest.NewRecorder()
	ns.SSHActionHandler(rec, newSSHActionRequest(t, src.ID, dst.ID))

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"rogue machine key must be rejected with 401")

	// And the auth cache must not have been mutated by the rejected request.
	if last, ok := app.state.GetLastSSHAuth(src.ID, dst.ID); ok {
		t.Fatalf("rejected SSH action must not record lastSSHAuth, got %v", last)
	}
}

// TestSSHActionHandler_RejectsUnknownDst verifies that the handler
// rejects a request for a dst_node_id that does not exist with 404.
func TestSSHActionHandler_RejectsUnknownDst(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("ssh-handler-unknown-user")
	src := putTestNodeInStore(t, app, user, "src-node")

	ns := &noiseServer{
		headscale:  app,
		machineKey: key.NewMachine().Public(),
	}

	rec := httptest.NewRecorder()
	ns.SSHActionHandler(rec, newSSHActionRequest(t, src.ID, 9999))

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"unknown dst node id must be rejected with 404")
}

// TestSSHActionFollowUp_RejectsBindingMismatch verifies that the
// follow-up handler refuses to honour an auth_id whose cached binding
// does not match the (src, dst) pair on the request URL. Without this
// check an attacker holding any auth_id could route its verdict to a
// different node pair.
func TestSSHActionFollowUp_RejectsBindingMismatch(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("ssh-binding-user")

	srcCached := putTestNodeInStore(t, app, user, "src-cached")
	dstCached := putTestNodeInStore(t, app, user, "dst-cached")
	srcOther := putTestNodeInStore(t, app, user, "src-other")
	dstOther := putTestNodeInStore(t, app, user, "dst-other")

	// Mint an SSH-check auth request bound to (srcCached, dstCached).
	authID := types.MustAuthID()
	app.state.SetAuthCacheEntry(
		authID,
		types.NewSSHCheckAuthRequest(srcCached.ID, dstCached.ID),
	)

	// Build a follow-up that claims to be for (srcOther, dstOther) but
	// reuses the bound auth_id. The Noise machineKey matches dstOther so
	// the outer machine-key check passes — only the binding check
	// should reject it.
	ns := &noiseServer{
		headscale:  app,
		machineKey: dstOther.MachineKey,
	}

	url := fmt.Sprintf(
		"/machine/ssh/action/%d/to/%d?auth_id=%s",
		srcOther.ID.Uint64(), dstOther.ID.Uint64(), authID.String(),
	)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("src_node_id", strconv.FormatUint(srcOther.ID.Uint64(), 10))
	rctx.URLParams.Add("dst_node_id", strconv.FormatUint(dstOther.ID.Uint64(), 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	ns.SSHActionHandler(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"binding mismatch must be rejected with 401")
}

// TestOverrideRemoteAddr asserts the middleware used inside the Noise
// tunnel pins r.RemoteAddr to the value captured from the outer
// (pre-hijack) request, so /machine/* requests log the trusted-proxy
// resolved client IP instead of the hijacked TCP socket's loopback peer.
func TestOverrideRemoteAddr(t *testing.T) {
	t.Parallel()

	const clientAddr = "192.168.91.240"

	r := chi.NewRouter()
	r.Use(overrideRemoteAddr(clientAddr))

	var observed string

	r.Get("/x", func(w http.ResponseWriter, r *http.Request) {
		observed = r.RemoteAddr

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	req.RemoteAddr = "127.0.0.1:44388"

	r.ServeHTTP(httptest.NewRecorder(), req)

	assert.Equal(t, clientAddr, observed)
}

// TestSSHActionHoldAndDelegate_PersistsAuthSession guards the happy path: the
// initial SSH-check poll returns a HoldAndDelegate URL carrying an auth_id, and
// that auth session must remain in the cache for the follow-up poll to find.
func TestSSHActionHoldAndDelegate_PersistsAuthSession(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("ssh-persist-user")
	src := putTestNodeInStore(t, app, user, "src-node")
	dst := putTestNodeInStore(t, app, user, "dst-node")

	ns := &noiseServer{headscale: app, machineKey: dst.MachineKey}

	rec := httptest.NewRecorder()
	ns.SSHActionHandler(rec, newSSHActionRequest(t, src.ID, dst.ID))
	require.Equal(t, http.StatusOK, rec.Code, "initial poll body=%s", rec.Body.String())

	var action tailcfg.SSHAction
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &action))
	require.NotEmpty(t, action.HoldAndDelegate, "expected HoldAndDelegate, got %+v", action)

	u, err := url.Parse(action.HoldAndDelegate)
	require.NoError(t, err)

	authIDStr := u.Query().Get("auth_id")
	require.NotEmpty(t, authIDStr, "HoldAndDelegate URL missing auth_id: %s", action.HoldAndDelegate)

	authID, err := types.AuthIDFromString(authIDStr)
	require.NoError(t, err)

	_, ok := app.state.GetAuthCacheEntry(authID)
	require.True(t, ok, "auth session %s must persist after HoldAndDelegate", authID)
}

// TestSSHActionHandler_RejectsMissingSessionWithoutCheck verifies that without
// an SSH check covering the pair, a follow-up poll for an unknown auth_id is a
// genuinely bogus request and is rejected. The re-delegation behaviour for a
// missing session (issue #3305, exercised end to end with a real client in the
// servertest package) applies only when the pair is still subject to a check.
func TestSSHActionHandler_RejectsMissingSessionWithoutCheck(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("ssh-nocheck-user")
	src := putTestNodeInStore(t, app, user, "src-node")
	dst := putTestNodeInStore(t, app, user, "dst-node")

	// No SSH-check policy is set, so the pair is not subject to a check.
	_, checkFound := app.state.SSHCheckParams(src.ID, dst.ID)
	require.False(t, checkFound, "test setup: pair must not be subject to a check")

	ns := &noiseServer{headscale: app, machineKey: dst.MachineKey}

	missing := types.MustAuthID()

	rec := httptest.NewRecorder()
	ns.SSHActionHandler(rec, newSSHActionFollowUpRequest(t, src.ID, dst.ID, missing))
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"a bogus auth_id with no active check must be rejected, body=%s", rec.Body.String())
}

// TestTS2021Route_AcceptsGETAndPOST reproduces a regression where the
// browser/WASM control client could not connect. Tailscale's JS/WASM control
// client opens /ts2021 as a WebSocket, which is an HTTP GET upgrade; the native
// Go client uses an HTTP POST upgrade. The gorilla->chi router migration
// registered /ts2021 for POST only, so the GET WebSocket handshake was rejected
// with 405 Method Not Allowed by the router before it could reach
// NoiseUpgradeHandler. Both methods must route to the handler.
//
// NoiseUpgradeHandler dispatches on the Upgrade header, not the HTTP method, so
// once the route is reachable the handler handles both upgrade styles. The
// httptest recorder is not an http.Hijacker, so the upgrade itself fails past
// the router (501 for the WebSocket path, 400 for the native path) — the point
// is only that neither is 405, i.e. the router no longer rejects GET early.
func TestTS2021Route_AcceptsGETAndPOST(t *testing.T) {
	t.Parallel()

	handler := createTestApp(t).HTTPHandler()

	tests := []struct {
		name    string
		method  string
		headers map[string]string
	}{
		{
			name:   "websocket_get_from_wasm_client",
			method: http.MethodGet,
			headers: map[string]string{
				"Connection":             "Upgrade",
				"Upgrade":                "websocket",
				"Sec-WebSocket-Version":  "13",
				"Sec-WebSocket-Key":      "dGhlIHNhbXBsZSBub25jZQ==",
				"Sec-WebSocket-Protocol": "tailscale-control-protocol",
			},
		},
		{
			name:   "native_post_upgrade",
			method: http.MethodPost,
			headers: map[string]string{
				"Connection":            "upgrade",
				"Upgrade":               "tailscale-control-protocol",
				"X-Tailscale-Handshake": "AAAA",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(context.Background(), tt.method,
				"/ts2021?X-Tailscale-Handshake=AAAA", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.NotEqual(t, http.StatusMethodNotAllowed, rec.Code,
				"%s /ts2021 must reach NoiseUpgradeHandler, not be rejected by the router with 405",
				tt.method)
		})
	}
}

// newSSHActionFollowUpRequest is like newSSHActionRequest but carries the
// auth_id query parameter that marks a follow-up poll.
func newSSHActionFollowUpRequest(t *testing.T, src, dst types.NodeID, authID types.AuthID) *http.Request {
	t.Helper()

	req := newSSHActionRequest(t, src, dst)

	q := req.URL.Query()
	q.Set("auth_id", authID.String())
	req.URL.RawQuery = q.Encode()

	return req
}
