package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
// captures the io.ReadAll result. This lets us verify the limit without
// needing a full Headscale instance.
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
// MaxBytesReader-wrapped body to verify it fails gracefully (json decode
// error on truncated data) rather than consuming unbounded memory.
func TestPollNetMapHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	ns := &noiseServer{}

	oversized := bytes.Repeat([]byte("x"), int(noiseBodyLimit)+1)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/map", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, noiseBodyLimit)

	ns.PollNetMapHandler(rec, req)

	// Body is truncated → json.Decode fails → httpError returns 500.
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestRegistrationHandler_OversizedBody calls the real handler with a
// MaxBytesReader-wrapped body to verify it returns an error response
// rather than consuming unbounded memory.
func TestRegistrationHandler_OversizedBody(t *testing.T) {
	t.Parallel()

	ns := &noiseServer{}

	oversized := bytes.Repeat([]byte("x"), int(noiseBodyLimit)+1)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/machine/register", bytes.NewReader(oversized))
	rec := httptest.NewRecorder()
	req.Body = http.MaxBytesReader(rec, req.Body, noiseBodyLimit)

	ns.RegistrationHandler(rec, req)

	// json.Decode returns MaxBytesError → regErr wraps it → handler writes
	// a RegisterResponse with the error and then rejectUnsupported kicks in
	// for version 0 → returns 400.
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// newSSHActionRequest builds an httptest request with the chi URL params
// SSHActionHandler reads (src_node_id and dst_node_id), so the handler
// can be exercised directly without going through the chi router.
func newSSHActionRequest(t *testing.T, src, dst types.NodeID) *http.Request {
	t.Helper()

	url := fmt.Sprintf("/machine/ssh/action/from/%d/to/%d", src.Uint64(), dst.Uint64())
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("src_node_id", strconv.FormatUint(src.Uint64(), 10))
	rctx.URLParams.Add("dst_node_id", strconv.FormatUint(dst.Uint64(), 10))
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	return req
}

// putTestNodeInStore creates a node via the database test helper and
// also stages it into the in-memory NodeStore so handlers that read
// NodeStore-backed APIs (e.g. State.GetNodeByID) can see it.
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

	// noiseServer carries the wrong machine key — a fresh throwaway key,
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
		"/machine/ssh/action/from/%d/to/%d?auth_id=%s",
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
