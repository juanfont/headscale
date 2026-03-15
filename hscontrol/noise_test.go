package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
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
