package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
	"unicode"

	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiV1Harness drives a request through the Huma service and compares the result
// against a golden keyed by the test name. Goldens neutralise timestamps so they
// stay stable across runs; refresh with HEADSCALE_UPDATE_GOLDEN=1 after an
// intentional contract change. assertParity suits reads/errors; mutations use
// assertParityIsolated against a freshly-seeded app.
type apiV1Harness struct {
	app  *Headscale
	huma http.Handler
}

func newAPIV1Harness(t *testing.T) *apiV1Harness {
	t.Helper()

	app := createTestApp(t)

	return &apiV1Harness{
		app:  app,
		huma: newHumaTestHandler(app),
	}
}

// newHumaTestHandler wraps the Huma handler in WithLocalTrust to bypass the
// bearer-key middleware — the same local-trust the unix socket gets — so these
// tests can exercise response shapes. Auth itself is covered against the full
// router in TestAPIV1AuthMiddleware.
func newHumaTestHandler(app *Headscale) http.Handler {
	mux, _ := apiv1.Handler(apiv1.Backend{
		State:  app.state,
		Change: app.Change,
		Cfg:    app.cfg,
	})

	return apiv1.WithLocalTrust(mux)
}

// newFastAPIV1Harness is newAPIV1Harness whose NodeStore flushes each write
// at once: a lone write otherwise waits out the 500ms batch timeout, which
// tables of stored-state rows pay many times over. Its state is closed when
// the test ends, after the batcher; left open, its 1ms ticker would spin for
// the rest of the package.
func newFastAPIV1Harness(t *testing.T) *apiV1Harness {
	t.Helper()

	app := createTestApp(t, func(cfg *types.Config) {
		cfg.Tuning.NodeStoreBatchTimeout = time.Millisecond
	})

	t.Cleanup(func() {
		app.mapBatcher.Close()
		// createTestApp's own cleanup skips a batcher already closed.
		app.mapBatcher = nil

		assert.NoError(t, app.state.Close())
	})

	return &apiV1Harness{app: app, huma: newHumaTestHandler(app)}
}

// nodeStoreWriters returns the IDs of the goroutines running a NodeStore
// write loop, from a full goroutine dump. They are found by their creator,
// not their frames: a writer not yet scheduled shows only Start's wrapper.
func nodeStoreWriters() map[string]bool {
	var buf bytes.Buffer

	_ = pprof.Lookup("goroutine").WriteTo(&buf, 2)

	ids := map[string]bool{}

	for g := range strings.SplitSeq(buf.String(), "\n\n") {
		if strings.Contains(g, "\ncreated by github.com/juanfont/headscale/hscontrol/state.(*NodeStore).Start in ") {
			id, _, _ := strings.Cut(strings.TrimPrefix(g, "goroutine "), " ")
			ids[id] = true
		}
	}

	return ids
}

// TestAPIV1FastHarnessCloses: nothing of a fast harness runs or answers once
// its test has ended: the NodeStore writer it started is gone and its
// database closed. Other tests' writers come and go, so only its own are
// followed.
func TestAPIV1FastHarnessCloses(t *testing.T) {
	before := nodeStoreWriters()

	var (
		h       *apiV1Harness
		started []string
	)

	t.Run("harness", func(t *testing.T) {
		h = newFastAPIV1Harness(t)
		h.app.state.CreateUserForTest("alice")

		for id := range nodeStoreWriters() {
			if !before[id] {
				started = append(started, id)
			}
		}

		require.Len(t, started, 1, "the harness's own writer")
	})

	// A -run selector that filters out the harness subtest leaves nothing
	// to check.
	if h == nil {
		return
	}

	// Stop signals the writer; it exits on its own.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		running := nodeStoreWriters()
		for _, id := range started {
			assert.False(c, running[id], "the NodeStore writer must stop")
		}
	}, 5*time.Second, 10*time.Millisecond)
	assert.Error(t, h.app.state.PingDB(t.Context()), "the database must be closed")
}

// httpResult is one HTTP exchange captured for comparison.
type httpResult struct {
	status int
	body   []byte
}

func callHandler(handler http.Handler, method, path string, body []byte) httpResult {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}

	req := httptest.NewRequestWithContext(context.Background(), method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	return httpResult{status: rec.Code, body: rec.Body.Bytes()}
}

func (h *apiV1Harness) callHuma(method, path string, body []byte) httpResult {
	return callHandler(h.huma, method, path, body)
}

// assertParity asserts the Huma response matches the golden: equal status, and
// for success an equal JSON body (timestamps neutralised). Error bodies are not
// compared — the shape deliberately deviates from legacy
// ({code,message,details} vs Huma RFC7807).
func (h *apiV1Harness) assertParity(t *testing.T, method, path string, body []byte) httpResult {
	t.Helper()

	hum := h.callHuma(method, path, body)

	assertAgainstGolden(t, method, path, hum)

	return hum
}

// assertParityIsolated runs the request against a fresh app seeded by seed (may
// be nil) and compares to the golden. Use for mutations.
func assertParityIsolated(
	t *testing.T,
	seed func(t *testing.T, app *Headscale),
	method, path string,
	body []byte,
) httpResult {
	t.Helper()

	humaApp := createTestApp(t)
	if seed != nil {
		seed(t, humaApp)
	}

	hum := callHandler(newHumaTestHandler(humaApp), method, path, body)

	assertAgainstGolden(t, method, path, hum)

	return hum
}

// assertStatus pins the exact HTTP status independently of the golden, so a
// regression fails even if the golden is blindly regenerated.
func assertStatus(t *testing.T, got httpResult, want int) {
	t.Helper()

	assert.Equalf(t, want, got.status,
		"unexpected HTTP status (golden-independent guard); body: %s", got.body)
}

func isSuccess(status int) bool {
	return status >= 200 && status < 300
}

const goldenDir = "testdata/apiv1_golden"

// goldenRecord is the persisted shape of a captured response: the HTTP status
// and, when present, the normalised JSON body.
type goldenRecord struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
}

func goldenPath(t *testing.T) string {
	t.Helper()

	// Go module zips refuse names with characters such as '>', and one
	// such file stops go get from fetching headscale.
	name := strings.Map(func(r rune) rune {
		if r == '-' || r == '.' || unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}

		return '_'
	}, t.Name())

	return filepath.Join(goldenDir, name+".json")
}

// assertAgainstGolden compares the Huma response to the recorded golden: status
// always, body only for success responses.
func assertAgainstGolden(t *testing.T, method, path string, hum httpResult) {
	t.Helper()

	gpath := goldenPath(t)

	if os.Getenv("HEADSCALE_UPDATE_GOLDEN") != "" {
		writeGolden(t, gpath, hum)

		return
	}

	raw, err := os.ReadFile(gpath)
	require.NoErrorf(t, err,
		"missing golden %s for %s %s — run with HEADSCALE_UPDATE_GOLDEN=1 to generate",
		gpath, method, path)

	var golden goldenRecord
	require.NoErrorf(t, json.Unmarshal(raw, &golden), "decoding golden %s", gpath)

	assert.Equalf(t, golden.Status, hum.status,
		"status mismatch for %s %s\nhuma body: %s", method, path, hum.body)

	if isSuccess(golden.Status) {
		var goldenBody any
		if len(golden.Body) > 0 {
			goldenBody = normalizeJSON(t, golden.Body, true)
		}

		assert.Equalf(t, goldenBody, normalizeJSON(t, hum.body, true),
			"body mismatch for %s %s", method, path)
	}
}

// writeGolden persists the response under HEADSCALE_UPDATE_GOLDEN. Success
// bodies are normalised the same way the comparison path does, so the file stays
// stable across runs. Error responses are stored status-only, since the reader
// never compares error bodies.
func writeGolden(t *testing.T, gpath string, hum httpResult) {
	t.Helper()

	rec := goldenRecord{Status: hum.status}

	if isSuccess(hum.status) {
		if normalised := normalizeJSON(t, hum.body, true); normalised != nil {
			raw, err := json.Marshal(normalised)
			require.NoErrorf(t, err, "marshalling golden body for %s", gpath)

			rec.Body = raw
		}
	}

	out, err := json.MarshalIndent(rec, "", "  ")
	require.NoErrorf(t, err, "marshalling golden record for %s", gpath)

	require.NoErrorf(t, os.MkdirAll(filepath.Dir(gpath), 0o755),
		"creating golden dir for %s", gpath)
	require.NoErrorf(t, os.WriteFile(gpath, append(out, '\n'), 0o600),
		"writing golden %s", gpath)

	t.Logf("updated golden %s", gpath)
}

// nonDeterministicRe matches values that embed per-app random material and so
// cannot match byte-for-byte across apps: masked key/secret prefixes
// (hskey-auth-<prefix>-***, hskey-api-<prefix>-***) and Tailscale key material
// (mkey:/nodekey:/discokey:<hex>). Neutralised to a sentinel when neutralise is
// true.
var nonDeterministicRe = regexp.MustCompile(
	`^(hskey-(auth|api)-[0-9a-f]+-\*\*\*|(mkey|nodekey|discokey):[0-9a-f]+)$`,
)

// normalizeJSON decodes JSON for order-independent, type-aware comparison.
// Numbers decode as json.Number so "5" and 5 are not conflated, surfacing
// string-encoding differences. With neutralise, timestamps and per-app random
// values (see nonDeterministicRe) become sentinels; otherwise timestamps are
// canonicalised to a UTC instant.
func normalizeJSON(t *testing.T, b []byte, neutralise bool) any {
	t.Helper()

	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()

	var v any
	require.NoErrorf(t, dec.Decode(&v), "decoding JSON: %s", b)

	return canonicalizeTimestamps(v, neutralise)
}

func canonicalizeTimestamps(v any, neutralise bool) any {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			val[k] = canonicalizeTimestamps(child, neutralise)
		}

		return val
	case []any:
		for i, child := range val {
			val[i] = canonicalizeTimestamps(child, neutralise)
		}

		return val
	case string:
		if neutralise && nonDeterministicRe.MatchString(val) {
			return "<secret>"
		}

		ts, err := time.Parse(time.RFC3339Nano, val)
		if err != nil {
			return val
		}

		if neutralise {
			return "<timestamp>"
		}

		return ts.UTC().Format(time.RFC3339Nano)
	default:
		return v
	}
}
