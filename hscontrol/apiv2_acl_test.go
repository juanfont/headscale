package hscontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const allowAllPolicy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

// storedPolicy returns the HuJSON actually persisted in the DB (server-side
// ground truth), or "" when none is set.
func storedPolicy(t *testing.T, app *Headscale) string {
	t.Helper()

	p, err := app.state.GetPolicy()
	if errors.Is(err, types.ErrPolicyNotFound) {
		return ""
	}

	require.NoError(t, err)

	return p.Data
}

// policyETagOf recomputes the expected ETag independently of the handler, so a
// handler that hashed the wrong buffer is caught.
func policyETagOf(data string) string {
	sum := sha256.Sum256([]byte(data))

	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// setACL POSTs a raw policy body with the given content type and optional
// headers (e.g. "If-Match: ...").
func setACL(t *testing.T, api humatest.TestAPI, body, contentType string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()

	args := make([]any, 0, 2+len(headers))
	args = append(args, bytes.NewReader([]byte(body)), "Content-Type: "+contentType)

	for _, h := range headers {
		args = append(args, h)
	}

	return api.Post("/api/v2/tailnet/-/acl", args...)
}

func TestAPIv2ACLDefaultWhenUnset(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	resp := api.Get("/api/v2/tailnet/-/acl")
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)
	assert.NotEmpty(t, resp.Header().Get("Etag"))
	assert.Contains(t, resp.Body.String(), `"acls"`)

	// GET did not materialize a stored policy.
	assert.Empty(t, storedPolicy(t, app))

	// Content-addressed: a second GET returns the same ETag.
	assert.Equal(t, resp.Header().Get("Etag"), api.Get("/api/v2/tailnet/-/acl").Header().Get("Etag"))
}

func TestAPIv2ACLContentNegotiation(t *testing.T) {
	api := registerAPIV2(t, createTestApp(t))

	jsonResp := api.Get("/api/v2/tailnet/-/acl")
	huResp := api.Get("/api/v2/tailnet/-/acl", "Accept: application/hujson")

	assert.Equal(t, "application/json", jsonResp.Header().Get("Content-Type"))
	assert.Equal(t, "application/hujson", huResp.Header().Get("Content-Type"))
	// Same bytes, same ETag — the ETag is over content, not type.
	assert.Equal(t, jsonResp.Body.Bytes(), huResp.Body.Bytes())
	assert.Equal(t, jsonResp.Header().Get("Etag"), huResp.Header().Get("Etag"))
}

func TestAPIv2ACLSetCanonicalJSON(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	set := setACL(t, api, allowAllPolicy, "application/json")
	require.Equalf(t, http.StatusOK, set.Code, "body: %s", set.Body)
	setETag := set.Header().Get("Etag")
	assert.NotEmpty(t, setETag)

	// (a) tool's own get reflects it, same ETag.
	get := api.Get("/api/v2/tailnet/-/acl")
	assert.Contains(t, get.Body.String(), `"action":"accept"`)
	assert.Equal(t, setETag, get.Header().Get("Etag"))

	// (b) server-side: exact stored bytes.
	assert.JSONEq(t, allowAllPolicy, storedPolicy(t, app))

	// (c) ETag is the sha256 of those bytes.
	assert.Equal(t, policyETagOf(allowAllPolicy), setETag)
}

func TestAPIv2ACLSetHuJSONWithComments(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	// Line comment + trailing comma: valid HuJSON, invalid strict JSON. The
	// server accepts it (the SDK sends the policy file this way) and standardizes
	// it on store; the ACL content survives even though comments are blanked.
	policy := "{\n  // allow all\n  \"acls\": [{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}],\n}"

	set := setACL(t, api, policy, "application/hujson")
	require.Equalf(t, http.StatusOK, set.Code, "body: %s", set.Body)

	// Server-side: stored, parseable, ACL intact.
	stored := storedPolicy(t, app)
	assert.Contains(t, stored, `"action":"accept"`)

	// GET round-trips the stored form and its content-addressed ETag.
	raw := api.Get("/api/v2/tailnet/-/acl", "Accept: application/hujson")
	assert.Equal(t, stored, raw.Body.String())
	assert.Equal(t, policyETagOf(stored), raw.Header().Get("Etag"))
}

func TestAPIv2ACLETagChangesOnChangeStableOnNoop(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	etag1 := setACL(t, api, allowAllPolicy, "application/json").Header().Get("Etag")
	stored1 := storedPolicy(t, app)

	p2 := `{"hosts":{"h":"100.64.0.1"},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
	etag2 := setACL(t, api, p2, "application/json").Header().Get("Etag")
	assert.NotEqual(t, etag1, etag2, "etag changes when policy changes")
	assert.NotEqual(t, stored1, storedPolicy(t, app))

	// No-op re-set keeps the ETag stable.
	etag3 := setACL(t, api, p2, "application/json").Header().Get("Etag")
	assert.Equal(t, etag2, etag3)
	assert.Equal(t, p2, storedPolicy(t, app))
}

func TestAPIv2ACLIfMatchPreconditions(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	etag := setACL(t, api, allowAllPolicy, "application/json").Header().Get("Etag")

	p2 := `{"hosts":{"h":"100.64.0.1"},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

	// Match -> 200, applies.
	require.Equal(t, http.StatusOK, setACL(t, api, p2, "application/json", "If-Match: "+etag).Code)
	assert.Equal(t, p2, storedPolicy(t, app))

	// Mismatch -> 412, server unchanged.
	before := storedPolicy(t, app)
	assert.Equal(t, http.StatusPreconditionFailed,
		setACL(t, api, allowAllPolicy, "application/json", `If-Match: "deadbeef"`).Code)
	assert.Equal(t, before, storedPolicy(t, app), "rejected write left the policy untouched")

	// Absent -> unconditional 200.
	require.Equal(t, http.StatusOK, setACL(t, api, allowAllPolicy, "application/json").Code)
	assert.JSONEq(t, allowAllPolicy, storedPolicy(t, app))
}

func TestAPIv2ACLIfMatchTsDefault(t *testing.T) {
	// No policy set: ts-default matches the allow-all default -> 200.
	app := createTestApp(t)
	api := registerAPIV2(t, app)
	require.Equal(t, http.StatusOK,
		setACL(t, api, allowAllPolicy, "application/json", `If-Match: "ts-default"`).Code)
	assert.JSONEq(t, allowAllPolicy, storedPolicy(t, app))

	// A non-default policy is set: ts-default no longer matches -> 412.
	assert.Equal(t, http.StatusPreconditionFailed,
		setACL(t, api, `{"hosts":{"h":"100.64.0.1"},"acls":[]}`, "application/json", `If-Match: "ts-default"`).Code)
}

func TestAPIv2ACLInvalidPolicyAtomicity(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	good := setACL(t, api, allowAllPolicy, "application/json")
	require.Equal(t, http.StatusOK, good.Code)
	goodETag := good.Header().Get("Etag")

	// Malformed body -> 400, and the stored policy is unchanged (atomicity).
	bad := setACL(t, api, `{ this is not valid`, "application/json")
	assert.Equal(t, http.StatusBadRequest, bad.Code)
	assert.Contains(t, bad.Body.String(), `"message"`)
	assert.JSONEq(t, allowAllPolicy, storedPolicy(t, app))

	// Wire-level: GET still serves the good policy + its ETag (no drift).
	get := api.Get("/api/v2/tailnet/-/acl")
	assert.Equal(t, goodETag, get.Header().Get("Etag"))
	assert.JSONEq(t, allowAllPolicy, storedPolicy(t, app))
}

func TestAPIv2ACLNonDefaultTailnet404(t *testing.T) {
	api := registerAPIV2(t, createTestApp(t))

	assert.Equal(t, http.StatusNotFound, api.Get("/api/v2/tailnet/example.com/acl").Code)
	assert.Equal(t, http.StatusNotFound,
		api.Post("/api/v2/tailnet/example.com/acl", bytes.NewReader([]byte(allowAllPolicy))).Code)
}

func TestAPIv2ACLFileModeReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acl.hujson")
	fileBytes := "{\n  // file-managed\n  \"acls\": [{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}],\n}"
	require.NoError(t, os.WriteFile(path, []byte(fileBytes), 0o600))

	cfg := &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}}
	_, api := humatest.New(t, apiv2.Config())
	apiv2.Register(api, apiv2.Backend{Cfg: cfg})

	// GET serves the file bytes + their ETag.
	get := api.Get("/api/v2/tailnet/-/acl")
	require.Equalf(t, http.StatusOK, get.Code, "body: %s", get.Body)
	assert.Equal(t, fileBytes, get.Body.String())
	assert.Equal(t, policyETagOf(fileBytes), get.Header().Get("Etag"))

	// POST is rejected in file mode; the file is unchanged.
	set := setACL(t, api, allowAllPolicy, "application/json")
	assert.Equal(t, http.StatusBadRequest, set.Code)
	assert.Contains(t, set.Body.String(), "database")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, fileBytes, string(after))
}
