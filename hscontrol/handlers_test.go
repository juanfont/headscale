package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var errTestUnexpected = errors.New("unexpected failure")

// TestHandleVerifyRequest_OversizedBodyRejected verifies that the
// /verify handler refuses POST bodies larger than [verifyBodyLimit].
// The [http.MaxBytesReader] is applied in [Headscale.VerifyHandler], so we simulate
// the same wrapping here.
func TestHandleVerifyRequest_OversizedBodyRejected(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("x", int(verifyBodyLimit)+128)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"/verify",
		bytes.NewReader([]byte(body)),
	)
	req.Body = http.MaxBytesReader(rec, req.Body, verifyBodyLimit)

	h := &Headscale{}

	err := h.handleVerifyRequest(req, &bytes.Buffer{})
	if err == nil {
		t.Fatal("oversized verify body must be rejected")
	}

	httpErr, ok := errorAsHTTPError(err)
	if !ok {
		t.Fatalf("error must be an HTTPError, got: %T (%v)", err, err)
	}

	assert.Equal(t, http.StatusRequestEntityTooLarge, httpErr.Code,
		"oversized body must surface 413")
}

// TestVerifyHandler_SuccessSetsJSONContentType verifies that a successful
// POST to /verify advertises Content-Type: application/json. The header
// must be set before the JSON body is written, otherwise the implicit
// WriteHeader on first Write locks in a sniffed content type and the
// later Header().Set becomes a no-op.
func TestVerifyHandler_SuccessSetsJSONContentType(t *testing.T) {
	tmpDir := t.TempDir()

	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := &types.Config{
		ServerURL:           "http://localhost:0",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		PrefixV4:            &prefixV4,
		PrefixV6:            &prefixV6,
		IPAllocation:        types.IPAllocationStrategySequential,
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
	}

	h, err := NewHeadscale(cfg)
	require.NoError(t, err)

	reqBody, err := json.Marshal(tailcfg.DERPAdmitClientRequest{
		NodePublic: key.NewNode().Public(),
	})
	require.NoError(t, err)

	// A real HTTP server is required to observe the bug: the first body
	// Write triggers an implicit WriteHeader that snapshots the header
	// map, so a Content-Type set afterwards never reaches the wire.
	// An httptest.ResponseRecorder does not snapshot, so it would hide
	// the defect.
	srv := httptest.NewServer(http.HandlerFunc(h.VerifyHandler))
	defer srv.Close()

	httpReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		srv.URL+"/verify",
		bytes.NewReader(reqBody),
	)
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"),
		"successful /verify response must advertise application/json")
}

// TestHandleVerifyRequest_AdmitsByNodeKey pins DERP admission to NodeKey
// membership. The oracle is the full-list scan the handler used to run, so
// the indexed lookup must agree with it on every row: expiry, tags and
// ephemerality never gate admission, and a rotated-away or deleted key is
// refused.
func TestHandleVerifyRequest_AdmitsByNodeKey(t *testing.T) {
	t.Parallel()

	app := createTestApp(t)
	user := app.state.CreateUserForTest("derp-admit")

	owned := putTestNodeInStore(t, app, user, "owned")

	tagged := app.state.CreateNodeForTest(user, "tagged")
	tagged.Tags = []string{"tag:derp"}
	app.state.PutNodeInStoreForTest(*tagged)

	ephemeral := app.state.CreateNodeForTest(user, "ephemeral")
	ephemeral.AuthKey = &types.Credential{Ephemeral: true}
	app.state.PutNodeInStoreForTest(*ephemeral)

	expired := app.state.CreateNodeForTest(user, "expired")
	expired.Expiry = new(time.Now().Add(-time.Hour))
	app.state.PutNodeInStoreForTest(*expired)

	rotated := putTestNodeInStore(t, app, user, "rotated")
	rotatedFrom := rotated.NodeKey
	rotated.NodeKey = key.NewNode().Public()
	app.state.PutNodeInStoreForTest(*rotated)

	deleted := putTestNodeInStore(t, app, user, "deleted")
	deletedView, ok := app.state.GetNodeByID(deleted.ID)
	require.True(t, ok)

	_, err := app.state.DeleteNode(deletedView)
	require.NoError(t, err)

	nv, ok := app.state.GetNodeByID(tagged.ID)
	require.True(t, ok)
	require.True(t, nv.IsTagged(), "test sanity: tagged row must be tagged")
	nv, ok = app.state.GetNodeByID(ephemeral.ID)
	require.True(t, ok)
	require.True(t, nv.IsEphemeral(), "test sanity: ephemeral row must be ephemeral")
	nv, ok = app.state.GetNodeByID(expired.ID)
	require.True(t, ok)
	require.True(t, nv.IsExpired(), "test sanity: expired row must be expired")

	tests := []struct {
		name string
		key  key.NodePublic
		want bool
	}{
		{name: "user", key: owned.NodeKey, want: true},
		{name: "tagged", key: tagged.NodeKey, want: true},
		{name: "ephemeral", key: ephemeral.NodeKey, want: true},
		{name: "rotated/old", key: rotatedFrom, want: false},
		{name: "rotated/new", key: rotated.NodeKey, want: true},
		{name: "expired", key: expired.NodeKey, want: true},
		{name: "deleted", key: deleted.NodeKey, want: false},
		{name: "unknown", key: key.NewNode().Public(), want: false},
		{name: "zero", key: key.NodePublic{}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body, err := json.Marshal(tailcfg.DERPAdmitClientRequest{NodePublic: tt.key})
			require.NoError(t, err)

			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				"/verify",
				bytes.NewReader(body),
			)

			var out bytes.Buffer
			require.NoError(t, app.handleVerifyRequest(req, &out))

			var resp tailcfg.DERPAdmitClientResponse
			require.NoError(t, json.Unmarshal(out.Bytes(), &resp))

			oracle := app.state.ListNodes().ContainsFunc(func(n types.NodeView) bool {
				return n.NodeKey() == tt.key
			})

			assert.Equal(t, tt.want, resp.Allow)
			assert.Equal(t, oracle, resp.Allow,
				"indexed admission must match the full-list membership scan")
		})
	}
}

// TestKeyHandler_UnsupportedCapVerDoesNotLeakKey reproduces
// https://github.com/juanfont/headscale/issues/3380. The /key handler
// must gate key disclosure on the same floor the Noise handshake
// enforces (capver.MinSupportedCapabilityVersion). A capability version
// below that floor can never complete a handshake, so it must be
// rejected rather than handed the server's Noise public key, which would
// otherwise serve only as a fingerprint / version-boundary oracle.
func TestKeyHandler_UnsupportedCapVerDoesNotLeakKey(t *testing.T) {
	t.Parallel()

	noise := key.NewMachine()
	h := &Headscale{noisePrivateKey: &noise}

	unsupported := capver.MinSupportedCapabilityVersion - 1

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		fmt.Sprintf("/key?v=%d", unsupported),
		nil,
	)

	h.KeyHandler(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code,
		"a client below the supported floor must be rejected")
	assert.NotContains(t, rec.Body.String(), noise.Public().String(),
		"must not disclose Noise public key to a client below the supported floor")

	// A supported client still receives the key.
	recOK := httptest.NewRecorder()
	reqOK := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		fmt.Sprintf("/key?v=%d", capver.MinSupportedCapabilityVersion),
		nil,
	)

	h.KeyHandler(recOK, reqOK)

	assert.Equal(t, http.StatusOK, recOK.Code)
	assert.Contains(t, recOK.Body.String(), noise.Public().String(),
		"a supported client must receive the Noise public key")
}

// errorAsHTTPError is a small local helper that unwraps an [HTTPError]
// from an error chain.
func errorAsHTTPError(err error) (HTTPError, bool) {
	if h, ok := errors.AsType[HTTPError](err); ok {
		return h, true
	}

	return HTTPError{}, false
}

func TestHttpUserError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		err            error
		wantCode       int
		wantContains   string
		wantNotContain string
	}{
		{
			name:           "forbidden_renders_authorization_message",
			err:            NewHTTPError(http.StatusForbidden, "csrf token mismatch", nil),
			wantCode:       http.StatusForbidden,
			wantContains:   "You are not authorized. Please contact your administrator.",
			wantNotContain: "csrf token mismatch",
		},
		{
			name:           "unauthorized_renders_authorization_message",
			err:            NewHTTPError(http.StatusUnauthorized, "unauthorised domain", nil),
			wantCode:       http.StatusUnauthorized,
			wantContains:   "You are not authorized. Please contact your administrator.",
			wantNotContain: "unauthorised domain",
		},
		{
			name:           "gone_renders_session_expired",
			err:            NewHTTPError(http.StatusGone, "login session expired, try again", nil),
			wantCode:       http.StatusGone,
			wantContains:   "Your session has expired. Please try again.",
			wantNotContain: "login session expired",
		},
		{
			name: "gone_with_user_message_renders_specific_guidance",
			err: newHTTPUserError(
				http.StatusGone,
				"registration link already used or expired",
				"This link has already been used or has expired.",
				nil,
			),
			wantCode:       http.StatusGone,
			wantContains:   "This link has already been used or has expired.",
			wantNotContain: "registration link already used or expired",
		},
		{
			name:           "bad_request_renders_generic_retry",
			err:            NewHTTPError(http.StatusBadRequest, "state not found", nil),
			wantCode:       http.StatusBadRequest,
			wantContains:   "The request could not be processed. Please try again.",
			wantNotContain: "state not found",
		},
		{
			name:         "plain_error_renders_500",
			err:          errTestUnexpected,
			wantCode:     http.StatusInternalServerError,
			wantContains: "Something went wrong. Please try again later.",
		},
		{
			name:         "html_structure_present",
			err:          NewHTTPError(http.StatusGone, "session expired", nil),
			wantCode:     http.StatusGone,
			wantContains: "<!DOCTYPE html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			httpUserError(rec, tt.err)

			assert.Equal(t, tt.wantCode, rec.Code)
			assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
			assert.Contains(t, rec.Body.String(), tt.wantContains)

			if tt.wantNotContain != "" {
				assert.NotContains(t, rec.Body.String(), tt.wantNotContain)
			}
		})
	}
}
