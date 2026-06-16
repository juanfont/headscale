package hscontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

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

// errorAsHTTPError is a small local helper that unwraps an [HTTPError]
// from an error chain.
func errorAsHTTPError(err error) (HTTPError, bool) {
	var h HTTPError
	if errors.As(err, &h) {
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
