package hscontrol

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var errTestUnexpected = errors.New("unexpected failure")

// TestHandleVerifyRequest_OversizedBodyRejected verifies that the
// /verify handler refuses POST bodies larger than verifyBodyLimit.
// The MaxBytesReader is applied in VerifyHandler, so we simulate
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

// errorAsHTTPError is a small local helper that unwraps an HTTPError
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
