package apiv1

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ogen-go/ogen/ogenerrors"
)

var errSecurityNotSatisfied = errors.New(
	`operation ListUsers: security "": security requirement is not satisfied`,
)

// TestClassifySecurityErrorIsMinimal ensures a failed security requirement
// becomes a clean 401 that does not leak ogen's internal operation/security
// message.
func TestClassifySecurityErrorIsMinimal(t *testing.T) {
	secErr := &ogenerrors.SecurityError{Err: errSecurityNotSatisfied}

	esc := classify(secErr)

	if esc.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", esc.StatusCode)
	}

	detail := esc.Response.Detail.Or("")
	if strings.Contains(detail, "operation") || strings.Contains(detail, "ListUsers") {
		t.Errorf("401 detail leaks internals: %q", detail)
	}
}
