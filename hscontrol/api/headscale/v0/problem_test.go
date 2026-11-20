package apiv0

import (
	"context"
	"errors"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
)

func TestMapError(t *testing.T) {
	api := newTestAPI(t, Backend{})

	answer := func(path string, err error) {
		register(api, huma.Operation{OperationID: "boom" + strings.ToUpper(path[1:2]) + path[2:], Method: http.MethodGet, Path: Prefix + path}, public, nil,
			func(context.Context, *struct{}) (*struct{}, error) { return nil, err })
	}

	answer("/text", errors.New(`pq: relation "users" does not exist`)) //nolint:err113
	answer("/undeclared", newProblem(CodeUnhealthy, "the operation does not state this"))
	answer("/unknown", newProblem("made_up", "x"))

	for _, path := range []string{"/text", "/undeclared", "/unknown"} {
		rec := api.Get(Prefix + path)
		p := decodeProblem(t, rec, CodeInternal)
		require.Empty(t, p.Detail, path)
		require.NotContains(t, rec.Body.String(), "relation")
	}
}

func TestFromHumaError(t *testing.T) {
	em := &huma.ErrorModel{Status: http.StatusUnprocessableEntity, Detail: "validation failed"}
	for range maxFieldErrors + 3 {
		em.Errors = append(em.Errors, &huma.ErrorDetail{Location: "body", Message: "unexpected property", Value: map[string]any{"secret": "x"}})
	}

	p := fromHumaError(em)
	require.Equal(t, CodeInvalidField, p.Code)
	require.Len(t, p.Errors, maxFieldErrors+1)
	require.Equal(t, FieldError{Message: "and 3 more"}, p.Errors[maxFieldErrors])

	for msg, want := range map[string]string{
		"unknown query parameter": "unknown query parameter",
		"expected string":         "expected string",
		"expected string to be RFC 5322 email: mail: missing '@' or angle-addr": "expected string to be RFC 5322 email",
		"invalid JSON: invalid character 'x' looking for beginning of value":    "invalid JSON",
		`strconv.ParseInt: parsing "x": invalid syntax`:                         notValid,
	} {
		p := fromHumaError(&huma.ErrorModel{Status: http.StatusUnprocessableEntity, Errors: []*huma.ErrorDetail{{Location: "query.n", Message: msg}}})
		require.Equal(t, []FieldError{{Location: "query.n", Message: want}}, p.Errors, msg)
	}

	long := fromHumaError(&huma.ErrorModel{Status: http.StatusUnprocessableEntity, Errors: []*huma.ErrorDetail{
		{Location: "query." + strings.Repeat("A", 300), Message: "unknown query parameter"},
		{Location: "body.a\nb\x00ü", Message: "unexpected property"},
	}})
	require.Equal(t, "query."+strings.Repeat("A", maxLocation-len("query.")), long.Errors[0].Location)
	require.Equal(t, "body.a?b??", long.Errors[1].Location)

	for status, want := range map[int]Code{
		http.StatusBadRequest:     CodeInvalidRequest,
		http.StatusNotAcceptable:  CodeNotAcceptable,
		http.StatusRequestTimeout: CodeRequestTimeout,
		http.StatusBadGateway:     CodeInternal,
	} {
		p := fromHumaError(&huma.ErrorModel{Status: status, Detail: "go error text", Errors: []*huma.ErrorDetail{{Message: "go error text"}}})
		require.Equal(t, want, p.Code, status)
		require.Equal(t, codes[want].status, p.Status, "a code has one status")
		require.NotContains(t, p.Detail, "go error text")
		require.Empty(t, p.Errors)
	}
}

// humaStatuses are the error statuses huma v2.40.0 answers by itself, read
// from its source. Each needs a code. When huma moves, read them again.
var humaStatuses = []int{400, 404, 406, 408, 413, 415, 422, 500}

func TestHumaStatuses(t *testing.T) {
	for _, s := range humaStatuses {
		c, ok := statusCodes[s]
		require.True(t, ok, "huma answers %d, which has no code", s)
		require.Equal(t, s, codes[c].status)
	}

	info, ok := debug.ReadBuildInfo()
	require.True(t, ok)

	for _, d := range info.Deps {
		if d.Path == "github.com/danielgtaylor/huma/v2" {
			require.Equal(t, "v2.40.0", d.Version, "huma moved: read the statuses it answers again, then update humaStatuses")
		}
	}
}
