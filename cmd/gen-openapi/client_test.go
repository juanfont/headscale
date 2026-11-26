package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/juanfont/headscale/client/shape"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

// answering is a client of a server that answers every request with
// status and body as JSON.
func answering(t *testing.T, status int, body string) *clientv0.ClientWithResponses {
	t.Helper()

	kind := "application/json"
	if status/100 != 2 {
		kind = "application/problem+json"
	}

	return answeringAs(t, kind, body, status)
}

// answeringAs is answering with the Content-Type kind, and 200 when no
// status is given.
func answeringAs(t *testing.T, kind, body string, status ...int) *clientv0.ClientWithResponses {
	t.Helper()

	code := http.StatusOK
	if len(status) > 0 {
		code = status[0]
	}

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", kind)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)

	c, err := clientv0.NewClientWithResponses(s.URL)
	require.NoError(t, err)

	return c
}

// TestPublicClientExactNames: the generated client's own entry points read
// a member by its exact name (002), as DecodeResponse does: one that
// differs in case only is no field, in an object and in a problem.
func TestPublicClientExactNames(t *testing.T) {
	t.Parallel()

	v, err := answering(t, http.StatusOK, `{"version":"one","Version":"two","commit":"","buildTime":"","dirty":false,"go":{"version":"","os":"","arch":""}}`).
		GetVersionWithResponse(t.Context())
	require.NoError(t, err)
	require.Equal(t, "one", v.JSON200.Version)

	p, err := answering(t, http.StatusUnauthorized, `{"code":"unauthenticated","Code":"internal","status":401,"title":"t"}`).
		GetMeWithResponse(t.Context())
	require.NoError(t, err)
	require.Equal(t, clientv0.ProblemCode("unauthenticated"), p.ApplicationproblemJSON401.Code)
}

// user is a row of GET /users with every member the document requires.
func user(id string) string {
	return `{"id":"` + id + `","name":"u` + id + `","displayName":"","email":"","loginName":"","created":"2026-01-01T00:00:00Z","nodeCount":0,"nodes":[],"profilePicUrl":"","provider":"local","providerId":""}`
}

// pages is a client of a server that answers GET /users with the page
// that page gives for the token asked, and notes each call.
func pages(t *testing.T, page func(call int, token string) (int, string)) (*clientv0.ClientWithResponses, *atomic.Int32) {
	t.Helper()

	var calls atomic.Int32

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body := page(int(calls.Add(1)), r.URL.Query().Get("pageToken"))

		w.Header().Set("Content-Type", "application/json")
		if status/100 != 2 {
			w.Header().Set("Content-Type", "application/problem+json")
		}

		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(s.Close)

	c, err := clientv0.NewClientWithResponses(s.URL)
	require.NoError(t, err)

	return c, &calls
}

const refusedToken = `{"type":"x","title":"x","status":422,"detail":"d","code":"invalid_page_token"}`

// doer answers every request with status, kind and body, built by hand as
// a caller's transport or a test double may: with the request it answers
// when withRequest, and without.
type doer struct {
	status      int
	kind, body  string
	withRequest bool
}

func (d doer) Do(r *http.Request) (*http.Response, error) {
	resp := &http.Response{
		StatusCode: d.status,
		Status:     fmt.Sprintf("%d %s", d.status, http.StatusText(d.status)),
		Header:     http.Header{"Content-Type": {d.kind}},
		Body:       io.NopCloser(strings.NewReader(d.body)),
	}
	if d.withRequest {
		resp.Request = r
	}

	return resp, nil
}

// class is how an answer was classified: "" for a success, else the kind
// of error and what it holds.
func class(err error) string {
	var (
		re *clientv0.ResponseError
		ae *clientv0.AnswerError
		se *shape.Error
	)

	switch {
	case err == nil:
		return ""
	case errors.As(err, &re) && re.Problem != nil:
		return "refusal " + string(re.Problem.Code)
	case errors.As(err, &re):
		return "refusal"
	case errors.Is(err, clientv0.ErrStatus):
		return "status"
	case errors.Is(err, clientv0.ErrEmptyPageToken):
		return "empty token"
	case errors.Is(err, clientv0.ErrPageTokenNotString):
		return "token not a string"
	case errors.As(err, &se) && strings.Contains(se.Why, "nextPageToken"):
		return "shape of the token"
	case errors.As(err, &se):
		return "shape"
	case errors.As(err, &ae) && strings.Contains(ae.Err.Error(), "nextPageToken"):
		return "decode of the token"
	case errors.As(err, &ae):
		return "decode"
	}

	return "other: " + err.Error()
}
