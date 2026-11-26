package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	jsonv1 "github.com/go-json-experiment/json/v1"
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

// TestPublicClientExactNamesInAPage: so does a row of a list page.
func TestPublicClientExactNamesInAPage(t *testing.T) {
	t.Parallel()

	l, err := answering(t, http.StatusOK, `{"users":[`+strings.Replace(user("1"), `"name":"u1"`, `"name":"alpha","Name":"beta"`, 1)+`]}`).
		ListUsersWithResponse(t.Context(), nil)
	require.NoError(t, err)
	require.Equal(t, "alpha", l.JSON200.Users[0].Name)
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

// TestAll: ListXAll walks every page; a token the server refuses starts
// the walk over once, keeping no row of the refused walk, and a second
// refusal is the problem. A token that would never end the walk is
// refused.
func TestAll(t *testing.T) {
	t.Parallel()

	t.Run("pages", func(t *testing.T) {
		t.Parallel()

		c, calls := pages(t, func(_ int, token string) (int, string) {
			if token == "" {
				return 200, `{"users":[` + user("1") + `],"nextPageToken":"a"}`
			}

			return 200, `{"users":[` + user("2") + `]}`
		})

		users, err := c.ListUsersAll(t.Context(), nil)
		require.NoError(t, err)
		require.Len(t, users, 2)
		require.EqualValues(t, 2, calls.Load())
	})

	t.Run("restart once", func(t *testing.T) {
		t.Parallel()

		c, calls := pages(t, func(call int, token string) (int, string) {
			switch {
			case call == 2:
				return 422, refusedToken
			case token == "":
				return 200, `{"users":[` + user("1") + `],"nextPageToken":"a"}`
			}

			return 200, `{"users":[` + user("2") + `]}`
		})

		users, err := c.ListUsersAll(t.Context(), nil)
		require.NoError(t, err)
		require.Len(t, users, 2, "a row of the refused walk is kept")
		require.EqualValues(t, 4, calls.Load())
	})

	t.Run("refused twice", func(t *testing.T) {
		t.Parallel()

		c, _ := pages(t, func(_ int, token string) (int, string) {
			if token == "" {
				return 200, `{"users":[],"nextPageToken":"a"}`
			}

			return 422, refusedToken
		})

		_, err := c.ListUsersAll(t.Context(), nil)

		var pe *clientv0.PageError

		require.ErrorAs(t, err, &pe)
		require.Equal(t, "a", pe.Token)

		var re *clientv0.ResponseError

		require.ErrorAs(t, err, &re)
		require.Equal(t, clientv0.ProblemCodeInvalidPageToken, re.Problem.Code)
	})

	for name, tt := range map[string]struct {
		next string
		want error
	}{
		"repeated":     {`"same"`, clientv0.ErrRepeatedPageToken},
		"empty":        {`""`, clientv0.ErrEmptyPageToken},
		"null":         {`null`, clientv0.ErrEmptyPageToken},
		"not a string": {`3`, clientv0.ErrPageTokenNotString},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, _ := pages(t, func(int, string) (int, string) {
				return 200, `{"users":[],"nextPageToken":` + tt.next + `}`
			})

			_, err := c.ListUsersAll(t.Context(), nil)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

// TestAllEnds: only a page without nextPageToken ends a list: an empty
// list, and a list of one full page, are one call each.
func TestAllEnds(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"empty list":    `{"users":[]}`,
		"one full page": `{"users":[` + user("1") + `,` + user("2") + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c, calls := pages(t, func(int, string) (int, string) { return 200, body })

			_, err := c.ListUsersAll(t.Context(), &clientv0.ListUsersParams{PageSize: new(int64(2))})
			require.NoError(t, err)
			require.EqualValues(t, 1, calls.Load())
		})
	}
}

// TestPagesResume: a walk from a token asks for that page first; an error
// there names it; a page that leads back to it is refused before it is
// yielded, and asked once.
func TestPagesResume(t *testing.T) {
	t.Parallel()

	start := "resume-a"

	for _, tt := range []struct {
		name   string
		page   func(token string) (int, string)
		asked  []string
		yields int
		want   error
	}{
		{
			name:  "an error at the token",
			page:  func(string) (int, string) { return 503, `{"code":"unavailable"}` },
			asked: []string{start},
		},
		{
			name:  "a page back to the token",
			page:  func(string) (int, string) { return 200, `{"users":[],"nextPageToken":"resume-a"}` },
			asked: []string{start},
			want:  clientv0.ErrRepeatedPageToken,
		},
		{
			name: "on to the next",
			page: func(token string) (int, string) {
				if token == start {
					return 200, `{"users":[],"nextPageToken":"resume-b"}`
				}

				return 200, `{"users":[]}`
			},
			asked:  []string{start, "resume-b"},
			yields: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var asked []string

			c, _ := pages(t, func(_ int, token string) (int, string) {
				asked = append(asked, token)

				return tt.page(token)
			})

			yields := 0

			var pe *clientv0.PageError

			for _, err := range c.ListUsersPages(t.Context(), &clientv0.ListUsersParams{PageToken: &start}) {
				if err != nil {
					require.ErrorAs(t, err, &pe)

					break
				}

				yields++
			}

			require.Equal(t, tt.asked, asked)
			require.Equal(t, tt.yields, yields)

			if tt.yields == 0 {
				require.NotNil(t, pe)
				require.Equal(t, start, pe.Token)
			}

			if tt.want != nil {
				require.ErrorIs(t, pe, tt.want)
			}
		})
	}
}

// TestMediaType: a success is read whatever case or parameters its
// Content-Type has, by the same rule: the typed answer and Result agree.
func TestMediaType(t *testing.T) {
	t.Parallel()

	nulled := `{"users":null}`

	for _, kind := range []string{"application/json", "APPLICATION/JSON", "Application/Json; charset=utf-8", "text/plain"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			_, err := answeringAs(t, kind, nulled).ListUsersWithResponse(t.Context(), nil)

			var se *shape.Error

			require.ErrorAs(t, err, &se, "WithResponse")
			require.Equal(t, "its users is null", se.Why)

			resp, err := answeringAs(t, kind, `{"users":[]}`).ListUsersWithResponse(t.Context(), nil)
			require.NoError(t, err)
			require.NotNil(t, resp.JSON200, "the typed answer")
		})
	}
}

// TestRefusal: an answer that is not a success stays a *ResponseError, its
// status and body kept, whatever its body: a problem that does not read
// has no Problem.
func TestRefusal(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, kind, body string
		status           int
	}{
		{"a 404 that is not JSON", "application/problem+json", `<html>`, 404},
		{"a 404 with a member of another kind", "application/problem+json", `{"code": 3}`, 404},
		{"an empty 404", "application/problem+json", ``, 404},
		{"a 404 of text", "text/plain", `<html>`, 404},
		{"a 502 that is not JSON", "application/problem+json", `<html>`, 502},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := clientv0.Got(answeringAs(t, tt.kind, tt.body, tt.status).GetUserWithResponse(t.Context(), "1"))

			var re *clientv0.ResponseError

			require.ErrorAs(t, err, &re)
			require.Nil(t, re.Problem)
			require.Equal(t, tt.status, re.Response.StatusCode)
			require.Equal(t, tt.body, string(re.Body))
		})
	}
}

// TestWithDecoded: a call tells what it read, and its bytes.
func TestWithDecoded(t *testing.T) {
	t.Parallel()

	var got []string

	ctx := clientv0.WithDecoded(t.Context(), func(v any, raw []byte) {
		if u, ok := v.(*clientv0.User); ok {
			got = append(got, u.Id+" "+string(raw))
		}
	})

	body := strings.Replace(user("1"), `{`, `{"new":1,`, 1)

	_, err := clientv0.Got(answering(t, http.StatusOK, body).GetUserWithResponse(ctx, "1"))
	require.NoError(t, err)
	require.Equal(t, []string{"1 " + body}, got)
}

// TestPagesYieldsBodies: ListXPages yields each page as the client read
// it, its body included, and ends on the first error.
func TestPagesYieldsBodies(t *testing.T) {
	t.Parallel()

	c, _ := pages(t, func(_ int, token string) (int, string) {
		if token == "" {
			return 200, `{"users":[` + user("1") + `],"nextPageToken":"a","new":1}`
		}

		return 500, `{"type":"x","title":"x","status":500,"detail":"d","code":"internal"}`
	})

	var (
		bodies []string
		errs   []error
	)

	for resp, err := range c.ListUsersPages(t.Context(), nil) {
		if err != nil {
			errs = append(errs, err)

			continue
		}

		bodies = append(bodies, string(resp.Body))
	}

	require.Len(t, bodies, 1)
	require.Contains(t, bodies[0], `"new":1`)
	require.Len(t, errs, 1)
}

// TestStrict: a success that lacks a member the document requires, or
// holds it null, is refused for every caller, as an *AnswerError holding
// a *shape.Error; a member the document does not know passes. A problem
// is read as it comes.
func TestStrict(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, body, want string
	}{
		{"every member", user("1"), ""},
		{"a member this build does not know", strings.Replace(user("1"), `{`, `{"new":[1e400],`, 1), ""},
		{"a member missing", strings.Replace(user("1"), `"name":"u1",`, ``, 1), "it has no name"},
		{"a member null", strings.Replace(user("1"), `"nodes":[]`, `"nodes":null`, 1), "its nodes is null"},
		{"a list that is not one", strings.Replace(user("1"), `"nodes":[]`, `"nodes":{}`, 1), "its nodes is not a list"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := clientv0.Got(answering(t, http.StatusOK, tt.body).GetUserWithResponse(t.Context(), "1"))
			if tt.want == "" {
				require.NoError(t, err)

				return
			}

			var (
				ae *clientv0.AnswerError
				se *shape.Error
			)

			require.ErrorAs(t, err, &ae)
			require.ErrorAs(t, err, &se)
			require.Equal(t, tt.want, se.Why)
		})
	}

	// A problem with only a code is still one.
	_, err := clientv0.Got(answering(t, http.StatusNotFound, `{"code":"not_found"}`).GetUserWithResponse(t.Context(), "1"))

	var re *clientv0.ResponseError

	require.ErrorAs(t, err, &re)
	require.Equal(t, clientv0.ProblemCodeNotFound, re.Problem.Code)
}

// TestResult: a success with a status the operation does not answer is an
// *AnswerError with ErrStatus and the statuses it does; an answer that is
// not a problem is a *ResponseError with no Problem.
func TestResult(t *testing.T) {
	t.Parallel()

	_, err := clientv0.Got(answering(t, http.StatusCreated, user("1")).GetUserWithResponse(t.Context(), "1"))

	var ae *clientv0.AnswerError

	require.ErrorAs(t, err, &ae)
	require.ErrorIs(t, err, clientv0.ErrStatus)
	require.Equal(t, []int{200}, ae.Want)

	// A success whose Content-Type is not JSON is read all the same.
	u, err := clientv0.Got(answeringAs(t, "text/plain", user("1")).GetUserWithResponse(t.Context(), "1"))
	require.NoError(t, err)
	require.Equal(t, "u1", u.Name)

	_, err = clientv0.Got(answering(t, http.StatusBadGateway, `<html>`).GetUserWithResponse(t.Context(), "1"))

	var re *clientv0.ResponseError

	require.ErrorAs(t, err, &re)
	require.Nil(t, re.Problem)
	require.Equal(t, http.StatusBadGateway, re.Response.StatusCode)
}

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

// TestEveryWay: every exported way to read an answer of the client, the
// direct call and its typed fields, Result through Got, Pages, All and
// WithDecoded, classifies the same faulty answer the same, with the
// response holding its request or not.
func TestEveryWay(t *testing.T) {
	t.Parallel()

	good := user("1")
	badTime := strings.Replace(good, `"2026-01-01T00:00:00Z"`, `"yesterday"`, 1)
	missing := strings.Replace(good, `"name":"u1",`, ``, 1)

	for _, tt := range []struct {
		name       string
		status     int
		kind, body string
		// page is the body of a page of the list for the same answer.
		page string
		// want is the class of the answer; problem the code of the typed
		// problem of the direct call, "-" for none.
		want, problem string
		// decoded is the times WithDecoded hears a success.
		decoded int
	}{
		{name: "a success", status: 200, kind: "application/json", body: good, page: `{"users":[` + good + `]}`, want: "", problem: "-", decoded: 1},
		{name: "a success in upper case", status: 200, kind: "APPLICATION/JSON; charset=utf-8", body: good, page: `{"users":[` + good + `]}`, want: "", problem: "-", decoded: 1},
		{name: "a success of text", status: 200, kind: "text/plain", body: good, page: `{"users":[` + good + `]}`, want: "", problem: "-", decoded: 1},
		{name: "a member missing", status: 200, kind: "application/json", body: missing, page: `{"users":[` + missing + `]}`, want: "shape", problem: "-"},
		{name: "a member of another kind", status: 200, kind: "application/json", body: badTime, page: `{"users":[` + badTime + `]}`, want: "decode", problem: "-"},
		{name: "a status the operation does not answer", status: 201, kind: "application/json", body: good, page: `{"users":[` + good + `]}`, want: "status", problem: "-"},
		{name: "a problem", status: 404, kind: "application/problem+json", body: `{"code":"not_found"}`, page: `{"code":"not_found"}`, want: "refusal not_found", problem: "not_found"},
		{name: "a problem in upper case", status: 404, kind: "APPLICATION/PROBLEM+JSON", body: `{"code":"not_found"}`, page: `{"code":"not_found"}`, want: "refusal not_found", problem: "not_found"},
		{name: "a problem that is a page of a proxy", status: 404, kind: "application/problem+json", body: `<html>`, page: `<html>`, want: "refusal", problem: "-"},
		{name: "a problem with a member of another kind", status: 404, kind: "application/problem+json", body: `{"code":3}`, page: `{"code":3}`, want: "refusal", problem: "-"},
		{name: "a list", status: 200, kind: "application/json", body: `[]`, page: `[]`, want: "shape", problem: "-"},
		{name: "a number", status: 200, kind: "application/json", body: `17`, page: `17`, want: "shape", problem: "-"},
		{name: "no body", status: 200, kind: "application/json", body: ``, page: ``, want: "shape", problem: "-"},
		{name: "not JSON", status: 200, kind: "application/json", body: `{`, page: `{`, want: "shape", problem: "-"},
	} {
		for _, withRequest := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/request=%t", tt.name, withRequest), func(t *testing.T) {
				t.Parallel()

				answer := func(body string) *clientv0.ClientWithResponses {
					c, err := clientv0.NewClientWithResponses("http://hs.test", clientv0.WithHTTPClient(doer{tt.status, tt.kind, body, withRequest}))
					require.NoError(t, err)

					return c
				}

				decoded := 0
				ctx := clientv0.WithDecoded(t.Context(), func(any, []byte) { decoded++ })

				resp, err := answer(tt.body).GetUserWithResponse(ctx, "1")
				_, gerr := clientv0.Got(resp, err)
				require.Equal(t, tt.want, class(gerr), "Got")
				require.Equal(t, tt.decoded, decoded, "WithDecoded")

				// The direct call fails itself only for a success it cannot
				// read; any other answer it holds, as Result reads it.
				switch tt.want {
				case "shape", "decode":
					require.Equal(t, tt.want, class(err), "WithResponse")
				default:
					require.NoError(t, err, "WithResponse")
				}

				if err == nil {
					// The direct call: a success it holds is the one Result
					// returns, and so is its problem.
					require.Equal(t, tt.want == "", resp.JSON200 != nil, "JSON200")

					problem := "-"
					if resp.ApplicationproblemJSON404 != nil {
						problem = string(resp.ApplicationproblemJSON404.Code)
					}

					require.Equal(t, tt.problem, problem, "ApplicationproblemJSON404")
				}

				_, aerr := answer(tt.page).ListUsersAll(t.Context(), nil)
				require.Equal(t, tt.want, class(aerr), "All")

				var perr error
				for _, err := range answer(tt.page).ListUsersPages(t.Context(), nil) {
					perr = cmp.Or(perr, err)
				}

				require.Equal(t, tt.want, class(perr), "Pages")

				// An answer that cannot be read keeps its status and its bytes,
				// whichever way read it.
				if tt.want == "shape" || tt.want == "decode" {
					for way, err := range map[string]error{"Got": gerr, "All": aerr, "Pages": perr} {
						var ae *clientv0.AnswerError

						require.ErrorAs(t, err, &ae, way)
						require.Equal(t, tt.status, ae.Response.StatusCode, way)
					}

					var ae *clientv0.AnswerError

					require.ErrorAs(t, aerr, &ae)
					require.Equal(t, tt.page, string(ae.Body), "All")
				}
			})
		}
	}
}

// TestPageFaultOrder: a page with more than one fault says the first in
// one order: its status, then its shape and rows, then its token.
func TestPageFaultOrder(t *testing.T) {
	t.Parallel()

	badTime := strings.Replace(user("1"), `"2026-01-01T00:00:00Z"`, `"yesterday"`, 1)

	// direct is the class of the direct call (XWithResponse and Got) where
	// it differs from the walk's: a page read alone has no walk to end, so
	// its token's fault is a fault of its shape or kind.
	for _, tt := range []struct {
		name   string
		status int
		page   string
		want   string
		direct string
	}{
		{"206, a null token", 206, `{"users":[],"nextPageToken":null}`, "status", ""},
		{"206, a token not a string", 206, `{"users":[],"nextPageToken":{}}`, "status", ""},
		{"206, a row of another kind, a null token", 206, `{"users":[` + badTime + `],"nextPageToken":null}`, "status", ""},
		{"206, a row missing a member, a token not a string", 206, `{"users":[{"id":"1"}],"nextPageToken":7}`, "status", ""},
		{"a row of another kind, a null token", 200, `{"users":[` + badTime + `],"nextPageToken":null}`, "decode", ""},
		{"a row of another kind, a token not a string", 200, `{"users":[` + badTime + `],"nextPageToken":7}`, "decode", ""},
		{"a row of another kind, an empty token", 200, `{"users":[` + badTime + `],"nextPageToken":""}`, "decode", ""},
		{"a row missing a member, a null token", 200, `{"users":[{"id":"1"}],"nextPageToken":null}`, "shape", ""},
		{"a row missing a member, a token not a string", 200, `{"users":[{"id":"1"}],"nextPageToken":7}`, "shape", ""},
		{"no token", 200, `{"users":[]}`, "", ""},
		{"only a null token", 200, `{"users":[],"nextPageToken":null}`, "empty token", "shape of the token"},
		{"only a token not a string", 200, `{"users":[],"nextPageToken":7}`, "token not a string", "decode of the token"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := clientv0.NewClientWithResponses("http://hs.test", clientv0.WithHTTPClient(doer{tt.status, "application/json", tt.page, true}))
			require.NoError(t, err)

			direct := cmp.Or(tt.direct, tt.want)

			resp, err := c.ListUsersWithResponse(t.Context(), nil)
			_, gerr := clientv0.Got(resp, err)
			require.Equal(t, direct, class(gerr), "Got")

			// A refusal of the status is the typed answer's, not the call's.
			if tt.status == 206 {
				require.NoError(t, err, "ListUsersWithResponse")
				require.Nil(t, resp.JSON200, "JSON200")
			} else {
				require.Equal(t, direct, class(err), "ListUsersWithResponse")
			}

			_, err = c.ListUsersAll(t.Context(), nil)
			require.Equal(t, tt.want, class(err), "All")

			var perr error
			for _, err := range c.ListUsersPages(t.Context(), nil) {
				perr = cmp.Or(perr, err)
			}

			require.Equal(t, tt.want, class(perr), "Pages")
		})
	}
}

// TestWithDecodedNil: a nil function tells nothing, and breaks nothing.
func TestWithDecodedNil(t *testing.T) {
	t.Parallel()

	c, err := clientv0.NewClientWithResponses("http://hs.test", clientv0.WithHTTPClient(doer{200, "application/json", user("1"), true}))
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, err = clientv0.Got(c.GetUserWithResponse(clientv0.WithDecoded(t.Context(), nil), "1"))
	})
	require.NoError(t, err)
}

// TestOnlyTokenIsOptionalText: no answer holds a *string, at any depth,
// but a page's nextPageToken: the read of a page for its rows takes any
// value for a *string (pageOptions), which must not reach a row.
func TestOnlyTokenIsOptionalText(t *testing.T) {
	t.Parallel()

	seen := map[reflect.Type]bool{}

	var walk func(t reflect.Type, at string)

	walk = func(typ reflect.Type, at string) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
			typ = typ.Elem()
		}

		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}

		seen[typ] = true

		for f := range typ.Fields() {
			if f.Type == reflect.TypeFor[*string]() {
				require.Equal(t, "NextPageToken", f.Name, "%s.%s", at, f.Name)
			}

			walk(f.Type, at+"."+f.Name)
		}
	}

	for m := range reflect.TypeFor[clientv0.ClientWithResponsesInterface]().Methods() {
		for f := range m.Type.Out(0).Elem().Fields() {
			if strings.HasPrefix(f.Name, "JSON2") {
				walk(f.Type, m.Name)
			}
		}
	}

	require.True(t, seen[reflect.TypeFor[clientv0.UserList]()])
}

// TestPageFaultAsItCame: the fault of a page is the decoder's on the bytes
// as they came, offset and all, whenever its token is right; and an answer
// that is no page is never read as one, whatever member it holds.
func TestPageFaultAsItCame(t *testing.T) {
	t.Parallel()

	row := strings.Replace(user("1"), `"nodeCount":0`, `"nodeCount":"many"`, 1)

	for _, page := range []string{
		`{"users":[` + row + `],"nextPageToken":"a"}`,
		`{"nextPageToken":"a","users":[` + row + `]}`,
		`{"users":[` + row + `]}`,
	} {
		c, err := clientv0.NewClientWithResponses("http://hs.test", clientv0.WithHTTPClient(doer{200, "application/json", page, true}))
		require.NoError(t, err)

		_, err = c.ListUsersWithResponse(t.Context(), nil)

		var ae *clientv0.AnswerError

		require.ErrorAs(t, err, &ae)

		want := clientv0.DecodeResponse([]byte(page), new(clientv0.UserList))
		require.Equal(t, want.Error(), ae.Err.Error(), page)

		var got, wanted *jsonv1.UnmarshalTypeError

		require.ErrorAs(t, ae.Err, &got, page)
		require.ErrorAs(t, want, &wanted, page)
		require.Equal(t, wanted.Offset, got.Offset, page)
		require.Equal(t, page, string(ae.Body), page)
	}

	// The faults of a user: the same with a member nextPageToken, which
	// is no member of a user.
	var said []string

	for _, more := range []string{``, `,"nextPageToken":true`, `,"nextPageToken":null`} {
		body := strings.Replace(strings.Replace(user("1"), `"name":"u1"`, `"name":9`, 1), `"nodeCount":0`, `"nodeCount":"x"`, 1)
		body = strings.TrimSuffix(body, "}") + more + "}"

		c, err := clientv0.NewClientWithResponses("http://hs.test", clientv0.WithHTTPClient(doer{200, "application/json", body, true}))
		require.NoError(t, err)

		_, err = c.GetUserWithResponse(t.Context(), "1")
		require.Error(t, err)

		said = append(said, err.Error())
	}

	require.Equal(t, said[0], said[1])
	require.Equal(t, said[0], said[2])
}
