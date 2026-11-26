package command

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type pageReply struct {
	token, body string
	status      int
}

type pageScript struct {
	t       *rapid.T
	size    int
	path    string
	replies []pageReply
}

func (s *pageScript) Do(req *http.Request) (*http.Response, error) {
	if len(s.replies) == 0 {
		fatalf(s.t, "extra page request %s", req.URL.RequestURI())
	}

	reply := s.replies[0]
	s.replies = s.replies[1:]

	q := req.URL.Query()
	if req.Method != http.MethodGet || req.URL.Path != s.path ||
		q.Get("pageSize") != strconv.Itoa(s.size) ||
		q.Has("pageToken") != (reply.token != "") ||
		q.Get("pageToken") != reply.token {
		fatalf(
			s.t,
			"request %s %s, expected page size %d token %q",
			req.Method,
			req.URL.RequestURI(),
			s.size,
			reply.token,
		)
	}

	return &http.Response{
		Request:    req,
		StatusCode: reply.status,
		Body:       io.NopCloser(strings.NewReader(reply.body)),
	}, nil
}

// A restarted walk discards every prior row and may reuse a previous token.
//
// Bound: IDs rise within and across pages, so returning rows in ID order
// passes.
func TestRapidPageWalk(t *testing.T) {
	for _, kind := range []string{"users", "nodes"} {
		t.Run(kind, func(t *testing.T) { checkRapidPageWalk(t, kind) })
	}
}

func checkRapidPageWalk(t *testing.T, kind string) {
	t.Helper()

	var refusals, cycles, distantCycles, emptyPages, multirowPages, singlePage int

	walks := 0

	rapid.Check(t, func(rt *rapid.T) {
		size := rapid.IntRange(1, 5).Draw(rt, "page size")
		failures := rapid.IntRange(0, 2).Draw(rt, "refusals")
		cycle := failures < 2 && rapid.Bool().Draw(rt, "cycle on final walk")
		suffix := rapid.SampledFrom([]string{"", "+", "=", "/", "&", " ", "ø"}).
			Draw(rt, "opaque token suffix")
		walks++
		script := pageScript{t: rt, size: size, path: "/api/headscale/v0/" + kind}

		var want []string

		nextID := 1

		for attempt := 0; attempt <= min(failures, 1); attempt++ {
			minimum := 1
			if attempt < failures || cycle {
				minimum = 2
			}

			pages := rapid.IntRange(minimum, 6).Draw(rt, "pages")
			if pages == 1 {
				singlePage++
			}

			token := ""
			want = nil

			for i := range pages {
				reply := pageReply{token: token, status: http.StatusOK}
				if i == pages-1 && attempt < failures {
					reply.status = http.StatusUnprocessableEntity
					reply.body = `{"code":"invalid_page_token","status":422,"title":"invalid token"}`
					script.replies = append(script.replies, reply)
					refusals++

					break
				}

				rowCount := rapid.IntRange(0, size).Draw(rt, "rows on page")
				if rowCount == 0 {
					emptyPages++
				}

				if rowCount > 1 {
					multirowPages++
				}

				rows := make([]string, rowCount)
				for j := range rows {
					id := strconv.Itoa(nextID)
					nextID++
					rows[j] = kindRow(kind, `{"id":`+strconv.Quote(id)+`}`)
					want = append(want, id)
				}

				reply.body = `{` + strconv.Quote(
					kind,
				) + `:[` + strings.Join(
					rows,
					",",
				) + "]"

				if i+1 < pages || cycle {
					idx := i
					if i+1 == pages {
						idx = rapid.IntRange(0, i-1).Draw(rt, "repeated token")
						cycles++

						if idx < i-1 {
							distantCycles++
						}
					}

					token = strconv.Itoa(idx) + suffix
					reply.body += `,"nextPageToken":` + strconv.Quote(token)
				}

				reply.body += "}"
				script.replies = append(script.replies, reply)
			}
		}

		ids, err := script.rowIDs(kind)
		if len(script.replies) != 0 {
			fatalf(rt, "stopped with %d replies unread: %v", len(script.replies), err)
		}

		switch {
		case failures == 2:
			if !errors.Is(err, errRestarted) {
				fatalf(rt, "refused twice: err=%v", err)
			}
		case cycle:
			if err == nil ||
				!strings.Contains(err.Error(), "page token it had sent before") {
				fatalf(rt, "repeated token: err=%v", err)
			}
		default:
			if err != nil {
				fatalf(rt, "%v", err)
			}

			if !slices.Equal(ids, want) {
				fatalf(rt, "rows=%q want=%q", ids, want)
			}
		}
	})
	t.Logf(
		"model classes token-refusals=%d cycles=%d distant-cycles=%d empty-pages=%d multirow-pages=%d single-page-walks=%d %s=%d",
		refusals,
		cycles,
		distantCycles,
		emptyPages,
		multirowPages,
		singlePage,
		kind,
		walks,
	)
}

func (s *pageScript) rowIDs(kind string) ([]string, error) {
	c, err := clientv0.NewClientWithResponses(
		"http://fixture",
		clientv0.WithHTTPClient(s),
	)
	if err != nil {
		fatalf(s.t, "%v", err)
	}

	api := &API{ClientWithResponses: c, target: "fixture", PageSize: new(int64(s.size))}

	var ids []string

	switch kind {
	case "users":
		var rows []clientv0.User

		rows, err = listUsers(s.t.Context(), api)
		for _, row := range rows {
			ids = append(ids, row.Id)
		}

		if err != nil && rows != nil {
			fatalf(s.t, "partial users on error: %v", rows)
		}
	case "nodes":
		var rows []clientv0.Node

		rows, err = listNodes(s.t.Context(), api)
		for _, row := range rows {
			ids = append(ids, row.Id)
		}

		if err != nil && rows != nil {
			fatalf(s.t, "partial nodes on error: %v", rows)
		}
	}

	return ids, err
}

// A page-token refusal and an invalid field share status 422. Only the former restarts a walk.
//
// Bound: query values are read with Get, so a repeated pageSize passes, and
// the problem detail is not checked.
func TestRapidPageProblem(t *testing.T) {
	problems := []struct {
		code   string
		status int
	}{
		{"invalid_field", http.StatusUnprocessableEntity},
		{"invalid_request", http.StatusBadRequest},
		{"internal", http.StatusInternalServerError},
	}

	for _, kind := range []string{"users", "nodes"} {
		t.Run(kind, func(t *testing.T) {
			var sharedStatus, afterRows, afterRestart int

			rapid.Check(t, func(rt *rapid.T) {
				problem := rapid.SampledFrom(problems).Draw(rt, "problem")
				before := rapid.IntRange(0, 3).Draw(rt, "pages before error")

				if problem.status == http.StatusUnprocessableEntity {
					sharedStatus++
				}

				if before > 0 {
					afterRows++
				}

				script := pageScript{t: rt, path: "/api/headscale/v0/" + kind, size: 1}
				if rapid.Bool().Draw(rt, "restart before problem") {
					afterRestart++

					script.replies = append(
						script.replies,
						pageReply{
							status: http.StatusOK,
							body: fmt.Sprintf(
								`{%q:[%s],"nextPageToken":"1"}`,
								kind,
								kindRow(kind, `{"id":"9"}`),
							),
						},
						pageReply{
							token:  "1",
							status: http.StatusUnprocessableEntity,
							body:   `{"code":"invalid_page_token","status":422,"title":"invalid token"}`,
						},
					)
				}

				token := ""

				for i := range before {
					next := strconv.Itoa(i + 1)
					body := fmt.Sprintf(
						`{%q:[%s],"nextPageToken":%q}`,
						kind,
						kindRow(kind, `{"id":`+strconv.Quote(next)+`}`),
						next,
					)
					script.replies = append(
						script.replies,
						pageReply{token: token, body: body, status: http.StatusOK},
					)
					token = next
				}

				body := fmt.Sprintf(
					`{"code":%q,"status":%d,"title":%q}`,
					problem.code,
					problem.status,
					problem.code,
				)
				script.replies = append(
					script.replies,
					pageReply{token: token, body: body, status: problem.status},
				)
				_, err := script.rowIDs(kind)

				got, ok := errors.AsType[*ProblemError](err)
				if len(script.replies) != 0 || !ok ||
					string(got.Problem.Code) != problem.code ||
					got.Problem.Status != int64(problem.status) {
					fatalf(
						rt,
						"after %d pages: unread=%d err=%v, want %s (%d)",
						before,
						len(script.replies),
						err,
						problem.code,
						problem.status,
					)
				}
			})
			t.Logf(
				"model classes same-status-other-code=%d problem-after-rows=%d problem-after-restart=%d",
				sharedStatus,
				afterRows,
				afterRestart,
			)
		})
	}
}

func TestNodeAnswerFieldNames(t *testing.T) {
	t.Parallel()

	row := rowOf[clientv0.Node](
		`{"hostname":"alpha","hostName":"beta","createdBy":{"loginName":"alice","logInName":"bob"}}`,
	)

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/headscale/v0/nodes" {
				_, _ = io.WriteString(w, `{"nodes":[`+row+`]}`)
				return
			}

			_, _ = io.WriteString(w, row)
		}),
	)
	t.Cleanup(server.Close)

	api := bare(t, server.URL, 1)
	list, err := listNodes(t.Context(), api)
	require.NoError(t, err)
	require.Len(t, list, 1)
	node, err := getNode(t.Context(), api, "1")
	require.NoError(t, err)

	for _, got := range []clientv0.Node{list[0], node} {
		require.Equal(t, "alpha", got.Hostname)
		require.Equal(t, "alice", got.CreatedBy.GetOrEmpty().LoginName)
	}
}

// kindRow is a whole row of a users or nodes page with members.
func kindRow(kind, members string) string {
	if kind == "users" {
		return rowOf[clientv0.User](members)
	}

	return rowOf[clientv0.Node](members)
}

// fatalf fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
