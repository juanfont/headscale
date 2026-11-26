package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// fieldCap is the number of field errors a problem lists. It pins what the
// server does today; neither proposal 002 nor the page of problem codes
// promises the number. The test holds its own copy, so a change of the cap
// fails here instead of moving the oracle with it.
const fieldCap = 20

// TestUserErrorCountCap: one bad field is one entry, twenty are twenty,
// and twenty-one are twenty and a last entry that counts the rest.
func TestUserErrorCountCap(t *testing.T) {
	_, api, auth := usersAPI(t)

	for n, want := range map[int][]FieldError{
		1:  {{Location: "body.other0", Message: "unexpected property"}},
		20: nil,
		21: {{Message: "and 1 more"}},
	} {
		body := map[string]any{"name": "charlie"}
		for i := range n {
			body["other"+strconv.Itoa(i)] = i
		}

		var p Problem

		res := api.Post(Prefix+"/users", auth, body)
		require.NoError(t, json.Unmarshal(res.Body.Bytes(), &p))
		require.Len(t, p.Errors, min(n, fieldCap)+btoi(n > fieldCap), n)

		if n == 1 || n > fieldCap {
			require.Equal(t, want[len(want)-1], p.Errors[len(p.Errors)-1], n)
		}

		for _, e := range p.Errors[:min(n, fieldCap)] {
			require.NotEmpty(t, e.Location, n)
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}

	return 0
}

func TestRapidUserErrorCount(t *testing.T) {
	_, api, auth := usersAPI(t)
	rapid.Check(t, func(rt *rapid.T) {
		unknown := rapid.IntRange(0, 2*fieldCap+2).Draw(rt, "unknown fields")
		badEmail := rapid.Bool().Draw(rt, "bad email")
		badName := rapid.Bool().Draw(rt, "overlong username")
		badDisplay := rapid.Bool().Draw(rt, "overlong display name")
		patch := rapid.Bool().Draw(rt, "PATCH")
		body := map[string]any{"name": "charlie"}
		fields := map[string]bool{}

		for i := range unknown {
			k := "other" + strconv.Itoa(i)
			fields["body."+k] = true
			body[k] = i
		}

		if badEmail {
			body["email"] = "bad"
			fields["body.email"] = true
		}

		if badName {
			body["name"] = strings.Repeat("!", 255)
			fields["body.name"] = true
		}

		if badDisplay {
			body["displayName"] = strings.Repeat("x", 129)
			fields["body.displayName"] = true
		}

		if len(fields) == 0 {
			body["email"] = "bad"
			fields["body.email"] = true
		}

		var res *httptest.ResponseRecorder
		if patch {
			res = api.Patch(
				Prefix+"/users/1",
				auth,
				"Content-Type: application/merge-patch+json",
				body,
			)
		} else {
			res = api.Post(Prefix+"/users", auth, body)
		}

		var p Problem

		err := json.Unmarshal(res.Body.Bytes(), &p)
		if err != nil || res.Code != http.StatusUnprocessableEntity ||
			p.Status != res.Code ||
			p.Code != CodeInvalidField {
			fatalf(
				rt,
				"field refusal: wire=%d body=%d code=%s err=%v",
				res.Code,
				p.Status,
				p.Code,
				err,
			)
		}

		// Past the cap, the last entry is the count of the rest, with no
		// location; below it there is no such entry.
		details := p.Errors
		listed := min(len(fields), fieldCap)

		if len(fields) > fieldCap {
			want := FieldError{
				Message: "and " + strconv.Itoa(len(fields)-fieldCap) + " more",
			}
			if n := len(details); n == 0 || details[n-1] != want {
				fatalf(
					rt,
					"with %d invalid fields the last entry is %v; want %v",
					len(fields),
					details,
					want,
				)
			}

			details = details[:len(details)-1]
		}

		if len(details) != listed {
			fatalf(
				rt,
				"listed=%d with %d invalid fields; want %d: %v",
				len(details),
				len(fields),
				listed,
				p.Errors,
			)
		}

		for _, d := range details {
			if !fields[d.Location] {
				fatalf(rt, "unexpected or repeated field %q", d.Location)
			}

			delete(fields, d.Location)
		}
	})
}

// fatalf fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
