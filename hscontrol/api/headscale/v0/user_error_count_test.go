package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestRapidUserErrorCount(t *testing.T) {
	_, api, auth := usersAPI(t)
	rapid.Check(t, func(rt *rapid.T) {
		unknown := rapid.IntRange(0, 2*maxFieldErrors+2).Draw(rt, "unknown fields")
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
			res = api.Patch(Prefix+"/users/1", auth, "Content-Type: application/merge-patch+json", body)
		} else {
			res = api.Post(Prefix+"/users", auth, body)
		}

		var p Problem

		err := json.Unmarshal(res.Body.Bytes(), &p)
		if err != nil || res.Code != http.StatusUnprocessableEntity || p.Status != res.Code || p.Code != CodeInvalidField {
			rt.Fatalf("field refusal: wire=%d body=%d code=%s err=%v", res.Code, p.Status, p.Code, err)
		}

		var trailer string

		details := p.Errors
		if n := len(details); n > 0 && details[n-1].Location == "" {
			trailer = details[n-1].Message
			details = details[:n-1]
		}

		want := ""
		if len(fields) > maxFieldErrors {
			want = "and " + strconv.Itoa(len(fields)-maxFieldErrors) + " more"
		}

		if trailer != want || len(details) != min(len(fields), maxFieldErrors) {
			rt.Fatalf("listed=%d trailer=%q with %d invalid fields; want %d and %q", len(details), trailer, len(fields), min(len(fields), maxFieldErrors), want)
		}

		for _, d := range details {
			if !fields[d.Location] {
				rt.Fatalf("unexpected or repeated field %q", d.Location)
			}

			delete(fields, d.Location)
		}
	})
}
