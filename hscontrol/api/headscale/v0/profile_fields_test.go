package apiv0

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// The raw client can send non-string members that the typed CLI cannot express.
func TestRapidUserFieldTypes(t *testing.T) {
	b, api, auth := usersAPI(t)
	alice := b.State.CreateUserForTest("alice")
	path := Prefix + "/users"
	userPath := path + "/" + strconv.FormatUint(uint64(alice.ID), 10)

	name, token, ok := strings.Cut(auth, ": ")
	if !ok {
		t.Fatal("fixture header malformed")
	}

	send := func(method, uri, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), method, uri, strings.NewReader(body))
		req.Header.Set(name, token)

		if method == http.MethodPatch {
			req.Header.Set("Content-Type", "application/merge-patch+json")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}

		rec := httptest.NewRecorder()
		api.Adapter().ServeHTTP(rec, req)

		return rec
	}

	holder := send(http.MethodPost, path, `{"name":"holder","email":"holder@example.org"}`)
	if holder.Code != http.StatusCreated {
		t.Fatalf("create holder: HTTP %d", holder.Code)
	}

	before := send(http.MethodGet, path, "")
	if before.Code != 200 {
		t.Fatalf("list control: status %d", before.Code)
	}

	type member struct {
		name, value string
		invalid     bool
	}

	var root, domain, wrongType, unknown, multi, conflicts int

	rapid.Check(t, func(rt *rapid.T) {
		method, uri := http.MethodPost, path
		if rapid.Bool().Draw(rt, "update") {
			method, uri = http.MethodPatch, userPath
		}

		var (
			want []string
			body string
		)

		status, code := http.StatusUnprocessableEntity, CodeInvalidField
		reasons := map[string]string{}

		switch rapid.IntRange(0, 9).Draw(rt, "shape") {
		case 0:
			body = rapid.SampledFrom([]string{"null", "[]", "3", `"record"`}).Draw(rt, "non-object")
			want = []string{"body"}
			root++
		case 1, 2:
			status = http.StatusConflict

			if rapid.Bool().Draw(rt, "occupied email") {
				body = `{"name":"spare","email":"holder@example.org"}`
				code = CodeEmailTaken
			} else {
				body = `{"name":"holder"}`
				code = CodeNameTaken
			}

			conflicts++
		default:
			members := []member{{"displayName", rapid.SampledFrom([]string{"4", "true", "[]", "{}"}).Draw(rt, "wrong type"), true}}
			if method == http.MethodPost || rapid.Bool().Draw(rt, "include name") {
				if rapid.Bool().Draw(rt, "bad username") {
					members = append(members, member{"name", `"1bad"`, true})
					reasons["body.name"] = "username"
				} else {
					members = append(members, member{"name", `"spare"`, false})
				}
			}

			for _, field := range []struct{ name, valid, invalid, reason string }{
				{"email", `"a@b.example"`, `"bad"`, "email"},
				{"profilePicUrl", `"https://a.example/p"`, `"relative"`, "url"},
			} {
				switch rapid.IntRange(0, 2).Draw(rt, field.name) {
				case 1:
					members = append(members, member{field.name, field.valid, false})
				case 2:
					members = append(members, member{field.name, field.invalid, true})
					reasons["body."+field.name] = field.reason
				}
			}

			if rapid.Bool().Draw(rt, "unknown member") {
				alias := rapid.SampledFrom([]string{"FutureValue", "Email", "DisplayName", "Name", "7", "bad.name", "a/b"}).Draw(rt, "spelling")
				members = append(members, member{alias, `"spare"`, true})
				unknown++
			}

			members = rapid.Permutation(members).Draw(rt, "members")

			words := make([]string, 0, len(members))
			for _, m := range members {
				words = append(words, strconv.Quote(m.name)+":"+m.value)
				if m.invalid {
					want = append(want, "body."+m.name)
				}
			}

			wrongType++

			if len(reasons) > 0 {
				domain++
			}

			if len(want) > 1 {
				multi++
			}

			body = "{" + strings.Join(words, ",") + "}"
		}

		res := send(method, uri, body)

		var prob Problem

		err := json.Unmarshal(res.Body.Bytes(), &prob)
		if err != nil {
			rt.Fatal(err)
		}

		if res.Code != status || prob.Status != status || prob.Code != code {
			rt.Fatalf("%s %s: wire=%d body=%d code=%s", method, body, res.Code, prob.Status, prob.Code)
		}

		got := locations(prob)
		slices.Sort(got)
		slices.Sort(want)

		if !slices.Equal(got, want) {
			rt.Fatalf("%s %s: locations %q, want %q", method, body, got, want)
		}

		for _, item := range prob.Errors {
			if reason := reasons[item.Location]; reason != "" && !strings.Contains(strings.ToLower(item.Message), reason) {
				rt.Fatalf("%s %s: diagnostic for %s omits %s: %s", method, body, item.Location, reason, item.Message)
			}
		}

		after := send(http.MethodGet, path, "")
		if after.Code != 200 || after.Body.String() != before.Body.String() {
			rt.Fatalf("%s %s changed the user list", method, body)
		}
	})
	t.Logf("model classes nonobject=%d domain-with-type=%d wrong-member-type=%d unknown-spelling=%d several-fields=%d occupied-identities=%d", root, domain, wrongType, unknown, multi, conflicts)
}
