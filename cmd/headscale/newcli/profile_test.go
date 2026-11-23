package newcli

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	cmp "github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmdline/argtest"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"pgregory.net/rapid"
)

type profileFields struct{ Name, DisplayName, Email, ProfilePicURL string }

func (p profileFields) matches(body []byte, id string) bool {
	var fields map[string]any
	if json.Unmarshal(body, &fields) != nil {
		return false
	}

	return fields["id"] == id && fields["name"] == p.Name && fields["loginName"] == p.loginName() &&
		fields["displayName"] == p.DisplayName && fields["email"] == p.Email && fields["profilePicUrl"] == p.ProfilePicURL
}

func (p profileFields) loginName() string {
	if p.Email != "" {
		return p.Email
	}

	return p.Name
}

func (p profileFields) matchesOutput(out, id string, changed []string, formatted bool) bool {
	if formatted {
		return p.matches([]byte(out), id)
	}

	return out == "User "+id+" ("+p.loginName()+") updated: "+strings.Join(changed, ", ")+".\n"
}

type profilePatchDraw struct {
	next      profileFields
	fields    map[string]any
	options   [][]string
	formatted bool
	changed   []string
	invalid   map[string]string
}

type profileDrawCounts struct {
	clears, repeated, renames, atLimit, aboveLimit int
}

func drawProfilePatch(rt *rapid.T, state, holder profileFields, counts *profileDrawCounts) profilePatchDraw {
	rt.Helper()

	next := state
	patch := map[string]any{}

	var options [][]string

	formatted := rapid.Bool().Draw(rt, "JSON")
	if formatted {
		options = append(options, []string{"-o", "json"})
	}

	changed := make([]string, 0, 4)
	invalid := map[string]string{}

	for _, field := range []struct {
		flag, key, label, value, bad string
		member                       *string
	}{
		{"--name", "name", "name", "alice-two", "x", &next.Name},
		{"--display-name", "displayName", "display name", "Alice Two", "", &next.DisplayName},
		{"--email", "email", "email", "second@example.org", "invalid", &next.Email},
		{"--picture-url", "profilePicUrl", "picture URL", "https://example.org/second", "relative.png", &next.ProfilePicURL},
	} {
		choices := []string{"omit", "clear", "set", "repeat"}
		if field.bad != "" {
			choices = append(choices, "invalid")
		}

		if field.key == "name" || field.key == "email" {
			choices = append(choices, "taken")
		}

		mode := rapid.SampledFrom(choices).Draw(rt, field.key)
		value := field.value

		switch mode {
		case "omit":
			continue
		case "clear":
			value = ""
			counts.clears++
		case "repeat":
			value = *field.member
			counts.repeated++
		case "invalid":
			value = field.bad
		case "taken":
			value = holder.Name
			if field.key == "email" {
				value = "Bob@example.org"
			}
		}

		if field.key == "displayName" && mode == "set" {
			size := rapid.SampledFrom([]int{1, 64, 65, 128, 129}).Draw(rt, "display-name length")
			letter := rapid.SampledFrom([]string{"é", "한", "가"}).Draw(rt, "display-name unit")

			value = strings.Repeat(letter, size)
			switch n := utf8.RuneCountInString(value); {
			case n == 128:
				counts.atLimit++
			case n > 128:
				counts.aboveLimit++
				invalid["body."+field.key] = field.flag
			}
		}

		if mode == "invalid" || (field.key == "name" && value == "") {
			invalid["body."+field.key] = field.flag
		}

		if field.key == "name" && len(value) > 1 && value != state.Name {
			counts.renames++
		}

		changed = append(changed, field.label)
		patch[field.key] = value
		*field.member = value
		options = append(options, argtest.Option(rt, field.flag, value))
	}

	return profilePatchDraw{next: next, fields: patch, options: options, formatted: formatted, changed: changed, invalid: invalid}
}

// An omitted field, an explicit empty field, and a rejected patch have different effects.
func TestRapidUserProfilePatch(t *testing.T) {
	f := newFixture(t, true)

	client, err := clientv0.NewClientWithResponses(f.srv.URL, clientv0.WithHTTPClient(f.srv.SocketClient()))
	if err != nil {
		t.Fatal(err)
	}

	baseline := profileFields{"alice", "Initial", "first@example.org", "https://example.org/first"}
	holder := profileFields{"bobby", "Bobby", "bob@example.org", "https://example.org/bob"}

	createProfile := func(rt *rapid.T, fields profileFields) string {
		rt.Helper()

		res, err := client.CreateUserWithResponse(rt.Context(), clientv0.CreateUserBody{Name: fields.Name, DisplayName: &fields.DisplayName, Email: &fields.Email, ProfilePicUrl: &fields.ProfilePicURL})
		if err != nil {
			rt.Fatal(err)
		}

		if res.JSON201 == nil || !fields.matches(res.Body, res.JSON201.Id) {
			rt.Fatal("could not create baseline profile")
		}

		return res.JSON201.Id
	}

	var (
		draws                                                                    profileDrawCounts
		combined, refused, textReplies, severalInvalid, clashes, validationFirst int
	)

	rapid.Check(t, func(rt *rapid.T) {
		resetCollectionUsers(rt, f)
		id := createProfile(rt, baseline)
		other := createProfile(rt, holder)
		owner := clientv0.ProblemObject{Id: other, Kind: "user", Name: holder.loginName()}

		state := baseline
		for range rapid.IntRange(1, 5).Draw(rt, "steps") {
			step := drawProfilePatch(rt, state, holder, &draws)

			target := id
			if rapid.Bool().Draw(rt, "lookup by name") {
				target = state.Name
			}

			argv := argtest.Interleave(rt, []string{target}, step.options...)
			for i, word := range argv {
				argv[i] = strconv.Quote(word)
			}

			got := f.run(t, cliCase{args: "users set " + strings.Join(argv, " ")})

			checkMergePatch(rt, got.sent, usersPath+"/"+id, step.fields)

			if len(step.fields) > 1 {
				combined++
			}

			field, clash := "", ""

			switch {
			case step.fields["name"] == holder.Name:
				field, clash = "name", holder.Name
			case step.fields["email"] == "Bob@example.org":
				field, clash = "email", "Bob@example.org"
			}

			if len(step.invalid) > 0 || len(step.fields) == 0 {
				refused++

				if got.code != 1 || got.stdout != "" || got.stderr == "" {
					rt.Fatalf("refused patch %v: code=%d stdout=%q stderr=%q", step.fields, got.code, got.stdout, got.stderr)
				}

				if len(step.invalid) > 1 {
					severalInvalid++
				}

				if field != "" {
					validationFirst++
				}

				if len(step.invalid) > 0 {
					checkRejectedFields(rt, got, usersPath+"/"+id, step.invalid)
				}
			} else if field != "" {
				refused++
				clashes++

				checkProfileConflict(rt, got, usersPath+"/"+id, owner, field, clash)
			} else {
				state = step.next

				if !step.formatted {
					textReplies++
				}

				if got.code != 0 || got.stderr != "" || !state.matchesOutput(got.stdout, id, step.changed, step.formatted) {
					rt.Fatalf("accepted patch %v: code=%d stdout=%q stderr=%q, want %+v", step.fields, got.code, got.stdout, got.stderr, state)
				}
			}

			read, err := client.GetUserWithResponse(rt.Context(), id)
			if err != nil || read.JSON200 == nil {
				rt.Fatalf("read after patch %v: response=%v err=%v", step.fields, read, err)
			}

			if !state.matches(read.Body, id) {
				rt.Fatalf("persisted after patch %v: got %s, want %+v", step.fields, read.Body, state)
			}

			second, err := client.GetUserWithResponse(rt.Context(), other)
			if err != nil {
				rt.Fatal(err)
			}

			if second.JSON200 == nil || !holder.matches(second.Body, other) {
				rt.Fatal("second profile changed")
			}
		}
	})
	t.Logf("model classes explicit-clears=%d combined-patches=%d refused-patches=%d repeated-values=%d name-changes-requested=%d text-replies=%d multiple-invalid-fields=%d at-display-limit=%d above-display-limit=%d identity-conflicts=%d field-before-conflict=%d", draws.clears, combined, refused, draws.repeated, draws.renames, textReplies, severalInvalid, draws.atLimit, draws.aboveLimit, clashes, validationFirst)
}

func checkMergePatch(rt *rapid.T, sent []string, path string, want map[string]any) {
	rt.Helper()

	var writes []map[string]any

	for _, request := range sent {
		line, ok := strings.CutPrefix(request, "PATCH ")
		if !ok {
			continue
		}

		target, body, ok := strings.Cut(line, " ")
		if !ok || target != path {
			rt.Fatalf("unexpected PATCH %q, want %q", request, path)
		}

		var fields map[string]any

		err := json.Unmarshal([]byte(body), &fields)
		if err != nil {
			rt.Fatal(err)
		}

		writes = append(writes, fields)
	}

	if len(want) == 0 {
		if len(writes) != 0 {
			rt.Fatalf("empty update sent %v", writes)
		}

		return
	}

	if len(writes) != 1 || !cmp.Equal(writes[0], want) {
		rt.Fatalf("sent %v, want one patch %v", writes, want)
	}
}

func userPatchProblem(t rapid.TB, got result, path string) clientv0.Problem {
	t.Helper()

	bodies := got.answers[path]
	if got.code != 1 || got.stdout != "" || len(bodies) == 0 {
		t.Fatalf("profile error: exit %d, stdout %q, answers %d", got.code, got.stdout, len(bodies))
	}

	var problem clientv0.Problem

	err := json.Unmarshal(bodies[len(bodies)-1], &problem)
	if err != nil {
		t.Fatal(err)
	}

	return problem
}

func checkRejectedFields(t rapid.TB, got result, path string, want map[string]string) {
	t.Helper()

	p := userPatchProblem(t, got, path)
	if p.Status != 422 || p.Code != "invalid_field" || len(p.Errors) != len(want) {
		t.Fatalf("invalid field response: status=%d code=%s errors=%v want=%v", p.Status, p.Code, p.Errors, want)
	}

	locations := map[string]bool{}

	lines := strings.Split(strings.TrimSuffix(got.stderr, "\n"), "\n")
	if len(lines) != len(want)+1 {
		t.Fatalf("CLI field errors %q want flags %v", got.stderr, want)
	}

	for _, field := range p.Errors {
		flag, ok := want[field.Location]
		if !ok || locations[field.Location] || field.Message == "" {
			t.Fatalf("invalid field entry %+v, want %v", field, want)
		}

		locations[field.Location] = true
		if !slices.Contains(lines[1:], "  "+flag+": "+field.Message) {
			t.Fatalf("CLI field errors %q missing %s: %s", got.stderr, flag, field.Message)
		}
	}
}

func checkProfileConflict(t rapid.TB, got result, path string, owner clientv0.ProblemObject, field, value string) {
	t.Helper()
	p := userPatchProblem(t, got, path)

	obj, err := p.Object.Get()
	if p.Status != 409 || string(p.Code) != field+"_taken" || err != nil || obj != owner || p.Details[field] != value {
		t.Fatalf("wrong conflict for %s %q: status=%d code=%s detail=%v holder=%+v want=%+v", field, value, p.Status, p.Code, p.Details[field], obj, owner)
	}

	want := fmt.Sprintf("Error: the %s %q belongs to User %s (%s).\n", field, value, owner.Id, owner.Name)
	if got.stderr != want {
		t.Fatalf("conflict stderr=%q want=%q", got.stderr, want)
	}
}

func TestUserProfileRefusals(t *testing.T) {
	f := newFixture(t, true)
	id := strconv.FormatUint(uint64(f.srv.CreateUser(t, "alice").ID), 10)
	other := strconv.FormatUint(uint64(f.srv.CreateUser(t, "bobby").ID), 10)

	client, err := clientv0.NewClientWithResponses(f.srv.URL, clientv0.WithHTTPClient(f.srv.SocketClient()))
	if err != nil {
		t.Fatal(err)
	}

	seed := f.run(t, cliCase{args: "users set bobby --email bob@example.org"})
	if seed.code != 0 {
		t.Fatal(seed.stderr)
	}

	read := func(id string) map[string]any {
		t.Helper()

		res, err := client.GetUserWithResponse(t.Context(), id)
		if err != nil || res.JSON200 == nil {
			t.Fatalf("read user %s: %v, %v", id, res, err)
		}

		var row map[string]any

		err = json.Unmarshal(res.Body, &row)
		if err != nil {
			t.Fatal(err)
		}

		return row
	}
	// Each accepted boundary becomes the baseline for later refusals.
	for _, tc := range []struct {
		name, flags, code, clash string
		fields                   map[string]string
	}{
		{name: "at character limit", flags: "--picture-url= --display-name " + strings.Repeat("é", 128)},
		{name: "above character limit", flags: "--picture-url=https://example.org/new --display-name " + strings.Repeat("é", 129), fields: map[string]string{"body.displayName": "--display-name"}},
		{name: "two invalid fields", flags: "--display-name=Changed --email=invalid --picture-url=relative.png", fields: map[string]string{"body.email": "--email", "body.profilePicUrl": "--picture-url"}},
		{name: "name conflict", flags: "--display-name=Changed --name=bobby", code: "name_taken", clash: "bobby"},
		{name: "email conflict", flags: "--display-name=Changed --email=Bob@example.org", code: "email_taken", clash: "Bob@example.org"},
		{name: "both conflicts", flags: "--email=Bob@example.org --name=bobby --display-name=Changed", code: "name_taken", clash: "bobby"},
		{name: "field before conflict", flags: "--email=Bob@example.org --display-name=Changed --picture-url=relative.png", fields: map[string]string{"body.profilePicUrl": "--picture-url"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, holder := read(id), read(other)

			got := f.run(t, cliCase{args: "users set " + id + " " + tc.flags + " -o json"})
			switch {
			case len(tc.fields) > 0:
				checkRejectedFields(t, got, usersPath+"/"+id, tc.fields)
			case tc.code != "":
				owner := clientv0.ProblemObject{Id: other, Kind: "user", Name: "bob@example.org"}
				checkProfileConflict(t, got, usersPath+"/"+id, owner, strings.TrimSuffix(tc.code, "_taken"), tc.clash)
			default:
				if got.code != 0 || got.stderr != "" {
					t.Fatalf("legal character boundary exit=%d stderr=%q", got.code, got.stderr)
				}

				before["displayName"] = strings.Repeat("é", 128)
				before["profilePicUrl"] = ""
			}

			if diff := cmp.Diff(before, read(id)); diff != "" {
				t.Fatalf("target after update (-want +got): %s", diff)
			}

			if diff := cmp.Diff(holder, read(other)); diff != "" {
				t.Fatalf("holder after update (-want +got): %s", diff)
			}
		})
	}
}
