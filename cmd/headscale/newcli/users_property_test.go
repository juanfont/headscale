package newcli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/argtest"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"pgregory.net/rapid"
)

// Bound: rows decode into a struct with Name only.
func TestRapidUserListJSONArray(t *testing.T) {
	f := newFixture(t, false)
	check := func(t *testing.T, filter string, want []string) {
		t.Helper()
		rapid.Check(t, func(rt *rapid.T) {
			leaf := rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "command")
			output := rapid.SampledFrom([]string{"-o json", "--output=json"}).
				Draw(rt, "output")
			sort := rapid.SampledFrom([]string{"name", "-name"}).Draw(rt, "sort")
			size := rapid.IntRange(1, 3).Draw(rt, "page size")
			args := "users " + leaf + " " + output + " --sort " + sort + filter
			r := f.run(t, cliCase{args: args, pageSize: size})

			var rows []struct{ Name string }

			err := json.Unmarshal([]byte(r.stdout), &rows)
			if err != nil || rows == nil || r.stderr != "" || r.code != 0 {
				fatalf(
					rt,
					"%s: expected JSON array; stdout=%q stderr=%q exit=%d decode=%v",
					args,
					r.stdout,
					r.stderr,
					r.code,
					err,
				)
			}

			names := make([]string, 0, len(rows))
			for _, u := range rows {
				names = append(names, u.Name)
			}

			ordered := slices.Clone(want)
			if sort == "-name" {
				slices.Reverse(ordered)
			}

			if !slices.Equal(names, ordered) {
				fatalf(rt, "%s: got %q want %q", args, names, ordered)
			}
		})
	}
	t.Run("empty-store", func(t *testing.T) { check(t, "", nil) })

	for _, name := range []string{"alice", "bob"} {
		f.srv.CreateUser(t, name)
	}

	t.Run(
		"filtered-empty",
		func(t *testing.T) { check(t, " --filter name=absent", nil) },
	)
	t.Run("nonempty", func(t *testing.T) { check(t, "", []string{"alice", "bob"}) })
}

// Bound: IDs are not compared, and API row order is checked only as page
// membership.
func TestRapidUserQuery(t *testing.T) {
	f := newFixture(t, false)

	names := []string{"alice", "bob", "carol"}
	for _, name := range names {
		f.srv.CreateUser(t, name)
	}

	rapid.Check(t, func(rt *rapid.T) {
		leaf := rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "leaf")
		output := rapid.SampledFrom([]string{"-o json", "-o=json", "--output=json", "--output json"}).
			Draw(rt, "global spelling")
		sort := rapid.SampledFrom([]string{"name", "-name"}).Draw(rt, "order")
		match := rapid.SampledFrom([]string{"a", "b", "absent", "e", "o"}).
			Draw(rt, "substring")
		size := rapid.IntRange(1, 4).Draw(rt, "page size")
		filter := "--filter name:" + match
		sortFlag := "--sort=" + sort

		locals := []string{filter, sortFlag}
		if rapid.Bool().Draw(rt, "swap local flags") {
			slices.Reverse(locals)
		}

		argv := append([]string{"users", leaf}, locals...)
		slot := rapid.IntRange(0, len(argv)).Draw(rt, "global slot")

		argv = slices.Insert(argv, slot, output)
		if rapid.Bool().Draw(rt, "trailing marker") {
			argv = append(argv, "--")
		}

		args := strings.Join(argv, " ")
		r := f.run(t, cliCase{args: args, pageSize: size})

		var rows []struct{ Name string }
		if r.code != 0 || r.stderr != "" ||
			json.Unmarshal([]byte(r.stdout), &rows) != nil ||
			rows == nil {
			fatalf(
				rt,
				"%s: code=%d stdout=%q stderr=%q",
				args,
				r.code,
				r.stdout,
				r.stderr,
			)
		}

		got := make([]string, 0, len(rows))

		var want []string

		for _, row := range rows {
			got = append(got, row.Name)
		}

		for _, name := range names {
			if strings.Contains(name, match) {
				want = append(want, name)
			}
		}

		if sort == "-name" {
			slices.Reverse(want)
		}

		if !slices.Equal(got, want) {
			fatalf(rt, "%s: rows=%q want=%q", args, got, want)
		}

		checkUserPages(rt, r, args, names, size)
	})
}

func checkUserPages(rt *rapid.T, r result, args string, names []string, size int) {
	pages := r.answers["/api/headscale/v0/users"]
	if len(pages) == 0 || len(r.asked) != len(pages) {
		fatalf(rt, "%s: %d pages, requests %q", args, len(pages), r.asked)
	}

	var prev *string

	seen := map[string]bool{}

	for i, body := range pages {
		request, ok := strings.CutPrefix(r.asked[i], "GET ")

		u, err := url.ParseRequestURI(request)
		if !ok || err != nil || u.Path != "/api/headscale/v0/users" {
			fatalf(rt, "unexpected request %q", r.asked[i])
		}

		q := u.Query()
		if q.Get("pageSize") != strconv.Itoa(size) ||
			(prev != nil) != q.Has("pageToken") ||
			prev != nil && q.Get("pageToken") != *prev {
			fatalf(rt, "%s page %d: query=%v previous next token=%v", args, i, q, prev)
		}

		var page struct {
			NextPageToken *string
			Users         []struct{ Name string }
		}

		err = json.Unmarshal(body, &page)
		if err != nil || page.Users == nil || len(page.Users) > size {
			fatalf(rt, "page %d: %s", i, body)
		}

		for _, u := range page.Users {
			if seen[u.Name] || !slices.Contains(names, u.Name) {
				fatalf(rt, "page %d: unexpected user %q", i, u.Name)
			}

			seen[u.Name] = true
		}

		prev = page.NextPageToken
		if (prev == nil) != (i == len(pages)-1) || prev != nil && *prev == "" {
			fatalf(rt, "page %d of %d: incorrect next token in %s", i, len(pages), body)
		}
	}

	if len(seen) != len(names) {
		fatalf(rt, "%s: paginated API users=%v", args, seen)
	}
}

// Every published leaf supplies a canonical help page. Alias and flag placement must preserve it.
func TestAllLeafHelpPlacements(t *testing.T) {
	tree := Tree()
	environ := []string{"HOME=" + t.TempDir()}
	run := func(argv []string) string {
		t.Helper()

		var stdout, stderr bytes.Buffer

		code := command.Run(
			tree,
			argv,
			command.Env{Stdout: &stdout, Stderr: &stderr, Environ: environ},
		)
		if code != 0 || stderr.Len() != 0 || stdout.Len() == 0 {
			t.Fatalf("%q: exit=%d stderr=%q", argv, code, stderr.String())
		}

		return stdout.String()
	}
	forms := 0

	cmds := tree.Commands()
	for _, cmd := range cmds {
		words := strings.Fields(cmd.Path)

		want := run(append(slices.Clone(words), "--help"))
		if !strings.Contains(want, "headscale "+cmd.Path) {
			t.Fatalf("%s: canonical usage missing its path", cmd.Path)
		}

		for _, leaf := range append([]string{words[len(words)-1]}, cmd.Aliases...) {
			words[len(words)-1] = leaf
			for _, flag := range []string{"-h", "--help"} {
				for argv := range argtest.Placements(words, []string{flag}) {
					if got := run(argv); got != want {
						t.Fatalf("%q: help differs from %s --help", argv, cmd.Path)
					}

					forms++
				}
			}
		}
	}

	t.Logf("%d commands, %d help placements", len(cmds), forms)
}

type renameAction struct {
	User      int
	Target    string
	Operation string
}

// Bound: a collision is checked up to "belongs to User", not the owner's
// ID.
func TestRapidUserRenames(t *testing.T) {
	action := rapid.Custom(func(rt *rapid.T) renameAction {
		return renameAction{
			User: rapid.IntRange(0, 1).Draw(rt, "user"),
			Target: rapid.SampledFrom([]string{"name", "id", "vacant"}).
				Draw(rt, "target"),
			Operation: rapid.SampledFrom([]string{"rename", "get", "collide"}).
				Draw(rt, "operation"),
		}
	})

	var successfulRenames, reclaimedNames, missingLookups, occupiedNames, idLookups int

	rapid.Check(t, func(rt *rapid.T) {
		suffix := rapid.StringOfN(rapid.RuneFrom([]rune("abcdefghijklmnopqrstuvwxyz0123456789")), 0, 10, 10).
			Draw(rt, "name suffix")
		steps := rapid.SliceOfN(action, 1, 12).Draw(rt, "steps")

		var err error

		t.Run(
			"fixture",
			func(t *testing.T) { err = checkUserRenames(t, suffix, steps) },
		)

		if err != nil {
			fatalf(rt, "%v", err)
		}

		renamed := false

		for _, step := range steps {
			switch {
			case step.Target == "vacant":
				missingLookups++
			case step.Operation == "collide":
				occupiedNames++
			case step.Operation == "rename":
				successfulRenames++

				if renamed {
					reclaimedNames++
				}

				renamed = true
			}

			if step.Target == "id" {
				idLookups++
			}
		}
	})
	t.Logf(
		"model classes successful-renames=%d reclaimed-names=%d absent-targets=%d occupied-names=%d id-targets=%d",
		successfulRenames,
		reclaimedNames,
		missingLookups,
		occupiedNames,
		idLookups,
	)
}

func checkUserRenames(t *testing.T, suffix string, steps []renameAction) error {
	t.Helper()
	f := newFixture(t, false)

	type identity struct{ ID, Name string }

	users := make([]identity, 0, 2)

	for _, prefix := range []string{"first", "second"} {
		name := prefix + suffix
		users = append(
			users,
			identity{
				strconv.FormatUint(uint64(f.srv.CreateUser(t, name).ID), 10),
				name,
			},
		)
	}

	vacant := "next" + suffix

	for i, step := range steps {
		user := users[step.User]
		target := user.Name

		switch step.Target {
		case "id":
			target = user.ID
		case "vacant":
			target = vacant
		}

		line := "users get " + target
		destination := vacant

		if step.Operation != "get" {
			if step.Operation == "collide" {
				destination = users[1-step.User].Name
			}

			line = "users set " + target + " --name " + destination
		}

		got := f.run(t, cliCase{args: line + " -o json"})

		var refusal string

		switch {
		case step.Target == "vacant":
			refusal = fmt.Sprintf("no user matches %q", target)
		case step.Operation == "collide":
			refusal = fmt.Sprintf("the name %q belongs to User", destination)
		case step.Operation == "rename":
			vacant = user.Name
			users[step.User].Name = destination
		}

		if refusal != "" {
			if got.code != 1 || got.stdout != "" ||
				!strings.Contains(got.stderr, refusal) {
				return fmt.Errorf(
					"%w: step %d %s: status=%d stdout=%q stderr=%q, want %q",
					errModelMismatch,
					i,
					line,
					got.code,
					got.stdout,
					got.stderr,
					refusal,
				)
			}
		} else {
			var body identity
			if got.code != 0 || got.stderr != "" ||
				json.Unmarshal([]byte(got.stdout), &body) != nil ||
				body != users[step.User] {
				return fmt.Errorf(
					"%w: step %d %s: status=%d stdout=%q stderr=%q want=%+v",
					errModelMismatch,
					i,
					line,
					got.code,
					got.stdout,
					got.stderr,
					users[step.User],
				)
			}
		}

		list := f.run(t, cliCase{args: "users list --sort id -o json", pageSize: 1})

		var seen []identity
		if list.code != 0 || list.stderr != "" ||
			json.Unmarshal([]byte(list.stdout), &seen) != nil ||
			!slices.Equal(seen, users) {
			return fmt.Errorf(
				"%w: step %d after %s: list=%q stderr=%q want=%v",
				errModelMismatch,
				i,
				line,
				list.stdout,
				list.stderr,
				users,
			)
		}

		var api []identity

		for _, raw := range list.answers[usersPath] {
			var page struct{ Users []identity }

			err := json.Unmarshal(raw, &page)
			if err != nil {
				return err
			}

			api = append(api, page.Users...)
		}

		if !slices.Equal(api, users) {
			return fmt.Errorf(
				"%w: step %d after %s: API=%v want=%v",
				errModelMismatch,
				i,
				line,
				api,
				users,
			)
		}
	}

	return nil
}

// workflowUser keeps just the fields the generated operations can observe.
type workflowUser struct {
	Name        string
	DisplayName string
}

func runUserWorkflow(t *testing.T, actions []int, displays []string) error {
	t.Helper()
	f := newFixture(t, false)

	client, err := clientv0.NewClientWithResponses(
		f.srv.URL,
		clientv0.WithHTTPClient(f.srv.SocketClient()),
	)
	if err != nil {
		return err
	}

	names := []string{"alice", "bob", "carol"}
	state := map[string]string{}
	// Three creates guarantee a second CLI page even when Rapid shrinks the suffix away.
	for _, action := range append([]int{0, 1, 2}, actions...) {
		name := names[action%len(names)]
		op := action / len(names)
		args := "users create " + name + " -o json"
		_, present := state[name]

		refusal := ""
		if !present && op != 0 {
			refusal = fmt.Sprintf("no user matches %q", name)
		}

		tc := cliCase{}

		switch op {
		case 0:
			display := displays[action%len(names)]
			if display != "" {
				args += " --display-name " + strconv.Quote(display)
			}

			if present {
				refusal = fmt.Sprintf("the name %q belongs to User", name)
			} else {
				state[name] = display
			}
		case 1, 2:
			display := ""
			if op == 1 {
				display = "Editor"
			}

			args = "users set " + name + " --display-name=" + display + " -o json"
			if present {
				state[name] = display
			}
		case 3:
			args = "users get " + name + " -o json"
		case 4, 5:
			args = "users delete " + name

			tc.terminal = true
			if op == 4 {
				tc.stdin = "n\n"
			}

			if present {
				refusal = "Aborted.\n"
			}
		case 6:
			args = "users delete " + name + " --force"
			delete(state, name)
		}

		tc.args = args

		r := f.run(t, tc)
		if refusal != "" {
			if r.code != 1 || r.stdout != "" || !strings.Contains(r.stderr, refusal) {
				return fmt.Errorf(
					"%w: %s: code=%d stdout=%q stderr=%q",
					errModelMismatch,
					args,
					r.code,
					r.stdout,
					r.stderr,
				)
			}
		} else if op == 6 {
			if r.code != 0 || r.stderr != "" ||
				!strings.HasSuffix(r.stdout, "("+name+") deleted.\n") {
				return fmt.Errorf(
					"%w: %s: code=%d stdout=%q stderr=%q",
					errModelMismatch,
					args,
					r.code,
					r.stdout,
					r.stderr,
				)
			}
		} else {
			var got workflowUser
			if r.code != 0 || r.stderr != "" ||
				json.Unmarshal([]byte(r.stdout), &got) != nil ||
				got != (workflowUser{name, state[name]}) {
				return fmt.Errorf(
					"%w: %s: code=%d got=%+v stderr=%q, want %s/%q",
					errModelMismatch,
					args,
					r.code,
					got,
					r.stderr,
					name,
					state[name],
				)
			}
		}

		err := checkWorkflowLists(t, f, client, state, args, action, op)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkWorkflowLists(
	t *testing.T,
	f *fixture,
	client *clientv0.ClientWithResponses,
	state map[string]string,
	args string,
	action, op int,
) error {
	t.Helper()

	// A separate unfiltered API read catches writes hidden by CLI selection.
	page, err := client.ListUsersWithResponse(
		t.Context(),
		&clientv0.ListUsersParams{PageSize: new(int64(100))},
	)
	if err != nil {
		return err
	}

	if page.JSON200 == nil || page.JSON200.NextPageToken != nil ||
		len(page.JSON200.Users) != len(state) {
		return fmt.Errorf(
			"%w: after %s: API status=%d, body=%s",
			errModelMismatch,
			args,
			page.StatusCode(),
			page.Body,
		)
	}

	observed := map[string]string{}
	for _, u := range page.JSON200.Users {
		observed[u.Name] = u.DisplayName
	}

	if !maps.Equal(observed, state) {
		return fmt.Errorf(
			"%w: after %s: API=%v want=%v",
			errModelMismatch,
			args,
			observed,
			state,
		)
	}

	order := "name"
	ordered := slices.Sorted(maps.Keys(state))

	if action%2 != 0 {
		order = "-name"

		slices.Reverse(ordered)
	}

	filter := "provider=local"
	if op == 1 {
		filter = "display-name=Editor"
	}

	want := []workflowUser{}

	for _, n := range ordered {
		if op != 1 || state[n] == "Editor" {
			want = append(want, workflowUser{n, state[n]})
		}
	}

	list := f.run(
		t,
		cliCase{
			args:     "users ls --sort " + order + " --filter " + filter + " -o json",
			pageSize: 1,
		},
	)

	// An empty list is [], never null, which would decode to the same nil.
	var got []workflowUser
	if list.code != 0 || list.stderr != "" || !strings.HasPrefix(list.stdout, "[") ||
		json.Unmarshal([]byte(list.stdout), &got) != nil ||
		!slices.Equal(got, want) ||
		len(list.asked) < len(state) {
		return fmt.Errorf(
			"%w: after %s: CLI list code=%d stdout=%q stderr=%q requests=%q want=%v",
			errModelMismatch,
			args,
			list.code,
			list.stdout,
			list.stderr,
			list.asked,
			want,
		)
	}

	return nil
}

// Bound: three users, display names from four values.
func TestRapidUserWorkflow(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		actions := rapid.SliceOfN(rapid.IntRange(0, 20), 0, 8).Draw(rt, "actions")
		displays := rapid.SliceOfN(rapid.SampledFrom([]string{"", "Editor", "Ada Lovelace", "Zoë"}), 3, 3).
			Draw(rt, "initial display names")

		var discrepancy error
		// Scope the server, socket, and DB cleanup to one generated sequence.
		t.Run(
			"fixture",
			func(t *testing.T) { discrepancy = runUserWorkflow(t, actions, displays) },
		)

		if discrepancy != nil {
			fatalf(rt, "%v", discrepancy)
		}
	})
}

// A text can name a user through either field. Releasing it lets the other user claim it.
//
// Bound: a released selector is held to "no user matches", not the quoted
// word.
func TestRapidUserIdentityTransfer(t *testing.T) {
	f := newFixture(t, false)
	starts := [2]string{"alice", "bobby"}
	fields := rapid.SampledFrom([]string{"name", "email"})

	var sameField, crossField int

	rapid.Check(t, func(rt *rapid.T) {
		resetCollectionUsers(rt, f)
		word := "move" + rapid.StringMatching("[a-z0-9]{0,8}").
			Draw(rt, "selector") +
			"@example.org"
		owner := rapid.IntRange(0, 1).Draw(rt, "initial owner")
		claims := rapid.SliceOfN(fields, 2, 5).Draw(rt, "claim fields")
		ids := [2]string{}
		model := [2]profileFields{}

		for i, name := range starts {
			user := f.srv.CreateUser(t, name)
			ids[i] = strconv.FormatUint(uint64(user.ID), 10)
			model[i].Name = name
		}

		run := func(args string) result {
			return f.run(t, cliCase{args: "users " + args + " -o json"})
		}
		check := func(i int, r result) {
			rt.Helper()

			if r.code != 0 || r.stderr != "" ||
				!model[i].matches([]byte(r.stdout), ids[i]) {
				rt.Logf(
					"user %s: want %+v; exit=%d out=%s err=%s",
					ids[i],
					model[i],
					r.code,
					r.stdout,
					r.stderr,
				)
				rt.Fatal("profile reply disagrees with the expected owner")
			}
		}

		for step, field := range claims {
			claim := "--" + field + "=" + word

			if step > 0 {
				next := 1 - owner

				refused := run("set " + ids[next] + " --display-name=blocked " + claim)
				if refused.code != 1 || refused.stdout != "" ||
					!strings.Contains(
						refused.stderr,
						"belongs to User "+ids[owner]+" ",
					) {
					rt.Logf(
						"occupied %s as %s: exit=%d out=%s err=%s",
						word,
						field,
						refused.code,
						refused.stdout,
						refused.stderr,
					)
					rt.Fatal("occupied selector was not refused for its current owner")
				}

				check(next, run("get "+ids[next]))

				previous := claims[step-1]

				value := ""
				if previous == "name" {
					value = starts[owner]
					model[owner].Name = value
				} else {
					model[owner].Email = ""
				}

				check(owner, run("set "+word+" --"+previous+"="+value))

				missing := run("get " + word)
				if missing.code != 1 || missing.stdout != "" ||
					!strings.Contains(missing.stderr, "no user matches") {
					rt.Logf(
						"released %s: exit=%d out=%s err=%s",
						word,
						missing.code,
						missing.stdout,
						missing.stderr,
					)
					rt.Fatal("released selector still resolves")
				}

				if previous == field {
					sameField++
				} else {
					crossField++
				}

				owner = next
			}

			if field == "name" {
				model[owner].Name = word
			} else {
				model[owner].Email = word
			}

			check(owner, run("set "+ids[owner]+" "+claim))
			check(owner, run("get "+word))
		}
	})
	t.Logf(
		"model classes same-field-transfers=%d cross-field-transfers=%d",
		sameField,
		crossField,
	)
}
