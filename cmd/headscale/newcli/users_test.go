package newcli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline/argtest"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestUserListJSONArray(t *testing.T) {
	f := newFixture(t, false)
	check := func(t *testing.T, filter string, want []string) {
		t.Helper()
		rapid.Check(t, func(rt *rapid.T) {
			leaf := rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "command")
			output := rapid.SampledFrom([]string{"-o json", "--output=json"}).Draw(rt, "output")
			sort := rapid.SampledFrom([]string{"name", "-name"}).Draw(rt, "sort")
			size := rapid.IntRange(1, 3).Draw(rt, "page size")
			args := "users " + leaf + " " + output + " --sort " + sort + filter
			r := f.run(t, cliCase{args: args, pageSize: size})

			var rows []struct{ Name string }

			err := json.Unmarshal([]byte(r.stdout), &rows)
			if err != nil || rows == nil || r.stderr != "" || r.code != 0 {
				rt.Fatalf("%s: expected JSON array; stdout=%q stderr=%q exit=%d decode=%v", args, r.stdout, r.stderr, r.code, err)
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
				rt.Fatalf("%s: got %q want %q", args, names, ordered)
			}
		})
	}
	t.Run("empty-store", func(t *testing.T) { check(t, "", nil) })

	for _, name := range []string{"alice", "bob"} {
		f.srv.CreateUser(t, name)
	}

	t.Run("filtered-empty", func(t *testing.T) { check(t, " --filter name=absent", nil) })
	t.Run("nonempty", func(t *testing.T) { check(t, "", []string{"alice", "bob"}) })
}

func TestRapidUserQuery(t *testing.T) {
	f := newFixture(t, false)

	names := []string{"alice", "bob", "carol"}
	for _, name := range names {
		f.srv.CreateUser(t, name)
	}

	rapid.Check(t, func(rt *rapid.T) {
		leaf := rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "leaf")
		output := rapid.SampledFrom([]string{"-o json", "-o=json", "--output=json", "--output json"}).Draw(rt, "global spelling")
		sort := rapid.SampledFrom([]string{"name", "-name"}).Draw(rt, "order")
		match := rapid.SampledFrom([]string{"a", "b", "absent", "e", "o"}).Draw(rt, "substring")
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
		if r.code != 0 || r.stderr != "" || json.Unmarshal([]byte(r.stdout), &rows) != nil || rows == nil {
			rt.Fatalf("%s: code=%d stdout=%q stderr=%q", args, r.code, r.stdout, r.stderr)
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
			rt.Fatalf("%s: rows=%q want=%q", args, got, want)
		}

		checkUserPages(rt, r, args, names, size)
	})
}

func checkUserPages(rt *rapid.T, r result, args string, names []string, size int) {
	pages := r.answers["/api/headscale/v0/users"]
	if len(pages) == 0 || len(r.asked) != len(pages) {
		rt.Fatalf("%s: %d pages, requests %q", args, len(pages), r.asked)
	}

	var prev *string

	seen := map[string]bool{}

	for i, body := range pages {
		request, ok := strings.CutPrefix(r.asked[i], "GET ")

		u, err := url.ParseRequestURI(request)
		if !ok || err != nil || u.Path != "/api/headscale/v0/users" {
			rt.Fatalf("unexpected request %q", r.asked[i])
		}

		q := u.Query()
		if q.Get("pageSize") != strconv.Itoa(size) || (prev != nil) != q.Has("pageToken") || prev != nil && q.Get("pageToken") != *prev {
			rt.Fatalf("%s page %d: query=%v previous next token=%v", args, i, q, prev)
		}

		var page struct {
			NextPageToken *string
			Users         []struct{ Name string }
		}

		err = json.Unmarshal(body, &page)
		if err != nil || page.Users == nil || len(page.Users) > size {
			rt.Fatalf("page %d: %s", i, body)
		}

		for _, u := range page.Users {
			if seen[u.Name] || !slices.Contains(names, u.Name) {
				rt.Fatalf("page %d: unexpected user %q", i, u.Name)
			}

			seen[u.Name] = true
		}

		prev = page.NextPageToken
		if (prev == nil) != (i == len(pages)-1) || prev != nil && *prev == "" {
			rt.Fatalf("page %d of %d: incorrect next token in %s", i, len(pages), body)
		}
	}

	if len(seen) != len(names) {
		rt.Fatalf("%s: paginated API users=%v", args, seen)
	}
}

// Every published leaf supplies a canonical help page. Alias and flag placement must preserve it.
func TestAllLeafHelpPlacements(t *testing.T) {
	tree := Tree()
	environ := []string{"HOME=" + t.TempDir()}
	run := func(argv []string) string {
		t.Helper()

		var stdout, stderr bytes.Buffer

		code := command.Run(tree, argv, command.Env{Stdout: &stdout, Stderr: &stderr, Environ: environ})
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

func TestRapidUserRenames(t *testing.T) {
	action := rapid.Custom(func(rt *rapid.T) renameAction {
		return renameAction{
			User:      rapid.IntRange(0, 1).Draw(rt, "user"),
			Target:    rapid.SampledFrom([]string{"name", "id", "vacant"}).Draw(rt, "target"),
			Operation: rapid.SampledFrom([]string{"rename", "get", "collide"}).Draw(rt, "operation"),
		}
	})

	var successfulRenames, reclaimedNames, missingLookups, occupiedNames, idLookups int

	rapid.Check(t, func(rt *rapid.T) {
		suffix := rapid.StringOfN(rapid.RuneFrom([]rune("abcdefghijklmnopqrstuvwxyz0123456789")), 0, 10, 10).Draw(rt, "name suffix")
		steps := rapid.SliceOfN(action, 1, 12).Draw(rt, "steps")

		var err error

		t.Run("fixture", func(t *testing.T) { err = checkUserRenames(t, suffix, steps) })

		if err != nil {
			rt.Fatal(err)
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
	t.Logf("model classes successful-renames=%d reclaimed-names=%d absent-targets=%d occupied-names=%d id-targets=%d",
		successfulRenames, reclaimedNames, missingLookups, occupiedNames, idLookups)
}

func checkUserRenames(t *testing.T, suffix string, steps []renameAction) error {
	t.Helper()
	f := newFixture(t, false)

	type identity struct{ ID, Name string }

	users := make([]identity, 0, 2)

	for _, prefix := range []string{"first", "second"} {
		name := prefix + suffix
		users = append(users, identity{strconv.FormatUint(uint64(f.srv.CreateUser(t, name).ID), 10), name})
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
			if got.code != 1 || got.stdout != "" || !strings.Contains(got.stderr, refusal) {
				return fmt.Errorf("%w: step %d %s: status=%d stdout=%q stderr=%q, want %q", errModelMismatch, i, line, got.code, got.stdout, got.stderr, refusal)
			}
		} else {
			var body identity
			if got.code != 0 || got.stderr != "" || json.Unmarshal([]byte(got.stdout), &body) != nil || body != users[step.User] {
				return fmt.Errorf("%w: step %d %s: status=%d stdout=%q stderr=%q want=%+v", errModelMismatch, i, line, got.code, got.stdout, got.stderr, users[step.User])
			}
		}

		list := f.run(t, cliCase{args: "users list --sort id -o json", pageSize: 1})

		var seen []identity
		if list.code != 0 || list.stderr != "" || json.Unmarshal([]byte(list.stdout), &seen) != nil || !slices.Equal(seen, users) {
			return fmt.Errorf("%w: step %d after %s: list=%q stderr=%q want=%v", errModelMismatch, i, line, list.stdout, list.stderr, users)
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
			return fmt.Errorf("%w: step %d after %s: API=%v want=%v", errModelMismatch, i, line, api, users)
		}
	}

	return nil
}

// people are the users of the proposal's examples, with their IDs: alice
// owns three nodes, bob nothing, carol comes from OIDC, and two users are
// named debtquity, one local and one from OIDC. Five users are three pages
// of the fixture's walk.
func people(tb testing.TB, f *fixture) {
	tb.Helper()

	day := 24 * time.Hour

	for _, u := range []types.User{
		{ID: 3, CreatedAt: f.now.Add(-100 * day), Name: "alice", DisplayName: "Alice"},
		{ID: 4, CreatedAt: f.now.Add(-40 * day), Name: "bob"},
		{
			ID: 5, CreatedAt: f.now.Add(-10 * day), Name: "carol", DisplayName: "Carol C", Email: "carol@example.com",
			Provider: "oidc", ProviderIdentifier: sql.NullString{String: "https://idp.example.com/carol", Valid: true},
		},
		{ID: 8, CreatedAt: f.now.Add(-2 * day), Name: "debtquity"},
		{
			ID: 9, CreatedAt: f.now.Add(-time.Hour), Name: "debtquity", Email: "d@example.com",
			Provider: "oidc", ProviderIdentifier: sql.NullString{String: "https://idp.example.com/d", Valid: true},
		},
	} {
		_, _, err := f.srv.State().CreateUser(u)
		require.NoError(tb, err)
	}

	alice, err := f.srv.State().GetUserByID(3)
	require.NoError(tb, err)

	for _, name := range []string{"mynode", "laptop", "phone"} {
		f.srv.CreateRegisteredNode(tb, alice, name)
	}
}

// userOf reads a user back from the server.
func userOf(tb testing.TB, f *fixture, id types.UserID) *types.User {
	tb.Helper()

	u, err := f.srv.State().GetUserByID(id)
	require.NoError(tb, err)

	return u
}

// usersPath is the list of users, and the path of a user under it.
const usersPath = "/api/headscale/v0/users"

var users = listAt{usersPath, "users"}

// only keeps the rows whose field is value.
func only(field, value string) func(map[string]any) bool {
	return func(row map[string]any) bool { return row[field] == value }
}

func all(map[string]any) bool { return true }

const usersTable = `ID  NAME       DISPLAY NAME  EMAIL              PROVIDER  COUNT  NODES
3   alice      Alice         -                  local     3      mynode, laptop, phone
4   bob        -             -                  local     0
5   carol      Carol C       carol@example.com  oidc      0
8   debtquity  -             -                  local     0
9   debtquity  -             d@example.com      oidc      0
`

var usersListCases = []cliCase{
	{
		name: "the table", args: "users list", stdout: usersTable,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Equal(tb, []string{
				"GET /api/headscale/v0/users?pageSize=2",
				"GET /api/headscale/v0/users?pageSize=2&pageToken=" + strings.TrimPrefix(r.asked[1], "GET /api/headscale/v0/users?pageSize=2&pageToken="),
				"GET /api/headscale/v0/users?pageSize=2&pageToken=" + strings.TrimPrefix(r.asked[2], "GET /api/headscale/v0/users?pageSize=2&pageToken="),
			}, r.asked, "three pages of two")
			require.NotEqual(tb, r.asked[1], r.asked[2])
		},
	},
	{name: "ls is list", args: "users ls", stdout: usersTable},
	{
		name: "the CLI's own page is the most v0 gives", args: "users list", pageSize: cliPages, stdout: usersTable,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Equal(tb, []string{"GET /api/headscale/v0/users?pageSize=1000"}, r.asked, "one call for up to 1000 rows")
		},
	},
	{
		name: "a credential that may not read users", args: "users list",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "devices:core:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope users:read.\n", code: 1,
	},
	{name: "-o json is every page's rows as they came", args: "users list -o json", want: users.rows(all)},
	{
		name: "a filter and a reverse sort", args: "users list --filter provider=oidc --sort -count",
		stdout: "ID  NAME       DISPLAY NAME  EMAIL              PROVIDER  COUNT  NODES\n" +
			"5   carol      Carol C       carol@example.com  oidc      0\n" +
			"9   debtquity  -             d@example.com      oidc      0\n",
	},
	{
		name: "columns added and taken away", args: "users ls --columns +login-name,-nodes",
		stdout: `ID  NAME       DISPLAY NAME  EMAIL              PROVIDER  COUNT  LOGIN NAME
3   alice      Alice         -                  local     3      alice
4   bob        -             -                  local     0      bob
5   carol      Carol C       carol@example.com  oidc      0      carol@example.com
8   debtquity  -             -                  local     0      debtquity
9   debtquity  -             d@example.com      oidc      0      d@example.com
`,
	},
	{name: "only these columns", args: "users list --columns name,id,created", stdout: "NAME       ID  CREATED\nalice      3   100d ago\nbob        4   40d ago\ncarol      5   10d ago\ndebtquity  8   2d ago\ndebtquity  9   1h ago\n"},
	{
		name: "a filter applies to JSON", args: "users list --filter email=carol@example.com -o json",
		want: users.rows(only("email", "carol@example.com")),
	},
	{name: "sort applies to JSON", args: "users list --sort -id --filter id>4 -o json", want: func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		out := make([]json.RawMessage, 0, 3)
		for _, id := range []string{"9", "8", "5"} {
			out = append(out, users.kept(tb, r, only("id", id))...)
		}

		b, err := json.Marshal(out)
		require.NoError(tb, err)

		return indent(tb, b)
	}},

	// Each rule of --filter on a users column, by kind.
	{name: "id =", args: "users list --filter id=4 --columns id", stdout: "ID\n4\n"},
	{name: "id <", args: "users list --filter id<5 --columns id", stdout: "ID\n3\n4\n"},
	{name: "id >", args: "users list --filter id>5 --columns id", stdout: "ID\n8\n9\n"},
	{name: "id compares as a number", args: "users list --filter id>10 --columns id", stdout: "ID\n"},
	{name: "text =", args: "users list --filter name=debtquity --columns id", stdout: "ID\n8\n9\n"},
	{name: "text = is exact", args: "users list --filter name=debt --columns id", stdout: "ID\n"},
	{name: "text :", args: "users list --filter name:o --columns id", stdout: "ID\n4\n5\n"},
	{name: "text = with no value finds an empty field", args: "users list --filter email= --columns id", stdout: "ID\n3\n4\n8\n"},
	{name: "number =", args: "users list --filter count=3 --columns id", stdout: "ID\n3\n"},
	{name: "number >", args: "users list --filter count>0 --columns id", stdout: "ID\n3\n"},
	{name: "number <", args: "users list --filter count<1 --columns id", stdout: "ID\n4\n5\n8\n9\n"},
	{name: "list = is one entry", args: "users list --filter nodes=laptop --columns id", stdout: "ID\n3\n"},
	{name: "list : is in one entry", args: "users list --filter nodes:top --columns id", stdout: "ID\n3\n"},
	{name: "time < a duration is newer", args: "users list --filter created<30d --columns id", stdout: "ID\n5\n8\n9\n"},
	{name: "time > a duration is older", args: "users list --filter created>30d --columns id", stdout: "ID\n3\n4\n"},
	{name: "time against a date", args: "users list --filter created<{twentyDaysAgo} --columns id", stdout: "ID\n3\n4\n"},
	{name: "time = never finds no time", args: "users list --filter created=never --columns id", stdout: "ID\n"},
	{name: "filters joined with commas all match", args: "users list --filter provider=local,count<1 --columns id", stdout: "ID\n4\n8\n"},
	{name: "a repeated filter all match", args: "users list --filter provider=local --filter name:e --columns id", stdout: "ID\n3\n8\n"},
	{name: "a sort by text", args: "users list --sort name --columns id,name", stdout: "ID  NAME\n3   alice\n4   bob\n5   carol\n8   debtquity\n9   debtquity\n"},
	{name: "a sort by time", args: "users list --sort created --columns id", stdout: "ID\n3\n4\n5\n8\n9\n"},
	{name: "a sort by a list", args: "users list --sort -nodes --columns id", stdout: "ID\n3\n4\n5\n8\n9\n"},

	// Nothing that matches.
	{name: "no rows in a pipe is the header", args: "users list --filter name=nobody", stdout: "ID  NAME  DISPLAY NAME  EMAIL  PROVIDER  COUNT  NODES\n"},
	{name: "no rows on a terminal", args: "users list --filter name=nobody", terminal: true, stdout: "No users.\n"},
	{name: "no rows in JSON", args: "users list --filter name=nobody -o json", stdout: "[]\n"},

	// What the line gets wrong, before any call.
	{
		name: "an unknown column", args: "users list --columns id,nam",
		stderr: "Error: unknown column \"nam\". Did you mean \"name\"?\nRun `headscale users list --list-columns`.\n", code: 1,
	},
	{
		name: "an unknown filter column", args: "users list --filter colour=red",
		stderr: "Error: unknown column \"colour\".\nRun `headscale users list --list-columns`.\n", code: 1,
	},
	{name: "an operator the kind does not take", args: "users list --filter count:3", stderr: "Error: column \"count\" is a number. It works with =, < and > only.\n", code: 1},
	{name: "a time that does not read", args: "users list --filter created>soon", stderr: "Error: column \"created\" takes a duration such as 30d, or a date such as 2026-01-01, not \"soon\".\n", code: 1},
	{name: "a mixed --columns", args: "users list --columns id,+email", stderr: "Error: --columns takes a plain list, or only + and - entries. Not both.\n", code: 1},
	{
		name: "--columns with JSON", args: "users list --columns id,count -o json",
		stderr: "Error: --columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {id, nodeCount}'\n", code: 1,
	},
	{name: "an empty --filter", args: "users list --filter=", stderr: "Error: the filter list is empty.\n", code: 1},
	{name: "contains with no value", args: "users list --filter email:", stderr: "Error: the filter \"email:\" has no value.\n", code: 1},
	{name: "no >=", args: "users list --filter count>=1", stderr: "Error: \"count>=1\": there is no >=. The operators are =, :, < and >.\n", code: 1},
	{name: "a column twice", args: "users list --columns id,name,id", stderr: "Error: --columns names \"id\" twice.\n", code: 1},
	{name: "a sort by an unknown column", args: "users list --sort -cnt", stderr: "Error: unknown column \"cnt\". Did you mean \"count\"?\nRun `headscale users list --list-columns`.\n", code: 1},
	{name: "two sorts", args: "users list --sort id --sort name", stderr: "Error: --sort is given twice. Only --filter may be repeated.\n", code: 1},

	{
		name: "the columns", args: "users list --list-columns",
		stdout: `COLUMN           FIELD          KIND    DEFAULT  DESCRIPTION
id               id             id      yes      User ID
name             name           text    yes      Username; empty for some users from OIDC
display-name     displayName    text    yes      Display name
email            email          text    yes      Email address
provider         provider       text    yes      Where the user comes from: local or oidc
count            nodeCount      number  yes      Nodes the user owns, tagged nodes not counted
nodes            nodes          list    yes      Names of the nodes the user owns
login-name       loginName      text    no       What headscale shows for the user: the email, else the username, else the provider identifier
profile-pic-url  profilePicUrl  text    no       URL of the profile picture
provider-id      providerId     text    no       Identifier at the identity provider
created          created        time    no       When the user was created
`,
	},
	{
		name: "the columns as JSON, from no server", args: "users list --list-columns -o json",
		want: func(tb testing.TB, _ *fixture, _ result) string {
			tb.Helper()

			b, err := json.Marshal(userColumns.Info())
			require.NoError(tb, err)

			return indent(tb, b)
		},
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(tb, r.stdout, `"Field": "nodeCount"`, "the keys are Go field names")
			require.Empty(tb, r.asked)
		},
	},
}

func TestUsersList(t *testing.T) {
	t.Parallel()

	runCases(t, func(tb testing.TB, f *fixture) {
		tb.Helper()
		people(tb, f)
		f.vars["twentyDaysAgo"] = f.now.Add(-20 * 24 * time.Hour).Format(time.DateOnly)
	}, usersListCases)
}

var usersGetCases = []cliCase{
	{
		name: "text of the server cannot drive the terminal", setup: escapes, args: "users get alice --output json",
		// JSON escapes a control below 0x20 itself; the CLI writes the
		// others as \uXXXX too, and every value stays the same.
		want: func(tb testing.TB, f *fixture, r result) string {
			tb.Helper()

			return string(table.VisibleJSON([]byte(users.row(only("id", "3"))(tb, f, r))))
		},
		check: func(tb testing.TB, f *fixture, r result) {
			tb.Helper()
			require.Contains(tb, r.stdout, `"displayName": "Alice\u001b[2J\u202e\\x1b\u0085"`)

			var u clientv0.User
			require.NoError(tb, json.Unmarshal([]byte(r.stdout), &u))
			require.Equal(tb, "Alice\x1b[2J\u202e\\x1b\u0085", u.DisplayName)

			r = f.run(tb, cliCase{args: "users get alice"})
			require.Contains(tb, r.stdout, `Display name:     Alice\x1b[2J\u202e\\x1b\x85`+"\n")
		},
	},
	{name: "an empty word is no user", args: "users get ''", stderr: "Error: an empty word names no user.\n", code: 1, check: noCall},
	{
		name: "a word that is one user's provider identifier and another's name", setup: namedLikeProviderID, args: "users get https://idp.example.com/d",
		stderr: `Error: "https://idp.example.com/d" matches 2 users. Use the ID to select one:

  ID  NAME                       EMAIL          PROVIDER  PROVIDER ID
  9   debtquity                  d@example.com  oidc      https://idp.example.com/d
  12  https://idp.example.com/d  -              local     -
`, code: 1,
	},
	{name: "by username", args: "users get alice", stdout: `ID:               3
Name:             alice
Display name:     Alice
Email:            -
Provider:         local
Count:            3
Nodes:            mynode, laptop, phone
Login name:       alice
Profile pic URL:  -
Provider ID:      -
Created:          100d ago ({aliceCreated})
`},
	{name: "by email, as JSON", args: "users get carol@example.com -o json", want: users.row(only("id", "5"))},
	{name: "by ID", args: "users get 4 --output json", want: users.row(only("id", "4"))},
	{name: "by provider identifier", args: "users get https://idp.example.com/d -o json", want: users.row(only("id", "9"))},
	{name: "an ID wins over a name", setup: namedLikeID, args: "users get 3 -o json", want: users.row(only("id", "3"))},
	{name: "a name that is no ID", setup: namedLikeID, args: "users get 33 -o json", want: users.row(only("id", "11"))},
	{
		name: "a word for two users lists them", args: "users get debtquity",
		stderr: `Error: "debtquity" matches 2 users. Use the ID to select one:

  ID  NAME       EMAIL          PROVIDER
  8   debtquity  -              local
  9   debtquity  d@example.com  oidc
`, code: 1,
	},
	{name: "no user", args: "users get nope", stderr: "Error: no user matches \"nope\".\n", code: 1},
	{name: "a match is exact", args: "users get alic", stderr: "Error: no user matches \"alic\".\n", code: 1},
	{name: "a word after -- is the user", args: "users get -- -x", stderr: "Error: no user matches \"-x\".\n", code: 1},
	{name: "one user", args: "users get alice bob", stderr: "Error: `users get` needs 1 argument, got 2.\n\n  headscale users get <user>\n", code: 1},
	{name: "a get has no list flags", args: "users get alice --columns id", stderr: "Error: --columns does not apply to `users get`.\nRun `headscale users get --help`.\n", code: 1},
	{name: "the old name points here", args: "user get alice", stderr: "Error: unknown command \"user\". It is now \"users\".\nRun `headscale users --help`.\n", code: 1},
}

// escapes gives alice a display name with a terminal escape, a
// right-to-left override, the text of an escape and a C1 control.
func escapes(tb testing.TB, f *fixture) {
	tb.Helper()

	_, _, err := f.srv.State().UpdateUser(3, func(u *types.User) error {
		u.DisplayName = "Alice\x1b[2J\u202e\\x1b\u0085"

		return nil
	})
	require.NoError(tb, err)
}

// forged is a user from OIDC whose login name ends a line and writes one
// of its own: the identity provider, not the admin, chose it.
func forged(tb testing.TB, f *fixture) {
	tb.Helper()

	for _, u := range []types.User{
		{ID: 23, Name: "x\x1b[31mred\nfake line", Provider: "oidc", ProviderIdentifier: sql.NullString{String: "https://idp.example.com/x", Valid: true}},
		// A local user cannot get such a name through the API; a v1 write
		// or an old row can hold one.
		{ID: 24, Name: "y\nfake line"},
	} {
		_, _, err := f.srv.State().CreateUser(u)
		require.NoError(tb, err)
	}
}

// namedLikeProviderID adds a user whose name is the provider
// identifier of user 9.
func namedLikeProviderID(tb testing.TB, f *fixture) {
	tb.Helper()

	_, _, err := f.srv.State().CreateUser(types.User{ID: 12, Name: "https://idp.example.com/d"})
	require.NoError(tb, err)
}

// noCall holds that a case asked nothing of the server.
func noCall(tb testing.TB, _ *fixture, r result) {
	tb.Helper()
	require.Empty(tb, r.asked, "nothing is asked of the server")
}

// namedLikeID adds a user whose name is the ID of another, and one whose
// name is a number no ID has.
func namedLikeID(tb testing.TB, f *fixture) {
	tb.Helper()

	for id, name := range map[uint]string{10: "3", 11: "33"} {
		_, _, err := f.srv.State().CreateUser(types.User{ID: id, Name: name})
		require.NoError(tb, err)
	}
}

func TestUsersGet(t *testing.T) {
	t.Parallel()

	runCases(t, func(tb testing.TB, f *fixture) {
		tb.Helper()
		people(tb, f)
		f.vars["aliceCreated"] = f.now.Add(-100 * 24 * time.Hour).Format("2006-01-02 15:04 UTC")
	}, usersGetCases)
}

var usersCreateCases = []cliCase{
	{
		name: "a username", args: "users create dave", stdout: "User 1 (dave) created.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, "dave", userOf(tb, f, 1).Name)
		},
	},
	{
		name: "every field", args: `users create dave --display-name "Dave D" --email dave@example.com`,
		stdout: "User 1 (dave@example.com) created.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			u := userOf(tb, f, 1)
			require.Equal(tb, []string{"dave", "Dave D", "dave@example.com"}, []string{u.Name, u.DisplayName, u.Email})
		},
	},
	{
		name: "a picture", args: "users create dave --picture-url https://example.com/d.png",
		stdout: "User 1 (dave) created.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, "https://example.com/d.png", userOf(tb, f, 1).ProfilePicURL)
		},
	},
	{name: "-o json is the new user", args: "users create dave -o json", want: answer(usersPath)},
	{
		name: "a name another local user has", setup: people, args: "users create alice",
		stderr: "Error: the name \"alice\" belongs to User 3 (alice).\n", code: 1,
	},
	{
		name: "the name of a user from OIDC", setup: people, args: "users create carol",
		stderr: "Error: the name \"carol\" belongs to User 5 (carol@example.com).\n", code: 1,
	},
	{
		name: "a name that is the email of another user", setup: people, args: "users create d@example.com",
		stderr: "Error: the name \"d@example.com\" belongs to User 9 (d@example.com).\n", code: 1,
	},
	{
		name: "an email another user has", setup: people, args: "users create dave --email Carol@example.com",
		stderr: "Error: the email \"Carol@example.com\" belongs to User 5 (carol@example.com).\n", code: 1,
	},
	{
		name: "values the server refuses", args: "users create 'bad name' --email x --picture-url javascript:alert(1)",
		stderr: "Error: the server refused a value:\n" +
			"  --email: is not one email address\n" +
			"  <name>: is not a valid username: at least 2 characters, starting with a letter, of letters, digits, '-', '.', '_' and at most one '@'\n" +
			"  --picture-url: is not an absolute http or https URL with a host and no user info\n",
		code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			_, err := f.srv.State().GetUserByID(1)
			require.Error(tb, err, "nothing is created")
		},
	},
	{name: "a name is needed", args: "users create", stderr: "Error: `users create` needs 1 argument, got 0.\n\n  headscale users create <name>\n", code: 1},
}

func TestUsersCreate(t *testing.T) {
	t.Parallel()

	runCases(t, nil, usersCreateCases)
}

var usersSetCases = []cliCase{
	{
		name: "two fields", args: `users set alice --display-name "Alice A" --email a@b.c`,
		stdout: "User 3 (a@b.c) updated: display name, email.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			u := userOf(tb, f, 3)
			require.Equal(tb, []string{"alice", "Alice A", "a@b.c"}, []string{u.Name, u.DisplayName, u.Email})
		},
	},
	{
		name: "the username", args: "users set alice --name alice2", stdout: "User 3 (alice2) updated: name.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, "alice2", userOf(tb, f, 3).Name)
		},
	},
	{
		name: "by ID", args: "users set 3 --name alice2 --email a@b.c", stdout: "User 3 (a@b.c) updated: name, email.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			u := userOf(tb, f, 3)
			require.Equal(tb, []string{"alice2", "a@b.c"}, []string{u.Name, u.Email})
		},
	},
	{
		name: "an empty value clears", setup: picture, args: `users set alice --picture-url ""`, stdout: "User 3 (alice) updated: picture URL.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			u := userOf(tb, f, 3)
			require.Empty(tb, u.ProfilePicURL)
			require.Equal(tb, "Alice", u.DisplayName, "a flag not given leaves its field")
		},
	},
	{name: "-o json is the user after the change", args: "users set alice --email a@b.c -o json", want: answer(usersPath + "/3")},
	{
		name: "no flag", args: "users set alice",
		stderr: "Error: nothing to change. Give at least one of\n  --name, --display-name, --email, --picture-url\n", code: 1,
		check: noCall,
	},
	{
		name: "a user from OIDC is refused", args: "users set carol --display-name Carol",
		stderr: "Error: User 5 (carol@example.com) is managed by OIDC and cannot be edited here.\n", code: 1,
	},
	{name: "a name that is taken", args: "users set alice --name bob", stderr: "Error: the name \"bob\" belongs to User 4 (bob).\n", code: 1},
	{
		name: "an email that is taken", args: "users set bob --email carol@example.com",
		stderr: "Error: the email \"carol@example.com\" belongs to User 5 (carol@example.com).\n", code: 1,
	},
	{
		name: "a token may not change the name", setup: usersToken, args: "users set alice --name alice2",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nAn OAuth access token cannot change the name or the email of a user; an API key can.\n", code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(tb, "alice", userOf(tb, f, 3).Name)
		},
	},
	{
		name: "a token may change the display name", setup: usersToken, args: "users set alice --display-name A",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stdout: "User 3 (alice) updated: display name.\n",
	},
	{
		name: "a user needs a name", args: "users set alice --name '' --email a@b.c",
		stderr: "Error: the server refused a value:\n" +
			"  --name: is not a valid username: at least 2 characters, starting with a letter, of letters, digits, '-', '.', '_' and at most one '@'\n",
		code: 1,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Empty(tb, userOf(tb, f, 3).Email, "all or nothing")
		},
	},
	{name: "a user that is not there", args: "users set nope --name x", stderr: "Error: no user matches \"nope\".\n", code: 1},
	{
		name: "a line break of the server cannot forge a line", setup: forged, args: "users set 23 --display-name x",
		stderr: `Error: User 23 (x\x1b[31mred\x0afake line) is managed by OIDC and cannot be edited here.` + "\n", code: 1,
	},
	{
		name: "a line break of the server cannot forge a line of a Done", setup: forged, args: "users set 24 --display-name x",
		stdout: `User 24 (y\x0afake line) updated: display name.` + "\n",
	},
}

// usersToken is an access token of an OAuth client with the scope users.
func usersToken(tb testing.TB, f *fixture) {
	tb.Helper()
	f.vars["token"] = f.token(tb, "users")
}

// picture gives alice a picture to clear.
func picture(tb testing.TB, f *fixture) {
	tb.Helper()

	_, _, err := f.srv.State().UpdateUser(3, func(u *types.User) error {
		u.ProfilePicURL = "https://example.com/a.png"

		return nil
	})
	require.NoError(tb, err)
}

func TestUsersSet(t *testing.T) {
	t.Parallel()

	runCases(t, people, usersSetCases)
}

// keyed is people with keys: bob (4) two auth keys and an API key, which
// the case may call with (its secret in the var bobkey), alice (3) two
// auth keys beside her three nodes.
func keyed(tb testing.TB, f *fixture) {
	tb.Helper()

	people(tb, f)

	for _, n := range f.srv.State().ListNodes().All() {
		keyless(tb, f, n)
	}

	st := f.srv.State()
	expiry := f.now.Add(24 * time.Hour)

	for _, id := range []types.UserID{4, 4, 3, 3} {
		_, err := st.CreatePreAuthKey(&id, false, false, &expiry, nil)
		require.NoError(tb, err)
	}

	bob := types.UserID(4)
	_, secret, err := st.CreateAPIKeyFrom(db.NewAPIKey{Owner: &bob, Expiration: &expiry})
	require.NoError(tb, err)

	f.vars["bobkey"] = secret
}

// keyless takes from node n the auth key the test server made for it, so
// alice's keys are only those a case gives her, as in the proposal.
func keyless(tb testing.TB, f *fixture, n types.NodeView) {
	tb.Helper()

	id, ok := n.AuthKeyID().GetOk()
	if !ok {
		return
	}

	db := f.srv.State().DB().DB
	require.NoError(tb, db.Exec("UPDATE nodes SET auth_key_id = NULL WHERE id = ?", n.ID()).Error)
	require.NoError(tb, db.Exec("DELETE FROM credentials WHERE id = ?", id).Error)
}

// gone holds that the user is gone, with every node it owned.
func gone(id types.UserID, nodes ...string) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()

		_, err := f.srv.State().GetUserByID(id)
		require.Error(tb, err, "the user is gone")

		for _, n := range f.srv.State().ListNodes().All() {
			require.NotContains(tb, nodes, n.Hostname(), "a node of the user is left")
		}
	}
}

// kept holds that the user is there, with nodes nodes.
func kept(id types.UserID, nodes int) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()

		userOf(tb, f, id)

		n := 0

		for _, v := range f.srv.State().ListNodes().All() {
			if v.UserID().Valid() && types.UserID(v.UserID().Get()) == id && !v.IsTagged() {
				n++
			}
		}

		require.Equal(tb, nodes, n, "nothing is removed")
	}
}

// deletes are the deletes of user id the CLI sent, and the token of every
// dry run in the order answered: a delete must send the token of the dry
// run just before it.
func deletes(tb testing.TB, r result, id string) ([]string, []string) {
	tb.Helper()

	var sent []string

	tokens := make([]string, 0, len(r.answers[usersPath+"/"+id]))

	for _, a := range r.asked {
		if strings.HasPrefix(a, "DELETE "+usersPath+"/"+id+"?") {
			sent = append(sent, strings.TrimPrefix(a, "DELETE "+usersPath+"/"+id))
		}
	}

	for _, body := range r.answers[usersPath+"/"+id] {
		var d clientv0.DeletedUser
		require.NoError(tb, json.Unmarshal(body, &d))

		tokens = append(tokens, d.Expect)
	}

	return sent, tokens
}

// pinned holds the requests of a delete: for each round, a dry run, then
// the delete with the token of that dry run; rounds is how many.
func pinned(id, withNodes string, rounds int) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, _ *fixture, r result) {
		tb.Helper()

		sent, tokens := deletes(tb, r, id)

		want := make([]string, 0, 2*rounds)

		for i := range rounds {
			want = append(want, "?withNodes="+withNodes+"&dryRun=true", "?withNodes="+withNodes+"&dryRun=false&expect="+tokens[2*i])
		}

		require.Equal(tb, want, sent)

		if rounds > 1 {
			require.NotEqual(tb, tokens[0], tokens[2], "a new token after the refusal")
		}
	}
}

// both runs every check.
func both(checks ...func(testing.TB, *fixture, result)) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, r result) {
		tb.Helper()

		for _, c := range checks {
			c(tb, f, r)
		}
	}
}

// registers gives alice a new node after each of the first times dry runs
// of her delete: what the question showed is then no longer true.
func registers(times int) func(testing.TB, *fixture, string) {
	return func(tb testing.TB, f *fixture, req string) {
		tb.Helper()

		if !strings.HasPrefix(req, "DELETE "+usersPath+"/3?") || !strings.Contains(req, "dryRun=true") || f.changes >= times {
			return
		}

		f.changes++

		keyless(tb, f, f.srv.CreateRegisteredNode(tb, userOf(tb, f, 3), []string{"tablet", "watch"}[f.changes-1]))
	}
}

var crowdNames = func() []string {
	names := make([]string, 20)
	for i := range names {
		names[i] = fmt.Sprintf("crowd%02d", i+1)
	}

	return names
}()

// crowd gives alice the twenty nodes of crowdNames more, put in the node
// store at once so that the setup waits one batch, not twenty; the time
// it is done is the var since.
func crowd(tb testing.TB, f *fixture) {
	tb.Helper()

	st := f.srv.State()
	alice := userOf(tb, f, 3)

	nodes := make([]types.NodeView, len(crowdNames))

	var wg sync.WaitGroup

	for i, name := range crowdNames {
		n := st.CreateRegisteredNodeForTest(alice, name)
		n.User = alice

		wg.Go(func() { nodes[i] = st.PutNodeInStoreForTest(*n) })
	}

	wg.Wait()

	for _, n := range nodes {
		keyless(tb, f, n)
	}

	f.vars["since"] = time.Now().Format(time.RFC3339Nano)
}

const aliceQuestion = "Delete User 3 (alice), 3 nodes and 2 auth keys?\n  mynode, laptop, phone\n[y/N] "

var usersDeleteCases = []cliCase{
	// The proposal's examples, word for word.
	{
		name: "a user with keys and no nodes", args: "users delete bob", terminal: true, stdin: "y\n",
		stderr: "Delete User 4 (bob), 2 auth keys and 1 API key? [y/N] ",
		stdout: "User 4 (bob) deleted with 2 auth keys and 1 API key.\n",
		check:  both(gone(4), pinned("4", "false", 1)),
	},
	{
		name: "a user with nodes and no --with-nodes", args: "users delete alice",
		stderr: "Error: User 3 (alice) still owns 3 nodes: mynode, laptop, phone.\nDelete or tag them first, or delete them together:\n  headscale users delete alice --with-nodes\n", code: 1,
		check: both(kept(3, 3), func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()

			sent, _ := deletes(tb, r, "3")
			require.Equal(tb, []string{"?withNodes=false&dryRun=true"}, sent, "the dry run is refused, nothing more is sent")
		}),
	},
	{
		name: "the line to delete the nodes too names the user as typed", args: "users delete 3",
		stderr: "Error: User 3 (alice) still owns 3 nodes: mynode, laptop, phone.\nDelete or tag them first, or delete them together:\n  headscale users delete 3 --with-nodes\n", code: 1,
		check: kept(3, 3),
	},
	{
		name: "--with-nodes", args: "users delete alice --with-nodes", terminal: true, stdin: "y\n",
		stderr: aliceQuestion, stdout: "User 3 (alice) deleted with 3 nodes and 2 auth keys.\n",
		check: both(gone(3, "mynode", "laptop", "phone"), pinned("3", "true", 1)),
	},
	{
		name: "--force asks nothing", args: "users delete alice --with-nodes --force",
		stdout: "User 3 (alice) deleted with 3 nodes and 2 auth keys.\n",
		check:  both(gone(3, "mynode", "laptop", "phone"), pinned("3", "true", 1)),
	},
	{
		name: "many nodes, at the server's own batch wait, inside the CLI's default timeout", args: "users delete alice --with-nodes --force",
		server: []servertest.ServerOption{servertest.WithNodeStoreBatchTimeout(500 * time.Millisecond)},
		setup:  crowd,
		env:    []string{"HEADSCALE_CLI_TIMEOUT=5s"},
		stdout: "User 3 (alice) deleted with 23 nodes and 2 auth keys.\n",
		check: both(gone(3, append([]string{"mynode", "laptop", "phone"}, crowdNames...)...), pinned("3", "true", 1), func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			since, err := time.Parse(time.RFC3339Nano, f.vars["since"])
			require.NoError(tb, err)
			require.Less(tb, time.Since(since), 3*time.Second, "the delete waits a tick, not a tick for each node")
		}),
	},
	{
		name: "a node registered while the question was open: asked again, deleted", args: "users delete alice --with-nodes", terminal: true, stdin: "y\ny\n",
		answered: registers(1),
		stderr: aliceQuestion + "User 3 (alice) changed while you decided.\n" +
			"Delete User 3 (alice), 4 nodes and 2 auth keys?\n  mynode, laptop, phone, tablet\n[y/N] ",
		stdout: "User 3 (alice) deleted with 4 nodes and 2 auth keys.\n",
		check:  both(gone(3, "mynode", "laptop", "phone", "tablet"), pinned("3", "true", 2)),
	},
	{
		name: "changed twice: an error, and nothing removed", args: "users delete alice --with-nodes", terminal: true, stdin: "y\ny\n",
		answered: registers(2),
		stderr: aliceQuestion + "User 3 (alice) changed while you decided.\n" +
			"Delete User 3 (alice), 4 nodes and 2 auth keys?\n  mynode, laptop, phone, tablet\n[y/N] " +
			"Error: User 3 (alice) changed while the command ran. Run it again.\n",
		code:  1,
		check: both(kept(3, 5), pinned("3", "true", 2)),
	},
	{
		name: "--force with a change in between: a new token, nothing asked or said", args: "users delete alice --with-nodes --force",
		answered: registers(1),
		stdout:   "User 3 (alice) deleted with 4 nodes and 2 auth keys.\n",
		check:    both(gone(3, "mynode", "laptop", "phone", "tablet"), pinned("3", "true", 2)),
	},
	{
		name: "--force changed twice", args: "users delete alice --with-nodes --force", answered: registers(2),
		stderr: "Error: User 3 (alice) changed while the command ran. Run it again.\n", code: 1,
		check: both(kept(3, 5), pinned("3", "true", 2)),
	},
	{
		name: "no terminal without --force", args: "users delete bob",
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete User 4 (bob).\n", code: 1,
		check: both(kept(4, 0), func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()

			sent, _ := deletes(tb, r, "4")
			require.Equal(tb, []string{"?withNodes=false&dryRun=true"}, sent, "only the dry run")
		}),
	},
	{
		name: "a terminal, but stdin is a pipe", args: "users delete bob", terminal: true, piped: true, stdin: "y\n",
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete User 4 (bob).\n", code: 1,
		check: kept(4, 0),
	},

	// Each way to answer.
	{name: "yes", args: "users delete bob", terminal: true, stdin: "yes\n", stderr: "Delete User 4 (bob), 2 auth keys and 1 API key? [y/N] ", stdout: "User 4 (bob) deleted with 2 auth keys and 1 API key.\n", check: gone(4)},
	{name: "no", args: "users delete bob", terminal: true, stdin: "n\n", stderr: "Delete User 4 (bob), 2 auth keys and 1 API key? [y/N] Aborted.\n", code: 1, check: kept(4, 0)},
	{name: "enter is no", args: "users delete bob", terminal: true, stdin: "\n", stderr: "Delete User 4 (bob), 2 auth keys and 1 API key? [y/N] Aborted.\n", code: 1, check: kept(4, 0)},
	{name: "no answer is no", args: "users delete bob", terminal: true, stderr: "Delete User 4 (bob), 2 auth keys and 1 API key? [y/N] Aborted.\n", code: 1, check: kept(4, 0)},
	{name: "no to the list", args: "users delete alice --with-nodes", terminal: true, stdin: "n\n", stderr: aliceQuestion + "Aborted.\n", code: 1, check: kept(3, 3)},
	{name: "rm is delete", args: "users rm bob --force", stdout: "User 4 (bob) deleted with 2 auth keys and 1 API key.\n", check: gone(4)},
	{name: "a user with nothing", args: "users delete debtquity --force", stderr: "Error: \"debtquity\" matches 2 users. Use the ID to select one:\n\n  ID  NAME       EMAIL          PROVIDER\n  8   debtquity  -              local\n  9   debtquity  d@example.com  oidc\n", code: 1},
	{name: "a user with nothing, by ID", args: "users delete 8", terminal: true, stdin: "y\n", stderr: "Delete User 8 (debtquity)? [y/N] ", stdout: "User 8 (debtquity) deleted.\n", check: gone(8)},
	{
		name: "a long list is cut to the terminal and says how many are left out", args: "users delete alice --with-nodes", terminal: true, width: 20, stdin: "n\n",
		stderr: "Delete User 3 (alice), 3 nodes and 2 auth keys?\n  mynode … (+2)\n[y/N] Aborted.\n", code: 1,
	},

	// -o json prints what was removed, and still asks.
	{
		name: "-o json asks, then prints what was removed", args: "users delete alice --with-nodes -o json", terminal: true, stdin: "y\n",
		stderr: aliceQuestion, want: answer(usersPath + "/3"),
		check: both(gone(3), pinned("3", "true", 1), func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(tb, r.stdout, `"name": "laptop"`)
			require.Contains(tb, r.stdout, `"authKeyCount": 2`)
		}),
	},
	{name: "-o json with --force", args: "users delete bob --force -o json", want: answer(usersPath + "/4"), check: gone(4)},
	{name: "-o json with no terminal is the refusal", args: "users delete bob -o json", stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete User 4 (bob).\n", code: 1},

	// Tokens.
	{
		name: "a token that may read users and not delete one", args: "users delete bob --force",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "users:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope users.\n", code: 1, check: kept(4, 0),
	},
	{
		name: "a token that may read users, with --with-nodes: both scopes it lacks", args: "users delete alice --with-nodes --force",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.vars["token"] = f.token(tb, "users:read")
		},
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scopes users and devices:core.\n", code: 1, check: kept(3, 3),
	},
	{
		name: "a token with users and no devices:core, with --with-nodes", args: "users delete alice --with-nodes --force", setup: usersToken,
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:core.\n", code: 1, check: kept(3, 3),
	},
	{
		name: "a token with users deletes a user with no nodes", args: "users delete bob --force", setup: usersToken,
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stdout: "User 4 (bob) deleted with 2 auth keys and 1 API key.\n", check: gone(4),
	},

	// The API key the CLI calls with goes with its user.
	{
		name: "the CLI's own API key goes with the user", args: "users delete bob", terminal: true, stdin: "y\n",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={bobkey}"},
		stderr: "Delete User 4 (bob), 2 auth keys and 1 API key? This CLI calls with an API key of this user: once the user is deleted, the server refuses the CLI. [y/N] ",
		stdout: "User 4 (bob) deleted with 2 auth keys and 1 API key.\n",
		check: both(gone(4), func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			r := f.run(tb, cliCase{args: "users list", env: []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={bobkey}"}})
			require.Equal(tb, 1, r.code, "the key went with bob")
		}),
	},
	{
		name: "the CLI's own API key, with no terminal", args: "users delete bob",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={bobkey}"},
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete User 4 (bob). This CLI calls with an API key of this user: once the user is deleted, the server refuses the CLI.\n", code: 1,
	},
	{
		name: "the CLI's own API key, with --force: nothing said, nobody asked who calls", args: "users delete bob --force",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={bobkey}"},
		stdout: "User 4 (bob) deleted with 2 auth keys and 1 API key.\n",
		check: both(gone(4), func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.NotContains(tb, r.asked, "GET /api/headscale/v0/me")
		}),
	},
	{
		name: "another user's delete says nothing of the CLI's key", args: "users delete alice --with-nodes", terminal: true, stdin: "n\n",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={bobkey}"},
		stderr: aliceQuestion + "Aborted.\n", code: 1,
	},

	{
		name: "the answer of the delete is lost: what to look at", args: "users delete alice --with-nodes --force", setup: cutOff("delete"),
		env:    []string{"HEADSCALE_CLI_ADDRESS={proxy}", "HEADSCALE_CLI_API_KEY={nobodykey}"},
		stderr: "Error: the server at {proxyhost} did not answer the change: the connection was closed.\n" + lookAt,
		code:   1, check: gone(3, "mynode", "laptop", "phone"),
	},
	{
		name: "the answer of the delete is cut after its headers: it may have been made all the same", args: "users delete alice --with-nodes --force", setup: cutOff("delete body"),
		env:    []string{"HEADSCALE_CLI_ADDRESS={proxy}", "HEADSCALE_CLI_API_KEY={nobodykey}"},
		stderr: "Error: the server at {proxyhost} did not answer the change: the connection was closed.\n" + lookAt,
		code:   1, check: gone(3, "mynode", "laptop", "phone"),
	},
	{
		name: "the answer of the dry run is lost: nothing was deleted", args: "users delete alice --with-nodes --force", setup: cutOff("dry run"),
		env:    []string{"HEADSCALE_CLI_ADDRESS={proxy}", "HEADSCALE_CLI_API_KEY={nobodykey}"},
		stderr: "Error: the server at {proxyhost} did not answer: the connection was closed.\nNothing was changed: run the command again.\n",
		code:   1, check: kept(3, 3),
	},
	{name: "no user", args: "users delete nope --force", stderr: "Error: no user matches \"nope\".\n", code: 1},
	{name: "one user", args: "users delete alice bob", stderr: "Error: `users delete` needs 1 argument, got 2.\n\n  headscale users delete <user>\n", code: 1},
}

// lookAt is what follows a delete whose answer was lost.
const lookAt = "The change may have been made: look before you run the command again.\n" +
	"To look: headscale users get 3\nIf no user matches, the delete was made.\n" +
	"The delete removes all of it or nothing: a user that is still there lost nothing.\n"

// cutOff is a proxy in front of the case's server that passes the
// requests of what on to it, and hangs up before the CLI has the whole
// answer: "delete" before the delete's headers, "delete body" after them
// and half of its body, "dry run" before the dry run's headers. The
// server did what was asked, and the CLI does not know. It calls with an
// API key of nobody's, in the var nobodykey; the proxy is the var proxy.
func cutOff(what string) func(tb testing.TB, f *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()

		expiry := f.now.Add(time.Hour)
		secret, _, err := f.srv.State().CreateAPIKey(&expiry)
		require.NoError(tb, err)

		target, err := url.Parse(f.vars["url"])
		require.NoError(tb, err)

		dry := map[string]string{"delete": "false", "delete body": "false", "dry run": "true"}[what]

		proxy := httputil.NewSingleHostReverseProxy(target)
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Query().Get("dryRun") != dry {
				proxy.ServeHTTP(w, r)

				return
			}

			rec := httptest.NewRecorder()
			proxy.ServeHTTP(rec, r)

			rc := http.NewResponseController(w)

			if what == "delete body" {
				maps.Copy(w.Header(), rec.Header())

				w.WriteHeader(rec.Code)
				_, _ = w.Write(rec.Body.Bytes()[:rec.Body.Len()/2])
				_ = rc.Flush()
			}

			// A hijack that fails answers, and the case fails on what it
			// prints.
			conn, _, err := rc.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}))
		tb.Cleanup(hs.Close)

		f.vars["proxy"], f.vars["proxyhost"], f.vars["nobodykey"] = hs.URL, strings.TrimPrefix(hs.URL, "http://"), secret
	}
}

func TestUsersDelete(t *testing.T) {
	t.Parallel()

	runCases(t, keyed, usersDeleteCases)
}

// TestUsersDeleteTakesTheAPIKeys: the API key of a user goes with it, and
// one with no owner stays.
func TestUsersDeleteTakesTheAPIKeys(t *testing.T) {
	t.Parallel()

	runCases(t, credring, []cliCase{{
		name: "bob's API key goes with him", args: "users delete bob --with-nodes --force",
		stdout: "User 4 (bob) deleted with 1 node, 2 auth keys and 1 API key.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			r := f.run(tb, cliCase{args: "api keys list --all --columns id"})
			require.Equal(tb, "ID\n1\n10\n11\n", r.stdout)
		},
	}})
}

// workflowUser keeps just the fields the generated operations can observe.
type workflowUser struct {
	Name        string
	DisplayName string
}

func runUserWorkflow(t *testing.T, actions []int) error {
	t.Helper()
	f := newFixture(t, false)

	client, err := clientv0.NewClientWithResponses(f.srv.URL, clientv0.WithHTTPClient(f.srv.SocketClient()))
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
			if present {
				refusal = fmt.Sprintf("the name %q belongs to User", name)
			} else {
				state[name] = ""
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
				return fmt.Errorf("%w: %s: code=%d stdout=%q stderr=%q", errModelMismatch, args, r.code, r.stdout, r.stderr)
			}
		} else if op == 6 {
			if r.code != 0 || r.stderr != "" || !strings.HasSuffix(r.stdout, "("+name+") deleted.\n") {
				return fmt.Errorf("%w: %s: code=%d stdout=%q stderr=%q", errModelMismatch, args, r.code, r.stdout, r.stderr)
			}
		} else {
			var got workflowUser
			if r.code != 0 || r.stderr != "" || json.Unmarshal([]byte(r.stdout), &got) != nil || got != (workflowUser{name, state[name]}) {
				return fmt.Errorf("%w: %s: code=%d stdout=%q stderr=%q, want %s/%q", errModelMismatch, args, r.code, r.stdout, r.stderr, name, state[name])
			}
		}

		err := checkWorkflowLists(t, f, client, state, args, action, op)
		if err != nil {
			return err
		}
	}

	return nil
}

func checkWorkflowLists(t *testing.T, f *fixture, client *clientv0.ClientWithResponses, state map[string]string, args string, action, op int) error {
	t.Helper()

	// A separate unfiltered API read catches writes hidden by CLI selection.
	page, err := client.ListUsersWithResponse(t.Context(), &clientv0.ListUsersParams{PageSize: new(int64(100))})
	if err != nil {
		return err
	}

	if page.JSON200 == nil || page.JSON200.NextPageToken != nil || len(page.JSON200.Users) != len(state) {
		return fmt.Errorf("%w: after %s: API status=%d, body=%s", errModelMismatch, args, page.StatusCode(), page.Body)
	}

	observed := map[string]string{}
	for _, u := range page.JSON200.Users {
		observed[u.Name] = u.DisplayName
	}

	if !maps.Equal(observed, state) {
		return fmt.Errorf("%w: after %s: API=%v want=%v", errModelMismatch, args, observed, state)
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

	list := f.run(t, cliCase{args: "users ls --sort " + order + " --filter " + filter + " -o json", pageSize: 1})

	var got []workflowUser
	if list.code != 0 || list.stderr != "" || json.Unmarshal([]byte(list.stdout), &got) != nil || !slices.Equal(got, want) || len(list.asked) < len(state) {
		return fmt.Errorf("%w: after %s: CLI list code=%d stdout=%q stderr=%q requests=%q want=%v", errModelMismatch, args, list.code, list.stdout, list.stderr, list.asked, want)
	}

	return nil
}

func TestRapidUserWorkflow(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		actions := rapid.SliceOfN(rapid.IntRange(0, 20), 0, 8).Draw(rt, "actions")

		var discrepancy error
		// Scope the server, socket, and DB cleanup to one generated sequence.
		t.Run("fixture", func(t *testing.T) { discrepancy = runUserWorkflow(t, actions) })

		if discrepancy != nil {
			rt.Fatal(discrepancy)
		}
	})
}
