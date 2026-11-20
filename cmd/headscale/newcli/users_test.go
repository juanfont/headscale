package newcli

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

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
