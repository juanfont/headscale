package cli

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/json"
	"hash/crc32"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/cli/command"
	"github.com/juanfont/headscale/hscontrol/config"
	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/offline"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"zombiezen.com/go/postgrestest"
)

const v0Policy = "/api/headscale/v0/policy"

// goodPolicy has a comment, tabs and a test, and bob owns tag:server.
const goodPolicy = "// the policy of the tailnet\n{\n\t\"tagOwners\": {\"tag:server\": [\"bob@\"]},\n\t\"acls\": [{\"action\": \"accept\", \"src\": [\"bob@\"], \"dst\": [\"*:*\"]}],\n\t\"tests\": [{\"src\": \"bob@\", \"accept\": [\"bob@:22\"]}],\n}\n"

// The refused policies, one of each kind, with the lines the CLI prints
// for each; the server and the database bypass print the same.
var refusedPolicies = []struct {
	name, policy, lines string
}{
	{
		name:   "a syntax error, at its place",
		policy: "{\n  \"acls\": [\n    {\"action\": \"accept\",, }\n  ]\n}\n",
		lines:  "  line 3, column 25: invalid character ',' at start of value\n",
	},
	{
		name:   "an unknown tag, group and host",
		policy: "{\n  \"acls\": [\n    {\"action\": \"accept\", \"src\": [\"tag:serverr\", \"group:nope\"], \"dst\": [\"nohost:22\"]}\n  ]\n}\n",
		lines:  "  line 3, column 34: unknown tag \"tag:serverr\"\n  line 3, column 49: unknown group \"group:nope\"\n  line 3, column 72: unknown host \"nohost\"\n",
	},
	{
		name:   "an unknown host at its use, not at an SSH login of its name",
		policy: "{\n\"ssh\":[{\"action\":\"accept\",\"src\":[\"bob@\"],\"dst\":[\"bob@\"],\"users\":[\"build\"]}],\n\"acls\":[{\"action\":\"accept\",\"src\":[\"bob@\"],\"dst\":[\"build:22\"]}]\n}\n",
		lines:  "  line 3, column 50: unknown host \"build\"\n",
	},
	{
		name: "a failed ACL test and a failed SSH test",
		policy: `{
  "acls": [{"action": "accept", "src": ["bob@"], "dst": ["*:22"]}],
  "ssh": [{"action": "check", "src": ["bob@"], "dst": ["bob@"], "users": ["root"]}],
  "tests": [{"src": "bob@", "accept": ["bob@:80"]}],
  "sshTests": [{"src": "bob@", "dst": ["bob@"], "deny": ["root"]}]
}
`,
		lines: "  line 4, column 13: test bob@ -> bob@:80: expected accept, got deny\n  line 5, column 16: SSH test bob@ -> bob@ as root: expected deny, got check\n",
	},
	{
		name: "a failed SSH test above a failed test, in the order of the file",
		policy: `{
  "acls": [{"action": "accept", "src": ["bob@"], "dst": ["*:22"]}],
  "ssh": [{"action": "check", "src": ["bob@"], "dst": ["bob@"], "users": ["root"]}],
  "sshTests": [{"src": "bob@", "dst": ["bob@"], "deny": ["root"]}],
  "tests": [{"src": "bob@", "accept": ["bob@:80"]}]
}
`,
		lines: "  line 4, column 16: SSH test bob@ -> bob@ as root: expected deny, got check\n  line 5, column 13: test bob@ -> bob@:80: expected accept, got deny\n",
	},
	{
		name:   "one line with three mistakes, as jq -c writes it",
		policy: `{"acls":[{"action":"accept","src":["tag:b","group:x"],"dst":["nohost:22"]}]}`,
		lines:  "  line 1, column 36: unknown tag \"tag:b\"\n  line 1, column 44: unknown group \"group:x\"\n  line 1, column 62: unknown host \"nohost\"\n",
	},
	{
		name: "a mistake, and the tests it kept from running",
		policy: `{
  "acls": [{"action": "accept", "src": ["tag:none"], "dst": ["*:*"]}],
  "tests": [{"src": "bob@", "accept": ["bob@:22"]}],
  "sshTests": [{"src": "bob@", "dst": ["bob@"], "accept": ["root"]}]
}
`,
		lines: "  line 2, column 41: unknown tag \"tag:none\"\n  2 tests did not run, because of the problems above.\n",
	},
	{
		name:   "a NUL byte in a comment",
		policy: "{\"acls\": []}\n// \x00\n",
		lines:  "  line 2, column 4: the text has a NUL byte, which a policy cannot hold; remove it\n",
	},
	{
		name:   "a name twice, on one line",
		policy: `{"acls": [], "acls": []}`,
		lines:  "  line 1, column 14: \"acls\" is named twice in the same object; name it once\n",
	},
	{
		name:   "a syntax error on one line",
		policy: `{"acls": [{"action": "accept"} {"action": "accept"}]}`,
		lines:  "  line 1, column 32: invalid character '{' after array value (expecting ',' or ']')\n",
	},
	{
		name:   "a test that cannot run",
		policy: "{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}],\n  \"tests\": [{\"src\": \"nobody@\", \"accept\": [\"bob@:22\"]}]\n}\n",
		lines:  "  line 3, column 13: tests[0]: the source \"nobody@\" matches no user\n",
	},
	{
		name:   "not an object",
		policy: "null\n",
		lines:  "  line 1, column 1: the policy must be an object, such as {}\n",
	},
	{
		name:   "an empty file",
		policy: "",
		lines:  "  policy is empty, use \"{}\" to allow all\n",
	},
	{
		name:   "a byte-order mark",
		policy: "\ufeff{}\n",
		lines:  "  line 1, column 1: the text has a byte-order mark, which HuJSON does not allow; save the file without it\n",
	},
}

// manyTags is a policy with 150 unknown tags: the server lists 100.
func manyTags() string {
	tags := make([]string, 150)
	for i := range tags {
		tags[i] = `"tag:t` + strings.Repeat("x", i) + `"`
	}

	return `{"acls": [{"action": "accept", "src": [` + strings.Join(
		tags,
		", ",
	) + `], "dst": ["*:*"]}]}`
}

// manyLines are the lines of manyTags: the first 100, and the count.
func manyLines() string {
	var b strings.Builder

	b.WriteString("Error: the policy is not valid.\n")

	column := len(`{"acls": [{"action": "accept", "src": [`) + 1

	for i := range 100 {
		tag := `"tag:t` + strings.Repeat("x", i) + `"`
		b.WriteString(
			"  line 1, column " + strconv.Itoa(column) + ": unknown tag " + tag + "\n",
		)
		column += len(tag) + len(", ")
	}

	b.WriteString("  150 problems in all; the first 100 are shown.\n")

	return b.String()
}

// manyTests is a policy with a test of 150 assertions that fail: the
// server lists 100.
func manyTests() (string, string) {
	ports := make([]string, 150)
	for i := range ports {
		ports[i] = `"bob@:` + strconv.Itoa(i+1) + `"`
	}

	var b strings.Builder

	b.WriteString("Error: the policy is not valid.\n")

	for i := range 100 {
		b.WriteString(
			"  line 1, column 24: test bob@ -> bob@:" + strconv.Itoa(
				i+1,
			) + ": expected accept, got deny\n",
		)
	}

	b.WriteString("  150 failed tests in all; the first 100 are shown.\n")

	return `{"acls": [], "tests": [{"src": "bob@", "accept": [` + strings.Join(
		ports,
		", ",
	) + `]}]}`, b.String()
}

// aliceLine is the refusal of alice.hujson when two users are alice.
const aliceLine = "Error: the policy is not valid.\n  line 2, column 41: \"alice@\" matches more than one user, so it matches none: 2 (alice), 3 (alice); give the users different names or emails, or name one by its provider identifier\n"

// policyServer has the user bob with a node, as the policies above name.
func policyServer(tb testing.TB, f *fixture) {
	tb.Helper()

	bob := f.srv.CreateUser(tb, "bob")
	f.srv.CreateRegisteredNode(tb, bob, "bob-laptop")

	f.vars["dir"] = tb.TempDir()
	file(tb, f, "good.hujson", goodPolicy)
	file(tb, f, "latin1.hujson", "// ok\n// caf\xe9\n{}\n")
}

// file writes a file of the case into its directory.
func file(tb testing.TB, f *fixture, name, text string) {
	tb.Helper()
	require.NoError(
		tb,
		os.WriteFile(filepath.Join(f.vars["dir"], name), []byte(text), 0o600),
	)
}

// inForce puts text in force on the server, as a write would.
func inForce(text string) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()

		_, _, err := f.srv.State().UpdatePolicy([]byte(text))
		require.NoError(tb, err)
	}
}

// storedAs is the policy in force now, as GET /policy answers it.
func storedAs(want string) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()
		require.Equal(tb, want, f.srv.State().Policy().Data)
	}
}

// sentAs holds the PUT the CLI sent: the file as its body, as it is, with
// no If-Match, since the last writer wins.
func sentAs(query, body string) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, _ *fixture, r result) {
		tb.Helper()

		i := slicesIndex(r.sent, "PUT "+v0Policy+query+" "+body)
		require.GreaterOrEqual(tb, i, 0, "sent: %q", r.sent)
		require.Empty(tb, r.headers[i].Values("If-Match"))
		require.Equal(tb, "application/hujson", r.headers[i].Get("Content-Type"))
	}
}

func slicesIndex(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}

	return -1
}

// ambiguous makes a second user named alice, from OIDC.
func ambiguous(tb testing.TB, f *fixture) {
	tb.Helper()

	st := f.srv.State()

	_, _, err := st.CreateUser(types.User{Name: "alice"})
	require.NoError(tb, err)

	_, _, err = st.CreateUser(types.User{
		Name:     "alice",
		Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{
			String: "https://idp.example.com/alice",
			Valid:  true,
		},
	})
	require.NoError(tb, err)

	file(
		tb,
		f,
		"alice.hujson",
		"{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"alice@\"], \"dst\": [\"*:*\"]}]\n}\n",
	)
}

var policyCases = func() []cliCase {
	cases := []cliCase{ //nolint:prealloc // the refused policies follow
		{
			name:   "get: nothing stored prints nothing, and says so",
			args:   "policy get",
			stderr: "No policy is in force: all traffic is allowed.\n",
		},
		{
			name:   "get: the example",
			setup:  inForce(goodPolicy),
			args:   "policy get",
			stdout: goodPolicy,
		},
		{
			name:  "get: -o json is GET /policy",
			setup: inForce(goodPolicy),
			args:  "policy get -o json",
			want:  answer(v0Policy),
		},
		{
			name: "get: -o json of nothing stored says nothing",
			args: "policy get -o json",
			want: answer(v0Policy),
		},
		{
			name: "get: a credential lacks the scope",
			args: "policy get",
			env: []string{
				"HEADSCALE_CLI_ADDRESS={url}",
				"HEADSCALE_CLI_API_KEY={token}",
			},
			setup:  func(tb testing.TB, f *fixture) { tb.Helper(); f.vars["token"] = f.token(tb, "users:read") },
			stderr: "Error: this credential may not do that.\nIt lacks the scope policy_file:read.\n",
			code:   1,
		},
		{
			name:   "get takes no arguments",
			args:   "policy get x",
			stderr: "Error: `policy get` takes no arguments, got 1.\n\n  headscale policy get\n",
			code:   1,
		},

		{
			name:   "set: the example",
			args:   "policy set {dir}/good.hujson",
			stdout: "Policy updated.\n",
			check: func(tb testing.TB, f *fixture, r result) {
				tb.Helper()
				storedAs(goodPolicy)(tb, f, r)
				sentAs("", goodPolicy)(tb, f, r)
			},
		},
		{
			name:   "set: --dry-run checks and changes nothing",
			setup:  inForce("{}"),
			args:   "policy set {dir}/good.hujson --dry-run",
			stdout: "Policy is valid for this server. Nothing was changed.\n",
			check: func(tb testing.TB, f *fixture, r result) {
				tb.Helper()
				storedAs("{}")(tb, f, r)
				sentAs("?dryRun=true", goodPolicy)(tb, f, r)
			},
		},
		{
			name:   "set: stdin",
			args:   "policy set -",
			stdin:  goodPolicy,
			stdout: "Policy updated.\n",
			check:  storedAs(goodPolicy),
		},
		{
			name: "set: -o json is what PUT /policy answered",
			args: "policy set {dir}/good.hujson -o json",
			want: answer(v0Policy),
		},
		{
			name: "set: -o json of a dry run",
			args: "policy set {dir}/good.hujson --dry-run -o json",
			want: answer(v0Policy),
		},
		{
			name:   "set: a name two users have",
			setup:  ambiguous,
			args:   "policy set {dir}/alice.hujson",
			stderr: aliceLine,
			code:   1,
		},
		{
			name:   "set: more than 100 problems",
			args:   "policy set {dir}/many.hujson",
			setup:  func(tb testing.TB, f *fixture) { tb.Helper(); file(tb, f, "many.hujson", manyTags()) },
			stderr: manyLines(),
			code:   1,
		},
		{
			name:   "set: a file that does not exist",
			args:   "policy set {dir}/nope.hujson",
			stderr: "Error: the file {dir}/nope.hujson does not exist.\n",
			code:   1,
		},
		{
			name:   "set: an empty file argument",
			args:   `policy set ""`,
			stderr: "Error: \"\" is not a valid <file>: it takes a path, or - for stdin.\n",
			code:   1,
		},
		{
			name:   "set: a directory",
			args:   "policy set {dir}",
			stderr: "Error: {dir} is a directory, not a file.\n",
			code:   1,
		},
		{
			name: "set: larger than the server takes",
			args: "policy set {dir}/large.hujson",
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				file(tb, f, "large.hujson", "{}"+strings.Repeat(" ", 1<<20))
			},
			stderr: "Error: the file is too large for the server.\n",
			code:   1,
		},
		{
			name: "set: a credential that may only read",
			args: "policy set {dir}/good.hujson",
			env: []string{
				"HEADSCALE_CLI_ADDRESS={url}",
				"HEADSCALE_CLI_API_KEY={token}",
			},
			setup:  func(tb testing.TB, f *fixture) { tb.Helper(); f.vars["token"] = f.token(tb, "policy_file:read") },
			stderr: "Error: this credential may not do that.\nIt lacks the scope policy_file.\n",
			code:   1,
		},
		{
			name:   "set: more than 100 failed tests",
			args:   "policy set {dir}/tests.hujson",
			setup:  func(tb testing.TB, f *fixture) { tb.Helper(); pol, _ := manyTests(); file(tb, f, "tests.hujson", pol) },
			stderr: func() string { _, lines := manyTests(); return lines }(),
			code:   1,
		},
		{
			name:   "set: a file that is not UTF-8 is refused before any call",
			args:   "policy set {dir}/latin1.hujson",
			stderr: latin1Refused,
			code:   1,
			check: func(tb testing.TB, _ *fixture, r result) {
				tb.Helper()
				require.Equal(
					tb,
					-1,
					slicesIndex(r.asked, "PUT "+v0Policy),
					"asked: %q",
					r.asked,
				)
			},
		},
		{
			name:     "set: stdin on a terminal says how to end it",
			args:     "policy set -",
			terminal: true,
			stdin:    goodPolicy,
			stdout:   "Policy updated.\n",
			stderr:   stdinHint,
			check:    storedAs(goodPolicy),
		},
		{
			name:   "get: controls of a comment into a pipe",
			setup:  inForce(commentEscapes),
			args:   "policy get",
			stdout: commentEscapes,
		},
		{
			name:     "get: controls of a comment on a terminal",
			setup:    inForce(commentEscapes),
			args:     "policy get",
			terminal: true,
			stdout:   commentShown,
		},
		{
			name:   "set needs a file",
			args:   "policy set",
			stderr: "Error: `policy set` needs 1 argument, got 0.\n\n  headscale policy set <file>\n",
			code:   1,
		},

		{
			name:   "reload: the database",
			setup:  inForce(goodPolicy),
			args:   "policy reload",
			stdout: "Policy reloaded from the database.\n",
		},
		{
			name:   "reload: nothing stored",
			args:   "policy reload",
			stdout: "Policy reloaded from the database. No policy is in force: all traffic is allowed.\n",
		},
		{
			name:  "reload: -o json",
			setup: inForce(goodPolicy),
			args:  "policy reload -o json",
			want:  answer(v0Policy + "/reload"),
		},
		{
			name: "reload: a stored policy that is not valid keeps the one in force",
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				inForce(goodPolicy)(tb, f)

				_, err := f.srv.State().SetPolicyInDB(refusedPolicies[1].policy)
				require.NoError(tb, err)
			},
			args:   "policy reload",
			stderr: "Error: the policy is not valid. The old policy is still in use.\n" + refusedPolicies[1].lines,
			code:   1,
			check:  storedAs(goodPolicy),
		},
		{
			name: "reload: a stored policy that changes on every read",
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				inForce(goodPolicy)(tb, f)

				// Changed under each of the three tries of the reload, then left.
				n := 0

				f.srv.State().SetPreparePolicyHookForTesting(func() {
					if n++; n <= 3 {
						_, err := f.srv.State().
							SetPolicyInDB(goodPolicy + "\n// " + strconv.Itoa(n) + "\n")
						require.NoError(tb, err)
					}
				})
			},
			args:   "policy reload",
			stderr: "Error: the policy changed while the server read it; the policy in force stays. Reload again.\n",
			code:   1,
			check:  storedAs(goodPolicy),
		},
		{
			name: "reload: a credential that may only read",
			args: "policy reload",
			env: []string{
				"HEADSCALE_CLI_ADDRESS={url}",
				"HEADSCALE_CLI_API_KEY={token}",
			},
			setup:  func(tb testing.TB, f *fixture) { tb.Helper(); f.vars["token"] = f.token(tb, "policy_file:read") },
			stderr: "Error: this credential may not do that.\nIt lacks the scope policy_file.\n",
			code:   1,
		},
	}

	for _, p := range refusedPolicies {
		for _, dry := range []string{"", " --dry-run"} {
			cases = append(cases, cliCase{
				name: "set" + dry + ": " + p.name,
				setup: func(tb testing.TB, f *fixture) {
					tb.Helper()
					inForce("{}")(tb, f)
					file(tb, f, "bad.hujson", p.policy)
				},
				args:   "policy set {dir}/bad.hujson" + dry,
				stderr: "Error: the policy is not valid.\n" + p.lines,
				code:   1,
				check:  storedAs("{}"),
			})
		}
	}

	return cases
}()

func TestPolicy(t *testing.T) {
	t.Parallel()

	runCases(t, policyServer, policyCases)
}

// stopped points the case's config at a database of its own, as a stopped
// server leaves it: bob with a node, and text stored unless it is "". The
// server of the case cannot be reached, so a command that asks it fails.
func stopped(mode, text string, env ...string) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()

		dir := tb.TempDir()
		f.vars["db"] = filepath.Join(dir, "db.sqlite")
		f.env = append(f.env,
			"HEADSCALE_UNIX_SOCKET=/nonexistent/headscale.sock",
			"HEADSCALE_DATABASE_SQLITE_PATH="+f.vars["db"],
			"HEADSCALE_NOISE_PRIVATE_KEY_PATH="+filepath.Join(dir, "noise.key"),
			"HEADSCALE_POLICY_MODE="+mode,
		)
		f.env = append(f.env, env...)

		d := openStopped(tb, f)
		defer d.Close()

		bob := d.CreateUserForTest("bob")
		d.CreateRegisteredNodeForTest(bob, "bob-laptop")

		if text != "" {
			_, err := d.SetPolicy(text)
			require.NoError(tb, err)
		}
	}
}

// withURL is the server URL a database bypass needs, as serve does.
const withURL = "HEADSCALE_SERVER_URL=https://hs.example.com"

// openStopped opens the database of a case of stopped.
func openStopped(tb testing.TB, f *fixture) *hsdb.HSDatabase {
	tb.Helper()

	var file string

	for _, kv := range f.env {
		if v, ok := strings.CutPrefix(kv, "HEADSCALE_CONFIG="); ok {
			file = v
		}
	}

	l, err := config.Load(file, true, f.env)
	require.NoError(tb, err)

	d, err := hsdb.NewHeadscaleDatabase(l.Config)
	require.NoError(tb, err)

	return d
}

// storedIn holds what the database of a case of stopped stores.
func storedIn(want string) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()

		d := openStopped(tb, f)
		defer d.Close()

		p, err := d.GetPolicy()
		if want == "" {
			require.ErrorIs(tb, err, types.ErrPolicyNotFound)

			return
		}

		require.NoError(tb, err)
		require.Equal(tb, want, p.Data)
	}
}

// bypassJSON is what -o json prints for the policy of a case of stopped:
// the policy object of the API, updated to the microsecond.
func bypassJSON(tb testing.TB, f *fixture, _ result) string {
	tb.Helper()

	d := openStopped(tb, f)
	defer d.Close()

	p, err := d.GetPolicy()
	require.NoError(tb, err)

	return policyJSON(tb, p.Data, p.UpdatedAt.UTC().Truncate(time.Microsecond))
}

// policyJSON is the policy object of the API in the server's order of
// keys, in database mode.
func policyJSON(tb testing.TB, policy string, updated any) string {
	tb.Helper()

	b, err := json.Marshal(struct {
		Policy  string `json:"policy"`
		Updated any    `json:"updated"`
		Mode    string `json:"mode"`
		Path    string `json:"path"`
	}{policy, updated, "database", ""})
	require.NoError(tb, err)

	return indent(tb, b)
}

// The refusals of the bypass for a database it must not touch.
const (
	unfinished = "Error: the database {db} holds a write that was not finished, which a read cannot recover without writing. Start the server once so it recovers the database, or run the command on a copy of the database files in a directory you may write.\n"
	inUse      = "Error: another program has the database {db} open, such as a server that is starting or running. Stop it, then run the command again.\n"
	closed     = "Error: the socket {closed} cannot be asked whether a server listens (permission denied), so one may be running. Run the command as a user who may open the socket, or stop the server and remove the socket.\n"
)

// journal is a stopped server in database mode with no write-ahead log.
func journal(text string) func(testing.TB, *fixture) {
	return stopped(
		"database",
		text,
		withURL,
		"HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG=false",
	)
}

// isRunning is the refusal of the bypass while a server answers.
const isRunning = "Error: a server is running: it answers on {socket}. Run the command without --bypass-server-and-access-database-directly.\n"

// stale is setup with a socket file that no server listens on, as a
// server that stopped without removing it leaves.
func stale(setup func(testing.TB, *fixture)) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		setup(tb, f)

		socket := filepath.Join(shortDir(tb), "s.sock")

		l, err := (&net.ListenConfig{}).Listen(tb.Context(), "unix", socket)
		require.NoError(tb, err)

		unix, ok := l.(*net.UnixListener)
		require.True(tb, ok)
		unix.SetUnlinkOnClose(false)
		require.NoError(tb, l.Close())
		require.FileExists(tb, socket)

		f.env = append(f.env, "HEADSCALE_UNIX_SOCKET="+socket)
	}
}

// keptFiles is setup that keeps the bytes of the database file, for
// unchanged. A read may leave a -shm and a -wal beside it, as any reader
// of SQLite does; the file is what holds the data.
func keptFiles(setup func(testing.TB, *fixture)) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		setup(tb, f)

		f.vars["files"] = fileOf(tb, f.vars["db"])
	}
}

// readOnly is setup with a database file that may only be read.
func readOnly(setup func(testing.TB, *fixture)) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		keptFiles(setup)(tb, f)

		require.NoError(tb, os.Chmod(f.vars["db"], 0o444))
	}
}

// unchanged holds that the database file of a case of keptFiles has the
// bytes it had.
func unchanged(tb testing.TB, f *fixture, _ result) {
	tb.Helper()

	require.Equal(
		tb,
		f.vars["files"],
		fileOf(tb, f.vars["db"]),
		"the database file changed",
	)
}

// fileOf is a hash of the bytes of the file at path.
func fileOf(tb testing.TB, path string) string {
	tb.Helper()

	data, err := os.ReadFile(path)
	require.NoError(tb, err)

	return strconv.FormatUint(uint64(crc32.ChecksumIEEE(data)), 16)
}

// crashed is setup that leaves the database of the case as a server killed
// in a write leaves it, in a copy that the case then names. With the
// write-ahead log "// newest" is committed and only in the log; without
// it "// uncommitted" is in the file and the stored policy in a hot
// journal.
func crashed(setup func(testing.TB, *fixture)) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		setup(tb, f)

		d := openStopped(tb, f)
		defer d.Close()

		sqlDB, err := d.DB.DB()
		require.NoError(tb, err)

		conn, err := sqlDB.Conn(tb.Context())
		require.NoError(tb, err)

		defer conn.Close()

		exec := func(stmt string, args ...any) {
			tb.Helper()

			_, err := conn.ExecContext(tb.Context(), stmt, args...)
			require.NoError(tb, err, stmt)
		}

		suffix := "-wal"

		if strings.Contains(strings.Join(f.env, " "), "WRITE_AHEAD_LOG=false") {
			// A small cache spills the large write into the file before
			// the commit, the pages it replaced into the journal.
			suffix = "-journal"

			exec("PRAGMA cache_size = 10")
			exec("BEGIN")
			exec(
				"UPDATE policies SET data = '// uncommitted' || ?",
				strings.Repeat(" ", 4<<20),
			)
		} else {
			exec("PRAGMA wal_autocheckpoint = 0")
			exec("UPDATE policies SET data = '// newest'")
		}

		dst := filepath.Join(tb.TempDir(), "db.sqlite")

		for _, s := range []string{"", suffix} {
			b, err := os.ReadFile(f.vars["db"] + s)
			require.NoError(tb, err)
			//nolint:gosec // a directory of the test
			require.NoError(tb, os.WriteFile(dst+s, b, 0o600))
		}

		if suffix == "-journal" {
			exec("ROLLBACK")
		}

		f.vars["db"] = dst
		f.env = append(f.env, "HEADSCALE_DATABASE_SQLITE_PATH="+dst)
	}
}

// held is setup that keeps the database of the case open in a process of
// its own, as a server that is starting or running does, until the case
// ends. The bypass sees only another process: the lock it asks for is
// shared by the connections of one.
func held(setup func(testing.TB, *fixture)) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		setup(tb, f)

		//nolint:gosec // the test binary itself
		cmd := exec.CommandContext(tb.Context(), os.Args[0])

		cmd.Env = append(slices.Clone(f.env), holdDB+"=1", "PATH="+os.Getenv("PATH"))

		stdin, err := cmd.StdinPipe()
		require.NoError(tb, err)

		stdout, err := cmd.StdoutPipe()
		require.NoError(tb, err)
		require.NoError(tb, cmd.Start())

		line, err := bufio.NewReader(stdout).ReadString('\n')
		require.NoError(tb, err)
		require.Equal(tb, "ready\n", line)

		tb.Cleanup(func() {
			_ = stdin.Close()
			_ = cmd.Wait()
		})
	}
}

// holdDB makes a run of the test binary hold the database of its config
// open, as a server does: hold.
const holdDB = "HEADSCALE_TEST_HOLD_DB"

// hold opens the database that the environment's config names, as a
// server does, says "ready", and keeps it open until stdin ends.
func hold() int {
	l, err := config.Load(os.Getenv("HEADSCALE_CONFIG"), true, os.Environ())
	if err != nil {
		panic(err)
	}

	d, err := hsdb.NewHeadscaleDatabase(l.Config)
	if err != nil {
		panic(err)
	}

	_, _ = os.Stdout.WriteString("ready\n")
	_, _ = io.Copy(io.Discard, os.Stdin)

	if d.Close() != nil {
		return 1
	}

	return 0
}

// shortDir is a directory for a unix socket, whose path is short: the
// test's own directory is too long.
func shortDir(tb testing.TB) string {
	tb.Helper()

	//nolint:usetesting // tb.TempDir is named after the test
	dir, err := os.MkdirTemp("", "hs")
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })

	return dir
}

// closedSocket is setup with a server that listens on a socket the user
// may not open, as a server's of mode 0770 is to a user not in its group.
func closedSocket(setup func(testing.TB, *fixture)) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()

		if os.Geteuid() == 0 {
			tb.Skip("root opens every socket")
		}

		setup(tb, f)

		socket := filepath.Join(shortDir(tb), "s.sock")

		l, err := (&net.ListenConfig{}).Listen(tb.Context(), "unix", socket)
		require.NoError(tb, err)
		tb.Cleanup(func() { _ = l.Close() })
		require.NoError(tb, os.Chmod(socket, 0o000))

		f.vars["closed"] = socket
		f.env = append(f.env, "HEADSCALE_UNIX_SOCKET="+socket)
	}
}

// migrated is setup that runs stmt on the database after it, as a server
// of another version leaves it; {last} is this build's last migration.
func migrated(
	setup func(testing.TB, *fixture),
	stmt string,
) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		setup(tb, f)

		d := openStopped(tb, f)
		defer d.Close()

		var last string

		require.NoError(
			tb,
			d.DB.Raw("SELECT MAX(id) FROM migrations WHERE id != 'SCHEMA_INIT'").
				Scan(&last).
				Error,
		)
		require.NoError(tb, d.DB.Exec(stmt).Error)

		f.vars["last"] = last
	}
}

// inConfigFile is a stopped server whose database and settings are in a
// config file, hs.yaml, and not in the environment.
func inConfigFile(text string) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		stopped("database", text, withURL)(tb, f)

		dir := filepath.Dir(f.vars["db"])
		yaml := "server_url: https://hs.example.com\n" +
			"unix_socket: /nonexistent/headscale.sock\n" +
			"noise:\n  private_key_path: " + filepath.Join(dir, "noise.key") + "\n" +
			"database:\n  type: sqlite\n  sqlite:\n    path: " + f.vars["db"] + "\n" +
			"policy:\n  mode: database\n"
		file(tb, f, "hs.yaml", yaml)

		var env []string

		for _, kv := range f.env {
			name, _, _ := strings.Cut(kv, "=")
			if name == "HEADSCALE_CONFIG" || !strings.HasPrefix(name, "HEADSCALE_") ||
				name == "HEADSCALE_CLI_TIMEOUT" {
				env = append(env, kv)
			}
		}

		f.env = env
	}
}

const (
	// commentEscapes is a policy whose comment would drive a terminal: a title, a
	// clear screen, the clipboard and a report of the cursor, which a
	// terminal types into the shell; commentShown is it made visible.
	commentEscapes = "// \x1b]0;pwned\x07 \x1b[2J \x1b]52;c;aGk=\x07 \x1b[6n\n{}\n"
	commentShown   = "// \\x1b]0;pwned\\x07 \\x1b[2J \\x1b]52;c;aGk=\\x07 \\x1b[6n\n{}\n"

	stdinHint     = "Reading from stdin: end with Ctrl-D at the start of a line.\n"
	latin1Refused = "Error: {dir}/latin1.hujson is not UTF-8 text: line 2 holds a byte that is not.\n"
)

const (
	bypass    = " --bypass-server-and-access-database-directly"
	readsDB   = "This reads the database directly. Headscale must not be running.\nContinue? [y/N] "
	writesDB  = "This writes the policy to the database directly. Headscale must not be running.\nContinue? [y/N] "
	noPolicyL = "No policy is in force: all traffic is allowed.\n"
)

// stoppedWith is a stopped server in database mode that stores text.
func stoppedWith(
	text string,
) func(testing.TB, *fixture) {
	return stopped("database", text, withURL)
}

var bypassCases = func() []cliCase {
	cases := []cliCase{ //nolint:prealloc // the refused policies follow
		{
			name:     "get: yes",
			setup:    stoppedWith(goodPolicy),
			args:     "policy get" + bypass,
			terminal: true,
			stdin:    "y\n",
			stdout:   goodPolicy,
			stderr:   readsDB,
		},
		{
			name:     "get: no",
			setup:    stoppedWith(goodPolicy),
			args:     "policy get" + bypass,
			terminal: true,
			stdin:    "n\n",
			stderr:   readsDB + "Aborted.\n",
			code:     1,
		},
		{
			name:   "get: no terminal",
			setup:  stoppedWith(goodPolicy),
			args:   "policy get" + bypass,
			stdin:  "y\n",
			stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to read the database directly.\n",
			code:   1,
		},
		{
			name:   "get: --force",
			setup:  stoppedWith(goodPolicy),
			args:   "policy get --force" + bypass,
			stdout: goodPolicy,
		},
		{
			name:   "get: nothing stored",
			setup:  stoppedWith(""),
			args:   "policy get --force" + bypass,
			stderr: noPolicyL,
		},
		{
			name:  "get: -o json is the policy object",
			setup: stoppedWith(goodPolicy),
			args:  "policy get --force -o json" + bypass,
			want:  bypassJSON,
		},
		{
			name: "get: file mode reads the file", args: "policy get --force" + bypass,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				stopped(
					"file",
					"",
					withURL,
					"HEADSCALE_POLICY_PATH="+filepath.Join(
						f.vars["dir"],
						"good.hujson",
					),
				)(
					tb,
					f,
				)
			},
			stdout: goodPolicy,
		},
		{
			name:   "get: file mode with no file",
			setup:  stopped("file", "", withURL),
			args:   "policy get --force" + bypass,
			stderr: "No policy file is set (policy.path), so no policy is in force: all traffic is allowed.\n",
		},
		{
			name:   "get: a config the server would refuse",
			setup:  stopped("database", ""),
			args:   "policy get --force" + bypass,
			stderr: "Error: the configuration is not valid: Fatal config error: server_url is required\n  hint: set server_url to the URL clients connect to, e.g. https://headscale.example.com\n",
			code:   1,
		},

		{
			name:   "set: --force",
			setup:  stoppedWith("{}"),
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stdout: "Policy updated.\n",
			check:  storedIn(goodPolicy),
		},
		{
			name:     "set: yes",
			setup:    stoppedWith(""),
			args:     "policy set {dir}/good.hujson" + bypass,
			terminal: true,
			stdin:    "y\n",
			stdout:   "Policy updated.\n",
			stderr:   writesDB,
			check:    storedIn(goodPolicy),
		},
		{
			name:     "set: no",
			setup:    stoppedWith("{}"),
			args:     "policy set {dir}/good.hujson" + bypass,
			terminal: true,
			stdin:    "n\n",
			stderr:   writesDB + "Aborted.\n",
			code:     1,
			check:    storedIn("{}"),
		},
		{
			name:   "set: stdin cannot answer",
			setup:  stoppedWith("{}"),
			args:   "policy set -" + bypass,
			stdin:  goodPolicy,
			stderr: "Error: confirmation needed, but stdin is the file given as -, so it cannot answer.\nRun again with --force to write the policy to the database directly.\n",
			code:   1,
			check:  storedIn("{}"),
		},
		{
			name:     "set: stdin on a terminal cannot answer either",
			setup:    stoppedWith("{}"),
			args:     "policy set -" + bypass,
			terminal: true,
			stdin:    "y\n",
			stderr:   "Error: confirmation needed, but stdin is the file given as -, so it cannot answer.\nRun again with --force to write the policy to the database directly.\n",
			code:     1,
			check:    storedIn("{}"),
		},
		{
			name:   "set: stdin with --force",
			setup:  stoppedWith("{}"),
			args:   "policy set - --force" + bypass,
			stdin:  goodPolicy,
			stdout: "Policy updated.\n",
			check:  storedIn(goodPolicy),
		},
		{
			name:  "set: -o json",
			setup: stoppedWith(""),
			args:  "policy set {dir}/good.hujson --force -o json" + bypass,
			want:  bypassJSON,
		},
		{
			name:     "set: --dry-run reads",
			setup:    stoppedWith("{}"),
			args:     "policy set {dir}/good.hujson --dry-run" + bypass,
			terminal: true,
			stdin:    "y\n",
			stdout:   "Policy is valid for this server. Nothing was changed.\n",
			stderr:   readsDB,
			check:    storedIn("{}"),
		},
		{
			name:  "set: --dry-run -o json",
			setup: stoppedWith("{}"),
			args:  "policy set {dir}/good.hujson --dry-run --force -o json" + bypass,
			want: func(tb testing.TB, _ *fixture, _ result) string {
				tb.Helper()

				return policyJSON(tb, goodPolicy, nil)
			},
		},
		{
			name: "set: file mode",
			args: "policy set {dir}/good.hujson --force" + bypass,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				stopped(
					"file",
					"",
					withURL,
					"HEADSCALE_POLICY_PATH="+filepath.Join(
						f.vars["dir"],
						"good.hujson",
					),
				)(
					tb,
					f,
				)
			},
			stderr: "Error: the policy is read from {dir}/good.hujson. Edit that file.\n",
			code:   1,
		},
		{
			name:   "set: file mode with no file",
			setup:  stopped("file", "", withURL),
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stderr: "Error: no policy file is set (policy.path), and the policy cannot be written while policy.mode is file.\n",
			code:   1,
		},
		{
			name:   "set: --dry-run in file mode",
			setup:  stopped("file", "", withURL),
			args:   "policy set {dir}/good.hujson --dry-run --force" + bypass,
			stdout: "Policy is valid for this server. Nothing was changed.\n",
		},
		{
			name: "set: a name two users have",
			args: "policy set {dir}/alice.hujson --force" + bypass,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				stoppedWith("{}")(tb, f)

				d := openStopped(tb, f)
				defer d.Close()

				_, err := d.CreateUser(types.User{Name: "alice"})
				require.NoError(tb, err)

				_, err = d.CreateUser(types.User{
					Name:     "alice",
					Provider: util.RegisterMethodOIDC,
					ProviderIdentifier: sql.NullString{
						String: "https://idp.example.com/alice",
						Valid:  true,
					},
				})
				require.NoError(tb, err)

				file(
					tb,
					f,
					"alice.hujson",
					"{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"alice@\"], \"dst\": [\"*:*\"]}]\n}\n",
				)
			},
			stderr: aliceLine,
			code:   1,
			check:  storedIn("{}"),
		},
		{
			name: "set: more than 100 problems",
			args: "policy set {dir}/many.hujson --force" + bypass,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				stoppedWith("{}")(tb, f)
				file(tb, f, "many.hujson", manyTags())
			},
			stderr: manyLines(),
			code:   1,
		},
		{
			name:   "set: a file that does not exist",
			setup:  stoppedWith("{}"),
			args:   "policy set {dir}/nope.hujson --force" + bypass,
			stderr: "Error: the file {dir}/nope.hujson does not exist.\n",
			code:   1,
		},
		{
			name: "set: more than 100 failed tests",
			args: "policy set {dir}/tests.hujson --force" + bypass,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				stoppedWith("{}")(tb, f)

				pol, _ := manyTests()
				file(tb, f, "tests.hujson", pol)
			},
			stderr: func() string { _, lines := manyTests(); return lines }(),
			code:   1,
		},

		{
			name:   "get: a server that answers on the socket",
			setup:  stoppedWith(goodPolicy),
			env:    []string{"HEADSCALE_UNIX_SOCKET={socket}"},
			args:   "policy get --force" + bypass,
			stderr: isRunning,
			code:   1,
		},
		{
			name:   "set: a server that answers on the socket",
			setup:  stoppedWith("{}"),
			env:    []string{"HEADSCALE_UNIX_SOCKET={socket}"},
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stderr: isRunning,
			code:   1,
			check:  storedIn("{}"),
		},
		{
			name:   "get: a socket file that nobody listens on",
			setup:  stale(stoppedWith(goodPolicy)),
			args:   "policy get --force" + bypass,
			stdout: goodPolicy,
		},
		{
			name:   "set: a socket file that nobody listens on",
			setup:  stale(stoppedWith("{}")),
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stdout: "Policy updated.\n",
			check:  storedIn(goodPolicy),
		},

		{
			name:   "get changes no byte of the database",
			setup:  keptFiles(stoppedWith(goodPolicy)),
			args:   "policy get --force" + bypass,
			stdout: goodPolicy,
			check:  unchanged,
		},
		{
			name:   "set --dry-run changes no byte of the database",
			setup:  keptFiles(stoppedWith("{}")),
			args:   "policy set {dir}/good.hujson --dry-run --force" + bypass,
			stdout: "Policy is valid for this server. Nothing was changed.\n",
			check:  unchanged,
		},
		{
			name:   "get: a read-only database",
			setup:  readOnly(stoppedWith(goodPolicy)),
			args:   "policy get --force" + bypass,
			stdout: goodPolicy,
			check:  unchanged,
		},
		{
			name:   "set --dry-run: a read-only database",
			setup:  readOnly(stoppedWith("{}")),
			args:   "policy set {dir}/good.hujson --dry-run --force" + bypass,
			stdout: "Policy is valid for this server. Nothing was changed.\n",
			check:  unchanged,
		},
		{
			name:   "get: a database that is not there",
			setup:  stoppedWith(""),
			env:    []string{"HEADSCALE_DATABASE_SQLITE_PATH={dir}/nope/sub/db.sqlite"},
			args:   "policy get --force" + bypass,
			stderr: "Error: the database {dir}/nope/sub/db.sqlite does not exist.\n",
			code:   1,
			check: func(tb testing.TB, f *fixture, _ result) {
				tb.Helper()
				require.NoDirExists(tb, filepath.Join(f.vars["dir"], "nope"))
			},
		},
		{
			name:   "set: a database that is not there",
			setup:  stoppedWith(""),
			env:    []string{"HEADSCALE_DATABASE_SQLITE_PATH={dir}/nope/sub/db.sqlite"},
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stderr: "Error: the database {dir}/nope/sub/db.sqlite does not exist.\n",
			code:   1,
			check: func(tb testing.TB, f *fixture, _ result) {
				tb.Helper()
				require.NoDirExists(tb, filepath.Join(f.vars["dir"], "nope"))
			},
		},
		{
			name: "get: a database of an older schema",
			setup: migrated(
				stoppedWith(goodPolicy),
				"DELETE FROM migrations WHERE id = (SELECT MAX(id) FROM migrations WHERE id != 'SCHEMA_INIT')",
			),
			args:   "policy get --force" + bypass,
			stderr: "Error: the database's schema is older than this headscale's: it lacks the migration {last}. Run the CLI of the server's version.\n",
			code:   1,
		},
		{
			name: "set: a database of a newer schema",
			setup: migrated(
				stoppedWith("{}"),
				"INSERT INTO migrations (id) VALUES ('999912312359-from-the-future')",
			),
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stderr: "Error: the database has a migration that this headscale does not know: 999912312359-from-the-future. Run the CLI of the server's version.\n",
			code:   1,
		},
		{
			name:   "get: a crash left the newest policy in the write-ahead log",
			setup:  keptFiles(crashed(stoppedWith(goodPolicy))),
			args:   "policy get --force" + bypass,
			stdout: "// newest",
			check:  unchanged,
		},
		{
			name:   "set --dry-run: a crash left the newest policy in the write-ahead log",
			setup:  keptFiles(crashed(stoppedWith(goodPolicy))),
			args:   "policy set {dir}/good.hujson --dry-run --force" + bypass,
			stdout: "Policy is valid for this server. Nothing was changed.\n",
			check:  unchanged,
		},
		{
			name:   "get: a crash left a hot journal",
			setup:  keptFiles(crashed(journal(goodPolicy))),
			args:   "policy get --force" + bypass,
			stderr: unfinished,
			code:   1,
			check:  unchanged,
		},
		{
			name:   "set --dry-run: a crash left a hot journal",
			setup:  keptFiles(crashed(journal(goodPolicy))),
			args:   "policy set {dir}/good.hujson --dry-run --force" + bypass,
			stderr: unfinished,
			code:   1,
			check:  unchanged,
		},
		{
			name:   "set: a program has the database open",
			setup:  held(stoppedWith("{}")),
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stderr: inUse,
			code:   1,
			check:  storedIn("{}"),
		},
		{
			name:   "get: a program has the database open, which a read says",
			setup:  held(stoppedWith(goodPolicy)),
			args:   "policy get --force" + bypass,
			stdout: goodPolicy,
			stderr: "warning: another program has the database {db} open, such as a server: what it stores may not be the policy in force.\n",
		},
		{
			name:   "get: a socket the user may not open",
			setup:  closedSocket(stoppedWith(goodPolicy)),
			args:   "policy get --force" + bypass,
			stderr: closed,
			code:   1,
		},
		{
			name:   "set: a socket the user may not open",
			setup:  closedSocket(stoppedWith("{}")),
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stderr: closed,
			code:   1,
			check:  storedIn("{}"),
		},
		{
			name:   "get: an empty stored policy is not one that allows all",
			setup:  migrated(stoppedWith(goodPolicy), "UPDATE policies SET data = ''"),
			args:   "policy get --force" + bypass,
			stderr: "Error: the stored policy is empty, which the server refuses: policy is empty, use \"{}\" to allow all. Store one with policy set.\n",
			code:   1,
		},
		{
			name:   "get: a file that is not a Headscale database",
			setup:  stoppedWith(""),
			env:    []string{"HEADSCALE_DATABASE_SQLITE_PATH={dir}/good.hujson"},
			args:   "policy get --force" + bypass,
			stderr: "Error: {dir}/good.hujson is not a Headscale database: it is not a SQLite file.\n",
			code:   1,
		},
		{
			name:   "get: the database in a file given by --config",
			setup:  inConfigFile(goodPolicy),
			args:   "policy get --force --config {dir}/hs.yaml" + bypass,
			stdout: goodPolicy,
		},
		{
			name:   "set: the database in a file given by --config",
			setup:  inConfigFile("{}"),
			args:   "policy set {dir}/good.hujson --force --config {dir}/hs.yaml" + bypass,
			stdout: "Policy updated.\n",
		},
		{
			name:     "get: --config - is a file named -, not stdin",
			setup:    stoppedWith(goodPolicy),
			args:     "policy get --config -" + bypass,
			terminal: true,
			stdin:    "n\n",
			stderr:   "Error: the config file - does not exist.\n",
			code:     1,
		},
		{
			name:   "set: a file that is not UTF-8, before the database is opened",
			setup:  stoppedWith(""),
			env:    []string{"HEADSCALE_DATABASE_SQLITE_PATH={dir}/nope/db.sqlite"},
			args:   "policy set {dir}/latin1.hujson --force" + bypass,
			stderr: latin1Refused,
			code:   1,
		},
		{
			name:     "set: stdin on a terminal says how to end it",
			setup:    stoppedWith("{}"),
			args:     "policy set - --force" + bypass,
			terminal: true,
			stdin:    goodPolicy,
			stdout:   "Policy updated.\n",
			stderr:   stdinHint,
			check:    storedIn(goodPolicy),
		},
		{
			name:   "get: controls of a comment into a pipe",
			setup:  stoppedWith(commentEscapes),
			args:   "policy get --force" + bypass,
			stdout: commentEscapes,
		},
		{
			name:     "get: controls of a comment on a terminal",
			setup:    stoppedWith(commentEscapes),
			args:     "policy get --force" + bypass,
			terminal: true,
			stdout:   commentShown,
		},
	}

	// The same lines as the server prints, for the same policy.
	for _, p := range refusedPolicies {
		for _, dry := range []string{"", " --dry-run"} {
			cases = append(cases, cliCase{
				name: "set" + dry + ": " + p.name,
				setup: func(tb testing.TB, f *fixture) {
					tb.Helper()
					stoppedWith("{}")(tb, f)
					file(tb, f, "bad.hujson", p.policy)
				},
				args:   "policy set {dir}/bad.hujson --force" + dry + bypass,
				stderr: "Error: the policy is not valid.\n" + p.lines,
				code:   1,
				check:  storedIn("{}"),
			})
		}
	}

	return cases
}()

// TestPolicyRefusedBothWays: a refused policy prints the same lines through
// the server and through the database bypass, set and --dry-run alike, and
// through check policy.
func TestPolicyRefusedBothWays(t *testing.T) {
	t.Parallel()

	tests, _ := manyTests()

	for _, p := range append(refusedPolicies, struct{ name, policy, lines string }{name: "many tags", policy: manyTags()}, struct{ name, policy, lines string }{name: "many tests", policy: tests}) {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, false)
			policyServer(t, f)
			file(t, f, "bad.hujson", p.policy)

			server := f.run(t, cliCase{args: "policy set {dir}/bad.hujson"})
			require.Equal(t, 1, server.code)
			require.Equal(
				t,
				server.stderr,
				f.run(t, cliCase{args: "policy set {dir}/bad.hujson --dry-run"}).stderr,
				"the server's dry run",
			)

			stopped("database", "{}", withURL)(t, f)

			for _, dry := range []string{"", " --dry-run"} {
				r := f.run(
					t,
					cliCase{args: "policy set {dir}/bad.hujson --force" + dry + bypass},
				)
				require.Equal(t, server.stderr, r.stderr, "the bypass%s", dry)
				require.Equal(t, 1, r.code)
			}

			// check policy says why in the same lines, but of a test that
			// needs a user the server lacks: its stand-ins have every user
			// the policy names.
			if p.name == "a test that cannot run" {
				return
			}

			r := f.run(t, cliCase{args: "check policy {dir}/bad.hujson"})
			require.Equal(t, server.stderr, r.stderr, "check policy")
			require.Equal(t, 1, r.code)
		})
	}
}

// TestPolicyBypass: the same commands on the database of a stopped server,
// with the same output, after a question that --force answers.
func TestPolicyBypass(t *testing.T) {
	t.Parallel()

	runCases(t, policyServer, bypassCases)
}

// TestPolicyRoundTrip: what set takes, get gives back byte for byte into a
// pipe, through the server and through the database bypass: comments,
// tabs, CRLF, text that is not ASCII, a word in the form of a credential,
// with and without a last newline. A terminal shows it as every text.
func TestPolicyRoundTrip(t *testing.T) {
	t.Parallel()

	//nolint:gosec,gosmopolitan // a made-up key, and text that is not ASCII, on purpose
	for name, tt := range map[string]struct{ text, shown string }{
		"crlf, not ascii, a credential": {
			"// hskey-api-abcdefghijkl-notakey\r\n{\r\n\t\"acls\": [], // ½ ✓ 東京\r\n}\r\n",
			"// hskey-api-***\\x0d\n{\\x0d\n\t\"acls\": [], // ½ ✓ 東京\\x0d\n}\\x0d\n",
		},
		"no last newline":    {"/* no last newline */ {\t}", "/* no last newline */ {\t}\n"},
		"many last newlines": {"{}\n\n\n", "{}\n\n\n"},
	} {
		text, shown := tt.text, tt.shown

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, via := range []string{"", bypass + " --force"} {
				f := newFixture(t, false)
				policyServer(t, f)

				if via != "" {
					stopped("database", "", withURL)(t, f)
				}

				file(t, f, "p.hujson", text)

				set := f.run(t, cliCase{args: "policy set {dir}/p.hujson" + via})
				require.Equal(t, 0, set.code, set.stderr)

				get := f.run(t, cliCase{args: "policy get" + via})
				require.Equal(t, 0, get.code, get.stderr)
				require.Equal(t, text, get.stdout, "via %q", via)

				// A terminal shows the text as the CLI shows every text.
				got := f.run(t, cliCase{args: "policy get" + via, terminal: true})
				require.Equal(t, shown, got.stdout, "on a terminal, via %q", via)
			}
		})
	}
}

// TestPolicyExamples runs the examples that name a file in the working
// directory, in one of their own.
func TestPolicyExamples(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("policy.hujson", []byte(goodPolicy), 0o600))
	require.NoError(t, os.WriteFile("p.hujson", []byte(goodPolicy), 0o600))

	for _, tc := range []cliCase{
		{name: "set", args: "policy set policy.hujson", stdout: "Policy updated.\n", check: storedAs(goodPolicy)},
		{name: "set --dry-run", args: "policy set policy.hujson --dry-run", stdout: "Policy is valid for this server. Nothing was changed.\n"},
		{
			name: "get with the bypass", setup: stopped("database", goodPolicy, withURL),
			args: "policy get" + bypass, terminal: true, stdin: "y\n", stdout: goodPolicy, stderr: readsDB,
		},
		{
			name: "set --dry-run with the bypass", setup: stopped("database", "{}", withURL),
			args: "policy set p.hujson --dry-run" + bypass, terminal: true, stdin: "y\n",
			stdout: "Policy is valid for this server. Nothing was changed.\n", stderr: readsDB,
		},
		{
			name: "set with the bypass", setup: stopped("database", "{}", withURL),
			args: "policy set p.hujson" + bypass, terminal: true, stdin: "y\n", stdout: "Policy updated.\n", stderr: writesDB, check: storedIn(goodPolicy),
		},
	} {
		t.Run(tc.name, func(t *testing.T) { runCase(t, policyServer, tc) })
	}
}

// TestPolicyFileMode: with the policy in a file, get prints the file, set
// is refused with its path and --dry-run still checks, and reload says
// whether the file was taken; a refused file leaves the one in force.
func TestPolicyFileMode(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(path, []byte(goodPolicy), 0o600))

	f := newFixture(t, false, servertest.WithPolicyFile(path))
	policyServer(t, f)

	for _, step := range []struct {
		args, stdout, stderr string
		code                 int
		before               string
	}{
		{args: "policy get", stdout: goodPolicy},
		{args: "policy set {dir}/good.hujson", stderr: "Error: the policy is read from " + path + ". Edit that file.\n", code: 1},
		{args: "policy set {dir}/good.hujson --dry-run", stdout: "Policy is valid for this server. Nothing was changed.\n"},
		{args: "policy reload", stdout: "Policy reloaded from " + path + ".\n"},
		{
			before: refusedPolicies[1].policy, args: "policy reload",
			stderr: "Error: the policy is not valid. The old policy is still in use.\n" + refusedPolicies[1].lines, code: 1,
		},
		{args: "policy get", stdout: goodPolicy},
		{args: "debug health", stdout: "healthy\n", stderr: "warning: The policy file is not valid; the last valid policy, or none, is in force.\n  To see why: headscale policy reload\n"},
	} {
		if step.before != "" {
			require.NoError(t, os.WriteFile(path, []byte(step.before), 0o600))
		}

		r := f.run(t, cliCase{args: step.args})
		require.Equal(t, step.stdout, r.stdout, step.args)
		require.Equal(t, step.stderr, r.stderr, step.args)
		require.Equal(t, step.code, r.code, step.args)
	}
}

// TestPolicyHealth: each warning of the policy says what to run.
func TestPolicyHealth(t *testing.T) {
	t.Parallel()

	runCases(t, policyServer, []cliCase{
		{
			name: "a name two users have",
			args: "debug health",
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()

				st := f.srv.State()

				_, _, err := st.CreateUser(types.User{Name: "alice"})
				require.NoError(tb, err)
				inForce(
					`{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["*:*"]}]}`,
				)(
					tb,
					f,
				)

				_, _, err = st.CreateUser(types.User{
					Name:     "alice",
					Provider: util.RegisterMethodOIDC,
					ProviderIdentifier: sql.NullString{
						String: "https://idp.example.com/alice",
						Valid:  true,
					},
				})
				require.NoError(tb, err)
			},
			stdout: "healthy\n",
			stderr: "warning: The policy in force names 1 text that more than one user matches; it matches nobody.\n" +
				"  To see them: headscale policy get | headscale policy set - --dry-run\n",
		},
	})
}

// TestVerbatimCommands: the commands that print a text of the server past
// the rule that masks a credential, each with why.
func TestVerbatimCommands(t *testing.T) {
	t.Parallel()

	// A Text is printed as a Verbatim text is.
	check := "a line of the check itself, which names the file as typed"
	file := "a file it makes: what is written to a file must be what was made"
	why := map[string]string{
		"policy get":             "a changed byte is a changed policy: get > file must give back what set took",
		"check config":           check,
		"check policy":           check,
		"check derp-map":         check,
		"check extra-records":    check,
		"check all":              "its report, which names the files of the config as written there",
		"generate private-key":   file,
		"generate config":        file + "; with --running the server's, which redacts its secrets",
		"generate nixos-options": file,
		"generate cli-reference": file,
		"generate man":           file,
	}

	for _, c := range Tree().Commands() {
		if c.Verbatim {
			require.NotEmpty(
				t,
				why[c.Path],
				"%s prints a text verbatim and is not on the list",
				c.Path,
			)
			delete(why, c.Path)
		}
	}

	require.Empty(t, why, "on the list and printing nothing verbatim")
}

// childLine is the line a run of the test binary as the CLI runs, as JSON;
// childRelease is the version that run claims.
const (
	childLine    = "HEADSCALE_TEST_CHILD_LINE"
	childRelease = "HEADSCALE_TEST_CHILD_RELEASE"
)

// child runs line as the binary would, with the log a server sets up: a
// console on stderr at trace, so any line the server's packages log shows.
func child(line string) int {
	var args []string

	err := json.Unmarshal([]byte(line), &args)
	if err != nil {
		panic(err)
	}

	zerolog.SetGlobalLevel(zerolog.TraceLevel)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true})

	if v := os.Getenv(childRelease); v != "" {
		types.GetVersionInfo = func() *types.VersionInfo { return &types.VersionInfo{Version: v} }
	}

	return command.Run(Tree(), args, command.OSEnv())
}

// TestPolicyBypassAsAProcess runs the bypass as a person does, a process of
// its own built as a release: stderr holds what the command says and no
// line of the server's log, and a read changes no byte of the database
// file. A write is refused while this process holds the database open, as
// a server does, and so is a database that another minor version opened.
func TestPolicyBypassAsAProcess(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, args, stdout, stderr string
		setup                      func(testing.TB, *fixture)
		check                      func(testing.TB, *fixture, result)
	}{
		{name: "get", args: "policy get --force" + bypass, stdout: goodPolicy, check: unchanged},
		{name: "set --dry-run", args: "policy set {dir}/good.hujson --dry-run --force" + bypass, stdout: "Policy is valid for this server. Nothing was changed.\n", check: unchanged},
		{name: "set", args: "policy set {dir}/good.hujson --force" + bypass, stdout: "Policy updated.\n", check: storedIn(goodPolicy)},
		{name: "set -o json", args: "policy set {dir}/good.hujson --force -o json" + bypass, check: storedIn(goodPolicy)},
		{
			name: "set while another process has the database open", setup: held(stoppedWith("{}")),
			args: "policy set {dir}/good.hujson --force" + bypass, stderr: inUse, check: storedIn("{}"),
		},
		{
			name: "get of a database another minor version opened", setup: migrated(stoppedWith(goodPolicy), "INSERT INTO database_versions (id, version, updated_at) VALUES (1, 'v0.29.5', CURRENT_TIMESTAMP) ON CONFLICT (id) DO UPDATE SET version = excluded.version"),
			args:   "policy get --force" + bypass,
			stderr: "Error: the database was last opened by headscale v0.29.5, and this CLI is v0.30.0. Run the CLI of headscale v0.29.5.\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, false)
			policyServer(t, f)

			setup := tc.setup
			if setup == nil {
				setup = stoppedWith(goodPolicy)
			}

			keptFiles(setup)(t, f)

			line, err := json.Marshal(words(f.expand(tc.args)))
			require.NoError(t, err)

			var stdout, stderr bytes.Buffer

			//nolint:gosec // the test binary itself
			cmd := exec.CommandContext(t.Context(), os.Args[0])

			cmd.Env = append(
				slices.Clone(f.env),
				childLine+"="+string(line),
				childRelease+"=v0.30.0",
				"PATH="+os.Getenv("PATH"),
			)
			cmd.Stdout, cmd.Stderr = &stdout, &stderr

			err = cmd.Run()

			require.Equal(t, f.expand(tc.stderr), stderr.String())

			if tc.stderr != "" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tc.stdout != "" {
				require.Equal(t, tc.stdout, stdout.String())
			}

			if tc.check != nil {
				tc.check(t, f, result{})
			}
		})
	}
}

// TestPolicyBypassPostgres runs the bypass on PostgreSQL through the
// commands: the same reads, checks and write as on SQLite, and a write
// says how many other sessions have the database open, since a server on
// another host is one that the socket does not see.
func TestPolicyBypassPostgres(t *testing.T) {
	t.Parallel()

	srv, err := postgrestest.Start(t.Context())
	if err != nil {
		t.Skipf("start postgres: %s", err)
	}

	t.Cleanup(srv.Cleanup)

	raw, err := srv.CreateDatabase(t.Context())
	require.NoError(t, err)
	t.Logf("created local postgres: %s", raw)

	u, err := url.Parse(raw)
	require.NoError(t, err)

	pass, _ := u.User.Password()

	f := newFixture(t, false)
	policyServer(t, f)

	f.env = append(f.env,
		"HEADSCALE_UNIX_SOCKET=/nonexistent/headscale.sock",
		"HEADSCALE_NOISE_PRIVATE_KEY_PATH="+filepath.Join(f.vars["dir"], "noise.key"),
		"HEADSCALE_POLICY_MODE=database",
		withURL,
		"HEADSCALE_DATABASE_TYPE=postgres",
		"HEADSCALE_DATABASE_POSTGRES_HOST="+u.Hostname(),
		"HEADSCALE_DATABASE_POSTGRES_PORT="+u.Port(),
		"HEADSCALE_DATABASE_POSTGRES_NAME="+strings.TrimPrefix(u.Path, "/"),
		"HEADSCALE_DATABASE_POSTGRES_USER="+u.User.Username(),
		"HEADSCALE_DATABASE_POSTGRES_PASS="+pass,
		"HEADSCALE_DATABASE_POSTGRES_SSL=disable",
	)

	d := openStopped(t, f)
	d.CreateRegisteredNodeForTest(d.CreateUserForTest("bob"), "bob-laptop")
	_, err = d.SetPolicy("{}")
	require.NoError(t, err)
	require.NoError(t, d.Close())

	file(t, f, "bad.hujson", refusedPolicies[1].policy)

	// A session that ended leaves pg_stat_activity once its backend has.
	alone := func() {
		t.Helper()

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			n, err := offline.Sessions(t.Context(), "", f.env)
			assert.NoError(c, err)
			assert.Zero(c, n)
		}, 10*time.Second, 50*time.Millisecond)
	}

	step := func(tc cliCase) {
		t.Helper()

		r := f.run(t, tc)
		want := f.expand(tc.stdout)

		if tc.want != nil {
			want = tc.want(t, f, r)
		}

		require.Equal(t, want, r.stdout, tc.args)
		require.Equal(t, f.expand(tc.stderr), r.stderr, tc.args)
		require.Equal(t, tc.code, r.code, tc.args)

		if tc.check != nil {
			tc.check(t, f, r)
		}
	}

	step(cliCase{args: "policy get --force" + bypass, stdout: "{}"})
	step(
		cliCase{
			args:   "policy set {dir}/good.hujson --dry-run --force" + bypass,
			stdout: "Policy is valid for this server. Nothing was changed.\n",
			check:  storedIn("{}"),
		},
	)
	step(
		cliCase{
			args:   "policy set {dir}/bad.hujson --force" + bypass,
			stderr: "Error: the policy is not valid.\n" + refusedPolicies[1].lines,
			code:   1,
			check:  storedIn("{}"),
		},
	)

	// PostgreSQL cannot store a NUL; the check refuses it before the store.
	file(t, f, "nul.hujson", "{\"acls\": []}\n// \x00\n")
	step(
		cliCase{
			args:   "policy set {dir}/nul.hujson --force" + bypass,
			stderr: "Error: the policy is not valid.\n  line 2, column 4: the text has a NUL byte, which a policy cannot hold; remove it\n",
			code:   1,
			check:  storedIn("{}"),
		},
	)

	alone()
	step(
		cliCase{
			args:     "policy set {dir}/good.hujson" + bypass,
			terminal: true,
			stdin:    "n\n",
			stderr:   writesDB + "Aborted.\n",
			code:     1,
		},
	)

	// A server, here or on another host, holds a session.
	server := openStopped(t, f)
	serverDB, err := server.DB.DB()
	require.NoError(t, err)
	conn, err := serverDB.Conn(t.Context())
	require.NoError(t, err)

	step(cliCase{
		args:     "policy set {dir}/good.hujson" + bypass,
		terminal: true,
		stdin:    "n\n",
		code:     1,
		stderr: "This writes the policy to the database directly. Headscale must not be running.\n" +
			"The database has 1 other session open; a server on another host would be one, and cannot be told from another client.\n" +
			"Continue? [y/N] Aborted.\n",
	})
	step(
		cliCase{
			args:   "policy set {dir}/good.hujson --force" + bypass,
			stdout: "Policy updated.\n",
		},
	)

	require.NoError(t, conn.Close())
	require.NoError(t, server.Close())

	step(cliCase{args: "policy get --force" + bypass, stdout: goodPolicy})
	step(cliCase{args: "policy get --force -o json" + bypass, want: bypassJSON})
}
