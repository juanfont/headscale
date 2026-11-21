package newcli

import (
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

var debugCases = []cliCase{
	{name: "healthy", args: "debug health", stdout: "healthy\n"},
	{name: "-o json is GET /health as it is", args: "debug health -o json", stdout: `{
  "healthy": true,
  "databaseConnectivity": true,
  "warnings": []
}
`},
	{
		name:   "the old name points here",
		args:   "health",
		stderr: "Error: unknown command \"health\". It is now \"debug health\".\nRun `headscale debug health --help`.\n",
		code:   1,
	},
	{name: "a typo gets a did you mean", args: "debug helth", stderr: "Error: unknown command \"debug helth\". Did you mean \"debug health\"?\nRun `headscale debug --help`.\n", code: 1},
	{
		name:   "a 200 that says unhealthy is refused",
		setup:  unhealthy,
		args:   "debug health",
		env:    []string{"HEADSCALE_CLI_ADDRESS={unhealthy}", "HEADSCALE_CLI_API_KEY=key"},
		stderr: "Error: the server is not healthy.\n",
		code:   1,
	},
	{
		name:   "a warning goes to stderr and is no failure",
		setup:  badNodes,
		args:   "debug health",
		stdout: "healthy\n",
		stderr: "warning: 2 nodes have a name that is not valid.\n  To see them: headscale nodes list --filter problems=node_name_invalid\n" +
			"warning: 1 node has a key expiry that is not valid.\n  To see them: headscale nodes list --filter problems=node_expiry_invalid\n",
	},
	{
		name: "the command a warning names shows those nodes", setup: badNodes, args: "nodes list --filter problems=node_name_invalid --columns id,problems",
		stdout: "ID  PROBLEMS\n41  node_name_invalid\n42  node_name_invalid\n",
	},
	{name: "with -o json the warnings are in the object only", setup: badNodes, args: "debug health -o json", want: answer("/api/headscale/v0/health")},
}

var debugCreateNodeCases = []cliCase{
	{
		name: "the example: a registration waits", args: "debug create-node --name fake-1 --key " + exampleID,
		stdout: "Registration of \"fake-1\" waits: headscale auth register <auth-id> <user> answers it.\n", check: waiting(exampleID, true),
	},
	{
		name: "the example with routes", args: "debug create-node --name fake-2 --key " + exampleID + " --route 10.0.0.0/8,192.168.0.0/24",
		stdout: "Registration of \"fake-2\" waits: headscale auth register <auth-id> <user> answers it.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			r := f.run(tb, cliCase{args: "auth register " + exampleID + " alice -o json"})
			require.Equal(tb, 0, r.code, r.stderr)
			require.Contains(tb, r.stdout, `"hostname": "fake-2"`)
			require.Contains(tb, r.stdout, `"10.0.0.0/8"`)
		},
	},
	{name: "--name is required", args: "debug create-node --key " + exampleID, stderr: "Error: --name is required: the hostname of the made-up node.\n", code: 1, check: asked()},
	{name: "--key is required", args: "debug create-node --name fake-1", stderr: "Error: --key is required: the auth ID it waits under.\n", code: 1, check: asked()},
	{name: "--key takes an auth ID", args: "debug create-node --name fake-1 --key 12", stderr: "Error: --key " + notAuthID, code: 1, check: asked()},
	{
		name: "--key takes no other credential", args: "debug create-node --name fake-1 --key hskey-api-ab12cd345678-S3cr3tS3cr3t",
		stderr: "Error: --key takes only a credential hskey-authreq-: hskey-api-*** is not sent.\n", code: 1, check: asked(),
	},
	{
		name: "an ID that waits already", args: "debug create-node --name fake-1 --key " + exampleID, setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			pending(tb, f, exampleID, "newlaptop")
		},
		stderr: "Error: the server refused a value:\n  --key: an auth request has this ID\n", code: 1,
	},
	{
		name: "the example as written: an ID it makes", args: `debug create-node --name fake-1 --key "hskey-authreq-$(openssl rand -hex 12)"`,
		stdout: "Registration of \"fake-1\" waits: headscale auth register <auth-id> <user> answers it.\n",
	},
	{
		name: "the help shows the example that makes an ID as it runs", args: "debug create-node --help",
		want: func(_ testing.TB, _ *fixture, r result) string { return r.stdout },
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(tb, r.stdout, `headscale debug create-node --name fake-1 --key "hskey-authreq-$(openssl rand -hex 12)"`)
		},
	},
	{
		name: "a list of routes is sent as a list", args: "debug create-node --name fake-2 --key " + exampleID + " --route 10.0.0.0/8,192.168.0.0/24",
		stdout: "Registration of \"fake-2\" waits: headscale auth register <auth-id> <user> answers it.\n",
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(tb, r.sent, "POST "+v0+"/debug/nodes "+`{"authId":"`+exampleID+`","hostname":"fake-2","routes":["10.0.0.0/8","192.168.0.0/24"]}`)
		},
	},
	{
		name: "--route given twice", args: "debug create-node --name fake-1 --key " + exampleID + " --route 10.0.0.0/8 --route 192.168.0.0/24",
		stderr: "Error: --route is given twice. Only --filter may be repeated.\n", code: 1, check: asked(),
	},
	{
		name: "a page of HTML is no success", args: "debug create-node --name fake-1 --key " + exampleID, setup: html,
		env:    []string{"HEADSCALE_CLI_ADDRESS={proxy}", "HEADSCALE_CLI_API_KEY={apikey}"},
		stderr: "Error: the server at {proxyhost} sent an answer this CLI cannot read: it is not JSON.\n", code: 1,
	},
	{
		name: "the cache of auth requests is full", args: "debug create-node --name fake-1 --key " + exampleID, setup: fullCache,
		stderr: "Error: the server holds as many auth requests as it takes. Answer some, or wait until they time out, then run the command again.\n", code: 1,
		check: waiting(exampleID, false),
	},
	{name: "a test tool has no -o json", args: "debug create-node --name fake-1 --key " + exampleID + " -o json", stderr: "Error: --output does not apply to `debug create-node`.\nRun `headscale debug create-node --help`.\n", code: 1},
}

// fullCache fills the server's auth requests up to its cap.
func fullCache(tb testing.TB, f *fixture) {
	tb.Helper()

	for {
		err := f.srv.State().SetAuthCacheEntry(types.MustAuthID(), types.NewRegisterAuthRequest(&types.RegistrationData{Hostname: "filler"}))
		if errors.Is(err, state.ErrAuthCacheFull) {
			return
		}

		require.NoError(tb, err)
	}
}

func TestDebugCreateNode(t *testing.T) {
	t.Parallel()

	runCases(t, func(tb testing.TB, f *fixture) {
		tb.Helper()
		f.srv.CreateUser(tb, "alice")
	}, debugCreateNodeCases)
}

// TestNoJSON lists every command that takes no --output, with why; a
// command that opts out and is not here fails.
func TestNoJSON(t *testing.T) {
	t.Parallel()

	why := map[string]string{
		"debug create-node": "a test tool: 001 has the debug test tools opt out of --output, and its answer holds the auth ID",
	}

	var got []string

	for _, c := range Tree().Commands() {
		if c.NoJSON {
			got = append(got, c.Path)
		}
	}

	require.ElementsMatch(t, slices.Collect(maps.Keys(why)), got)
}

func TestDebugHealth(t *testing.T) {
	t.Parallel()

	runCases(t, nil, debugCases)
}

// unhealthy is a server that answers 200 and says it is not healthy.
func unhealthy(tb testing.TB, f *fixture) {
	tb.Helper()

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Headscale-Version", types.GetVersionInfo().Version)
		_, _ = w.Write([]byte(`{"healthy": false, "databaseConnectivity": false, "warnings": []}`))
	}))
	tb.Cleanup(s.Close)

	f.vars["unhealthy"] = s.URL
}

// badNodes are nodes whose stored data is not valid.
func badNodes(tb testing.TB, f *fixture) {
	tb.Helper()

	user := f.srv.CreateUser(tb, "user")
	tooLong := strings.Repeat("a", 300)

	for _, n := range []*types.Node{
		{ID: 41, UserID: &user.ID, GivenName: tooLong},
		{ID: 42, UserID: &user.ID, GivenName: tooLong + "b"},
		{ID: 43, UserID: &user.ID, GivenName: "ok", Expiry: new(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))},
	} {
		f.srv.State().PutNodeInStoreForTest(*n)
	}
}
