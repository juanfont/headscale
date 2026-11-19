package newcli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
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
		stderr: "warning: 2 nodes have a name that is not valid.\nwarning: 1 node has a key expiry that is not valid.\n",
	},
	{name: "with -o json the warnings are in the object only", setup: badNodes, args: "debug health -o json", want: answer("/api/headscale/v0/health")},
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
