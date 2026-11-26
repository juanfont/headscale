package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strconv"
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
	{
		name:   "a typo gets a did you mean",
		args:   "debug helth",
		stderr: "Error: unknown command \"debug helth\". Did you mean \"debug health\"?\nRun `headscale debug --help`.\n",
		code:   1,
	},
	{
		name:  "a 200 that says unhealthy is refused",
		setup: unhealthy,
		args:  "debug health",
		env: []string{
			"HEADSCALE_CLI_ADDRESS={unhealthy}",
			"HEADSCALE_CLI_API_KEY=key",
		},
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
		name:   "the command a warning names shows those nodes",
		setup:  badNodes,
		args:   "nodes list --filter problems=node_name_invalid --columns id,problems",
		stdout: "ID  PROBLEMS\n41  node_name_invalid\n42  node_name_invalid\n",
	},
	{
		name:  "with -o json the warnings are in the object only",
		setup: badNodes,
		args:  "debug health -o json",
		want:  answer("/api/headscale/v0/health"),
	},
}

var debugCreateNodeCases = []cliCase{
	{
		name:   "the example: a registration waits",
		args:   "debug create-node --name fake-1 --key " + exampleID,
		stdout: "Registration of \"fake-1\" waits: headscale auth register <auth-id> <user> answers it.\n",
		check:  waiting(exampleID, true),
	},
	{
		name:   "the example with routes",
		args:   `debug create-node --name fake-2 --key "$id" --route 10.0.0.0/8,192.168.0.0/24`,
		setup:  idVar,
		stdout: "Registration of \"fake-2\" waits: headscale auth register <auth-id> <user> answers it.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			r := f.run(
				tb,
				cliCase{args: "auth register " + exampleID + " alice -o json"},
			)
			require.Equal(tb, 0, r.code, r.stderr)
			require.Contains(tb, r.stdout, `"hostname": "fake-2"`)
			require.Contains(tb, r.stdout, `"10.0.0.0/8"`)
		},
	},
	{
		name:   "--name is required",
		args:   "debug create-node --key " + exampleID,
		stderr: "Error: --name is required: the hostname of the made-up node.\n",
		code:   1,
		check:  asked(),
	},
	{
		name:   "--key is required",
		args:   "debug create-node --name fake-1",
		stderr: "Error: --key is required: the auth ID it waits under.\n",
		code:   1,
		check:  asked(),
	},
	{
		name:   "--key takes an auth ID",
		args:   "debug create-node --name fake-1 --key 12",
		stderr: "Error: --key " + notAuthID,
		code:   1,
		check:  asked(),
	},
	{
		name:   "--key takes no other credential",
		args:   "debug create-node --name fake-1 --key hskey-api-ab12cd345678-S3cr3tS3cr3t",
		stderr: "Error: --key takes only a credential hskey-authreq-: hskey-api-*** is not sent.\n",
		code:   1,
		check:  asked(),
	},
	{
		name: "an ID that waits already",
		args: "debug create-node --name fake-1 --key " + exampleID,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			pending(tb, f, exampleID, "newlaptop")
		},
		stderr: "Error: the server refused a value:\n  --key: an auth request has this ID\n",
		code:   1,
	},
	{
		name: "the help's script as written: the ID in a variable, then both commands",
		args: `debug create-node --name fake-1 --key "$id"`,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()

			f.vars["id"] = "hskey-authreq-" + strings.Repeat("ab", 12)
		},
		stdout: "Registration of \"fake-1\" waits: headscale auth register <auth-id> <user> answers it.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			r := f.run(tb, cliCase{args: `auth register "$id" alice`})
			require.Equal(tb, 0, r.code, r.stderr)
			require.Contains(tb, r.stdout, "(fake-1) registered to User 1 (alice).")
		},
	},
	{
		name: "the help shows the script that keeps the ID",
		args: "debug create-node --help",
		want: func(_ testing.TB, _ *fixture, r result) string { return r.stdout },
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(
				tb,
				r.stdout,
				"  id=\"hskey-authreq-$(openssl rand -hex 12)\"\n  headscale debug create-node --name fake-1 --key \"$id\"\n  headscale auth register \"$id\" alice\n",
			)
		},
	},
	{
		name:   "a list of routes is sent as a list",
		args:   "debug create-node --name fake-2 --key " + exampleID + " --route 10.0.0.0/8,192.168.0.0/24",
		stdout: "Registration of \"fake-2\" waits: headscale auth register <auth-id> <user> answers it.\n",
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Contains(
				tb,
				r.sent,
				"POST "+v0+"/debug/nodes "+`{"authId":"`+exampleID+`","hostname":"fake-2","routes":["10.0.0.0/8","192.168.0.0/24"]}`,
			)
		},
	},
	{
		name:   "--route given twice",
		args:   "debug create-node --name fake-1 --key " + exampleID + " --route 10.0.0.0/8 --route 192.168.0.0/24",
		stderr: "Error: --route is given twice. Only --filter may be repeated.\n",
		code:   1,
		check:  asked(),
	},
	{
		name:  "a page of HTML is no success",
		args:  "debug create-node --name fake-1 --key " + exampleID,
		setup: html,
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: "Error: the server at {proxyhost} sent an answer this CLI cannot read: it is not JSON.\n" +
			"The change may have been made: look before you run the command again.\n",
		code: 1,
	},
	{
		name:   "the cache of auth requests is full",
		args:   "debug create-node --name fake-1 --key " + exampleID,
		setup:  fullCache,
		stderr: "Error: the server holds as many auth requests as it takes. Answer some, or wait until they time out, then run the command again.\n",
		code:   1,
		check:  waiting(exampleID, false),
	},
	{
		name:   "a test tool has no -o json",
		args:   "debug create-node --name fake-1 --key " + exampleID + " -o json",
		stderr: "Error: --output does not apply to `debug create-node`.\nRun `headscale debug create-node --help`.\n",
		code:   1,
	},
}

// fullCache fills the server's auth requests up to its cap.
func fullCache(tb testing.TB, f *fixture) {
	tb.Helper()

	for {
		err := f.srv.State().
			SetAuthCacheEntry(types.MustAuthID(), types.NewRegisterAuthRequest(&types.RegistrationData{Hostname: "filler"}))
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

	s := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Headscale-Version", types.GetVersionInfo().Version)
			_, _ = w.Write(
				[]byte(
					`{"healthy": false, "databaseConnectivity": false, "warnings": []}`,
				),
			)
		}),
	)
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

// mockOIDCEnv sets up debug mockoidc on a free port, which {port} names.
func mockOIDCEnv(tb testing.TB, f *fixture) {
	tb.Helper()

	l, err := new(net.ListenConfig).Listen(tb.Context(), "tcp", "127.0.0.1:0")
	require.NoError(tb, err)

	addr, ok := l.Addr().(*net.TCPAddr)
	require.True(tb, ok)

	f.vars["port"] = strconv.Itoa(addr.Port)

	require.NoError(tb, l.Close())
}

// servesDiscovery waits until the mock OIDC server at {port} answers its
// discovery document, and keeps its issuer as {issuer}.
func servesDiscovery(ctx context.Context, f *fixture) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	url := "http://127.0.0.1:" + f.vars["port"] + "/oidc/.well-known/openid-configuration"

	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			var doc struct {
				Issuer string `json:"issuer"`
			}

			_ = json.NewDecoder(resp.Body).Decode(&doc)
			resp.Body.Close()

			f.vars["issuer"] = doc.Issuer

			return
		}

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

var mockOIDCEnvs = []string{
	"MOCKOIDC_ADDR=127.0.0.1", "MOCKOIDC_PORT={port}", "MOCKOIDC_CLIENT_ID=superclient",
	"MOCKOIDC_CLIENT_SECRET=supersecret", "MOCKOIDC_USERS=[]",
}

var mockOIDCCases = []cliCase{
	{
		name:  "serves until it is stopped",
		args:  "debug mockoidc",
		env:   mockOIDCEnvs,
		until: servesDiscovery,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()
			require.Equal(
				tb,
				"http://127.0.0.1:"+f.vars["port"]+"/oidc",
				f.vars["issuer"],
			)
		},
	},
	{
		name:   "a variable that is missing",
		args:   "debug mockoidc",
		code:   1,
		stderr: "Error: running mock OIDC server: MOCKOIDC_CLIENT_ID not defined\n",
	},
	{
		name:   "users that are not JSON",
		args:   "debug mockoidc",
		env:    append(slices.Clone(mockOIDCEnvs), "MOCKOIDC_USERS=x"),
		code:   1,
		stderr: "Error: running mock OIDC server: unmarshalling users: invalid character 'x' looking for beginning of value\n",
	},
	{
		name:   "reads no config",
		args:   "debug mockoidc -c x.yaml",
		code:   1,
		stderr: "Error: --config does not apply to `debug mockoidc`.\nRun `headscale debug mockoidc --help`.\n",
	},
	{
		name:   "no --output",
		args:   "debug mockoidc -o json",
		code:   1,
		stderr: "Error: --output does not apply to `debug mockoidc`.\nRun `headscale debug mockoidc --help`.\n",
	},
	{
		name:   "the old name points here",
		args:   "mockoidc",
		code:   1,
		stderr: "Error: unknown command \"mockoidc\". It is now \"debug mockoidc\".\nRun `headscale debug mockoidc --help`.\n",
	},
}

func TestDebugMockOIDC(t *testing.T) {
	t.Parallel()

	runCases(t, mockOIDCEnv, mockOIDCCases)
}

// TestMockOIDCLogs runs debug mockoidc as a process: it logs that it
// listens, as the old mockoidc does, though every command starts with the
// log off.
func TestMockOIDCLogs(t *testing.T) {
	t.Parallel()

	f := &fixture{vars: map[string]string{}}
	mockOIDCEnv(t, f)

	line, err := json.Marshal([]string{"debug", "mockoidc"})
	require.NoError(t, err)

	// A server that never says it listens is stopped, and the test fails.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0]) //nolint:gosec // this test binary
	cmd.Env = []string{"HOME=" + t.TempDir(), childLine + "=" + string(line)}

	for _, e := range mockOIDCEnvs {
		cmd.Env = append(cmd.Env, f.expand(e))
	}

	stderr, err := cmd.StderrPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	var seen []string

	for s := bufio.NewScanner(stderr); s.Scan(); {
		seen = append(seen, s.Text())
		if strings.Contains(
			s.Text(),
			"mock OIDC server listening on 127.0.0.1:"+f.vars["port"],
		) {
			return
		}
	}

	t.Fatalf("no line says the server listens; stderr:\n%s", strings.Join(seen, "\n"))
}
