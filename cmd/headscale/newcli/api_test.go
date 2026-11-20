package newcli

import (
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

var apiCases = []cliCase{
	{
		name: "over the socket",
		args: "api whoami",
		stdout: `Principal:   local (unix socket)
Scopes:      all
Tags:        any
Resources:   all
`,
	},
	{
		name: "an API key",
		args: "api whoami",
		env:  []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={apikey}"},
		stdout: `Principal:   API key
Credential:  API key {apikeyid} ({apikeyprefix})
Key owner:   User {bobid} (bob)
Scopes:      all
Tags:        any
Resources:   all
Expiry:      {apikeyexpiry}
`,
	},
	{
		name: "an API key with no owner",
		args: "api whoami",
		env:  []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={lonekey}"},
		stdout: `Principal:   API key
Credential:  API key {lonekeyid} ({lonekeyprefix})
Key owner:   none
Scopes:      all
Tags:        any
Resources:   all
Expiry:      {apikeyexpiry}
`,
	},
	{
		name: "an access token of an OAuth client",
		args: "api whoami",
		env:  []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"},
		stdout: `Principal:   OAuth client
Credential:  OAuth access token {tokenid} ({tokenprefix})
Client:      {clientid} (ci)
Scopes:      users:read
Tags:        none
Resources:   all
Expiry:      {tokenexpiry}
`,
	},
	{name: "-o json is GET /me as it is", args: "api whoami -o json", want: answer("/api/headscale/v0/me")},
	{
		name:   "a key the server does not accept",
		args:   "api whoami",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY=hskey-api-abcdefghijkl-nope"},
		stderr: "Error: the server did not accept the API key.\n",
		code:   1,
	},
	{
		name:   "a remote server needs a key",
		args:   "api whoami",
		env:    []string{"HEADSCALE_CLI_ADDRESS={url}"},
		stderr: "Error: a remote server needs an API key: set HEADSCALE_CLI_API_KEY, or cli.api_key in the config\n",
		code:   1,
	},
	{
		name: "no server",
		args: "api whoami",
		env:  []string{"HEADSCALE_UNIX_SOCKET=/nonexistent/headscale.sock", "HEADSCALE_CLI_TIMEOUT=100ms"},
		stderr: `Error: cannot connect to /nonexistent/headscale.sock: no such file or directory
Is headscale running? To use another server:
  --config <file>, HEADSCALE_UNIX_SOCKET, or HEADSCALE_CLI_ADDRESS
`,
		code: 1,
	},
	{
		name:   "a config file that does not exist",
		args:   "api whoami -c /nonexistent.yaml",
		stderr: "Error: the config file /nonexistent.yaml does not exist.\n",
		code:   1,
	},
	{
		name:   "HEADSCALE_CONFIG of the case wins",
		args:   "api whoami",
		env:    []string{"HEADSCALE_CONFIG=/nonexistent.yaml"},
		stderr: "Error: the config file /nonexistent.yaml does not exist.\n",
		code:   1,
	},
	{name: "the group shows its help", args: "api", stdout: `Authentication towards the headscale API

Commands:

  whoami   Show what the CLI is connected as

Examples:

  headscale api whoami
`},
	{name: "takes no arguments", args: "api whoami me", stderr: "Error: `api whoami` takes no arguments, got 1.\n\n  headscale api whoami\n", code: 1},
}

func TestAPIWhoami(t *testing.T) {
	t.Parallel()

	runCases(t, whoamiSetup, apiCases)
}

// whoamiSetup makes a user, an API key with that owner, one with none, and
// an access token of an OAuth client.
func whoamiSetup(tb testing.TB, f *fixture) {
	tb.Helper()

	st := f.srv.State()
	bob := f.srv.CreateUser(tb, "bob")

	keyExpiry := f.now.Add(60*24*time.Hour + time.Minute)
	apiKey, key, err := st.CreateAPIKey(&keyExpiry)
	require.NoError(tb, err)
	require.NoError(tb, st.SetAPIKeyUser(key.ID, types.UserID(bob.ID)))

	loneKey, lone, err := st.CreateAPIKey(&keyExpiry)
	require.NoError(tb, err)

	_, client, err := st.CreateOAuthClient([]string{"users:read"}, nil, "ci", nil)
	require.NoError(tb, err)

	tokenExpiry := f.now.Add(time.Hour + time.Minute)
	token, tok, err := st.MintAccessToken(client.ClientID, []string{"users:read"}, nil, &tokenExpiry)
	require.NoError(tb, err)

	f.vars["bobid"] = strconv.FormatUint(uint64(bob.ID), 10)
	f.vars["apikey"] = apiKey
	f.vars["apikeyid"] = strconv.FormatUint(key.ID, 10)
	f.vars["apikeyprefix"] = key.Prefix
	f.vars["apikeyexpiry"] = table.When(keyExpiry, f.now)
	f.vars["lonekey"] = loneKey
	f.vars["lonekeyid"] = strconv.FormatUint(lone.ID, 10)
	f.vars["lonekeyprefix"] = lone.Prefix
	f.vars["token"] = token
	f.vars["tokenid"] = strconv.FormatUint(tok.ID, 10)
	f.vars["tokenprefix"] = tok.Prefix
	f.vars["tokenexpiry"] = table.When(tokenExpiry, f.now)
	f.vars["clientid"] = client.ClientID
}
