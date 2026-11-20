package newcli

import (
	"cmp"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/hscontrol/servertest"
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

  whoami                          Show what the CLI is connected as
  keys list                       List the API keys (alias: ls)
  keys get <key>                  Show one API key
  keys create                     Create an API key
  keys delete <key>               Revoke an API key (alias: rm)
  oauth-clients list              List the OAuth clients (alias: ls)
  oauth-clients get <client>      Show one OAuth client
  oauth-clients create <scopes>   Create an OAuth client
  oauth-clients delete <client>   Revoke an OAuth client (alias: rm)

Examples:

  headscale api whoami
  headscale api keys list
  headscale api keys get 2
  headscale api keys create
  headscale api keys delete tr81ys
  headscale api oauth-clients list
  headscale api oauth-clients get c9f2aa000001
  headscale api oauth-clients create devices:core:read
  headscale api oauth-clients delete c9f2aa000001
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

// credring is keyring with API keys and OAuth clients in every state: API
// keys 1 (no owner) and 2 (bob) valid, 10 revoked a day ago, 11 expired;
// clients c9f2aa000001 and c9f2aa000002 valid, d0d0aa000003 revoked a day
// ago. Four rows are two pages of the fixture's walk.
func credring(tb testing.TB, f *fixture) {
	tb.Helper()

	keyring(tb, f)

	day := 24 * time.Hour
	at := func(d time.Duration) *time.Time { return new(f.now.Add(d)) }
	user := func(id uint) *uint { return &id }

	for _, k := range []types.Credential{
		{ID: 1, Kind: types.CredentialAPIKey, Identifier: "mk40pz", Expiration: at(89 * day), CreatedAt: at(-day), LastSeen: at(-2 * time.Minute)},
		{ID: 2, Kind: types.CredentialAPIKey, Identifier: "tr81ys", UserID: user(4), Expiration: at(60 * day), CreatedAt: at(-30 * day), LastSeen: at(-time.Minute)},
		{ID: 10, Kind: types.CredentialAPIKey, Identifier: "qq11rr", UserID: user(3), Expiration: at(5 * day), CreatedAt: at(-2 * day), Revoked: at(-day)},
		{ID: 11, Kind: types.CredentialAPIKey, Identifier: "xx22yy", Expiration: at(-3 * day), CreatedAt: at(-33 * day)},
		{ID: 12, Kind: types.CredentialOAuthClient, Identifier: "c9f2aa000001", Scopes: []string{"auth_keys", "devices:core"}, Tags: []string{"tag:ci"}, Description: "CI", UserID: user(3), CreatedAt: at(-12 * day)},
		{ID: 13, Kind: types.CredentialOAuthClient, Identifier: "c9f2aa000002", Scopes: []string{"devices:core:read"}, CreatedAt: at(-2 * day)},
		{ID: 14, Kind: types.CredentialOAuthClient, Identifier: "d0d0aa000003", Scopes: []string{"users:read"}, CreatedAt: at(-3 * day), Revoked: at(-day)},
	} {
		k.Hash = []byte("$sha256$none")
		require.NoError(tb, f.srv.State().DB().DB.Create(&k).Error)
	}

	for name, t := range map[string]time.Time{"in60d": f.now.Add(60 * day), "ago30d": f.now.Add(-30 * day), "ago1m": f.now.Add(-time.Minute), "ago12d": f.now.Add(-12 * day)} {
		f.vars[name] = t.UTC().Format("2006-01-02 15:04 UTC")
	}
}

const (
	apiKeysPath      = "/api/headscale/v0/api-keys" //nolint:gosec // a path, not a credential
	oauthClientsPath = "/api/headscale/v0/oauth-clients"
)

var (
	apiKeys      = listAt{apiKeysPath, "apiKeys"}
	oauthClients = listAt{oauthClientsPath, "oauthClients"}
)

const tr81ysSheet = `ID:         2
Prefix:     tr81ys
Owner:      User 4 (bob)
State:      valid
Expiry:     in 60d ({in60d})
Created:    30d ago ({ago30d})
Last seen:  1m ago ({ago1m})
`

const c9f2Sheet = `ID:           c9f2aa000001
Scopes:       auth_keys, devices:core
Tags:         tag:ci
Description:  CI
Created:      12d ago ({ago12d})
State:        valid
`

var apiKeysCases = []cliCase{
	{name: "only the valid keys, as in the proposal", args: "api keys list", stdout: "ID  PREFIX  OWNER  EXPIRY  CREATED  LAST SEEN\n1   mk40pz  -      in 89d  1d ago   2m ago\n2   tr81ys  bob    in 60d  30d ago  1m ago\n"},
	{
		name: "--all shows every state, with STATE", args: "api keys list --all",
		stdout: "ID  PREFIX  OWNER  STATE    EXPIRY  CREATED  LAST SEEN\n1   mk40pz  -      valid    in 89d  1d ago   2m ago\n2   tr81ys  bob    valid    in 60d  30d ago  1m ago\n10  qq11rr  alice  revoked  in 5d   2d ago   never\n11  xx22yy  -      expired  3d ago  33d ago  never\n",
	},
	{name: "-o json leaves out what the table hides", args: "api keys list -o json", want: apiKeys.rows(onlyID("1", "2"))},
	{name: "-o json with --all is every row", args: "api keys list --all -o json", want: apiKeys.rows(all)},
	{name: "a filter on state, without STATE", args: "api keys list --filter state=revoked", stdout: "ID  PREFIX  OWNER  EXPIRY  CREATED  LAST SEEN\n10  qq11rr  alice  in 5d   2d ago   never\n"},
	{name: "a filter on state as JSON", args: "api keys list --filter state=expired -o json", want: apiKeys.rows(onlyID("11"))},
	{name: "an owner", args: "api keys list --filter owner=alice", terminal: true, stdout: "No API keys. --all shows 1 more.\n"},
	{name: "an owner, with --all", args: "api keys list --filter owner=alice --all --columns id,state", stdout: "ID  STATE\n10  revoked\n"},
	{name: "not used for 30 days", args: "api keys ls --filter 'last-seen>30d' -o json", want: apiKeys.rows(func(map[string]any) bool { return false })},
	// A key never used has no time to compare.
	{name: "not used for a minute, with --all", args: "api keys list --all --filter 'last-seen>90s' --columns id", stdout: "ID\n1\n"},
	{
		name: "the columns", args: "api keys list --list-columns",
		stdout: `COLUMN     FIELD     KIND   DEFAULT  DESCRIPTION
id         id        id     yes      API key ID
prefix     prefix    text   yes      The part of the key that is not secret
owner      owner     owner  yes      The user recorded on the key; it does not limit what the key may do
state      state     text   no       valid, expired or revoked; the list shows only state=valid, --all every row and this column
expiry     expiry    time   yes      When the key stops working
created    created   time   yes      When the key was made
last-seen  lastSeen  time   yes      When the key was last used, to the minute
`,
	},
	{name: "the list as JSON, with --all", args: "api keys list --all -o json", want: apiKeys.rows(all)},
	{name: "by ID, a sheet", args: "api keys get 2", stdout: tr81ysSheet},
	{name: "by prefix, as JSON", args: "api keys get tr81ys -o json", want: apiKeys.row(onlyID("2"))},
	{name: "masked, as older output shows it", args: "api keys get hskey-api-tr81ys-***", stdout: tr81ysSheet},
	{
		name: "a whole key is refused before any call, its secret not repeated", args: "api keys get hskey-api-tr81ys000000-0123456789abcdef",
		stderr: "Error: a key is named by its ID or its prefix, never by the whole key. Its prefix is tr81ys000000.\n", code: 1, check: noCall,
	},
	{name: "an auth key is no API key", args: "api keys get ab12cd", stderr: "Error: no API key matches \"ab12cd\".\n", code: 1},
	{name: "get has no --columns", args: "api keys get 10 --columns id,state", stderr: "Error: --columns does not apply to `api keys get`.\nRun `headscale api keys get --help`.\n", code: 1},
	{name: "the examples of delete", args: "api keys rm 2 --force", stdout: "API key 2 (tr81ys) is revoked. Its record is removed in 7d.\n"},
	{name: "the examples of delete, as JSON", args: "api keys delete 2 --force -o json", want: answer(apiKeysPath + "/2")},
	{
		name: "a credential that may not read API keys", args: "api keys list", setup: withToken(nil, "devices:core:read"), env: tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope all:read.\n", code: 1,
	},
}

func TestAPIKeys(t *testing.T) {
	t.Parallel()

	runCases(t, credring, apiKeysCases)
}

var oauthClientsCases = []cliCase{
	{name: "only the valid clients", args: "api oauth-clients list", stdout: "ID            SCOPES                   TAGS    DESCRIPTION  CREATED\nc9f2aa000001  auth_keys, devices:core  tag:ci  CI           12d ago\nc9f2aa000002  devices:core:read                -            2d ago\n"},
	{
		name: "--all shows the revoked, with STATE", args: "api oauth-clients list --all",
		stdout: "ID            SCOPES                   TAGS    DESCRIPTION  CREATED  STATE\nc9f2aa000001  auth_keys, devices:core  tag:ci  CI           12d ago  valid\nc9f2aa000002  devices:core:read                -            2d ago   valid\nd0d0aa000003  users:read                       -            3d ago   revoked\n",
	},
	{name: "-o json leaves out what the table hides", args: "api oauth-clients list -o json", want: oauthClients.rows(onlyID("c9f2aa000001", "c9f2aa000002"))},
	{name: "-o json with --all is every row", args: "api oauth-clients list --all -o json", want: oauthClients.rows(all)},
	{name: "a filter on state, as JSON", args: "api oauth-clients list --filter state=revoked -o json", want: oauthClients.rows(onlyID("d0d0aa000003"))},
	{name: "a filter on state", args: "api oauth-clients list --filter state=revoked --columns id,scopes", stdout: "ID            SCOPES\nd0d0aa000003  users:read\n"},
	{name: "a tag, as JSON", args: "api oauth-clients ls --filter tags=tag:ci -o json", want: oauthClients.rows(onlyID("c9f2aa000001"))},
	{name: "the ID sorts as text", args: "api oauth-clients list --all --sort -id --columns id", stdout: "ID\nd0d0aa000003\nc9f2aa000002\nc9f2aa000001\n"},
	{name: "the ID is no number", args: "api oauth-clients list --filter 'id>c9f2aa000001'", stderr: "Error: column \"id\" compares IDs as numbers with < and >, not \"c9f2aa000001\".\n", code: 1},
	{name: "nothing valid, on a terminal", args: "api oauth-clients list --filter scopes=users:read", terminal: true, stdout: "No OAuth clients. --all shows 1 more.\n"},
	{name: "by ID, a sheet", args: "api oauth-clients get c9f2aa000001", stdout: c9f2Sheet},
	{name: "by ID, as JSON", args: "api oauth-clients get c9f2aa000001 -o json", want: oauthClients.row(onlyID("c9f2aa000001"))},
	{
		name: "the masked form names no client: no output prints it", args: "api oauth-clients get hskey-client-c9f2aa000001-***",
		stderr: "Error: an OAuth client is named by its ID, never by its secret. Its ID is c9f2aa000001.\n", code: 1, check: noCall,
	},
	{name: "a description names no client", args: "api oauth-clients get CI", stderr: "Error: no OAuth client matches \"CI\".\n", code: 1},
	{
		name: "a whole secret is refused before any call", args: "api oauth-clients get hskey-client-c9f2aa000001-0123456789abcdef",
		stderr: "Error: an OAuth client is named by its ID, never by its secret. Its ID is c9f2aa000001.\n", code: 1, check: noCall,
	},
	{
		name: "a credential that may not read clients", args: "api oauth-clients list", setup: withToken(nil, "devices:core:read"), env: tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope oauth_keys:read.\n", code: 1,
	},
}

func TestOAuthClients(t *testing.T) {
	t.Parallel()

	runCases(t, credring, oauthClientsCases)
}

// createdAt is created for the create at path of a credential whose secret
// is hskey-<kind>-<part>-…, part the prefix or, for a client, the ID.
func createdAt(path, kind string) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, f *fixture, r result) string {
		tb.Helper()

		bodies := r.answers[path]
		require.NotEmpty(tb, bodies, "no create")

		var k struct{ ID, Prefix, Key string }
		require.NoError(tb, json.Unmarshal(bodies[len(bodies)-1], &k))

		part := cmp.Or(k.Prefix, k.ID)
		require.True(tb, strings.HasPrefix(k.Key, "hskey-"+kind+"-"+part+"-"), k.Key)

		f.vars["id"], f.vars["prefix"], f.vars["key"] = k.ID, part, k.Key

		return k.Key + "\n"
	}
}

var (
	apiKeyCreated      = createdAt(apiKeysPath, "api")
	oauthClientCreated = createdAt(oauthClientsPath, "client")
)

const secretShownOnce = "This is the only time the secret is shown.\n"

var apiKeysCreateCases = []cliCase{
	{name: "no owner, 90 days", args: "api keys create", want: apiKeyCreated, stderr: "API key {id} ({prefix}): expires in 90d.\n" + shownOnce},
	{name: "30 days", args: "api keys create --expiry 30d", want: apiKeyCreated, stderr: "API key {id} ({prefix}): expires in 30d.\n" + shownOnce},
	{
		name: "owned by a user", args: "api keys create --user alice --expiry 90d", want: apiKeyCreated,
		stderr: "API key {id} ({prefix}) for User 3 (alice); expires in 90d.\n" + shownOnce,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			c, err := f.srv.State().GetAPIKeyCredential(mustID(tb, f.vars["id"]))
			require.NoError(tb, err)
			require.Equal(tb, uint(3), *c.UserID)
		},
	},
	{name: "-u, as JSON, the secret in key and no note", args: "api keys create -u alice -o json", want: answer(apiKeysPath)},
	{name: "until a date, as JSON", args: "api keys create -e 2999-08-27T10:00:00Z -o json", want: answer(apiKeysPath)},
	{name: "never", args: "api keys create --expiry never", stderr: "Error: a key must have an expiry: a time, a date or a duration such as 90d.\n", code: 1},
	{name: "now", args: "api keys create -e now", stderr: "Error: a key must have an expiry: a time, a date or a duration such as 90d.\n", code: 1},
	{
		name: "no upper limit, but a duration has one", args: "api keys create -e 300y",
		stderr: "Error: \"300y\" is not a valid --expiry: a duration from now is at most 292y; a later time is written as a date, such as 2999-08-27.\n", code: 1,
	},
	{name: "a time in the past", args: "api keys create --expiry 2024-01-01", stderr: "Error: 2024-01-01 00:00 UTC is in the past.\n", code: 1},
	{name: "a user nobody is", args: "api keys create --user alcie", stderr: "Error: no user matches \"alcie\".\n", code: 1},
	{name: "the owner is a flag", args: "api keys create alice", stderr: "Error: `api keys create` takes no arguments, got 1.\n\n  headscale api keys create\n", code: 1},
	{
		name: "the user is deleted after the lookup", args: "api keys create --user bob",
		answered: func(tb testing.TB, f *fixture, req string) {
			tb.Helper()

			if strings.HasPrefix(req, "GET /api/headscale/v0/users") && f.changes == 0 {
				f.changes++
				require.NoError(tb, f.srv.State().DB().DB.Exec("DELETE FROM users WHERE id = 4").Error)
			}
		},
		stderr: "Error: the server refused a value:\n  --user: no user has this ID\n", code: 1,
	},
	{
		name: "a token makes no API key", args: "api keys create", setup: withToken(nil, "all"), env: tokenEnv,
		stderr: "Error: this credential may not do that.\nAn OAuth access token cannot make an API key: an API key may do everything, so only an API key or the socket makes one.\n", code: 1,
	},
}

func TestAPIKeysCreate(t *testing.T) {
	t.Parallel()

	runCases(t, credring, apiKeysCreateCases)
}

var oauthClientsCreateCases = []cliCase{
	{name: "one scope", args: "api oauth-clients create devices:core:read", want: oauthClientCreated, stderr: "OAuth client {id}: scopes devices:core:read.\n" + secretShownOnce},
	{
		name: "scopes and a tag", args: "api oauth-clients create devices:core,auth_keys --tags tag:ci", want: oauthClientCreated,
		stderr: "OAuth client {id}: scopes auth_keys, devices:core; tags tag:ci.\n" + secretShownOnce,
	},
	{
		name: "lists copied from a table, a space after each comma", args: `api oauth-clients create "devices:core, auth_keys" --tags "tag:ci, tag:build"`, want: oauthClientCreated,
		stderr: "OAuth client {id}: scopes auth_keys, devices:core; tags tag:build, tag:ci.\n" + secretShownOnce,
	},
	{
		name: "with a description", args: `api oauth-clients create devices:core --tags tag:ci -d "CI"`, want: oauthClientCreated,
		stderr: "OAuth client {id}: scopes devices:core; tags tag:ci.\n" + secretShownOnce,
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			c, err := f.srv.State().GetOAuthClientCredential(f.vars["id"])
			require.NoError(tb, err)
			require.Equal(tb, "CI", c.Description)
		},
	},
	{name: "as JSON, the secret in key and no note", args: "api oauth-clients create devices:core --tags tag:ci -o json", want: answer(oauthClientsPath)},
	{name: "a scope that needs a tag", args: "api oauth-clients create auth_keys", stderr: "Error: scope auth_keys needs at least one tag (--tags).\n", code: 1},
	{name: "an unknown scope", args: "api oauth-clients create devices:cor", stderr: "Error: unknown scope: devices:cor.\n", code: 1},
	{name: "a tag that is not in the policy", args: "api oauth-clients create devices:core --tags tag:serverr", stderr: "Error: these tags are not in the policy: tag:serverr.\n", code: 1},
	{name: "no scope", args: "api oauth-clients create", stderr: "Error: `api oauth-clients create` needs 1 argument, got 0.\n\n  headscale api oauth-clients create <scopes>\n", code: 1},
	{name: "an empty item is refused on the line", args: "api oauth-clients create devices:core,", stderr: "Error: the scope list has an empty item.\n", code: 1, check: noCall},
	{name: "--tags given twice", args: "api oauth-clients create devices:core --tags tag:ci --tags tag:prod", stderr: "Error: --tags is given twice. Only --filter may be repeated.\n", code: 1},
	{
		name: "a description too long", args: "api oauth-clients create devices:core:read -d " + strings.Repeat("x", 51),
		stderr: "Error: the server refused a value:\n  --description: expected length <= 50\n", code: 1,
	},
	{
		name: "a token makes a client for a tag it owns", args: "api oauth-clients create devices:core --tags tag:prod -o json",
		setup: withToken([]string{"tag:ci"}, "oauth_keys", "devices:core"), env: tokenEnv, want: answer(oauthClientsPath),
	},
	{
		name: "a token and a scope it does not hold", args: "api oauth-clients create auth_keys --tags tag:ci",
		setup: withToken([]string{"tag:ci"}, "oauth_keys", "devices:core"), env: tokenEnv,
		stderr: "Error: this credential may not do that.\nAn OAuth access token makes an OAuth client with only scopes it holds itself.\n", code: 1,
	},
	{
		name: "a token and a tag it does not own", args: "api oauth-clients create devices:core --tags tag:build",
		setup: withToken([]string{"tag:ci"}, "oauth_keys", "devices:core"), env: tokenEnv,
		stderr: "Error: this credential may not do that.\nAn OAuth access token gives a key or an OAuth client only tags it holds or owns; " +
			"an API key may give any tag of the policy.\n", code: 1,
	},
	{
		name: "a token that may only read clients", args: "api oauth-clients create devices:core:read", setup: withToken(nil, "oauth_keys:read"), env: tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope oauth_keys.\n", code: 1,
	},
}

func TestOAuthClientsCreate(t *testing.T) {
	t.Parallel()

	runCases(t, credring, oauthClientsCreateCases)
}

func mustID(tb testing.TB, s string) uint64 {
	tb.Helper()

	id, err := strconv.ParseUint(s, 10, 64)
	require.NoError(tb, err)

	return id
}

// credKind is one kind of credential as the tests of every kind see it,
// on credring: a valid record, a revoked one, and how to make one.
type credKind struct {
	group, kind, path, noun string
	// valid is the word that names the valid record, id its ID in the API,
	// row its row in the database, name as messages say it, and asked what
	// the question says after the name.
	valid, id, name, asked string
	row                    int
	revoked, revokedName   string
	revokedRow             int
	// write is the scope a delete needs, unknown a word that names none.
	write, unknown string
	create         string
	created        func(testing.TB, *fixture, result) string
}

func credKinds() []credKind {
	return []credKind{
		{
			group: "auth keys", kind: "auth", path: authKeysPath, noun: "auth key",
			valid: "ab12cd", id: "7", name: "Auth key 7 (ab12cd)", asked: ", owned by User 3 (alice)", row: 7,
			revoked: "3", revokedName: "Auth key 3 (zz91aa)", revokedRow: 3,
			write: "auth_keys", unknown: "8", create: "auth keys create alice --reusable -d ci", created: created,
		},
		{
			group: "api keys", kind: "api", path: apiKeysPath, noun: "API key",
			valid: "tr81ys", id: "2", name: "API key 2 (tr81ys)", asked: ", owned by User 4 (bob)", row: 2,
			revoked: "10", revokedName: "API key 10 (qq11rr)", revokedRow: 10,
			write: "all", unknown: "99", create: "api keys create --user alice", created: apiKeyCreated,
		},
		{
			group: "api oauth-clients", kind: "client", path: oauthClientsPath, noun: "OAuth client",
			valid: "c9f2aa000001", id: "c9f2aa000001", name: "OAuth client c9f2aa000001", asked: " (CI)", row: 12,
			revoked: "d0d0aa000003", revokedName: "OAuth client d0d0aa000003", revokedRow: 14,
			write: "oauth_keys", unknown: "ffffffffffff", create: "api oauth-clients create devices:core --tags tag:ci", created: oauthClientCreated,
		},
	}
}

// removeRow removes the record of row after the first answer to a request
// that starts with method, as the server's cleanup would.
func removeRow(row int, method string) func(testing.TB, *fixture, string) {
	return func(tb testing.TB, f *fixture, req string) {
		tb.Helper()

		if strings.HasPrefix(req, method+" ") && f.changes == 0 {
			f.changes++
			require.NoError(tb, f.srv.State().DB().DB.Exec("DELETE FROM credentials WHERE id = ?", row).Error)
		}
	}
}

// endCases are the cases of the delete of a kind: every way to answer the
// question, every sentence the server's record allows, and the reads that
// fail. Each kind runs all of them, so no kind can lack one.
func endCases(k credKind) []cliCase {
	del := k.group + " delete "
	ask := "Delete " + k.name + k.asked + "? [y/N] "
	removed := k.name + " is revoked. Its record is removed in 7d.\n"
	noTerminal := "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete " + k.name + ".\n"

	return []cliCase{
		{name: "asks, and yes", args: del + k.valid, terminal: true, stdin: "y\n", stderr: ask, stdout: removed, check: asksMe(false)},
		{name: "no is not done", args: del + k.valid, terminal: true, stdin: "n\n", stderr: ask + "Aborted.\n", code: 1},
		{name: "nothing typed is no", args: del + k.id, terminal: true, stderr: ask + "Aborted.\n", code: 1},
		{name: "no terminal", args: del + k.valid, stderr: noTerminal, code: 1},
		{name: "a terminal, but stdin is a pipe", args: del + k.valid, terminal: true, piped: true, stdin: "y\n", stderr: noTerminal, code: 1},
		{name: "--force", args: k.group + " rm " + k.valid + " --force", stdout: removed},
		{name: "-o json is the revoked record", args: del + k.valid + " --force -o json", want: answer(k.path + "/" + k.id)},
		{
			name: "a revoked record does not ask, and changes nothing", args: del + k.revoked, terminal: true,
			stdout: k.revokedName + " was revoked already. Its record is removed in 6d.\n",
		},
		{
			name: "a revoked record whose removal has passed", args: del + k.revoked,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				require.NoError(tb, f.srv.State().DB().DB.Exec("UPDATE credentials SET revoked = ? WHERE id = ?", f.now.Add(-8*24*time.Hour), k.revokedRow).Error)
			},
			stdout: k.revokedName + " was revoked already. Its record is due for removal.\n",
		},
		{
			name: "a record kept for ever", args: del + k.valid + " --force", server: keptForEver,
			stdout: k.name + " is revoked. Its record is kept.\n",
		},
		{
			name: "a revoked record kept for ever", args: del + k.revoked, server: keptForEver,
			stdout: k.revokedName + " was revoked already. Its record is kept.\n",
		},
		{name: "gone after the lookup", args: del + k.valid + " --force", pageSize: cliPages, answered: removeRow(k.row, "GET"), stderr: "Error: " + k.name + " no longer exists.\n", code: 1},
		{name: "gone before its removal is read", args: del + k.valid + " --force", answered: removeRow(k.row, "DELETE"), stdout: k.name + " is revoked.\n"},
		{name: "gone before its removal is read, as JSON", args: del + k.valid + " --force -o json", answered: removeRow(k.row, "DELETE")},
		{name: "nothing matches", args: del + k.unknown + " --force", stderr: "Error: no " + k.noun + " matches \"" + k.unknown + "\".\n", code: 1},
		{
			name: "a credential that may only read", args: del + k.valid + " --force", setup: withToken([]string{"tag:ci"}, k.write+":read"), env: tokenEnv,
			stderr: "Error: this credential may not do that.\nIt lacks the scope " + k.write + ".\n", code: 1,
		},
	}
}

// keptForEver is a server that never removes a revoked record.
var keptForEver = []servertest.ServerOption{servertest.WithRevokedRetention(0)}

// TestCredentialsEnd runs the same cases over every kind of credential.
func TestCredentialsEnd(t *testing.T) {
	t.Parallel()

	// The kinds are the tree's: a group with a command that prints a
	// secret makes a credential, and a kind that credKinds lacks would get
	// none of these cases, nor TestSecretOnce's.
	var made []string

	for _, c := range Tree().Commands() {
		if c.Secret {
			made = append(made, c.Path[:strings.LastIndex(c.Path, " ")])
		}
	}

	kinds := credKinds()
	require.Len(t, made, len(kinds), "credKinds and the groups that make a credential")

	for _, k := range kinds {
		require.Contains(t, made, k.group, "credKinds and the groups that make a credential")
	}

	for _, k := range credKinds() {
		t.Run(k.group, func(t *testing.T) {
			t.Parallel()
			runCases(t, credring, endCases(k))
		})
	}
}

// selfKey is an API key with no owner that the case calls with: its
// secret, ID and prefix in the vars self, selfid and selfprefix.
func selfKey(tb testing.TB, f *fixture) {
	tb.Helper()

	expiry := f.now.Add(24 * time.Hour)
	secret, k, err := f.srv.State().CreateAPIKey(&expiry)
	require.NoError(tb, err)

	f.vars["self"], f.vars["selfid"], f.vars["selfprefix"] = secret, strconv.FormatUint(k.ID, 10), k.Prefix
}

// selfClient is an OAuth client that may manage clients, and a token of
// it that the case calls with: the client's ID in clientid, the token in
// token.
func selfClient(tb testing.TB, f *fixture) {
	tb.Helper()

	scopes := []string{"oauth_keys"}
	_, client, err := f.srv.State().CreateOAuthClient(scopes, nil, "self", nil)
	require.NoError(tb, err)

	expiry := f.now.Add(time.Hour)
	token, _, err := f.srv.State().MintAccessToken(client.ClientID, scopes, nil, &expiry)
	require.NoError(tb, err)

	f.vars["clientid"], f.vars["token"] = client.ClientID, token
}

var selfEnv = []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={self}"}

// The CLI deletes the credential it calls with: the question says so, the
// delete works, and the read after it is refused, which is no error.
var selfCases = []cliCase{
	{
		name: "an API key deletes itself", args: "api keys delete {selfid}", setup: selfKey, env: selfEnv, terminal: true, stdin: "y\n",
		stderr: "Delete API key {selfid} ({selfprefix}), with no owner? " + ownSentence + " [y/N] ",
		stdout: "API key {selfid} ({selfprefix}) is revoked.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			r := f.run(tb, cliCase{args: "api whoami", env: selfEnv})
			require.Equal(tb, "Error: the server did not accept the API key.\n", r.stderr)
		},
	},
	{name: "an API key deletes itself, as JSON", args: "api keys delete {selfid} --force -o json", setup: selfKey, env: selfEnv, check: asksMe(false)},
	{
		name: "with no terminal, the refusal says so too", args: "api keys delete {selfid}", setup: selfKey, env: selfEnv, check: asksMe(true),
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete API key {selfid} ({selfprefix}). " + ownSentence + "\n", code: 1,
	},
	{name: "--force says nothing and asks nothing of who calls", args: "api keys rm {selfid} --force", setup: selfKey, env: selfEnv, stdout: "API key {selfid} ({selfprefix}) is revoked.\n", check: asksMe(false)},
	{
		name: "another API key is not the CLI's", args: "api keys delete 1", setup: selfKey, env: selfEnv, terminal: true, stdin: "y\n",
		stderr: "Delete API key 1 (mk40pz), with no owner? [y/N] ", stdout: "API key 1 (mk40pz) is revoked. Its record is removed in 7d.\n",
	},
	{
		name: "a token deletes its own client", args: "api oauth-clients delete {clientid}", setup: selfClient, env: tokenEnv, terminal: true, stdin: "y\n",
		stderr: "Delete OAuth client {clientid} (self)? " + ownSentence + " [y/N] ",
		stdout: "OAuth client {clientid} is revoked.\n",
	},
}

// asksMe holds whether the case read who the CLI calls as: only for a
// question that a person reads, and never over the socket.
func asksMe(want bool) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, _ *fixture, r result) {
		tb.Helper()
		require.Equal(tb, want, slices.Contains(r.asked, "GET /api/headscale/v0/me"), r.asked)
	}
}

// ownSentence is the sentence of the question when the CLI deletes what it
// calls with, as command writes it.
const ownSentence = "This CLI calls with it: once it is revoked, the server refuses the CLI."

func TestCredentialDeletesItself(t *testing.T) {
	t.Parallel()

	runCases(t, credring, selfCases)
}

// TestSecretOnce: the secret of a new credential, of every kind, is on the
// create's stdout and in its -o json, and in nothing else: no other output
// of any command, typed into any place of a line, no request the CLI
// sends, and not the create's stderr. The secret is tried with a dash in
// it, as keys of 0.28 and 0.29 can hold.
func TestSecretOnce(t *testing.T) {
	t.Parallel()

	for _, k := range credKinds() {
		t.Run(k.group, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, false)
			credring(t, f)

			r := f.run(t, cliCase{args: k.create})
			require.Equal(t, 0, r.code, r.stderr)

			key := k.created(t, f, r)
			head := "hskey-" + k.kind + "-" + f.vars["prefix"] + "-"
			secret := strings.TrimSpace(strings.TrimPrefix(key, head))
			require.Greater(t, len(secret), 30)
			require.Equal(t, head+secret+"\n", r.stdout, "stdout is the secret alone")
			require.NotContains(t, r.stderr, secret)

			f.vars["group"] = k.group
			f.vars["dashed"] = head + secret[:20] + "-" + secret[21:]
			upper := strings.ToUpper(f.vars["key"])

			lines := []string{
				"{group} list", "{group} list --all", "{group} list --all -o json", "{group} list --list-columns", "{group} list --list-columns -o json",
				"{group} get {prefix}", "{group} get {id} -o json", "{group} get {key}", "{group} get {dashed}", "{group} get " + upper,
				"{group} get hskey-oops-{prefix}-" + secret, "{group} get hskey-" + k.kind + "-{prefix}-***", "{group} get hskey-" + k.kind + "-000000000000-" + secret,
				"{group} get {key}-***", "{group} delete {key}-*** --force",
				"{group} delete {key}", "{group} delete {dashed} --force", "{group} delete {key} --force -o json",
				"{group} list --filter id={key}", "{group} list --filter description={key}", "{group} list --columns {key}",
				"{group} {key}", "{group} get --{key}", "{group} get {id} --{key}",
				"{group} --help", "{group} create --help",
				"nodes get {key}", "users get {key}", "auth keys create {key}", "auth keys create {dashed}", "auth keys create alice,{key}",
				"auth keys create tag:ci,{key}", "auth keys list --filter owner={key}", "api keys create --user {key}",
				"auth keys create alice,bob -d " + secret,
				// A value the server would store or answer back: a name, a
				// display name, a description, a scope, a tag.
				"users create {key}", "users create dave --display-name {key}", "users set alice --name {key}",
				"auth keys create alice -d {key}", "api oauth-clients create devices:core --tags tag:ci -d {key}",
				"api oauth-clients create {key}", "api oauth-clients create devices:core,{key} --tags tag:ci",
				"api oauth-clients create devices:core --tags {key}", "api oauth-clients create devices:core --tags tag:ci,{dashed}",
				"auth keys create tag:{key}", "auth keys create tag:ci,tag:{dashed}",
				"{group} delete {id} --force", "{group} list --filter id={id} --all",
			}

			for _, args := range lines {
				r := f.run(t, cliCase{args: args})
				require.NotContains(t, r.stdout, secret, args)
				require.NotContains(t, r.stderr, secret, args)
				require.NotContains(t, strings.ToLower(r.stdout+r.stderr), strings.ToLower(secret[21:]), args)

				for path, bodies := range r.answers {
					for _, b := range bodies {
						require.NotContains(t, string(b), secret, "%s: the answer of %s", args, path)
					}
				}

				for _, req := range r.sent {
					require.NotContains(t, req, secret, "%s: a request", args)
					require.NotContains(t, req, secret[21:], "%s: a request", args)
				}
			}

			// Nothing typed was stored: no user, key or client holds it.
			for _, list := range []string{"users list -o json", "auth keys list --all -o json", "api oauth-clients list --all -o json"} {
				require.NotContains(t, f.run(t, cliCase{args: list}).stdout, secret, list)
			}

			r = f.run(t, cliCase{args: k.create + " -o json"})
			require.Equal(t, 0, r.code, r.stderr)
			require.Contains(t, r.stdout, `"key": "hskey-`+k.kind+"-", "-o json has the secret in key")
			require.Empty(t, r.stderr, "-o json prints no note")
		})
	}
}
