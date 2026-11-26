package newcli

import (
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const keysPolicy = `{
	"tagOwners": {"tag:ci": [], "tag:build": [], "tag:prod": ["tag:ci"]},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// keyring holds the keys of the proposal's example: alice (3) and bob (4),
// and one key in each state. 3 is revoked a day ago, 5 expired, 6 used by
// a node of bob's that still refers to it, 7 and 9 valid. Five keys are
// three pages of the fixture's walk.
func keyring(tb testing.TB, f *fixture) {
	tb.Helper()

	st := f.srv.State()
	day := 24 * time.Hour

	_, err := st.SetPolicy([]byte(keysPolicy))
	require.NoError(tb, err)

	for _, u := range []types.User{{ID: 3, Name: "alice", DisplayName: "Alice"}, {ID: 4, Name: "bob"}} {
		_, _, err := st.CreateUser(u)
		require.NoError(tb, err)
	}

	at := func(d time.Duration) *time.Time { return new(f.now.Add(d)) }
	user := func(id uint) *uint { return &id }

	for _, k := range []types.Credential{
		{ID: 3, Identifier: "zz91aa", UserID: user(3), Expiration: at(5 * day), CreatedAt: at(-2 * day), Revoked: at(-day)},
		{ID: 5, Identifier: "kk20bb", UserID: user(4), Reusable: true, Expiration: at(-3 * day), CreatedAt: at(-33 * day)},
		{ID: 6, Identifier: "mm77cc", UserID: user(4), Used: true, Expiration: at(2 * day), CreatedAt: at(-5 * day)},
		{ID: 7, Identifier: "ab12cd", UserID: user(3), Reusable: true, Expiration: at(23 * time.Hour), CreatedAt: at(-time.Hour)},
		{ID: 9, Identifier: "ef34gh", Tags: []string{"tag:ci"}, Ephemeral: true, Expiration: at(6 * day), CreatedAt: at(-2 * day), Description: "CI runners"},
	} {
		k.Kind = types.CredentialPreAuthKey
		k.Hash = []byte("$sha256$none")
		require.NoError(tb, st.DB().DB.Create(&k).Error)
	}

	v4 := netip.MustParseAddr("100.64.0.40")
	node := types.Node{
		ID:             40,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "laptop",
		GivenName:      "laptop",
		UserID:         user(4),
		IPv4:           &v4,
		RegisterMethod: "authkey",
		AuthKeyID:      new(uint64(6)),
		Hostinfo:       &tailcfg.Hostinfo{Hostname: "laptop"},
		CreatedAt:      f.now.Add(-5 * day),
	}
	require.NoError(tb, st.DB().DB.Create(&node).Error)

	for name, t := range map[string]time.Time{"in23h": f.now.Add(23 * time.Hour), "ago1h": f.now.Add(-time.Hour), "in5d": f.now.Add(5 * day), "ago2d": f.now.Add(-2 * day)} {
		f.vars[name] = t.UTC().Format("2006-01-02 15:04 UTC")
	}
}

const authKeysPath = "/api/headscale/v0/auth-keys"

var authKeys = listAt{authKeysPath, "authKeys"}

const allKeysTable = `ID  PREFIX  OWNER   STATE    REUSABLE  EPHEMERAL  EXPIRY  CREATED
3   zz91aa  alice   revoked  no        no         in 5d   2d ago
5   kk20bb  bob     expired  yes       no         3d ago  33d ago
6   mm77cc  bob     used     no        no         in 2d   5d ago
7   ab12cd  alice   valid    yes       no         in 23h  1h ago
9   ef34gh  tag:ci  valid    no        yes        in 6d   2d ago
`

const ab12cdSheet = `ID:           7
Prefix:       ab12cd
Owner:        User 3 (alice)
State:        valid
Reusable:     yes
Ephemeral:    no
Expiry:       in 23h ({in23h})
Created:      1h ago ({ago1h})
Description:  -
`

// tokenEnv calls as the access token in the fixture's var token.
var tokenEnv = []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"}

// withToken is a setup that makes an access token with tags and scopes.
func withToken(tags []string, scopes ...string) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		f.vars["token"] = f.taggedToken(tb, tags, scopes...)
	}
}

var authKeysListCases = []cliCase{
	{
		name:   "only the valid keys, walked over three pages",
		args:   "auth keys list",
		stdout: "ID  PREFIX  OWNER   REUSABLE  EPHEMERAL  EXPIRY  CREATED\n7   ab12cd  alice   yes       no         in 23h  1h ago\n9   ef34gh  tag:ci  no        yes        in 6d   2d ago\n",
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Len(tb, r.asked, 3, "three pages of two")
		},
	},
	{
		name:   "--all shows every state, with STATE",
		args:   "auth keys list --all",
		stdout: allKeysTable,
	},
	{
		name: "-o json leaves out what the table hides",
		args: "auth keys list -o json",
		want: authKeys.rows(onlyID("7", "9")),
	},
	{
		name: "-o json with --all is every row",
		args: "auth keys list --all -o json",
		want: authKeys.rows(all),
	},
	{
		name:   "a tag",
		args:   "auth keys list --filter owner=tag:ci",
		stdout: "ID  PREFIX  OWNER   REUSABLE  EPHEMERAL  EXPIRY  CREATED\n9   ef34gh  tag:ci  no        yes        in 6d   2d ago\n",
	},
	{
		name:   "a user",
		args:   "auth keys list --filter owner=alice --all --columns id,state",
		stdout: "ID  STATE\n3   revoked\n7   valid\n",
	},
	{
		name:   "a filter on state shows that state, without STATE",
		args:   "auth keys list --filter state=expired",
		stdout: "ID  PREFIX  OWNER  REUSABLE  EPHEMERAL  EXPIRY  CREATED\n5   kk20bb  bob    yes       no         3d ago  33d ago\n",
	},
	{
		name: "a filter on state as JSON",
		args: "auth keys list --filter state=used -o json",
		want: authKeys.rows(onlyID("6")),
	},
	{
		name:   "the columns named, without --all",
		args:   "auth keys list --columns id,state,description",
		stdout: "ID  STATE  DESCRIPTION\n7   valid  -\n9   valid  CI runners\n",
	},
	{
		name:   "the columns named, with --all",
		args:   "auth keys list --all --columns id,prefix",
		stdout: "ID  PREFIX\n3   zz91aa\n5   kk20bb\n6   mm77cc\n7   ab12cd\n9   ef34gh\n",
	},
	{
		name:   "a column added to --all",
		args:   "auth keys list --all --columns +description,-created --filter id>5",
		stdout: "ID  PREFIX  OWNER   STATE  REUSABLE  EPHEMERAL  EXPIRY  DESCRIPTION\n6   mm77cc  bob     used   no        no         in 2d   -\n7   ab12cd  alice   valid  yes       no         in 23h  -\n9   ef34gh  tag:ci  valid  no        yes        in 6d   CI runners\n",
	},
	{
		name:   "the next expiry first",
		args:   "auth keys list --all --sort expiry --columns id,expiry",
		stdout: "ID  EXPIRY\n5   3d ago\n7   in 23h\n6   in 2d\n3   in 5d\n9   in 6d\n",
	},
	{
		name: "expiring within a week",
		args: "auth keys ls --filter 'expiry<7d' -o json",
		want: authKeys.rows(onlyID("7", "9")),
	},
	{
		name:   "the state filter of the proposal",
		args:   "auth keys list --filter state=expired --columns id",
		stdout: "ID\n5\n",
	},
	{
		name:     "nothing valid, on a terminal",
		args:     "auth keys list --filter owner=bob",
		terminal: true,
		stdout:   "No auth keys. --all shows 2 more.\n",
	},
	{
		name:     "nothing at all, on a terminal",
		args:     "auth keys list --all --filter owner=tag:build",
		terminal: true,
		stdout:   "No auth keys.\n",
	},
	{
		name: "the columns", args: "auth keys list --list-columns",
		stdout: `COLUMN       FIELD        KIND   DEFAULT  DESCRIPTION
id           id           id     yes      Auth key ID
prefix       prefix       text   yes      The part of the key that is not secret
owner        owner        owner  yes      The user, or the tags, that a node joining with the key gets
state        state        text   no       valid, used, expired or revoked; the list shows only state=valid, --all every row and this column
reusable     reusable     bool   yes      Whether more than one node may join with the key
ephemeral    ephemeral    bool   yes      Whether a node that joins is removed some time after it disconnects
expiry       expiry       time   yes      When the key stops working
created      created      time   yes      When the key was made
description  description  text   no       What the key is for
`,
	},
	{
		name:   "a credential that may not read keys",
		args:   "auth keys list",
		setup:  withToken(nil, "devices:core:read"),
		env:    tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope auth_keys:read.\n",
		code:   1,
	},
	{
		name:   "the old name",
		args:   "preauthkeys list",
		stderr: "Error: unknown command \"preauthkeys\". It is now \"auth keys\".\nRun `headscale auth keys --help`.\n",
		code:   1,
	},
}

func TestAuthKeysList(t *testing.T) {
	t.Parallel()

	runCases(t, keyring, authKeysListCases)
}

var authKeysGetCases = []cliCase{
	{name: "by prefix, a sheet", args: "auth keys get ab12cd", stdout: ab12cdSheet},
	{
		name: "by ID as JSON",
		args: "auth keys get 7 -o json",
		want: authKeys.row(onlyID("7")),
	},
	{
		name:   "masked, as older output shows it",
		args:   "auth keys get hskey-auth-ab12cd-***",
		stdout: ab12cdSheet,
	},
	{
		name:   "a revoked key",
		args:   "auth keys get zz91aa",
		stdout: "ID:           3\nPrefix:       zz91aa\nOwner:        User 3 (alice)\nState:        revoked\nReusable:     no\nEphemeral:    no\nExpiry:       in 5d ({in5d})\nCreated:      2d ago ({ago2d})\nDescription:  -\n",
	},
	{
		name:   "a key nobody has",
		args:   "auth keys get nope",
		stderr: "Error: no auth key matches \"nope\".\n",
		code:   1,
	},
	{
		name:   "a whole key is refused before any call, its secret not repeated",
		args:   "auth keys get hskey-auth-ab12cd000000-0123456789abcdef",
		stderr: "Error: a key is named by its ID or its prefix, never by the whole key. Its prefix is ab12cd000000.\n",
		code:   1,
		check:  noCall,
	},
	{
		name:   "an empty word",
		args:   "auth keys get ''",
		stderr: "Error: an empty word names no auth key.\n",
		code:   1,
		check: func(tb testing.TB, _ *fixture, r result) {
			tb.Helper()
			require.Empty(tb, r.asked)
		},
	},
}

func TestAuthKeysGet(t *testing.T) {
	t.Parallel()

	runCases(t, keyring, authKeysGetCases)
}

// created reads the answer of the create and fills the vars id, prefix
// and key: what stdout holds, alone.
func created(tb testing.TB, f *fixture, r result) string {
	tb.Helper()

	bodies := r.answers[authKeysPath]
	require.NotEmpty(tb, bodies, "no create")

	var k struct{ ID, Prefix, Key string }
	require.NoError(tb, json.Unmarshal(bodies[len(bodies)-1], &k))
	require.True(tb, strings.HasPrefix(k.Key, "hskey-auth-"+k.Prefix+"-"), k.Key)

	f.vars["id"], f.vars["prefix"], f.vars["key"] = k.ID, k.Prefix, k.Key

	return k.Key + "\n"
}

// stored is a check that reads the new key back from the server.
func stored(
	want func(tb testing.TB, k *types.PreAuthKey),
) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()

		keys, err := f.srv.State().ListPreAuthKeys()
		require.NoError(tb, err)

		for _, k := range keys {
			if k.Prefix == f.vars["prefix"] {
				want(tb, &k)

				return
			}
		}

		tb.Fatalf("no key %s", f.vars["prefix"])
	}
}

const shownOnce = "This is the only time the key is shown.\n"

var authKeysCreateCases = []cliCase{
	{
		name:   "for a user, an hour",
		args:   "auth keys create alice",
		want:   created,
		stderr: "Auth key {id} ({prefix}) for User 3 (alice); expires in 1h.\n" + shownOnce,
		check: stored(func(tb testing.TB, k *types.PreAuthKey) {
			tb.Helper()
			require.False(tb, k.Reusable)
			require.False(tb, k.Ephemeral)
		}),
	},
	{
		name:   "reusable, a day",
		args:   "auth keys create alice --reusable --expiry 24h",
		want:   created,
		stderr: "Auth key {id} ({prefix}) for User 3 (alice); reusable, expires in 1d.\n" + shownOnce,
	},
	{
		name:   "for tags, ephemeral, with a description",
		args:   `auth keys create tag:ci,tag:build --ephemeral -d "CI runners"`,
		want:   created,
		stderr: "Auth key {id} ({prefix}) for tag:build, tag:ci; ephemeral, expires in 1h.\n" + shownOnce,
		check: stored(func(tb testing.TB, k *types.PreAuthKey) {
			tb.Helper()
			require.Equal(tb, "CI runners", k.Description)
			require.Nil(tb, k.User, "a tagged key has no user")
		}),
	},
	{
		name:   "tags copied from a table, a space after each comma",
		args:   `auth keys create "tag:ci, tag:build"`,
		want:   created,
		stderr: "Auth key {id} ({prefix}) for tag:build, tag:ci; expires in 1h.\n" + shownOnce,
	},
	{
		name:   "a user with space around it",
		args:   `auth keys create " alice "`,
		want:   created,
		stderr: "Auth key {id} ({prefix}) for User 3 (alice); expires in 1h.\n" + shownOnce,
	},
	{
		name: "until a date",
		args: "auth keys create tag:ci --expiry 2999-08-27",
		want: created,
		// Days counted apart from the table engine, which once read this
		// date as minus millions of minutes.
		setup: func(_ testing.TB, f *fixture) {
			f.vars["far"] = strconv.Itoa(
				int(
					math.Round(
						float64(
							time.Date(2999, 8, 27, 0, 0, 0, 0, time.UTC).
								Unix()-
								f.now.Unix(),
						) / (24 * 3600),
					),
				),
			)
		},
		stderr: "Auth key {id} ({prefix}) for tag:ci; expires in {far}d.\n" + shownOnce,
	},
	{
		name: "as JSON, the secret in key and no note",
		args: "auth keys create tag:ci -o json",
		want: answer(authKeysPath),
	},
	{
		name: "a user by ID, an expiry as a time",
		args: "auth keys create 4 -e 2999-08-27T10:00:00Z -o json",
		want: answer(authKeysPath),
	},
	{
		name:   "a user and tags",
		args:   "auth keys create alice,tag:ci",
		stderr: "Error: a key needs one owner: one user, or tags, not both.\n",
		code:   1,
	},
	{
		name:   "two users",
		args:   "auth keys create alice,bob",
		stderr: "Error: a key is owned by one user. Got 2: alice, bob.\n",
		code:   1,
	},
	{
		name:   "a tag that is not in the policy",
		args:   "auth keys create tag:serverr --reusable",
		stderr: "Error: these tags are not in the policy: tag:serverr.\n",
		code:   1,
	},
	{
		name:   "a user nobody is",
		args:   "auth keys create alcie",
		stderr: "Error: no user matches \"alcie\".\n",
		code:   1,
	},
	{
		name:   "never",
		args:   "auth keys create alice --expiry never",
		stderr: "Error: a key must have an expiry: a time, a date or a duration such as 90d.\n",
		code:   1,
	},
	{
		name:   "no upper limit, but a duration has one",
		args:   "auth keys create alice -e 300y",
		stderr: "Error: \"300y\" is not a valid --expiry: a duration from now is at most 292y; a later time is written as a date, such as 2999-08-27.\n",
		code:   1,
	},
	{
		name:   "now",
		args:   "auth keys create alice --expiry now",
		stderr: "Error: a key must have an expiry: a time, a date or a duration such as 90d.\n",
		code:   1,
	},
	{
		name:   "no time ahead",
		args:   "auth keys create alice -e 0s",
		stderr: "Error: \"0s\" is not a valid --expiry: a duration from now is longer than 0.\n",
		code:   1,
	},
	{
		name:   "a time in the past",
		args:   "auth keys create alice --expiry 2024-01-01",
		stderr: "Error: 2024-01-01 00:00 UTC is in the past.\n",
		code:   1,
	},
	{
		name:   "a description too long",
		args:   "auth keys create alice -d " + strings.Repeat("x", 51),
		stderr: "Error: the server refused a value:\n  --description: expected length <= 50\n",
		code:   1,
	},
	{
		name: "the user is deleted after the lookup",
		args: "auth keys create bob",
		answered: func(tb testing.TB, f *fixture, req string) {
			tb.Helper()

			if strings.HasPrefix(req, "GET /api/headscale/v0/users") && f.changes == 0 {
				f.changes++
				require.NoError(
					tb,
					f.srv.State().DB().DB.Exec("DELETE FROM users WHERE id = 4").Error,
				)
			}
		},
		stderr: "Error: the server refused a value:\n  <owner>: no user has this ID\n",
		code:   1,
	},
	{
		name:   "no owner",
		args:   "auth keys create",
		stderr: "Error: `auth keys create` needs 1 argument, got 0.\n\n  headscale auth keys create <owner>\n",
		code:   1,
	},
	{
		name:   "--tags is no flag of it",
		args:   "auth keys create alice --tags tag:ci",
		stderr: "Error: --tags does not apply to `auth keys create`.\nRun `headscale auth keys create --help`.\n",
		code:   1,
	},
	{
		name:   "a token makes a key for its tag",
		args:   "auth keys create tag:ci",
		setup:  withToken([]string{"tag:ci"}, "auth_keys"),
		env:    tokenEnv,
		want:   created,
		stderr: "Auth key {id} ({prefix}) for tag:ci; expires in 1h.\n" + shownOnce,
	},
	{
		name:  "a token makes a key for a tag it owns",
		args:  "auth keys create tag:prod -o json",
		setup: withToken([]string{"tag:ci"}, "auth_keys"),
		env:   tokenEnv,
		want:  answer(authKeysPath),
	},
	{
		name:  "a token and a tag it does not own",
		args:  "auth keys create tag:build",
		setup: withToken([]string{"tag:ci"}, "auth_keys"),
		env:   tokenEnv,
		stderr: "Error: this credential may not do that.\nAn OAuth access token gives a key or an OAuth client only tags it holds or owns; " +
			"an API key may give any tag of the policy.\n",
		code: 1,
	},
	{
		name:   "a token and a user",
		args:   "auth keys create alice",
		setup:  withToken([]string{"tag:ci"}, "auth_keys", "users:read"),
		env:    tokenEnv,
		stderr: "Error: this credential may not do that.\nAn OAuth access token makes only tagged keys; an API key may make a key for a user.\n",
		code:   1,
	},
	{
		name:   "a token that cannot read the user",
		args:   "auth keys create alice",
		setup:  withToken([]string{"tag:ci"}, "auth_keys"),
		env:    tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope users:read.\n",
		code:   1,
	},
	{
		name:   "a token that may only read keys",
		args:   "auth keys create tag:ci",
		setup:  withToken([]string{"tag:ci"}, "auth_keys:read"),
		env:    tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope auth_keys.\n",
		code:   1,
	},
}

func TestAuthKeysCreate(t *testing.T) {
	t.Parallel()

	runCases(t, keyring, authKeysCreateCases)
}

// removeKey removes the record of key 7 after the first answer to a
// request that starts with method, as the server's cleanup would.
func removeKey(method string) func(testing.TB, *fixture, string) {
	return func(tb testing.TB, f *fixture, req string) {
		tb.Helper()

		if strings.HasPrefix(req, method+" ") && f.changes == 0 {
			f.changes++
			require.NoError(
				tb,
				f.srv.State().
					DB().
					DB.Exec(
					"DELETE FROM credentials WHERE id = 7",
				).Error,
			)
		}
	}
}

// revoked is a check that key 7 is revoked, or not.
func revoked(want bool) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()

		k, err := f.srv.State().GetPreAuthKeyByID(7)
		require.NoError(tb, err)
		require.Equal(tb, want, k.Revoked != nil)
	}
}

var authKeysDeleteCases = []cliCase{
	{
		name:     "asks, and yes",
		args:     "auth keys delete 7",
		terminal: true,
		stdin:    "y\n",
		stderr:   "Delete Auth key 7 (ab12cd), owned by User 3 (alice)? [y/N] ",
		stdout:   "Auth key 7 (ab12cd) is revoked. Its record is removed in 7d.\n",
		check:    revoked(true),
	},
	{
		name:     "no is not done",
		args:     "auth keys delete 7",
		terminal: true,
		stdin:    "n\n",
		stderr:   "Delete Auth key 7 (ab12cd), owned by User 3 (alice)? [y/N] Aborted.\n",
		code:     1,
		check:    revoked(false),
	},
	{
		name:     "nothing typed is no",
		args:     "auth keys delete ab12cd",
		terminal: true,
		stderr:   "Delete Auth key 7 (ab12cd), owned by User 3 (alice)? [y/N] Aborted.\n",
		code:     1,
		check:    revoked(false),
	},
	{
		name:     "a tagged key",
		args:     "auth keys delete ef34gh",
		terminal: true,
		stdin:    "yes\n",
		stderr:   "Delete Auth key 9 (ef34gh), tagged tag:ci? [y/N] ",
		stdout:   "Auth key 9 (ef34gh) is revoked. Its record is removed in 7d.\n",
	},
	{
		name:   "no terminal",
		args:   "auth keys delete 7",
		stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete Auth key 7 (ab12cd).\n",
		code:   1,
		check:  revoked(false),
	},
	{
		name:     "a terminal, but stdin is a pipe",
		args:     "auth keys delete 7",
		terminal: true,
		piped:    true,
		stdin:    "y\n",
		stderr:   "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete Auth key 7 (ab12cd).\n",
		code:     1,
		check:    revoked(false),
	},
	{
		name:   "--force, by prefix",
		args:   "auth keys rm ab12cd --force",
		stdout: "Auth key 7 (ab12cd) is revoked. Its record is removed in 7d.\n",
		check:  revoked(true),
	},
	{
		name:  "-o json is the revoked key",
		args:  "auth keys delete 7 --force -o json",
		want:  answer(authKeysPath + "/7"),
		check: revoked(true),
	},
	{
		name: "the example of the help",
		args: "auth keys delete 7 --force -o json",
		want: answer(authKeysPath + "/7"),
	},
	{
		name:     "a revoked key does not ask, and changes nothing",
		args:     "auth keys delete 3",
		terminal: true,
		stdout:   "Auth key 3 (zz91aa) was revoked already. Its record is removed in 6d.\n",
		check: func(tb testing.TB, f *fixture, _ result) {
			tb.Helper()

			k, err := f.srv.State().GetPreAuthKeyByID(3)
			require.NoError(tb, err)
			require.Equal(
				tb,
				f.now.Add(-24*time.Hour),
				k.Revoked.UTC(),
				"the first revoke stays",
			)
		},
	},
	{
		name: "a revoked key whose removal has passed",
		args: "auth keys delete 3",
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			require.NoError(
				tb,
				f.srv.State().
					DB().
					DB.Exec(
					"UPDATE credentials SET revoked = ? WHERE id = 3",
					f.now.Add(-8*24*time.Hour),
				).Error,
			)
		},
		stdout: "Auth key 3 (zz91aa) was revoked already. Its record is due for removal.\n",
	},
	{
		name:   "a key a node refers to is kept",
		args:   "auth keys delete mm77cc --force",
		stdout: "Auth key 6 (mm77cc) is revoked. Its record is kept.\n",
	},
	{
		name:   "an expired key",
		args:   "auth keys delete 5 --force",
		stdout: "Auth key 5 (kk20bb) is revoked. Its record is removed in 7d.\n",
	},
	{
		name:     "gone after the lookup",
		args:     "auth keys delete 7 --force",
		pageSize: cliPages,
		answered: removeKey("GET"),
		stderr:   "Error: Auth key 7 (ab12cd) no longer exists.\n",
		code:     1,
	},
	{
		name:     "gone before its removal is read",
		args:     "auth keys delete 7 --force",
		answered: removeKey("DELETE"),
		stdout:   "Auth key 7 (ab12cd) is revoked.\n",
	},
	{
		name:     "gone before its removal is read, as JSON",
		args:     "auth keys delete 7 --force -o json",
		answered: removeKey("DELETE"),
	},
	{
		name:   "a key nobody has",
		args:   "auth keys delete 8 --force",
		stderr: "Error: no auth key matches \"8\".\n",
		code:   1,
	},
	{
		name:   "a credential that may only read keys",
		args:   "auth keys delete 7 --force",
		setup:  withToken([]string{"tag:ci"}, "auth_keys:read"),
		env:    tokenEnv,
		stderr: "Error: this credential may not do that.\nIt lacks the scope auth_keys.\n",
		code:   1,
	},
}

func TestAuthKeysDelete(t *testing.T) {
	t.Parallel()

	runCases(t, keyring, authKeysDeleteCases)
}
