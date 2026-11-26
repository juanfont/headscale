package newcli

import (
	"cmp"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// The auth IDs of the cases: real in form, made up in content. exampleID
// is the one of the examples.
const (
	exampleID = "hskey-authreq-0123456789abcdef01234567"
	sshID     = "hskey-authreq-0123456789abcdef0123ffff"
	taggedID  = "hskey-authreq-0123456789abcdef0123eeee"
	unknownID = "hskey-authreq-0123456789abcdef0123dddd"
	// approveRegID is the registration of the cases of approve, whose
	// example is an SSH check.
	approveRegID = "hskey-authreq-0123456789abcdef0123cccc"
	// clonedID is a registration of a machine the server refuses.
	clonedID = "hskey-authreq-0123456789abcdef0123bbbb"
)

const requestsPolicy = `{
	"tagOwners": {"tag:ci": ["alice@"]},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
}`

// idVar keeps exampleID in $id, the shell variable of the examples.
func idVar(tb testing.TB, f *fixture) {
	tb.Helper()

	f.vars["id"] = exampleID
}

// requests is the state of the proposal's example: alice (1) and bob (2);
// alice's nodes mynode (1) and builder (2); a registration of newlaptop
// under exampleID; an SSH check from mynode to builder under sshID; and a
// registration of ci-box that asks for tag:ci, which alice may give, under
// taggedID.
func requests(tb testing.TB, f *fixture) {
	tb.Helper()
	requestsAt(tb, f, exampleID, sshID)
}

// requestsUnder is requests with the registration of newlaptop under reg
// and the SSH check under ssh.
func requestsUnder(reg, ssh types.AuthID) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		requestsAt(tb, f, reg, ssh)
	}
}

func requestsAt(tb testing.TB, f *fixture, reg, ssh types.AuthID) {
	tb.Helper()

	st := f.srv.State()

	_, err := st.SetPolicy([]byte(requestsPolicy))
	require.NoError(tb, err)

	alice := f.srv.CreateUser(tb, "alice")
	f.srv.CreateUser(tb, "bob")

	var nodes [2]types.NodeID

	for i, name := range []string{"mynode", "builder"} {
		k, err := st.CreatePreAuthKey(
			new(types.UserID(alice.ID)),
			false,
			false,
			nil,
			nil,
		)
		require.NoError(tb, err)

		n, _, err := st.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: k.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: name},
		}, key.NewMachine().Public())
		require.NoError(tb, err)

		nodes[i] = n.ID()
	}

	pending(tb, f, reg, "newlaptop")
	require.NoError(
		tb,
		st.SetAuthCacheEntry(ssh, types.NewSSHCheckAuthRequest(nodes[0], nodes[1])),
	)
	pending(tb, f, taggedID, "ci-box", "tag:ci")
}

// pending is a registration of a new machine under id.
func pending(
	tb testing.TB,
	f *fixture,
	id types.AuthID,
	hostname string,
	tags ...string,
) {
	tb.Helper()

	require.NoError(
		tb,
		f.srv.State().
			SetAuthCacheEntry(id, types.NewRegisterAuthRequest(&types.RegistrationData{
				MachineKey: key.NewMachine().Public(),
				NodeKey:    key.NewNode().Public(),
				Hostname:   hostname,
				Hostinfo:   &tailcfg.Hostinfo{Hostname: hostname, RequestTags: tags},
			})),
	)
}

// cloned waits under clonedID: another machine that sent the node key of
// mynode.
func cloned(tb testing.TB, f *fixture) {
	tb.Helper()

	n, ok := f.srv.State().GetNodeByID(1)
	require.True(tb, ok)
	pendingMachine(tb, f, key.NewMachine().Public(), n.NodeKey(), "cloned")
}

// tooLarge waits under clonedID: mynode's machine logs in again, and its
// report merged with mynode's is over the limit.
func tooLarge(tb testing.TB, f *fixture) {
	tb.Helper()

	st := f.srv.State()
	n, ok := st.GetNodeByID(1)
	require.True(tb, ok)

	big := n.AsStruct()
	big.Hostinfo = &tailcfg.Hostinfo{Hostname: big.Hostname, OSVersion: "v"}
	encoded, err := json.Marshal(big.Hostinfo)
	require.NoError(tb, err)

	big.Hostinfo.OSVersion = strings.Repeat("v", types.MaxHostinfoSize-len(encoded))
	st.PutNodeInStoreForTest(*big)
	pendingMachine(
		tb,
		f,
		big.MachineKey,
		key.NewNode().Public(),
		strings.Repeat("h", types.MaxHostnameLength),
	)
}

// pendingMachine is a registration under clonedID of the machine with these keys.
func pendingMachine(
	tb testing.TB,
	f *fixture,
	machine key.MachinePublic,
	node key.NodePublic,
	hostname string,
) {
	tb.Helper()

	require.NoError(
		tb,
		f.srv.State().
			SetAuthCacheEntry(clonedID, types.NewRegisterAuthRequest(&types.RegistrationData{
				MachineKey: machine,
				NodeKey:    node,
				Hostname:   hostname,
				Hostinfo:   &tailcfg.Hostinfo{Hostname: hostname},
			})),
	)
}

// timedOut waits until every auth request of the case timed out.
func timedOut(tb testing.TB, f *fixture) {
	tb.Helper()

	require.EventuallyWithT(tb, func(c *assert.CollectT) {
		for _, id := range []types.AuthID{exampleID, sshID, taggedID, approveRegID} {
			_, ok := f.srv.State().AuthRequest(id)
			assert.False(c, ok)
		}
	}, 5*time.Second, 10*time.Millisecond)
}

// answeredBefore answers id before the case: it is gone.
func answeredBefore(id types.AuthID) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		require.NoError(tb, f.srv.State().AnswerAuthRequest(id, false))
	}
}

// waiting holds whether id still waits for an answer, after the case.
func waiting(id types.AuthID, want bool) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, f *fixture, _ result) {
		tb.Helper()

		_, ok := f.srv.State().AuthRequest(id)
		require.Equal(tb, want, ok, "%s waits", id.Hidden())
	}
}

// asked holds the requests of the case, in order.
func asked(want ...string) func(testing.TB, *fixture, result) {
	return func(tb testing.TB, _ *fixture, r result) {
		tb.Helper()
		require.Equal(tb, want, r.asked)
	}
}

// lostAnswer is what follows a write on an auth request whose answer was
// lost.
const lostAnswer = "Error: the server at {proxyhost} did not answer the change: the connection was closed.\n" +
	"The change may have been made: look before you run the command again.\n" +
	"To look, run the same command again: a request that was answered is gone, and it says so.\n"

const (
	v0          = "/api/headscale/v0"
	getExample  = "GET " + v0 + "/auth-requests/" + exampleID
	getSSH      = "GET " + v0 + "/auth-requests/" + sshID
	wrongVerbSS = "Error: this is an SSH check request. Use:\n  headscale auth approve <auth-id>\n"
	wrongVerbRg = "Error: this is a registration request. It needs a user:\n  headscale auth register <auth-id> <user>\n"
	goneText    = "Error: no auth request has this ID. It may have timed out, or it was answered already.\n"
	notAuthID   = "is not an auth ID: it starts with hskey-authreq-, as the end of the URL the node shows.\n"
	repeatedID  = "Error: the command was done, but the server's answer repeats <auth-id>, a secret, so it is not printed. This is a fault of the server.\n"
	//nolint:gosec // a sentence, not a credential
	tokenRule = "An OAuth access token cannot approve an SSH check; an API key can, and a token may reject one.\n"
)

var authRegisterCases = []cliCase{
	{
		name:   "the example: a node for alice",
		args:   `auth register "$id" alice`,
		setup:  idVar,
		stdout: "Node 3 (newlaptop) registered to User 1 (alice).\n",
		check: both(
			waiting(exampleID, false),
			asked(
				"GET "+v0+"/users?pageSize=2",
				"POST "+v0+"/auth-requests/"+exampleID+"/register",
			),
		),
	},
	{
		name: "-o json is the new node",
		args: `auth register "$id" 3 -o json`,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			idVar(tb, f)
			f.srv.CreateUser(tb, "carol")
		},
		want: answer(v0 + "/auth-requests/" + exampleID + "/register"),
	},
	{
		name:   "a node that asked for tags its user may give joins tagged",
		args:   "auth register " + taggedID + " alice",
		stdout: "Node 3 (ci-box) registered, tagged tag:ci.\n",
	},
	{
		name:   "the user by ID",
		args:   "auth register " + exampleID + " 2",
		stdout: "Node 3 (newlaptop) registered to User 2 (bob).\n",
	},
	{
		name: "an SSH check takes approve", args: "auth register " + sshID + " alice",
		stderr: wrongVerbSS, code: 1, check: waiting(sshID, true),
	},
	{
		name:   "a user nobody is",
		args:   "auth register " + exampleID + " nobody",
		stderr: "Error: no user matches \"nobody\".\n",
		code:   1,
		check:  waiting(exampleID, true),
	},
	{
		name:   "tags are no user",
		args:   "auth register " + exampleID + " tag:ci",
		code:   1,
		stderr: "Error: a tag is not a user.\nA node joins tagged when it asks for tags its user may give (tailscale up --advertise-tags): register it to that user.\n",
	},
	{
		name:   "the URL the node shows: the ID is taken from it",
		args:   "auth register https://hs.example.com/register/" + exampleID + " alice",
		stdout: "Node 3 (newlaptop) registered to User 1 (alice).\n",
		check: asked(
			"GET "+v0+"/users?pageSize=2",
			"POST "+v0+"/auth-requests/"+exampleID+"/register",
		),
	},
	{
		name:   "a node that asked for tags its user may not give",
		args:   "auth register " + taggedID + " bob",
		stderr: "Error: User 2 (bob) may not give tag:ci, which the node asked for. Register it to a user that owns the tag, or the node must ask without it.\n",
		code:   1,
		check:  waiting(taggedID, true),
	},
	{
		name:  "the node key of the machine is another node's",
		args:  "auth register " + clonedID + " alice",
		setup: cloned,
		stderr: "Error: the node key of this machine belongs to another node already.\n" +
			"Run tailscale logout on the machine, then tailscale up, and answer the request it shows then.\n",
		code:  1,
		check: waiting(clonedID, true),
	},
	{
		name:  "the machine reported too much",
		args:  "auth register " + clonedID + " alice",
		setup: tooLarge,
		stderr: "Error: this machine reported more about itself than the server takes.\n" +
			"Have it advertise less, such as fewer routes or tags, and answer the request it shows then.\n",
		code:  1,
		check: waiting(clonedID, true),
	},
	{
		name: "an answer that repeats the ID is not printed",
		args: "auth register " + exampleID + " alice -o json",
		setup: rewritten(
			func(_ *fixture, body string) string { return strings.ReplaceAll(body, "newlaptop", exampleID) },
		),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: repeatedID,
		code:   1,
		check:  waiting(exampleID, false),
	},
	{
		name:   "two users are no user",
		args:   "auth register " + exampleID + " alice,bob",
		stderr: "Error: no user matches \"alice,bob\".\n",
		code:   1,
	},
	{
		name:   "an empty user",
		args:   "auth register " + exampleID + " ''",
		stderr: "Error: an empty word names no user.\n",
		code:   1,
	},
	{
		name:   "no user",
		args:   "auth register " + exampleID,
		stderr: "Error: `auth register` needs 2 arguments, got 1.\n\n  headscale auth register <auth-id> <user>\n",
		code:   1,
	},
	{
		name:   "an unknown ID",
		args:   "auth register " + unknownID + " alice",
		stderr: goneText,
		code:   1,
	},
	{
		name:   "an answered request",
		args:   "auth register " + exampleID + " alice",
		setup:  answeredBefore(exampleID),
		stderr: goneText,
		code:   1,
	},
	{
		name:   "a request that timed out",
		args:   "auth register " + exampleID + " alice",
		stderr: goneText,
		code:   1,
		server: []servertest.ServerOption{
			servertest.WithRegisterCacheExpiration(50 * time.Millisecond),
		},
		setup: timedOut,
	},
	{
		name:  "a token cannot register a node to a user",
		args:  "auth register " + exampleID + " alice",
		setup: tokenWith("devices:core", "users:read"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\nAn OAuth access token cannot register a node to a user; an API key can.\n",
		code:   1,
		check:  waiting(exampleID, true),
	},
	{
		name:  "any token is refused before its scopes are read",
		args:  "auth register " + exampleID + " alice",
		setup: tokenWith("users:read"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\nAn OAuth access token cannot register a node to a user; an API key can.\n",
		code:   1,
	},
	{
		name:  "the answer is lost: it was made",
		args:  "auth register " + exampleID + " alice",
		setup: cutAnswer("/register"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: lostAnswer,
		code:   1,
		check:  waiting(exampleID, false),
	},
}

var authApproveCases = []cliCase{
	{
		name:   "the example: an SSH check",
		args:   `auth approve "$id"`,
		setup:  idVar,
		stdout: "SSH check from Node 1 (mynode) to Node 2 (builder) approved.\n",
		check: both(
			waiting(exampleID, false),
			asked(
				"GET "+v0+"/auth-requests/"+exampleID,
				"POST "+v0+"/auth-requests/"+exampleID+"/approve",
			),
		),
	},
	{
		name:  "-o json prints nothing",
		args:  "auth approve " + exampleID + " -o json",
		check: waiting(exampleID, false),
	},
	{
		name: "a node of the check that is gone has no name",
		args: "auth approve " + exampleID,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			f.srv.State().DeleteNodeFromStoreForTest(1)
		},
		stdout: "SSH check from Node 1 to Node 2 (builder) approved.\n",
	},
	{
		name:   "a registration takes register",
		args:   "auth approve " + approveRegID,
		stderr: wrongVerbRg,
		code:   1,
		check:  waiting(approveRegID, true),
	},
	{
		name:   "an unknown ID",
		args:   "auth approve " + unknownID,
		stderr: goneText,
		code:   1,
		check:  asked("GET " + v0 + "/auth-requests/" + unknownID),
	},
	{
		name:   "an answered request",
		args:   "auth approve " + exampleID,
		setup:  answeredBefore(exampleID),
		stderr: goneText,
		code:   1,
	},
	{
		name:   "a request that timed out",
		args:   "auth approve " + exampleID,
		stderr: goneText,
		code:   1,
		server: []servertest.ServerOption{
			servertest.WithRegisterCacheExpiration(50 * time.Millisecond),
		},
		setup: timedOut,
	},
	{
		name:  "a token that may only read",
		args:  "auth approve " + exampleID,
		setup: tokenWith("devices:core:read"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\n" + tokenRule,
		code:   1,
		check:  waiting(exampleID, true),
	},
	{
		name:  "a token that may write is refused all the same",
		args:  "auth approve " + exampleID,
		setup: tokenWith("devices:core"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\n" + tokenRule,
		code:   1,
		check:  waiting(exampleID, true),
	},
	{
		name: "a kind this CLI does not know is not approved",
		args: "auth approve " + exampleID,
		setup: rewritten(
			func(_ *fixture, body string) string { return strings.ReplaceAll(body, `"sshCheck"`, `"weird"`) },
		),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: "Error: the server calls this auth request \"weird\", a kind this CLI does not know. It was not answered.\n",
		code:   1,
		check:  both(waiting(exampleID, true), asked(getExample)),
	},
	{
		name:   "the URL the node shows: the ID is taken from it",
		args:   "auth approve https://hs.example.com/a/" + exampleID,
		stdout: "SSH check from Node 1 (mynode) to Node 2 (builder) approved.\n",
		check:  asked(getExample, "POST "+v0+"/auth-requests/"+exampleID+"/approve"),
	},
	{
		name:  "a token that may not read",
		args:  "auth approve " + exampleID,
		setup: tokenWith("users"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:core:read.\n",
		code:   1,
	},
	{
		name:  "the answer is lost: it was made",
		args:  "auth approve " + exampleID,
		setup: cutAnswer("/approve"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: lostAnswer,
		code:   1,
		check:  waiting(exampleID, false),
	},
}

var (
	rejectRegistration = "Reject the registration of \"newlaptop\"? The node must start again. [y/N] "
	rejectSSH          = "Reject the SSH check from Node 1 (mynode) to Node 2 (builder)? [y/N] "
)

var authRejectCases = []cliCase{
	{
		name:     "the example: a registration, asked and answered yes",
		args:     `auth reject "$id"`,
		setup:    idVar,
		terminal: true,
		stdin:    "y\n",
		stdout:   "Registration of \"newlaptop\" rejected.\n",
		stderr:   rejectRegistration,
		check: both(
			waiting(exampleID, false),
			asked(getExample, "POST "+v0+"/auth-requests/"+exampleID+"/reject"),
		),
	},
	{
		name:   "the example with --force: not asked",
		args:   `auth reject "$id" --force`,
		setup:  idVar,
		stdout: "Registration of \"newlaptop\" rejected.\n",
		check:  waiting(exampleID, false),
	},
	{
		name:     "an SSH check, asked and answered yes",
		args:     "auth reject " + sshID,
		terminal: true,
		stdin:    "yes\n",
		stdout:   "SSH check from Node 1 (mynode) to Node 2 (builder) rejected.\n",
		stderr:   rejectSSH,
		check:    waiting(sshID, false),
	},
	{
		name:     "answered no: not rejected",
		args:     "auth reject " + sshID,
		terminal: true,
		stdin:    "n\n",
		stderr:   rejectSSH + "Aborted.\n",
		code:     1,
		check:    both(waiting(sshID, true), asked(getSSH)),
	},
	{
		name:     "no answer is no",
		args:     "auth reject " + exampleID,
		terminal: true,
		stderr:   rejectRegistration + "Aborted.\n",
		code:     1,
		check:    waiting(exampleID, true),
	},
	{
		name:     "no terminal",
		args:     "auth reject " + exampleID,
		terminal: true,
		piped:    true,
		stdin:    "\n",
		stderr:   "Error: confirmation needed, but there is no terminal.\nRun again with --force to reject the registration of \"newlaptop\".\n",
		code:     1,
		check:    waiting(exampleID, true),
	},
	{
		name:  "-o json prints nothing",
		args:  "auth reject " + sshID + " --force -o json",
		check: waiting(sshID, false),
	},
	{
		name: "a kind this CLI does not know is not rejected",
		args: "auth reject " + exampleID + " --force",
		setup: rewritten(
			func(_ *fixture, body string) string { return strings.ReplaceAll(body, `"registration"`, `""`) },
		),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: "Error: the server calls this auth request \"\", a kind this CLI does not know. It was not answered.\n",
		code:   1,
		check:  both(waiting(exampleID, true), asked(getExample)),
	},
	{
		name:   "an unknown ID",
		args:   "auth reject " + unknownID + " --force",
		stderr: goneText,
		code:   1,
	},
	{
		name:   "an answered request",
		args:   "auth reject " + exampleID + " --force",
		setup:  answeredBefore(exampleID),
		stderr: goneText,
		code:   1,
	},
	{
		name:   "a request that timed out",
		args:   "auth reject " + exampleID + " --force",
		stderr: goneText,
		code:   1,
		server: []servertest.ServerOption{
			servertest.WithRegisterCacheExpiration(50 * time.Millisecond),
		},
		setup: timedOut,
	},
	{
		name:  "a token that may only read",
		args:  "auth reject " + sshID + " --force",
		setup: tokenWith("devices:core:read"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stderr: "Error: this credential may not do that.\nIt lacks the scope devices:core.\n",
		code:   1,
		check:  waiting(sshID, true),
	},
	{
		name:  "a token may reject an SSH check",
		args:  "auth reject " + sshID + " --force",
		setup: tokenWith("devices:core"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={url}",
			"HEADSCALE_CLI_API_KEY={token}",
		},
		stdout: "SSH check from Node 1 (mynode) to Node 2 (builder) rejected.\n",
		check:  waiting(sshID, false),
	},
	{
		name:  "the answer is lost: it was made",
		args:  "auth reject " + exampleID + " --force",
		setup: cutAnswer("/reject"),
		env: []string{
			"HEADSCALE_CLI_ADDRESS={proxy}",
			"HEADSCALE_CLI_API_KEY={apikey}",
		},
		stderr: lostAnswer,
		code:   1,
		check:  waiting(exampleID, false),
	},
}

// Every command that takes an auth ID refuses the same words before any
// call.
func idCases(cmd, after string) []cliCase {
	refused := func(name, word, stderr string) cliCase {
		return cliCase{
			name:   cmd + ": " + name,
			args:   cmd + " " + word + after,
			stderr: stderr,
			code:   1,
			check:  asked(),
		}
	}

	return []cliCase{
		refused("the prefix alone", "hskey-authreq-", "Error: <auth-id> "+notAuthID),
		refused("an ID", "12", "Error: <auth-id> "+notAuthID),
		refused(
			"upper case",
			strings.ToUpper(exampleID),
			"Error: <auth-id> "+notAuthID,
		),
		refused(
			"the URL with a query",
			"https://hs.example.com/register/"+exampleID+"?x=1",
			"Error: <auth-id> "+notAuthID,
		),
		refused(
			"an API key behind the prefix",
			"hskey-authreq-hskey-api-ab12cd345678-S3cr3t",
			"Error: <auth-id> "+notAuthID,
		),
		refused("a dot", exampleID+".def", "Error: <auth-id> "+notAuthID),
		refused("a parenthesis", exampleID+")", "Error: <auth-id> "+notAuthID),
		refused("a slash", exampleID+"/", "Error: <auth-id> "+notAuthID),
		refused("a query", exampleID+"?x=1", "Error: <auth-id> "+notAuthID),
		refused("a fragment", exampleID+"#f", "Error: <auth-id> "+notAuthID),
		refused("a space", "'"+exampleID+" x'", "Error: <auth-id> "+notAuthID),
		refused("a line break", exampleID+"\nx", "Error: <auth-id> "+notAuthID),
		refused("a letter beyond ASCII", exampleID+"é", "Error: <auth-id> "+notAuthID),
		refused(
			"ten thousand characters",
			"hskey-authreq-"+strings.Repeat("0", 10000),
			"Error: <auth-id> "+notAuthID,
		),
		refused(
			"an API key",
			"hskey-api-ab12cd345678-S3cr3tS3cr3t",
			"Error: <auth-id> takes only a credential hskey-authreq-: hskey-api-*** is not sent.\n",
		),
		refused(
			"an auth key",
			"hskey-auth-ab12cd345678-S3cr3tS3cr3t",
			"Error: <auth-id> takes only a credential hskey-authreq-: hskey-auth-*** is not sent.\n",
		),
	}
}

func TestAuthRegister(t *testing.T) {
	t.Parallel()

	runCases(
		t,
		requests,
		append(authRegisterCases, idCases("auth register", " alice")...),
	)
}

func TestAuthApprove(t *testing.T) {
	t.Parallel()

	runCases(
		t,
		requestsUnder(approveRegID, exampleID),
		append(authApproveCases, idCases("auth approve", "")...),
	)
}

func TestAuthReject(t *testing.T) {
	t.Parallel()

	runCases(
		t,
		requests,
		append(authRejectCases, idCases("auth reject", " --force")...),
	)
}

// tokenWith is an OAuth access token with scopes, in the var token.
func tokenWith(scopes ...string) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()
		f.vars["token"] = f.token(tb, scopes...)
	}
}

// proxied is a proxy in front of the case's server, in the var proxy, its
// host in proxyhost, with an API key in the var apikey: serve answers each
// request, and passes one on to the server through next.
func proxied(
	serve func(f *fixture, w http.ResponseWriter, r *http.Request, next http.Handler),
) func(testing.TB, *fixture) {
	return func(tb testing.TB, f *fixture) {
		tb.Helper()

		expiry := f.now.Add(time.Hour)
		secret, _, err := f.srv.State().CreateAPIKey(&expiry)
		require.NoError(tb, err)

		target, err := url.Parse(f.vars["url"])
		require.NoError(tb, err)

		next := httputil.NewSingleHostReverseProxy(target)
		hs := httptest.NewServer(
			http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) { serve(f, w, r, next) },
			),
		)
		tb.Cleanup(hs.Close)

		f.vars["proxy"], f.vars["proxyhost"], f.vars["apikey"] = hs.URL, strings.TrimPrefix(
			hs.URL,
			"http://",
		), secret
	}
}

// cutAnswer hangs up on the POST whose path ends in verb, after the server
// answered it: the change is made, and the CLI does not know.
func cutAnswer(verb string) func(tb testing.TB, f *fixture) {
	return proxied(
		func(_ *fixture, w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, verb) {
				next.ServeHTTP(w, r)

				return
			}

			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			maps.Copy(w.Header(), rec.Header())

			conn, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		},
	)
}

// rewritten passes every request on and changes the body of each answer, as
// a server that answers otherwise would.
func rewritten(
	change func(f *fixture, body string) string,
) func(tb testing.TB, f *fixture) {
	return proxied(
		func(f *fixture, w http.ResponseWriter, r *http.Request, next http.Handler) {
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)

			body := change(f, rec.Body.String())

			maps.Copy(w.Header(), rec.Header())
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(rec.Code)
			_, _ = w.Write([]byte(body))
		},
	)
}

// authIDCommands are the commands that take an auth ID: the line that runs
// each, with {id} in the place of the ID, and the requests that may carry
// the ID, with {id} in its place: a request in the path of the one call
// that needs it, and the body of debug/nodes, which the caller fills.
var authIDCommands = map[string]struct {
	line string
	may  []string
}{
	"auth register": {
		"auth register {id} alice",
		[]string{"POST " + v0 + "/auth-requests/{id}/register {\"userId\":\"1\"}"},
	},
	"auth approve": {
		"auth approve {id}",
		[]string{
			"GET " + v0 + "/auth-requests/{id} ",
			"POST " + v0 + "/auth-requests/{id}/approve ",
		},
	},
	"auth reject": {
		"auth reject {id} --force",
		[]string{
			"GET " + v0 + "/auth-requests/{id} ",
			"POST " + v0 + "/auth-requests/{id}/reject ",
		},
	},
	"debug create-node": {
		"debug create-node --name fake-1 --key {id}",
		[]string{
			"POST " + v0 + "/debug/nodes {\"authId\":\"{id}\",\"hostname\":\"fake-1\",\"routes\":[]}",
		},
	},
}

// TestAuthIDOnce: the auth ID, a secret the admin types, leaves the CLI in
// the requests that may carry it and in no other, in no header and no query,
// whether the request was answered or not, and comes back in no byte the CLI
// writes: not on stdout or stderr, with or without -o json, in an error of
// the server, of a server that does not answer, redirects, answers HTML or
// repeats the ID, of an answer that is lost, a question, a refusal of the
// line, or Tab on a half-typed ID. Every command that takes one is here; one
// that is not fails.
func TestAuthIDOnce(t *testing.T) {
	t.Parallel()

	for _, c := range Tree().Commands() {
		_, ok := authIDCommands[c.Path]
		require.True(
			t,
			ok || len(c.Whole) == 0,
			"%s takes %v and is not in authIDCommands",
			c.Path,
			c.Whole,
		)
	}

	proxy := []string{"HEADSCALE_CLI_ADDRESS={proxy}", "HEADSCALE_CLI_API_KEY={apikey}"}

	for path, cmd := range authIDCommands {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			for _, v := range []struct {
				name, id, after string
				// typed is what a request may carry in the place of the ID;
				// "" is id.
				typed    string
				env      []string
				setup    func(testing.TB, *fixture)
				terminal bool
			}{
				{name: "a registration", id: "{reg}"},
				{name: "a registration, -o json", id: "{reg}", after: " -o json"},
				{name: "an SSH check", id: "{ssh}"},
				{name: "an SSH check, -o json", id: "{ssh}", after: " -o json"},
				{name: "unknown", id: "{new}"},
				{name: "answered", id: "{reg}", setup: func(tb testing.TB, f *fixture) {
					tb.Helper()
					require.NoError(tb, f.srv.State().AnswerAuthRequest(types.AuthID(f.vars["reg"]), false))
				}},
				{name: "asked and answered no", id: "{reg}", terminal: true},
				{name: "a token", id: "{reg}", setup: tokenWith("devices:core", "users:read"), env: []string{"HEADSCALE_CLI_ADDRESS={url}", "HEADSCALE_CLI_API_KEY={token}"}},
				{name: "a server that does not answer", id: "{reg}", env: []string{"HEADSCALE_CLI_ADDRESS=http://127.0.0.1:1", "HEADSCALE_CLI_API_KEY=k"}},
				{name: "a lost answer", id: "{reg}", setup: cutAnswer(""), env: proxy},
				{name: "a redirect to a second host", id: "{reg}", setup: redirected, env: proxy},
				{name: "a page of HTML", id: "{reg}", setup: html, env: proxy},
				{name: "an answer that repeats the ID", id: "{reg}", after: " -o json", setup: repeating, env: proxy},
				{name: "an answer that repeats the ID, text", id: "{reg}", setup: repeating, env: proxy},
				{name: "a kind this CLI does not know", id: "{reg}", setup: rewritten(func(_ *fixture, body string) string {
					return strings.ReplaceAll(body, `"registration"`, `"weird"`)
				}), env: proxy},
				{name: "the whole URL pasted", id: "https://hs.example.com/register/{reg}", typed: "{reg}"},
				{name: "upper case", id: "{upper}"},
				{name: "one character more", id: "{reg}x"},
				{name: "a dot more", id: "{reg}.x"},
				{name: "as a flag", id: "--{reg}"},
				{name: "-h", id: "{reg}", after: " -h"},
				{name: "a word too many", id: "{reg}", after: " {reg}"},
				{name: "an unknown command", id: "{reg}", after: " nope"},
			} {
				t.Run(v.name, func(t *testing.T) {
					t.Parallel()

					f := newFixture(t, false)
					reg, ssh := types.MustAuthID(), types.MustAuthID()
					requestsAt(t, f, reg, ssh)
					f.vars["reg"], f.vars["ssh"], f.vars["new"] = string(
						reg,
					), string(
						ssh,
					), string(
						types.MustAuthID(),
					)
					f.vars["upper"] = strings.ToUpper(string(reg))

					if v.setup != nil {
						v.setup(t, f)
					}

					line := strings.ReplaceAll(cmd.line, "{id}", v.id) + v.after
					if v.name == "an unknown command" {
						line = strings.Fields(path)[0] + " " + v.id + v.after
					}

					r := f.run(
						t,
						cliCase{
							args:     line,
							env:      v.env,
							terminal: v.terminal,
							stdin:    "n\n",
						},
					)

					// The word as typed is what a request may carry: the
					// CLI takes the ID whole, and the server checks it.
					typed := f.expand(cmp.Or(v.typed, v.id))
					for _, id := range []string{f.vars["reg"], f.vars["ssh"], f.vars["new"]} {
						holdsNoID(t, f, id, typed, line, r, cmd.may)
					}

					require.NotContains(
						t,
						r.stdout+r.stderr,
						"hs.example.com",
						"%s: the rest of a URL",
						line,
					)

					for _, req := range r.sent {
						require.NotContains(
							t,
							req,
							"hs.example.com",
							"%s: the rest of a URL",
							line,
						)
					}

					// Tab on a half-typed ID offers nothing, and repeats none.
					half := f.vars["reg"][:len(f.vars["reg"])-5]
					tab := f.run(
						t,
						cliCase{
							args: "__complete " + strings.ReplaceAll(
								cmd.line,
								"{id}",
								half,
							),
						},
					)
					require.NotContains(
						t,
						strings.ToLower(tab.stdout+tab.stderr),
						half[len("hskey-authreq-"):],
						"Tab",
					)
				})
			}
		})
	}
}

// pieceLength is the length of a piece of an ID's secret that the test
// looks for. The secret is hex, and an output can hold node keys, which are
// long runs of hex: six characters could match one by chance, eight do not.
const pieceLength = 8

// pieces are every piece of pieceLength of the secret of id, in lower case.
func pieces(id string) []string {
	secret := strings.ToLower(id[len("hskey-authreq-"):])

	out := make([]string, 0, len(secret))
	for i := 0; i+pieceLength <= len(secret); i++ {
		out = append(out, secret[i:i+pieceLength])
	}

	return out
}

// holdsNoID fails when a piece of id is in a byte the CLI wrote for line,
// in a header of any request, or in a request that may not carry it: one
// of may, with typed in its place.
func holdsNoID(
	t *testing.T,
	f *fixture,
	id, typed, line string,
	r result,
	may []string,
) {
	t.Helper()

	in := func(s string) bool {
		s = strings.ToLower(s)

		return slices.ContainsFunc(
			pieces(id),
			func(p string) bool { return strings.Contains(s, p) },
		)
	}

	require.False(t, in(r.stdout+r.stderr), "%s: the output holds the ID", line)
	require.Len(t, r.headers, len(r.sent))

	for i, req := range r.sent {
		for k, vs := range r.headers[i] {
			require.False(
				t,
				in(k+": "+strings.Join(vs, ", ")),
				"%s: the header %s of %q holds the ID",
				line,
				k,
				req,
			)
		}

		if !in(req) {
			continue
		}

		ok := false

		for _, m := range may {
			ok = ok || f.expand(strings.ReplaceAll(m, "{id}", typed)) == req
		}

		require.True(t, ok, "%s: the request %q may not carry the ID", line, req)
	}
}

// redirected answers every request but GET /version with a redirect to a
// second host, as a proxy that moved; a request that reaches that host
// fails the test.
func redirected(tb testing.TB, f *fixture) {
	tb.Helper()

	second := httptest.NewServer(
		http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			tb.Errorf(
				"a request reached the host of a redirect: %s %s",
				r.Method,
				r.URL,
			)
		}),
	)
	tb.Cleanup(second.Close)

	proxied(
		func(_ *fixture, w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == v0+"/version" {
				next.ServeHTTP(w, r)

				return
			}

			//nolint:gosec // the redirect is the test
			http.Redirect(
				w,
				r,
				second.URL+r.URL.RequestURI(),
				http.StatusTemporaryRedirect,
			)
		},
	)(
		tb,
		f,
	)
}

// html answers every write with a page of HTML that carries the version.
func html(tb testing.TB, f *fixture) {
	tb.Helper()

	proxied(
		func(_ *fixture, w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet {
				next.ServeHTTP(w, r)

				return
			}

			w.Header().Set("Headscale-Version", types.GetVersionInfo().Version)
			w.Header().Set("Content-Type", "text/html")
			// 201, the status of debug create-node, so that the body is judged.
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("<html>" + f.vars["reg"] + "</html>"))
		},
	)(
		tb,
		f,
	)
}

// repeating is a server whose answers repeat the ID of the registration in
// the place of its hostname, as the fake node of the review did in
// registerMethod.
var repeating = rewritten(func(f *fixture, body string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(body, "newlaptop", f.vars["reg"]),
		"mynode",
		f.vars["reg"],
	)
})
