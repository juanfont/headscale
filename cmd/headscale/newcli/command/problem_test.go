package command

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

func TestProblemSentence(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		p    clientv0.Problem
		want string
	}{
		{"unauthorized", clientv0.Problem{Code: clientv0.ProblemCodeUnauthorized}, "the server did not accept the credential of this CLI: it is unknown, expired or revoked.\nIt is set by cli.api_key in the config file, or HEADSCALE_CLI_API_KEY."},
		// Text of the server cannot end the line and write one of its own.
		{"a title with a line break", clientv0.Problem{Code: "new_code", Title: "New\nError: fake"}, `New\x0aError: fake (new_code).`},
		{
			"a reason with a line break",
			clientv0.Problem{Code: clientv0.ProblemCodeUnhealthy, Details: map[string]any{"reasons": []any{map[string]any{"message": "db\nfake"}}}},
			"the server is not healthy:\n  " + `db\x0afake`,
		},
		{
			"a field message with a line break",
			clientv0.Problem{Code: clientv0.ProblemCodeInvalidField, Errors: []clientv0.FieldError{{Location: "body.x", Message: "bad\nError: fake"}}},
			"the server refused a value:\n  body.x (as the server names it): " + `bad\x0aError: fake`,
		},
		{"forbidden", clientv0.Problem{Code: clientv0.ProblemCodeForbidden}, "this credential may not do that."},
		{
			"forbidden for scopes",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{"users", "devices:core"}, "rule": nil}},
			"this credential may not do that.\nIt lacks the scopes users and devices:core.",
		},
		{
			"forbidden for three scopes",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{"users", "devices:core", "auth_keys"}}},
			"this credential may not do that.\nIt lacks the scopes users, devices:core and auth_keys.",
		},
		{
			"forbidden by a rule",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "tags_of_token"}},
			"this credential may not do that.\nA token rule refuses it: tags_of_token.",
		},
		{
			"forbidden by a rule this build knows",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_cannot_change_user_name_or_email"}},
			"this credential may not do that.\nAn OAuth access token cannot change the name or the email of a user; an API key can.",
		},
		{
			"not found names the object",
			clientv0.Problem{Code: clientv0.ProblemCodeNotFound, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "node", Id: "12", Name: "mynode"})},
			"Node 12 (mynode) no longer exists.",
		},
		{
			"not found of an auth request names no ID, also when the server sent one",
			clientv0.Problem{Code: clientv0.ProblemCodeNotFound, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "authRequest", Id: "hskey-authreq-0123456789abcdef01234567"})},
			"no auth request has this ID. It may have timed out, or it was answered already.",
		},
		{
			"a registration answered with the verb of an SSH check",
			clientv0.Problem{Code: clientv0.ProblemCodeAuthRequestKind, Details: map[string]any{"kind": "registration"}},
			"this is a registration request. It needs a user:\n  headscale auth register <auth-id> <user>",
		},
		{
			"an SSH check answered with the verb of a registration",
			clientv0.Problem{Code: clientv0.ProblemCodeAuthRequestKind, Details: map[string]any{"kind": "sshCheck"}},
			"this is an SSH check request. Use:\n  headscale auth approve <auth-id>",
		},
		{
			"not found of an auth request whose object is a hostname and no ID",
			clientv0.Problem{Code: clientv0.ProblemCodeNotFound, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "authRequest", Name: "newlaptop"})},
			"no auth request has this ID. It may have timed out, or it was answered already.",
		},
		{
			"a registration refused: the node key is another node's",
			clientv0.Problem{Code: clientv0.ProblemCodeRegistrationRefused, Details: map[string]any{"reason": "nodeKeyInUse"}},
			"the node key of this machine belongs to another node already.\nRun tailscale logout on the machine, then tailscale up, and answer the request it shows then.",
		},
		{
			"a registration refused: the report is too large",
			clientv0.Problem{Code: clientv0.ProblemCodeRegistrationRefused, Details: map[string]any{"reason": "reportTooLarge"}},
			"this machine reported more about itself than the server takes.\nHave it advertise less, such as fewer routes or tags, and answer the request it shows then.",
		},
		{
			"a registration refused for a reason this build does not know",
			clientv0.Problem{Code: clientv0.ProblemCodeRegistrationRefused, Details: map[string]any{"reason": "new\nError: x"}},
			`the server refused the registration (new\x0aError: x).`,
		},
		{
			"the cache of auth requests is full",
			clientv0.Problem{Code: clientv0.ProblemCodeUnhealthy, Details: map[string]any{"reasons": []any{
				map[string]any{"code": "auth_requests_full", "message": "The cache is full."},
			}}},
			"the server holds as many auth requests as it takes. Answer some, or wait until they time out, then run the command again.",
		},
		{"a kind of auth request this build does not know", clientv0.Problem{Code: clientv0.ProblemCodeAuthRequestKind, Title: "Wrong kind", Details: map[string]any{"kind": "new"}}, "Wrong kind (auth_request_kind)."},
		{
			"a token cannot register a node to a user",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_cannot_register_node_to_user"}},
			"this credential may not do that.\nAn OAuth access token cannot register a node to a user; an API key can.",
		},
		{
			"a token cannot approve an SSH check",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_cannot_approve_ssh_check"}},
			"this credential may not do that.\nAn OAuth access token cannot approve an SSH check; an API key can, and a token may reject one.",
		},
		{"tags required of what is no node, such as a key", clientv0.Problem{Code: clientv0.ProblemCodeTagsRequired}, "the tag list is empty."},
		{
			"tags not permitted names them, escaped",
			clientv0.Problem{Code: clientv0.ProblemCodeTagsNotPermitted, Details: map[string]any{"tags": []any{"tag:serverr", "tag:x\nError: fake"}}},
			"these tags are not in the policy: tag:serverr, " + `tag:x\x0aError: fake.`,
		},
		{"expiry in past", clientv0.Problem{Code: clientv0.ProblemCodeExpiryInPast}, "the expiry is in the past."},
		{"update refused: not connected", refusal("notConnected", ""), "Node 12 (mynode) is not connected."},
		{"update refused: updates not allowed", refusal("updatesNotAllowed", ""), `Node 12 (mynode) does not allow remote updates. Run "tailscale set --auto-update" on it.`},
		{"update refused: the client's text, escaped", refusal("clientRefused", "not supported\nError: fake"), `Node 12 (mynode) refused the update: not supported\x0aError: fake`},
		{"update refused: the client sent no text", refusal("clientRefused", ""), "Node 12 (mynode) refused the update."},
		{"update refused: timeout", refusal("timeout", ""), "Node 12 (mynode) did not answer in time."},
		{"update refused: a reason this build does not know", refusal("new\nreason", ""), `Node 12 (mynode) did not start the update (new\x0areason).`},
		{
			"forbidden by the rule on tags",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_must_own_tags"}},
			"this credential may not do that.\nAn OAuth access token gives a key or an OAuth client only tags it holds or owns; an API key may give any tag of the policy.",
		},
		{
			"forbidden by the rule on keys for a user",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_cannot_create_key_for_user"}},
			"this credential may not do that.\nAn OAuth access token makes only tagged keys; an API key may make a key for a user.",
		},
		{"owner conflict, both or none", clientv0.Problem{Code: clientv0.ProblemCodeOwnerConflict}, "a key needs one owner: one user, or tags, not both."},
		{"an unknown scope", clientv0.Problem{Code: clientv0.ProblemCodeInvalidScope, Details: map[string]any{"scopes": []any{"devices:cor"}}}, "unknown scope: devices:cor."},
		{"unknown scopes", clientv0.Problem{Code: clientv0.ProblemCodeInvalidScope, Details: map[string]any{"scopes": []any{"a", "b\nError: fake"}}}, "unknown scopes: a, " + `b\x0aError: fake.`},
		{"a scope that needs tags", clientv0.Problem{Code: clientv0.ProblemCodeScopeRequiresTags, Details: map[string]any{"scopes": []any{"auth_keys"}}}, "scope auth_keys needs at least one tag (--tags)."},
		{"scopes that need tags", clientv0.Problem{Code: clientv0.ProblemCodeScopeRequiresTags, Details: map[string]any{"scopes": []any{"auth_keys", "devices:core"}}}, "scopes auth_keys, devices:core need at least one tag (--tags)."},
		{
			"a token makes no API key",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_cannot_create_api_key"}},
			"this credential may not do that.\nAn OAuth access token cannot make an API key: an API key may do everything, so only an API key or the socket makes one.",
		},
		{
			"a token gives a client only its own scopes",
			clientv0.Problem{Code: clientv0.ProblemCodeForbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_must_hold_scopes"}},
			"this credential may not do that.\nAn OAuth access token makes an OAuth client with only scopes it holds itself.",
		},
		{"expiry required", clientv0.Problem{Code: clientv0.ProblemCodeExpiryRequired}, "a key must have an expiry."},
		{"not found with no object", clientv0.Problem{Code: clientv0.ProblemCodeNotFound, Title: "Not found"}, "Not found (not_found)."},
		{
			"unhealthy lists the reasons",
			clientv0.Problem{Code: clientv0.ProblemCodeUnhealthy, Details: map[string]any{"reasons": []any{
				map[string]any{"code": "database_unreachable", "message": "The database does not answer."},
			}}},
			"the server is not healthy:\n  The database does not answer.",
		},
		{
			"invalid field names each field",
			clientv0.Problem{Code: clientv0.ProblemCodeInvalidField, Errors: []clientv0.FieldError{{Location: "body.name", Message: "is too long"}}},
			"the server refused a value:\n  body.name (as the server names it): is too long",
		},
		{
			"name taken names the holder and the name",
			clientv0.Problem{
				Code: clientv0.ProblemCodeNameTaken, Details: map[string]any{"name": "bob"},
				Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "4", Name: "bob@example.com"}),
			},
			`the name "bob" belongs to User 4 (bob@example.com).`,
		},
		{
			"name taken without the name",
			clientv0.Problem{Code: clientv0.ProblemCodeNameTaken, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "node", Id: "27", Name: "web-1"})},
			"the name belongs to Node 27 (web-1).",
		},
		{
			"email taken names the holder and the email",
			clientv0.Problem{
				Code: clientv0.ProblemCodeEmailTaken, Details: map[string]any{"email": "Bob@example.com"},
				Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "4", Name: "bob@example.com"}),
			},
			`the email "Bob@example.com" belongs to User 4 (bob@example.com).`,
		},
		{
			"email taken without the email",
			clientv0.Problem{Code: clientv0.ProblemCodeEmailTaken, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "4", Name: "bob"})},
			"the email belongs to User 4 (bob).",
		},
		{"name taken with no holder", clientv0.Problem{Code: clientv0.ProblemCodeNameTaken, Title: "The name is taken"}, "The name is taken (name_taken)."},
		{
			"a user of OIDC",
			clientv0.Problem{Code: clientv0.ProblemCodeUserManagedByOidc, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "5", Name: "carol@example.com"})},
			"User 5 (carol@example.com) is managed by OIDC and cannot be edited here.",
		},
		{"too large", clientv0.Problem{Code: clientv0.ProblemCodeTooLarge}, "the file is too large for the server."},
		{
			"a policy refused, each problem at its line, a control made visible",
			policyRefused([]any{
				map[string]any{"message": `unknown tag "tag:serverr"`, "line": 14, "column": 30},
				map[string]any{"message": "no place\nError: fake", "line": nil, "column": nil},
			}, 2, []any{
				map[string]any{"kind": "acl", "index": 2, "src": "alice@", "dst": "10.0.0.1:22", "user": nil, "want": "accept", "got": "deny", "line": 30, "column": 5},
				map[string]any{"kind": "ssh", "index": 0, "src": "bob@", "dst": "bob@", "user": "root", "want": "deny", "got": "check", "line": nil, "column": nil},
			}, 2),
			"the policy is not valid.\n" +
				"  line 14, column 30: unknown tag \"tag:serverr\"\n" +
				"  line 30, column 5: test alice@ -> 10.0.0.1:22: expected accept, got deny\n" +
				"  no place\\x0aError: fake\n" +
				"  sshTests[0]: bob@ -> bob@ as root: expected deny, got check",
		},
		{
			"a policy refused, in the order of the file, a line with no column, and tests that did not run",
			func() clientv0.Problem {
				p := policyRefused([]any{
					map[string]any{"message": "c", "line": 3, "column": 9},
					map[string]any{"message": "a", "line": 1, "column": 57},
					map[string]any{"message": "b", "line": 3, "column": 2},
					map[string]any{"message": "only a line", "line": 2, "column": nil},
				}, 4, []any{
					map[string]any{"kind": "ssh", "index": 1, "src": "alice@", "dst": "alice@", "user": "root", "want": "accept", "got": "deny", "line": 2, "column": 5},
				}, 1)
				p.Details["testsNotRun"] = 3

				return p
			}(),
			"the policy is not valid.\n" +
				"  line 1, column 57: a\n" +
				"  line 2: only a line\n" +
				"  line 2, column 5: SSH test alice@ -> alice@ as root: expected accept, got deny\n" +
				"  line 3, column 2: b\n" +
				"  line 3, column 9: c\n" +
				"  3 tests did not run, because of the problems above.",
		},
		{
			"a policy refused with lists the server cut",
			policyRefused([]any{map[string]any{"message": `unknown tag "tag:a"`, "line": 1, "column": 2}}, 150,
				[]any{map[string]any{"kind": "acl", "index": 0, "src": "a@", "dst": "b@:1", "want": "deny", "got": "accept", "line": 3, "column": 1}}, 101),
			"the policy is not valid.\n" +
				"  line 1, column 2: unknown tag \"tag:a\"\n" +
				"  line 3, column 1: test a@ -> b@:1: expected deny, got accept\n" +
				"  150 problems in all; the first 1 are shown.\n" +
				"  101 failed tests in all; the first 1 are shown.",
		},
		{"a policy file", clientv0.Problem{Code: clientv0.ProblemCodePolicyReadOnly, Details: map[string]any{"path": "/etc/headscale/policy.hujson"}}, "the policy is read from /etc/headscale/policy.hujson. Edit that file."},
		{
			"a policy file that is not set",
			clientv0.Problem{Code: clientv0.ProblemCodePolicyReadOnly, Details: map[string]any{"path": ""}},
			"no policy file is set (policy.path), and the policy cannot be written while policy.mode is file.",
		},
		{"internal names the request", clientv0.Problem{Code: clientv0.ProblemCodeInternal, RequestId: "Zx81kq3f9a0c"}, "the server had an internal error. Its log has the request Zx81kq3f9a0c."},
		{"a code this build does not know", clientv0.Problem{Code: "user_has_nodes", Title: "The user still owns nodes"}, "The user still owns nodes (user_has_nodes)."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.EqualError(t, &ProblemError{Problem: tt.p}, tt.want)
		})
	}

	node := &ProblemError{Problem: clientv0.Problem{Code: clientv0.ProblemCodeTagsRequired}, target: clientv0.ProblemObject{Kind: "node", Id: "12"}}
	require.EqualError(t, node, "the tag list is empty. A tagged node needs at least one tag.", "tags required of a node")

	require.EqualError(t, problemOf(502, []byte("<html>")), "the server answered 502 Bad Gateway")

	reload := &ProblemError{Problem: policyRefused([]any{map[string]any{"message": "x", "line": 1, "column": 1}}, 1, []any{}, 0), kept: true}
	require.EqualError(t, reload, "the policy is not valid. The old policy is still in use.\n  line 1, column 1: x", "a reload refused")
}

// policyRefused is policy_invalid with its details as the server sends them.
func policyRefused(errs []any, errCount int, tests []any, testCount int) clientv0.Problem {
	return clientv0.Problem{Code: clientv0.ProblemCodePolicyInvalid, Details: map[string]any{
		"policyErrors": errs, "policyErrorCount": errCount, "failedTests": tests, "failedTestCount": testCount,
	}}
}

// TestFlagsOf: an invalid_field entry names the flag or the argument that
// filled the field, not its place in the body.
func TestFlagsOf(t *testing.T) {
	t.Parallel()

	type in struct {
		Name          string      `arg:"name"`
		DisplayName   Opt[string] `flag:"display-name" help:"x"`
		ProfilePicURL string      `flag:"picture-url"  help:"x"`
		Owner         Owner       `arg:"owner"`
	}

	type entities struct {
		Scopes []string           `arg:"scopes"`
		User   Opt[clientv0.User] `flag:"user"  help:"x"`
		Tags   []string           `flag:"tags"  help:"x"`
	}

	p := &ProblemError{Problem: clientv0.Problem{Code: clientv0.ProblemCodeInvalidField, Errors: []clientv0.FieldError{
		{Location: "body.name", Message: "a"},
		{Location: "body.displayName", Message: "b"},
		{Location: "body.profilePicUrl", Message: "c"},
		{Location: "body.other", Message: "d"},
		{Location: "query.pageSize", Message: "e"},
		{Location: "body.userId", Message: "f"},
		{Location: "body.tags[1]", Message: "g"},
	}}}

	require.Equal(t, "the server refused a value:\n"+
		"  <name>: a\n  --display-name: b\n  --picture-url: c\n  body.other (as the server names it): d\n  query.pageSize (as the server names it): e\n  <owner>: f\n  <owner>: g",
		sentence(flagsOf[in](fmt.Errorf("wrapped: %w", p))))
	require.Equal(t, errBroken, flagsOf[in](errBroken))

	p = &ProblemError{Problem: clientv0.Problem{Code: clientv0.ProblemCodeInvalidField, Errors: []clientv0.FieldError{
		{Location: "body.userId", Message: "a"},
		{Location: "body.tags[1]", Message: "b"},
		{Location: "body.scopes", Message: "c"},
		{Location: "body.scopes[0]", Message: "d"},
	}}}

	require.Equal(t, "the server refused a value:\n  --user: a\n  --tags: b\n  <scopes>: c\n  <scopes>: d", sentence(flagsOf[entities](p)))
}

// refusal is an update_refused of Node 12 (mynode) for reason.
func refusal(reason, clientError string) clientv0.Problem {
	return clientv0.Problem{
		Code:    clientv0.ProblemCodeUpdateRefused,
		Object:  nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "node", Id: "12", Name: "mynode"}),
		Details: map[string]any{"reason": reason, "clientError": clientError},
	}
}

// hasNodesOf is a problem about User 3 named name, with details.nodes of
// the names given.
// TestHasNodes: user_has_nodes names every node, and the line to delete
// them together names the user by the word typed when it can be typed
// again and finds this user alone, which the lookup that it came through
// knows; by the ID otherwise.
func TestHasNodes(t *testing.T) {
	t.Parallel()

	const line = "\nDelete or tag them first, or delete them together:\n  headscale users delete "

	for _, tt := range []struct {
		name, login, word string
		nodes             []any
		want              string
	}{
		{"the name typed", "alice", "alice", []any{"web", "db"}, "User 3 (alice) still owns 2 nodes: web, db." + line + "alice --with-nodes"},
		{"one node", "alice", "alice", []any{"web"}, "User 3 (alice) still owns 1 node: web." + line + "alice --with-nodes"},
		{"an email typed", "carol", "carol@example.com", []any{"web"}, "User 3 (carol) still owns 1 node: web." + line + "carol@example.com --with-nodes"},
		{"the ID typed", "alice", "3", []any{"web"}, "User 3 (alice) still owns 1 node: web." + line + "3 --with-nodes"},
		// The login name may be another user's email or name: only the word
		// the lookup found this user by is known to find it alone.
		{"not the login name, which may match another user too", "bob@example.com", "3", []any{"web"}, "User 3 (bob@example.com) still owns 1 node: web." + line + "3 --with-nodes"},
		{"a word of digits that is not the ID would be read as one", "42", "42", []any{"web"}, "User 3 (42) still owns 1 node: web." + line + "3 --with-nodes"},
		{"a word with a dash first would be read as a flag", "-alice", "-alice", []any{"web"}, "User 3 (-alice) still owns 1 node: web." + line + "3 --with-nodes"},
		{"a word a shell would split", "a b;rm", "a b;rm", []any{"web\nError: fake"}, "User 3 (a b;rm) still owns 1 node: " + `web\x0aError: fake` + "." + line + "3 --with-nodes"},
		{"no word typed", "alice", "", []any{"web"}, "User 3 (alice) still owns 1 node: web." + line + "3 --with-nodes"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			e := &ProblemError{Problem: hasNodesOf(tt.login, tt.nodes), word: tt.word}
			require.Equal(t, tt.want, e.Error())
		})
	}
}

func hasNodesOf(name string, nodes []any) clientv0.Problem {
	list := make([]any, 0, len(nodes))
	for i, n := range nodes {
		list = append(list, map[string]any{"id": strconv.Itoa(i + 1), "name": n})
	}

	return clientv0.Problem{
		Code:    clientv0.ProblemCodeUserHasNodes,
		Object:  nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "3", Name: name}),
		Details: map[string]any{"nodes": list},
	}
}

func TestProblemFieldNames(t *testing.T) {
	t.Parallel()

	const raw = `{"code":"new_issue","coDe":"extra_code","title":"Known","titLe":"Extra","object":{"name":"alpha","naMe":"beta"}}`

	err := problemOf(http.StatusUnprocessableEntity, []byte(raw))
	problem, ok := errors.AsType[*ProblemError](err)
	require.True(t, ok)

	obj, err := problem.Problem.Object.Get()
	require.NoError(t, err)
	require.Equal(t, []string{"new_issue", "Known", "alpha"}, []string{string(problem.Problem.Code), problem.Problem.Title, obj.Name})
}

func TestPolicyProblemFieldNames(t *testing.T) {
	t.Parallel()

	const raw = `{"code":"policy_invalid","details":{"policyErrors":[{"message":"alpha","messAge":"beta"}],"policyerrors":[{"message":"extra"}]}}`
	require.EqualError(t, problemOf(http.StatusUnprocessableEntity, []byte(raw)), "the policy is not valid.\n  alpha")
}
