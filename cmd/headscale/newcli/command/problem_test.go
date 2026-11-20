package command

import (
	"fmt"
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
		{"unauthorized", clientv0.Problem{Code: clientv0.ProblemCodeUnauthorized}, "the server did not accept the API key."},
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
			"this credential may not do that.\nIt lacks the scope users, devices:core.",
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
