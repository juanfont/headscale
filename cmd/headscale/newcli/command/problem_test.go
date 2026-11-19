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
		{"unauthorized", clientv0.Problem{Code: clientv0.Unauthorized}, "the server did not accept the API key."},
		{"forbidden", clientv0.Problem{Code: clientv0.Forbidden}, "this credential may not do that."},
		{
			"forbidden for scopes",
			clientv0.Problem{Code: clientv0.Forbidden, Details: map[string]any{"scopes": []any{"users", "devices:core"}, "rule": nil}},
			"this credential may not do that.\nIt lacks the scope users, devices:core.",
		},
		{
			"forbidden by a rule",
			clientv0.Problem{Code: clientv0.Forbidden, Details: map[string]any{"scopes": []any{}, "rule": "tags_of_token"}},
			"this credential may not do that.\nA token rule refuses it: tags_of_token.",
		},
		{
			"forbidden by a rule this build knows",
			clientv0.Problem{Code: clientv0.Forbidden, Details: map[string]any{"scopes": []any{}, "rule": "token_cannot_change_user_name_or_email"}},
			"this credential may not do that.\nAn OAuth access token cannot change the name or the email of a user; an API key can.",
		},
		{
			"not found names the object",
			clientv0.Problem{Code: clientv0.NotFound, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "node", Id: "12", Name: "mynode"})},
			"Node 12 (mynode) no longer exists.",
		},
		{"not found with no object", clientv0.Problem{Code: clientv0.NotFound, Title: "Not found"}, "Not found (not_found)."},
		{
			"unhealthy lists the reasons",
			clientv0.Problem{Code: clientv0.Unhealthy, Details: map[string]any{"reasons": []any{
				map[string]any{"code": "database_unreachable", "message": "The database does not answer."},
			}}},
			"the server is not healthy:\n  The database does not answer.",
		},
		{
			"invalid field names each field",
			clientv0.Problem{Code: clientv0.InvalidField, Errors: []clientv0.FieldError{{Location: "body.name", Message: "is too long"}}},
			"the server refused a value:\n  body.name: is too long",
		},
		{
			"name taken names the holder and the name",
			clientv0.Problem{
				Code: clientv0.NameTaken, Details: map[string]any{"name": "bob"},
				Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "4", Name: "bob@example.com"}),
			},
			`the name "bob" belongs to User 4 (bob@example.com).`,
		},
		{
			"name taken without the name",
			clientv0.Problem{Code: clientv0.NameTaken, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "node", Id: "27", Name: "web-1"})},
			"the name belongs to Node 27 (web-1).",
		},
		{
			"email taken names the holder and the email",
			clientv0.Problem{
				Code: clientv0.EmailTaken, Details: map[string]any{"email": "Bob@example.com"},
				Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "4", Name: "bob@example.com"}),
			},
			`the email "Bob@example.com" belongs to User 4 (bob@example.com).`,
		},
		{
			"email taken without the email",
			clientv0.Problem{Code: clientv0.EmailTaken, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "4", Name: "bob"})},
			"the email belongs to User 4 (bob).",
		},
		{"name taken with no holder", clientv0.Problem{Code: clientv0.NameTaken, Title: "The name is taken"}, "The name is taken (name_taken)."},
		{
			"a user of OIDC",
			clientv0.Problem{Code: clientv0.UserManagedByOidc, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "user", Id: "5", Name: "carol@example.com"})},
			"User 5 (carol@example.com) is managed by OIDC and cannot be edited here.",
		},
		{"too large", clientv0.Problem{Code: clientv0.TooLarge}, "the file is too large for the server."},
		{"internal names the request", clientv0.Problem{Code: clientv0.Internal, RequestId: "Zx81kq3f9a0c"}, "the server had an internal error. Its log has the request Zx81kq3f9a0c."},
		{"a code this build does not know", clientv0.Problem{Code: "user_has_nodes", Title: "The user still owns nodes"}, "The user still owns nodes (user_has_nodes)."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.EqualError(t, &ProblemError{Problem: tt.p}, tt.want)
		})
	}

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
	}

	p := &ProblemError{Problem: clientv0.Problem{Code: clientv0.InvalidField, Errors: []clientv0.FieldError{
		{Location: "body.name", Message: "a"},
		{Location: "body.displayName", Message: "b"},
		{Location: "body.profilePicUrl", Message: "c"},
		{Location: "body.other", Message: "d"},
		{Location: "query.pageSize", Message: "e"},
	}}}

	require.Equal(t, "the server refused a value:\n"+
		"  <name>: a\n  --display-name: b\n  --picture-url: c\n  body.other: d\n  query.pageSize: e",
		sentence(flagsOf[in](fmt.Errorf("wrapped: %w", p))))
	require.Equal(t, errBroken, flagsOf[in](errBroken))
}
