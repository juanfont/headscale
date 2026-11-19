package command

import (
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
