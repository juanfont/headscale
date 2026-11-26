package command

import (
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// TestProblemFieldNames: a problem is read by the exact member names; a
// member that differs in case only is not the code.
func TestProblemFieldNames(t *testing.T) {
	t.Parallel()

	const raw = `{"code":"new_issue","coDe":"extra_code","title":"Known","titLe":"Extra","object":{"name":"alpha","naMe":"beta"}}`

	var problem *ProblemError
	require.ErrorAs(t, problemOf(422, []byte(raw)), &problem)

	obj, err := problem.Problem.Object.Get()
	require.NoError(t, err)
	require.Equal(
		t,
		[]string{"new_issue", "Known", "alpha"},
		[]string{string(problem.Problem.Code), problem.Problem.Title, obj.Name},
	)
}

func TestProblemSentence(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		p    clientv0.Problem
		want string
	}{
		{"unauthorized", clientv0.Problem{Code: clientv0.ProblemCodeUnauthorized}, "the server did not accept the API key."},
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
			"not found names the object",
			clientv0.Problem{Code: clientv0.ProblemCodeNotFound, Object: nullable.NewNullableWithValue(clientv0.ProblemObject{Kind: "node", Id: "12", Name: "mynode"})},
			"Node 12 (mynode) no longer exists.",
		},
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
			"the server refused a value:\n  body.name: is too long",
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

	require.EqualError(
		t,
		problemOf(502, []byte("<html>")),
		"the server answered 502 Bad Gateway",
	)
}
