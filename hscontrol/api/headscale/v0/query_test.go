package apiv0

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStrictQuery: a query that does not decode is refused before any
// handler runs, at every query parameter of every operation, so no broken
// guard or preview writes and no broken filter or cursor reads more.
func TestStrictQuery(t *testing.T) {
	_, api, auth := usersAPI(t)

	sent := 0

	for path, item := range api.OpenAPI().Paths {
		for method, op := range operations(item) {
			target := path

			for _, p := range op.Parameters {
				if p.In == "path" {
					target = strings.ReplaceAll(target, "{"+p.Name+"}", "1")
				}
			}

			for _, param := range op.Parameters {
				if param.In != "query" {
					continue
				}

				for _, v := range []string{"true%", "%zz", "tr%ue", "1;2"} {
					for _, query := range []string{param.Name + "=" + v, param.Name + "=" + v + "&" + param.Name + "=true"} {
						p := decodeProblem(
							t,
							api.Do(method, target+"?"+query, auth),
							CodeInvalidField,
						)
						require.Equal(
							t,
							[]FieldError{
								{
									Location: "query." + param.Name,
									Message:  "is not percent-encoded: escape % as %25 and ; as %3B",
								},
							},
							p.Errors,
							method+" "+target+"?"+query,
						)

						sent++
					}
				}
			}
		}
	}

	require.NotZero(t, sent, "the document has query parameters")

	t.Run("a name that does not decode", func(t *testing.T) {
		p := decodeProblem(t, api.Get(Prefix+"/users?na%me=x", auth), CodeInvalidField)
		require.Equal(
			t,
			[]FieldError{
				{
					Location: "query",
					Message:  "has a parameter name that is not percent-encoded: escape % as %25 and ; as %3B",
				},
			},
			p.Errors,
		)
	})

	t.Run("an escaped % and ; are values", func(t *testing.T) {
		rec := api.Get(Prefix+"/users?name=a%25b%3Bc", auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("no credential is 401 first", func(t *testing.T) {
		decodeProblem(t, api.Get(Prefix+"/users?name=x%"), CodeUnauthorized)
	})

	t.Run("a query that parses reads as url.ParseQuery", func(t *testing.T) {
		for _, raw := range []string{"", "a=1", "a=1&b=2&a=3", "a", "a=", "=1", "&&a=1&", "a+b=c+d", "a=%2B%26%3D", "a=b=c"} {
			want, err := url.ParseQuery(raw)
			require.NoError(t, err, raw)

			got, errs := parseQuery(raw)
			require.Empty(t, errs, raw)
			require.Equal(t, want, got, raw)
		}
	})
}
