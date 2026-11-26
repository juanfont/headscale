package apiv0

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
)

// usersAPI is v0 on a fresh server, with the header of an API key.

// forgedToken is token with one digit of its signature changed to one it
// is not. Not the last digit: its low bits may carry nothing, so a change
// there can leave the token as it was.
func forgedToken(token string) string {
	i := len(token) - 3

	c := byte('A')
	if token[i] == c {
		c = 'B'
	}

	return token[:i] + string(c) + token[i+1:]
}

func usersAPI(t *testing.T) (Backend, humatest.TestAPI, string) {
	t.Helper()

	b := newBackend(t)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	return b, newTestAPI(t, b), "Authorization: Bearer " + key
}

func decodeUser(t *testing.T, body []byte) User {
	t.Helper()

	var u User
	require.NoError(t, json.Unmarshal(body, &u), string(body))

	return u
}

func TestListUsers(t *testing.T) {
	b, api, auth := usersAPI(t)

	users := b.State.CreateUsersForTest(5, "user")
	_, _, err := b.State.CreateUser(
		types.User{
			Name:               "user-1",
			Provider:           util.RegisterMethodOIDC,
			ProviderIdentifier: sql.NullString{String: "/sub", Valid: true},
		},
	)
	require.NoError(t, err)

	page := func(t *testing.T, query string) (UserList, *Problem) {
		t.Helper()

		rec := api.Get(Prefix+"/users?"+query, auth)
		if rec.Code != http.StatusOK {
			p := decodeProblem(t, rec, Code(problemCode(rec.Body.Bytes())))

			return UserList{}, &p
		}

		require.NotContains(t, rec.Body.String(), `"nextPageToken":""`)

		var l UserList
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &l))

		return l, nil
	}

	// walk follows every token from the first page with a page size of 2.
	walk := func(t *testing.T, filters string) ([]string, int) {
		t.Helper()

		var (
			ids   []string
			pages int
			token string
		)

		for {
			q := "pageSize=2&" + filters
			if token != "" {
				q += "&pageToken=" + url.QueryEscape(token)
			}

			l, p := page(t, q)
			require.Nil(t, p)

			pages++

			for _, u := range l.Users {
				ids = append(ids, u.ID)
			}

			if l.NextPageToken == "" {
				return ids, pages
			}

			token = l.NextPageToken
		}
	}

	id := func(u *types.User) string { return strconv.FormatUint(uint64(u.ID), 10) }

	t.Run("walk every user", func(t *testing.T) {
		ids, pages := walk(t, "")
		require.Len(t, ids, 6)
		require.Equal(
			t,
			[]string{
				id(users[0]),
				id(users[1]),
				id(users[2]),
				id(users[3]),
				id(users[4]),
			},
			ids[:5],
		)
		require.Equal(t, 3, pages)
	})

	t.Run("walk a filter", func(t *testing.T) {
		ids, pages := walk(t, "name=user-1")
		require.Len(t, ids, 2, "a local and an OIDC user share the name")
		require.Equal(t, 1, pages, "a list that fits in one page has no token")
	})

	t.Run("default page size", func(t *testing.T) {
		l, _ := page(t, "")
		require.Len(t, l.Users, 6)
		require.Empty(t, l.NextPageToken)
	})

	t.Run("a filter that matches nothing is an empty list", func(t *testing.T) {
		rec := api.Get(Prefix+"/users?email=nobody@example.com", auth)
		require.Equal(t, http.StatusOK, rec.Code)
		require.JSONEq(t, `{"users": []}`, rec.Body.String())
	})

	first, _ := page(t, "pageSize=2")
	require.NotEmpty(t, first.NextPageToken)

	token := url.QueryEscape(first.NextPageToken)

	for _, tt := range []struct {
		name  string
		query string
	}{
		{"forged", "pageSize=2&pageToken=" + url.QueryEscape(forgedToken(first.NextPageToken))},
		{"other filters", "pageSize=2&name=user-1&pageToken=" + token},
		{"made up", "pageSize=2&pageToken=djEudXNlcnMuMi5hYmM"},
	} {
		t.Run("token "+tt.name, func(t *testing.T) {
			_, p := page(t, tt.query)
			require.NotNil(t, p)
			require.Equal(t, CodeInvalidPageToken, p.Code)
		})
	}

	t.Run("token of another list", func(t *testing.T) {
		pg, err := openPage[uint64](PageQuery{PageSize: 2}, "nodes", "", "")
		require.NoError(t, err)

		_, other := cutPage(pg, []uint64{1, 2, 3}, func(n uint64) uint64 { return n })

		_, p := page(t, "pageSize=2&pageToken="+url.QueryEscape(other))
		require.NotNil(t, p)
		require.Equal(t, CodeInvalidPageToken, p.Code)
	})

	t.Run("pageSize may change between pages", func(t *testing.T) {
		l, p := page(t, "pageSize=3&pageToken="+token)
		require.Nil(t, p)
		require.Len(t, l.Users, 3)
	})

	for _, size := range []string{"0", "1001", "-1", "x"} {
		t.Run("pageSize "+size, func(t *testing.T) {
			_, p := page(t, "pageSize="+size)
			require.NotNil(t, p)
			require.Equal(t, CodeInvalidField, p.Code)
			require.Equal(t, "query.pageSize", p.Errors[0].Location)
		})
	}

	t.Run("an unknown filter is refused", func(t *testing.T) {
		_, p := page(t, "usr=3")
		require.NotNil(t, p)
		require.Equal(t, CodeInvalidField, p.Code)
	})

	// A filter that falls away would return every row.
	for query, want := range map[string]string{
		"name=":                   "query.name",
		"name":                    "query.name",
		"email=":                  "query.email",
		"pageToken=":              "query.pageToken",
		"pageSize=":               "query.pageSize",
		"name=alice&name=bob":     "query.name",
		"pageSize=2&pageSize=3":   "query.pageSize",
		"email=a@b.c&email=a@b.c": "query.email",
	} {
		t.Run("query "+query, func(t *testing.T) {
			_, p := page(t, query)
			require.NotNil(t, p)
			require.Equal(t, CodeInvalidField, p.Code)
			require.Equal(t, []string{want}, locations(*p))
		})
	}

	t.Run("no credential is 401 before the query is read", func(t *testing.T) {
		decodeProblem(t, api.Get(Prefix+"/users?name=&name="), CodeUnauthorized)
	})
}

// problemCode reads the code of a problem body.
func problemCode(body []byte) string {
	var p struct {
		Code string `json:"code"`
	}

	_ = json.Unmarshal(body, &p)

	return p.Code
}

func TestGetUser(t *testing.T) {
	b, api, auth := usersAPI(t)

	alice := b.State.CreateUserForTest("alice")

	// Two nodes alice owns, out of ID order in the store, and a tagged node
	// she made, which her tags own.
	nodes := make([]*types.Node, 0, 3)
	for _, name := range []string{"laptop", "phone", "builder"} {
		nodes = append(nodes, b.State.CreateNodeForTest(alice, name))
	}

	nodes[2].Tags = []string{"tag:ci"}

	stored := map[int]types.NodeView{}
	for _, i := range []int{1, 0, 2} {
		stored[i] = b.State.PutNodeInStoreForTest(*nodes[i])
	}

	rec := api.Get(Prefix+"/users/"+strconv.FormatUint(uint64(alice.ID), 10), auth)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	got := decodeUser(t, rec.Body.Bytes())
	require.Equal(t, User{
		ID:        strconv.FormatUint(uint64(alice.ID), 10),
		Name:      "alice",
		LoginName: "alice",
		Provider:  "local",
		NodeCount: 2,
		Nodes: []NodeReference{
			{
				ID:   strconv.FormatUint(uint64(nodes[0].ID), 10),
				Name: stored[0].GivenName(),
			},
			{
				ID:   strconv.FormatUint(uint64(nodes[1].ID), 10),
				Name: stored[1].GivenName(),
			},
		},
		Created: micro(alice.CreatedAt),
	}, got)

	for _, path := range []string{"999", "abc", "-1", "1.0", "0", "007", "+7", "9223372036854775808", "18446744073709551616"} {
		t.Run("not found "+path, func(t *testing.T) {
			p := decodeProblem(t, api.Get(Prefix+"/users/"+path, auth), CodeNotFound)
			if path == "999" {
				require.Equal(t, &ProblemObject{Kind: "user", ID: "999"}, p.Object)
			} else {
				require.Nil(t, p.Object, "the request is not copied back")
			}
		})
	}

	t.Run("no credential", func(t *testing.T) {
		decodeProblem(t, api.Get(Prefix+"/users/abc?x=1"), CodeUnauthorized)
	})
}

// TestUsersAreOneMoment: a user read and the nodes it owns are of one moment;
// a rename of the user and a node it then gets that land during the read wait
// for it.
func TestUsersAreOneMoment(t *testing.T) {
	for _, mode := range []string{"list", "get"} {
		t.Run(mode, func(t *testing.T) {
			b, api, auth := usersAPI(t)
			alice := b.State.CreateUserForTest("alice")

			onQuery(t, b, "users", true, "", func() {
				whileBlocked(t, func() {
					_, _, err := b.State.RenameUser(types.UserID(alice.ID), "alicia")
					if err != nil {
						t.Error(err)
					}

					b.State.PutNodeInStoreForTest(
						*b.State.CreateRegisteredNodeForTest(alice, "late"),
					)
				})
			})

			var u User

			if mode == "get" {
				rec := api.Get(
					Prefix+"/users/"+strconv.FormatUint(uint64(alice.ID), 10),
					auth,
				)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				u = decodeUser(t, rec.Body.Bytes())
			} else {
				rec := api.Get(Prefix+"/users", auth)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

				var page UserList
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
				require.Len(t, page.Users, 1)
				u = page.Users[0]
			}

			require.Equal(t, "alice", u.Name)
			require.Empty(t, u.Nodes, "alice never owned a node; alicia did")
		})
	}
}

func TestCreateUser(t *testing.T) {
	b, api, auth := usersAPI(t)

	t.Run("created", func(t *testing.T) {
		rec := api.Post(Prefix+"/users", auth, map[string]any{
			"name":          "dave",
			"email":         "dave@example.com",
			"displayName":   "Dave",
			"profilePicUrl": "https://example.com/dave.png",
		})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

		got := decodeUser(t, rec.Body.Bytes())
		require.Equal(t, Prefix+"/users/"+got.ID, rec.Header().Get("Location"))
		require.Equal(t, "dave", got.Name)
		require.Equal(t, "dave@example.com", got.LoginName)
		require.Equal(t, "Dave", got.DisplayName)
		require.Equal(t, "https://example.com/dave.png", got.ProfilePicURL)
		require.Equal(t, "local", got.Provider)
		require.Equal(t, []NodeReference{}, got.Nodes)
		require.WithinDuration(t, time.Now(), got.Created, time.Minute)
	})

	t.Run("name taken names the holder", func(t *testing.T) {
		p := decodeProblem(
			t,
			api.Post(Prefix+"/users", auth, map[string]any{"name": "dave"}),
			CodeNameTaken,
		)
		require.Equal(t, "user", p.Object.Kind)
		require.Equal(t, "dave@example.com", p.Object.Name)
		require.Equal(t, map[string]any{"name": "dave"}, p.Details)
	})

	erin, _, err := b.State.CreateUser(types.User{
		Name: "erin", Email: "erin@corp.com", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp/erin", Valid: true},
	})
	require.NoError(t, err)

	erinObject := &ProblemObject{
		Kind: "user",
		ID:   strconv.FormatUint(uint64(erin.ID), 10),
		Name: "erin@corp.com",
	}

	// A policy names a user by these texts; see TestLocalUserCannotMovePolicyRules in state.
	for _, tt := range []struct {
		name    string
		body    map[string]any
		want    Code
		details map[string]any
	}{
		{"the name of a user from OIDC", map[string]any{"name": "Erin"}, CodeNameTaken, map[string]any{"name": "Erin"}},
		{"a name that is another user's email", map[string]any{"name": "erin@corp.com"}, CodeNameTaken, map[string]any{"name": "erin@corp.com"}},
		{"the email of a user from OIDC", map[string]any{"name": "mallory", "email": "ERIN@corp.com"}, CodeEmailTaken, map[string]any{"email": "ERIN@corp.com"}},
		{"name wins when both clash", map[string]any{"name": "erin", "email": "erin@corp.com"}, CodeNameTaken, map[string]any{"name": "erin"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeProblem(t, api.Post(Prefix+"/users", auth, tt.body), tt.want)
			require.Equal(t, erinObject, p.Object)
			require.Equal(t, tt.details, p.Details)
		})
	}

	t.Run("every bad field at once", func(t *testing.T) {
		p := decodeProblem(t, api.Post(Prefix+"/users", auth, map[string]any{
			"name":          "1x",
			"email":         "Dave <dave@example.com>",
			"profilePicUrl": "javascript:alert(1)",
		}), CodeInvalidField)
		require.Equal(
			t,
			[]string{"body.email", "body.name", "body.profilePicUrl"},
			locations(p),
		)
		require.NotContains(
			t,
			p.Errors[0].Message,
			"Dave",
			"the request is not copied back",
		)
	})

	for _, tt := range []struct {
		name string
		body any
		want Code
	}{
		{"no name", map[string]any{"email": "x@example.com"}, CodeInvalidField},
		{"unknown field", map[string]any{"name": "frank", "id": "3"}, CodeInvalidField},
		{"null name", map[string]any{"name": nil}, CodeInvalidField},
		{"null email", map[string]any{"name": "frank", "email": nil}, CodeInvalidField},
		{"too large", map[string]any{"name": "frank", "displayName": strings.Repeat("x", maxUserBody)}, CodeTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			decodeProblem(t, api.Post(Prefix+"/users", auth, tt.body), tt.want)
		})
	}

	t.Run("null is left out in a create", func(t *testing.T) {
		p := decodeProblem(
			t,
			api.Post(
				Prefix+"/users",
				auth,
				map[string]any{"name": "frank", "email": nil},
			),
			CodeInvalidField,
		)
		require.Equal(
			t,
			[]FieldError{
				{
					Location: "body.email",
					Message:  "cannot be null; leave the field out",
				},
			},
			p.Errors,
		)
	})

	post := func(body string, headers ...any) *httptest.ResponseRecorder {
		return api.Post(
			Prefix+"/users",
			append([]any{auth, strings.NewReader(body)}, headers...)...)
	}

	const asJSON = "Content-Type: application/json"

	for _, tt := range []struct {
		name string
		body string
		want Code
		at   string
	}{
		{"bad JSON", `{"name": `, CodeInvalidRequest, ""},
		{"a key given twice", `{"name": "frank", "name": "grace"}`, CodeInvalidRequest, ""},
		{"not UTF-8", "{\"name\": \"fr\xffnk\"}", CodeInvalidRequest, ""},
		// The validator matches NAME to name and checks only "ok"; the typed
		// decode must not take the long value.
		{"a key in another case beside the key", `{"name": "frank", "NAME": "` + strings.Repeat("x", 300) + `"}`, CodeInvalidField, "body.NAME"},
		{"a key in another case", `{"NAME": "frank"}`, CodeInvalidField, ""},
		{"a name too long", `{"name": "f` + strings.Repeat("x", 254) + `"}`, CodeInvalidField, "body.name"},
		{"an email too long", `{"name": "frank", "email": "` + strings.Repeat("x", 245) + `@example.com"}`, CodeInvalidField, "body.email"},
		{"a display name too long", `{"name": "frank", "displayName": "` + strings.Repeat("ü", 129) + `"}`, CodeInvalidField, "body.displayName"},
		{"a picture URL too long", `{"name": "frank", "profilePicUrl": "https://example.com/` + strings.Repeat("x", 2048) + `"}`, CodeInvalidField, "body.profilePicUrl"},
		{"a terminal escape in the display name", `{"name": "frank", "displayName": "\u001b]0;pwn\u0007"}`, CodeInvalidField, "body.displayName"},
		{"NUL in the display name", `{"name": "frank", "displayName": "a\u0000b"}`, CodeInvalidField, "body.displayName"},
		{"a right-to-left override in the display name", `{"name": "frank", "displayName": "evil\u202egnp.exe"}`, CodeInvalidField, "body.displayName"},
		{"user info in the picture URL", `{"name": "frank", "profilePicUrl": "https://u:p@example.com/a.png"}`, CodeInvalidField, "body.profilePicUrl"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeProblem(t, post(tt.body, asJSON), tt.want)
			if tt.at != "" {
				require.Equal(t, []string{tt.at}, locations(p), p.Errors)
			}
		})
	}

	for _, ct := range []string{"", "text/plain", "application/foo+json", "application/merge-patch+json", "application/json; charset=latin1", "application/json; x=y"} {
		t.Run("media type "+ct, func(t *testing.T) {
			decodeProblem(
				t,
				post(`{"name": "frank"}`, "Content-Type: "+ct),
				CodeUnsupportedMediaType,
			)
		})
	}

	t.Run("a charset is allowed", func(t *testing.T) {
		rec := post(
			`{"name": "grace"}`,
			"Content-Type: application/json; charset=UTF-8",
		)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	})

	t.Run("a token may create", func(t *testing.T) {
		rec := post(
			`{"name": "heidi", "email": "heidi@example.com"}`,
			asJSON,
			"Authorization: Bearer "+usersToken(t, b),
		)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	})

	t.Run("a read scope cannot create", func(t *testing.T) {
		_, client, err := b.State.CreateOAuthClient(
			[]string{"users:read"},
			nil,
			"",
			nil,
		)
		require.NoError(t, err)

		token, _, err := b.State.MintAccessToken(
			client.ClientID,
			[]string{"users:read"},
			nil,
			new(time.Now().Add(time.Hour)),
		)
		require.NoError(t, err)

		p := decodeProblem(
			t,
			api.Post(
				Prefix+"/users",
				"Authorization: Bearer "+token,
				map[string]any{"name": "frank"},
			),
			CodeForbidden,
		)
		require.Equal(t, []any{"users"}, p.Details["scopes"])

		rec := api.Get(Prefix+"/users", "Authorization: Bearer "+token)
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

// usersToken is an OAuth access token with the users scope.
func usersToken(t *testing.T, b Backend) string {
	t.Helper()

	_, client, err := b.State.CreateOAuthClient([]string{"users"}, nil, "", nil)
	require.NoError(t, err)

	token, _, err := b.State.MintAccessToken(
		client.ClientID,
		[]string{"users"},
		nil,
		new(time.Now().Add(time.Hour)),
	)
	require.NoError(t, err)

	return token
}

func locations(p Problem) []string {
	out := make([]string, len(p.Errors))
	for i, e := range p.Errors {
		out[i] = e.Location
	}

	return out
}

// TestUserValidationReportsEachField: every field that is not valid is
// named, on create and on update.
func TestUserValidationReportsEachField(t *testing.T) {
	b, api, auth := usersAPI(t)
	user := b.State.CreateUserForTest("alice")
	path := Prefix + "/users/" + strconv.FormatUint(uint64(user.ID), 10)

	body := map[string]any{"name": "", "displayName": strings.Repeat("é", 129)}
	for _, res := range []*httptest.ResponseRecorder{
		api.Post(Prefix+"/users", auth, body),
		api.Patch(path, auth, body),
	} {
		p := decodeProblem(t, res, CodeInvalidField)
		require.ElementsMatch(
			t,
			[]string{"body.name", "body.displayName"},
			locations(p),
		)
	}
}

// TestUserFieldErrorsSurviveOtherTypes: a member of the wrong type does not
// hide the field errors of its siblings.
func TestUserFieldErrorsSurviveOtherTypes(t *testing.T) {
	_, api, auth := usersAPI(t)
	for _, tc := range []struct {
		name, body string
		locations  []string
	}{
		{"null document", "null", []string{"body"}},
		{"invalid sibling after type", `{"displayName":4,"name":"valid","email":"bad"}`, []string{"body.displayName", "body.email"}},
		{"invalid sibling before type", `{"name":"valid","email":"bad","displayName":4}`, []string{"body.displayName", "body.email"}},
		{"valid sibling", `{"displayName":4,"name":"valid"}`, []string{"body.displayName"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, r := range []*httptest.ResponseRecorder{
				api.Post(Prefix+"/users", auth, "Content-Type: application/json", strings.NewReader(tc.body)),
				api.Patch(Prefix+"/users/1", auth, "Content-Type: application/merge-patch+json", strings.NewReader(tc.body)),
			} {
				p := decodeProblem(t, r, CodeInvalidField)
				require.ElementsMatch(t, tc.locations, locations(p), tc.body)
			}
		})
	}
}

// TestNullUsernameRepair: a null name says what to send instead.
func TestNullUsernameRepair(t *testing.T) {
	_, api, auth := usersAPI(t)
	res := api.Patch(
		Prefix+"/users/1",
		auth,
		"Content-Type: application/merge-patch+json",
		strings.NewReader(`{"name":null}`),
	)
	p := decodeProblem(t, res, CodeInvalidField)
	require.Equal(
		t,
		[]FieldError{
			{Location: "body.name", Message: "cannot be null; send a valid username"},
		},
		p.Errors,
	)
}

// TestUserFieldErrorCount: an error the schema and a resolver both give
// counts once, also against the cap.
func TestUserFieldErrorCount(t *testing.T) {
	_, api, auth := usersAPI(t)

	body := map[string]any{"name": "charlie"}
	for i := range maxFieldErrors/2 + 1 {
		body["other"+strconv.Itoa(i)] = i
	}

	p := decodeProblem(t, api.Post(Prefix+"/users", auth, body), CodeInvalidField)
	require.Len(t, p.Errors, len(body)-1)
}

func TestUpdateUser(t *testing.T) {
	b, api, auth := usersAPI(t)

	alice, _, err := b.State.CreateUser(
		types.User{
			Name:          "alice",
			DisplayName:   "Alice",
			Email:         "alice@example.com",
			ProfilePicURL: "https://example.com/a.png",
		},
	)
	require.NoError(t, err)

	b.State.CreateUserForTest("bob")

	oidc, _, err := b.State.CreateUser(
		types.User{
			Name:               "carol",
			Provider:           util.RegisterMethodOIDC,
			ProviderIdentifier: sql.NullString{String: "/carol", Valid: true},
		},
	)
	require.NoError(t, err)

	path := Prefix + "/users/" + strconv.FormatUint(uint64(alice.ID), 10)

	patch := func(t *testing.T, body string, args ...any) *httptest.ResponseRecorder {
		t.Helper()

		return api.Patch(
			path,
			append(
				[]any{auth, "Content-Type: application/json", strings.NewReader(body)},
				args...)...)
	}

	t.Run("a field left out does not change", func(t *testing.T) {
		rec := patch(t, `{"displayName": "Alice A."}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		got := decodeUser(t, rec.Body.Bytes())
		require.Equal(t, "Alice A.", got.DisplayName)
		require.Equal(t, "alice", got.Name)
		require.Equal(t, "alice@example.com", got.Email)
	})

	t.Run("an empty string clears, as merge patch", func(t *testing.T) {
		rec := patch(
			t,
			`{"email": "", "profilePicUrl": ""}`,
			"Content-Type: application/merge-patch+json",
		)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		got := decodeUser(t, rec.Body.Bytes())
		require.Empty(t, got.Email)
		require.Empty(t, got.ProfilePicURL)
		require.Equal(t, "alice", got.LoginName, "loginName falls back to the name")
	})

	t.Run("rename", func(t *testing.T) {
		rec := patch(t, `{"name": "alicia"}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, "alicia", decodeUser(t, rec.Body.Bytes()).Name)
	})

	t.Run("name taken names the holder, and nothing changes", func(t *testing.T) {
		p := decodeProblem(
			t,
			patch(t, `{"name": "bob", "displayName": "Bob?"}`),
			CodeNameTaken,
		)
		require.Equal(t, "bob", p.Object.Name)
		require.Equal(t, map[string]any{"name": "bob"}, p.Details)

		u, err := b.State.GetUserByID(types.UserID(alice.ID))
		require.NoError(t, err)
		require.Equal(t, "Alice A.", u.DisplayName)
	})

	for _, tt := range []struct {
		name string
		body string
		want Code
		at   string
	}{
		{"empty", `{}`, CodeEmptyPatch, ""},
		{"empty name", `{"name": ""}`, CodeInvalidField, "body.name"},
		{"null name", `{"name": null}`, CodeInvalidField, "body.name"},
		{"null displayName", `{"displayName": null}`, CodeInvalidField, "body.displayName"},
		{"a key in another case", `{"DISPLAYNAME": "x"}`, CodeInvalidField, "body.DISPLAYNAME"},
		{"a key given twice", `{"displayName": "x", "displayName": "y"}`, CodeInvalidRequest, ""},
		{"a control character", `{"displayName": "a\tb"}`, CodeInvalidField, "body.displayName"},
		{"bad email", `{"email": "alice"}`, CodeInvalidField, "body.email"},
		{"relative picture", `{"profilePicUrl": "/a.png"}`, CodeInvalidField, "body.profilePicUrl"},
		{"a field that cannot change", `{"id": "9"}`, CodeInvalidField, "body.id"},
		{"read-only loginName", `{"loginName": "x"}`, CodeInvalidField, "body.loginName"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := decodeProblem(t, patch(t, tt.body), tt.want)
			if tt.at != "" {
				require.Equal(t, tt.at, p.Errors[0].Location, p.Errors)
			}
		})
	}

	t.Run("a user from OIDC", func(t *testing.T) {
		p := decodeProblem(
			t,
			api.Patch(
				Prefix+"/users/"+strconv.FormatUint(uint64(oidc.ID), 10),
				auth,
				"Content-Type: application/json",
				strings.NewReader(`{"displayName": "C"}`),
			),
			CodeUserManagedByOIDC,
		)
		require.Equal(
			t,
			&ProblemObject{
				Kind: "user",
				ID:   strconv.FormatUint(uint64(oidc.ID), 10),
				Name: "carol",
			},
			p.Object,
		)
	})

	t.Run("null says how to clear", func(t *testing.T) {
		p := decodeProblem(t, patch(t, `{"email": null}`), CodeInvalidField)
		require.Equal(
			t,
			[]FieldError{
				{
					Location: "body.email",
					Message:  "cannot be null; send \"\" to clear it",
				},
			},
			p.Errors,
		)
	})

	t.Run("email taken names the holder", func(t *testing.T) {
		b.State.CreateUserForTest("dan@example.com")

		p := decodeProblem(t, patch(t, `{"email": "DAN@example.com"}`), CodeEmailTaken)
		require.Equal(t, "dan@example.com", p.Object.Name)
		require.Equal(t, map[string]any{"email": "DAN@example.com"}, p.Details)
	})

	t.Run("not found", func(t *testing.T) {
		decodeProblem(
			t,
			api.Patch(
				Prefix+"/users/999",
				auth,
				"Content-Type: application/json",
				strings.NewReader(`{"displayName": "x"}`),
			),
			CodeNotFound,
		)
	})

	// What the request alone shows comes before the resource of the path.
	for _, id := range []string{"999", "abc", "007", "9223372036854775808"} {
		t.Run("a bad field before not found "+id, func(t *testing.T) {
			p := decodeProblem(
				t,
				api.Patch(
					Prefix+"/users/"+id,
					auth,
					"Content-Type: application/json",
					strings.NewReader(`{"email": "x"}`),
				),
				CodeInvalidField,
			)
			require.Equal(t, []string{"body.email"}, locations(p))
		})
	}

	t.Run("an ID out of the form names nothing", func(t *testing.T) {
		for _, id := range []string{"0" + strconv.FormatUint(uint64(alice.ID), 10), "9223372036854775808"} {
			p := decodeProblem(
				t,
				api.Patch(
					Prefix+"/users/"+id,
					auth,
					"Content-Type: application/json",
					strings.NewReader(`{"displayName": "x"}`),
				),
				CodeNotFound,
			)
			require.Nil(t, p.Object)
		}
	})
}

// TestUpdateUserTokenRule: a token cannot change the name or the email of a
// user, which would move a policy rule to another user in two calls that
// never make a clash; an API key and the socket can.
// TestUserWriteAfterCommit: a user write that committed and whose refresh of
// the policy then failed answers what was stored and tells peers; the policy
// catches up without another write.
func TestUserWriteAfterCommit(t *testing.T) {
	b := newBackend(t)
	sent := countChanges(&b)
	fail := failPolicyUsers(b)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	api, auth := newTestAPI(t, b), "Authorization: Bearer "+key

	alice := b.State.CreateUserForTest("alice")

	// With its owner loaded, as the NodeStore holds it, so a profile changes.
	n, err := b.State.DB().
		GetNodeByID(b.State.CreateRegisteredNodeForTest(alice, "n1").ID)
	require.NoError(t, err)
	b.State.PutNodeInStoreForTest(*n)

	path := Prefix + "/users/" + strconv.FormatUint(uint64(alice.ID), 10)

	for _, write := range []struct {
		name string
		send func() *httptest.ResponseRecorder
		code int
	}{
		{"update", func() *httptest.ResponseRecorder {
			return api.Patch(path, auth, "Content-Type: application/merge-patch+json", strings.NewReader(`{"displayName":"Alice New"}`))
		}, http.StatusOK},
		{"create", func() *httptest.ResponseRecorder {
			return api.Post(Prefix+"/users", auth, "Content-Type: application/json", strings.NewReader(`{"name":"bob"}`))
		}, http.StatusCreated},
	} {
		t.Run(write.name, func(t *testing.T) {
			sent.Store(0)
			fail.Store(1)

			rec := write.send()
			require.Equal(t, write.code, rec.Code, rec.Body.String())
			require.NotZero(t, sent.Load(), "peers are told what was stored")

			require.False(
				t,
				b.State.CatchUpPolicyUsers().IsEmpty(),
				"the policy catches up",
			)
			require.True(t, b.State.CatchUpPolicyUsers().IsEmpty(), "once")
		})
	}

	u := decodeUser(t, api.Get(path, auth).Body.Bytes())
	require.Equal(t, "Alice New", u.DisplayName)
	decodeProblem(
		t,
		api.Post(
			Prefix+"/users",
			auth,
			"Content-Type: application/json",
			strings.NewReader(`{"name":"bob"}`),
		),
		CodeNameTaken,
	)
}

func TestUpdateUserTokenRule(t *testing.T) {
	b, api, auth := usersAPI(t)

	alice := b.State.CreateUserForTest("alice")
	bob := b.State.CreateUserForTest("bob")
	token := "Authorization: Bearer " + usersToken(t, b)

	path := func(u *types.User) string { return Prefix + "/users/" + strconv.FormatUint(uint64(u.ID), 10) }
	patch := func(ctx context.Context, u *types.User, body string, headers ...any) *httptest.ResponseRecorder {
		return api.PatchCtx(
			ctx,
			path(u),
			append(
				[]any{"Content-Type: application/json", strings.NewReader(body)},
				headers...)...)
	}

	for _, body := range []string{`{"name": "alice-old"}`, `{"email": "alice@example.com"}`, `{"name": "alice-old", "displayName": "A"}`} {
		t.Run("token "+body, func(t *testing.T) {
			p := decodeProblem(t, patch(t.Context(), alice, body, token), CodeForbidden)
			require.Equal(
				t,
				"token_cannot_change_user_name_or_email",
				p.Details["rule"],
			)
			require.Equal(t, []any{}, p.Details["scopes"])
		})
	}

	t.Run("token, a field wrong in itself before the rule", func(t *testing.T) {
		p := decodeProblem(
			t,
			patch(t.Context(), alice, `{"email": "x"}`, token),
			CodeInvalidField,
		)
		require.Equal(t, []string{"body.email"}, locations(p))
	})

	t.Run("token may change the display name and the picture", func(t *testing.T) {
		rec := patch(
			t.Context(),
			alice,
			`{"displayName": "Alice", "profilePicUrl": "https://example.com/a.png"}`,
			token,
		)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	// The swap the rule is for: neither call makes a clash.
	t.Run("API key", func(t *testing.T) {
		rec := patch(t.Context(), alice, `{"name": "alice-old"}`, auth)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	t.Run("socket", func(t *testing.T) {
		rec := patch(
			context.WithValue(t.Context(), localTrustKey, struct{}{}),
			bob,
			`{"name": "alice", "email": "bob@example.com"}`,
		)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})
}
