package hscontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/danielgtaylor/huma/v2"
	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIV1AuthMiddleware proves the v1 API, mounted on the real router, is
// guarded by the Huma security middleware: missing or bad Bearer tokens are
// rejected with 401 before reaching a handler; a valid key passes to 200. The
// per-endpoint harness bypasses auth via WithLocalTrust, so this is the one
// place the middleware itself is exercised.
func TestAPIV1AuthMiddleware(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	expiry := time.Now().Add(time.Hour)
	valid, _, err := app.state.CreateAPIKey(&expiry)
	require.NoError(t, err)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{name: "missing bearer", authHeader: "", wantStatus: http.StatusUnauthorized},
		{name: "no bearer prefix", authHeader: "tskey-invalid", wantStatus: http.StatusUnauthorized},
		{name: "invalid bearer token", authHeader: "Bearer tskey-invalid", wantStatus: http.StatusUnauthorized},
		{name: "valid api key", authHeader: "Bearer " + valid, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, "/api/v1/node", nil,
			)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equalf(t, tt.wantStatus, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// TestAPIV1RevokedAPIKey: an API key revoked through /api/headscale/v0 is
// refused by /api/v1 from its next request on, and its list no longer shows
// it, since its answer cannot say that a key is revoked.
func TestAPIV1RevokedAPIKey(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	other, _, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	secret, key, err := app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	get := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/apikey", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec
	}

	require.Equal(t, http.StatusOK, get(secret).Code)
	require.NoError(t, app.state.RevokeAPIKey(key.ID))
	require.Equal(t, http.StatusUnauthorized, get(secret).Code)

	rec := get(other)
	require.Equal(t, http.StatusOK, rec.Code)

	var list struct {
		APIKeys []struct {
			ID string `json:"id"`
		} `json:"apiKeys"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Len(t, list.APIKeys, 1)
	assert.NotEqual(t, strconv.FormatUint(key.ID, 10), list.APIKeys[0].ID)
}

// TestAPIV1DocsArePublic proves the OpenAPI document and docs UI live under
// /api/v1 and are reachable without an API key, while the operations beside them
// stay key-gated. The docs page points at the versioned spec so a future
// /api/v2 can carry its own.
func TestAPIV1DocsArePublic(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	tests := []struct {
		path     string
		contains string
	}{
		{path: "/api/v1/openapi.yaml", contains: "openapi:"},
		{path: "/api/v1/docs", contains: "/api/v1/openapi.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			// No Authorization header: these must be public.
			req := httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, tt.path, nil,
			)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equalf(t, http.StatusOK, rec.Code, "%s should be public; body: %s", tt.path, rec.Body.String())
			assert.Containsf(t, rec.Body.String(), tt.contains, "%s body", tt.path)
		})
	}
}

// TestAPIV1Unauthorized401 pins the 401 body: plain "Unauthorized", as 0.29's
// httpAuthenticationMiddleware wrote it before the request reached the
// gateway. headscale-admin matches the text; the integration auth-bypass tests
// require it small and free of data.
func TestAPIV1Unauthorized401(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/api/v1/node", nil,
	)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "Unauthorized", rec.Body.String())
}

// TestAPIV1QueryAsGateway: 0.29's grpc-gateway refused a query parameter given
// twice ("too many values", runtime/query.go:159-161 at v2.29.0) and an empty
// value it could not parse as the field's type (:166-170). Huma would read the
// first value, or none, and a write would act on it.
func TestAPIV1QueryAsGateway(t *testing.T) {
	h := newAPIV1Harness(t)
	user := h.app.state.CreateUserForTest("alice")

	_, apiKey, err := h.app.state.CreateAPIKey(nil)
	require.NoError(t, err)

	pak1, err := h.app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)
	pak2, err := h.app.state.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
	require.NoError(t, err)

	id1, id2 := strconv.FormatUint(pak1.ID, 10), strconv.FormatUint(pak2.ID, 10)
	apiKeyID := strconv.FormatUint(apiKey.ID, 10)

	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{"pre-auth key id twice", http.MethodDelete, "/api/v1/preauthkey?id=" + id1 + "&id=" + id2, http.StatusBadRequest},
		{"pre-auth key id empty", http.MethodDelete, "/api/v1/preauthkey?id=", http.StatusBadRequest},
		{"api key id twice", http.MethodDelete, "/api/v1/apikey/" + apiKey.Prefix + "?id=" + apiKeyID + "&id=" + apiKeyID, http.StatusBadRequest},
		{"api key id empty", http.MethodDelete, "/api/v1/apikey/" + apiKey.Prefix + "?id=", http.StatusBadRequest},
		{"backfill confirmed twice", http.MethodPost, "/api/v1/node/backfillips?confirmed=true&confirmed=false", http.StatusBadRequest},
		{"backfill confirmed empty", http.MethodPost, "/api/v1/node/backfillips?confirmed=", http.StatusBadRequest},
		{"register user twice", http.MethodPost, "/api/v1/node/register?user=alice&user=bob&key=x", http.StatusBadRequest},
		{"list nodes user twice", http.MethodGet, "/api/v1/node?user=alice&user=bob", http.StatusBadRequest},
		{"pre-auth key id after semicolon", http.MethodDelete, "/api/v1/preauthkey?x;id=" + id1, http.StatusBadRequest},
		// A dotted key into a scalar named no field (query.go:144-146); a
		// bracketed one gave it a second value (query.go:50-53).
		{"pre-auth key id dotted", http.MethodDelete, "/api/v1/preauthkey?id.x=" + id1, http.StatusBadRequest},
		{"pre-auth key id bracketed", http.MethodDelete, "/api/v1/preauthkey?id[x]=" + id1, http.StatusBadRequest},
		{"list users name dotted", http.MethodGet, "/api/v1/user?name.child=value", http.StatusBadRequest},
		{"list users name bracketed", http.MethodGet, "/api/v1/user?name[alice]=", http.StatusBadRequest},
		// Without its closing bracket the key is one unknown name, ignored.
		{"list users name unclosed bracket", http.MethodGet, "/api/v1/user?name[alice=1", http.StatusOK},
		// GetNode had no query parsed at all (no PopulateQueryParameters in
		// its generated handler at v0.29.7): every key is ignored.
		{"get node, path field dotted", http.MethodGet, "/api/v1/node/99999?nodeId.x=1", http.StatusNotFound},
		{"get node, unclosed bracket", http.MethodGet, "/api/v1/node/99999?nodeId[x=1", http.StatusNotFound},
		{"get node, semicolon", http.MethodGet, "/api/v1/node/99999?a;b", http.StatusNotFound},
		{"get node, path field dotted, other name", http.MethodGet, "/api/v1/node/99999?nodeId.child=1", http.StatusNotFound},
		// Health parsed no query either; ListNodes did, so a bad escape is a
		// 400 there and nothing on health.
		{"health, bad escape", http.MethodGet, "/api/v1/health?unrelated=%ZZ", http.StatusOK},
		{"list nodes, bad escape", http.MethodGet, "/api/v1/node?unrelated=%ZZ", http.StatusBadRequest},
		// A string parses from "", so the gateway took it as given.
		{"list users name empty", http.MethodGet, "/api/v1/user?name=", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := h.callHuma(tt.method, tt.path, nil)
			assert.Equal(t, tt.wantStatus, res.status, "body: %s", res.body)
		})
	}

	// A bare key is an empty value, as the gateway read it, not "true"; a
	// user named true tells the two apart.
	h.app.state.CreateUserForTest("true")

	for query, want := range map[string]int{
		"name":         2,
		"name=":        2,
		"name=alice":   1,
		"name=true":    1,
		"unrelated=1":  2,
		"name=&other=": 2,
	} {
		res := h.callHuma(http.MethodGet, "/api/v1/user?"+query, nil)
		require.Equal(t, http.StatusOK, res.status, "%s: %s", query, res.body)

		var got struct {
			Users []map[string]any `json:"users"`
		}
		require.NoError(t, json.Unmarshal(res.body, &got))
		assert.Len(t, got.Users, want, "?%s", query)
	}

	keys, err := h.app.state.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 2, "no pre-auth key may be deleted")

	apiKeys, err := h.app.state.ListAPIKeys()
	require.NoError(t, err)
	assert.Len(t, apiKeys, 1, "no API key may be deleted")
}

// TestAPIV1RequestForms pins every v1 operation that takes a body or a query
// against how 0.29's grpc-gateway decoded a request (v2.29.0, the generated
// headscale.pb.gw.go at v0.29.7): a missing body read as an empty message, a
// body decoded as JSON whatever its Content-Type, a form POST to a GET path
// served as the GET (mux.go, isPathLengthFallback), a repeated or unparsable
// query value refused. Each row is either the 0.29 answer or a refusal named
// here; IDs name nothing, so a handler that ran would answer 404 and a 400 or
// 415 with the framework's words was refused before any write.
func TestAPIV1RequestForms(t *testing.T) {
	h := newAPIV1Harness(t)
	_, api := apiv1.Handler(apiv1.Backend{})

	// The gateway read no body as an empty request; these take that as 0.29
	// did. Every other body is required, a refusal kept on purpose: an empty
	// SetApprovedRoutes cleared the node's routes (SetTags refused no tags).
	optionalBody := map[string]int{
		"checkPolicy": http.StatusOK,       // an empty policy passes
		"expireNode":  http.StatusNotFound, // the bare call, on no node
	}

	param := regexp.MustCompile(`\{[^}]+\}`)

	type form struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantStatus  int
		wantText    string
	}

	var forms []form

	for path, item := range api.OpenAPI().Paths {
		concrete := param.ReplaceAllString(path, "99999")

		for method, op := range map[string]*huma.Operation{
			http.MethodGet: item.Get, http.MethodPost: item.Post,
			http.MethodPut: item.Put, http.MethodDelete: item.Delete,
		} {
			if op == nil {
				continue
			}

			if op.RequestBody != nil {
				if want, ok := optionalBody[op.OperationID]; ok {
					forms = append(forms, form{op.OperationID + " no body", method, concrete, "application/json", "", want, ""})
				} else {
					forms = append(forms, form{op.OperationID + " no body", method, concrete, "application/json", "", http.StatusBadRequest, "request body is required"})
				}

				// Refused on purpose: curl -d sends this type.
				forms = append(forms, form{op.OperationID + " form type", method, concrete, "application/x-www-form-urlencoded", "{}", http.StatusUnsupportedMediaType, "unknown content type"})
			}

			if method == http.MethodGet && item.Post == nil {
				// Refused on purpose: 0.29 served it as the GET, a read.
				forms = append(forms, form{op.OperationID + " form POST", http.MethodPost, concrete, "application/x-www-form-urlencoded", "", http.StatusNotImplemented, "Method Not Allowed"})
			}

			for _, p := range op.Parameters {
				// The gateway parsed a query only where the request had query
				// fields.
				parsesQuery := slices.ContainsFunc(op.Parameters, func(q *huma.Param) bool { return q.In == "query" })

				if parsesQuery && p.In == "path" && snakeCase(p.Name) != p.Name {
					// Filtered out as the path's by either name; only the
					// JSON name with a dotted key reached the parser.
					forms = append(forms,
						form{op.OperationID + " " + p.Name + " path, dotted", method, concrete + "?" + p.Name + ".x=1", "", "", http.StatusBadRequest, "is not a message"},
						form{op.OperationID + " " + p.Name + " path, proto name dotted", method, concrete + "?" + snakeCase(p.Name) + ".x=1", "", "", 0, ""},
					)
				}

				if p.In != "query" {
					continue
				}

				if p.Schema.Format == "date-time" {
					// A Timestamp is a message: its fields are keys.
					forms = append(forms, form{op.OperationID + " " + p.Name + " dotted", method, concrete + "?" + p.Name + ".seconds=1", "", "", 0, ""})
				} else {
					forms = append(forms, form{op.OperationID + " " + p.Name + " dotted", method, concrete + "?" + p.Name + ".x=1", "", "", http.StatusBadRequest, "is not a message"})
				}

				forms = append(forms, form{op.OperationID + " " + p.Name + " bracketed", method, concrete + "?" + p.Name + "[x]=1", "", "", http.StatusBadRequest, ""})

				forms = append(forms, form{op.OperationID + " " + p.Name + " twice", method, concrete + "?" + p.Name + "=1&" + p.Name + "=2", "", "", http.StatusBadRequest, "too many values"})

				if p.Schema.Type != huma.TypeString || p.Schema.Format != "" {
					forms = append(forms, form{op.OperationID + " " + p.Name + " empty", method, concrete + "?" + p.Name + "=", "", "", http.StatusBadRequest, "parsing field"})
				}
			}
		}
	}

	require.NotEmpty(t, forms)

	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), f.method, f.path, strings.NewReader(f.body))
			if f.contentType != "" {
				req.Header.Set("Content-Type", f.contentType)
			}

			rec := httptest.NewRecorder()
			h.huma.ServeHTTP(rec, req)

			// 0: the key is read as 0.29 read it, ignored or as the
			// handler's own: the answer is the one without the query.
			if f.wantStatus == 0 {
				base, _, _ := strings.Cut(f.path, "?")
				want := httptest.NewRecorder()
				h.huma.ServeHTTP(want, httptest.NewRequestWithContext(context.Background(), f.method, base, strings.NewReader(f.body)))

				assert.Equal(t, want.Code, rec.Code, "body: %s", rec.Body.String())
				assert.Equal(t, want.Body.String(), rec.Body.String())

				return
			}

			assert.Equal(t, f.wantStatus, rec.Code, "body: %s", rec.Body.String())
			assert.Contains(t, rec.Body.String(), f.wantText)
		})
	}
}

// snakeCase is the proto name protoc derived a JSON name from: nodeId from
// node_id.
func snakeCase(s string) string {
	var b strings.Builder

	for _, r := range s {
		if unicode.IsUpper(r) {
			b.WriteByte('_')

			r = unicode.ToLower(r)
		}

		b.WriteRune(r)
	}

	return b.String()
}

// TestAPIV1BodyMembers pins how a v1 body's members are read against 0.29's
// gateway, protojson with DiscardUnknown: a member by its JSON or its proto
// name, a member it does not know dropped, the same field twice refused. For
// every operation with a body, against a fresh server each: an undeclared
// member answers as without it, a member by its proto name as by its JSON
// name, and both names together are refused, so no member the client sent
// is read as not given.
func TestAPIV1BodyMembers(t *testing.T) {
	_, api := apiv1.Handler(apiv1.Backend{})
	param := regexp.MustCompile(`\{[^}]+\}`)

	// A value of each member's type the server accepts.
	sample := func(s *huma.Schema) string {
		switch {
		case s.Type == huma.TypeBoolean:
			return `true`
		case s.Type == huma.TypeArray:
			return `["tag:x"]`
		case s.Format == "date-time":
			return `"2099-01-01T00:00:00Z"`
		case s.Format == "uint64":
			return `"1"`
		default:
			return `"x"`
		}
	}

	// A created key's secret and the times differ on every server.
	secret := regexp.MustCompile(`hskey-(auth|api)-[0-9a-f]+-[0-9a-f]+`)
	stamp := regexp.MustCompile(`"\d{4}-\d\d-\d\dT[^"]*"`)

	call := func(method, path, body string) httpResult {
		t.Helper()

		h := newFastAPIV1Harness(t)
		h.app.state.CreateUserForTest("alice")

		res := h.callHuma(method, path, []byte(body))
		res.body = stamp.ReplaceAll(secret.ReplaceAll(res.body, []byte("<secret>")), []byte(`"<time>"`))

		return res
	}

	for path, item := range api.OpenAPI().Paths {
		concrete := param.ReplaceAllString(path, "1")

		for method, op := range map[string]*huma.Operation{
			http.MethodPost: item.Post, http.MethodPut: item.Put,
		} {
			if op == nil || op.RequestBody == nil {
				continue
			}

			schema := api.OpenAPI().Components.Schemas.SchemaFromRef(op.RequestBody.Content["application/json"].Schema.Ref)
			require.NotNil(t, schema, op.OperationID)

			t.Run(op.OperationID+" undeclared member", func(t *testing.T) {
				want := call(method, concrete, `{}`)
				got := call(method, concrete, `{"undeclaredMember":1,"Name":"y"}`)
				assert.Equal(t, want.status, got.status, "%s", got.body)
				assert.JSONEq(t, string(want.body), string(got.body))
			})

			for name, member := range schema.Properties {
				proto := snakeCase(name)
				if proto == name {
					continue
				}

				value := sample(member)

				t.Run(op.OperationID+" "+proto, func(t *testing.T) {
					want := call(method, concrete, `{"`+name+`":`+value+`}`)
					got := call(method, concrete, `{"`+proto+`":`+value+`}`)
					assert.Equal(t, want.status, got.status, "%s", got.body)
					assert.JSONEq(t, string(want.body), string(got.body))

					both := call(method, concrete, `{"`+name+`":`+value+`,"`+proto+`":`+value+`}`)
					assert.Equal(t, http.StatusBadRequest, both.status, "%s", both.body)
					assert.Contains(t, string(both.body), "duplicate field")
				})
			}
		}
	}
}

// v1State is what a v1 write can change, to show a refused request wrote
// nothing.
// ptrValue prints what p points at, never its address.
func ptrValue[T any](p *T) string {
	if p == nil {
		return "<nil>"
	}

	return fmt.Sprint(*p)
}

// optValue prints an optional view value.
func optValue[T any](v T, ok bool) string {
	if !ok {
		return "<nil>"
	}

	return fmt.Sprint(v)
}

func v1State(t *testing.T, app *Headscale) string {
	t.Helper()

	users, err := app.state.ListAllUsers()
	require.NoError(t, err)

	apiKeys, err := app.state.ListAPIKeys()
	require.NoError(t, err)

	paks, err := app.state.ListPreAuthKeys()
	require.NoError(t, err)

	// Every stored column a v1 write can change, exactly, from the write
	// handlers: users (create, rename, delete), pre-auth and API keys
	// (create, expire, delete or revoke), nodes (register, expire, rename,
	// tags, routes, backfillips, delete) and the policy. Pending
	// registrations (auth register, approve, reject; debug create-node) live
	// in the auth cache, not here.
	var b strings.Builder

	for _, u := range users {
		fmt.Fprintf(&b, "user %d %q %q %q %q\n", u.ID, u.Name, u.DisplayName, u.Email, u.ProfilePicURL)
	}

	for _, k := range apiKeys {
		fmt.Fprintf(&b, "api key %d %s %s\n", k.ID, k.Prefix, ptrValue(k.Expiration))
	}

	for _, k := range paks {
		fmt.Fprintf(&b, "pre-auth key %d %s %s %s %v %v %v %v\n", k.ID, ptrValue(k.UserID), ptrValue(k.Expiration), ptrValue(k.Revoked), k.Used, k.Reusable, k.Ephemeral, k.Tags)
	}

	for _, n := range app.state.ListNodes().All() {
		fmt.Fprintf(&b, "node %d %s %q %s %s %s %v %v %v\n", n.ID(), optValue(n.UserID().GetOk()), n.GivenName(),
			optValue(n.IPv4().GetOk()), optValue(n.IPv6().GetOk()), optValue(n.Expiry().GetOk()),
			n.KeyExpiryDisabled(), n.ApprovedRoutes().AsSlice(), n.Tags().AsSlice())
	}

	policy, err := app.state.GetPolicy()
	if err == nil {
		fmt.Fprintf(&b, "policy %q\n", policy.Data)
	}

	return b.String()
}

// failingBody yields its bytes, then the error, as a client that drops the
// connection midway. With together, the error comes with the last bytes and
// EOF follows: 0.29's gateway decoded those bytes and wrote; Huma refuses a
// body whose read failed, and v1 keeps Huma's rule.
type failingBody struct {
	data     []byte
	err      error
	together bool
	failed   bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if len(b.data) == 0 {
		if b.together && b.failed {
			return 0, io.EOF
		}

		b.failed = true

		return 0, b.err
	}

	n := copy(p, b.data)
	b.data = b.data[n:]

	if b.together && len(b.data) == 0 {
		b.failed = true

		return n, b.err
	}

	return n, nil
}

// TestAPIV1BodyDecoding runs a corpus of broken bodies against every v1
// operation with a body. 0.29 refused each before the RPC (protojson, and
// the gateway's json.Decoder); none may write. encoding/json/v2 decides
// what is JSON. A read that fails midway is the read error, as Huma answers
// it, with nothing written.
func TestAPIV1BodyDecoding(t *testing.T) {
	h := newFastAPIV1Harness(t)
	seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

	_, api := apiv1.Handler(apiv1.Backend{})
	param := regexp.MustCompile(`\{[^}]+\}`)

	before := v1State(t, h.app)

	for path, item := range api.OpenAPI().Paths {
		concrete := param.ReplaceAllString(path, "1")

		for method, op := range map[string]*huma.Operation{
			http.MethodPost: item.Post, http.MethodPut: item.Put,
		} {
			if op == nil || op.RequestBody == nil {
				continue
			}

			schema := api.OpenAPI().Components.Schemas.SchemaFromRef(op.RequestBody.Content["application/json"].Schema.Ref)
			member := slices.Sorted(maps.Keys(schema.Properties))[0]
			whole := `{"` + member + `":"x"}`

			for name, body := range map[string]string{
				"truncated":       `{"` + member + `":"x"`,
				"wrong bracket":   `{"` + member + `":"x"]`,
				"trailing bytes":  whole + ` x`,
				"second value":    whole + whole,
				"duplicate":       `{"` + member + `":"x","` + member + `":"x"}`,
				"proto duplicate": `{"` + member + `":"x","` + snakeCase(member) + `":"x"}`,
				"array":           `[` + whole + `]`,
				"invalid utf-8":   "{\"" + member + "\":\"\xff\"}",
			} {
				if name == "proto duplicate" && snakeCase(member) == member {
					continue
				}

				t.Run(op.OperationID+" "+name, func(t *testing.T) {
					res := h.callHuma(method, concrete, []byte(body))
					assert.Equal(t, http.StatusBadRequest, res.status, "body: %s", res.body)
				})
			}

			for _, together := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s read fails, error with the bytes %v", op.OperationID, together), func(t *testing.T) {
					req := httptest.NewRequestWithContext(context.Background(), method, concrete,
						&failingBody{data: []byte(whole), err: io.ErrUnexpectedEOF, together: together})
					req.Header.Set("Content-Type", "application/json")

					rec := httptest.NewRecorder()
					h.huma.ServeHTTP(rec, req)

					assert.Equal(t, http.StatusInternalServerError, rec.Code, "body: %s", rec.Body.String())
					assert.Contains(t, rec.Body.String(), "cannot read request body")
				})
			}
		}
	}

	assert.Equal(t, before, v1State(t, h.app), "a refused body must write nothing")

	// The controls: whole bodies write.
	res := h.callHuma(http.MethodPost, "/api/v1/user", []byte(`{"name":"bob"}`))
	require.Equal(t, http.StatusOK, res.status, "body: %s", res.body)

	res = h.callHuma(http.MethodPost, "/api/v1/user", []byte(`{"name":"carol"]`))
	assert.Equal(t, http.StatusBadRequest, res.status, "body: %s", res.body)

	users, err := h.app.state.ListAllUsers()
	require.NoError(t, err)
	assert.Len(t, users, 2, "alice and bob, not carol")
}

// TestAPIV1BodyPathField: 0.29 decoded the path's own field in a body
// (SetApprovedRoutesRequest and SetTagsRequest carry node_id) as a uint64
// before the path overwrote it, so a malformed or doubled one was refused
// before the RPC. One naming another node is refused too. Stored routes are
// asserted unchanged on every refusal.
func TestAPIV1BodyPathField(t *testing.T) {
	route := netip.MustParsePrefix("10.0.0.0/24")

	tests := []struct {
		name   string
		path   string
		body   string
		status int
	}{
		{"routes, bool ID", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":true}`, http.StatusBadRequest},
		{"routes, both spellings", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":"1","node_id":"1"}`, http.StatusBadRequest},
		{"routes, other node", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":"2"}`, http.StatusBadRequest},
		{"routes, not a number", "/api/v1/node/1/approve_routes", `{"routes":[],"node_id":"one"}`, http.StatusBadRequest},
		{"routes, same ID as string", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":"1"}`, http.StatusOK},
		{"routes, same ID as number", "/api/v1/node/1/approve_routes", `{"routes":[],"node_id":1}`, http.StatusOK},
		// protojson's uint64 rules (wrapperspb.UInt64Value at the tag's
		// google.golang.org/protobuf v1.36.12).
		{"routes, ID 1.0", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":1.0}`, http.StatusOK},
		{"routes, ID \"1e0\"", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":"1e0"}`, http.StatusOK},
		{"routes, ID 0.1e1", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":0.1e1}`, http.StatusOK},
		{"routes, ID null", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":null}`, http.StatusOK},
		{"routes, ID \"01\"", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":"01"}`, http.StatusBadRequest},
		{"routes, ID -1", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":-1}`, http.StatusBadRequest},
		{"routes, ID 1.5", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":1.5}`, http.StatusBadRequest},
		{"routes, ID overflow", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":18446744073709551616}`, http.StatusBadRequest},
		// "" is no ID: v0.29.7 refused it before the RPC, main (422) too.
		{"routes, ID empty string", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":""}`, http.StatusBadRequest},
		{"routes, proto ID empty string", "/api/v1/node/1/approve_routes", `{"routes":[],"node_id":""}`, http.StatusBadRequest},
		{"routes, proto ID null", "/api/v1/node/1/approve_routes", `{"routes":[],"node_id":null}`, http.StatusOK},
		{"tags, ID empty string", "/api/v1/node/1/tags", `{"tags":["tag:x"],"nodeId":""}`, http.StatusBadRequest},
		{"tags, proto ID empty string", "/api/v1/node/1/tags", `{"tags":["tag:x"],"node_id":""}`, http.StatusBadRequest},
		{"routes, ID with space", "/api/v1/node/1/approve_routes", `{"routes":[],"nodeId":" 1"}`, http.StatusBadRequest},
		{"routes, unrelated member", "/api/v1/node/1/approve_routes", `{"routes":[],"comment":"x"}`, http.StatusOK},
		{"tags, bool ID", "/api/v1/node/1/tags", `{"tags":["tag:x"],"nodeId":true}`, http.StatusBadRequest},
		{"tags, both spellings", "/api/v1/node/1/tags", `{"tags":["tag:x"],"nodeId":"1","node_id":"1"}`, http.StatusBadRequest},
	}

	// One server; each row starts from the same stored routes and tags.
	h := newFastAPIV1Harness(t)
	seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := h.app.state.SetApprovedRoutes(1, []netip.Prefix{route})
			require.NoError(t, err)

			res := h.callHuma(http.MethodPost, tt.path, []byte(tt.body))
			assert.Equal(t, tt.status, res.status, "body: %s", res.body)

			node, ok := h.app.state.GetNodeByID(1)
			require.True(t, ok)

			if tt.status == http.StatusOK {
				assert.Empty(t, node.ApprovedRoutes().AsSlice())
			} else {
				assert.Equal(t, []netip.Prefix{route}, node.ApprovedRoutes().AsSlice(), "a refused request must not touch the routes")
				assert.Empty(t, node.Tags().AsSlice())
			}
		})
	}
}

// TestAPIV1BodyReadDeadline: the body is read under the operation's read
// deadline, as Huma reads it, even though the middleware reads first. A
// client that stops sending gets Huma's 408, and nothing is written; read
// outside the deadline it would hang.
func TestAPIV1BodyReadDeadline(t *testing.T) {
	// Waits out Huma's 5s read deadline; its own server, so it runs beside
	// the rest.
	t.Parallel()

	h := newFastAPIV1Harness(t)
	before := v1State(t, h.app)

	srv := httptest.NewServer(h.huma)
	t.Cleanup(srv.Close)

	pr, pw := io.Pipe()

	t.Cleanup(func() { _ = pw.Close() })

	go func() { _, _ = pw.Write([]byte(`{"name":`)) }()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/user", pr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}

	res, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = res.Body.Close() })

	assert.Equal(t, http.StatusRequestTimeout, res.StatusCode)
	assert.Equal(t, before, v1State(t, h.app))
}

// TestAPIV1BodyIDForms pins every declared ID member of a v1 body, form by
// form, by what it stores. Numbers and strings are read by protojson's
// uint64 rules, as at the tag; absent and null are not given. "" is not
// given either, for two reasons: the CLI's tags-only pre-auth key sends user
// "", and the two expire selectors keep main's reading of an empty id. 0 is
// no ID, as CreatePreAuthKey at v0.29.7 read it (request.GetUser() != 0).
// The path's own ID in a body refuses "", as at the tag and on main.
func TestAPIV1BodyIDForms(t *testing.T) {
	forms := []struct {
		name   string
		member string // the member and its value, "" for absent
	}{
		{"absent", ""},
		{"null", `null`},
		{"empty", `""`},
		{"zero", `0`},
		{"zero string", `"0"`},
		{"valid", `"1"`},
		{"valid number", `1.0`},
		{"leading zero", `"01"`},
		{"not a number", `"x"`},
	}

	member := func(name, value string) string {
		if value == "" {
			return ""
		}

		return `"` + name + `":` + value + `,`
	}

	t.Run("createPreAuthKey user", func(t *testing.T) {
		// What the key is made for: no user, alice, or refused.
		want := map[string]string{
			"absent": "none", "null": "none", "empty": "none", "zero": "none", "zero string": "none",
			"valid": "alice", "valid number": "alice", "leading zero": "refused", "not a number": "refused",
		}

		for _, f := range forms {
			h := newFastAPIV1Harness(t)
			h.app.state.CreateUserForTest("alice")

			res := h.callHuma(http.MethodPost, "/api/v1/preauthkey",
				[]byte(`{`+member("user", f.member)+`"aclTags":["tag:x"],"expiration":"2099-01-01T00:00:00Z"}`))

			keys, err := h.app.state.ListPreAuthKeys()
			require.NoError(t, err)

			switch want[f.name] {
			case "refused":
				assert.Equal(t, http.StatusBadRequest, res.status, "%s: %s", f.name, res.body)
				assert.Empty(t, keys, f.name)
			case "none":
				require.Equal(t, http.StatusOK, res.status, "%s: %s", f.name, res.body)
				require.Len(t, keys, 1, f.name)
				assert.Nil(t, keys[0].User, "%s: a tags-only key", f.name)
			case "alice":
				require.Equal(t, http.StatusOK, res.status, "%s: %s", f.name, res.body)
				require.Len(t, keys, 1, f.name)
				require.NotNil(t, keys[0].User, f.name)
				assert.Equal(t, "alice", keys[0].User.Name, f.name)
			}
		}
	})

	t.Run("expirePreAuthKey id", func(t *testing.T) {
		// Expired, or left as it was: no ID is not found, a bad one refused.
		want := map[string]int{
			"absent": http.StatusNotFound, "null": http.StatusNotFound, "empty": http.StatusNotFound,
			"zero": http.StatusNotFound, "zero string": http.StatusNotFound,
			"valid": http.StatusOK, "valid number": http.StatusOK,
			"leading zero": http.StatusBadRequest, "not a number": http.StatusBadRequest,
		}

		for _, f := range forms {
			h := newFastAPIV1Harness(t)
			user := h.app.state.CreateUserForTest("alice")
			later := time.Now().Add(time.Hour).Truncate(time.Second).UTC()

			_, err := h.app.state.CreatePreAuthKey(user.TypedID(), false, false, &later, nil)
			require.NoError(t, err)

			res := h.callHuma(http.MethodPost, "/api/v1/preauthkey/expire", []byte(`{`+strings.TrimSuffix(member("id", f.member), ",")+`}`))
			assert.Equal(t, want[f.name], res.status, "%s: %s", f.name, res.body)

			keys, err := h.app.state.ListPreAuthKeys()
			require.NoError(t, err)
			require.Len(t, keys, 1)
			require.NotNil(t, keys[0].Expiration)

			// A refusal leaves the seeded instant exactly, not merely in
			// the future.
			if res.status == http.StatusOK {
				assert.True(t, keys[0].Expiration.Before(time.Now()), "%s: expired", f.name)
			} else {
				assert.True(t, later.Equal(*keys[0].Expiration), "%s: stored %v", f.name, keys[0].Expiration)
			}
		}
	})

	t.Run("expireApiKey id", func(t *testing.T) {
		// No ID and no prefix is "must provide id or prefix".
		want := map[string]int{
			"absent": http.StatusBadRequest, "null": http.StatusBadRequest, "empty": http.StatusBadRequest,
			"zero": http.StatusBadRequest, "zero string": http.StatusBadRequest,
			"valid": http.StatusOK, "valid number": http.StatusOK,
			"leading zero": http.StatusBadRequest, "not a number": http.StatusBadRequest,
		}

		for _, f := range forms {
			h := newFastAPIV1Harness(t)
			later := time.Now().Add(time.Hour).Truncate(time.Second).UTC()

			_, _, err := h.app.state.CreateAPIKey(&later)
			require.NoError(t, err)

			res := h.callHuma(http.MethodPost, "/api/v1/apikey/expire", []byte(`{`+strings.TrimSuffix(member("id", f.member), ",")+`}`))
			assert.Equal(t, want[f.name], res.status, "%s: %s", f.name, res.body)

			keys, err := h.app.state.ListAPIKeys()
			require.NoError(t, err)
			require.Len(t, keys, 1)
			require.NotNil(t, keys[0].Expiration)

			if res.status == http.StatusOK {
				assert.True(t, keys[0].Expiration.Before(time.Now()), "%s: expired", f.name)
			} else {
				assert.True(t, later.Equal(*keys[0].Expiration), "%s: stored %v", f.name, keys[0].Expiration)
			}
		}
	})

	t.Run("approve_routes nodeId", func(t *testing.T) {
		// The path's field: absent, null or the path's ID, the routes are
		// set; "" (refused at the tag and on main), another ID or a bad one
		// is refused and the routes stay.
		route := netip.MustParsePrefix("10.0.0.0/24")
		want := map[string]int{
			"absent": http.StatusOK, "null": http.StatusOK, "empty": http.StatusBadRequest,
			"zero": http.StatusBadRequest, "zero string": http.StatusBadRequest,
			"valid": http.StatusOK, "valid number": http.StatusOK,
			"leading zero": http.StatusBadRequest, "not a number": http.StatusBadRequest,
		}

		h := newFastAPIV1Harness(t)
		seedNodes(newNodeSeed("alice", "node-a"))(t, h.app)

		for _, f := range forms {
			_, _, err := h.app.state.SetApprovedRoutes(1, []netip.Prefix{route})
			require.NoError(t, err)

			res := h.callHuma(http.MethodPost, "/api/v1/node/1/approve_routes", []byte(`{`+member("nodeId", f.member)+`"routes":[]}`))
			assert.Equal(t, want[f.name], res.status, "%s: %s", f.name, res.body)

			node, ok := h.app.state.GetNodeByID(1)
			require.True(t, ok)

			if res.status == http.StatusOK {
				assert.Empty(t, node.ApprovedRoutes().AsSlice(), "%s: routes replaced", f.name)
			} else {
				assert.Equal(t, []netip.Prefix{route}, node.ApprovedRoutes().AsSlice(), "%s: routes kept", f.name)
			}
		}
	})
}

// TestAPIV1BodyMediaType: the members are read the same for every
// Content-Type Huma decodes as JSON, since bodyMiddleware asks Huma's own
// format lookup; any other type is Huma's 415 and writes nothing.
func TestAPIV1BodyMediaType(t *testing.T) {
	tests := []struct {
		contentType string
		body        string
		status      int
		display     string // stored display name of user ed; "" = no user
	}{
		{"application/json", `{"name":"ed","display_name":"Editor"}`, http.StatusOK, "Editor"},
		{"application/json; charset=utf-8", `{"name":"ed","display_name":"Editor"}`, http.StatusOK, "Editor"},
		{"application/vnd.example+json", `{"name":"ed","display_name":"Editor"}`, http.StatusOK, "Editor"},
		{"", `{"name":"ed","display_name":"Editor"}`, http.StatusOK, "Editor"},
		{"application/vnd.example+json", `{"name":"ed","displayName":"A","display_name":"B"}`, http.StatusBadRequest, ""},
		{"application/vnd.example+json", `{"name":"ed"]`, http.StatusBadRequest, ""},
		{"text/plain", `{"name":"ed","display_name":"Editor"}`, http.StatusUnsupportedMediaType, ""},
	}

	for _, tt := range tests {
		t.Run(tt.contentType+" "+tt.body, func(t *testing.T) {
			h := newFastAPIV1Harness(t)

			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/user", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			rec := httptest.NewRecorder()
			h.huma.ServeHTTP(rec, req)
			assert.Equal(t, tt.status, rec.Code, "body: %s", rec.Body.String())

			users, err := h.app.state.ListAllUsers()
			require.NoError(t, err)

			if tt.display == "" {
				assert.Empty(t, users, "a refused request must not create a user")

				return
			}

			require.Len(t, users, 1)
			assert.Equal(t, tt.display, users[0].DisplayName)
		})
	}
}
