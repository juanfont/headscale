package hscontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
