package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIV1ErrorBody pins the error body of /api/v1 to what 0.29 sent, through
// the real router. 0.29 served v1 with grpc-gateway v2.29.0 and its default
// ServeMux: DefaultHTTPErrorHandler writes status.Convert(err).Proto() with
// protojson (EmitUnpopulated, so details is []), at HTTPStatusFromCode(code);
// DefaultRoutingErrorHandler answers an unknown path with NotFound and a wrong
// method with Unimplemented (501). The 401 is pinned in TestAPIV1Unauthorized401,
// the routing errors in TestAPIV1RoutingError.
//
// Where the 0.29 text is reproduced byte for byte the whole body is pinned;
// elsewhere the code, the status and the message as main words it.
func TestAPIV1ErrorBody(t *testing.T) {
	app := createTestApp(t)
	handler := app.HTTPHandler()

	expiry := time.Now().Add(time.Hour)
	apiKey, _, err := app.state.CreateAPIKey(&expiry)
	require.NoError(t, err)

	app.state.CreateUserForTest("alice")

	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+apiKey)

		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec
	}

	tests := []struct {
		name       string
		method     string
		path       string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			// 0.29: status.Errorf(codes.NotFound, "node not found").
			name:       "not found",
			method:     http.MethodGet,
			path:       "/api/v1/node/99999",
			wantStatus: http.StatusNotFound,
			wantBody:   `{"code":5,"message":"node not found","details":[]}`,
		},
		{
			// 0.29: the generated gateway's path parameter error, word for word.
			name:       "invalid path parameter",
			method:     http.MethodGet,
			path:       "/api/v1/node/abc",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"code":3,"message":"type mismatch, parameter: node_id, error: strconv.ParseUint: parsing \"abc\": invalid syntax","details":[]}`,
		},
		{
			// 0.29: a plain error, so Unknown at 500, with the same text.
			name:       "internal",
			method:     http.MethodGet,
			path:       "/api/v1/policy",
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"code":2,"message":"loading ACL from database: acl policy not found","details":[]}`,
		},
		{
			// 0.29: Internal at 500 ("creating user: ..."). Since #3717 a 409,
			// which the gateway would write as AlreadyExists.
			name:       "conflict",
			method:     http.MethodPost,
			path:       "/api/v1/user",
			body:       `{"name":"alice"}`,
			wantStatus: http.StatusConflict,
			wantBody:   `{"code":6,"message":"user already exists","details":[]}`,
		},
		{
			// 0.29 refused a malformed request with InvalidArgument at 400;
			// Huma's 422 is written as that.
			name:       "validation",
			method:     http.MethodPost,
			path:       "/api/v1/user",
			body:       `{"name":1}`,
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"code":3,"message":"validation failed: expected string (body.name)","details":[]}`,
		},
		{
			// The gateway's own words after "validation failed": parsing
			// field "expiry": parsing time ... (runtime/query.go).
			name:       "expire query",
			method:     http.MethodPost,
			path:       "/api/v1/node/1/expire?expiry=tomorrow",
			wantStatus: http.StatusBadRequest,
			wantBody:   `{"code":3,"message":"validation failed: parsing field \"expiry\": parsing time \"tomorrow\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"tomorrow\" as \"2006\"","details":[]}`,
		},
		{
			name:       "malformed json",
			method:     http.MethodPost,
			path:       "/api/v1/user",
			body:       `{`,
			wantStatus: http.StatusBadRequest,
			// encoding/json/v2's words: it decides what is JSON (bodyMiddleware).
			wantBody: `{"code":3,"message":"jsontext: unexpected EOF after offset 1","details":[]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := call(tt.method, tt.path, tt.body)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
			assert.JSONEq(t, tt.wantBody, rec.Body.String())
		})
	}
}

// TestAPIV1ErrorBodyFilePolicy: 0.29 returned ErrPolicyUpdateIsDisabled
// unwrapped, so Unknown at 500; main answers 400, and the body keeps the 0.29
// shape.
func TestAPIV1ErrorBodyFilePolicy(t *testing.T) {
	app := createFilePolicyApp(t)

	res := callHandler(newHumaTestHandler(app), http.MethodPut, "/api/v1/policy", []byte(`{"policy":"{}"}`))
	assert.Equal(t, http.StatusBadRequest, res.status)
	assert.JSONEq(t,
		`{"code":3,"message":"`+types.ErrPolicyUpdateIsDisabled.Error()+`","details":[]}`,
		string(res.body))
}

// TestAPIV1SpecDescribesStatus: the OpenAPI document names the body errors
// really have.
func TestAPIV1SpecDescribesStatus(t *testing.T) {
	spec, err := apiv1.Spec()
	require.NoError(t, err)

	assert.Contains(t, string(spec), "#/components/schemas/Status")
	assert.NotContains(t, string(spec), "ErrorModel")
	assert.NotContains(t, string(spec), "application/problem+json")
}

// TestAPIV1RoutingError: 0.29 authenticated every /api request before the
// gateway routed it (hscontrol/app.go at v0.29.7), so without a valid key an
// unknown path or method was a 401 and only with one the gateway's 404 or 501.
// 0.29's socket spoke gRPC only, so it had no HTTP answer to keep; the socket
// is trusted like an operation call over it is.
func TestAPIV1RoutingError(t *testing.T) {
	app := createTestApp(t)
	router := app.HTTPHandler()
	socket := newHumaTestHandler(app)

	expiry := time.Now().Add(time.Hour)
	apiKey, _, err := app.state.CreateAPIKey(&expiry)
	require.NoError(t, err)

	const (
		notFound      = `{"code":5,"message":"Not Found","details":[]}`
		notAllowed    = `{"code":12,"message":"Method Not Allowed","details":[]}`
		unauthorized  = "Unauthorized"
		textPlain     = "text/plain; charset=utf-8"
		jsonType      = "application/json"
		unknownPath   = "/api/v1/nope"
		servedPathPut = "/api/v1/node/1"
	)

	tests := []struct {
		name       string
		handler    http.Handler
		auth       string
		method     string
		path       string
		wantStatus int
		wantType   string
		wantBody   string
	}{
		{"unknown path, no key", router, "", http.MethodGet, unknownPath, http.StatusUnauthorized, textPlain, unauthorized},
		{"unknown path, bad key", router, "Bearer hskey-api-bad", http.MethodGet, unknownPath, http.StatusUnauthorized, textPlain, unauthorized},
		{"unknown path, good key", router, "Bearer " + apiKey, http.MethodGet, unknownPath, http.StatusNotFound, jsonType, notFound},
		{"unknown path, socket", socket, "", http.MethodGet, unknownPath, http.StatusNotFound, jsonType, notFound},
		{"wrong method, no key", router, "", http.MethodPut, servedPathPut, http.StatusUnauthorized, textPlain, unauthorized},
		{"wrong method, bad key", router, "Bearer hskey-api-bad", http.MethodPut, servedPathPut, http.StatusUnauthorized, textPlain, unauthorized},
		{"wrong method, good key", router, "Bearer " + apiKey, http.MethodPut, servedPathPut, http.StatusNotImplemented, jsonType, notAllowed},
		{"wrong method, socket", socket, "", http.MethodPut, servedPathPut, http.StatusNotImplemented, jsonType, notAllowed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, nil)
			if tt.auth != "" {
				req.Header.Set("Authorization", tt.auth)
			}

			rec := httptest.NewRecorder()
			tt.handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, tt.wantType, rec.Header().Get("Content-Type"))

			if tt.wantType == jsonType {
				assert.JSONEq(t, tt.wantBody, rec.Body.String())
			} else {
				assert.Equal(t, tt.wantBody, rec.Body.String())
			}
		})
	}
}
