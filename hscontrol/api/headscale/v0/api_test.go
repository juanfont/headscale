package apiv0

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newBackend is a real State on a fresh SQLite database.
func newBackend(tb testing.TB) Backend {
	tb.Helper()

	cfg := config.Default()
	cfg.Database.Type = types.DatabaseSqlite
	cfg.Database.Sqlite.Path = tb.TempDir() + "/headscale.db"
	cfg.Policy.Mode = types.PolicyModeDB

	st, err := state.NewState(&cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = st.Close() })

	return Backend{State: st, Cfg: &cfg}
}

// newTestAPI is v0 on b, through humatest. Every answer is checked for a
// list sent as null, which a nullable:"false" tag does not prevent.
func newTestAPI(tb testing.TB, b Backend) humatest.TestAPI {
	tb.Helper()

	cfg := Config("test")
	cfg.Transformers = append(
		cfg.Transformers,
		func(_ huma.Context, _ string, v any) (any, error) {
			if at := nullList(reflect.ValueOf(v), "body"); at != "" {
				return nil, fmt.Errorf("%s is a nil list", at) //nolint:err113
			}

			return v, nil
		},
	)

	return humatest.Wrap(tb, newAPI(chi.NewMux(), b, cfg))
}

// nullList finds a nil slice in v that JSON would send as null, except in a
// field tagged nullable:"true".
func nullList(v reflect.Value, at string) string {
	switch v.Kind() { //nolint:exhaustive // only kinds that hold a slice
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return ""
		}

		return nullList(v.Elem(), at)
	case reflect.Slice:
		if v.IsNil() {
			return at
		}

		for i := range v.Len() {
			if found := nullList(
				v.Index(i),
				fmt.Sprintf("%s[%d]", at, i),
			); found != "" {
				return found
			}
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if found := nullList(
				v.MapIndex(k),
				fmt.Sprintf("%s.%v", at, k),
			); found != "" {
				return found
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if !f.IsExported() ||
				(f.Type.Kind() == reflect.Slice && f.Tag.Get("nullable") == "true" && v.Field(i).IsNil()) {
				continue
			}

			if found := nullList(v.Field(i), at+"."+f.Name); found != "" {
				return found
			}
		}
	}

	return ""
}

func TestNullListCheck(t *testing.T) {
	require.Equal(t, "body.Errors", nullList(reflect.ValueOf(&Problem{}), "body"))
	require.Equal(
		t,
		"body.Details.reasons",
		nullList(
			reflect.ValueOf(
				Problem{
					Errors:  []FieldError{},
					Details: map[string]any{"reasons": []HealthMessage(nil)},
				},
			),
			"body",
		),
	)
	require.Empty(
		t,
		nullList(reflect.ValueOf(Authorization{Scopes: []string{}}), "body"),
		"tags may be null",
	)
}

// decodeProblem reads a problem and checks the members every problem has.
func decodeProblem(tb testing.TB, rec *httptest.ResponseRecorder, want Code) Problem {
	tb.Helper()

	require.Equal(
		tb,
		problemContentType,
		rec.Header().Get("Content-Type"),
		rec.Body.String(),
	)

	var p Problem
	require.NoError(tb, json.Unmarshal(rec.Body.Bytes(), &p))

	require.Equal(tb, want, p.Code, rec.Body.String())
	require.Equal(tb, codes[want].status, rec.Code)
	require.Equal(tb, codes[want].status, p.Status)
	require.Equal(tb, problemTypeBase+string(want), p.Type)
	require.Equal(tb, codes[want].title, p.Title)
	require.NotNil(tb, p.Errors, "errors is a list, never null")
	require.NotNil(tb, p.Details, "details is an object, never null")

	return p
}

// withCommit makes the build know a commit for one test.
func withCommit(t *testing.T) {
	t.Helper()

	info := *types.GetVersionInfo()
	info.Version, info.Commit = "0.30.1", "a491228b7deadbeef"

	old := versionInfo
	versionInfo = func() *types.VersionInfo { return &info }

	t.Cleanup(func() { versionInfo = old })
}

func TestHandler(t *testing.T) {
	withCommit(t)

	h := Handler(newBackend(t))

	do := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, path, nil))

		return rec
	}

	t.Run("an unknown path is a problem", func(t *testing.T) {
		for _, path := range []string{Prefix + "/nope", Prefix, Prefix + "/"} {
			decodeProblem(t, do(http.MethodGet, path), CodeNotFound)
		}
	})

	t.Run("a wrong method is a problem with Allow", func(t *testing.T) {
		rec := do(http.MethodDelete, Prefix+"/version")
		decodeProblem(t, rec, CodeMethodNotAllowed)
		require.Equal(t, "GET", rec.Header().Get("Allow"))
	})

	t.Run("an unknown query parameter is invalid_field", func(t *testing.T) {
		p := decodeProblem(
			t,
			do(http.MethodGet, Prefix+"/version?usr=3"),
			CodeInvalidField,
		)
		require.Equal(
			t,
			[]FieldError{{Location: "query.usr", Message: "unknown query parameter"}},
			p.Errors,
		)
	})

	t.Run("Accept never refuses: v0 answers JSON whatever it asks", func(t *testing.T) {
		for _, accept := range []string{"text/plain", "application/json;q=0", "application/problem+json"} {
			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				Prefix+"/version",
				nil,
			)
			req.Header.Set("Accept", accept)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			require.Equal(t, http.StatusOK, rec.Code, accept)
			require.Equal(
				t,
				"application/json",
				rec.Header().Get("Content-Type"),
				accept,
			)
		}

		for _, info := range codes {
			require.NotEqual(
				t,
				http.StatusNotAcceptable,
				info.status,
				"no code may promise a 406 v0 never sends",
			)
		}
	})

	t.Run("the document and the docs page need no credential", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, do(http.MethodGet, Prefix+"/openapi.yaml").Code)
		assert.Equal(t, http.StatusOK, do(http.MethodGet, Prefix+"/docs").Code)
	})
}

// TestEarlyAnswersCarryVersion: the CLI reads the version headers before
// any body, so the answers made before a handler runs carry them too. The
// CORS preflight is checked where the router adds it, in hscontrol.
func TestEarlyAnswersCarryVersion(t *testing.T) {
	withCommit(t)

	b := newBackend(t)

	// Handler with one scoped operation, for the 403.
	mux := chi.NewMux()
	api := NewAPI(mux, b, "0.30.1")
	register(
		api,
		huma.Operation{
			OperationID: "readUsers",
			Method:      http.MethodGet,
			Path:        Prefix + "/scoped",
		},
		needs(
			scope.UsersRead,
		),
		nil,
		func(context.Context, *struct{}) (*struct{}, error) { return &struct{}{}, nil },
	)

	_, client, err := b.State.CreateOAuthClient(nil, nil, "", nil)
	require.NoError(t, err)

	token, _, err := b.State.MintAccessToken(
		client.ClientID,
		[]string{},
		nil,
		new(time.Now().Add(time.Hour)),
	)
	require.NoError(t, err)

	down := newBackend(t)
	key, _, err := down.State.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NoError(t, down.State.Close())

	for _, tt := range []struct {
		h      http.Handler
		method string
		path   string
		auth   string
		want   Code
	}{
		{Handler(b), http.MethodGet, Prefix + "/me", "", CodeUnauthorized},
		{VersionHeaders(mux), http.MethodGet, Prefix + "/scoped", "Bearer " + token, CodeForbidden},
		{Handler(b), http.MethodGet, Prefix + "/nope", "", CodeNotFound},
		{Handler(b), http.MethodPost, Prefix + "/me", "", CodeMethodNotAllowed},
		{Handler(down), http.MethodGet, Prefix + "/me", "Bearer " + key, CodeUnhealthy},
	} {
		req := httptest.NewRequestWithContext(t.Context(), tt.method, tt.path, nil)
		if tt.auth != "" {
			req.Header.Set("Authorization", tt.auth)
		}

		rec := httptest.NewRecorder()
		tt.h.ServeHTTP(rec, req)

		decodeProblem(t, rec, tt.want)
		require.Equal(t, "0.30.1", rec.Header().Get("Headscale-Version"), tt.want)
		require.Equal(t, "a491228", rec.Header().Get("Headscale-Commit"), tt.want)
	}
}

// TestAccessKind: no value of access is scoped without scopes. Such a value
// is undeclared, which register, the guard and the middleware refuse.
func TestAccessKind(t *testing.T) {
	for _, tt := range []struct {
		a    access
		want accessKind
	}{
		{access{}, undeclared},
		{access{open: scopedAccess}, undeclared},
		{access{open: publicAccess, scopes: []scope.Scope{scope.UsersRead}}, undeclared},
		{public, publicAccess},
		{anyCredential, anyCredentialAccess},
		{needs(scope.UsersRead), scopedAccess},
	} {
		require.Equal(t, tt.want, tt.a.kind(), "%+v", tt.a)
	}

	require.Panics(t, func() {
		//nolint:nilnil
		register(
			NewAPI(chi.NewMux(), Backend{}, "test"),
			huma.Operation{
				OperationID: "x",
				Method:      http.MethodGet,
				Path:        Prefix + "/x",
			},
			access{
				open: scopedAccess,
			},
			nil,
			func(context.Context, *struct{}) (*struct{}, error) { return nil, nil },
		)
	})
}

// TestNewAPIConcurrently: servers built at once share no state that
// building writes. It finds a race only under -race, as the gorace check
// runs it.
func TestNewAPIConcurrently(t *testing.T) {
	var wg sync.WaitGroup

	for range 4 {
		wg.Go(func() { NewAPI(chi.NewMux(), Backend{}, "test") })
	}

	wg.Wait()
}

// TestResponsesAreOpen: 002 lets a release add fields to an answer, so a
// client that validates answers against the document must take a field it
// does not know; a request body stays strict.
func TestResponsesAreOpen(t *testing.T) {
	oapi := NewAPI(chi.NewMux(), Backend{}, specVersion).OpenAPI()
	reg := oapi.Components.Schemas
	requests, responses := documentRoots(oapi)

	for name := range reachedSchemas(reg, requests) {
		require.Equal(
			t,
			false,
			reg.Map()[name].AdditionalProperties,
			"request schema %s must refuse an unknown field",
			name,
		)
	}

	for name := range reachedSchemas(reg, responses) {
		require.NotEqual(
			t,
			false,
			reg.Map()[name].AdditionalProperties,
			"response schema %s must take a field a later release adds",
			name,
		)

		for prop, ps := range reg.Map()[name].Properties {
			require.Empty(
				t,
				ps.Enum,
				"%s.%s must take a value a later release adds",
				name,
				prop,
			)

			if ps.Ref != "" {
				require.Empty(
					t,
					reg.SchemaFromRef(ps.Ref).Enum,
					"%s.%s must take a value a later release adds",
					name,
					prop,
				)
			}
		}
	}

	// What a strict client does with an answer of a later release.
	api := newTestAPI(t, newBackend(t))

	var later map[string]any
	require.NoError(t, json.Unmarshal(api.Get(Prefix+"/version").Body.Bytes(), &later))

	later["addedLater"] = true

	res := &huma.ValidateResult{}
	huma.Validate(
		reg,
		operations(oapi.Paths[Prefix+"/version"])[http.MethodGet].Responses["200"].Content["application/json"].Schema,
		huma.NewPathBuffer(nil, 0),
		huma.ModeReadFromServer,
		later,
		res,
	)
	require.Empty(t, res.Errors)

	// And a code it does not know.
	var problem map[string]any
	require.NoError(t, json.Unmarshal(api.Get(Prefix+"/me").Body.Bytes(), &problem))

	problem["code"] = "added_later"

	huma.Validate(
		reg,
		operations(oapi.Paths[Prefix+"/me"])[http.MethodGet].Responses["401"].Content[problemContentType].Schema,
		huma.NewPathBuffer(nil, 0),
		huma.ModeReadFromServer,
		problem,
		res,
	)
	require.Empty(t, res.Errors)
}

// TestAlwaysSentHeadersAreRequired: every answer that declares Location or
// ETag sends it, so the document says it is there.
func TestAlwaysSentHeadersAreRequired(t *testing.T) {
	oapi := NewAPI(chi.NewMux(), Backend{}, specVersion).OpenAPI()

	for path, item := range oapi.Paths {
		for method, op := range operations(item) {
			for status, r := range op.Responses {
				for _, name := range []string{"Location", "ETag"} {
					if h, ok := r.Headers[name]; ok {
						require.True(
							t,
							h.Required,
							"%s %s %s: %s",
							method,
							path,
							status,
							name,
						)
					}
				}
			}
		}
	}
}
