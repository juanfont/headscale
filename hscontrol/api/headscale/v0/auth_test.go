package apiv0

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	b := newBackend(t)
	api := newTestAPI(t, b)

	// No operation of this part needs a scope; this one stands in for them.
	register(api, huma.Operation{
		OperationID: "readUsers",
		Method:      http.MethodGet,
		Path:        Prefix + "/scoped",
	}, needs(scope.UsersRead, scope.DevicesCoreRead), nil, func(context.Context, *struct{}) (*struct{}, error) {
		return &struct{}{}, nil
	})

	apiKey, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	_, client, err := b.State.CreateOAuthClient(
		[]string{"devices:core:read"},
		nil,
		"reader",
		nil,
	)
	require.NoError(t, err)

	token, _, err := b.State.MintAccessToken(
		client.ClientID,
		[]string{"devices:core:read"},
		nil,
		new(time.Now().Add(time.Hour)),
	)
	require.NoError(t, err)

	// Authenticated is not authorized: a token with no scope still reads
	// /me and /health.
	noScope, _, err := b.State.MintAccessToken(
		client.ClientID,
		[]string{},
		nil,
		new(time.Now().Add(time.Hour)),
	)
	require.NoError(t, err)

	// A write scope holds its read scope.
	writer, _, err := b.State.MintAccessToken(
		client.ClientID,
		[]string{"devices:core"},
		nil,
		new(time.Now().Add(time.Hour)),
	)
	require.NoError(t, err)

	past := new(time.Now().Add(-time.Hour))
	expiredKey, _, err := b.State.CreateAPIKey(past)
	require.NoError(t, err)

	for _, tt := range []struct {
		name   string
		header string
		path   string
		want   int
		code   Code
		// missing is details.scopes of a forbidden answer.
		missing []any
	}{
		{name: "no credential", path: "/me", want: http.StatusUnauthorized, code: CodeUnauthorized},
		{name: "unknown key", header: "Bearer hskey-api-aaaaaaaaaaaa-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", path: "/me", want: http.StatusUnauthorized, code: CodeUnauthorized},
		{name: "expired key", header: "Bearer " + expiredKey, path: "/me", want: http.StatusUnauthorized, code: CodeUnauthorized},
		{name: "basic is the Tailscale API's", header: "Basic " + apiKey, path: "/me", want: http.StatusUnauthorized, code: CodeUnauthorized},
		{name: "api key", header: "Bearer " + apiKey, path: "/me", want: http.StatusOK},
		{name: "token", header: "Bearer " + token, path: "/me", want: http.StatusOK},
		{name: "token with no scope reads me", header: "Bearer " + noScope, path: "/me", want: http.StatusOK},
		{name: "token with no scope reads health", header: "Bearer " + noScope, path: "/health", want: http.StatusOK},
		{name: "token with no scope lacks every scope", header: "Bearer " + noScope, path: "/scoped", want: http.StatusForbidden, code: CodeForbidden, missing: []any{"users:read", "devices:core:read"}},
		{name: "a write scope holds its read scope", header: "Bearer " + writer, path: "/scoped", want: http.StatusForbidden, code: CodeForbidden, missing: []any{"users:read"}},
		{name: "the scheme ignores case", header: "bEARER " + apiKey, path: "/me", want: http.StatusOK},
		{name: "spaces after the scheme", header: "Bearer   " + apiKey, path: "/me", want: http.StatusOK},
		{name: "no credential is 401 before an unknown parameter", path: "/me?usr=3", want: http.StatusUnauthorized, code: CodeUnauthorized},
		{name: "api key holds every scope", header: "Bearer " + apiKey, path: "/scoped", want: http.StatusNoContent},
		{name: "token lacks one scope", header: "Bearer " + token, path: "/scoped", want: http.StatusForbidden, code: CodeForbidden, missing: []any{"users:read"}},
		{name: "version needs no credential", path: "/version", want: http.StatusOK},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var args []any
			if tt.header != "" {
				args = append(args, "Authorization: "+tt.header)
			}

			rec := api.Get(Prefix+tt.path, args...)
			require.Equal(t, tt.want, rec.Code, rec.Body.String())

			if tt.want == http.StatusUnauthorized {
				require.Equal(
					t,
					"Bearer",
					rec.Header().Get("WWW-Authenticate"),
					"RFC 9110 asks a challenge on 401",
				)
			}

			if tt.code != "" {
				p := decodeProblem(t, rec, tt.code)
				if tt.code == CodeForbidden {
					require.Equal(
						t,
						map[string]any{"scopes": tt.missing, "rule": nil},
						p.Details,
					)
				}
			}
		})
	}

	t.Run("no scope is an empty list", func(t *testing.T) {
		rec := api.Get(Prefix+"/me", "Authorization: Bearer "+noScope)
		require.Contains(t, rec.Body.String(), `"scopes":[]`)
	})

	t.Run("the socket needs no credential and has every scope", func(t *testing.T) {
		h := WithLocalTrust(Handler(b))

		for _, path := range []string{"/me", "/health"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(
				rec,
				httptest.NewRequestWithContext(
					t.Context(),
					http.MethodGet,
					Prefix+path,
					nil,
				),
			)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		}
	})

	t.Run(
		"an operation without access is refused for every caller",
		func(t *testing.T) {
			huma.Register(
				api,
				huma.Operation{
					OperationID: "bare",
					Method:      http.MethodGet,
					Path:        Prefix + "/bare",
				},
				func(context.Context, *struct{}) (*struct{}, error) { return &struct{}{}, nil },
			)

			decodeProblem(t, api.Get(Prefix+"/bare"), CodeInternal)
			decodeProblem(
				t,
				api.Get(Prefix+"/bare", "Authorization: Bearer "+noScope),
				CodeInternal,
			)
			decodeProblem(
				t,
				api.Get(Prefix+"/bare", "Authorization: Bearer "+apiKey),
				CodeInternal,
			)

			rec := httptest.NewRecorder()
			api.Adapter().ServeHTTP(rec, httptest.NewRequestWithContext(
				context.WithValue(
					t.Context(),
					localTrustKey,
					struct{}{},
				),
				http.MethodGet,
				Prefix+"/bare",
				nil,
			))
			decodeProblem(t, rec, CodeInternal)
		},
	)

	t.Run("needs without a scope panics", func(t *testing.T) {
		require.Panics(t, func() { needs() })
	})

	t.Run(
		"a database that does not answer is unhealthy, not unauthorized",
		func(t *testing.T) {
			down := newBackend(t)
			key, _, err := down.State.CreateAPIKey(nil)
			require.NoError(t, err)
			require.NoError(t, down.State.Close())

			for _, header := range []string{"Bearer " + key, "Bearer " + token} {
				p := decodeProblem(
					t,
					newTestAPI(t, down).Get(Prefix+"/me", "Authorization: "+header),
					CodeUnhealthy,
				)
				require.Equal(
					t,
					[]any{
						map[string]any{
							"code":    "database_unreachable",
							"message": "The database does not answer.",
							"details": map[string]any{},
						},
					},
					p.Details["reasons"],
				)
			}
		},
	)
}

func TestCredentialProblem(t *testing.T) {
	for _, tt := range []struct {
		err    error
		code   Code
		reason HealthCode
	}{
		{fmt.Errorf("looking up: %w: %w", db.ErrCredentialStore, sql.ErrConnDone), CodeUnhealthy, ReasonDatabaseUnreachable},
		{fmt.Errorf("verifying: %w", db.ErrLegacyHashBusy), CodeUnhealthy, ReasonCredentialCheckBusy},
		{db.ErrAPIKeyNotFound, CodeUnauthorized, ""},
		{db.ErrAccessTokenExpired, CodeUnauthorized, ""},
		//nolint:err113
		{errors.New("verifying api_key credential 3: stored hash is malformed"), CodeUnauthorized, ""},
	} {
		p := credentialProblem(t.Context(), tt.err)
		require.Equal(t, tt.code, p.Code, tt.err)

		if tt.reason != "" {
			//nolint:forcetypeassert
			require.Equal(t, tt.reason, p.Details["reasons"].([]HealthMessage)[0].Code)
		}
	}
}
