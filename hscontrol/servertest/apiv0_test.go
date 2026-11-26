package servertest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAPIv0Me runs the generated client against a real server for each
// kind of caller of today: an API key, an OAuth token and the unix socket.
func TestAPIv0Me(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	apiKey := srv.CreateAPIKey(t, alice)

	_, client, err := srv.State().CreateOAuthClient([]string{"users:read"}, nil, "ci", nil)
	require.NoError(t, err)

	token, _, err := srv.State().MintAccessToken(client.ClientID, []string{"users:read"}, nil, new(time.Now().Add(time.Hour)))
	require.NoError(t, err)

	overTCP := &http.Client{Transport: &http.Transport{DialContext: srv.MemNet().Dial}}

	bearer := func(key string) clientv0.RequestEditorFn {
		return func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+key)

			return nil
		}
	}

	for _, tt := range []struct {
		name       string
		server     string
		httpClient *http.Client
		editors    []clientv0.RequestEditorFn
		check      func(t *testing.T, me *clientv0.Me)
	}{
		{
			name:       "api key",
			server:     srv.URL,
			httpClient: overTCP,
			editors:    []clientv0.RequestEditorFn{bearer(apiKey)},
			check: func(t *testing.T, me *clientv0.Me) {
				t.Helper()
				require.Equal(t, clientv0.PrincipalKindApiKey, me.Principal.Kind)

				cred := me.Credential.MustGet()
				require.Equal(t, clientv0.CredentialKindApiKey, cred.Kind)
				require.Equal(t, "alice", cred.Owner.MustGet().User.MustGet().LoginName)
				require.Equal(t, []string{"all"}, me.Authorization.Scopes)
				require.True(t, me.Authorization.Tags.IsNull())
			},
		},
		{
			name:       "oauth token",
			server:     srv.URL,
			httpClient: overTCP,
			editors:    []clientv0.RequestEditorFn{bearer(token)},
			check: func(t *testing.T, me *clientv0.Me) {
				t.Helper()
				require.Equal(t, clientv0.PrincipalKindOauthClient, me.Principal.Kind)

				cred := me.Credential.MustGet()
				require.Equal(t, clientv0.CredentialKindOauthToken, cred.Kind)
				require.Equal(t, "ci", cred.Client.MustGet().Description)
				require.Equal(t, []string{"users:read"}, me.Authorization.Scopes)
				require.Equal(t, []string{}, me.Authorization.Tags.MustGet())
			},
		},
		{
			name:       "unix socket",
			server:     "http://headscale",
			httpClient: srv.SocketClient(),
			check: func(t *testing.T, me *clientv0.Me) {
				t.Helper()
				require.Equal(t, clientv0.PrincipalKindLocal, me.Principal.Kind)
				require.True(t, me.Credential.IsNull())
				require.Equal(t, []string{"all"}, me.Authorization.Scopes)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := clientv0.NewClientWithResponses(tt.server, clientv0.WithHTTPClient(tt.httpClient))
			require.NoError(t, err)

			resp, err := c.GetMeWithResponse(t.Context(), tt.editors...)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
			require.Equal(t, types.GetVersionInfo().Version, resp.HTTPResponse.Header.Get("Headscale-Version"))
			tt.check(t, resp.JSON200)

			health, err := c.GetHealthWithResponse(t.Context(), tt.editors...)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, health.StatusCode(), string(health.Body))
			require.True(t, health.JSON200.Healthy)
		})
	}

	t.Run("no credential is a problem the client reads", func(t *testing.T) {
		t.Parallel()

		c, err := clientv0.NewClientWithResponses(srv.URL, clientv0.WithHTTPClient(overTCP))
		require.NoError(t, err)

		resp, err := c.GetMeWithResponse(t.Context())
		require.NoError(t, err)
		require.Equal(t, clientv0.ProblemCodeUnauthorized, resp.ApplicationproblemJSON401.Code)

		version, err := c.GetVersionWithResponse(t.Context())
		require.NoError(t, err)
		require.Equal(t, types.GetVersionInfo().Version, version.JSON200.Version)
	})
}
