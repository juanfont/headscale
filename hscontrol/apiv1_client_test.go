package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

// TestAPIV1GeneratedClient smoke-tests the generated client against the Huma
// service over a real HTTP server, exercising the typed request/response path
// end to end.
func TestAPIV1GeneratedClient(t *testing.T) {
	app := createTestApp(t)
	srv := httptest.NewServer(newHumaTestHandler(app))
	t.Cleanup(srv.Close)

	client, err := clientv1.NewClientWithResponses(srv.URL)
	require.NoError(t, err)

	ctx := context.Background()

	health, err := client.HealthWithResponse(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, health.StatusCode())
	require.NotNil(t, health.JSON200)
	assert.True(t, health.JSON200.DatabaseConnectivity)

	name := "alice"
	created, err := client.CreateUserWithResponse(ctx, clientv1.CreateUserJSONRequestBody{
		Name: &name,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, created.StatusCode())
	require.NotNil(t, created.JSON200)
	require.NotNil(t, created.JSON200.User)
	assert.Equal(t, "alice", created.JSON200.User.Name)
	assert.Equal(t, "1", created.JSON200.User.Id)

	listed, err := client.ListUsersWithResponse(ctx, &clientv1.ListUsersParams{})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listed.StatusCode())
	require.NotNil(t, listed.JSON200)
	require.Len(t, listed.JSON200.Users, 1)
	assert.Equal(t, "alice", listed.JSON200.Users[0].Name)

	docs := false
	cfg, err := client.GetConfigWithResponse(ctx, &clientv1.GetConfigParams{Docs: &docs})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, cfg.StatusCode())

	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(cfg.Body, &doc), string(cfg.Body))
	assert.Contains(t, doc, "server_url")
	assert.NotContains(t, doc, "cli")
	assert.NotRegexp(t, `(?m)^\s*#`, string(cfg.Body))
}
