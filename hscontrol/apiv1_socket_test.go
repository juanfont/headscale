package hscontrol

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIV1SocketClient proves the CLI's local transport: the Huma handler over
// a unix socket reached by an http.Client that dials it, the same wiring as the
// server's socket listener and the CLI's newSocketClient, on local trust.
func TestAPIV1SocketClient(t *testing.T) {
	app := createTestApp(t)

	socketPath := filepath.Join(t.TempDir(), "headscale.sock")

	lis, err := new(net.ListenConfig).Listen(context.Background(), "unix", socketPath)
	require.NoError(t, err)

	srv := &http.Server{Handler: newHumaTestHandler(app)} //nolint:gosec
	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(func() { _ = srv.Close() })

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer

				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}

	client, err := clientv1.NewClientWithResponses(
		"http://local",
		clientv1.WithHTTPClient(httpClient),
	)
	require.NoError(t, err)

	ctx := context.Background()

	health, err := client.HealthWithResponse(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, health.StatusCode())
	require.NotNil(t, health.JSON200)
	assert.True(t, health.JSON200.DatabaseConnectivity)

	name := "socket-user"
	created, err := client.CreateUserWithResponse(ctx, clientv1.CreateUserJSONRequestBody{Name: &name})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, created.StatusCode())
	require.NotNil(t, created.JSON200)
	assert.Equal(t, "socket-user", created.JSON200.User.Name)
}
