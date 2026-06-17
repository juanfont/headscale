package servertest_test

import (
	"context"
	"net/http"
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIv1_Health is the foundation smoke test: the ogen-generated client
// talks to the ogen-generated server in-process and gets a healthy response
// reporting database connectivity.
func TestAPIv1_Health(t *testing.T) {
	srv := servertest.NewServer(t)
	client := srv.APIClient(t, srv.CreateAPIKey(t))

	resp, err := client.Health(context.Background())
	require.NoError(t, err)
	assert.True(
		t,
		resp.DatabaseConnectivity.Value,
		"expected database connectivity true",
	)
}

// TestAPIv1_Health_Unauthorized verifies the bearer-auth SecurityHandler:
// an invalid API key yields a 401 RFC 7807 problem, matching the previous
// gRPC/gateway behaviour of rejecting bad tokens.
func TestAPIv1_Health_Unauthorized(t *testing.T) {
	srv := servertest.NewServer(t)
	client := srv.APIClient(t, "tskey-invalid")

	_, err := client.Health(context.Background())
	require.Error(t, err)

	var problem *apiv1.ErrorStatusCode
	require.ErrorAs(
		t,
		err, &problem,
		"expected *apiv1.ErrorStatusCode, got %T",
		err,
	)
	assert.Equal(t, http.StatusUnauthorized, problem.StatusCode)
}
