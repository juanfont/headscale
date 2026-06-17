package servertest_test

import (
	"testing"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiClient spins up a server and returns an authenticated v1 API client plus
// the server, for HTTP-parity tests.
func apiClient(t *testing.T) (*servertest.TestServer, *apiv1.Client) {
	t.Helper()

	srv := servertest.NewServer(t)

	return srv, srv.APIClient(t, srv.CreateAPIKey(t))
}

// requireProblem asserts that err is an RFC 7807 problem with the given HTTP
// status code.
func requireProblem(t *testing.T, err error, status int) {
	t.Helper()

	var problem *apiv1.ErrorStatusCode
	require.ErrorAsf(t, err, &problem, "expected *apiv1.ErrorStatusCode, got %T: %v", err, err)
	assert.Equal(t, status, problem.StatusCode)
}
