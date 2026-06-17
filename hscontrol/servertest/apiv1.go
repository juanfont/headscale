package servertest

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
)

// APIClient returns an ogen-generated v1 API client wired to this server's
// in-memory network and authenticated with apiKey (use [TestServer.CreateAPIKey]
// to mint one). This is the entry point for HTTP-API parity tests: the
// generated client talks to the generated server in-process, exercising the
// real request/response encoding.
func (s *TestServer) APIClient(tb testing.TB, apiKey string) *apiv1.Client {
	tb.Helper()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return s.memNet.Dial(ctx, network, addr)
			},
		},
	}

	client, err := apiv1.NewClient(
		s.URL,
		bearerToken(apiKey),
		apiv1.WithClient(httpClient),
	)
	if err != nil {
		tb.Fatalf("servertest: building API client: %v", err)
	}

	return client
}

// CreateNode creates a registered test node present in both the database and
// the in-memory NodeStore, so it can be read and mutated through the API.
func (s *TestServer) CreateNode(
	tb testing.TB,
	user *types.User,
	hostname string,
) *types.Node {
	tb.Helper()

	node := s.st.CreateRegisteredNodeForTest(user, hostname)
	// Ensure the User association is present in the NodeStore snapshot; the
	// database read path preloads it, but the test helper does not.
	node.User = user
	s.st.PutNodeInStoreForTest(*node)

	return node
}

// CreateAPIKey mints a non-expiring API key and returns the secret token.
func (s *TestServer) CreateAPIKey(tb testing.TB) string {
	tb.Helper()

	expiry := time.Now().Add(24 * time.Hour)

	key, _, err := s.st.CreateAPIKey(&expiry)
	if err != nil {
		tb.Fatalf("servertest: CreateAPIKey: %v", err)
	}

	return key
}

// bearerToken is an [apiv1.SecuritySource] that supplies a fixed bearer token.
type bearerToken string

func (t bearerToken) BearerAuth(
	context.Context,
	apiv1.OperationName,
) (apiv1.BearerAuth, error) {
	return apiv1.BearerAuth{Token: string(t)}, nil
}
