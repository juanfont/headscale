package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIAuthPendingInspect covers GET /api/v1/auth/{authId}: the endpoint
// an external registration page uses to show which device is waiting
// before it calls auth/register.
func TestAPIAuthPendingInspect(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithTestName("apiauthpending"),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	var apiKey string
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		out, err := headscale.Execute([]string{
			"headscale", "apikeys", "create", "--expiration", "24h",
		})
		assert.NoError(ct, err)
		assert.NotEmpty(ct, out)
		apiKey = strings.TrimSpace(out)
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	endpoint := headscale.GetEndpoint()

	get := func(ctx context.Context, id string) (*http.Response, map[string]any) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			endpoint+"/api/v1/auth/"+id, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+apiKey)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp, body
	}

	ctx := context.Background()

	t.Run("malformed id is 400", func(t *testing.T) {
		resp, _ := get(ctx, "not-an-auth-id")
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("unknown id is 404", func(t *testing.T) {
		resp, _ := get(ctx, "hskey-authreq-0123456789abcdef01234567")
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("pending session is described", func(t *testing.T) {
		clients, err := scenario.ListTailscaleClients()
		require.NoError(t, err)
		require.Len(t, clients, 1)

		// The env setup completed the first login; log out and start a
		// fresh web login that is left pending. Its login URL is
		// <endpoint>/register/<auth-id>.
		require.NoError(t, clients[0].Logout())
		loginURL, err := clients[0].LoginWithURL(endpoint)
		require.NoError(t, err)
		authID := path.Base(loginURL.Path)
		require.NotEmpty(t, authID)

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			resp, body := get(ctx, authID)
			if !assert.Equal(c, http.StatusOK, resp.StatusCode) {
				return
			}
			assert.Equal(c, authID, body["authId"])
			assert.Equal(c, clients[0].Hostname(), body["hostname"])
			assert.Equal(c, true, body["registration"])
		}, integrationutil.ScaledTimeout(30*time.Second), time.Second)
	})
}
