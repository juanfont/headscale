package hsic

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sentinels, not credentials: each holds "sentinel" in its secret part.
const (
	apiSecret    = "hskey-api-0123456789ab-sentinelapisecret01"       //nolint:gosec // a sentinel
	authSecret   = "hskey-auth-ba9876543210-sentinelauthsecret02"     //nolint:gosec // a sentinel
	clientSecret = "hskey-client-c9f2a1-sentinelclientsecret03"       //nolint:gosec // a sentinel
	tokenSecret  = "hskey-oauthtok-ab12cd34ef56-sentineltokensecret4" //nolint:gosec // a sentinel
)

// decodeInto is the failure of decoding out into a new T, as cliJSON makes it.
func decodeInto[T any](out string) error {
	var v T

	err := json.Unmarshal([]byte(out), &v)
	if err == nil {
		return nil
	}

	return decodeFailure([]string{binHeadscale, "auth", "keys", "create", "HEADSCALE_CLI_API_KEY=" + apiSecret}, out, err)
}

// serve answers every request with status and body as JSON.
func serve(t *testing.T, status int, body string) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

// TestNoSecretInFailures runs every failure path of the helpers that make
// or take a credential, through the CLI (v0 objects) and through the
// generated v2 client, with sentinel secrets where a failure could show
// them: the argv, the output, the decoder's own error, an answer of another
// status. Neither the log nor the error may show a sentinel, and the error
// still unwraps to its cause. A new helper of the kind needs a row here.
func TestNoSecretInFailures(t *testing.T) {
	badCreated := func(secret string) string {
		return `{"id":"1","key":"` + secret + `","created":"` + secret + `"}`
	}

	tests := []struct {
		name  string
		fail  func(t *testing.T) error
		cause any
	}{
		{
			name: "a command that fails, secret in argv, stdout and stderr",
			fail: func(*testing.T) error {
				return execFailure(
					[]string{binHeadscale, "auth", "keys", "create", "tag:a", "HEADSCALE_CLI_API_KEY=" + apiSecret},
					`{"key":"`+authSecret+`"}`, "Error: "+clientSecret, dockertestutil.ErrDockertestCommandFailed)
			},
			cause: &dockertestutil.ErrDockertestCommandFailed,
		},
		{
			name:  "v0 auth key that does not decode",
			fail:  func(*testing.T) error { return decodeInto[clientv0.CreatedAuthKey](badCreated(authSecret)) },
			cause: new(*time.ParseError),
		},
		{
			name:  "v0 API key that does not decode",
			fail:  func(*testing.T) error { return decodeInto[clientv0.CreatedAPIKey](badCreated(apiSecret)) },
			cause: new(*time.ParseError),
		},
		{
			name:  "v0 OAuth client that does not decode",
			fail:  func(*testing.T) error { return decodeInto[clientv0.CreatedOAuthClient](badCreated(clientSecret)) },
			cause: new(*time.ParseError),
		},
		{
			name:  "output that is not JSON",
			fail:  func(*testing.T) error { return decodeInto[clientv0.CreatedAuthKey]("Error: " + authSecret) },
			cause: new(*json.SyntaxError),
		},
		{
			name: "v2 OAuth client that does not decode",
			fail: func(t *testing.T) error {
				t.Helper()

				_, _, err := createOAuthClient(context.Background(), serve(t, http.StatusOK, badCreated(clientSecret)), http.DefaultClient, apiSecret, []string{"auth_keys"}, nil)

				return err
			},
			cause: new(*time.ParseError),
		},
		{
			name: "v2 answer of another status that holds secrets",
			fail: func(t *testing.T) error {
				t.Helper()

				_, _, err := createOAuthClient(context.Background(), serve(t, http.StatusBadRequest, `{"message":"`+clientSecret+` `+tokenSecret+`"}`), http.DefaultClient, apiSecret, []string{"auth_keys"}, nil)

				return err
			},
			cause: &errOAuthStatus,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer

			orig := log.Writer()

			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(orig) })

			err := tt.fail(t)
			require.Error(t, err)

			for _, got := range []string{logs.String(), err.Error()} {
				assert.NotContains(t, got, "sentinel")
			}

			assert.Contains(t, err.Error(), "-***", "the error names the credential: %s", err)

			switch c := tt.cause.(type) {
			case *error:
				require.ErrorIs(t, err, *c)
			default:
				assert.ErrorAs(t, err, c, "unwraps to %T", c)
			}
		})
	}
}
