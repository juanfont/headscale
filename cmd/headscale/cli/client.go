package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	apiv1 "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/prometheus/common/model"
	"github.com/spf13/cobra"
)

// apiRunE wraps a cobra [cobra.Command.RunE] func, injecting a ready v1 API
// client and context. Connection lifecycle is managed by the wrapper.
func apiRunE(
	fn func(ctx context.Context, client *apiv1.Client, cmd *cobra.Command, args []string) error,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx, client, cancel, err := newHeadscaleAPIClient()
		if err != nil {
			return fmt.Errorf("connecting to headscale: %w", err)
		}
		defer cancel()

		return fn(ctx, client, cmd, args)
	}
}

// withAPI opens a v1 API client, runs fn with it, and cancels the context
// afterwards. It is the building block for commands that branch on a flag
// before deciding to talk to the server.
func withAPI(fn func(ctx context.Context, client *apiv1.Client) error) error {
	ctx, client, cancel, err := newHeadscaleAPIClient()
	if err != nil {
		return fmt.Errorf("connecting to headscale: %w", err)
	}
	defer cancel()

	return fn(ctx, client)
}

// newHeadscaleAPIClient builds a v1 HTTP API client. With no configured
// address it talks to the local unix socket (filesystem permissions are the
// trust boundary, no API key needed); otherwise it uses HTTPS with the API key.
func newHeadscaleAPIClient() (context.Context, *apiv1.Client, context.CancelFunc, error) {
	cfg, err := types.LoadCLIConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	if cfg.CLI.Address == "" {
		client, err := localSocketClient(cfg.UnixSocket)
		if err != nil {
			cancel()
			return nil, nil, nil, err
		}

		return ctx, client, cancel, nil
	}

	client, err := remoteClient(cfg.CLI.Address, cfg.CLI.APIKey, cfg.CLI.Insecure)
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}

	return ctx, client, cancel, nil
}

func localSocketClient(socketPath string) (*apiv1.Client, error) {
	err := checkSocketPermissions(socketPath)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialSocketWaiting(ctx, socketPath)
			},
		},
	}

	// The socket bypasses bearer auth; the token is a placeholder.
	return apiv1.NewClient("http://unix", cliToken("local-socket"), apiv1.WithClient(httpClient))
}

// dialSocketWaiting connects to the local unix socket, retrying while it is
// still absent. headscale removes and rebinds the socket during startup, so a
// CLI command issued right after "systemctl start" can beat the server to it.
// This mirrors the old blocking dial, which retried until the CLI timeout.
func dialSocketWaiting(ctx context.Context, socketPath string) (net.Conn, error) {
	var dialer net.Dialer

	for {
		conn, err := dialer.DialContext(ctx, "unix", socketPath)
		if err == nil {
			return conn, nil
		}

		if ctx.Err() != nil {
			return nil, err
		}

		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func remoteClient(address, apiKey string, insecure bool) (*apiv1.Client, error) {
	if apiKey == "" {
		return nil, errAPIKeyNotSet
	}

	transport := &http.Transport{}
	if insecure {
		//nolint:gosec // G402: insecure is an explicit, documented opt-in.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return apiv1.NewClient(
		serverURLFromAddress(address),
		cliToken(apiKey),
		apiv1.WithClient(&http.Client{Transport: transport}),
	)
}

// serverURLFromAddress turns a configured CLI address into a base URL,
// defaulting to https when no scheme is given.
func serverURLFromAddress(address string) string {
	if strings.Contains(address, "://") {
		return address
	}

	return "https://" + address
}

// checkSocketPermissions gives a friendlier error than a dial failure when the
// user cannot access the headscale socket.
func checkSocketPermissions(socketPath string) error {
	socket, err := os.OpenFile(socketPath, os.O_WRONLY, SocketWritePermissions) //nolint
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf(
				"unable to read/write to headscale socket %q, do you have the correct permissions? %w",
				socketPath, err,
			)
		}

		// ENXIO and similar are expected for a socket opened with O_WRONLY; the
		// real connection uses net.Dial which handles sockets properly.
		return nil
	}

	socket.Close()

	return nil
}

// optString / optUint64 / optTime build optional API request values from flag
// inputs, treating zero values as "unset".

func optString(s string) apiv1.OptString {
	if s == "" {
		return apiv1.OptString{}
	}

	return apiv1.NewOptString(s)
}

func optUint64(v uint64) apiv1.OptUint64 {
	if v == 0 {
		return apiv1.OptUint64{}
	}

	return apiv1.NewOptUint64(v)
}

// expirationFromFlag parses the --expiration flag as a Prometheus-style
// duration (e.g. "90d", "1h") and returns it as an absolute optional timestamp.
// An empty flag yields an unset value.
func expirationFromFlag(cmd *cobra.Command) (apiv1.OptDateTime, error) {
	durationStr, _ := cmd.Flags().GetString("expiration")
	if durationStr == "" {
		return apiv1.OptDateTime{}, nil
	}

	duration, err := model.ParseDuration(durationStr)
	if err != nil {
		return apiv1.OptDateTime{}, fmt.Errorf("parsing duration: %w", err)
	}

	return apiv1.NewOptDateTime(time.Now().UTC().Add(time.Duration(duration))), nil
}

// cliToken is an [apiv1.SecuritySource] that supplies a fixed bearer token.
type cliToken string

func (t cliToken) BearerAuth(context.Context, apiv1.OperationName) (apiv1.BearerAuth, error) {
	return apiv1.BearerAuth{Token: string(t)}, nil
}
