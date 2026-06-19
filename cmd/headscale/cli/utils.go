package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/prometheus/common/model"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	HeadscaleDateTimeFormat = "2006-01-02 15:04:05"
	SocketWritePermissions  = 0o666

	outputFormatJSON     = "json"
	outputFormatJSONLine = "json-line"
	outputFormatYAML     = "yaml"
)

var (
	errAPIKeyNotSet     = errors.New("HEADSCALE_CLI_API_KEY environment variable needs to be set")
	errMissingParameter = errors.New("missing parameters")
	errResponseStatus   = errors.New("unexpected response status")
)

// apiError turns a non-2xx response into an error, surfacing the server's
// RFC7807 problem detail. detail holds the operation context and errors[] the
// wrapped cause (e.g. "name is too long"); both are joined so the server's
// message text is not lost.
func apiError(statusCode int, problem *clientv1.ErrorModel) error {
	if problem == nil {
		return fmt.Errorf("%w: %d %s", errResponseStatus, statusCode, http.StatusText(statusCode))
	}

	parts := make([]string, 0, 2)

	if problem.Detail != nil && *problem.Detail != "" {
		parts = append(parts, *problem.Detail)
	}

	if problem.Errors != nil {
		for _, e := range *problem.Errors {
			if e.Message != nil && *e.Message != "" {
				parts = append(parts, *e.Message)
			}
		}
	}

	if len(parts) == 0 && problem.Title != nil && *problem.Title != "" {
		parts = append(parts, *problem.Title)
	}

	if len(parts) == 0 {
		return fmt.Errorf("%w: %d %s", errResponseStatus, statusCode, http.StatusText(statusCode))
	}

	return fmt.Errorf("%w: %s", errResponseStatus, strings.Join(parts, ": "))
}

// mustMarkRequired marks the named flags as required, panicking on an unknown
// flag. Only called from init(), where a failure is a programming error.
func mustMarkRequired(cmd *cobra.Command, names ...string) {
	for _, n := range names {
		err := cmd.MarkFlagRequired(n)
		if err != nil {
			panic(fmt.Sprintf("marking flag %q required on %q: %v", n, cmd.Name(), err))
		}
	}
}

func newHeadscaleServerWithConfig() (*hscontrol.Headscale, error) {
	cfg, err := types.LoadServerConfig()
	if err != nil {
		return nil, fmt.Errorf(
			"loading configuration: %w",
			err,
		)
	}

	app, err := hscontrol.NewHeadscale(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating new headscale: %w", err)
	}

	return app, nil
}

// clientRunE wraps a [cobra.Command.RunE] func, injecting a ready API client
// and a context whose timeout/cancel the wrapper owns.
func clientRunE(
	fn func(ctx context.Context, client *clientv1.ClientWithResponses, cmd *cobra.Command, args []string) error,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx, client, cancel, err := newHeadscaleCLIWithConfig()
		if err != nil {
			return fmt.Errorf("connecting to headscale: %w", err)
		}
		defer cancel()

		return fn(ctx, client, cmd, args)
	}
}

// withClient runs fn with an API client. For commands that branch on a flag
// before talking to the server, where clientRunE's whole-RunE wrapping does
// not fit.
func withClient(
	fn func(ctx context.Context, client *clientv1.ClientWithResponses) error,
) error {
	ctx, client, cancel, err := newHeadscaleCLIWithConfig()
	if err != nil {
		return fmt.Errorf("connecting to headscale: %w", err)
	}
	defer cancel()

	return fn(ctx, client)
}

// newHeadscaleCLIWithConfig builds an HTTP client for the Headscale v1 API.
//
// When cfg.CLI.Address is unset the CLI is assumed to run on the server host
// and talks to the unix socket over HTTP without authentication (local trust).
// Otherwise it talks to the remote TCP address over HTTPS and injects the
// configured API key as a bearer token.
func newHeadscaleCLIWithConfig() (context.Context, *clientv1.ClientWithResponses, context.CancelFunc, error) {
	cfg, err := types.LoadCLIConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading configuration: %w", err)
	}

	log.Debug().
		Dur("timeout", cfg.CLI.Timeout).
		Msgf("Setting timeout")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	address := cfg.CLI.Address

	// If the address is not set, we assume that we are on the server hosting [hscontrol].
	if address == "" {
		log.Debug().
			Str("socket", cfg.UnixSocket).
			Msgf("HEADSCALE_CLI_ADDRESS environment is not set, connecting to unix socket.")

		client, err := newSocketClient(cfg.UnixSocket)
		if err != nil {
			cancel()

			return nil, nil, nil, err
		}

		log.Trace().Caller().Str(zf.Address, cfg.UnixSocket).Msg("connecting via unix socket")

		return ctx, client, cancel, nil
	}

	// Remote connections require an API key for authentication.
	apiKey := cfg.CLI.APIKey
	if apiKey == "" {
		cancel()

		return nil, nil, nil, errAPIKeyNotSet
	}

	client, err := newRemoteClient(address, apiKey, cfg.CLI.Insecure)
	if err != nil {
		cancel()

		return nil, nil, nil, err
	}

	log.Trace().Caller().Str(zf.Address, address).Msg("connecting via HTTPS")

	return ctx, client, cancel, nil
}

// newSocketClient builds an API client that dials the local unix socket. The
// base-URL host is irrelevant; the custom dialer routes every request to the
// socket.
func newSocketClient(socketPath string) (*clientv1.ClientWithResponses, error) {
	// Probe for a clearer permission error up front. [os.OpenFile] on a unix
	// socket returns ENXIO on Linux (expected); only permission errors are
	// actionable. The real connection goes through [net.Dial].
	socket, err := os.OpenFile(socketPath, os.O_WRONLY, SocketWritePermissions) //nolint
	if err != nil {
		if os.IsPermission(err) {
			return nil, fmt.Errorf(
				"unable to read/write to headscale socket %q, do you have the correct permissions? %w",
				socketPath,
				err,
			)
		}
	} else {
		socket.Close()
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialHeadscaleSocket(ctx, socketPath)
			},
		},
	}

	return clientv1.NewClientWithResponses(
		"http://local",
		clientv1.WithHTTPClient(httpClient),
	)
}

// dialHeadscaleSocket connects to the unix socket, retrying until it appears or
// ctx (the CLI timeout) expires. The socket is created late in startup (after
// noise key, database, migrations), so a command run right after the server
// starts can race its creation; retrying preserves the old gRPC client's
// blocking-dial tolerance rather than failing on a not-yet-present socket.
func dialHeadscaleSocket(ctx context.Context, socketPath string) (net.Conn, error) {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 50 * time.Millisecond
	b.MaxInterval = 1 * time.Second

	return backoff.Retry(ctx, func() (net.Conn, error) {
		return util.SocketDialer(ctx, socketPath)
	}, backoff.WithBackOff(b))
}

// clientBaseURL turns a configured CLI address into a client base URL. A bare
// host[:port] (the historical form) defaults to https; an address that already
// carries a scheme is used as-is, so an explicit http:// or https:// is honoured
// rather than doubled into https://https://...
func clientBaseURL(address string) string {
	if strings.Contains(address, "://") {
		return address
	}

	return "https://" + address
}

// newRemoteClient builds an API client for a remote Headscale over HTTPS,
// honouring insecure (skip TLS verification) and injecting the API key as a
// bearer token on every request.
func newRemoteClient(address, apiKey string, insecure bool) (*clientv1.ClientWithResponses, error) {
	transport := &http.Transport{}
	if insecure {
		transport.TLSClientConfig = &tls.Config{
			// turn off gosec as we are intentionally setting insecure.
			//nolint:gosec
			InsecureSkipVerify: true,
		}
	}

	httpClient := &http.Client{Transport: transport}

	return clientv1.NewClientWithResponses(
		clientBaseURL(address),
		clientv1.WithHTTPClient(httpClient),
		clientv1.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+apiKey)

			return nil
		}),
	)
}

// formatOutput serialises result into the requested format. For the
// default (empty) format the human-readable override string is returned.
func formatOutput(result any, override string, outputFormat string) (string, error) {
	switch outputFormat {
	case outputFormatJSON:
		b, err := json.MarshalIndent(result, "", "\t")
		if err != nil {
			return "", fmt.Errorf("marshalling JSON output: %w", err)
		}

		return string(b), nil
	case outputFormatJSONLine:
		b, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("marshalling JSON-line output: %w", err)
		}

		return string(b), nil
	case outputFormatYAML:
		b, err := yaml.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("marshalling YAML output: %w", err)
		}

		return string(b), nil
	default:
		return override, nil
	}
}

// printOutput formats result and writes it to stdout. It reads the --output
// flag from cmd to decide the serialisation format.
func printOutput(cmd *cobra.Command, result any, override string) error {
	format, _ := cmd.Flags().GetString("output")

	out, err := formatOutput(result, override, format)
	if err != nil {
		return err
	}

	fmt.Println(out)

	return nil
}

// expirationFromFlag parses the --expiration flag as a Prometheus-style
// duration (e.g. "90d", "1h") and returns an absolute time.
func expirationFromFlag(cmd *cobra.Command) (time.Time, error) {
	durationStr, _ := cmd.Flags().GetString("expiration")

	duration, err := model.ParseDuration(durationStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing duration: %w", err)
	}

	return time.Now().UTC().Add(time.Duration(duration)), nil
}

// confirmAction returns true when the user confirms a prompt, or when
// --force is set.  Callers decide what to do when it returns false.
func confirmAction(cmd *cobra.Command, prompt string) bool {
	force, _ := cmd.Flags().GetBool("force")
	if force {
		return true
	}

	return util.YesNo(prompt)
}

// renderTable prints a human-readable pterm table with the given header row
// and data rows, using the shared header styling.
func renderTable(header []string, rows [][]string) error {
	tableData := make(pterm.TableData, 0, 1+len(rows))
	tableData = append(tableData, header)
	tableData = append(tableData, rows...)

	return pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}

// printListOutput checks the --output flag: when a machine-readable format is
// requested it serialises data as JSON/YAML; otherwise it calls the render
// callback to produce the human-readable pterm table.
func printListOutput(
	cmd *cobra.Command,
	data any,
	renderTable func() error,
) error {
	format, _ := cmd.Flags().GetString("output")
	if format != "" {
		return printOutput(cmd, data, "")
	}

	return renderTable()
}

// printError writes err to stderr, formatting it as JSON/YAML when the
// --output flag requests machine-readable output.  Used exclusively by
// [Execute] so that every error surfaces in the format the caller asked for.
func printError(err error, outputFormat string) {
	type errOutput struct {
		Error string `json:"error"`
	}

	if outputFormat == "" {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)

		return
	}

	// formatOutput cannot fail here: errOutput is a single string field.
	out, _ := formatOutput(errOutput{Error: err.Error()}, "", outputFormat)
	fmt.Fprintf(os.Stderr, "%s\n", out)
}

func hasMachineOutputFlag() bool {
	return slices.ContainsFunc(os.Args, func(arg string) bool {
		return arg == outputFormatJSON || arg == outputFormatJSONLine || arg == outputFormatYAML
	})
}
