package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/prometheus/common/model"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
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
)

// mustMarkRequired marks the named flags as required on cmd, panicking
// if any name does not match a registered flag.  This is only called
// from init() where a failure indicates a programming error.
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

// grpcRunE wraps a cobra RunE func, injecting a ready gRPC client and
// context. Connection lifecycle is managed by the wrapper — callers
// never see the underlying conn or cancel func.
func grpcRunE(
	fn func(ctx context.Context, client v1.HeadscaleServiceClient, cmd *cobra.Command, args []string) error,
) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig()
		if err != nil {
			return fmt.Errorf("connecting to headscale: %w", err)
		}
		defer cancel()
		defer conn.Close()

		return fn(ctx, client, cmd, args)
	}
}

func newHeadscaleCLIWithConfig() (context.Context, v1.HeadscaleServiceClient, *grpc.ClientConn, context.CancelFunc, error) {
	cfg, err := types.LoadCLIConfig()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("loading configuration: %w", err)
	}

	log.Debug().
		Dur("timeout", cfg.CLI.Timeout).
		Msgf("Setting timeout")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(), //nolint:staticcheck // SA1019: deprecated but supported in 1.x
	}

	address := cfg.CLI.Address

	// If the address is not set, we assume that we are on the server hosting hscontrol.
	if address == "" {
		log.Debug().
			Str("socket", cfg.UnixSocket).
			Msgf("HEADSCALE_CLI_ADDRESS environment is not set, connecting to unix socket.")

		address = cfg.UnixSocket

		// Try to give the user better feedback if we cannot write to the headscale
		// socket.  Note: os.OpenFile on a Unix domain socket returns ENXIO on
		// Linux which is expected — only permission errors are actionable here.
		// The actual gRPC connection uses net.Dial which handles sockets properly.
		socket, err := os.OpenFile(cfg.UnixSocket, os.O_WRONLY, SocketWritePermissions) //nolint
		if err != nil {
			if os.IsPermission(err) {
				cancel()

				return nil, nil, nil, nil, fmt.Errorf(
					"unable to read/write to headscale socket %q, do you have the correct permissions? %w",
					cfg.UnixSocket,
					err,
				)
			}
		} else {
			socket.Close()
		}

		grpcOptions = append(
			grpcOptions,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(util.GrpcSocketDialer),
		)
	} else {
		// If we are not connecting to a local server, require an API key for authentication
		apiKey := cfg.CLI.APIKey
		if apiKey == "" {
			cancel()

			return nil, nil, nil, nil, errAPIKeyNotSet
		}

		grpcOptions = append(grpcOptions,
			grpc.WithPerRPCCredentials(tokenAuth{
				token: apiKey,
			}),
		)

		if cfg.CLI.Insecure {
			tlsConfig := &tls.Config{
				// turn of gosec as we are intentionally setting
				// insecure.
				//nolint:gosec
				InsecureSkipVerify: true,
			}

			grpcOptions = append(grpcOptions,
				grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
			)
		} else {
			grpcOptions = append(grpcOptions,
				grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")),
			)
		}
	}

	log.Trace().Caller().Str(zf.Address, address).Msg("connecting via gRPC")

	conn, err := grpc.DialContext(ctx, address, grpcOptions...) //nolint:staticcheck // SA1019: deprecated but supported in 1.x
	if err != nil {
		cancel()

		return nil, nil, nil, nil, fmt.Errorf("connecting to %s: %w", address, err)
	}

	client := v1.NewHeadscaleServiceClient(conn)

	return ctx, client, conn, cancel, nil
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
// duration (e.g. "90d", "1h") and returns an absolute timestamp.
func expirationFromFlag(cmd *cobra.Command) (*timestamppb.Timestamp, error) {
	durationStr, _ := cmd.Flags().GetString("expiration")

	duration, err := model.ParseDuration(durationStr)
	if err != nil {
		return nil, fmt.Errorf("parsing duration: %w", err)
	}

	return timestamppb.New(time.Now().UTC().Add(time.Duration(duration))), nil
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

// printListOutput checks the --output flag: when a machine-readable format is
// requested it serialises data as JSON/YAML; otherwise it calls renderTable
// to produce the human-readable pterm table.
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
// Execute() so that every error surfaces in the format the caller asked for.
func printError(err error, outputFormat string) {
	type errOutput struct {
		Error string `json:"error"`
	}

	e := errOutput{Error: err.Error()}

	var formatted []byte

	switch outputFormat {
	case outputFormatJSON:
		formatted, _ = json.MarshalIndent(e, "", "\t") //nolint:errchkjson // errOutput contains only a string field
	case outputFormatJSONLine:
		formatted, _ = json.Marshal(e) //nolint:errchkjson // errOutput contains only a string field
	case outputFormatYAML:
		formatted, _ = yaml.Marshal(e)
	default:
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)

		return
	}

	fmt.Fprintf(os.Stderr, "%s\n", formatted)
}

func hasMachineOutputFlag() bool {
	for _, arg := range os.Args {
		if arg == outputFormatJSON || arg == outputFormatJSONLine || arg == outputFormatYAML {
			return true
		}
	}

	return false
}

type tokenAuth struct {
	token string
}

// Return value is mapped to request headers.
func (t tokenAuth) GetRequestMetadata(
	ctx context.Context,
	in ...string,
) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
	return true
}
