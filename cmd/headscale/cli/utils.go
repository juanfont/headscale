package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

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

func newHeadscaleCLIWithConfig() (context.Context, v1.HeadscaleServiceClient, *grpc.ClientConn, context.CancelFunc) {
	cfg, err := types.LoadCLIConfig()
	if err != nil {
		log.Fatal().
			Err(err).
			Caller().
			Msgf("Failed to load configuration")
		os.Exit(-1) // we get here if logging is suppressed (i.e., json output)
	}

	log.Debug().
		Dur("timeout", cfg.CLI.Timeout).
		Msgf("Setting timeout")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(),
	}

	address := cfg.CLI.Address

	// If the address is not set, we assume that we are on the server hosting hscontrol.
	if address == "" {
		log.Debug().
			Str("socket", cfg.UnixSocket).
			Msgf("HEADSCALE_CLI_ADDRESS environment is not set, connecting to unix socket.")

		address = cfg.UnixSocket

		// Try to give the user better feedback if we cannot write to the headscale
		// socket.
		socket, err := os.OpenFile(cfg.UnixSocket, os.O_WRONLY, 0o666) // nolint
		if err != nil {
			if os.IsPermission(err) {
				log.Fatal().
					Err(err).
					Str("socket", cfg.UnixSocket).
					Msgf("Unable to read/write to headscale socket, do you have the correct permissions?")
			}
		}
		socket.Close()

		grpcOptions = append(
			grpcOptions,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(util.GrpcSocketDialer),
		)
	} else {
		// If we are not connecting to a local server, require an API key for authentication
		apiKey := cfg.CLI.APIKey
		if apiKey == "" {
			log.Fatal().Caller().Msgf("HEADSCALE_CLI_API_KEY environment variable needs to be set.")
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

	log.Trace().Caller().Str("address", address).Msg("Connecting via gRPC")
	conn, err := grpc.DialContext(ctx, address, grpcOptions...)
	if err != nil {
		log.Fatal().Caller().Err(err).Msgf("Could not connect: %v", err)
		os.Exit(-1) // we get here if logging is suppressed (i.e., json output)
	}

	client := v1.NewHeadscaleServiceClient(conn)

	return ctx, client, conn, cancel
}

func output(result interface{}, override string, outputFormat string) string {
	var jsonBytes []byte
	var err error
	switch outputFormat {
	case "json":
		jsonBytes, err = json.MarshalIndent(result, "", "\t")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to unmarshal output")
		}
	case "json-line":
		jsonBytes, err = json.Marshal(result)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to unmarshal output")
		}
	case "yaml":
		jsonBytes, err = yaml.Marshal(result)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to unmarshal output")
		}
	default:
		// nolint
		return override
	}

	return string(jsonBytes)
}

// SuccessOutput prints the result to stdout and exits with status code 0.
func SuccessOutput(result interface{}, override string, outputFormat string) {
	fmt.Println(output(result, override, outputFormat))
	os.Exit(0)
}

// ErrorOutput prints an error message to stderr and exits with status code 1.
func ErrorOutput(errResult error, override string, outputFormat string) {
	type errOutput struct {
		Error string `json:"error"`
	}

	fmt.Fprintf(os.Stderr, "%s\n", output(errOutput{errResult.Error()}, override, outputFormat))
	os.Exit(1)
}

func HasMachineOutputFlag() bool {
	for _, arg := range os.Args {
		if arg == "json" || arg == "json-line" || arg == "yaml" {
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

// GetOutputFlag returns the output flag value (never fails)
func GetOutputFlag(cmd *cobra.Command) string {
	output, _ := cmd.Flags().GetString("output")
	return output
}


// GetNodeIdentifier returns the node ID using smart lookup via gRPC ListNodes call
func GetNodeIdentifier(cmd *cobra.Command) (uint64, error) {
	nodeFlag, _ := cmd.Flags().GetString("node")

	// Use --node flag
	if nodeFlag == "" {
		return 0, fmt.Errorf("--node flag is required")
	}

	// Use smart lookup via gRPC
	return lookupNodeBySpecifier(nodeFlag)
}

// lookupNodeBySpecifier performs smart lookup of a node by ID, name, hostname, or IP
func lookupNodeBySpecifier(specifier string) (uint64, error) {
	var nodeID uint64

	err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ListNodesRequest{}

		// Detect what type of specifier this is and set appropriate filter
		if id, err := strconv.ParseUint(specifier, 10, 64); err == nil && id > 0 {
			// Looks like a numeric ID
			request.Id = id
		} else if isIPAddress(specifier) {
			// Looks like an IP address
			request.IpAddresses = []string{specifier}
		} else {
			// Treat as hostname/name
			request.Name = specifier
		}

		response, err := client.ListNodes(ctx, request)
		if err != nil {
			return fmt.Errorf("failed to lookup node: %w", err)
		}

		nodes := response.GetNodes()
		if len(nodes) == 0 {
			return fmt.Errorf("no node found matching '%s'", specifier)
		}

		if len(nodes) > 1 {
			var nodeInfo []string
			for _, node := range nodes {
				nodeInfo = append(nodeInfo, fmt.Sprintf("ID=%d name=%s", node.GetId(), node.GetName()))
			}
			return fmt.Errorf("multiple nodes found matching '%s': %s", specifier, strings.Join(nodeInfo, ", "))
		}

		// Exactly one match - this is what we want
		nodeID = nodes[0].GetId()
		return nil
	})
	if err != nil {
		return 0, err
	}

	return nodeID, nil
}

// isIPAddress checks if a string looks like an IP address
func isIPAddress(s string) bool {
	// Try parsing as IP address (both IPv4 and IPv6)
	if net.ParseIP(s) != nil {
		return true
	}
	// Try parsing as CIDR
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return false
}

// GetUserIdentifier returns the user ID using smart lookup via gRPC ListUsers call
func GetUserIdentifier(cmd *cobra.Command) (uint64, error) {
	userFlag, _ := cmd.Flags().GetString("user")
	nameFlag, _ := cmd.Flags().GetString("name")

	var specifier string

	// Determine which flag was used (prefer --user, fall back to legacy flags)
	if userFlag != "" {
		specifier = userFlag
	} else if nameFlag != "" {
		specifier = nameFlag
	} else {
		return 0, fmt.Errorf("--user flag is required")
	}

	// Use smart lookup via gRPC
	return lookupUserBySpecifier(specifier)
}

// lookupUserBySpecifier performs smart lookup of a user by ID, name, or email
func lookupUserBySpecifier(specifier string) (uint64, error) {
	var userID uint64

	err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.ListUsersRequest{}

		// Detect what type of specifier this is and set appropriate filter
		if id, err := strconv.ParseUint(specifier, 10, 64); err == nil && id > 0 {
			// Looks like a numeric ID
			request.Id = id
		} else if strings.Contains(specifier, "@") {
			// Looks like an email address
			request.Email = specifier
		} else {
			// Treat as username
			request.Name = specifier
		}

		response, err := client.ListUsers(ctx, request)
		if err != nil {
			return fmt.Errorf("failed to lookup user: %w", err)
		}

		users := response.GetUsers()
		if len(users) == 0 {
			return fmt.Errorf("no user found matching '%s'", specifier)
		}

		if len(users) > 1 {
			var userInfo []string
			for _, user := range users {
				userInfo = append(userInfo, fmt.Sprintf("ID=%d name=%s email=%s", user.GetId(), user.GetName(), user.GetEmail()))
			}
			return fmt.Errorf("multiple users found matching '%s': %s", specifier, strings.Join(userInfo, ", "))
		}

		// Exactly one match - this is what we want
		userID = users[0].GetId()
		return nil
	})
	if err != nil {
		return 0, err
	}

	return userID, nil
}
