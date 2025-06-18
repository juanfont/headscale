package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/pterm/pterm"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

const (
	HeadscaleDateTimeFormat = "2006-01-02 15:04:05"
	SocketWritePermissions  = 0o666
)

// newHeadscaleCLIWithConfig creates a new gRPC client connection to headscale
func newHeadscaleCLIWithConfig(configPath string) (context.Context, v1.HeadscaleServiceClient, *grpc.ClientConn, context.CancelFunc, error) {
	// Load configuration
	if configPath == "" {
		configPath = os.Getenv("HEADSCALE_CONFIG")
	}
	if configPath == "" {
		configPath = "/etc/headscale/config.yaml"
	}

	cfg, err := types.LoadCLIConfig()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to load CLI config: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	grpcOptions := []grpc.DialOption{
		grpc.WithBlock(),
	}

	address := cfg.CLI.Address
	switch {
	case cfg.CLI.Insecure:
		grpcOptions = append(grpcOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	default:
		grpcOptions = append(grpcOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName: cfg.CLI.Address,
		})))
	}

	log.Trace().
		Str("address", address).
		Dur("timeout", cfg.CLI.Timeout).
		Msg("Connecting to headscale")

	conn, err := grpc.DialContext(ctx, address, grpcOptions...)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, fmt.Errorf("failed to connect: %w", err)
	}

	client := v1.NewHeadscaleServiceClient(conn)

	return ctx, client, conn, cancel, nil
}

// newHeadscaleServerWithConfig creates a new headscale server instance
func newHeadscaleServerWithConfig(configPath string) (*hscontrol.Headscale, error) {
	// Load configuration if not already loaded
	if configPath == "" {
		configPath = os.Getenv("HEADSCALE_CONFIG")
	}
	if configPath == "" {
		configPath = "/etc/headscale/config.yaml"
	}

	cfg, err := types.LoadServerConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load server config: %w", err)
	}

	app, err := hscontrol.NewHeadscale(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create headscale app: %w", err)
	}

	return app, nil
}

// outputResult outputs the result in the specified format
func outputResult(result interface{}, overrideText string, format string) error {
	switch format {
	case "json":
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(jsonBytes))
	case "yaml":
		yamlBytes, err := yaml.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal YAML: %w", err)
		}
		fmt.Print(string(yamlBytes))
	default:
		if overrideText != "" {
			fmt.Println(overrideText)
		} else {
			// Default table/human-readable output
			return outputTable(result)
		}
	}
	return nil
}

// nodesToPtables converts nodes to printable table format
func nodesToPtables(userFilter string, showTags bool, nodes []*v1.Node) (pterm.TableData, error) {
	tableData := pterm.TableData{}

	// Header row
	header := []string{"ID", "Name", "User", "IPv4", "IPv6", "Ephemeral", "Last Seen", "Online", "Expired"}
	if showTags {
		header = append(header, "Tags")
	}
	tableData = append(tableData, header)

	// Data rows
	for _, node := range nodes {
		row := []string{
			fmt.Sprintf("%d", node.GetId()),
			node.GetName(),
			node.GetUser().GetName(),
			strings.Join(node.GetIpAddresses(), ", "),
			"", // IPv6 - would need to be extracted from addresses
			"", // Ephemeral field not available in current API
			timestampProtoToString(node.GetLastSeen()),
			boolToString(node.GetOnline()),
			boolToString(node.GetExpiry() != nil && node.GetExpiry().AsTime().Before(time.Now())),
		}
		if showTags {
			row = append(row, stringSliceToString(node.GetForcedTags()))
		}
		tableData = append(tableData, row)
	}

	return tableData, nil
}

// nodeRoutesToPtables converts node route strings to printable table format
func nodeRoutesToPtables(routes []string) (pterm.TableData, error) {
	tableData := pterm.TableData{}

	// Header row
	header := []string{"Route"}
	tableData = append(tableData, header)

	// Data rows
	for _, route := range routes {
		row := []string{route}
		tableData = append(tableData, row)
	}

	return tableData, nil
}

// prettyPrintJSON prints JSON in a formatted way
func prettyPrintJSON(data interface{}) error {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(jsonBytes))
	return nil
}

// isSocketAddress checks if an address is a Unix socket
func isSocketAddress(address string) bool {
	return address[0] == '/'
}

// getSocketAddr returns the socket address for Unix sockets
func getSocketAddr(address string) net.Addr {
	addr, _ := net.ResolveUnixAddr("unix", address)
	return addr
}

// timestampToString converts a timestamp to a readable string
func timestampToString(ts *time.Time) string {
	if ts == nil {
		return ""
	}
	return ts.Format(HeadscaleDateTimeFormat)
}

// boolToString converts a boolean to a string representation
func boolToString(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// stringSliceToString converts a string slice to a comma-separated string
func stringSliceToString(slice []string) string {
	if len(slice) == 0 {
		return ""
	}
	return fmt.Sprintf("[%s]", strings.Join(slice, ", "))
}

// colourTime returns a colored time string for output
func colourTime(t time.Time) string {
	return t.Format(HeadscaleDateTimeFormat)
}
