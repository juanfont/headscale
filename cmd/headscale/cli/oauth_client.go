package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	clientv2 "github.com/juanfont/headscale/gen/client/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
)

// oauthTailnet is the single Headscale tailnet the v2 API addresses as "-".
const oauthTailnet = "-"

func init() {
	rootCmd.AddCommand(oauthClientsCmd)

	oauthClientsCmd.AddCommand(listOAuthClientsCmd)

	createOAuthClientCmd.Flags().
		StringArrayP("scope", "s", nil, "Scope the client's tokens are granted (repeatable): auth_keys, oauth_keys, devices:core, devices:routes, policy_file, feature_settings (each with a :read variant), or all/all:read")
	createOAuthClientCmd.Flags().
		StringArrayP("tag", "t", nil, "Tag the client's tokens may assign to devices (repeatable), e.g. tag:k8s-operator")
	createOAuthClientCmd.Flags().StringP("description", "d", "", "Human-readable description")
	oauthClientsCmd.AddCommand(createOAuthClientCmd)

	deleteOAuthClientCmd.Flags().StringP("id", "i", "", "OAuth client id")
	oauthClientsCmd.AddCommand(deleteOAuthClientCmd)
}

var oauthClientsCmd = &cobra.Command{
	Use:     "oauth-clients",
	Short:   "Manage OAuth clients",
	Aliases: []string{"oauth-client", "oauthclients", "oauthclient", "oauth"},
}

var createOAuthClientCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an OAuth client",
	Long: `Create a general-purpose OAuth client. It authenticates with the OAuth 2.0
client-credentials grant and mints short-lived, scope-limited access tokens.
The wire format is compatible with Tailscale tooling (the Terraform provider,
the Kubernetes operator, tscli, ...), so those can drive Headscale unchanged.

The client secret is shown ONCE on creation and cannot be retrieved again; if
you lose it, delete the client and create a new one.

Scopes gate what the client's tokens may do; tags are the device tags those
tokens may assign and are required when the scopes include devices:core or
auth_keys.`,
	Aliases: []string{"c", cmdNew},
	RunE: func(cmd *cobra.Command, _ []string) error {
		scopes, _ := cmd.Flags().GetStringArray("scope")
		tags, _ := cmd.Flags().GetStringArray("tag")
		description, _ := cmd.Flags().GetString("description")

		if len(scopes) == 0 {
			return fmt.Errorf("at least one --scope is required: %w", errMissingParameter)
		}

		ctx, client, cancel, err := newV2Client()
		if err != nil {
			return err
		}
		defer cancel()

		keyType := "client"

		resp, err := client.CreateKeyWithResponse(ctx, oauthTailnet, clientv2.CreateKeyRequest{
			KeyType:     &keyType,
			Scopes:      &scopes,
			Tags:        &tags,
			Description: &description,
		})
		if err != nil {
			return fmt.Errorf("creating oauth client: %w", err)
		}

		err = v2Error(resp.HTTPResponse.StatusCode, resp.Body)
		if err != nil {
			return err
		}

		key := resp.JSON200

		return printOutput(cmd, key,
			fmt.Sprintf("OAuth client %s created.\nSecret (shown once, store it now): %s", key.Id, ptrStr(key.Key)))
	},
}

var listOAuthClientsCmd = &cobra.Command{
	Use:     cmdList,
	Short:   "List OAuth clients",
	Aliases: []string{"ls", cmdShow},
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, client, cancel, err := newV2Client()
		if err != nil {
			return err
		}
		defer cancel()

		resp, err := client.ListKeysWithResponse(ctx, oauthTailnet, nil)
		if err != nil {
			return fmt.Errorf("listing oauth clients: %w", err)
		}

		err = v2Error(resp.HTTPResponse.StatusCode, resp.Body)
		if err != nil {
			return err
		}

		// The keys endpoint is multiplexed; keep only OAuth clients.
		clients := make([]clientv2.Key, 0, len(resp.JSON200.Keys))

		for _, k := range resp.JSON200.Keys {
			if k.KeyType == "client" {
				clients = append(clients, k)
			}
		}

		return printListOutput(cmd, clients, func() error {
			rows := make([][]string, 0, len(clients))
			for _, c := range clients {
				rows = append(rows, []string{
					c.Id,
					strings.Join(ptrStrs(c.Scopes), ","),
					strings.Join(ptrStrs(c.Tags), ","),
					ptrStr(c.Description),
					c.Created.Format(HeadscaleDateTimeFormat),
				})
			}

			return renderTable([]string{"ID", "Scopes", "Tags", "Description", colCreated}, rows)
		})
	},
}

var deleteOAuthClientCmd = &cobra.Command{
	Use:     cmdDelete,
	Short:   "Delete an OAuth client",
	Aliases: []string{"remove", aliasDel},
	RunE: func(cmd *cobra.Command, _ []string) error {
		id, _ := cmd.Flags().GetString("id")
		if id == "" {
			return fmt.Errorf("--id is required: %w", errMissingParameter)
		}

		ctx, client, cancel, err := newV2Client()
		if err != nil {
			return err
		}
		defer cancel()

		resp, err := client.DeleteKeyWithResponse(ctx, oauthTailnet, id)
		if err != nil {
			return fmt.Errorf("deleting oauth client: %w", err)
		}

		err = v2Error(resp.HTTPResponse.StatusCode, resp.Body)
		if err != nil {
			return err
		}

		return printOutput(cmd, map[string]string{"id": id}, "OAuth client "+id+" deleted")
	},
}

// newV2Client builds a generated v2 API client, selecting the transport the same
// way the v1 client does: over the local unix socket it is unauthenticated
// (local trust); a remote address injects the configured API key as a bearer
// token.
func newV2Client() (context.Context, *clientv2.ClientWithResponses, context.CancelFunc, error) {
	cfg, err := types.LoadCLIConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading configuration: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.CLI.Timeout)

	if cfg.CLI.Address == "" {
		socketPath := cfg.UnixSocket

		httpClient := &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialHeadscaleSocket(ctx, socketPath)
			},
		}}

		client, err := clientv2.NewClientWithResponses("http://local", clientv2.WithHTTPClient(httpClient))
		if err != nil {
			cancel()

			return nil, nil, nil, err
		}

		return ctx, client, cancel, nil
	}

	if cfg.CLI.APIKey == "" {
		cancel()

		return nil, nil, nil, errAPIKeyNotSet
	}

	transport := &http.Transport{}
	if cfg.CLI.Insecure {
		//nolint:gosec // intentionally honouring the insecure flag
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	apiKey := cfg.CLI.APIKey

	client, err := clientv2.NewClientWithResponses(
		clientBaseURL(cfg.CLI.Address),
		clientv2.WithHTTPClient(&http.Client{Transport: transport}),
		clientv2.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+apiKey)

			return nil
		}),
	)
	if err != nil {
		cancel()

		return nil, nil, nil, err
	}

	return ctx, client, cancel, nil
}

// v2Error turns a non-2xx v2 response into an error. The v2 API emits the
// Tailscale error body ({"message":...}) rather than RFC 7807, so it reads the
// "message" field instead of the generated problem+json types.
func v2Error(status int, body []byte) error {
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return nil
	}

	var e struct {
		Message string `json:"message"`
	}

	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		//nolint:err113 // surfacing the server's message
		return fmt.Errorf("api error (%d): %s", status, e.Message)
	}

	//nolint:err113 // surfacing the server's body
	return fmt.Errorf("api error (%d): %s", status, strings.TrimSpace(string(body)))
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}

func ptrStrs(s *[]string) []string {
	if s == nil {
		return nil
	}

	return *s
}
