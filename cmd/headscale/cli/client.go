package cli

import (
	"context"
	"fmt"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// ClientWrapper wraps the gRPC client with automatic connection lifecycle management
type ClientWrapper struct {
	ctx    context.Context
	client v1.HeadscaleServiceClient
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

// NewClient creates a new ClientWrapper with automatic connection setup
func NewClient() (*ClientWrapper, error) {
	ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
	
	return &ClientWrapper{
		ctx:    ctx,
		client: client,
		conn:   conn,
		cancel: cancel,
	}, nil
}

// Close properly closes the gRPC connection and cancels the context
func (c *ClientWrapper) Close() {
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// ExecuteWithErrorHandling executes a gRPC operation with standardized error handling
func (c *ClientWrapper) ExecuteWithErrorHandling(
	cmd *cobra.Command,
	operation func(client v1.HeadscaleServiceClient) (interface{}, error),
	errorMsg string,
) (interface{}, error) {
	result, err := operation(c.client)
	if err != nil {
		output := GetOutputFormat(cmd)
		ErrorOutput(
			err,
			fmt.Sprintf("%s: %s", errorMsg, status.Convert(err).Message()),
			output,
		)
		return nil, err
	}
	return result, nil
}

// Specific operation helpers with automatic error handling and output formatting

// ListNodes executes a ListNodes request with error handling
func (c *ClientWrapper) ListNodes(cmd *cobra.Command, req *v1.ListNodesRequest) (*v1.ListNodesResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd, 
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ListNodes(c.ctx, req)
		},
		"Cannot get nodes",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ListNodesResponse), nil
}

// RegisterNode executes a RegisterNode request with error handling
func (c *ClientWrapper) RegisterNode(cmd *cobra.Command, req *v1.RegisterNodeRequest) (*v1.RegisterNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.RegisterNode(c.ctx, req)
		},
		"Cannot register node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.RegisterNodeResponse), nil
}

// DeleteNode executes a DeleteNode request with error handling
func (c *ClientWrapper) DeleteNode(cmd *cobra.Command, req *v1.DeleteNodeRequest) (*v1.DeleteNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.DeleteNode(c.ctx, req)
		},
		"Error deleting node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.DeleteNodeResponse), nil
}

// ExpireNode executes an ExpireNode request with error handling
func (c *ClientWrapper) ExpireNode(cmd *cobra.Command, req *v1.ExpireNodeRequest) (*v1.ExpireNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ExpireNode(c.ctx, req)
		},
		"Cannot expire node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ExpireNodeResponse), nil
}

// RenameNode executes a RenameNode request with error handling
func (c *ClientWrapper) RenameNode(cmd *cobra.Command, req *v1.RenameNodeRequest) (*v1.RenameNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.RenameNode(c.ctx, req)
		},
		"Cannot rename node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.RenameNodeResponse), nil
}

// MoveNode executes a MoveNode request with error handling
func (c *ClientWrapper) MoveNode(cmd *cobra.Command, req *v1.MoveNodeRequest) (*v1.MoveNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.MoveNode(c.ctx, req)
		},
		"Error moving node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.MoveNodeResponse), nil
}

// GetNode executes a GetNode request with error handling
func (c *ClientWrapper) GetNode(cmd *cobra.Command, req *v1.GetNodeRequest) (*v1.GetNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.GetNode(c.ctx, req)
		},
		"Error getting node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.GetNodeResponse), nil
}

// SetTags executes a SetTags request with error handling
func (c *ClientWrapper) SetTags(cmd *cobra.Command, req *v1.SetTagsRequest) (*v1.SetTagsResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.SetTags(c.ctx, req)
		},
		"Error while sending tags to headscale",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SetTagsResponse), nil
}

// SetApprovedRoutes executes a SetApprovedRoutes request with error handling
func (c *ClientWrapper) SetApprovedRoutes(cmd *cobra.Command, req *v1.SetApprovedRoutesRequest) (*v1.SetApprovedRoutesResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.SetApprovedRoutes(c.ctx, req)
		},
		"Error while sending routes to headscale",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SetApprovedRoutesResponse), nil
}

// BackfillNodeIPs executes a BackfillNodeIPs request with error handling
func (c *ClientWrapper) BackfillNodeIPs(cmd *cobra.Command, req *v1.BackfillNodeIPsRequest) (*v1.BackfillNodeIPsResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.BackfillNodeIPs(c.ctx, req)
		},
		"Error backfilling IPs",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.BackfillNodeIPsResponse), nil
}

// ListUsers executes a ListUsers request with error handling
func (c *ClientWrapper) ListUsers(cmd *cobra.Command, req *v1.ListUsersRequest) (*v1.ListUsersResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ListUsers(c.ctx, req)
		},
		"Cannot get users",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ListUsersResponse), nil
}

// CreateUser executes a CreateUser request with error handling
func (c *ClientWrapper) CreateUser(cmd *cobra.Command, req *v1.CreateUserRequest) (*v1.CreateUserResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.CreateUser(c.ctx, req)
		},
		"Cannot create user",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.CreateUserResponse), nil
}

// RenameUser executes a RenameUser request with error handling
func (c *ClientWrapper) RenameUser(cmd *cobra.Command, req *v1.RenameUserRequest) (*v1.RenameUserResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.RenameUser(c.ctx, req)
		},
		"Cannot rename user",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.RenameUserResponse), nil
}

// DeleteUser executes a DeleteUser request with error handling
func (c *ClientWrapper) DeleteUser(cmd *cobra.Command, req *v1.DeleteUserRequest) (*v1.DeleteUserResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.DeleteUser(c.ctx, req)
		},
		"Error deleting user",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.DeleteUserResponse), nil
}

// ListApiKeys executes a ListApiKeys request with error handling
func (c *ClientWrapper) ListApiKeys(cmd *cobra.Command, req *v1.ListApiKeysRequest) (*v1.ListApiKeysResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ListApiKeys(c.ctx, req)
		},
		"Cannot get API keys",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ListApiKeysResponse), nil
}

// CreateApiKey executes a CreateApiKey request with error handling
func (c *ClientWrapper) CreateApiKey(cmd *cobra.Command, req *v1.CreateApiKeyRequest) (*v1.CreateApiKeyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.CreateApiKey(c.ctx, req)
		},
		"Cannot create API key",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.CreateApiKeyResponse), nil
}

// ExpireApiKey executes an ExpireApiKey request with error handling
func (c *ClientWrapper) ExpireApiKey(cmd *cobra.Command, req *v1.ExpireApiKeyRequest) (*v1.ExpireApiKeyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ExpireApiKey(c.ctx, req)
		},
		"Cannot expire API key",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ExpireApiKeyResponse), nil
}

// DeleteApiKey executes a DeleteApiKey request with error handling
func (c *ClientWrapper) DeleteApiKey(cmd *cobra.Command, req *v1.DeleteApiKeyRequest) (*v1.DeleteApiKeyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.DeleteApiKey(c.ctx, req)
		},
		"Error deleting API key",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.DeleteApiKeyResponse), nil
}

// ListPreAuthKeys executes a ListPreAuthKeys request with error handling
func (c *ClientWrapper) ListPreAuthKeys(cmd *cobra.Command, req *v1.ListPreAuthKeysRequest) (*v1.ListPreAuthKeysResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ListPreAuthKeys(c.ctx, req)
		},
		"Cannot get preauth keys",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ListPreAuthKeysResponse), nil
}

// CreatePreAuthKey executes a CreatePreAuthKey request with error handling
func (c *ClientWrapper) CreatePreAuthKey(cmd *cobra.Command, req *v1.CreatePreAuthKeyRequest) (*v1.CreatePreAuthKeyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.CreatePreAuthKey(c.ctx, req)
		},
		"Cannot create preauth key",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.CreatePreAuthKeyResponse), nil
}

// ExpirePreAuthKey executes an ExpirePreAuthKey request with error handling
func (c *ClientWrapper) ExpirePreAuthKey(cmd *cobra.Command, req *v1.ExpirePreAuthKeyRequest) (*v1.ExpirePreAuthKeyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.ExpirePreAuthKey(c.ctx, req)
		},
		"Cannot expire preauth key",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.ExpirePreAuthKeyResponse), nil
}

// GetPolicy executes a GetPolicy request with error handling
func (c *ClientWrapper) GetPolicy(cmd *cobra.Command, req *v1.GetPolicyRequest) (*v1.GetPolicyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.GetPolicy(c.ctx, req)
		},
		"Cannot get policy",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.GetPolicyResponse), nil
}

// SetPolicy executes a SetPolicy request with error handling
func (c *ClientWrapper) SetPolicy(cmd *cobra.Command, req *v1.SetPolicyRequest) (*v1.SetPolicyResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.SetPolicy(c.ctx, req)
		},
		"Cannot set policy",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.SetPolicyResponse), nil
}

// DebugCreateNode executes a DebugCreateNode request with error handling
func (c *ClientWrapper) DebugCreateNode(cmd *cobra.Command, req *v1.DebugCreateNodeRequest) (*v1.DebugCreateNodeResponse, error) {
	result, err := c.ExecuteWithErrorHandling(cmd,
		func(client v1.HeadscaleServiceClient) (interface{}, error) {
			return client.DebugCreateNode(c.ctx, req)
		},
		"Cannot create node",
	)
	if err != nil {
		return nil, err
	}
	return result.(*v1.DebugCreateNodeResponse), nil
}

// Helper function to execute commands with automatic client management
func ExecuteWithClient(cmd *cobra.Command, operation func(*ClientWrapper) error) {
	client, err := NewClient()
	if err != nil {
		output := GetOutputFormat(cmd)
		ErrorOutput(err, "Cannot connect to headscale", output)
		return
	}
	defer client.Close()

	err = operation(client)
	if err != nil {
		// Error already handled by the operation
		return
	}
}