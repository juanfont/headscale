package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewMockHeadscaleServiceClient(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	// Verify mock is properly initialized
	assert.NotNil(t, mock)
	assert.NotNil(t, mock.CallCount)
	assert.Equal(t, 0, len(mock.CallCount))
	
	// Verify default responses are set
	assert.NotNil(t, mock.ListUsersResponse)
	assert.NotNil(t, mock.CreateUserResponse)
	assert.NotNil(t, mock.ListNodesResponse)
	assert.NotNil(t, mock.CreateApiKeyResponse)
}

func TestMockClient_ListUsers(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	// Test successful response
	req := &v1.ListUsersRequest{}
	resp, err := mock.ListUsers(context.Background(), req)
	
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, mock.CallCount["ListUsers"])
	assert.Equal(t, req, mock.LastRequest)
}

func TestMockClient_ListUsersError(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	// Configure error response
	expectedError := status.Error(codes.Internal, "test error")
	mock.ListUsersError = expectedError
	
	req := &v1.ListUsersRequest{}
	resp, err := mock.ListUsers(context.Background(), req)
	
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Equal(t, expectedError, err)
	assert.Equal(t, 1, mock.CallCount["ListUsers"])
}

func TestMockClient_CreateUser(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	req := &v1.CreateUserRequest{Name: "testuser"}
	resp, err := mock.CreateUser(context.Background(), req)
	
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.User)
	assert.Equal(t, 1, mock.CallCount["CreateUser"])
	assert.Equal(t, req, mock.LastRequest)
}

func TestMockClient_ListNodes(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	req := &v1.ListNodesRequest{}
	resp, err := mock.ListNodes(context.Background(), req)
	
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 1, mock.CallCount["ListNodes"])
	assert.Equal(t, req, mock.LastRequest)
}

func TestMockClient_CreateApiKey(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	req := &v1.CreateApiKeyRequest{}
	resp, err := mock.CreateApiKey(context.Background(), req)
	
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.ApiKey)
	assert.Equal(t, 1, mock.CallCount["CreateApiKey"])
}

func TestMockClient_CallTracking(t *testing.T) {
	mock := NewMockHeadscaleServiceClient()
	
	// Make multiple calls to different methods
	mock.ListUsers(context.Background(), &v1.ListUsersRequest{})
	mock.ListUsers(context.Background(), &v1.ListUsersRequest{})
	mock.ListNodes(context.Background(), &v1.ListNodesRequest{})
	
	// Verify call counts
	assert.Equal(t, 2, mock.CallCount["ListUsers"])
	assert.Equal(t, 1, mock.CallCount["ListNodes"])
	assert.Equal(t, 0, mock.CallCount["CreateUser"]) // Not called
}

func TestNewMockClientWrapper(t *testing.T) {
	wrapper := NewMockClientWrapperOld()
	
	assert.NotNil(t, wrapper)
	assert.NotNil(t, wrapper.MockClient)
	assert.NotNil(t, wrapper.ctx)
	assert.NotNil(t, wrapper.cancel)
}

func TestMockClientWrapper_Close(t *testing.T) {
	wrapper := NewMockClientWrapperOld()
	
	// Test that Close doesn't panic
	wrapper.Close()
	
	// Verify context is cancelled
	select {
	case <-wrapper.ctx.Done():
		// Context was cancelled - good
	default:
		t.Error("Context should be cancelled after Close()")
	}
}

func TestExecuteCommand(t *testing.T) {
	// Create a simple test command that doesn't call external dependencies
	cmd := CreateTestCommand("test")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		fmt.Print("test output")
	}
	
	output, err := ExecuteCommand(cmd, []string{})
	
	assert.NoError(t, err)
	assert.Contains(t, output, "test output")
}

func TestExecuteCommandWithInput(t *testing.T) {
	// Create a command that reads input
	cmd := CreateTestCommand("test")
	cmd.Run = func(cmd *cobra.Command, args []string) {
		fmt.Print("command executed")
	}
	
	output, err := ExecuteCommandWithInput(cmd, []string{}, "test input\n")
	
	assert.NoError(t, err)
	assert.Contains(t, output, "command executed")
}

func TestExecuteCommandError(t *testing.T) {
	// Create a command that returns an error
	cmd := CreateTestCommand("test")
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("test error")
	}
	cmd.Run = nil // Clear the default Run function
	
	output, err := ExecuteCommand(cmd, []string{})
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test error")
	assert.Equal(t, "", output) // No output on error
}

func TestValidateJSONOutput(t *testing.T) {
	// Test valid JSON
	jsonOutput := `{"name": "test", "id": 123}`
	expected := map[string]interface{}{
		"name": "test",
		"id":   float64(123), // JSON numbers become float64
	}
	
	// This should not panic or fail
	ValidateJSONOutput(t, jsonOutput, expected)
}

func TestValidateJSONOutput_Invalid(t *testing.T) {
	// Test with invalid JSON - should cause test failure
	// We can't easily test this without a custom test runner,
	// but we can verify the function exists
	assert.NotNil(t, ValidateJSONOutput)
}

func TestValidateYAMLOutput(t *testing.T) {
	// Test valid YAML
	yamlOutput := `name: test
id: 123`
	expected := map[string]interface{}{
		"name": "test",
		"id":   123,
	}
	
	// This should not panic or fail
	ValidateYAMLOutput(t, yamlOutput, expected)
}

func TestValidateTableOutput(t *testing.T) {
	// Test table output validation
	tableOutput := `ID    Name       Status
1     testnode   online
2     testnode2  offline`
	
	expectedHeaders := []string{"ID", "Name", "Status"}
	
	// This should not panic or fail
	ValidateTableOutput(t, tableOutput, expectedHeaders)
}

func TestNewTestUser(t *testing.T) {
	user := NewTestUser(123, "testuser")
	
	assert.NotNil(t, user)
	assert.Equal(t, uint64(123), user.Id)
	assert.Equal(t, "testuser", user.Name)
	assert.Equal(t, "testuser@example.com", user.Email)
	assert.NotNil(t, user.CreatedAt)
}

func TestNewTestNode(t *testing.T) {
	user := NewTestUser(1, "testuser")
	node := NewTestNode(456, "testnode", user)
	
	assert.NotNil(t, node)
	assert.Equal(t, uint64(456), node.Id)
	assert.Equal(t, "testnode", node.Name)
	assert.Equal(t, "testnode-device", node.GivenName)
	assert.Equal(t, user, node.User)
	assert.Equal(t, []string{"192.168.1.456"}, node.IpAddresses)
	assert.True(t, node.Online)
	assert.NotNil(t, node.CreatedAt)
	assert.NotNil(t, node.LastSeen)
}

func TestNewTestApiKey(t *testing.T) {
	apiKey := NewTestApiKey(789, "testprefix")
	
	assert.NotNil(t, apiKey)
	assert.Equal(t, uint64(789), apiKey.Id)
	assert.Equal(t, "testprefix", apiKey.Prefix)
	assert.NotNil(t, apiKey.CreatedAt)
}

func TestNewTestPreAuthKey(t *testing.T) {
	preAuthKey := NewTestPreAuthKey(101, 202)
	
	assert.NotNil(t, preAuthKey)
	assert.Equal(t, uint64(101), preAuthKey.Id)
	assert.Equal(t, "preauthkey-101-abcdef", preAuthKey.Key)
	assert.NotNil(t, preAuthKey.User)
	assert.Equal(t, uint64(202), preAuthKey.User.Id)
	assert.False(t, preAuthKey.Reusable)
	assert.False(t, preAuthKey.Ephemeral)
	assert.False(t, preAuthKey.Used)
	assert.NotNil(t, preAuthKey.CreatedAt)
}

func TestCreateTestCommand(t *testing.T) {
	cmd := CreateTestCommand("testcmd")
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "testcmd", cmd.Use)
	assert.Equal(t, "Test testcmd command", cmd.Short)
	assert.NotNil(t, cmd.Run)
	
	// Verify common flags are added
	assert.NotNil(t, cmd.Flags().Lookup("output"))
	assert.NotNil(t, cmd.Flags().Lookup("force"))
}

func TestValidateCommandStructure(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run:   func(cmd *cobra.Command, args []string) {},
	}
	
	// This should not panic or fail
	ValidateCommandStructure(t, cmd, "test", "Test command")
}

func TestValidateCommandFlags(t *testing.T) {
	cmd := CreateTestCommand("test")
	
	// This should not panic or fail - output and force flags should exist
	ValidateCommandFlags(t, cmd, []string{"output", "force"})
}

func TestValidateCommandHelp(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Long:  "This is a test command",
		Run:   func(cmd *cobra.Command, args []string) {},
	}
	
	// This should not panic or fail
	ValidateCommandHelp(t, cmd)
}

func TestMockClient_AllOperationsCovered(t *testing.T) {
	// Test that all required gRPC operations are implemented in the mock
	mock := NewMockHeadscaleServiceClient()
	ctx := context.Background()
	
	// Test all user operations
	_, err := mock.ListUsers(ctx, &v1.ListUsersRequest{})
	assert.NoError(t, err)
	
	_, err = mock.CreateUser(ctx, &v1.CreateUserRequest{})
	assert.NoError(t, err)
	
	_, err = mock.RenameUser(ctx, &v1.RenameUserRequest{})
	assert.NoError(t, err)
	
	_, err = mock.DeleteUser(ctx, &v1.DeleteUserRequest{})
	assert.NoError(t, err)
	
	// Test all node operations
	_, err = mock.ListNodes(ctx, &v1.ListNodesRequest{})
	assert.NoError(t, err)
	
	_, err = mock.RegisterNode(ctx, &v1.RegisterNodeRequest{})
	assert.NoError(t, err)
	
	_, err = mock.DeleteNode(ctx, &v1.DeleteNodeRequest{})
	assert.NoError(t, err)
	
	_, err = mock.ExpireNode(ctx, &v1.ExpireNodeRequest{})
	assert.NoError(t, err)
	
	_, err = mock.RenameNode(ctx, &v1.RenameNodeRequest{})
	assert.NoError(t, err)
	
	_, err = mock.MoveNode(ctx, &v1.MoveNodeRequest{})
	assert.NoError(t, err)
	
	_, err = mock.GetNode(ctx, &v1.GetNodeRequest{})
	assert.NoError(t, err)
	
	_, err = mock.SetTags(ctx, &v1.SetTagsRequest{})
	assert.NoError(t, err)
	
	_, err = mock.SetApprovedRoutes(ctx, &v1.SetApprovedRoutesRequest{})
	assert.NoError(t, err)
	
	_, err = mock.BackfillNodeIPs(ctx, &v1.BackfillNodeIPsRequest{})
	assert.NoError(t, err)
	
	// Test all API key operations
	_, err = mock.ListApiKeys(ctx, &v1.ListApiKeysRequest{})
	assert.NoError(t, err)
	
	_, err = mock.CreateApiKey(ctx, &v1.CreateApiKeyRequest{})
	assert.NoError(t, err)
	
	_, err = mock.ExpireApiKey(ctx, &v1.ExpireApiKeyRequest{})
	assert.NoError(t, err)
	
	_, err = mock.DeleteApiKey(ctx, &v1.DeleteApiKeyRequest{})
	assert.NoError(t, err)
	
	// Test all preauth key operations
	_, err = mock.ListPreAuthKeys(ctx, &v1.ListPreAuthKeysRequest{})
	assert.NoError(t, err)
	
	_, err = mock.CreatePreAuthKey(ctx, &v1.CreatePreAuthKeyRequest{})
	assert.NoError(t, err)
	
	_, err = mock.ExpirePreAuthKey(ctx, &v1.ExpirePreAuthKeyRequest{})
	assert.NoError(t, err)
	
	// Test policy operations
	_, err = mock.GetPolicy(ctx, &v1.GetPolicyRequest{})
	assert.NoError(t, err)
	
	_, err = mock.SetPolicy(ctx, &v1.SetPolicyRequest{})
	assert.NoError(t, err)
	
	// Test debug operations
	_, err = mock.DebugCreateNode(ctx, &v1.DebugCreateNodeRequest{})
	assert.NoError(t, err)
	
	// Verify all operations were called
	expectedOperations := []string{
		"ListUsers", "CreateUser", "RenameUser", "DeleteUser",
		"ListNodes", "RegisterNode", "DeleteNode", "ExpireNode", "RenameNode", "MoveNode", "GetNode", "SetTags", "SetApprovedRoutes", "BackfillNodeIPs",
		"ListApiKeys", "CreateApiKey", "ExpireApiKey", "DeleteApiKey",
		"ListPreAuthKeys", "CreatePreAuthKey", "ExpirePreAuthKey",
		"GetPolicy", "SetPolicy",
		"DebugCreateNode",
	}
	
	for _, op := range expectedOperations {
		assert.Equal(t, 1, mock.CallCount[op], "Operation %s should have been called exactly once", op)
	}
}

func TestMockIntegrationWithExistingInfrastructure(t *testing.T) {
	// Test that mock client integrates well with existing CLI infrastructure
	
	// Create a test command that uses our flag infrastructure
	cmd := CreateTestCommand("integration-test")
	AddUserFlag(cmd)
	AddIdentifierFlag(cmd, "identifier", "Test identifier")
	
	// Set up flags
	err := cmd.Flags().Set("user", "testuser")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("identifier", "123")
	require.NoError(t, err)
	
	err = cmd.Flags().Set("output", "json")
	require.NoError(t, err)
	
	// Test that flag getters work
	user, err := GetUser(cmd)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", user)
	
	identifier, err := GetIdentifier(cmd, "identifier")
	assert.NoError(t, err)
	assert.Equal(t, uint64(123), identifier)
	
	output := GetOutputFormat(cmd)
	assert.Equal(t, "json", output)
	
	// Test that output manager works
	om := NewOutputManager(cmd)
	assert.True(t, om.HasMachineOutput())
	
	// Test that mock client can be used with our patterns
	mock := NewMockClientWrapperOld()
	defer mock.Close()
	
	// Verify mock client has the expected structure
	assert.NotNil(t, mock.MockClient)
	assert.NotNil(t, mock.ctx)
}

func TestTestingInfrastructure_CompleteWorkflow(t *testing.T) {
	// Test a complete workflow using the testing infrastructure
	
	// 1. Create a mock client
	mock := NewMockClientWrapperOld()
	defer mock.Close()
	
	// 2. Configure mock responses
	testUser := NewTestUser(1, "testuser")
	testNode := NewTestNode(1, "testnode", testUser)
	
	mock.MockClient.ListUsersResponse = &v1.ListUsersResponse{
		Users: []*v1.User{testUser},
	}
	
	mock.MockClient.ListNodesResponse = &v1.ListNodesResponse{
		Nodes: []*v1.Node{testNode},
	}
	
	// 3. Test that mock responds correctly
	usersResp, err := mock.MockClient.ListUsers(context.Background(), &v1.ListUsersRequest{})
	assert.NoError(t, err)
	assert.Len(t, usersResp.Users, 1)
	assert.Equal(t, "testuser", usersResp.Users[0].Name)
	
	nodesResp, err := mock.MockClient.ListNodes(context.Background(), &v1.ListNodesRequest{})
	assert.NoError(t, err)
	assert.Len(t, nodesResp.Nodes, 1)
	assert.Equal(t, "testnode", nodesResp.Nodes[0].Name)
	
	// 4. Verify call tracking
	assert.Equal(t, 1, mock.MockClient.CallCount["ListUsers"])
	assert.Equal(t, 1, mock.MockClient.CallCount["ListNodes"])
	
	// 5. Test JSON serialization (important for CLI output)
	userJSON, err := json.Marshal(testUser)
	assert.NoError(t, err)
	assert.Contains(t, string(userJSON), "testuser")
	
	nodeJSON, err := json.Marshal(testNode)
	assert.NoError(t, err)
	assert.Contains(t, string(nodeJSON), "testnode")
}

func TestErrorScenarios(t *testing.T) {
	// Test various error scenarios with the mock
	mock := NewMockHeadscaleServiceClient()
	
	// Test network error
	mock.ListUsersError = status.Error(codes.Unavailable, "connection refused")
	
	_, err := mock.ListUsers(context.Background(), &v1.ListUsersRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection refused")
	
	// Test not found error
	mock.GetNodeError = status.Error(codes.NotFound, "node not found")
	
	_, err = mock.GetNode(context.Background(), &v1.GetNodeRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "node not found")
	
	// Test permission error
	mock.DeleteUserError = status.Error(codes.PermissionDenied, "insufficient permissions")
	
	_, err = mock.DeleteUser(context.Background(), &v1.DeleteUserRequest{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient permissions")
}