package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// MockHeadscaleServiceClient provides a mock implementation of the HeadscaleServiceClient
// for testing CLI commands without requiring a real server
type MockHeadscaleServiceClient struct {
	// Configurable responses for all gRPC methods
	ListUsersResponse         *v1.ListUsersResponse
	CreateUserResponse        *v1.CreateUserResponse
	RenameUserResponse        *v1.RenameUserResponse
	DeleteUserResponse        *v1.DeleteUserResponse
	ListNodesResponse         *v1.ListNodesResponse
	RegisterNodeResponse      *v1.RegisterNodeResponse
	DeleteNodeResponse        *v1.DeleteNodeResponse
	ExpireNodeResponse        *v1.ExpireNodeResponse
	RenameNodeResponse        *v1.RenameNodeResponse
	MoveNodeResponse          *v1.MoveNodeResponse
	GetNodeResponse           *v1.GetNodeResponse
	SetTagsResponse           *v1.SetTagsResponse
	SetApprovedRoutesResponse *v1.SetApprovedRoutesResponse
	BackfillNodeIPsResponse   *v1.BackfillNodeIPsResponse
	ListApiKeysResponse       *v1.ListApiKeysResponse
	CreateApiKeyResponse      *v1.CreateApiKeyResponse
	ExpireApiKeyResponse      *v1.ExpireApiKeyResponse
	DeleteApiKeyResponse      *v1.DeleteApiKeyResponse
	ListPreAuthKeysResponse   *v1.ListPreAuthKeysResponse
	CreatePreAuthKeyResponse  *v1.CreatePreAuthKeyResponse
	ExpirePreAuthKeyResponse  *v1.ExpirePreAuthKeyResponse
	GetPolicyResponse         *v1.GetPolicyResponse
	SetPolicyResponse         *v1.SetPolicyResponse
	DebugCreateNodeResponse   *v1.DebugCreateNodeResponse

	// Error responses for testing error conditions
	ListUsersError         error
	CreateUserError        error
	RenameUserError        error
	DeleteUserError        error
	ListNodesError         error
	RegisterNodeError      error
	DeleteNodeError        error
	ExpireNodeError        error
	RenameNodeError        error
	MoveNodeError          error
	GetNodeError           error
	SetTagsError           error
	SetApprovedRoutesError error
	BackfillNodeIPsError   error
	ListApiKeysError       error
	CreateApiKeyError      error
	ExpireApiKeyError      error
	DeleteApiKeyError      error
	ListPreAuthKeysError   error
	CreatePreAuthKeyError  error
	ExpirePreAuthKeyError  error
	GetPolicyError         error
	SetPolicyError         error
	DebugCreateNodeError   error

	// Call tracking
	LastRequest interface{}
	CallCount   map[string]int
}

// NewMockHeadscaleServiceClient creates a new mock client with default responses
func NewMockHeadscaleServiceClient() *MockHeadscaleServiceClient {
	return &MockHeadscaleServiceClient{
		CallCount: make(map[string]int),
		
		// Default successful responses
		ListUsersResponse:         &v1.ListUsersResponse{Users: []*v1.User{NewTestUser(1, "testuser"), NewTestUser(2, "olduser")}},
		CreateUserResponse:        &v1.CreateUserResponse{User: NewTestUser(1, "testuser")},
		RenameUserResponse:        &v1.RenameUserResponse{User: NewTestUser(1, "renamed-user")},
		DeleteUserResponse:        &v1.DeleteUserResponse{},
		ListNodesResponse:         &v1.ListNodesResponse{Nodes: []*v1.Node{}},
		RegisterNodeResponse:      &v1.RegisterNodeResponse{Node: NewTestNode(1, "testnode", NewTestUser(1, "testuser"))},
		DeleteNodeResponse:        &v1.DeleteNodeResponse{},
		ExpireNodeResponse:        &v1.ExpireNodeResponse{Node: NewTestNode(1, "testnode", NewTestUser(1, "testuser"))},
		RenameNodeResponse:        &v1.RenameNodeResponse{Node: NewTestNode(1, "renamed-node", NewTestUser(1, "testuser"))},
		MoveNodeResponse:          &v1.MoveNodeResponse{Node: NewTestNode(1, "testnode", NewTestUser(2, "newuser"))},
		GetNodeResponse:           &v1.GetNodeResponse{Node: NewTestNode(1, "testnode", NewTestUser(1, "testuser"))},
		SetTagsResponse:           &v1.SetTagsResponse{Node: NewTestNode(1, "testnode", NewTestUser(1, "testuser"))},
		SetApprovedRoutesResponse: &v1.SetApprovedRoutesResponse{Node: NewTestNode(1, "testnode", NewTestUser(1, "testuser"))},
		BackfillNodeIPsResponse:   &v1.BackfillNodeIPsResponse{Changes: []string{"192.168.1.1"}},
		ListApiKeysResponse:       &v1.ListApiKeysResponse{ApiKeys: []*v1.ApiKey{}},
		CreateApiKeyResponse:      &v1.CreateApiKeyResponse{ApiKey: "testkey_abcdef123456"},
		ExpireApiKeyResponse:      &v1.ExpireApiKeyResponse{},
		DeleteApiKeyResponse:      &v1.DeleteApiKeyResponse{},
		ListPreAuthKeysResponse:   &v1.ListPreAuthKeysResponse{PreAuthKeys: []*v1.PreAuthKey{}},
		CreatePreAuthKeyResponse:  &v1.CreatePreAuthKeyResponse{PreAuthKey: NewTestPreAuthKey(1, 1)},
		ExpirePreAuthKeyResponse:  &v1.ExpirePreAuthKeyResponse{},
		GetPolicyResponse:         &v1.GetPolicyResponse{Policy: "{}"},
		SetPolicyResponse:         &v1.SetPolicyResponse{Policy: "{}"},
		DebugCreateNodeResponse:   &v1.DebugCreateNodeResponse{Node: NewTestNode(1, "debug-node", NewTestUser(1, "testuser"))},
	}
}

// NewMockClientWrapper creates a ClientWrapper with a mock client for testing
func NewMockClientWrapper() *ClientWrapper {
	mockClient := NewMockHeadscaleServiceClient()
	return &ClientWrapper{
		client: mockClient,
	}
}

// Implement all v1.HeadscaleServiceClient methods

func (m *MockHeadscaleServiceClient) ListUsers(ctx context.Context, req *v1.ListUsersRequest, opts ...grpc.CallOption) (*v1.ListUsersResponse, error) {
	m.CallCount["ListUsers"]++
	m.LastRequest = req
	if m.ListUsersError != nil {
		return nil, m.ListUsersError
	}
	return m.ListUsersResponse, nil
}

func (m *MockHeadscaleServiceClient) CreateUser(ctx context.Context, req *v1.CreateUserRequest, opts ...grpc.CallOption) (*v1.CreateUserResponse, error) {
	m.CallCount["CreateUser"]++
	m.LastRequest = req
	if m.CreateUserError != nil {
		return nil, m.CreateUserError
	}
	return m.CreateUserResponse, nil
}

func (m *MockHeadscaleServiceClient) RenameUser(ctx context.Context, req *v1.RenameUserRequest, opts ...grpc.CallOption) (*v1.RenameUserResponse, error) {
	m.CallCount["RenameUser"]++
	m.LastRequest = req
	if m.RenameUserError != nil {
		return nil, m.RenameUserError
	}
	return m.RenameUserResponse, nil
}

func (m *MockHeadscaleServiceClient) DeleteUser(ctx context.Context, req *v1.DeleteUserRequest, opts ...grpc.CallOption) (*v1.DeleteUserResponse, error) {
	m.CallCount["DeleteUser"]++
	m.LastRequest = req
	if m.DeleteUserError != nil {
		return nil, m.DeleteUserError
	}
	return m.DeleteUserResponse, nil
}

func (m *MockHeadscaleServiceClient) ListNodes(ctx context.Context, req *v1.ListNodesRequest, opts ...grpc.CallOption) (*v1.ListNodesResponse, error) {
	m.CallCount["ListNodes"]++
	m.LastRequest = req
	if m.ListNodesError != nil {
		return nil, m.ListNodesError
	}
	return m.ListNodesResponse, nil
}

func (m *MockHeadscaleServiceClient) RegisterNode(ctx context.Context, req *v1.RegisterNodeRequest, opts ...grpc.CallOption) (*v1.RegisterNodeResponse, error) {
	m.CallCount["RegisterNode"]++
	m.LastRequest = req
	if m.RegisterNodeError != nil {
		return nil, m.RegisterNodeError
	}
	return m.RegisterNodeResponse, nil
}

func (m *MockHeadscaleServiceClient) DeleteNode(ctx context.Context, req *v1.DeleteNodeRequest, opts ...grpc.CallOption) (*v1.DeleteNodeResponse, error) {
	m.CallCount["DeleteNode"]++
	m.LastRequest = req
	if m.DeleteNodeError != nil {
		return nil, m.DeleteNodeError
	}
	return m.DeleteNodeResponse, nil
}

func (m *MockHeadscaleServiceClient) ExpireNode(ctx context.Context, req *v1.ExpireNodeRequest, opts ...grpc.CallOption) (*v1.ExpireNodeResponse, error) {
	m.CallCount["ExpireNode"]++
	m.LastRequest = req
	if m.ExpireNodeError != nil {
		return nil, m.ExpireNodeError
	}
	return m.ExpireNodeResponse, nil
}

func (m *MockHeadscaleServiceClient) RenameNode(ctx context.Context, req *v1.RenameNodeRequest, opts ...grpc.CallOption) (*v1.RenameNodeResponse, error) {
	m.CallCount["RenameNode"]++
	m.LastRequest = req
	if m.RenameNodeError != nil {
		return nil, m.RenameNodeError
	}
	return m.RenameNodeResponse, nil
}

func (m *MockHeadscaleServiceClient) MoveNode(ctx context.Context, req *v1.MoveNodeRequest, opts ...grpc.CallOption) (*v1.MoveNodeResponse, error) {
	m.CallCount["MoveNode"]++
	m.LastRequest = req
	if m.MoveNodeError != nil {
		return nil, m.MoveNodeError
	}
	return m.MoveNodeResponse, nil
}

func (m *MockHeadscaleServiceClient) GetNode(ctx context.Context, req *v1.GetNodeRequest, opts ...grpc.CallOption) (*v1.GetNodeResponse, error) {
	m.CallCount["GetNode"]++
	m.LastRequest = req
	if m.GetNodeError != nil {
		return nil, m.GetNodeError
	}
	return m.GetNodeResponse, nil
}

func (m *MockHeadscaleServiceClient) SetTags(ctx context.Context, req *v1.SetTagsRequest, opts ...grpc.CallOption) (*v1.SetTagsResponse, error) {
	m.CallCount["SetTags"]++
	m.LastRequest = req
	if m.SetTagsError != nil {
		return nil, m.SetTagsError
	}
	return m.SetTagsResponse, nil
}

func (m *MockHeadscaleServiceClient) SetApprovedRoutes(ctx context.Context, req *v1.SetApprovedRoutesRequest, opts ...grpc.CallOption) (*v1.SetApprovedRoutesResponse, error) {
	m.CallCount["SetApprovedRoutes"]++
	m.LastRequest = req
	if m.SetApprovedRoutesError != nil {
		return nil, m.SetApprovedRoutesError
	}
	return m.SetApprovedRoutesResponse, nil
}

func (m *MockHeadscaleServiceClient) BackfillNodeIPs(ctx context.Context, req *v1.BackfillNodeIPsRequest, opts ...grpc.CallOption) (*v1.BackfillNodeIPsResponse, error) {
	m.CallCount["BackfillNodeIPs"]++
	m.LastRequest = req
	if m.BackfillNodeIPsError != nil {
		return nil, m.BackfillNodeIPsError
	}
	return m.BackfillNodeIPsResponse, nil
}

func (m *MockHeadscaleServiceClient) ListApiKeys(ctx context.Context, req *v1.ListApiKeysRequest, opts ...grpc.CallOption) (*v1.ListApiKeysResponse, error) {
	m.CallCount["ListApiKeys"]++
	m.LastRequest = req
	if m.ListApiKeysError != nil {
		return nil, m.ListApiKeysError
	}
	return m.ListApiKeysResponse, nil
}

func (m *MockHeadscaleServiceClient) CreateApiKey(ctx context.Context, req *v1.CreateApiKeyRequest, opts ...grpc.CallOption) (*v1.CreateApiKeyResponse, error) {
	m.CallCount["CreateApiKey"]++
	m.LastRequest = req
	if m.CreateApiKeyError != nil {
		return nil, m.CreateApiKeyError
	}
	return m.CreateApiKeyResponse, nil
}

func (m *MockHeadscaleServiceClient) ExpireApiKey(ctx context.Context, req *v1.ExpireApiKeyRequest, opts ...grpc.CallOption) (*v1.ExpireApiKeyResponse, error) {
	m.CallCount["ExpireApiKey"]++
	m.LastRequest = req
	if m.ExpireApiKeyError != nil {
		return nil, m.ExpireApiKeyError
	}
	return m.ExpireApiKeyResponse, nil
}

func (m *MockHeadscaleServiceClient) DeleteApiKey(ctx context.Context, req *v1.DeleteApiKeyRequest, opts ...grpc.CallOption) (*v1.DeleteApiKeyResponse, error) {
	m.CallCount["DeleteApiKey"]++
	m.LastRequest = req
	if m.DeleteApiKeyError != nil {
		return nil, m.DeleteApiKeyError
	}
	return m.DeleteApiKeyResponse, nil
}

func (m *MockHeadscaleServiceClient) ListPreAuthKeys(ctx context.Context, req *v1.ListPreAuthKeysRequest, opts ...grpc.CallOption) (*v1.ListPreAuthKeysResponse, error) {
	m.CallCount["ListPreAuthKeys"]++
	m.LastRequest = req
	if m.ListPreAuthKeysError != nil {
		return nil, m.ListPreAuthKeysError
	}
	return m.ListPreAuthKeysResponse, nil
}

func (m *MockHeadscaleServiceClient) CreatePreAuthKey(ctx context.Context, req *v1.CreatePreAuthKeyRequest, opts ...grpc.CallOption) (*v1.CreatePreAuthKeyResponse, error) {
	m.CallCount["CreatePreAuthKey"]++
	m.LastRequest = req
	if m.CreatePreAuthKeyError != nil {
		return nil, m.CreatePreAuthKeyError
	}
	return m.CreatePreAuthKeyResponse, nil
}

func (m *MockHeadscaleServiceClient) ExpirePreAuthKey(ctx context.Context, req *v1.ExpirePreAuthKeyRequest, opts ...grpc.CallOption) (*v1.ExpirePreAuthKeyResponse, error) {
	m.CallCount["ExpirePreAuthKey"]++
	m.LastRequest = req
	if m.ExpirePreAuthKeyError != nil {
		return nil, m.ExpirePreAuthKeyError
	}
	return m.ExpirePreAuthKeyResponse, nil
}

func (m *MockHeadscaleServiceClient) GetPolicy(ctx context.Context, req *v1.GetPolicyRequest, opts ...grpc.CallOption) (*v1.GetPolicyResponse, error) {
	m.CallCount["GetPolicy"]++
	m.LastRequest = req
	if m.GetPolicyError != nil {
		return nil, m.GetPolicyError
	}
	return m.GetPolicyResponse, nil
}

func (m *MockHeadscaleServiceClient) SetPolicy(ctx context.Context, req *v1.SetPolicyRequest, opts ...grpc.CallOption) (*v1.SetPolicyResponse, error) {
	m.CallCount["SetPolicy"]++
	m.LastRequest = req
	if m.SetPolicyError != nil {
		return nil, m.SetPolicyError
	}
	return m.SetPolicyResponse, nil
}

func (m *MockHeadscaleServiceClient) DebugCreateNode(ctx context.Context, req *v1.DebugCreateNodeRequest, opts ...grpc.CallOption) (*v1.DebugCreateNodeResponse, error) {
	m.CallCount["DebugCreateNode"]++
	m.LastRequest = req
	if m.DebugCreateNodeError != nil {
		return nil, m.DebugCreateNodeError
	}
	return m.DebugCreateNodeResponse, nil
}

// MockClientWrapper wraps MockHeadscaleServiceClient for testing
type MockClientWrapper struct {
	MockClient *MockHeadscaleServiceClient
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewMockClientWrapperOld creates a new mock client wrapper for testing (legacy)
func NewMockClientWrapperOld() *MockClientWrapper {
	ctx, cancel := context.WithCancel(context.Background())
	return &MockClientWrapper{
		MockClient: NewMockHeadscaleServiceClient(),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Close implements the ClientWrapper interface
func (m *MockClientWrapper) Close() {
	if m.cancel != nil {
		m.cancel()
	}
}

// CLI test execution helpers

// ExecuteCommand executes a command and captures its output
func ExecuteCommand(cmd *cobra.Command, args []string) (string, error) {
	return ExecuteCommandWithInput(cmd, args, "")
}

// ExecuteCommandWithInput executes a command with input and captures its output
func ExecuteCommandWithInput(cmd *cobra.Command, args []string, input string) (string, error) {
	// Create buffers for capturing output
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	oldStdin := os.Stdin
	
	// Create pipes for capturing output
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	
	// Set up input if provided
	if input != "" {
		tmpfile, err := os.CreateTemp("", "test-input")
		if err != nil {
			return "", err
		}
		defer os.Remove(tmpfile.Name())
		tmpfile.WriteString(input)
		tmpfile.Seek(0, 0)
		os.Stdin = tmpfile
	}
	
	// Capture output
	var buf bytes.Buffer
	done := make(chan bool)
	go func() {
		io.Copy(&buf, r)
		done <- true
	}()
	
	// Execute command
	cmd.SetArgs(args)
	err := cmd.Execute()
	
	// Restore original streams
	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	os.Stdin = oldStdin
	
	// Wait for output capture to complete
	<-done
	
	return buf.String(), err
}

// AssertCommandSuccess executes a command and asserts it succeeds
func AssertCommandSuccess(t interface{}, cmd *cobra.Command, args []string) {
	output, err := ExecuteCommand(cmd, args)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Command failed: %v\nOutput: %s", err, output)
	}
}

// AssertCommandError executes a command and asserts it fails with expected error
func AssertCommandError(t interface{}, cmd *cobra.Command, args []string, expectedError string) {
	output, err := ExecuteCommand(cmd, args)
	if err == nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Expected command to fail but it succeeded\nOutput: %s", output)
	}
	if !strings.Contains(err.Error(), expectedError) {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Expected error to contain '%s' but got: %v", expectedError, err)
	}
}

// Output format testing

// ValidateJSONOutput validates that output is valid JSON and matches expected structure
func ValidateJSONOutput(t interface{}, output string, expected interface{}) {
	var actual interface{}
	err := json.Unmarshal([]byte(output), &actual)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Invalid JSON output: %v\nOutput: %s", err, output)
	}
	
	// Convert expected to JSON and back for comparison
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Failed to marshal expected JSON: %v", err)
	}
	
	var expectedParsed interface{}
	err = json.Unmarshal(expectedJSON, &expectedParsed)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Failed to unmarshal expected JSON: %v", err)
	}
	
	// Compare structures (basic comparison)
	actualJSON, _ := json.Marshal(actual)
	if string(actualJSON) != string(expectedJSON) {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("JSON output mismatch.\nExpected: %s\nActual: %s", expectedJSON, actualJSON)
	}
}

// ValidateYAMLOutput validates that output is valid YAML and matches expected structure
func ValidateYAMLOutput(t interface{}, output string, expected interface{}) {
	var actual interface{}
	err := yaml.Unmarshal([]byte(output), &actual)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Invalid YAML output: %v\nOutput: %s", err, output)
	}
	
	// Convert expected to YAML for comparison
	expectedYAML, err := yaml.Marshal(expected)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Failed to marshal expected YAML: %v", err)
	}
	
	actualYAML, err := yaml.Marshal(actual)
	if err != nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Failed to marshal actual YAML: %v", err)
	}
	
	if string(actualYAML) != string(expectedYAML) {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("YAML output mismatch.\nExpected: %s\nActual: %s", expectedYAML, actualYAML)
	}
}

// ValidateTableOutput validates that output contains expected table headers
func ValidateTableOutput(t interface{}, output string, expectedHeaders []string) {
	for _, header := range expectedHeaders {
		if !strings.Contains(output, header) {
			t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Table output missing expected header '%s'\nOutput: %s", header, output)
		}
	}
}

// Test fixtures and data helpers

// NewTestUser creates a test user with the given ID and name
func NewTestUser(id uint64, name string) *v1.User {
	return &v1.User{
		Id:        id,
		Name:      name,
		Email:     fmt.Sprintf("%s@example.com", name),
		CreatedAt: timestamppb.Now(),
	}
}

// NewTestNode creates a test node with the given ID, name, and user
func NewTestNode(id uint64, name string, user *v1.User) *v1.Node {
	return &v1.Node{
		Id:          id,
		Name:        name,
		GivenName:   fmt.Sprintf("%s-device", name),
		User:        user,
		IpAddresses: []string{fmt.Sprintf("192.168.1.%d", id)},
		Online:      true,
		ValidTags:   []string{},
		CreatedAt:   timestamppb.Now(),
		LastSeen:    timestamppb.Now(),
	}
}

// NewTestApiKey creates a test API key with the given ID and prefix
func NewTestApiKey(id uint64, prefix string) *v1.ApiKey {
	return &v1.ApiKey{
		Id:        id,
		Prefix:    prefix,
		CreatedAt: timestamppb.Now(),
	}
}

// NewTestPreAuthKey creates a test preauth key with the given ID and user ID
func NewTestPreAuthKey(id uint64, userID uint64) *v1.PreAuthKey {
	return &v1.PreAuthKey{
		Id:        id,
		Key:       fmt.Sprintf("preauthkey-%d-abcdef", id),
		User:      NewTestUser(userID, fmt.Sprintf("user%d", userID)),
		Reusable:  false,
		Ephemeral: false,
		Used:      false,
		CreatedAt: timestamppb.Now(),
	}
}

// CreateTestCommand creates a basic test command with common flags
func CreateTestCommand(name string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   name,
		Short: fmt.Sprintf("Test %s command", name),
		Run: func(cmd *cobra.Command, args []string) {
			// Default test implementation
		},
	}
	
	// Add common flags
	AddOutputFlag(cmd)
	AddForceFlag(cmd)
	
	return cmd
}

// Test utilities for command validation

// ValidateCommandStructure validates that a command has required properties
func ValidateCommandStructure(t interface{}, cmd *cobra.Command, expectedUse string, expectedShort string) {
	if cmd.Use != expectedUse {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Expected Use '%s', got '%s'", expectedUse, cmd.Use)
	}
	
	if cmd.Short != expectedShort {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Expected Short '%s', got '%s'", expectedShort, cmd.Short)
	}
	
	if cmd.Run == nil && cmd.RunE == nil {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Command must have a Run or RunE function")
	}
}

// ValidateCommandFlags validates that a command has expected flags
func ValidateCommandFlags(t interface{}, cmd *cobra.Command, expectedFlags []string) {
	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Expected flag '%s' not found", flagName)
		}
	}
}

// Helper to check if command has proper help text
func ValidateCommandHelp(t interface{}, cmd *cobra.Command) {
	if cmd.Short == "" {
		t.(interface{ Fatalf(string, ...interface{}) }).Fatalf("Command must have Short description")
	}
	
	if cmd.Long == "" {
		// Long description is optional but recommended
	}
	
	if cmd.Example == "" {
		// Examples are optional but recommended for better UX
	}
}