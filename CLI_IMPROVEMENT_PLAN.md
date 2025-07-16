# Headscale CLI Improvement Plan

## Overview
This document outlines a comprehensive plan to refactor and improve the Headscale CLI by implementing DRY principles, standardizing patterns, and streamlining the codebase.

## Phase 1: DRY Infrastructure & Common Patterns

### Objective
Eliminate code duplication by creating reusable infrastructure for common CLI patterns found across all commands.

### Current Duplication Analysis

#### 1. Flag Parsing Patterns (Found in every command)
```go
// Repeated in nodes.go, users.go, api_key.go, preauthkeys.go, policy.go
output, _ := cmd.Flags().GetString("output")
identifier, err := cmd.Flags().GetUint64("identifier")
if err != nil {
    ErrorOutput(err, fmt.Sprintf("Error converting ID to integer: %s", err), output)
    return
}
```

#### 2. gRPC Client Setup (Found in every command)
```go
// Repeated ~30+ times across all command files
ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
defer cancel()
defer conn.Close()
```

#### 3. Error Handling Patterns (Found in every command)
```go
// Repeated error handling pattern
if err != nil {
    ErrorOutput(err, fmt.Sprintf("Cannot do operation: %s", status.Convert(err).Message()), output)
    return
}
```

#### 4. Success Output Patterns (Found in every command)
```go
// Repeated success output pattern
SuccessOutput(response.GetSomething(), "Operation successful", output)
```

#### 5. Flag Registration Patterns
```go
// Repeated flag setup in init() functions
cmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
err := cmd.MarkFlagRequired("identifier")
if err != nil {
    log.Fatal(err.Error())
}
```

#### 6. User/Namespace Flag Handling (Found in nodes.go, users.go, preauthkeys.go)
```go
// Deprecated namespace flag handling pattern repeated 3+ times
cmd.Flags().StringP("namespace", "n", "", "User")
namespaceFlag := cmd.Flags().Lookup("namespace")
namespaceFlag.Deprecated = deprecateNamespaceMessage
namespaceFlag.Hidden = true
```

### Phase 1 Implementation Plan

#### Checkpoint 0: Create CLI Unit Testing Infrastructure
**File**: `cmd/headscale/cli/testing.go`, `cmd/headscale/cli/testing_test.go`

**Tasks**:
- [ ] Create mock gRPC client infrastructure for CLI testing
- [ ] Create CLI test execution framework
- [ ] Create output format validation helpers
- [ ] Create test fixtures and data helpers
- [ ] Create test utilities for command validation

**Functions to implement**:
```go
// Mock gRPC client for testing
type MockHeadscaleServiceClient struct {
    // Configurable responses for all gRPC methods
    ListUsersResponse *v1.ListUsersResponse
    CreateUserResponse *v1.CreateUserResponse
    // ... etc for all methods
    
    // Call tracking
    LastRequest interface{}
    CallCount map[string]int
}

// CLI test execution helpers
func ExecuteCommand(cmd *cobra.Command, args []string) (string, error)
func ExecuteCommandWithInput(cmd *cobra.Command, args []string, input string) (string, error)
func AssertCommandSuccess(t *testing.T, cmd *cobra.Command, args []string)
func AssertCommandError(t *testing.T, cmd *cobra.Command, args []string, expectedError string)

// Output format testing
func ValidateJSONOutput(t *testing.T, output string, expected interface{})
func ValidateYAMLOutput(t *testing.T, output string, expected interface{})
func ValidateTableOutput(t *testing.T, output string, expectedHeaders []string)

// Test fixtures
func NewTestUser(id uint64, name string) *v1.User
func NewTestNode(id uint64, name string, user *v1.User) *v1.Node
func NewTestPreAuthKey(id uint64, user uint64) *v1.PreAuthKey
```

**Success Criteria**:
- Mock client can simulate all gRPC operations
- Commands can be tested in isolation without real server
- Output format validation works for JSON, YAML, and tables
- Test fixtures cover all CLI data types

#### Checkpoint 1: Create Common Flag Infrastructure
**File**: `cmd/headscale/cli/flags.go`

**Tasks**:
- [ ] Create standardized flag registration functions
- [ ] Create standardized flag getter functions with error handling
- [ ] Create flag validation helpers
- [ ] Create deprecated flag handling utilities

**Functions to implement**:
```go
// Flag registration helpers
func AddIdentifierFlag(cmd *cobra.Command, name string, help string)
func AddUserFlag(cmd *cobra.Command) 
func AddOutputFlag(cmd *cobra.Command)
func AddForceFlag(cmd *cobra.Command)
func AddExpirationFlag(cmd *cobra.Command, defaultValue string)
func AddDeprecatedNamespaceFlag(cmd *cobra.Command)

// Flag getter helpers with error handling
func GetIdentifier(cmd *cobra.Command) (uint64, error)
func GetUser(cmd *cobra.Command) (string, error) 
func GetUserID(cmd *cobra.Command) (uint64, error)
func GetOutputFormat(cmd *cobra.Command) string
func GetForce(cmd *cobra.Command) bool
func GetExpiration(cmd *cobra.Command) (time.Duration, error)

// Validation helpers
func ValidateRequiredFlags(cmd *cobra.Command, flags ...string) error
func ValidateExclusiveFlags(cmd *cobra.Command, flags ...string) error
```

**Success Criteria**:
- All flag registration patterns are centralized
- All flag parsing includes consistent error handling
- Flag validation is reusable across commands

#### Checkpoint 2: Create gRPC Client Infrastructure
**File**: `cmd/headscale/cli/client.go`

**Tasks**:
- [ ] Create client wrapper that handles connection lifecycle
- [ ] Create standardized error handling for gRPC operations
- [ ] Create typed client operation helpers
- [ ] Create request/response logging utilities

**Functions to implement**:
```go
// Client wrapper
type ClientWrapper struct {
    ctx    context.Context
    client v1.HeadscaleServiceClient
    conn   *grpc.ClientConn
    cancel context.CancelFunc
}

func NewClient() (*ClientWrapper, error)
func (c *ClientWrapper) Close()

// Operation helpers with automatic error handling
func (c *ClientWrapper) ExecuteWithErrorHandling(
    operation func(client v1.HeadscaleServiceClient) (interface{}, error),
    errorMsg string,
    output string,
) interface{}

// Specific operation helpers
func (c *ClientWrapper) ListNodes(req *v1.ListNodesRequest, output string) *v1.ListNodesResponse
func (c *ClientWrapper) ListUsers(req *v1.ListUsersRequest, output string) *v1.ListUsersResponse
func (c *ClientWrapper) CreateUser(req *v1.CreateUserRequest, output string) *v1.CreateUserResponse
// ... etc for all operations
```

**Success Criteria**:
- gRPC client setup is done once per command execution
- Error handling is consistent across all operations
- Connection lifecycle is managed automatically

#### Checkpoint 3: Create Output Infrastructure
**File**: `cmd/headscale/cli/output.go`

**Tasks**:
- [ ] Create standardized table formatting utilities
- [ ] Create reusable column formatters
- [ ] Create consistent success/error output helpers
- [ ] Create output format validation

**Functions to implement**:
```go
// Table utilities
func RenderTable(headers []string, rows [][]string) error
func CreateTableData(headers []string) pterm.TableData

// Column formatters
func FormatTimeColumn(t *timestamppb.Timestamp) string
func FormatBoolColumn(b bool) string
func FormatIDColumn(id uint64) string
func FormatUserColumn(user *v1.User, highlight bool) string
func FormatStatusColumn(online bool) string

// Output helpers
func Success(result interface{}, message string, output string)
func Error(err error, message string, output string)
func ValidateOutputFormat(format string) error

// Specific table formatters
func NodesTable(nodes []*v1.Node, showTags bool, currentUser string) (pterm.TableData, error)
func UsersTable(users []*v1.User) (pterm.TableData, error)
func ApiKeysTable(keys []*v1.ApiKey) (pterm.TableData, error)
func PreAuthKeysTable(keys []*v1.PreAuthKey) (pterm.TableData, error)
```

**Success Criteria**:
- Table formatting is consistent across all commands
- Output format handling is centralized
- Column formatting is reusable

#### Checkpoint 4: Create Common Command Patterns
**File**: `cmd/headscale/cli/patterns.go`

**Tasks**:
- [ ] Create standard command execution patterns
- [ ] Create confirmation prompt utilities
- [ ] Create resource identification helpers
- [ ] Create bulk operation patterns

**Functions to implement**:
```go
// Command execution patterns
func ExecuteListCommand(cmd *cobra.Command, args []string, 
    listFunc func(*ClientWrapper, string) (interface{}, error),
    tableFunc func(interface{}) (pterm.TableData, error))

func ExecuteCreateCommand(cmd *cobra.Command, args []string,
    createFunc func(*ClientWrapper, *cobra.Command, []string, string) (interface{}, error))

func ExecuteDeleteCommand(cmd *cobra.Command, args []string,
    getFunc func(*ClientWrapper, uint64, string) (interface{}, error),
    deleteFunc func(*ClientWrapper, uint64, string) (interface{}, error),
    confirmationMessage func(interface{}) string)

// Confirmation utilities
func ConfirmAction(message string, force bool) (bool, error)
func ConfirmDeletion(resourceName string, force bool) (bool, error)

// Resource identification
func ResolveUserByNameOrID(client *ClientWrapper, nameOrID string, output string) (*v1.User, error)
func ResolveNodeByID(client *ClientWrapper, id uint64, output string) (*v1.Node, error)

// Bulk operations
func ProcessMultipleResources[T any](
    items []T,
    processor func(T) error,
    continueOnError bool,
) []error
```

**Success Criteria**:
- Common command patterns are reusable
- Confirmation logic is consistent
- Resource resolution is standardized

#### Checkpoint 5: Create Validation Infrastructure
**File**: `cmd/headscale/cli/validation.go`

**Tasks**:
- [ ] Create input validation utilities
- [ ] Create URL/email validation helpers
- [ ] Create duration parsing utilities
- [ ] Create business logic validation

**Functions to implement**:
```go
// Input validation
func ValidateEmail(email string) error
func ValidateURL(url string) error
func ValidateDuration(duration string) (time.Duration, error)
func ValidateUserName(name string) error
func ValidateNodeName(name string) error

// Business logic validation
func ValidateTagsFormat(tags []string) error
func ValidateRoutesFormat(routes []string) error
func ValidateAPIKeyPrefix(prefix string) error

// Pre-flight validation
func ValidateUserExists(client *ClientWrapper, userID uint64, output string) error
func ValidateNodeExists(client *ClientWrapper, nodeID uint64, output string) error
```

**Success Criteria**:
- Input validation is consistent across commands
- Validation errors provide helpful feedback
- Business logic validation is centralized

#### Checkpoint 6: Create Unit Tests for Missing Commands
**Files**: Create test files for all commands lacking unit tests

**Tasks**:
- [ ] **Create `version_test.go`**: Test version command output and flags
- [ ] **Create `generate_test.go`**: Test private key generation and validation
- [ ] **Create `configtest_test.go`**: Test configuration validation logic
- [ ] **Create `debug_test.go`**: Test debug command utilities and node creation
- [ ] **Create `serve_test.go`**: Test server startup parameter validation
- [ ] **Create `mockoidc_test.go`**: Test OIDC testing utility functionality
- [ ] **Create `utils_test.go`**: Test all utility functions in utils.go
- [ ] **Create `pterm_style_test.go`**: Test formatting and color functions

**Test Coverage Requirements**:
```go
// Example test structure for each command
func TestVersionCommand(t *testing.T) {
    tests := []struct {
        name     string
        args     []string
        want     string
        wantErr  bool
    }{
        {"default output", []string{}, "headscale version", false},
        {"json output", []string{"--output", "json"}, "", false},
        {"yaml output", []string{"--output", "yaml"}, "", false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

**Success Criteria**:
- All CLI commands have unit test coverage
- Edge cases and error conditions are tested
- Output format validation for all commands
- Flag parsing and validation thoroughly tested

#### Checkpoint 7: Refactor Existing Commands
**Files**: `nodes.go`, `users.go`, `api_key.go`, `preauthkeys.go`, `policy.go`

**Tasks for each file**:
- [ ] Replace flag parsing with common helpers
- [ ] Replace gRPC client setup with ClientWrapper
- [ ] Replace error handling with common patterns
- [ ] Replace table formatting with common utilities
- [ ] Replace validation with common validators

**Example refactoring for `listNodesCmd`**:

**Before** (current):
```go
var listNodesCmd = &cobra.Command{
    Use: "list",
    Run: func(cmd *cobra.Command, args []string) {
        output, _ := cmd.Flags().GetString("output")
        user, err := cmd.Flags().GetString("user")
        if err != nil {
            ErrorOutput(err, fmt.Sprintf("Error getting user: %s", err), output)
        }
        showTags, err := cmd.Flags().GetBool("tags")
        if err != nil {
            ErrorOutput(err, fmt.Sprintf("Error getting tags flag: %s", err), output)
        }

        ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
        defer cancel()
        defer conn.Close()

        request := &v1.ListNodesRequest{User: user}
        response, err := client.ListNodes(ctx, request)
        if err != nil {
            ErrorOutput(err, "Cannot get nodes: "+status.Convert(err).Message(), output)
        }

        if output != "" {
            SuccessOutput(response.GetNodes(), "", output)
        }

        tableData, err := nodesToPtables(user, showTags, response.GetNodes())
        if err != nil {
            ErrorOutput(err, fmt.Sprintf("Error converting to table: %s", err), output)
        }

        err = pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
        if err != nil {
            ErrorOutput(err, fmt.Sprintf("Failed to render pterm table: %s", err), output)
        }
    },
}
```

**After** (refactored):
```go
var listNodesCmd = &cobra.Command{
    Use: "list",
    Run: func(cmd *cobra.Command, args []string) {
        ExecuteListCommand(cmd, args, 
            func(client *ClientWrapper, output string) (interface{}, error) {
                user, _ := GetUser(cmd)
                showTags, _ := cmd.Flags().GetBool("tags")
                return client.ListNodes(&v1.ListNodesRequest{User: user}, output)
            },
            func(result interface{}) (pterm.TableData, error) {
                response := result.(*v1.ListNodesResponse)
                user, _ := GetUser(cmd)
                showTags, _ := cmd.Flags().GetBool("tags")
                return NodesTable(response.GetNodes(), showTags, user)
            })
    },
}
```

**Success Criteria**:
- All commands use common infrastructure
- Code duplication is eliminated
- Commands are more concise and readable

### Phase 1 Completion Criteria

#### Quantitative Goals
- [ ] Reduce CLI codebase by 40-50% through DRY principles
- [ ] Eliminate 100+ instances of duplicate flag parsing
- [ ] Eliminate 30+ instances of duplicate gRPC client setup
- [ ] Centralize all error handling patterns
- [ ] Centralize all table formatting logic

#### Qualitative Goals
- [ ] All commands follow consistent patterns
- [ ] New commands can be implemented faster using common infrastructure
- [ ] Error messages are consistent across all commands
- [ ] Code is more maintainable and testable

#### Testing Requirements

**Current CLI Testing Gaps Identified:**
The CLI currently has **ZERO unit tests** - only integration tests exist. Major gaps include:
- No unit tests for any CLI command structure or flag parsing
- No tests for utility functions in `utils.go`, `pterm_style.go`
- Missing tests for commands: `version`, `generate`, `configtest`, `debug`, `mockoidc`, `serve`
- No mock gRPC client infrastructure for CLI testing
- No systematic testing of output formats (JSON, YAML, human-readable)

**New Unit Testing Infrastructure (Must be created)**
- [ ] **CLI Test Framework** (`cli/testing.go`): Mock gRPC client, command execution helpers
- [ ] **Flag Testing Utilities**: Systematic flag parsing validation framework
- [ ] **Output Testing Helpers**: JSON/YAML/human-readable format validation
- [ ] **Mock Client Infrastructure**: Test doubles for all gRPC operations

**Unit Testing (After Each Checkpoint)**
- [ ] **Flag Infrastructure Tests**: Test all flag parsing helpers with edge cases
- [ ] **Client Wrapper Tests**: Test client wrapper error handling and connection management
- [ ] **Output Formatting Tests**: Test all output formatters for consistency
- [ ] **Validation Helper Tests**: Test all validation functions with edge cases
- [ ] **Utility Function Tests**: Test `HasMachineOutputFlag`, `ColourTime`, auth helpers
- [ ] **Command Structure Tests**: Test command initialization and flag setup
- [ ] **Error Handling Tests**: Test error output formatting and exit codes

**Missing Command Coverage (Must be implemented)**
- [ ] **Version Command Tests**: Test version output formatting and flags
- [ ] **Generate Command Tests**: Test private key generation and output
- [ ] **ConfigTest Command Tests**: Test configuration validation logic
- [ ] **Debug Command Tests**: Test debug utilities and node creation
- [ ] **Serve Command Tests**: Test server startup parameter validation
- [ ] **MockOIDC Command Tests**: Test OIDC testing utility functionality

**Integration Testing (After Phase 1 Completion)**
All CLI integration tests are defined in `integration/cli_test.go`. These tests validate CLI functionality end-to-end:

**Test Execution Commands:**
```bash
# Run specific CLI tests individually 
go run ./cmd/hi run "TestUserCommand"
go run ./cmd/hi run "TestPreAuthKeyCommand"
go run ./cmd/hi run "TestApiKeyCommand"
go run ./cmd/hi run "TestNodeCommand"
go run ./cmd/hi run "TestNodeTagCommand"
go run ./cmd/hi run "TestNodeExpireCommand"
go run ./cmd/hi run "TestNodeRenameCommand"
go run ./cmd/hi run "TestNodeMoveCommand"
go run ./cmd/hi run "TestPolicyCommand"

# Run all CLI tests together
go run ./cmd/hi run "Test*Command"

# Run with PostgreSQL backend for database-heavy operations
go run ./cmd/hi run "TestUserCommand" --postgres
```

**Critical CLI Tests to Validate:**
- **TestUserCommand**: Tests user creation, listing, renaming, deletion with both ID and name parameters
- **TestPreAuthKeyCommand**: Tests preauth key creation, listing, expiration with various flags
- **TestApiKeyCommand**: Tests API key lifecycle, expiration, deletion operations
- **TestNodeCommand**: Tests node registration, listing, deletion, filtering by user
- **TestNodeTagCommand**: Tests node tagging operations and ACL validation
- **TestNodeExpireCommand**: Tests node expiration functionality
- **TestNodeRenameCommand**: Tests node renaming with validation
- **TestNodeMoveCommand**: Tests moving nodes between users
- **TestPolicyCommand**: Tests policy get/set operations

**Test Artifacts & Debugging:**
- Test logs saved to `control_logs/TIMESTAMP-ID/` directory
- Includes Headscale server logs, client logs, database dumps
- Integration tests use real Docker containers with Tailscale clients
- Each test validates JSON output format and CLI return codes

**Testing Methodology After Each Checkpoint:**
1. **Checkpoint Completion**: Run unit tests for new infrastructure
2. **Refactor Commands**: Run relevant CLI integration tests
3. **Phase 1 Completion**: Run full CLI test suite
4. **Regression Testing**: Compare test results before/after refactoring

**Success Criteria for Testing:**
- [ ] All existing integration tests pass without modification
- [ ] JSON output format remains identical
- [ ] CLI exit codes and error messages unchanged
- [ ] Performance within 10% of original (measured via test execution time)
- [ ] No new test infrastructure required for basic CLI operations

### Implementation Order

**Updated timeline to include comprehensive unit testing:**

1. **Week 1**: Checkpoint 0-1 (Testing infrastructure and Flags)
   - Day 1-2: Create CLI unit testing infrastructure (Checkpoint 0)
   - Day 3-4: Implement flag helpers infrastructure (Checkpoint 1)
   - Day 5: Unit tests for flag infrastructure

2. **Week 2**: Checkpoints 2-3 (Client and Output infrastructure) 
   - Day 1-2: Implement gRPC client wrapper (Checkpoint 2)
   - Day 3-4: Implement output utilities and patterns (Checkpoint 3)
   - Day 5: Unit tests and validate with `TestUserCommand`, `TestNodeCommand`

3. **Week 3**: Checkpoints 4-5 (Patterns and Validation infrastructure)
   - Day 1-2: Implement command patterns infrastructure (Checkpoint 4)
   - Day 3-4: Implement validation helpers (Checkpoint 5)
   - Day 5: Unit tests and validate with `TestApiKeyCommand`, `TestPreAuthKeyCommand`

4. **Week 4**: Checkpoint 6 (Unit tests for missing commands)
   - Day 1-3: Create unit tests for all untested commands (version, generate, etc.)
   - Day 4-5: Validate with `TestNodeTagCommand`, `TestPolicyCommand`

5. **Week 5**: Checkpoint 7 (Refactor existing commands)
   - Day 1-4: Apply new infrastructure to all existing commands
   - Day 5: Run full CLI integration test suite

6. **Week 6**: Final testing, documentation, and refinement
   - Day 1-2: Performance testing and optimization
   - Day 3-4: Documentation updates and code cleanup
   - Day 5: Final integration test validation and regression testing

### Testing Commands Summary

**Unit Tests (run after each checkpoint):**
```bash
# Run all CLI unit tests
go test ./cmd/headscale/cli/... -v

# Run specific test files  
go test ./cmd/headscale/cli/flags_test.go -v
go test ./cmd/headscale/cli/client_test.go -v
go test ./cmd/headscale/cli/utils_test.go -v

# Run with coverage
go test ./cmd/headscale/cli/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

**Integration Tests (run after major checkpoints):**
```bash
# Test specific CLI functionality
go run ./cmd/hi run "TestUserCommand"
go run ./cmd/hi run "TestNodeCommand"
go run ./cmd/hi run "TestApiKeyCommand"

# Full CLI integration test suite
go run ./cmd/hi run "Test*Command"

# With PostgreSQL backend
go run ./cmd/hi run "Test*Command" --postgres
```

**Complete Validation (end of Phase 1):**
```bash
# All unit tests
make test
go test ./cmd/headscale/cli/... -race -v

# All integration tests
go run ./cmd/hi run "Test*Command"

# Performance baseline comparison
time go run ./cmd/hi run "TestUserCommand"
```

### Dependencies & Risks
- **Risk**: Breaking existing functionality during refactoring
  - **Mitigation**: Comprehensive testing at each checkpoint
- **Risk**: Performance impact from additional abstractions
  - **Mitigation**: Benchmark testing and optimization
- **Risk**: CLI currently has zero unit tests, making refactoring risky
  - **Mitigation**: Create unit test infrastructure first (Checkpoint 0)
- **Dependency**: Understanding of all current CLI usage patterns
  - **Mitigation**: Thorough analysis before implementation

## Phase 2: Intelligent Flag System Redesign

### Objective
Replace the current confusing and inconsistent flag system with intelligent, reusable identifier resolution that works consistently across all commands.

### Current Flag Problems Analysis

#### Inconsistent Identifier Flags
**Current problematic patterns:**
```bash
# Node identification - 4 different ways!
headscale nodes delete --identifier 5     # nodes use --identifier/-i
headscale nodes tag -i 5 -t tag:test      # nodes use -i short form
headscale debug create-node --id 5         # debug uses --id

# User identification - 3 different ways!
headscale users destroy --identifier 5     # users use --identifier  
headscale users list --name username       # users use --name
headscale preauthkeys --user 5 create      # preauthkeys use --user

# API keys use completely different pattern
headscale apikeys expire --prefix abc123   # API keys use --prefix
```

#### Problems with Current Approach
1. **Cognitive Load**: Users must remember different flags for similar operations
2. **Inconsistent Behavior**: Same flag name (`-i`) means different things in different contexts
3. **Poor UX**: Users often know hostname but not node ID, or username but not user ID
4. **Flag Definition Scattered**: Flags defined far from command logic (in `init()` functions)
5. **No Intelligent Lookup**: Users forced to know exact internal IDs

### Phase 2 Implementation Plan

#### Checkpoint 1: Design Intelligent Identifier System
**File**: `cmd/headscale/cli/identifiers.go`

**New Unified Flag System:**
```bash
# Node operations - ONE consistent way
headscale nodes delete --node "node-hostname"     # by hostname
headscale nodes delete --node "5"                 # by ID  
headscale nodes delete --node "user1-laptop"      # by given name
headscale nodes tag --node "192.168.1.100" -t test # by IP address

# User operations - ONE consistent way  
headscale users destroy --user "john@company.com" # by email
headscale users destroy --user "john"             # by username
headscale users destroy --user "5"                # by ID

# API key operations - consistent with pattern
headscale apikeys expire --apikey "abc123"        # by prefix
headscale apikeys expire --apikey "5"             # by ID
```

**Intelligent Identifier Resolution Functions:**
```go
// Core identifier resolution system
type NodeIdentifier struct {
    Value string
    Type  NodeIdentifierType // ID, Hostname, GivenName, IPAddress
}

type UserIdentifier struct {
    Value string  
    Type  UserIdentifierType // ID, Name, Email
}

type APIKeyIdentifier struct {
    Value string
    Type  APIKeyIdentifierType // ID, Prefix
}

// Smart resolution functions
func ResolveNode(client *ClientWrapper, identifier string) (*v1.Node, error)
func ResolveUser(client *ClientWrapper, identifier string) (*v1.User, error) 
func ResolveAPIKey(client *ClientWrapper, identifier string) (*v1.ApiKey, error)

// Resolution with filtering for list commands
func FilterNodesByIdentifier(nodes []*v1.Node, identifier string) []*v1.Node
func FilterUsersByIdentifier(users []*v1.User, identifier string) []*v1.User

// Validation and ambiguity detection
func ValidateUniqueNodeMatch(matches []*v1.Node, identifier string) (*v1.Node, error)
func ValidateUniqueUserMatch(matches []*v1.User, identifier string) (*v1.User, error)
```

#### Checkpoint 2: Create Smart Flag Registration System
**File**: `cmd/headscale/cli/smart_flags.go`

**Goal**: Move flag definitions close to command logic, make them reusable

**Before (current scattered approach):**
```go
// In init() function far from command logic
func init() {
    listNodesCmd.Flags().StringP("user", "u", "", "Filter by user")
    deleteNodeCmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID)")
    err := deleteNodeCmd.MarkFlagRequired("identifier")
    // ... repeated everywhere
}
```

**After (smart flag system with backward compatibility):**
```go
// Flags defined WITH the command, reusable helpers + backward compatibility
var deleteNodeCmd = &cobra.Command{
    Use:   "delete",
    Short: "Delete a node",
    PreRunE: SmartFlags(
        RequiredNode("node"),              // New smart flag
        DeprecatedIdentifierAsNode(),      // Backward compatibility with deprecation warning
        OptionalForce(),                   // Reusable force flag
    ),
    Run: func(cmd *cobra.Command, args []string) {
        node := MustGetResolvedNode(cmd)   // Works with both --node and --identifier
        force := GetForce(cmd)
        
        // Command logic is clean and focused
        if !force && !ConfirmAction(fmt.Sprintf("Delete node %s?", node.GetName())) {
            return
        }
        
        client := MustGetClient(cmd)
        client.DeleteNode(&v1.DeleteNodeRequest{NodeId: node.GetId()})
    },
}
```

**Smart Flag System Functions:**
```go
// Smart flag definition helpers (used in PreRunE)
func RequiredNode(flagName string) SmartFlagOption
func OptionalNode(flagName string) SmartFlagOption  
func RequiredUser(flagName string) SmartFlagOption
func OptionalUser(flagName string) SmartFlagOption
func RequiredAPIKey(flagName string) SmartFlagOption
func OptionalForce() SmartFlagOption
func OptionalOutput() SmartFlagOption

// Backward compatibility helpers (with deprecation warnings)
func DeprecatedIdentifierAsNode() SmartFlagOption     // --identifier → --node  
func DeprecatedIdentifierAsUser() SmartFlagOption     // --identifier → --user
func DeprecatedNameAsUser() SmartFlagOption           // --name → --user
func DeprecatedPrefixAsAPIKey() SmartFlagOption       // --prefix → --apikey

// Smart flag resolution (used in Run functions)
func MustGetResolvedNode(cmd *cobra.Command) *v1.Node
func GetResolvedNode(cmd *cobra.Command) (*v1.Node, error)
func MustGetResolvedUser(cmd *cobra.Command) *v1.User
func GetResolvedUser(cmd *cobra.Command) (*v1.User, error)

// Backward compatibility resolution (checks both new and old flags)
func GetNodeFromAnyFlag(cmd *cobra.Command) (*v1.Node, error)
func GetUserFromAnyFlag(cmd *cobra.Command) (*v1.User, error)
func GetAPIKeyFromAnyFlag(cmd *cobra.Command) (*v1.ApiKey, error)

// List command filtering
func GetNodeFilter(cmd *cobra.Command) NodeFilter
func GetUserFilter(cmd *cobra.Command) UserFilter
func ApplyNodeFilter(nodes []*v1.Node, filter NodeFilter) []*v1.Node
```

#### Checkpoint 3: Implement Node Identifier Resolution
**File**: `cmd/headscale/cli/node_resolution.go`

**Smart Node Resolution Logic:**
```go
func ResolveNode(client *ClientWrapper, identifier string) (*v1.Node, error) {
    allNodes, err := client.ListNodes(&v1.ListNodesRequest{})
    if err != nil {
        return nil, fmt.Errorf("failed to list nodes: %w", err)
    }
    
    var matches []*v1.Node
    
    // Try different resolution strategies
    matches = append(matches, findNodesByID(allNodes.Nodes, identifier)...)
    matches = append(matches, findNodesByHostname(allNodes.Nodes, identifier)...)
    matches = append(matches, findNodesByGivenName(allNodes.Nodes, identifier)...)
    matches = append(matches, findNodesByIPAddress(allNodes.Nodes, identifier)...)
    
    // Remove duplicates and validate uniqueness
    unique := removeDuplicateNodes(matches)
    
    if len(unique) == 0 {
        return nil, fmt.Errorf("no node found matching '%s'", identifier)
    }
    if len(unique) > 1 {
        return nil, fmt.Errorf("ambiguous node identifier '%s', matches: %s", 
            identifier, formatNodeMatches(unique))
    }
    
    return unique[0], nil
}

// Helper functions for different resolution strategies
func findNodesByID(nodes []*v1.Node, identifier string) []*v1.Node
func findNodesByHostname(nodes []*v1.Node, identifier string) []*v1.Node  
func findNodesByGivenName(nodes []*v1.Node, identifier string) []*v1.Node
func findNodesByIPAddress(nodes []*v1.Node, identifier string) []*v1.Node
```

#### Checkpoint 4: Implement User Identifier Resolution
**File**: `cmd/headscale/cli/user_resolution.go`

**Smart User Resolution Logic:**
```go
func ResolveUser(client *ClientWrapper, identifier string) (*v1.User, error) {
    allUsers, err := client.ListUsers(&v1.ListUsersRequest{})
    if err != nil {
        return nil, fmt.Errorf("failed to list users: %w", err)
    }
    
    var matches []*v1.User
    
    // Try different resolution strategies
    matches = append(matches, findUsersByID(allUsers.Users, identifier)...)
    matches = append(matches, findUsersByName(allUsers.Users, identifier)...)
    matches = append(matches, findUsersByEmail(allUsers.Users, identifier)...)
    
    // Validate uniqueness
    unique := removeDuplicateUsers(matches)
    
    if len(unique) == 0 {
        return nil, fmt.Errorf("no user found matching '%s'", identifier)
    }
    if len(unique) > 1 {
        return nil, fmt.Errorf("ambiguous user identifier '%s', matches: %s",
            identifier, formatUserMatches(unique))
    }
    
    return unique[0], nil
}
```

#### Checkpoint 5: Implement List Command Filtering
**File**: `cmd/headscale/cli/list_filtering.go`

**Smart Filtering for List Commands:**
```bash
# New filtering capabilities
headscale nodes list --user "john"           # Show nodes for user john
headscale nodes list --node "laptop"         # Show nodes matching "laptop" 
headscale users list --user "@company.com"   # Show users from company.com domain
headscale nodes list --ip "192.168.1."       # Show nodes in IP range
```

**Filtering Implementation:**
```go
type NodeFilter struct {
    UserIdentifier string
    NodeIdentifier string  // Partial matching for list commands
    IPPattern      string
    TagPattern     string
}

func ApplyNodeFilter(nodes []*v1.Node, filter NodeFilter) []*v1.Node {
    var filtered []*v1.Node
    
    for _, node := range nodes {
        if filter.UserIdentifier != "" && !matchesUserFilter(node.User, filter.UserIdentifier) {
            continue
        }
        if filter.NodeIdentifier != "" && !matchesNodeFilter(node, filter.NodeIdentifier) {
            continue  
        }
        if filter.IPPattern != "" && !matchesIPPattern(node.IpAddresses, filter.IPPattern) {
            continue
        }
        if filter.TagPattern != "" && !matchesTagPattern(node.Tags, filter.TagPattern) {
            continue
        }
        
        filtered = append(filtered, node)
    }
    
    return filtered
}
```

#### Checkpoint 6: Refactor All Commands to Use Smart Flags
**Files**: Update all command files (`nodes.go`, `users.go`, etc.)

**Command Transformation Examples:**

**Before (nodes delete):**
```go
var deleteNodeCmd = &cobra.Command{
    Use:   "delete",
    Run: func(cmd *cobra.Command, args []string) {
        output, _ := cmd.Flags().GetString("output")
        identifier, err := cmd.Flags().GetUint64("identifier")
        if err != nil {
            ErrorOutput(err, fmt.Sprintf("Error converting ID to integer: %s", err), output)
            return
        }
        
        ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
        defer cancel()
        defer conn.Close()
        
        getRequest := &v1.GetNodeRequest{NodeId: identifier}
        getResponse, err := client.GetNode(ctx, getRequest)
        // ... 50+ lines of boilerplate
    },
}
```

**After (nodes delete with backward compatibility):**
```go
var deleteNodeCmd = &cobra.Command{
    Use:   "delete",
    Short: "Delete a node",
    PreRunE: SmartFlags(
        RequiredNode("node"),              // New smart flag
        DeprecatedIdentifierAsNode(),      // Backward compatibility  
        OptionalForce(),
        OptionalOutput(),
    ),
    Run: func(cmd *cobra.Command, args []string) {
        // GetNodeFromAnyFlag checks both --node and --identifier (with deprecation warning)
        node, err := GetNodeFromAnyFlag(cmd) 
        if err != nil {
            ErrorOutput(err, "Failed to resolve node", GetOutput(cmd))
            return
        }
        
        force := GetForce(cmd)
        output := GetOutput(cmd)
        
        if !force && !ConfirmAction(fmt.Sprintf("Delete node %s?", node.GetName())) {
            return
        }
        
        client := MustGetClient(cmd)
        response := client.DeleteNode(&v1.DeleteNodeRequest{NodeId: node.GetId()})
        SuccessOutput(response, "Node deleted", output)
    },
}
```

### User Experience Improvements

#### Before vs After Comparison

**Old Confusing Way:**
```bash
# User must know internal IDs and remember different flag names
headscale nodes list --user 5                    # Must know user ID
headscale nodes delete --identifier 123          # Must know node ID  
headscale users destroy --identifier 5           # Different flag for users
headscale apikeys expire --prefix abc123         # Completely different pattern
```

**New Intuitive Way:**
```bash
# Users can use natural identifiers consistently  
headscale nodes list --user "john@company.com"   # Email, name, or ID
headscale nodes delete --node "laptop"           # Hostname, name, IP, or ID
headscale users destroy --user "john"            # Name, email, or ID  
headscale apikeys expire --apikey "abc123"       # Prefix or ID
```

#### Error Message Improvements

**Before (cryptic):**
```
Error: required flag(s) "identifier" not set
```

**After (helpful):**
```
Error: no node found matching 'laptop-old'

Similar nodes found:
- laptop-new (ID: 5, IP: 192.168.1.100)  
- desktop-laptop (ID: 8, IP: 192.168.1.200)

Use --node with the exact hostname, IP address, or ID.
```

### Migration Strategy

#### Backward Compatibility
- Keep old flags working with deprecation warnings for 1 release
- Provide clear migration guidance in help text
- Update all documentation and examples

#### Detailed Migration Implementation

**Phase 1: Deprecation Warnings (Current Release)**
```bash
# Old flags work but show deprecation warnings
$ headscale nodes delete --identifier 5
WARNING: Flag --identifier is deprecated, use --node instead
Node deleted

$ headscale users destroy --identifier 3  
WARNING: Flag --identifier is deprecated, use --user instead
User destroyed

$ headscale apikeys expire --prefix abc123
WARNING: Flag --prefix is deprecated, use --apikey instead
Key expired

# New flags work without warnings
$ headscale nodes delete --node 5
Node deleted

$ headscale users destroy --user "john@company.com"
User destroyed
```

**Backward Compatibility Implementation:**
```go
// Example: DeprecatedIdentifierAsNode implementation
func DeprecatedIdentifierAsNode() SmartFlagOption {
    return func(cmd *cobra.Command) error {
        // Add the deprecated flag
        cmd.Flags().Uint64P("identifier", "i", 0, "Node identifier (ID) [DEPRECATED: use --node]")
        cmd.Flags().MarkDeprecated("identifier", "use --node instead")
        
        return nil
    }
}

// Example: GetNodeFromAnyFlag checks both flags
func GetNodeFromAnyFlag(cmd *cobra.Command) (*v1.Node, error) {
    // Check new flag first
    if nodeFlag, _ := cmd.Flags().GetString("node"); nodeFlag != "" {
        return ResolveNode(MustGetClient(cmd), nodeFlag)
    }
    
    // Check deprecated flag with warning
    if identifierFlag, _ := cmd.Flags().GetUint64("identifier"); identifierFlag != 0 {
        fmt.Fprintf(os.Stderr, "WARNING: Flag --identifier is deprecated, use --node instead\n")
        return ResolveNode(MustGetClient(cmd), fmt.Sprintf("%d", identifierFlag))
    }
    
    return nil, fmt.Errorf("either --node or --identifier must be specified")
}
```

**Phase 2: Removal (Next Major Release v0.x+1)**
```bash
# Only new flags work
$ headscale nodes delete --identifier 5
Error: unknown flag: --identifier
Use --node instead

$ headscale nodes delete --node 5  
Node deleted
```

### Implementation Timeline (8 weeks - Extended for comprehensive testing)

1. **Week 1**: Checkpoint 1 (Design identifier system)
   - Day 1-3: Design and implement core identifier resolution system
   - Day 4-5: Create unit tests for `identifiers_test.go`

2. **Week 2**: Checkpoint 2 (Smart flag framework) 
   - Day 1-3: Implement smart flag registration system with backward compatibility
   - Day 4-5: Create unit tests for `smart_flags_test.go` and `backward_compatibility_test.go`

3. **Week 3**: Checkpoints 3-4 (Resolution implementation)
   - Day 1-2: Implement node identifier resolution 
   - Day 3: Create unit tests for `node_resolution_test.go`
   - Day 4-5: Implement user identifier resolution and unit tests for `user_resolution_test.go`

4. **Week 4**: Checkpoint 5 (List filtering and API key resolution)
   - Day 1-2: Implement list command filtering
   - Day 3: Create unit tests for `list_filtering_test.go`  
   - Day 4-5: Implement API key resolution and comprehensive unit test coverage

5. **Week 5**: Checkpoint 6a (Refactor core commands with unit testing)
   - Day 1-2: Refactor nodes commands with new smart flag system
   - Day 3-4: Refactor users commands with new smart flag system
   - Day 5: Run unit tests and validate changes

6. **Week 6**: Checkpoint 6b (Refactor remaining commands and create integration tests)
   - Day 1-2: Refactor apikeys, preauthkeys, policy commands
   - Day 3-4: Create new integration test files per subcommand
   - Day 5: Split existing `integration/cli_test.go` into separate files

7. **Week 7**: Integration testing and backward compatibility validation
   - Day 1-2: Implement all new integration tests for smart resolution
   - Day 3-4: Implement backward compatibility integration tests
   - Day 5: Full integration test suite validation

8. **Week 8**: Final validation and migration preparation
   - Day 1-2: Performance testing and optimization
   - Day 3-4: Migration guides, documentation, and final testing
   - Day 5: Complete regression testing with both unit and integration tests

### Testing Checkpoints Per Week

**Week 1-4: Unit Test Development**
- Each implementation week includes corresponding unit test creation
- Unit test coverage target: 90%+ for all new identifier resolution logic
- Mock testing for all gRPC client interactions

**Week 5-6: Integration with Unit Testing**  
- Validate refactored commands work with existing integration tests
- Create unit tests for refactored command logic
- Ensure backward compatibility works in practice

**Week 7: New Integration Test Development**
- Create comprehensive integration tests for all new smart resolution features
- Test backward compatibility end-to-end with real Headscale server
- Validate deprecation warnings appear correctly in integration environment

**Week 8: Complete Validation**
- Run full test matrix: unit tests + integration tests + backward compatibility tests
- Performance regression testing
- Migration path validation

### Success Criteria
- [ ] All commands use consistent `--node`, `--user`, `--apikey` flags
- [ ] Users can identify resources by any natural identifier
- [ ] Ambiguous identifiers provide helpful error messages
- [ ] List commands support intelligent filtering
- [ ] Flag definitions are co-located with command logic
- [ ] 90% reduction in flag-related code duplication
- [ ] Backward compatibility maintained with deprecation warnings

### Testing Requirements

#### Unit Tests (Required for Phase 2)
**New unit test files to create:**
- [ ] `cmd/headscale/cli/identifiers_test.go` - Core identifier resolution logic
- [ ] `cmd/headscale/cli/smart_flags_test.go` - Smart flag system
- [ ] `cmd/headscale/cli/node_resolution_test.go` - Node identifier resolution
- [ ] `cmd/headscale/cli/user_resolution_test.go` - User identifier resolution  
- [ ] `cmd/headscale/cli/list_filtering_test.go` - List command filtering
- [ ] `cmd/headscale/cli/backward_compatibility_test.go` - Deprecation warnings

**Unit Test Coverage Requirements:**
```go
// Example: node_resolution_test.go
func TestResolveNode(t *testing.T) {
    tests := []struct {
        name       string
        identifier string
        nodes      []*v1.Node
        want       *v1.Node
        wantErr    bool
        errContains string
    }{
        {
            name: "resolve by ID",
            identifier: "5",
            nodes: []*v1.Node{{Id: 5, Name: "test-node"}},
            want: &v1.Node{Id: 5, Name: "test-node"},
        },
        {
            name: "resolve by hostname", 
            identifier: "laptop",
            nodes: []*v1.Node{{Id: 5, Name: "laptop", GivenName: "user-laptop"}},
            want: &v1.Node{Id: 5, Name: "laptop", GivenName: "user-laptop"},
        },
        {
            name: "ambiguous identifier",
            identifier: "test",
            nodes: []*v1.Node{
                {Id: 1, Name: "test-1"},
                {Id: 2, Name: "test-2"},
            },
            wantErr: true,
            errContains: "ambiguous node identifier",
        },
        // ... more test cases
    }
}

// Example: backward_compatibility_test.go  
func TestDeprecatedIdentifierWarning(t *testing.T) {
    tests := []struct {
        name         string
        args         []string
        expectWarning bool
        warningText   string
    }{
        {
            name: "new flag no warning",
            args: []string{"--node", "5"},
            expectWarning: false,
        },
        {
            name: "deprecated flag shows warning",
            args: []string{"--identifier", "5"},
            expectWarning: true,
            warningText: "WARNING: Flag --identifier is deprecated, use --node instead",
        },
    }
}
```

#### Integration Tests (Reorganized by Subcommand)

**Current situation:** All CLI integration tests are in one large file `integration/cli_test.go` (1900+ lines)

**New structure:** Split into focused test files per subcommand:

- [ ] `integration/nodes_cli_test.go` - All node command integration tests
- [ ] `integration/users_cli_test.go` - All user command integration tests  
- [ ] `integration/apikeys_cli_test.go` - All API key command integration tests
- [ ] `integration/preauthkeys_cli_test.go` - All preauth key command integration tests
- [ ] `integration/policy_cli_test.go` - All policy command integration tests

**New integration tests to add for Phase 2 features:**

**`integration/nodes_cli_test.go`:**
```go
// Test smart node resolution by different identifiers
func TestNodeResolutionByHostname(t *testing.T)
func TestNodeResolutionByGivenName(t *testing.T) 
func TestNodeResolutionByIPAddress(t *testing.T)
func TestNodeResolutionAmbiguous(t *testing.T)

// Test backward compatibility
func TestNodesDeleteDeprecatedIdentifier(t *testing.T)
func TestNodesExpireDeprecatedIdentifier(t *testing.T)
func TestNodesRenameDeprecatedIdentifier(t *testing.T)

// Test list filtering
func TestNodesListFilterByUser(t *testing.T)
func TestNodesListFilterByNodePattern(t *testing.T)
func TestNodesListFilterByIPPattern(t *testing.T)
```

**`integration/users_cli_test.go`:**
```go
// Test smart user resolution
func TestUserResolutionByEmail(t *testing.T)
func TestUserResolutionByName(t *testing.T)
func TestUserResolutionAmbiguous(t *testing.T)

// Test backward compatibility
func TestUsersDestroyDeprecatedIdentifier(t *testing.T)
func TestUsersRenameDeprecatedIdentifier(t *testing.T)
func TestUsersListDeprecatedName(t *testing.T)

// Test enhanced filtering
func TestUsersListFilterByEmailDomain(t *testing.T)
func TestUsersListFilterByNamePattern(t *testing.T)
```

**`integration/apikeys_cli_test.go`:**
```go
// Test smart API key resolution
func TestAPIKeyResolutionByPrefix(t *testing.T)
func TestAPIKeyResolutionByID(t *testing.T)
func TestAPIKeyResolutionAmbiguous(t *testing.T)

// Test backward compatibility
func TestAPIKeysExpireDeprecatedPrefix(t *testing.T)
func TestAPIKeysDeleteDeprecatedPrefix(t *testing.T)
```

#### Comprehensive Testing Commands
```bash
# Run all unit tests for Phase 2
go test ./cmd/headscale/cli/... -v -run "Test.*Resolution"
go test ./cmd/headscale/cli/... -v -run "Test.*Deprecated" 
go test ./cmd/headscale/cli/... -v -run "Test.*SmartFlag"

# Run specific integration test files  
go run ./cmd/hi run "integration/nodes_cli_test.go::TestNodeResolution*"
go run ./cmd/hi run "integration/users_cli_test.go::TestUserResolution*"
go run ./cmd/hi run "integration/apikeys_cli_test.go::TestAPIKeyResolution*"

# Run all new Phase 2 integration tests
go run ./cmd/hi run "Test*Resolution*" 
go run ./cmd/hi run "Test*Deprecated*"
go run ./cmd/hi run "Test*Filter*"

# Test backward compatibility specifically
go run ./cmd/hi run "Test*DeprecatedIdentifier"
go run ./cmd/hi run "Test*DeprecatedPrefix"
go run ./cmd/hi run "Test*DeprecatedName"
```

#### Migration Testing Strategy
```bash
# Phase 1: Test both old and new flags work
./headscale nodes delete --identifier 5      # Should work with warning
./headscale nodes delete --node 5            # Should work without warning  
./headscale users destroy --identifier 3     # Should work with warning
./headscale users destroy --user "john"      # Should work without warning

# Test help text shows deprecation
./headscale nodes delete --help | grep "DEPRECATED"
./headscale users destroy --help | grep "DEPRECATED"

# Phase 2: Test old flags are removed (future release)
./headscale nodes delete --identifier 5      # Should fail with "unknown flag"
./headscale nodes delete --node 5            # Should work
```

### Complete Flag Migration Mapping
**All deprecated flags that will be supported:**

| Old Flag | New Flag | Commands Affected | Deprecation Helper |
|----------|----------|-------------------|-------------------|
| `--identifier` | `--node` | nodes delete, expire, rename, tag, move | `DeprecatedIdentifierAsNode()` |
| `--identifier` | `--user` | users destroy, rename | `DeprecatedIdentifierAsUser()` |
| `--name` | `--user` | users list | `DeprecatedNameAsUser()` |
| `--prefix` | `--apikey` | apikeys expire, delete | `DeprecatedPrefixAsAPIKey()` |
| `--user` (ID only) | `--user` (smart) | preauthkeys, nodes list | Enhanced to accept name/email |

## Phase 3: Command Documentation & Usage Streamlining

### Objective
Transform the CLI from having inconsistent, unclear help text into a polished, professional tool with comprehensive documentation, clear examples, and intuitive command descriptions.

### Current Documentation Problems Analysis

#### Inconsistent Command Descriptions
**Current problematic help text:**
```bash
$ headscale nodes delete --help
Delete a node

$ headscale users destroy --help  
Destroys a user

$ headscale apikeys expire --help
Expire an ApiKey

$ headscale preauthkeys create --help
Creates a new preauthkey in the specified user
```

**Problems identified:**
1. **Inconsistent Tone**: "Delete" vs "Destroys" vs "Expire" vs "Creates"
2. **Unclear Consequences**: No explanation of what happens when you delete/destroy
3. **Missing Context**: No examples of how to use commands
4. **Poor Formatting**: Inconsistent capitalization and punctuation
5. **No Usage Patterns**: Users don't know the common workflows

#### Missing Usage Examples
**Current state:** Most commands have no examples
```bash
$ headscale nodes list --help
List nodes
# No examples, no common usage patterns
```

**What users actually need:**
```bash
$ headscale nodes list --help
List and filter nodes in your Headscale network

Examples:
  # List all nodes
  headscale nodes list

  # List nodes for a specific user
  headscale nodes list --user "john@company.com"
  
  # List nodes matching a pattern
  headscale nodes list --node "laptop"
  
  # List nodes with their tags
  headscale nodes list --tags
```

### Phase 3 Implementation Plan

#### Checkpoint 1: Design Documentation Standards
**File**: `cmd/headscale/cli/docs_standards.go`

**Documentation Guidelines:**
```go
// Documentation standards for all CLI commands
type CommandDocs struct {
    // Short description: imperative verb + object (max 50 chars)
    Short string
    
    // Long description: explains what, why, and consequences (2-4 sentences)
    Long string
    
    // Usage examples: 3-5 practical examples with comments
    Examples []Example
    
    // Related commands: help users discover related functionality
    SeeAlso []string
}

type Example struct {
    Description string  // What this example demonstrates
    Command     string  // The actual command
    Note        string  // Optional: additional context
}

// Standard verb patterns for consistency
var StandardVerbs = map[string]string{
    "create": "Create",     // Create a new resource
    "list":   "List",       // List existing resources  
    "delete": "Delete",     // Remove a resource permanently
    "show":   "Show",       // Display detailed information
    "update": "Update",     // Modify an existing resource
    "expire": "Expire",     // Mark as expired/invalid
}
```

**Standardized Command Description Patterns:**
```bash
# Consistent short descriptions (imperative verb + object)
"Create a new user"
"List nodes in your network"  
"Delete a node permanently"
"Show detailed node information"
"Update user settings"
"Expire an API key"

# Consistent long descriptions (what + why + consequences)
"Create a new user in your Headscale network. Users can own nodes and 
have policies applied to them. This creates an empty user that can 
register nodes using preauth keys."

"List all nodes in your Headscale network with optional filtering. 
Use filters to find specific nodes or view nodes belonging to 
particular users."
```

#### Checkpoint 2: Create Example Generation System
**File**: `cmd/headscale/cli/examples.go`

**Comprehensive Example System:**
```go
// Example generation system for consistent, helpful examples
type ExampleGenerator struct {
    CommandPath []string  // e.g., ["nodes", "delete"]
    EntityType  string    // "node", "user", "apikey"
    Operation   string    // "create", "list", "delete"
}

func (eg *ExampleGenerator) GenerateExamples() []Example {
    examples := []Example{}
    
    // Basic usage (always included)
    examples = append(examples, eg.basicExample())
    
    // Smart identifier examples (Phase 2 integration)
    examples = append(examples, eg.identifierExamples()...)
    
    // Advanced filtering examples
    examples = append(examples, eg.filteringExamples()...)
    
    // Output format examples
    examples = append(examples, eg.outputExamples()...)
    
    // Common workflow examples
    examples = append(examples, eg.workflowExamples()...)
    
    return examples
}

// Example generation for node commands
func generateNodeExamples() map[string][]Example {
    return map[string][]Example{
        "list": {
            {"List all nodes", "headscale nodes list", ""},
            {"List nodes for a user", "headscale nodes list --user 'john@company.com'", ""},
            {"List nodes matching pattern", "headscale nodes list --node 'laptop'", "Partial matching"},
            {"List with tags", "headscale nodes list --tags", "Shows ACL tags"},
            {"Export as JSON", "headscale nodes list --output json", "Machine readable"},
        },
        "delete": {
            {"Delete by hostname", "headscale nodes delete --node 'laptop.local'", ""},
            {"Delete by IP", "headscale nodes delete --node '192.168.1.100'", ""},
            {"Delete by ID", "headscale nodes delete --node '5'", ""},
            {"Force delete", "headscale nodes delete --node 'laptop' --force", "No confirmation"},
        },
    }
}
```

#### Checkpoint 3: Implement Usage Pattern Documentation
**File**: `cmd/headscale/cli/usage_patterns.go`

**Common Usage Pattern Documentation:**
```go
// Common workflows and usage patterns
type UsagePattern struct {
    Name        string    // "Node Management", "User Setup"
    Description string    // What this pattern accomplishes
    Steps       []Step    // Sequential steps
    Notes       []string  // Important considerations
}

type Step struct {
    Action      string  // What you're doing
    Command     string  // The command to run
    Explanation string  // Why this step is needed
}

// Example: Node management workflow
var NodeManagementPatterns = []UsagePattern{
    {
        Name: "Adding a new device to your network",
        Description: "Register a new device and configure it for your network",
        Steps: []Step{
            {
                Action: "Create a preauth key",
                Command: "headscale preauthkeys --user 'john@company.com' create --expiration 1h",
                Explanation: "Generate a one-time key for device registration",
            },
            {
                Action: "Register the device",
                Command: "headscale nodes register --user 'john@company.com' --key 'nodekey:...'",
                Explanation: "Add the device to your network",
            },
            {
                Action: "Verify registration",
                Command: "headscale nodes list --user 'john@company.com'",
                Explanation: "Confirm the device appears in your network",
            },
        },
        Notes: []string{
            "Preauth keys expire for security - create them just before use",
            "Device will appear online once Tailscale connects successfully",
        },
    },
}
```

#### Checkpoint 4: Enhance Help Text with Smart Examples
**File**: Updates to all command files

**Before (current poor help):**
```go
var deleteNodeCmd = &cobra.Command{
    Use:   "delete",
    Short: "Delete a node",
    // No Long description
    // No Examples
    // No SeeAlso
}
```

**After (comprehensive help):**
```go
var deleteNodeCmd = &cobra.Command{
    Use:   "delete",
    Short: "Delete a node permanently from your network",
    Long: `Delete a node permanently from your Headscale network.

This removes the node from your network and revokes its access. The device
will lose connectivity to your network immediately. This action cannot be
undone - to reconnect the device, you'll need to register it again.`,
    
    Example: `  # Delete a node by hostname
  headscale nodes delete --node "laptop.local"
  
  # Delete a node by IP address  
  headscale nodes delete --node "192.168.1.100"
  
  # Delete a node by its ID
  headscale nodes delete --node "5"
  
  # Delete without confirmation prompt
  headscale nodes delete --node "laptop" --force
  
  # Delete with JSON output
  headscale nodes delete --node "laptop" --output json`,
  
    SeeAlso: `headscale nodes list, headscale nodes expire`,
    
    PreRunE: SmartFlags(
        RequiredNode("node"),
        DeprecatedIdentifierAsNode(),
        OptionalForce(),
        OptionalOutput(),
    ),
    Run: deleteNodeRun,
}
```

#### Checkpoint 5: Create Interactive Help System
**File**: `cmd/headscale/cli/interactive_help.go`

**Enhanced Help Features:**
```go
// Interactive help system
func EnhanceHelpCommand() {
    // Add global help improvements
    rootCmd.SetHelpTemplate(CustomHelpTemplate)
    rootCmd.SetUsageTemplate(CustomUsageTemplate)
    
    // Add command discovery
    rootCmd.AddCommand(examplesCmd)      // "headscale examples"
    rootCmd.AddCommand(workflowsCmd)     // "headscale workflows" 
    rootCmd.AddCommand(quickStartCmd)    // "headscale quickstart"
}

// New help commands
var examplesCmd = &cobra.Command{
    Use:   "examples",
    Short: "Show common usage examples",
    Long:  "Display practical examples for common Headscale operations",
    Run: func(cmd *cobra.Command, args []string) {
        ShowCommonExamples()
    },
}

var workflowsCmd = &cobra.Command{
    Use:   "workflows", 
    Short: "Show step-by-step workflows",
    Long:  "Display common workflows like adding devices, managing users, etc.",
    Run: func(cmd *cobra.Command, args []string) {
        ShowCommonWorkflows()
    },
}

// Example output for "headscale examples"
func ShowCommonExamples() {
    fmt.Println(`Common Headscale Examples:

NODE MANAGEMENT:
  # List all nodes
  headscale nodes list
  
  # Find a specific node  
  headscale nodes list --node "laptop"
  
  # Delete a node
  headscale nodes delete --node "laptop.local"

USER MANAGEMENT:
  # Create a new user
  headscale users create "john@company.com"
  
  # List all users
  headscale users list
  
  # Delete a user and all their nodes
  headscale users destroy --user "john@company.com"

For more examples: headscale <command> --help`)
}
```

#### Checkpoint 6: Implement Contextual Help
**File**: `cmd/headscale/cli/contextual_help.go`

**Smart Help Based on Context:**
```go
// Contextual help that suggests related commands
func AddContextualHelp(cmd *cobra.Command) {
    originalRun := cmd.Run
    cmd.Run = func(c *cobra.Command, args []string) {
        // Run the original command
        originalRun(c, args)
        
        // Show contextual suggestions after success
        ShowContextualSuggestions(c)
    }
}

func ShowContextualSuggestions(cmd *cobra.Command) {
    cmdPath := GetCommandPath(cmd)
    
    switch cmdPath {
    case "users create":
        fmt.Println("\nNext steps:")
        fmt.Println("  • Create preauth keys: headscale preauthkeys --user <user> create")
        fmt.Println("  • View all users: headscale users list")
        
    case "nodes register":
        fmt.Println("\nNext steps:")
        fmt.Println("  • Verify registration: headscale nodes list")
        fmt.Println("  • Configure routes: headscale nodes approve-routes --node <node>")
        
    case "preauthkeys create":
        fmt.Println("\nNext steps:")
        fmt.Println("  • Use this key to register a device with Tailscale")
        fmt.Println("  • View key usage: headscale preauthkeys --user <user> list")
    }
}
```

### Documentation Quality Standards

#### Command Description Guidelines
1. **Short descriptions**: Imperative verb + clear object (max 50 chars)
2. **Long descriptions**: What + Why + Consequences (2-4 sentences)
3. **Consistent terminology**: "node" not "machine", "user" not "namespace"
4. **Clear consequences**: Explain what happens when command runs

#### Example Quality Standards
1. **Practical examples**: Real-world scenarios users encounter
2. **Progressive complexity**: Start simple, show advanced usage
3. **Smart identifier integration**: Showcase Phase 2 improvements
4. **Output format examples**: JSON, YAML, table formats
5. **Common workflows**: Multi-step processes

#### Help Text Formatting
1. **Consistent capitalization**: Sentence case for descriptions
2. **Proper punctuation**: End descriptions with periods
3. **Clear sections**: Use consistent section headers
4. **Readable formatting**: Proper indentation and spacing

### User Experience Improvements

#### Before vs After Comparison

**Before (unclear help):**
```bash
$ headscale nodes delete --help
Delete a node

Usage:
  headscale nodes delete [flags]

Flags:
  -i, --identifier uint   Node identifier (ID)
  -h, --help             help for delete
```

**After (comprehensive help):**
```bash
$ headscale nodes delete --help
Delete a node permanently from your network

This removes the node from your Headscale network and revokes its access.
The device will lose connectivity immediately. This action cannot be undone.

Usage:
  headscale nodes delete --node <identifier> [flags]

Examples:
  # Delete by hostname
  headscale nodes delete --node "laptop.local"
  
  # Delete by IP address
  headscale nodes delete --node "192.168.1.100"
  
  # Delete by ID
  headscale nodes delete --node "5"
  
  # Delete without confirmation
  headscale nodes delete --node "laptop" --force

Flags:
      --node string    Node identifier (hostname, IP, ID, or name)
      --force          Delete without confirmation prompt
  -o, --output string  Output format (json, yaml, or table)
  -h, --help           Show this help message

See also: headscale nodes list, headscale nodes expire
```

#### New Global Help Features
```bash
# Discover common examples
$ headscale examples

# Learn step-by-step workflows  
$ headscale workflows

# Quick start guide
$ headscale quickstart

# Better command discovery
$ headscale --help
# Now shows organized command groups with descriptions
```

### Implementation Timeline (4 weeks)

1. **Week 1**: Checkpoint 1-2 (Documentation standards and example system)
   - Day 1-3: Design documentation standards and example generation system
   - Day 4-5: Create unit tests for documentation consistency

2. **Week 2**: Checkpoint 3-4 (Usage patterns and enhanced help text)
   - Day 1-3: Implement usage pattern documentation and workflow guides
   - Day 4-5: Update all command help text with comprehensive examples

3. **Week 3**: Checkpoint 5-6 (Interactive and contextual help)
   - Day 1-3: Implement interactive help commands and contextual suggestions
   - Day 4-5: Create comprehensive help text consistency tests

4. **Week 4**: Documentation validation and refinement
   - Day 1-3: User testing of new help system and example validation
   - Day 4-5: Final documentation polishing and integration testing

### Success Criteria
- [ ] All commands have consistent, professional help text
- [ ] Every command includes 3-5 practical examples  
- [ ] Users can discover related commands through "See also" links
- [ ] Interactive help commands guide users through common workflows
- [ ] Help text showcases Phase 2 smart identifier features
- [ ] Documentation passes consistency and quality tests
- [ ] New user onboarding is significantly improved

### Testing Requirements
- [ ] **Documentation consistency tests**: Verify all commands follow standards
- [ ] **Example validation tests**: Ensure all examples work correctly
- [ ] **Help text integration tests**: Test help output in CI
- [ ] **User experience testing**: Validate help text improves usability
- [ ] **Workflow validation**: Test that documented workflows actually work