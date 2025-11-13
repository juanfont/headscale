# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Overview

Headscale is an open-source implementation of the Tailscale control server written in Go. It provides self-hosted coordination for Tailscale networks (tailnets), managing node registration, IP allocation, policy enforcement, and DERP routing.

## Development Commands

### Quick Setup

```bash
# Recommended: Use Nix for dependency management
nix develop

# Full development workflow
make dev  # runs fmt + lint + test + build
```

### Essential Commands

```bash
# Build headscale binary
make build

# Run tests
make test
go test ./...                    # All unit tests
go test -race ./...              # With race detection

# Run specific integration test
go run ./cmd/hi run "TestName" --postgres

# Code formatting and linting
make fmt         # Format all code (Go, docs, proto)
make lint        # Lint all code (Go, proto)
make fmt-go      # Format Go code only
make lint-go     # Lint Go code only

# Protocol buffer generation (after modifying proto/)
make generate

# Clean build artifacts
make clean
```

### Integration Testing

```bash
# Use the hi (Headscale Integration) test runner
go run ./cmd/hi doctor                    # Check system requirements
go run ./cmd/hi run "TestPattern"         # Run specific test
go run ./cmd/hi run "TestPattern" --postgres  # With PostgreSQL backend

# Test artifacts are saved to control_logs/ with logs and debug data
```

## Pre-Commit Quality Checks

### **MANDATORY: Automated Pre-Commit Hooks with prek**

**CRITICAL REQUIREMENT**: This repository uses [prek](https://prek.j178.dev/) for automated pre-commit hooks. All commits are automatically validated for code quality, formatting, and common issues.

### Initial Setup

When you first clone the repository or enter the nix shell, install the git hooks:

```bash
# Enter nix development environment
nix develop

# Install prek git hooks (one-time setup)
prek install
```

This installs the pre-commit hook at `.git/hooks/pre-commit` which automatically runs all configured checks before each commit.

### Configured Hooks

The repository uses `.pre-commit-config.yaml` with the following hooks:

**Built-in Checks** (optimized fast-path execution):

- `check-added-large-files` - Prevents accidentally committing large files
- `check-case-conflict` - Checks for files that would conflict in case-insensitive filesystems
- `check-executables-have-shebangs` - Ensures executables have proper shebangs
- `check-json` - Validates JSON syntax
- `check-merge-conflict` - Prevents committing files with merge conflict markers
- `check-symlinks` - Checks for broken symlinks
- `check-toml` - Validates TOML syntax
- `check-xml` - Validates XML syntax
- `check-yaml` - Validates YAML syntax
- `detect-private-key` - Detects accidentally committed private keys
- `end-of-file-fixer` - Ensures files end with a newline
- `fix-byte-order-marker` - Removes UTF-8 byte order markers
- `mixed-line-ending` - Prevents mixed line endings
- `trailing-whitespace` - Removes trailing whitespace

**Project-Specific Hooks**:

- `nixpkgs-fmt` - Formats Nix files
- `prettier` - Formats markdown, YAML, JSON, and TOML files
- `golangci-lint` - Runs Go linter with auto-fix on changed files only

### Manual Hook Execution

Run hooks manually without making a commit:

```bash
# Run hooks on staged files only
prek run

# Run hooks on all files in the repository
prek run --all-files

# Run a specific hook
prek run golangci-lint

# Run hooks on specific files
prek run --files path/to/file1.go path/to/file2.go
```

### Workflow Pattern

With prek installed, your normal workflow becomes:

```bash
# 1. Make your code changes
vim hscontrol/state/state.go

# 2. Stage your changes
git add .

# 3. Commit - hooks run automatically
git commit -m "feat: add new feature"

# If hooks fail, they will show which checks failed
# Fix the issues and try committing again
```

### Manual golangci-lint (Optional)

While golangci-lint runs automatically via prek, you can also run it manually:

```bash
# Use the same logic as the pre-commit hook (recommended)
./.golangci-lint-hook.sh

# Or manually specify a base reference
golangci-lint run --new-from-rev=upstream/main --timeout=5m --fix
```

The `.golangci-lint-hook.sh` script automatically finds where your branch diverged from the main branch by checking `upstream/main`, `origin/main`, or `main` in that order.

### Skipping Hooks (Not Recommended)

In rare cases where you need to skip hooks (e.g., work-in-progress commits), use:

```bash
git commit --no-verify -m "WIP: work in progress"
```

**WARNING**: Only use `--no-verify` for temporary WIP commits on feature branches. All commits to main must pass all hooks.

### Troubleshooting

**Hook installation issues**:

```bash
# Check if hooks are installed
ls -la .git/hooks/pre-commit

# Reinstall hooks
prek install
```

**Hooks running slow**:

```bash
# prek uses optimized fast-path for built-in hooks
# If running slow, check which hook is taking time with verbose output
prek run -v
```

**Update hook configuration**:

```bash
# After modifying .pre-commit-config.yaml, hooks will automatically use new config
# No reinstallation needed
```

## Project Structure & Architecture

### Top-Level Organization

```
headscale/
├── cmd/                    # Command-line applications
│   ├── headscale/         # Main headscale server binary
│   └── hi/               # Headscale Integration test runner
├── hscontrol/            # Core control plane logic
├── integration/          # End-to-end Docker-based tests
├── proto/               # Protocol buffer definitions
├── gen/                 # Generated code (protobuf)
├── docs/                # Documentation
└── packaging/           # Distribution packaging
```

### Core Packages (`hscontrol/`)

**Main Server (`hscontrol/`)**

- `app.go`: Application setup, dependency injection, server lifecycle
- `handlers.go`: HTTP/gRPC API endpoints for management operations
- `grpcv1.go`: gRPC service implementation for headscale API
- `poll.go`: **Critical** - Handles Tailscale MapRequest/MapResponse protocol
- `noise.go`: Noise protocol implementation for secure client communication
- `auth.go`: Authentication flows (web, OIDC, command-line)
- `oidc.go`: OpenID Connect integration for user authentication

**State Management (`hscontrol/state/`)**

- `state.go`: Central coordinator for all subsystems (database, policy, IP allocation, DERP)
- `node_store.go`: **Performance-critical** - In-memory cache with copy-on-write semantics
- Thread-safe operations with deadlock detection
- Coordinates between database persistence and real-time operations

**Database Layer (`hscontrol/db/`)**

- `db.go`: Database abstraction, GORM setup, migration management
- `node.go`: Node lifecycle, registration, expiration, IP assignment
- `users.go`: User management, namespace isolation
- `api_key.go`: API authentication tokens
- `preauth_keys.go`: Pre-authentication keys for automated node registration
- `ip.go`: IP address allocation and management
- `policy.go`: Policy storage and retrieval
- Schema migrations in `schema.sql` with extensive test data coverage

**Policy Engine (`hscontrol/policy/`)**

- `policy.go`: Core ACL evaluation logic, HuJSON parsing
- `v2/`: Next-generation policy system with improved filtering
- `matcher/`: ACL rule matching and evaluation engine
- Determines peer visibility, route approval, and network access rules
- Supports both file-based and database-stored policies

**Network Management (`hscontrol/`)**

- `derp/`: DERP (Designated Encrypted Relay for Packets) server implementation
  - NAT traversal when direct connections fail
  - Fallback relay for firewall-restricted environments
- `mapper/`: Converts internal Headscale state to Tailscale's wire protocol format
  - `tail.go`: Tailscale-specific data structure generation
- `routes/`: Subnet route management and primary route selection
- `dns/`: DNS record management and MagicDNS implementation

**Utilities & Support (`hscontrol/`)**

- `types/`: Core data structures, configuration, validation
- `util/`: Helper functions for networking, DNS, key management
- `templates/`: Client configuration templates (Apple, Windows, etc.)
- `notifier/`: Event notification system for real-time updates
- `metrics.go`: Prometheus metrics collection
- `capver/`: Tailscale capability version management

### Key Subsystem Interactions

**Node Registration Flow**

1. **Client Connection**: `noise.go` handles secure protocol handshake
2. **Authentication**: `auth.go` validates credentials (web/OIDC/preauth)
3. **State Creation**: `state.go` coordinates IP allocation via `db/ip.go`
4. **Storage**: `db/node.go` persists node, `NodeStore` caches in memory
5. **Network Setup**: `mapper/` generates initial Tailscale network map

**Ongoing Operations**

1. **Poll Requests**: `poll.go` receives periodic client updates
2. **State Updates**: `NodeStore` maintains real-time node information
3. **Policy Application**: `policy/` evaluates ACL rules for peer relationships
4. **Map Distribution**: `mapper/` sends network topology to all affected clients

**Route Management**

1. **Advertisement**: Clients announce routes via `poll.go` Hostinfo updates
2. **Storage**: `db/` persists routes, `NodeStore` caches for performance
3. **Approval**: `policy/` auto-approves routes based on ACL rules
4. **Distribution**: `routes/` selects primary routes, `mapper/` distributes to peers

### Command-Line Tools (`cmd/`)

**Main Server (`cmd/headscale/`)**

- `headscale.go`: CLI parsing, configuration loading, server startup
- Supports daemon mode, CLI operations (user/node management), database operations

**Integration Test Runner (`cmd/hi/`)**

- `main.go`: Test execution framework with Docker orchestration
- `run.go`: Individual test execution with artifact collection
- `doctor.go`: System requirements validation
- `docker.go`: Container lifecycle management
- Essential for validating changes against real Tailscale clients

### Generated & External Code

**Protocol Buffers (`proto/` → `gen/`)**

- Defines gRPC API for headscale management operations
- Client libraries can generate from these definitions
- Run `make generate` after modifying `.proto` files

**Integration Testing (`integration/`)**

- `scenario.go`: Docker test environment setup
- `tailscale.go`: Tailscale client container management
- Individual test files for specific functionality areas
- Real end-to-end validation with network isolation

### Critical Performance Paths

**High-Frequency Operations**

1. **MapRequest Processing** (`poll.go`): Every 15-60 seconds per client
2. **NodeStore Reads** (`node_store.go`): Every operation requiring node data
3. **Policy Evaluation** (`policy/`): On every peer relationship calculation
4. **Route Lookups** (`routes/`): During network map generation

**Database Write Patterns**

- **Frequent**: Node heartbeats, endpoint updates, route changes
- **Moderate**: User operations, policy updates, API key management
- **Rare**: Schema migrations, bulk operations

### Configuration & Deployment

**Configuration** (`hscontrol/types/config.go`)\*\*

- Database connection settings (SQLite/PostgreSQL)
- Network configuration (IP ranges, DNS settings)
- Policy mode (file vs database)
- DERP relay configuration
- OIDC provider settings

**Key Dependencies**

- **GORM**: Database ORM with migration support
- **Tailscale Libraries**: Core networking and protocol code
- **Zerolog**: Structured logging throughout the application
- **Buf**: Protocol buffer toolchain for code generation

### Development Workflow Integration

The architecture supports incremental development:

- **Unit Tests**: Focus on individual packages (`*_test.go` files)
- **Integration Tests**: Validate cross-component interactions
- **Database Tests**: Extensive migration and data integrity validation
- **Policy Tests**: ACL rule evaluation and edge cases
- **Performance Tests**: NodeStore and high-frequency operation validation

## Integration Testing System

### Overview

Headscale uses Docker-based integration tests with real Tailscale clients to validate end-to-end functionality. The integration test system is complex and requires specialized knowledge for effective execution and debugging.

### **MANDATORY: Use the headscale-integration-tester Agent**

**CRITICAL REQUIREMENT**: For ANY integration test execution, analysis, troubleshooting, or validation, you MUST use the `headscale-integration-tester` agent. This agent contains specialized knowledge about:

- Test execution strategies and timing requirements
- Infrastructure vs code issue distinction (99% vs 1% failure patterns)
- Security-critical debugging rules and forbidden practices
- Comprehensive artifact analysis workflows
- Real-world failure patterns from HA debugging experiences

### Quick Reference Commands

```bash
# Check system requirements (always run first)
go run ./cmd/hi doctor

# Run single test (recommended for development)
go run ./cmd/hi run "TestName"

# Use PostgreSQL for database-heavy tests
go run ./cmd/hi run "TestName" --postgres

# Pattern matching for related tests
go run ./cmd/hi run "TestPattern*"
```

**Critical Notes**:

- Only ONE test can run at a time (Docker port conflicts)
- Tests generate ~100MB of logs per run in `control_logs/`
- Clean environment before each test: `rm -rf control_logs/202507* && docker system prune -f`

### Test Artifacts Location

All test runs save comprehensive debugging artifacts to `control_logs/TIMESTAMP-ID/` including server logs, client logs, database dumps, MapResponse protocol data, and Prometheus metrics.

**For all integration test work, use the headscale-integration-tester agent - it contains the complete knowledge needed for effective testing and debugging.**

## NodeStore Implementation Details

**Key Insight from Recent Work**: The NodeStore is a critical performance optimization that caches node data in memory while ensuring consistency with the database. When working with route advertisements or node state changes:

1. **Timing Considerations**: Route advertisements need time to propagate from clients to server. Use `require.EventuallyWithT()` patterns in tests instead of immediate assertions.

2. **Synchronization Points**: NodeStore updates happen at specific points like `poll.go:420` after Hostinfo changes. Ensure these are maintained when modifying the polling logic.

3. **Peer Visibility**: The NodeStore's `peersFunc` determines which nodes are visible to each other. Policy-based filtering is separate from monitoring visibility - expired nodes should remain visible for debugging but marked as expired.

## Testing Guidelines

### Integration Test Patterns

#### **CRITICAL: EventuallyWithT Pattern for External Calls**

**All external calls in integration tests MUST be wrapped in EventuallyWithT blocks** to handle eventual consistency in distributed systems. External calls include:

- `client.Status()` - Getting Tailscale client status
- `client.Curl()` - Making HTTP requests through clients
- `client.Traceroute()` - Running network diagnostics
- `headscale.ListNodes()` - Querying headscale server state
- Any other calls that interact with external systems or network operations

**Key Rules**:

1. **Never use bare `require.NoError(t, err)` with external calls** - Always wrap in EventuallyWithT
2. **Keep related assertions together** - If multiple assertions depend on the same external call, keep them in the same EventuallyWithT block
3. **Split unrelated external calls** - Different external calls should be in separate EventuallyWithT blocks
4. **Never nest EventuallyWithT calls** - Each EventuallyWithT should be at the same level
5. **Declare shared variables at function scope** - Variables used across multiple EventuallyWithT blocks must be declared before first use

**Examples**:

```go
// CORRECT: External call wrapped in EventuallyWithT
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    status, err := client.Status()
    assert.NoError(c, err)

    // Related assertions using the same status call
    for _, peerKey := range status.Peers() {
        peerStatus := status.Peer[peerKey]
        assert.NotNil(c, peerStatus.PrimaryRoutes)
        requirePeerSubnetRoutesWithCollect(c, peerStatus, expectedRoutes)
    }
}, 5*time.Second, 200*time.Millisecond, "Verifying client status and routes")

// INCORRECT: Bare external call without EventuallyWithT
status, err := client.Status()  // ❌ Will fail intermittently
require.NoError(t, err)

// CORRECT: Separate EventuallyWithT for different external calls
// First external call - headscale.ListNodes()
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err := headscale.ListNodes()
    assert.NoError(c, err)
    assert.Len(c, nodes, 2)
    requireNodeRouteCountWithCollect(c, nodes[0], 2, 2, 2)
}, 10*time.Second, 500*time.Millisecond, "route state changes should propagate to nodes")

// Second external call - client.Status()
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    status, err := client.Status()
    assert.NoError(c, err)

    for _, peerKey := range status.Peers() {
        peerStatus := status.Peer[peerKey]
        requirePeerSubnetRoutesWithCollect(c, peerStatus, []netip.Prefix{tsaddr.AllIPv4(), tsaddr.AllIPv6()})
    }
}, 10*time.Second, 500*time.Millisecond, "routes should be visible to client")

// INCORRECT: Multiple unrelated external calls in same EventuallyWithT
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err := headscale.ListNodes()  // ❌ First external call
    assert.NoError(c, err)

    status, err := client.Status()  // ❌ Different external call - should be separate
    assert.NoError(c, err)
}, 10*time.Second, 500*time.Millisecond, "mixed calls")

// CORRECT: Variable scoping for shared data
var (
    srs1, srs2, srs3       *ipnstate.Status
    clientStatus           *ipnstate.Status
    srs1PeerStatus         *ipnstate.PeerStatus
)

assert.EventuallyWithT(t, func(c *assert.CollectT) {
    srs1 = subRouter1.MustStatus()  // = not :=
    srs2 = subRouter2.MustStatus()
    clientStatus = client.MustStatus()

    srs1PeerStatus = clientStatus.Peer[srs1.Self.PublicKey]
    // assertions...
}, 5*time.Second, 200*time.Millisecond, "checking router status")

// CORRECT: Wrapping client operations
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    result, err := client.Curl(weburl)
    assert.NoError(c, err)
    assert.Len(c, result, 13)
}, 5*time.Second, 200*time.Millisecond, "Verifying HTTP connectivity")

assert.EventuallyWithT(t, func(c *assert.CollectT) {
    tr, err := client.Traceroute(webip)
    assert.NoError(c, err)
    assertTracerouteViaIPWithCollect(c, tr, expectedRouter.MustIPv4())
}, 5*time.Second, 200*time.Millisecond, "Verifying network path")
```

**Helper Functions**:

- Use `requirePeerSubnetRoutesWithCollect` instead of `requirePeerSubnetRoutes` inside EventuallyWithT
- Use `requireNodeRouteCountWithCollect` instead of `requireNodeRouteCount` inside EventuallyWithT
- Use `assertTracerouteViaIPWithCollect` instead of `assertTracerouteViaIP` inside EventuallyWithT

```go
// Node route checking by actual node properties, not array position
var routeNode *v1.Node
for _, node := range nodes {
    if nodeIDStr := fmt.Sprintf("%d", node.GetId()); expectedRoutes[nodeIDStr] != "" {
        routeNode = node
        break
    }
}
```

### Running Problematic Tests

- Some tests require significant time (e.g., `TestNodeOnlineStatus` runs for 12 minutes)
- Infrastructure issues like disk space can cause test failures unrelated to code changes
- Use `--postgres` flag when testing database-heavy scenarios

## Quality Assurance and Testing Requirements

### **MANDATORY: Always Use Specialized Testing Agents**

**CRITICAL REQUIREMENT**: For ANY task involving testing, quality assurance, review, or validation, you MUST use the appropriate specialized agent at the END of your task list. This ensures comprehensive quality validation and prevents regressions.

**Required Agents for Different Task Types**:

1. **Integration Testing**: Use `headscale-integration-tester` agent for:
   - Running integration tests with `cmd/hi`
   - Analyzing test failures and artifacts
   - Troubleshooting Docker-based test infrastructure
   - Validating end-to-end functionality changes

2. **Quality Control**: Use `quality-control-enforcer` agent for:
   - Code review and validation
   - Ensuring best practices compliance
   - Preventing common pitfalls and anti-patterns
   - Validating architectural decisions

**Agent Usage Pattern**: Always add the appropriate agent as the FINAL step in any task list to ensure quality validation occurs after all work is complete.

### Integration Test Debugging Reference

Test artifacts are preserved in `control_logs/TIMESTAMP-ID/` including:

- Headscale server logs (stderr/stdout)
- Tailscale client logs and status
- Database dumps and network captures
- MapResponse JSON files for protocol debugging

**For integration test issues, ALWAYS use the headscale-integration-tester agent - do not attempt manual debugging.**

## EventuallyWithT Pattern for Integration Tests

### Overview

EventuallyWithT is a testing pattern used to handle eventual consistency in distributed systems. In Headscale integration tests, many operations are asynchronous - clients advertise routes, the server processes them, updates propagate through the network. EventuallyWithT allows tests to wait for these operations to complete while making assertions.

### External Calls That Must Be Wrapped

The following operations are **external calls** that interact with the headscale server or tailscale clients and MUST be wrapped in EventuallyWithT:

- `headscale.ListNodes()` - Queries server state
- `client.Status()` - Gets client network status
- `client.Curl()` - Makes HTTP requests through the network
- `client.Traceroute()` - Performs network diagnostics
- `client.Execute()` when running commands that query state
- Any operation that reads from the headscale server or tailscale client

### Operations That Must NOT Be Wrapped

The following are **blocking operations** that modify state and should NOT be wrapped in EventuallyWithT:

- `tailscale set` commands (e.g., `--advertise-routes`, `--exit-node`)
- Any command that changes configuration or state
- Use `client.MustStatus()` instead of `client.Status()` when you just need the ID for a blocking operation

### Five Key Rules for EventuallyWithT

1. **One External Call Per EventuallyWithT Block**
   - Each EventuallyWithT should make ONE external call (e.g., ListNodes OR Status)
   - Related assertions based on that single call can be grouped together
   - Unrelated external calls must be in separate EventuallyWithT blocks

2. **Variable Scoping**
   - Declare variables that need to be shared across EventuallyWithT blocks at function scope
   - Use `=` for assignment inside EventuallyWithT, not `:=` (unless the variable is only used within that block)
   - Variables declared with `:=` inside EventuallyWithT are not accessible outside

3. **No Nested EventuallyWithT**
   - NEVER put an EventuallyWithT inside another EventuallyWithT
   - This is a critical anti-pattern that must be avoided

4. **Use CollectT for Assertions**
   - Inside EventuallyWithT, use `assert` methods with the CollectT parameter
   - Helper functions called within EventuallyWithT must accept `*assert.CollectT`

5. **Descriptive Messages**
   - Always provide a descriptive message as the last parameter
   - Message should explain what condition is being waited for

### Correct Pattern Examples

```go
// CORRECT: Blocking operation NOT wrapped
for _, client := range allClients {
    status := client.MustStatus()
    command := []string{
        "tailscale",
        "set",
        "--advertise-routes=" + expectedRoutes[string(status.Self.ID)],
    }
    _, _, err = client.Execute(command)
    require.NoErrorf(t, err, "failed to advertise route: %s", err)
}

// CORRECT: Single external call with related assertions
var nodes []*v1.Node
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err = headscale.ListNodes()
    assert.NoError(c, err)
    assert.Len(c, nodes, 2)
    requireNodeRouteCountWithCollect(c, nodes[0], 2, 2, 2)
}, 10*time.Second, 500*time.Millisecond, "nodes should have expected route counts")

// CORRECT: Separate EventuallyWithT for different external call
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    status, err := client.Status()
    assert.NoError(c, err)
    for _, peerKey := range status.Peers() {
        peerStatus := status.Peer[peerKey]
        requirePeerSubnetRoutesWithCollect(c, peerStatus, expectedPrefixes)
    }
}, 10*time.Second, 500*time.Millisecond, "client should see expected routes")
```

### Incorrect Patterns to Avoid

```go
// INCORRECT: Blocking operation wrapped in EventuallyWithT
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    status, err := client.Status()
    assert.NoError(c, err)

    // This is a blocking operation - should NOT be in EventuallyWithT!
    command := []string{
        "tailscale",
        "set",
        "--advertise-routes=" + expectedRoutes[string(status.Self.ID)],
    }
    _, _, err = client.Execute(command)
    assert.NoError(c, err)
}, 5*time.Second, 200*time.Millisecond, "wrong pattern")

// INCORRECT: Multiple unrelated external calls in same EventuallyWithT
assert.EventuallyWithT(t, func(c *assert.CollectT) {
    // First external call
    nodes, err := headscale.ListNodes()
    assert.NoError(c, err)
    assert.Len(c, nodes, 2)

    // Second unrelated external call - WRONG!
    status, err := client.Status()
    assert.NoError(c, err)
    assert.NotNil(c, status)
}, 10*time.Second, 500*time.Millisecond, "mixed operations")
```

## Important Notes

- **Dependencies**: Use `nix develop` for consistent toolchain (Go, buf, protobuf tools, linting)
- **Protocol Buffers**: Changes to `proto/` require `make generate` and should be committed separately
- **Code Style**: Enforced via golangci-lint with golines (width 88) and gofumpt formatting
- **Linting**: ALL code must pass `golangci-lint run --new-from-rev=upstream/main --timeout=5m --fix` before commit
- **Database**: Supports both SQLite (development) and PostgreSQL (production/testing)
- **Integration Tests**: Require Docker and can consume significant disk space - use headscale-integration-tester agent
- **Performance**: NodeStore optimizations are critical for scale - be careful with changes to state management
- **Quality Assurance**: Always use appropriate specialized agents for testing and validation tasks
