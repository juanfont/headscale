# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

**Configuration** (`hscontrol/types/config.go`)**
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

## Integration Test System

### Overview
Integration tests use Docker containers running real Tailscale clients against a Headscale server. Tests validate end-to-end functionality including routing, ACLs, node lifecycle, and network coordination.

### Running Integration Tests

**System Requirements**
```bash
# Check if your system is ready
go run ./cmd/hi doctor
```
This verifies Docker, Go, required images, and disk space.

**Test Execution Patterns**
```bash
# Run a single test (recommended for development)
go run ./cmd/hi run "TestSubnetRouterMultiNetwork"

# Run with PostgreSQL backend (for database-heavy tests)
go run ./cmd/hi run "TestExpireNode" --postgres

# Run multiple tests with pattern matching
go run ./cmd/hi run "TestSubnet*"

# Run all integration tests (CI/full validation)
go test ./integration -timeout 30m
```

**Test Categories & Timing**
- **Fast tests** (< 2 min): Basic functionality, CLI operations
- **Medium tests** (2-5 min): Route management, ACL validation  
- **Slow tests** (5+ min): Node expiration, HA failover
- **Long-running tests** (10+ min): `TestNodeOnlineStatus` (12 min duration)

### Test Infrastructure

**Docker Setup**
- Headscale server container with configurable database backend
- Multiple Tailscale client containers with different versions
- Isolated networks per test scenario
- Automatic cleanup after test completion

**Test Artifacts**
All test runs save artifacts to `control_logs/TIMESTAMP-ID/`:
```
control_logs/20250713-213106-iajsux/
├── hs-testname-abc123.stderr.log     # Headscale server logs
├── hs-testname-abc123.stdout.log
├── hs-testname-abc123.db             # Database snapshot
├── hs-testname-abc123_metrics.txt    # Prometheus metrics
├── hs-testname-abc123-mapresponses/  # Protocol debug data
├── ts-client-xyz789.stderr.log       # Tailscale client logs
├── ts-client-xyz789.stdout.log
└── ts-client-xyz789_status.json      # Client status dump
```

### Test Development Guidelines

**Timing Considerations**
Integration tests involve real network operations and Docker container lifecycle:

```go
// ❌ Wrong: Immediate assertions after async operations
client.Execute([]string{"tailscale", "set", "--advertise-routes=10.0.0.0/24"})
nodes, _ := headscale.ListNodes()
require.Len(t, nodes[0].GetAvailableRoutes(), 1) // May fail due to timing

// ✅ Correct: Wait for async operations to complete
client.Execute([]string{"tailscale", "set", "--advertise-routes=10.0.0.0/24"})
require.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err := headscale.ListNodes()
    assert.NoError(c, err)
    assert.Len(c, nodes[0].GetAvailableRoutes(), 1)
}, 10*time.Second, 100*time.Millisecond, "route should be advertised")
```

**Common Test Patterns**
- **Route Advertisement**: Use `EventuallyWithT` for route propagation
- **Node State Changes**: Wait for NodeStore synchronization  
- **ACL Policy Changes**: Allow time for policy recalculation
- **Network Connectivity**: Use ping tests with retries

**Test Data Management**
```go
// Node identification: Don't assume array ordering
expectedRoutes := map[string]string{"1": "10.33.0.0/16"}
for _, node := range nodes {
    nodeIDStr := fmt.Sprintf("%d", node.GetId())
    if route, shouldHaveRoute := expectedRoutes[nodeIDStr]; shouldHaveRoute {
        // Test the node that should have the route
    }
}
```

### Troubleshooting Integration Tests

**Common Failure Patterns**
1. **Timing Issues**: Test assertions run before async operations complete
   - **Solution**: Use `EventuallyWithT` with appropriate timeouts
   - **Timeout Guidelines**: 3-5s for route operations, 10s for complex scenarios

2. **Infrastructure Problems**: Disk space, Docker issues, network conflicts
   - **Check**: `go run ./cmd/hi doctor` for system health
   - **Clean**: Remove old test containers and networks

3. **NodeStore Synchronization**: Tests expecting immediate data availability
   - **Key Points**: Route advertisements must propagate through poll requests
   - **Fix**: Wait for NodeStore updates after Hostinfo changes

4. **Database Backend Differences**: SQLite vs PostgreSQL behavior differences
   - **Use**: `--postgres` flag for database-intensive tests
   - **Note**: Some timing characteristics differ between backends

**Debugging Failed Tests**
1. **Check test artifacts** in `control_logs/` for detailed logs
2. **Examine MapResponse JSON** files for protocol-level debugging
3. **Review Headscale stderr logs** for server-side error messages
4. **Check Tailscale client status** for network-level issues

**Resource Management**
- Tests require significant disk space (each run ~100MB of logs)
- Docker containers are cleaned up automatically on success
- Failed tests may leave containers running - clean manually if needed
- Use `docker system prune` periodically to reclaim space

### Best Practices for Test Modifications

1. **Always test locally** before committing integration test changes
2. **Use appropriate timeouts** - too short causes flaky tests, too long slows CI
3. **Clean up properly** - ensure tests don't leave persistent state
4. **Handle both success and failure paths** in test scenarios
5. **Document timing requirements** for complex test scenarios

## NodeStore Implementation Details

**Key Insight from Recent Work**: The NodeStore is a critical performance optimization that caches node data in memory while ensuring consistency with the database. When working with route advertisements or node state changes:

1. **Timing Considerations**: Route advertisements need time to propagate from clients to server. Use `require.EventuallyWithT()` patterns in tests instead of immediate assertions.

2. **Synchronization Points**: NodeStore updates happen at specific points like `poll.go:420` after Hostinfo changes. Ensure these are maintained when modifying the polling logic.

3. **Peer Visibility**: The NodeStore's `peersFunc` determines which nodes are visible to each other. Policy-based filtering is separate from monitoring visibility - expired nodes should remain visible for debugging but marked as expired.

## Testing Guidelines

### Integration Test Patterns
```go
// Use EventuallyWithT for async operations
require.EventuallyWithT(t, func(c *assert.CollectT) {
    nodes, err := headscale.ListNodes()
    assert.NoError(c, err)
    // Check expected state
}, 10*time.Second, 100*time.Millisecond, "description")

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

## Important Notes

- **Dependencies**: Use `nix develop` for consistent toolchain (Go, buf, protobuf tools, linting)
- **Protocol Buffers**: Changes to `proto/` require `make generate` and should be committed separately
- **Code Style**: Enforced via golangci-lint with golines (width 88) and gofumpt formatting
- **Database**: Supports both SQLite (development) and PostgreSQL (production/testing)
- **Integration Tests**: Require Docker and can consume significant disk space
- **Performance**: NodeStore optimizations are critical for scale - be careful with changes to state management

## Debugging Integration Tests

Test artifacts are preserved in `control_logs/TIMESTAMP-ID/` including:
- Headscale server logs (stderr/stdout)
- Tailscale client logs and status
- Database dumps and network captures
- MapResponse JSON files for protocol debugging

When tests fail, check these artifacts first before assuming code issues.
