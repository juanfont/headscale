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

## Important Notes

- **Dependencies**: Use `nix develop` for consistent toolchain (Go, buf, protobuf tools, linting)
- **Protocol Buffers**: Changes to `proto/` require `make generate` and should be committed separately
- **Code Style**: Enforced via golangci-lint with golines (width 88) and gofumpt formatting
- **Database**: Supports both SQLite (development) and PostgreSQL (production/testing)
- **Integration Tests**: Require Docker and can consume significant disk space - use headscale-integration-tester agent
- **Performance**: NodeStore optimizations are critical for scale - be careful with changes to state management
- **Quality Assurance**: Always use appropriate specialized agents for testing and validation tasks
