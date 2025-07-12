# GEMINI.md

Be explicit and concise. Do not be polite or overly wordy.

## Project Overview

Headscale is an open-source, self-hosted implementation of the Tailscale control server. It implements the Tailscale coordination protocol allowing users to create their own private mesh VPN networks with Tailscale clients.

## Build and Development Commands

If any command fail, run it in the nix shell with `nix develop --command <COMMAND>`.

Always prefer `go run` over building the binary with `go build` for debugging.

### Building

- `nix build` - Build using Nix directly

### Testing

- `go test ./...` - go tests, if fails, run in nix shell
- `nix develop --command go test ./...` - Run go tests in nix shell

#### Integration Testing with `hi` CLI Tool

The preferred way to run integration tests is using the `hi` CLI tool,
`hi` is available in nix shell, or with `go run ./cmd/hi.`

After the tests ALWAYS READ the logs from `./control_logs`, NEVER IGNORE THEM.

**Basic Usage:**

- `hi run TestPingAllByIP` - Run specific test
- `hi run TestPingAllByIP --verbose` - Run with verbose output
- `hi run TestSSH --postgres --timeout 180m` - Advanced options

**Common Flags:**

- `--verbose` - Verbose output with detailed logging
- `--postgres` - Use PostgreSQL instead of SQLite
- `--timeout 120m` - Set test timeout (default: 120m)
- `--failfast` - Stop on first test failure (default: true)
- `--keep-on-failure` - Keep containers when tests fail for debugging
- `--clean-before=false` - Skip pre-test cleanup
- `--clean-after=false` - Skip post-test cleanup

**Cleanup Commands:**

- `hi clean all` - Clean all Docker resources
- `hi clean containers` - Kill test containers
- `hi clean networks` - Prune Docker networks
- `hi clean images` - Remove old test images
- `hi clean cache` - Clean Go module cache volume

**Features:**

- Automatic Docker context detection (supports colima, etc.)
- Test isolation with unique run IDs
- Docker volume caching for Go modules
- Automatic Docker image pulling
- Comprehensive artifact collection in `control_logs/`
  - This is where you look at logs if there is a failing test

### Code Quality

- `make fmt` - Format all code (Go, Prettier, Proto)
- `make fmt-go` - Format Go code using gofumpt and golangci-lint
- `make fmt-prettier` - Format documentation and config files
- `make fmt-proto` - Format Protocol Buffer files using clang-format
- `make proto-lint` - Lint protobuf files using buf
- `golangci-lint run --fix`

### Code Generation

- `make generate` - Generate Go code from Protocol Buffers (must run after proto changes)
- Commit generated code changes in `gen/` separately for easier review

## Architecture

### Core Package Structure

**hscontrol/** - Main control server implementation

- `app.go` - Main application and HTTP server setup
- `auth.go` - Authentication and authorization logic
- `handlers.go` - HTTP request handlers
- `grpcv1.go` - gRPC API implementation
- `poll.go` - Tailscale polling mechanism
- `noise.go` - Noise protocol implementation

**hscontrol/db/** - Database layer

- All database models and operations
- Migration handling
- SQLite and PostgreSQL support

**hscontrol/mapper/** - Network mapping

- Converts between Headscale and Tailscale network representations
- Handles node mapping and network topology

**hscontrol/policy/** - Access Control Lists (ACL)

- Policy engine for network access control
- Route approval logic
- User and tag-based permissions

**hscontrol/types/** - Core types and configuration

- Configuration structures
- Node, user, and network types
- Constants and shared types

**cmd/headscale/** - CLI application

- `cli/` directory contains all CLI commands
- Main entry point in `headscale.go`

**cmd/hi/** - Integration test runner CLI tool

- Utility for running integration tests
- Docker container management for tests

**integration/** - Integration test framework

- Comprehensive test scenarios with real Tailscale clients
- Docker-based test environment
- Tests multiple Tailscale client versions

### Key Components

1. **Control Server**: HTTP/gRPC server that implements Tailscale's coordination protocol
2. **Database Layer**: Supports SQLite and PostgreSQL for persistent storage
3. **Policy Engine**: Handles ACLs and network access permissions
4. **Mapper**: Translates between internal representations and Tailscale protocol
5. **DERP Server**: Embedded relay server for NAT traversal
6. **Authentication**: Supports OIDC, web-based auth, and pre-auth keys

## Development Environment

### Preferred Setup

Use Nix development environment: `nix develop`

- Installs all required tools (Go, Buf, protobuf tools)
- Ensures consistency with maintainer environment

### Required Tools

- Go (latest version)
- Buf (Protocol Buffer tooling)
- golangci-lint
- gofumpt (Go formatting)
- clang-format (Proto formatting)
- prettier (Documentation formatting)

## Testing Strategy

### Unit Tests

- Located alongside source files (`*_test.go`)
- Race detection enabled
- Coverage reporting to `coverage.out`

### Integration Tests

- Located in `integration/` directory
- Test real Tailscale client compatibility
- Use Docker containers for isolated test environments
- Test multiple Tailscale client versions (versions are updated via capver)
- Include scenarios like ping tests, ACL enforcement, route handling

## Code Style and Standards

### Go Code

- Formatted with `gofumpt`
- Linted with `golangci-lint` (see `.golangci.yaml`)
- Run `make lint` and `make fmt` before committing
- All exported functions must have godoc
- All complex functions must have godoc
- Avoid inline simple comments, only add comments complex logic

### Proto Code

- Linted with `buf`
- Formatted with `clang-format`

### Documentation

- Formatted with `prettier`
- Includes Markdown, YAML, and other config files

### Commit messages

- Follow the golang teams standard: https://go.dev/wiki/CommitMessage
- Do not use co-authored-by

## Protocol Buffer Generation

When modifying `.proto` files:

1. Run `make generate` to regenerate Go code
2. Commit generated changes in `gen/` directory separately
3. Required for any changes in `proto/` directory
