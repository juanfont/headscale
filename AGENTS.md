# Headscale Custom IP Implementation - Agent Guidelines

## Objective

This document provides guidance for AI agents working on the Headscale custom IP address assignment feature. The implementation allows users to assign custom IP addresses to specific nodes via configuration file and CLI command, with full gRPC integration.

## Architecture Overview

### Components

1. **Configuration Layer** (`hscontrol/types/config.go`)
   - `StaticNodesConfig` type maps hostname to IP addresses
   - Parsed on server startup via `staticNodesConfig()` function
   - Configuration structure:
     ```yaml
     static_nodes:
       hostname:
         ipv4: [list of IPv4 addresses]
         ipv6: [list of IPv6 addresses, optional]
     ```

2. **IP Utilities** (`hscontrol/util/ip_static.go`)
   - `ValidateIPAddress()` - Validates IP format
   - `ValidateIPInRange()` - Checks IP is within configured prefix
   - `GenerateIPv6FromIPv4()` - Auto-generates IPv6 from IPv4 within Tailscale subnet

3. **Database Layer** (`hscontrol/db/node.go`)
   - `SetNodeIPs()` - Updates node IPs with validation and conflict checking
   - `GetNodeByHostname()` - Finds node by hostname/given name
   - All database operations include transaction support and error handling

4. **State Layer** (`hscontrol/state/state.go`)
   - `SetNodeIPs()` - State-level IP update with NodeStore synchronization
   - `ApplyStaticNodes()` - Applies static_nodes config on startup
   - Ensures consistency between NodeStore and database

5. **gRPC Layer** (`hscontrol/grpcv1.go`)
   - `SetNodeIP()` - gRPC handler with validation
   - Validates IPs, generates IPv6 if needed, calls state layer
   - Returns clear error messages

6. **CLI Layer** (`cmd/headscale/cli/nodes.go`)
   - `setNodeIPCmd` - CLI command: `headscale nodes set-ip`
   - Supports node identification by ID or hostname
   - Validates inputs before sending to gRPC

7. **Startup Logic** (`hscontrol/app.go`)
   - Calls `ApplyStaticNodes()` after state initialization
   - Logs all static IP assignments and errors

## Key Implementation Details

### IPv6 Auto-Generation

When IPv6 is not provided:
1. Uses configured IPv6 prefix (default: `fd7a:115c:a1e0::/48`)
2. Embeds IPv4 address in lower 32 bits of IPv6
3. Format: `<prefix_network>:0:0:<ipv4_bytes>`
4. Validates generated IPv6 is within configured prefix

### Error Handling

All functions return clear, actionable error messages:
- **Node not found**: Includes node ID/hostname
- **IP format invalid**: Shows the invalid IP and parsing error
- **IP out of range**: Shows IP, configured prefix, and suggests valid range
- **IP conflict**: Shows conflicting node ID and hostname
- **Database errors**: Wrapped with context

### Validation Flow

1. **Format Validation**: Parse IP addresses
2. **Range Validation**: Check IPs are in configured prefixes
3. **Conflict Detection**: Query database for existing assignments
4. **Database Update**: Atomic transaction with error handling
5. **NodeStore Sync**: Update in-memory cache after DB update

### Configuration Loading

Static nodes are applied:
- On server startup (in `NewHeadscale()`)
- After state initialization
- Before serving requests
- Logs all assignments and errors

## File Locations

- Config structure: `hscontrol/types/config.go`
- Config parsing: `hscontrol/types/config.go::staticNodesConfig()`
- Config example: `config-example.yaml` (lines ~67-75)
- IP utilities: `hscontrol/util/ip_static.go`
- Database functions: `hscontrol/db/node.go::SetNodeIPs()`
- State functions: `hscontrol/state/state.go::SetNodeIPs()`, `ApplyStaticNodes()`
- gRPC handler: `hscontrol/grpcv1.go::SetNodeIP()`
- CLI command: `cmd/headscale/cli/nodes.go::setNodeIPCmd`
- Startup logic: `hscontrol/app.go::NewHeadscale()`
- Proto definitions: `proto/headscale/v1/headscale.proto`, `node.proto`

## Development Guidelines

1. **Follow Headscale Patterns**: Use existing functions like `SetTags`, `SetApprovedRoutes` as templates
2. **Maintainability**: Simple, concise code without external dependencies
3. **Error Messages**: Always provide clear, actionable error messages
4. **Database Integrity**: All DB operations must validate before writing
5. **NodeStore Sync**: Always update NodeStore after database changes
6. **Logging**: Log all IP assignments and errors at appropriate levels

## Testing Considerations

- Unit tests for IP validation functions
- Unit tests for IPv6 generation
- Integration tests for CLI command
- Integration tests for config loading
- Database transaction tests
- Error case testing (conflicts, invalid IPs, etc.)

## Known Issues and Limitations

1. **Proto Generation Required**: Run `make generate` to generate gRPC code before compilation
2. **IPv6 Generation**: Only works when IPv6 prefix is configured
3. **Node Identification**: Hostname matching is case-sensitive
4. **Multiple IPs**: Only first IPv4/IPv6 from config arrays is used

## Next Steps

1. Generate proto code: `make generate`
2. Run tests to verify implementation
3. Update Swagger documentation
4. Test with real headscale instance
