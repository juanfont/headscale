# CLI Standardization Summary

## Changes Made

### 1. Command Naming Standardization
- **Fixed**: `backfillips` → `backfill-ips` (with backward compat alias)
- **Fixed**: `dumpConfig` → `dump-config` (with backward compat alias) 
- **Result**: All commands now use kebab-case consistently

### 2. Flag Standardization

#### Node Commands
- **Added**: `--node` flag as primary way to specify nodes
- **Deprecated**: `--identifier` flag (hidden, marked deprecated)
- **Backward Compatible**: Both flags work, `--identifier` shows deprecation warning
- **Smart Lookup Ready**: `--node` accepts strings for future name/hostname/IP lookup

#### User Commands  
- **Updated**: User identification flow prepared for `--user` flag
- **Maintained**: Existing `--name` and `--identifier` flags for backward compatibility

### 3. Description Consistency
- **Fixed**: "Api" → "API" throughout
- **Fixed**: Capitalization consistency in short descriptions
- **Fixed**: Removed unnecessary periods from short descriptions
- **Standardized**: "Handle/Manage the X of Headscale" pattern

### 4. Type Consistency
- **Standardized**: Node IDs use `uint64` consistently
- **Maintained**: Backward compatibility with existing flag types

## Current Status

### ✅ Completed
- Command naming (kebab-case)
- Flag deprecation and aliasing
- Description standardization  
- Backward compatibility preservation
- Helper functions for flag processing
- **SMART LOOKUP IMPLEMENTATION**:
  - Enhanced `ListNodesRequest` proto with ID, name, hostname, IP filters
  - Implemented smart filtering in `ListNodes` gRPC method
  - Added CLI smart lookup functions for nodes and users
  - Single match validation with helpful error messages
  - Automatic detection: ID (numeric) vs IP vs name/hostname/email

### ✅ Smart Lookup Features
- **Node Lookup**: By ID, hostname, or IP address
- **User Lookup**: By ID, username, or email address  
- **Single Match Enforcement**: Errors if 0 or >1 matches found
- **Helpful Error Messages**: Shows all matches when ambiguous
- **Full Backward Compatibility**: All existing flags still work
- **Enhanced List Commands**: Both `nodes list` and `users list` support all filter types

## Breaking Changes

**None.** All changes maintain full backward compatibility through flag aliases and deprecation warnings.

## Implementation Details

### Smart Lookup Algorithm

1. **Input Detection**:
   ```go
   if numeric && > 0 -> treat as ID
   else if contains "@" -> treat as email (users only)  
   else if valid IP address -> treat as IP (nodes only)
   else -> treat as name/hostname
   ```

2. **gRPC Filtering**:
   - Uses enhanced `ListNodes`/`ListUsers` with specific filters
   - Server-side filtering for optimal performance
   - Single transaction per lookup

3. **Match Validation**:
   - Exactly 1 match: Return ID
   - 0 matches: Error with "not found" message
   - >1 matches: Error listing all matches for disambiguation

### Enhanced Proto Definitions

```protobuf
message ListNodesRequest { 
  string user = 1;           // existing
  uint64 id = 2;            // new: filter by ID
  string name = 3;          // new: filter by hostname  
  string hostname = 4;      // new: alias for name
  repeated string ip_addresses = 5; // new: filter by IPs
}
```

### Future Enhancements

- **Fuzzy Matching**: Partial name matching with confirmation
- **Recently Used**: Cache recently accessed nodes/users
- **Tab Completion**: Shell completion for names/hostnames
- **Bulk Operations**: Multi-select with pattern matching

## Migration Path for Users

### Now Available (Current Release)
```bash
# Old way (still works, shows deprecation warning)
headscale nodes expire --identifier 123

# New way with smart lookup:
headscale nodes expire --node 123                    # by ID
headscale nodes expire --node "my-laptop"           # by hostname  
headscale nodes expire --node "100.64.0.1"          # by Tailscale IP
headscale nodes expire --node "192.168.1.100"       # by real IP

# User operations:
headscale users destroy --user 123                   # by ID
headscale users destroy --user "alice"               # by username
headscale users destroy --user "alice@company.com"   # by email

# Enhanced list commands with filtering:
headscale nodes list --node "laptop"                 # filter nodes by name
headscale nodes list --ip "100.64.0.1"              # filter nodes by IP
headscale nodes list --user "alice"                  # filter nodes by user
headscale users list --user "alice"                  # smart lookup user
headscale users list --email "@company.com"          # filter by email domain
headscale users list --name "alice"                  # filter by exact name

# Error handling examples:
headscale nodes expire --node "laptop"
# Error: multiple nodes found matching 'laptop': ID=1 name=laptop-alice, ID=2 name=laptop-bob

headscale nodes expire --node "nonexistent" 
# Error: no node found matching 'nonexistent'
```

## Command Structure Overview

```
headscale [global-flags] <command> [command-flags] <subcommand> [subcommand-flags] [args]

Global Flags:
  --config, -c     config file path
  --output, -o     output format (json, yaml, json-line)  
  --force          disable prompts

Commands:
├── serve
├── version  
├── config-test
├── dump-config (alias: dumpConfig)
├── mockoidc
├── generate/
│   └── private-key
├── nodes/
│   ├── list (--user, --tags, --columns)
│   ├── register (--user, --key) 
│   ├── list-routes (--node)
│   ├── expire (--node)
│   ├── rename (--node) <new-name>
│   ├── delete (--node)
│   ├── move (--node, --user)
│   ├── tag (--node, --tags)
│   ├── approve-routes (--node, --routes)
│   └── backfill-ips (alias: backfillips)
├── users/
│   ├── create <name> (--display-name, --email, --picture-url)
│   ├── list (--user, --name, --email, --columns)
│   ├── destroy (--user|--name|--identifier)
│   └── rename (--user|--name|--identifier, --new-name)
├── apikeys/
│   ├── list
│   ├── create (--expiration)
│   ├── expire (--prefix)
│   └── delete (--prefix)
├── preauthkeys/
│   ├── list (--user)
│   ├── create (--user, --reusable, --ephemeral, --expiration, --tags)
│   └── expire (--user) <key>
├── policy/
│   ├── get
│   ├── set (--file)
│   └── check (--file)
└── debug/
    └── create-node (--name, --user, --key, --route)
```

## Deprecated Flags

All deprecated flags continue to work but show warnings:

- `--identifier` → use `--node` (for node commands) or `--user` (for user commands)
- `--namespace` → use `--user` (already implemented)
- `dumpConfig` → use `dump-config`
- `backfillips` → use `backfill-ips`

## Error Handling

Improved error messages provide clear guidance:
```
Error: node specifier must be a numeric ID (smart lookup by name/hostname/IP not yet implemented)
Error: --node flag is required  
Error: --user flag is required
```