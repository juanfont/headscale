# CLI Simplification - WithClient Pattern

## Problem
Every CLI command has repetitive gRPC client setup boilerplate:

```go
// This pattern appears 25+ times across all commands
ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
defer cancel()
defer conn.Close()

// ... command logic ...
```

## Solution
Simple closure that handles client lifecycle:

```go
// client.go - 16 lines total
func WithClient(fn func(context.Context, v1.HeadscaleServiceClient) error) error {
	ctx, client, conn, cancel := newHeadscaleCLIWithConfig()
	defer cancel()
	defer conn.Close()
	
	return fn(ctx, client)
}
```

## Usage Example

### Before (users.go listUsersCmd):
```go
Run: func(cmd *cobra.Command, args []string) {
    output, _ := cmd.Flags().GetString("output")
    
    ctx, client, conn, cancel := newHeadscaleCLIWithConfig()  // 4 lines
    defer cancel()
    defer conn.Close()
    
    request := &v1.ListUsersRequest{}
    // ... build request ...
    
    response, err := client.ListUsers(ctx, request)
    if err != nil {
        ErrorOutput(err, "Cannot get users: "+status.Convert(err).Message(), output)
    }
    // ... handle response ...
}
```

### After:
```go
Run: func(cmd *cobra.Command, args []string) {
    output, _ := cmd.Flags().GetString("output")
    
    err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
        request := &v1.ListUsersRequest{}
        // ... build request ...
        
        response, err := client.ListUsers(ctx, request)
        if err != nil {
            ErrorOutput(err, "Cannot get users: "+status.Convert(err).Message(), output)
            return err
        }
        // ... handle response ...
        return nil
    })
    
    if err != nil {
        return  // Error already handled
    }
}
```

## Benefits
- **Removes 4 lines of boilerplate** from every command
- **Ensures proper cleanup** - no forgetting defer statements
- **Simpler error handling** - return from closure, handled centrally
- **Easy to apply** - minimal changes to existing commands

## Rollout
This pattern can be applied to all 25+ commands systematically, removing ~100 lines of repetitive boilerplate.