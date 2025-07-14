# Column Filtering for Table Output

## Overview

All CLI commands that output tables now support a `--columns` flag to customize which columns are displayed.

## Usage

```bash
# Show all default columns
headscale users list

# Show only name and email
headscale users list --columns="name,email"

# Show only ID and username
headscale users list --columns="id,username"

# Show columns in custom order
headscale users list --columns="email,name,id"
```

## Available Columns

### Users List
- `id` - User ID
- `name` - Display name  
- `username` - Username
- `email` - Email address
- `created` - Creation date

### Implementation Pattern

For developers adding this to other commands:

```go
// 1. Add columns flag with default columns
AddColumnsFlag(cmd, "id,name,hostname,ip,status")

// 2. Use ListOutput with TableRenderer
ListOutput(cmd, items, func(tr *TableRenderer) {
    tr.AddColumn("id", "ID", func(item interface{}) string {
        node := item.(*v1.Node)
        return strconv.FormatUint(node.GetId(), 10)
    }).
    AddColumn("name", "Name", func(item interface{}) string {
        node := item.(*v1.Node)
        return node.GetName()
    }).
    AddColumn("hostname", "Hostname", func(item interface{}) string {
        node := item.(*v1.Node)
        return node.GetHostname()
    })
    // ... add more columns
})
```

## Notes

- Column filtering only applies to table output, not JSON/YAML output
- Invalid column names are silently ignored
- Columns appear in the order specified in the --columns flag
- Default columns are defined per command based on most useful information