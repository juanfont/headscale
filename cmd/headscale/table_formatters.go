package main

import (
	"fmt"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/pterm/pterm"
)

// tableStyle returns a consistent table style for all commands
func tableStyle() *pterm.TablePrinter {
	return pterm.DefaultTable.WithHasHeader().WithHeaderRowSeparator("-")
}

// outputTable outputs data in table format based on type
func outputTable(data interface{}) error {
	switch v := data.(type) {
	case []*v1.User:
		return outputUsersTable(v)
	case []*v1.Node:
		return outputNodesTable(v)
	case []*v1.PreAuthKey:
		return outputPreAuthKeysTable(v)
	case []*v1.ApiKey:
		return outputApiKeysTable(v)
	case *v1.User:
		return outputUsersTable([]*v1.User{v})
	case *v1.Node:
		return outputNodesTable([]*v1.Node{v})
	case *v1.PreAuthKey:
		return outputPreAuthKeysTable([]*v1.PreAuthKey{v})
	case *v1.ApiKey:
		return outputApiKeysTable([]*v1.ApiKey{v})
	default:
		// Fallback to JSON for unknown types
		return prettyPrintJSON(v)
	}
}

// outputUsersTable formats users in a table
func outputUsersTable(users []*v1.User) error {
	if len(users) == 0 {
		fmt.Println("No users found")
		return nil
	}

	table := tableStyle()
	data := [][]string{
		{"ID", "Name", "Email", "Provider ID", "Created"},
	}

	for _, user := range users {
		row := []string{
			fmt.Sprintf("%d", user.GetId()),
			user.GetName(),
			user.GetEmail(),
			user.GetProviderId(),
			timestampProtoToString(user.GetCreatedAt()),
		}
		data = append(data, row)
	}

	table.WithData(data)
	return table.Render()
}

// outputNodesTable formats nodes in a table
func outputNodesTable(nodes []*v1.Node) error {
	return outputNodesTableWithOptions(nodes, false)
}

// outputNodesTableWithTags formats nodes in a table including tags
func outputNodesTableWithTags(nodes []*v1.Node) error {
	return outputNodesTableWithOptions(nodes, true)
}

// outputNodesTableWithOptions formats nodes in a table with optional features
func outputNodesTableWithOptions(nodes []*v1.Node, showTags bool) error {
	if len(nodes) == 0 {
		fmt.Println("No nodes found")
		return nil
	}

	table := tableStyle()

	// Build header
	header := []string{"ID", "Name", "User", "IPv4", "IPv6", "Ephemeral", "Last Seen", "Online", "Expired"}
	if showTags {
		header = append(header, "Tags")
	}

	data := [][]string{header}

	for _, node := range nodes {
		// Get IP addresses
		var ipv4, ipv6 string
		for _, ip := range node.GetIpAddresses() {
			if strings.Contains(ip, ":") {
				ipv6 = ip
			} else {
				ipv4 = ip
			}
		}

		// Format last seen
		lastSeen := "Never"
		if node.GetLastSeen() != nil {
			lastSeen = timestampProtoToString(node.GetLastSeen())
		}

		// Build row
		row := []string{
			fmt.Sprintf("%d", node.GetId()),
			node.GetName(),
			node.GetUser().GetName(),
			ipv4,
			ipv6,
			"-", // Ephemeral field not available in this API version
			lastSeen,
			fmt.Sprintf("%t", node.GetOnline()),
			fmt.Sprintf("%t", node.GetExpiry() != nil && node.GetExpiry().AsTime().Before(time.Now())),
		}

		if showTags {
			tags := strings.Join(node.GetForcedTags(), ", ")
			if tags == "" {
				tags = "-"
			}
			row = append(row, tags)
		}

		data = append(data, row)
	}

	table.WithData(data)
	return table.Render()
}

// outputPreAuthKeysTable formats preauth keys in a table
func outputPreAuthKeysTable(keys []*v1.PreAuthKey) error {
	if len(keys) == 0 {
		fmt.Println("No preauth keys found")
		return nil
	}

	table := tableStyle()
	data := [][]string{
		{"ID", "Key", "User", "Reusable", "Ephemeral", "Used", "Expiration", "Created", "Tags"},
	}

	for _, key := range keys {
		// Format expiration
		expiration := "Never"
		if key.GetExpiration() != nil {
			expiration = timestampProtoToString(key.GetExpiration())
		}

		// Format tags
		tags := strings.Join(key.GetAclTags(), ", ")
		if tags == "" {
			tags = "-"
		}

		row := []string{
			fmt.Sprintf("%d", key.GetId()),
			key.GetKey(),
			key.GetUser().GetName(),
			fmt.Sprintf("%t", key.GetReusable()),
			fmt.Sprintf("%t", key.GetEphemeral()),
			fmt.Sprintf("%t", key.GetUsed()),
			expiration,
			timestampProtoToString(key.GetCreatedAt()),
			tags,
		}
		data = append(data, row)
	}

	table.WithData(data)
	return table.Render()
}

// outputApiKeysTable formats API keys in a table
func outputApiKeysTable(keys []*v1.ApiKey) error {
	if len(keys) == 0 {
		fmt.Println("No API keys found")
		return nil
	}

	table := tableStyle()
	data := [][]string{
		{"ID", "Prefix", "Expiration", "Created", "Last Seen"},
	}

	for _, key := range keys {
		// Format expiration
		expiration := "Never"
		if key.GetExpiration() != nil {
			expiration = timestampProtoToString(key.GetExpiration())
		}

		// Format last seen
		lastSeen := "Never"
		if key.GetLastSeen() != nil {
			lastSeen = timestampProtoToString(key.GetLastSeen())
		}

		row := []string{
			fmt.Sprintf("%d", key.GetId()),
			key.GetPrefix(),
			expiration,
			timestampProtoToString(key.GetCreatedAt()),
			lastSeen,
		}
		data = append(data, row)
	}

	table.WithData(data)
	return table.Render()
}

// outputRoutesTable formats routes in a table
func outputRoutesTable(routes []string) error {
	if len(routes) == 0 {
		fmt.Println("No routes found")
		return nil
	}

	table := tableStyle()
	data := [][]string{
		{"Route", "Status"},
	}

	for _, route := range routes {
		row := []string{
			route,
			"Enabled", // Default status, could be enhanced with actual route status
		}
		data = append(data, row)
	}

	table.WithData(data)
	return table.Render()
}

// outputPolicyTable formats policy information
func outputPolicyTable(policy interface{}) error {
	// For policy, we'll use JSON output as it's complex nested data
	return prettyPrintJSON(policy)
}

// Helper function to format timestamps consistently
func timestampProtoToString(ts interface{}) string {
	if ts == nil {
		return "-"
	}

	// Handle different timestamp types that might be passed
	switch t := ts.(type) {
	case interface{ AsTime() time.Time }:
		return t.AsTime().Format("2006-01-02 15:04:05")
	case *time.Time:
		if t == nil {
			return "-"
		}
		return t.Format("2006-01-02 15:04:05")
	case time.Time:
		return t.Format("2006-01-02 15:04:05")
	default:
		return fmt.Sprintf("%v", ts)
	}
}

// formatDuration formats a duration string in a human-readable way
func formatDuration(duration string) string {
	if duration == "" {
		return "Never"
	}

	d, err := time.ParseDuration(duration)
	if err != nil {
		return duration // Return as-is if can't parse
	}

	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	} else {
		return fmt.Sprintf("%.1fd", d.Hours()/24)
	}
}

// formatFileSize formats bytes in a human-readable way
func formatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// truncateString truncates a string to a maximum length with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// formatBoolAsYesNo formats a boolean as Yes/No instead of true/false
func formatBoolAsYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// formatStringSlice formats a string slice as a comma-separated list
func formatStringSlice(slice []string, maxItems int) string {
	if len(slice) == 0 {
		return "-"
	}

	if len(slice) <= maxItems {
		return strings.Join(slice, ", ")
	}

	result := strings.Join(slice[:maxItems], ", ")
	return fmt.Sprintf("%s... (+%d more)", result, len(slice)-maxItems)
}
