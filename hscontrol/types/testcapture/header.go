package testcapture

import (
	"fmt"
	"strings"
)

// CommentHeader returns the // comment header that gets prepended to
// a Capture file when it is written. The header is purely
// informational; consumers ignore it. Format:
//
//	<TestID>
//
//	<Description, possibly multi-line>
//
//	Nodes with filter rules: <X> of <Y>           ← for non-SSH captures
//	Nodes with SSH rules: <X> of <Y>              ← for SSH captures
//	Captured at:    <RFC3339 UTC>
//	tscap version:  <ToolVersion>
//	schema version: <SchemaVersion>
//
// Both `tool_version` and `schema_version` are also stored as
// first-class JSON fields on the Capture struct; the comment lines
// exist purely so the values are visible at a glance without
// parsing the file.
//
// The leading "// " on every line is added by the hujson writer.
func CommentHeader(c *Capture) string {
	if c == nil {
		return ""
	}

	var b strings.Builder

	b.WriteString(c.TestID)
	b.WriteByte('\n')

	if c.Description != "" {
		b.WriteByte('\n')
		b.WriteString(c.Description)
		b.WriteByte('\n')
	}

	stats := captureStats(c)
	if stats != "" {
		b.WriteByte('\n')
		b.WriteString(stats)
		b.WriteByte('\n')
	}

	if !c.CapturedAt.IsZero() {
		fmt.Fprintf(&b, "Captured at:    %s\n", c.CapturedAt.UTC().Format("2006-01-02T15:04:05Z"))
	}

	if c.ToolVersion != "" {
		fmt.Fprintf(&b, "tscap version:  %s\n", c.ToolVersion)
	}

	if c.SchemaVersion != 0 {
		fmt.Fprintf(&b, "schema version: %d\n", c.SchemaVersion)
	}

	return strings.TrimRight(b.String(), "\n")
}

// captureStats returns a one-line summary of how many nodes had
// non-empty captured data, or the empty string if there are no
// captures at all.
//
// The phrasing depends on which fields the capture uses:
//   - SSH captures populate SSHRules
//   - other captures populate PacketFilterRules
//
// If both fields appear (mixed/unusual), filter rules wins.
func captureStats(c *Capture) string {
	if len(c.Captures) == 0 {
		return ""
	}

	var (
		total          = len(c.Captures)
		filterRules    int
		sshRules       int
		filterRulesSet bool
		sshRulesSet    bool
	)

	for _, n := range c.Captures {
		if n.PacketFilterRules != nil {
			filterRulesSet = true

			if len(n.PacketFilterRules) > 0 {
				filterRules++
			}
		}

		if n.SSHRules != nil {
			sshRulesSet = true

			if len(n.SSHRules) > 0 {
				sshRules++
			}
		}
	}

	switch {
	case filterRulesSet:
		return fmt.Sprintf("Nodes with filter rules: %d of %d", filterRules, total)
	case sshRulesSet:
		return fmt.Sprintf("Nodes with SSH rules: %d of %d", sshRules, total)
	default:
		return ""
	}
}
