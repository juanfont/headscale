package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// markerPrefix tags the machine-readable footer of a bot-authored pull request
// body. It is the bot's only persistent state: everything else is rebuilt from
// the base branch on every run.
const markerPrefix = "<!-- versionbump:v1 "

// marker records what a run produced, so the next run can tell "nothing new"
// from "the same change, already rejected".
type marker struct {
	Tree  string            `json:"tree"`
	Head  string            `json:"head"`
	Areas map[string]string `json:"areas"`
}

func (m marker) render() string {
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}

	return markerPrefix + string(b) + " -->"
}

// parseMarker recovers the marker from a pull request body. A body without one
// was not written by this tool.
func parseMarker(body string) (marker, bool) {
	_, rest, ok := strings.Cut(body, markerPrefix)
	if !ok {
		return marker{}, false
	}

	payload, _, ok := strings.Cut(rest, " -->")
	if !ok {
		return marker{}, false
	}

	var m marker

	err := json.Unmarshal([]byte(payload), &m)
	if err != nil {
		return marker{}, false
	}

	return m, true
}

func markerOf(results []result, tree, head string) marker {
	areas := make(map[string]string, len(results))
	for _, res := range results {
		areas[res.Area] = string(res.State)
	}

	return marker{Tree: tree, Head: head, Areas: areas}
}

// renderBody writes the pull request body. It leads with what landed and what
// did not, because the point of the bot is that the reader can decide from the
// body plus the checks without reproducing the run.
func renderBody(results []result, m marker, gate string) string {
	var sb strings.Builder

	sb.WriteString("Automated version bump.\n\n")
	sb.WriteString("| Area | Result | Change |\n|---|---|---|\n")

	for _, res := range results {
		summary := res.Change.Summary
		if summary == "" {
			summary = res.Reason
		}

		fmt.Fprintf(&sb, "| `%s` | %s | %s |\n", res.Area, res.State, cell(summary))
	}

	writeDetails(&sb, results)
	writeDropped(&sb, results)

	sb.WriteString("\n")
	sb.WriteString(gateNote(gate))
	sb.WriteString("\n")
	sb.WriteString(m.render())
	sb.WriteString("\n")

	return sb.String()
}

func writeDetails(sb *strings.Builder, results []result) {
	var opened bool

	for _, res := range results {
		if len(res.Change.Detail) == 0 {
			continue
		}

		if !opened {
			sb.WriteString("\n<details><summary>What moved</summary>\n\n")

			opened = true
		}

		fmt.Fprintf(sb, "**%s**\n\n", res.Area)

		for _, line := range res.Change.Detail {
			fmt.Fprintf(sb, "- %s\n", line)
		}

		sb.WriteString("\n")
	}

	if opened {
		sb.WriteString("</details>\n")
	}
}

func writeDropped(sb *strings.Builder, results []result) {
	var opened bool

	open := func() {
		if !opened {
			sb.WriteString("\n### Dropped\n\n")

			opened = true
		}
	}

	for _, res := range results {
		if res.State == stateDropped {
			open()
			fmt.Fprintf(sb, "- **`%s`** — %s\n", res.Area, res.Reason)
			writeLog(sb, res.Log)
		}

		for _, d := range res.Change.Drops {
			open()
			fmt.Fprintf(sb, "- **`%s`** (in `%s`) — %s\n", d.Name, res.Area, d.Reason)
			writeLog(sb, d.Log)
		}
	}
}

func writeLog(sb *strings.Builder, log string) {
	if log == "" {
		return
	}

	sb.WriteString("\n  ```\n")

	for line := range strings.Lines(log) {
		fmt.Fprintf(sb, "  %s", line)
	}

	sb.WriteString("\n  ```\n")
}

// gateNote says what the bump job did and did not already run, so the reader
// knows how much of the green tick below is new information.
func gateNote(gate string) string {
	switch gate {
	case gateFull:
		return "The nix checks and the tailscale builder images were already run in the bump job; " +
			"the integration matrix is left to this pull request's own CI.\n"
	case gateQuick:
		return "Only `nix build .#checks.<system>.build` was run in the bump job; " +
			"everything else is left to this pull request's own CI.\n"
	default:
		return "No gate was run in the bump job; every check below is the first one.\n"
	}
}

// cell keeps a markdown table cell from breaking the table.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")

	const maxCell = 160

	runes := []rune(s)
	if len(runes) > maxCell {
		s = string(runes[:maxCell]) + "…"
	}

	if s == "" {
		return "—"
	}

	return s
}

// changedAreas reports whether the outcome differs from the last run, which is
// what decides between silently updating the pull request and commenting on it.
func changedAreas(prev marker, now marker) bool {
	if len(prev.Areas) != len(now.Areas) {
		return true
	}

	for name, st := range now.Areas {
		if prev.Areas[name] != st {
			return true
		}
	}

	return false
}
