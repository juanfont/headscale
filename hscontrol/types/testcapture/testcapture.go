// Package testcapture defines the on-disk format used by Headscale's
// policy v2 compatibility tests for golden data captured from
// Tailscale SaaS by the tscap tool.
//
// Files are HuJSON. The package intentionally does not import
// tailscale.com/tailcfg so it can live under hscontrol/types/
// without dragging extra dependencies. Wire-format Tailscale data
// (filter rules, netmap, whois, SSH rules) is stored as
// json.RawMessage; consumers json.Unmarshal into the typed shape
// they need.
//
// All four corpora (acl, routes, grant, ssh) use the same Capture
// shape. SSH scenarios populate Captures[name].SSHRules; the others
// populate Captures[name].PacketFilterRules + Captures[name].Netmap.
package testcapture

import (
	"encoding/json"
	"time"
)

// SchemaVersion identifies the on-disk format. Bumped on breaking changes.
//
// Files written before SchemaVersion existed do not have this field; new
// captures from tscap always set it to the current value.
const SchemaVersion = 1

// Capture is one captured run of one scenario.
//
// All four corpora (acl, routes, grant, ssh) use this same shape.
// SSH scenarios populate Captures[name].SSHRules; the others populate
// Captures[name].PacketFilterRules + Captures[name].Netmap.
type Capture struct {
	// SchemaVersion identifies the on-disk format version. Always set
	// to testcapture.SchemaVersion when written by tscap.
	SchemaVersion int `json:"schema_version"`

	// TestID is the stable identifier of the scenario, derived from
	// its filename. Used as the test name in Go tests.
	TestID string `json:"test_id"`

	// Description is free-form text copied from the scenario file.
	// Rendered in the comment header at the top of the file.
	Description string `json:"description,omitempty"`

	// Category is an optional grouping label (e.g. "routes",
	// "grant", "ssh").
	Category string `json:"category,omitempty"`

	// CapturedAt is the UTC timestamp of when the capture was taken.
	CapturedAt time.Time `json:"captured_at"`

	// ToolVersion identifies the binary that produced the file.
	ToolVersion string `json:"tool_version"`

	// Tailnet is the name of the SaaS tailnet the capture was taken
	// against (e.g. "kratail2tid@passkey").
	Tailnet string `json:"tailnet"`

	// Error is true when the SaaS API rejected the policy or when
	// capture itself failed. In the rejection case, Captures reflects
	// the pre-push baseline (deny-all default) and Input.APIResponseBody
	// is populated.
	Error bool `json:"error,omitempty"`

	// CaptureError is set when the capture itself failed (timeout,
	// missing data, etc.). The partially-captured Captures map is
	// still included for post-mortem. Distinct from
	// Input.APIResponseBody which describes a SaaS API rejection.
	CaptureError string `json:"capture_error,omitempty"`

	// Input is everything that was sent to the tailnet to produce
	// the captured state.
	Input Input `json:"input"`

	// Topology is the users and nodes present in the tailnet at
	// capture time. Always populated by tscap.
	Topology Topology `json:"topology"`

	// Captures holds the per-node captured data, keyed by node
	// GivenName.
	Captures map[string]Node `json:"captures"`
}

// Input describes everything that was sent to the tailnet to produce
// the captured state.
type Input struct {
	// FullPolicy is the verbatim policy that was POSTed to the SaaS
	// API. Stored as raw JSON so it round-trips losslessly.
	FullPolicy json.RawMessage `json:"full_policy"`

	// APIResponseCode is the HTTP status code of the policy POST.
	APIResponseCode int `json:"api_response_code"`

	// APIResponseBody is only populated when APIResponseCode != 200.
	APIResponseBody *APIResponseBody `json:"api_response_body,omitempty"`

	// Tailnet describes the tailnet-wide settings tscap applied
	// before pushing the policy.
	Tailnet TailnetInput `json:"tailnet"`

	// ScenarioHuJSON is the verbatim contents of the scenario file
	// (HuJSON). Reading this back is enough to re-run the exact
	// same scenario.
	ScenarioHuJSON string `json:"scenario_hujson"`

	// ScenarioPath is the path the scenario was loaded from,
	// relative to the captures directory. Informational only.
	ScenarioPath string `json:"scenario_path,omitempty"`
}

// APIResponseBody is the (subset of) the SaaS API error response we keep.
type APIResponseBody struct {
	Message string `json:"message,omitempty"`
}

// TailnetInput captures tailnet-wide settings tscap applied before
// pushing the policy.
type TailnetInput struct {
	DNS      DNSInput      `json:"dns"`
	Settings SettingsInput `json:"settings"`
}

// DNSInput describes the DNS configuration applied to the tailnet.
type DNSInput struct {
	MagicDNS    bool                `json:"magic_dns"`
	Nameservers []string            `json:"nameservers"`
	SearchPaths []string            `json:"search_paths"`
	SplitDNS    map[string][]string `json:"split_dns"`
}

// SettingsInput describes tailnet settings applied via the API.
//
// Pointer fields are nil when the scenario does not override the
// reset default for that setting.
type SettingsInput struct {
	DevicesApprovalOn      *bool `json:"devices_approval_on,omitempty"`
	DevicesAutoUpdatesOn   *bool `json:"devices_auto_updates_on,omitempty"`
	DevicesKeyDurationDays *int  `json:"devices_key_duration_days,omitempty"`
}

// Topology describes the users and nodes present in the tailnet at
// capture time. Headscale's compat tests use this to construct
// equivalent types.User and types.Node objects.
type Topology struct {
	// Users in the tailnet. Always populated by tscap.
	Users []TopologyUser `json:"users"`

	// Nodes in the tailnet, keyed by GivenName.
	Nodes map[string]TopologyNode `json:"nodes"`
}

// TopologyUser identifies one user account in the tailnet.
type TopologyUser struct {
	ID    uint   `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

// TopologyNode is one node in the tailnet topology.
type TopologyNode struct {
	Hostname string   `json:"hostname"`
	Tags     []string `json:"tags"`
	IPv4     string   `json:"ipv4"`
	IPv6     string   `json:"ipv6"`

	// User is the TopologyUser.Name for user-owned nodes. Empty for
	// tagged nodes.
	User string `json:"user,omitempty"`

	// RoutableIPs is what the node advertised
	// (Hostinfo.RoutableIPs in its own netmap.SelfNode).
	// May include 0.0.0.0/0 + ::/0 for exit nodes.
	RoutableIPs []string `json:"routable_ips"`

	// ApprovedRoutes is the subset of RoutableIPs the tailnet has
	// approved. Used by Headscale's NodeCanApproveRoute test.
	ApprovedRoutes []string `json:"approved_routes"`
}

// Node is the captured state for one node, keyed by GivenName in
// Capture.Captures.
//
// All four corpora populate the same struct. Different fields are
// used by different test types:
//
//   - acl, routes, grant: PacketFilterRules + PacketFilterMatches + Netmap
//   - grant (with capture_whois): + Whois
//   - ssh: SSHRules
//
// Whichever fields are set in the file is what the consumer reads.
type Node struct {
	// PacketFilterRules is the wire-format []tailcfg.FilterRule as
	// returned by tailscaled localapi /debug-packet-filter-rules.
	// The single most important field for ACL/routes/grant tests.
	PacketFilterRules json.RawMessage `json:"packet_filter_rules,omitempty"`

	// PacketFilterMatches is the compiled []filtertype.Match with
	// CapMatch, returned by tailscaled localapi
	// /debug-packet-filter-matches. Captured alongside
	// PacketFilterRules; useful for grant tests that want the
	// compiled form.
	PacketFilterMatches json.RawMessage `json:"packet_filter_matches,omitempty"`

	// Netmap is the full netmap as returned by tailscaled localapi
	// /watch-ipn-bus?mask=NotifyInitialNetMap. NEVER trimmed.
	// Consumers extract whatever fields they need.
	Netmap json.RawMessage `json:"netmap,omitempty"`

	// Whois is per-peer whois lookups, keyed by peer IP. Each value
	// is the verbatim WhoIsResponse JSON returned by
	// /localapi/v0/whois. Captured only when
	// scenario.options.capture_whois is true.
	Whois map[string]json.RawMessage `json:"whois,omitempty"`

	// SSHRules is the SSH rules for SSH corpus. Same shape as
	// tailcfg.SSHPolicy.Rules ([]tailcfg.SSHRule), kept as raw JSON.
	// Populated only for SSH scenarios.
	SSHRules json.RawMessage `json:"ssh_rules,omitempty"`
}
