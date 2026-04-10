// Package testcapture defines the on-disk format used by Headscale's
// policy v2 compatibility tests for golden data captured from
// Tailscale SaaS by the tscap tool.
//
// Files are HuJSON. Wire-format Tailscale data (filter rules, netmap,
// whois, SSH rules) is stored as proper tailcfg/netmap/filtertype/
// apitype values rather than json.RawMessage so that schema drift
// between tscap and headscale becomes a compile error rather than a
// silent test failure, and so that consumers don't have to repeat
// json.Unmarshal at every read site. Storing data as json.RawMessage
// previously hid a serious capture-pipeline bug (the IPN bus initial
// notification returns a stale Peers slice — see the comment on
// Node.Netmap below) for months.
//
// All four corpora (acl, routes, grant, ssh) use the same Capture
// shape. SSH scenarios populate Captures[name].SSHRules; the others
// populate Captures[name].PacketFilterRules + Captures[name].Netmap.
package testcapture

import (
	"bytes"
	"encoding/json"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter/filtertype"
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
//
// Input has a custom UnmarshalJSON to accept both the new on-disk
// shape (where full_policy is a JSON-encoded string) and the legacy
// shape (where full_policy is a JSON object). The legacy shape is
// re-marshaled to a string at load time so consumers see the typed
// field uniformly.
type Input struct {
	// FullPolicy is the verbatim policy that was POSTed to the SaaS
	// API. Stored as a string because it is opaque JSON that round-
	// trips losslessly without parsing — headscale's policy parser
	// reads it on demand.
	FullPolicy string `json:"full_policy"`

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

// MarshalJSON writes FullPolicy as a raw JSON object rather than a
// double-quoted string. Consumers (including via_compat_test.go which
// uses its own local types) expect to parse full_policy as a JSON
// object, not a JSON string. The UnmarshalJSON below accepts both
// forms on read so old and new captures are interchangeable.
func (i Input) MarshalJSON() ([]byte, error) {
	type alias Input

	raw := struct {
		alias

		FullPolicy json.RawMessage `json:"full_policy"`
	}{
		alias: alias(i),
	}

	if i.FullPolicy != "" {
		raw.FullPolicy = json.RawMessage(i.FullPolicy)
	}

	return json.Marshal(raw)
}

// UnmarshalJSON handles both the current on-disk shape (full_policy
// as a JSON-encoded string) and the legacy shape (full_policy as a
// JSON object). Legacy objects are re-marshaled into a string at
// load time so consumers see the typed field uniformly. New captures
// always write the object form via the custom MarshalJSON above.
func (i *Input) UnmarshalJSON(data []byte) error {
	type alias Input

	var raw struct {
		alias

		FullPolicy json.RawMessage `json:"full_policy"`
	}

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	*i = Input(raw.alias)
	// raw.FullPolicy might be a JSON-encoded string ("...") or a JSON
	// object/array/null. Try string first; on failure use the raw bytes
	// verbatim, normalised to compact form.
	if len(raw.FullPolicy) == 0 || string(raw.FullPolicy) == "null" {
		i.FullPolicy = ""
		return nil
	}

	if raw.FullPolicy[0] == '"' {
		var s string

		err := json.Unmarshal(raw.FullPolicy, &s)
		if err != nil {
			return err
		}

		i.FullPolicy = s

		return nil
	}
	// Legacy (and new MarshalJSON output): full_policy is a raw JSON
	// object. Compact whitespace but preserve key ordering so the
	// round-trip is stable.
	var buf bytes.Buffer

	err = json.Compact(&buf, raw.FullPolicy)
	if err != nil {
		return err
	}

	i.FullPolicy = buf.String()

	return nil
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
	// PacketFilterRules is the wire-format filter rules as returned
	// by tailscaled localapi /debug-packet-filter-rules. The single
	// most important field for ACL/routes/grant tests.
	PacketFilterRules []tailcfg.FilterRule `json:"packet_filter_rules,omitempty"`

	// PacketFilterMatches is the compiled filter matches (with
	// CapMatch) returned by tailscaled localapi
	// /debug-packet-filter-matches. Captured alongside
	// PacketFilterRules; useful for grant tests that want the
	// compiled form.
	PacketFilterMatches []filtertype.Match `json:"packet_filter_matches,omitempty"`

	// Netmap is the full netmap as observed by the local tailscaled.
	// NEVER trimmed. Consumers extract whatever fields they need.
	//
	// IMPORTANT: tscap captures this by waiting for the IPN bus to
	// settle on a fresh delta-triggered notification, NOT by reading
	// the WatchIPNBus(NotifyInitialNetMap) initial notification.
	// The initial notification carries cn.NetMap() which returns
	// nb.netMap as-is — the netmap.NetworkMap whose Peers slice was
	// set at full-sync time and never re-synchronized from the
	// authoritative nb.peers map. tscap previously used the initial
	// notification and silently captured netmaps with mostly-empty
	// Peers, which corrupted every via-grant compat test against the
	// stale data. See tscap/tsdaemon/capture.go:NetMap for the
	// stability-wait pattern, and tailscale.com/ipn/ipnlocal/c2n.go
	// :handleC2NDebugNetMap which uses netMapWithPeers() for the
	// same reason.
	Netmap *netmap.NetworkMap `json:"netmap,omitempty"`

	// Whois is per-peer whois lookups, keyed by peer IP. Captured
	// only when scenario.options.capture_whois is true.
	Whois map[string]*apitype.WhoIsResponse `json:"whois,omitempty"`

	// SSHRules is the SSH rules slice extracted from
	// netmap.SSHPolicy.Rules. Populated only for SSH scenarios.
	SSHRules []*tailcfg.SSHRule `json:"ssh_rules,omitempty"`
}
