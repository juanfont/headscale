package testcapture_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

func sampleACLCapture() *testcapture.Capture {
	rules := []tailcfg.FilterRule{
		{
			SrcIPs: []string{"*"},
			DstPorts: []tailcfg.NetPortRange{
				{IP: "*", Ports: tailcfg.PortRangeAny},
			},
		},
	}
	nm := &netmap.NetworkMap{
		SelfNode: (&tailcfg.Node{Name: "user1.tail.example.com."}).View(),
	}

	return &testcapture.Capture{
		SchemaVersion: testcapture.SchemaVersion,
		TestID:        "ACL-A01",
		Description:   "wildcard ACL: every node sees every other node",
		Category:      "acl",
		CapturedAt:    time.Date(2026, 4, 7, 12, 34, 56, 0, time.UTC),
		ToolVersion:   "tscap-test-0.0.0",
		Tailnet:       "kratail2tid@passkey",
		Input: testcapture.Input{
			FullPolicy:      `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
			APIResponseCode: 200,
			Tailnet: testcapture.TailnetInput{
				DNS: testcapture.DNSInput{
					MagicDNS:    false,
					Nameservers: []string{},
					SearchPaths: []string{},
					SplitDNS:    map[string][]string{},
				},
			},
			ScenarioHuJSON: `{"id":"acl-a01","policy":{}}`,
			ScenarioPath:   "scenarios/acl/acl-a01.hujson",
		},
		Topology: testcapture.Topology{
			Users: []testcapture.TopologyUser{
				{ID: 1, Name: "kratail2tid", Email: "kratail2tid@passkey"},
				{ID: 2, Name: "kristoffer", Email: "kristoffer@dalby.cc"},
			},
			Nodes: map[string]testcapture.TopologyNode{
				"user1": {
					Hostname:       "user1",
					IPv4:           "100.90.199.68",
					IPv6:           "fd7a:115c:a1e0::2d01:c747",
					User:           "kratail2tid",
					RoutableIPs:    []string{},
					ApprovedRoutes: []string{},
				},
				"tagged-server": {
					Hostname:       "tagged-server",
					Tags:           []string{"tag:server"},
					IPv4:           "100.108.74.26",
					IPv6:           "fd7a:115c:a1e0::b901:4a87",
					RoutableIPs:    []string{},
					ApprovedRoutes: []string{},
				},
			},
		},
		Captures: map[string]testcapture.Node{
			"user1": {
				PacketFilterRules: rules,
				Netmap:            nm,
			},
			"tagged-server": {
				PacketFilterRules: rules,
				Netmap:            nm,
			},
		},
	}
}

func sampleSSHCapture() *testcapture.Capture {
	sshRules := []*tailcfg.SSHRule{
		{
			Action:     &tailcfg.SSHAction{Accept: true},
			Principals: []*tailcfg.SSHPrincipal{{NodeIP: "100.90.199.68"}},
			SSHUsers:   map[string]string{"root": "root"},
		},
	}

	return &testcapture.Capture{
		SchemaVersion: testcapture.SchemaVersion,
		TestID:        "SSH-A01",
		Description:   "ssh accept autogroup:member to autogroup:self",
		Category:      "ssh",
		CapturedAt:    time.Date(2026, 4, 7, 13, 0, 0, 0, time.UTC),
		ToolVersion:   "tscap-test-0.0.0",
		Tailnet:       "kratail2tid@passkey",
		Input: testcapture.Input{
			FullPolicy:      `{"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}]}`,
			APIResponseCode: 200,
			Tailnet: testcapture.TailnetInput{
				DNS: testcapture.DNSInput{
					Nameservers: []string{},
					SearchPaths: []string{},
					SplitDNS:    map[string][]string{},
				},
			},
			ScenarioHuJSON: `{"id":"ssh-a01"}`,
		},
		Topology: testcapture.Topology{
			Users: []testcapture.TopologyUser{
				{ID: 1, Name: "kratail2tid", Email: "kratail2tid@passkey"},
			},
			Nodes: map[string]testcapture.TopologyNode{
				"user1": {
					Hostname:       "user1",
					IPv4:           "100.90.199.68",
					IPv6:           "fd7a:115c:a1e0::2d01:c747",
					User:           "kratail2tid",
					RoutableIPs:    []string{},
					ApprovedRoutes: []string{},
				},
			},
		},
		Captures: map[string]testcapture.Node{
			"user1": {SSHRules: sshRules},
		},
	}
}

// equalViaJSON compares two captures by JSON-marshaling them and
// comparing the bytes. The Capture struct embeds tailcfg view types
// with unexported pointer fields that go-cmp can't traverse, so a
// JSON round-trip is the simplest way to verify Write+Read produced
// equivalent values.
func equalViaJSON(t *testing.T, want, got *testcapture.Capture) {
	t.Helper()

	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}

	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}

	if string(wantJSON) != string(gotJSON) {
		t.Errorf("roundtrip mismatch\n--- want ---\n%s\n--- got ---\n%s",
			string(wantJSON), string(gotJSON))
	}
}

func TestWriteReadRoundtrip_ACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ACL-A01.hujson")

	in := sampleACLCapture()

	err := testcapture.Write(path, in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := testcapture.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	equalViaJSON(t, in, out)
}

func TestWriteReadRoundtrip_SSH(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SSH-A01.hujson")

	in := sampleSSHCapture()

	err := testcapture.Write(path, in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := testcapture.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	equalViaJSON(t, in, out)
}

func TestWrite_ProducesCommentHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ACL-A01.hujson")

	c := sampleACLCapture()

	err := testcapture.Write(path, c)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 {
		t.Fatal("file is empty")
	}

	// First line should be the test ID prefixed with "// ".
	if want := "// ACL-A01"; lines[0] != want {
		t.Errorf("first line: want %q, got %q", want, lines[0])
	}

	header := strings.Join(extractHeaderLines(lines), "\n")
	if !strings.Contains(header, "wildcard ACL") {
		t.Errorf("header missing description; got:\n%s", header)
	}

	if !strings.Contains(header, "Nodes with filter rules: 2 of 2") {
		t.Errorf("header missing stats line; got:\n%s", header)
	}

	if !strings.Contains(header, "Captured at:") || !strings.Contains(header, "2026-04-07T12:34:56Z") {
		t.Errorf("header missing capture timestamp; got:\n%s", header)
	}

	if !strings.Contains(header, "tscap version:") || !strings.Contains(header, "tscap-test-0.0.0") {
		t.Errorf("header missing tool version; got:\n%s", header)
	}

	if !strings.Contains(header, "schema version: 1") {
		t.Errorf("header missing schema version; got:\n%s", header)
	}
}

func TestWrite_SSH_StatsUseSSHRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "SSH-A01.hujson")

	c := sampleSSHCapture()

	err := testcapture.Write(path, c)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	header := strings.Join(extractHeaderLines(strings.Split(string(raw), "\n")), "\n")
	if !strings.Contains(header, "Nodes with SSH rules: 1 of 1") {
		t.Errorf("ssh stats line missing; got:\n%s", header)
	}
}

func TestRead_HuJSONWithComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.hujson")

	const content = `// hand-written
// comments + trailing commas
{
    "schema_version": 1,
    "test_id": "MANUAL",
    "captured_at": "2026-04-07T12:00:00Z",
    "tool_version": "test",
    "tailnet": "example.com",
    "input": {
        "full_policy": "{}",
        "api_response_code": 200,
        "tailnet": {
            "dns": {
                "magic_dns": false,
                "nameservers": [],
                "search_paths": [],
                "split_dns": {},
            },
            "settings": {},
        },
        "scenario_hujson": "",
    },
    "topology": {
        "users": [],
        "nodes": {},
    },
    "captures": {},
}
`

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, err := testcapture.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if c.TestID != "MANUAL" {
		t.Errorf("TestID = %q, want MANUAL", c.TestID)
	}

	if c.SchemaVersion != testcapture.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", c.SchemaVersion, testcapture.SchemaVersion)
	}
}

func TestRead_RejectsNewerSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "future.hujson")

	content := fmt.Sprintf(`{
	    "schema_version": %d,
	    "test_id": "FUTURE",
	    "captured_at": "2099-01-01T00:00:00Z",
	    "tool_version": "future",
	    "tailnet": "example.com",
	    "input": {
	        "full_policy": "{}",
	        "api_response_code": 200,
	        "tailnet": {
	            "dns": {"magic_dns": false, "nameservers": [], "search_paths": [], "split_dns": {}},
	            "settings": {}
	        },
	        "scenario_hujson": ""
	    },
	    "topology": {"users": [], "nodes": {}},
	    "captures": {}
	}`, testcapture.SchemaVersion+1)

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = testcapture.Read(path)
	if !errors.Is(err, testcapture.ErrUnsupportedSchemaVersion) {
		t.Fatalf("Read(future-schema) = %v, want ErrUnsupportedSchemaVersion", err)
	}
}

func TestWrite_NilCapture(t *testing.T) {
	err := testcapture.Write(filepath.Join(t.TempDir(), "x.hujson"), nil)
	if err == nil {
		t.Fatal("Write(nil) returned nil error, want error")
	}
}

func TestCommentHeader_NilSafe(t *testing.T) {
	if got := testcapture.CommentHeader(nil); got != "" {
		t.Errorf("CommentHeader(nil) = %q, want empty", got)
	}
}

func TestCommentHeader_ZeroTime(t *testing.T) {
	c := &testcapture.Capture{TestID: "ZERO"}
	got := testcapture.CommentHeader(c)

	if strings.Contains(got, "Captured at") {
		t.Errorf("zero time should not produce 'Captured at': %q", got)
	}

	if !strings.HasPrefix(got, "ZERO") {
		t.Errorf("header should start with TestID: %q", got)
	}
}

func TestCommentHeader_NoStatsForEmptyCaptures(t *testing.T) {
	c := &testcapture.Capture{TestID: "EMPTY"}

	header := testcapture.CommentHeader(c)
	if strings.Contains(header, "filter rules") || strings.Contains(header, "SSH rules") {
		t.Errorf("empty captures should not produce stats line: %q", header)
	}
}

func TestCommentHeader_EmptyFilterRulesCountAsEmpty(t *testing.T) {
	// Mixed: nil, empty slice, and one populated rule. Only the
	// populated entry should be counted in the "filter rules" stat.
	c := &testcapture.Capture{
		TestID: "NULLS",
		Captures: map[string]testcapture.Node{
			"a": {PacketFilterRules: nil},
			"b": {PacketFilterRules: []tailcfg.FilterRule{}},
			"c": {PacketFilterRules: []tailcfg.FilterRule{{SrcIPs: []string{"*"}}}},
		},
	}

	header := testcapture.CommentHeader(c)
	// Only "b" and "c" are non-nil, so the capture is detected as
	// "filter rules" — and only "c" actually has rules. With the new
	// typed semantics, b's empty slice still counts as "set" (not
	// nil), so the denominator is 2 of 3 capture entries that have
	// any filter-rules slice at all, and 1 of those is populated.
	if !strings.Contains(header, "Nodes with filter rules: 1 of 3") {
		t.Errorf("expected '1 of 3' in header; got:\n%s", header)
	}
}

// TestInputUnmarshal_LegacyObjectForm asserts that a legacy capture
// file written with full_policy as a raw JSON object (not a
// JSON-encoded string) still deserialises into a valid Input, with
// the policy re-marshaled to a compact string so downstream consumers
// see a uniform typed field.
func TestInputUnmarshal_LegacyObjectForm(t *testing.T) {
	legacy := []byte(`{
		"full_policy": {"tagOwners": {"tag:ops": ["user@example.com"]}},
		"api_response_code": 200,
		"tailnet": {"name": "corp", "dnsConfig": {}},
		"scenario_hujson": "",
		"scenario_path": ""
	}`)

	var got testcapture.Input

	err := json.Unmarshal(legacy, &got)
	if err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}

	if got.APIResponseCode != 200 {
		t.Errorf("APIResponseCode: got %d, want 200", got.APIResponseCode)
	}

	want := `{"tagOwners":{"tag:ops":["user@example.com"]}}`
	if got.FullPolicy != want {
		t.Errorf("FullPolicy:\n got %q\nwant %q", got.FullPolicy, want)
	}

	// Round-trip: the new MarshalJSON must emit the object form so
	// UnmarshalJSON re-reads it identically.
	out, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	var back testcapture.Input

	err = json.Unmarshal(out, &back)
	if err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}

	if back.FullPolicy != want {
		t.Errorf("round-trip FullPolicy drift:\n got %q\nwant %q", back.FullPolicy, want)
	}
}

// extractHeaderLines returns the leading "// ..." comment lines from a
// slice of raw file lines, stripped of the "// " prefix. Stops at the
// first non-comment line.
func extractHeaderLines(lines []string) []string {
	var out []string

	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "// "):
			out = append(out, strings.TrimPrefix(l, "// "))
		case l == "//":
			out = append(out, "")
		default:
			return out
		}
	}

	return out
}
