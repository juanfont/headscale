package testcapture_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
)

func sampleACLCapture() *testcapture.Capture {
	policy := json.RawMessage(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)
	rules := json.RawMessage(`[
        {
            "SrcIPs": ["*"],
            "DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}]
        }
    ]`)
	netmap := json.RawMessage(`{"SelfNode":{"Name":"user1.tail.example.com."}}`)

	return &testcapture.Capture{
		SchemaVersion: testcapture.SchemaVersion,
		TestID:        "ACL-A01",
		Description:   "wildcard ACL: every node sees every other node",
		Category:      "acl",
		CapturedAt:    time.Date(2026, 4, 7, 12, 34, 56, 0, time.UTC),
		ToolVersion:   "tscap-test-0.0.0",
		Tailnet:       "kratail2tid@passkey",
		Input: testcapture.Input{
			FullPolicy:      policy,
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
				Netmap:            netmap,
			},
			"tagged-server": {
				PacketFilterRules: rules,
				Netmap:            netmap,
			},
		},
	}
}

func sampleSSHCapture() *testcapture.Capture {
	policy := json.RawMessage(`{"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}]}`)
	sshRules := json.RawMessage(`[{"action":{"accept":true},"principals":[{"nodeIP":"100.90.199.68"}],"sshUsers":{"root":"root"}}]`)

	return &testcapture.Capture{
		SchemaVersion: testcapture.SchemaVersion,
		TestID:        "SSH-A01",
		Description:   "ssh accept autogroup:member to autogroup:self",
		Category:      "ssh",
		CapturedAt:    time.Date(2026, 4, 7, 13, 0, 0, 0, time.UTC),
		ToolVersion:   "tscap-test-0.0.0",
		Tailnet:       "kratail2tid@passkey",
		Input: testcapture.Input{
			FullPolicy:      policy,
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

// jsonRawMessageEqual is a cmp.Comparer that treats two json.RawMessage
// values as equal if they decode to the same value. This avoids false
// negatives from indentation/whitespace differences after hujson formats
// the embedded raw blobs.
func jsonRawMessageEqual(a, b json.RawMessage) bool {
	var va, vb any

	err := json.Unmarshal(a, &va)
	if err != nil {
		return string(a) == string(b)
	}

	err = json.Unmarshal(b, &vb)
	if err != nil {
		return string(a) == string(b)
	}

	// Both va and vb came from successful Unmarshal, so they're guaranteed to
	// re-marshal cleanly. The error returns here are for the linter; we treat
	// them as bytewise inequality if they ever fire.
	ja, jaErr := json.Marshal(va)
	jb, jbErr := json.Marshal(vb)

	if jaErr != nil || jbErr != nil {
		return string(a) == string(b)
	}

	return string(ja) == string(jb)
}

func captureCompareOpts() []cmp.Option {
	return []cmp.Option{
		cmp.Comparer(jsonRawMessageEqual),
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

	if diff := cmp.Diff(in, out, captureCompareOpts()...); diff != "" {
		t.Errorf("ACL roundtrip mismatch (-want +got):\n%s", diff)
	}
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

	if diff := cmp.Diff(in, out, captureCompareOpts()...); diff != "" {
		t.Errorf("SSH roundtrip mismatch (-want +got):\n%s", diff)
	}
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
        "full_policy": {},
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

func TestCommentHeader_NullFilterRulesCountAsEmpty(t *testing.T) {
	c := &testcapture.Capture{
		TestID: "NULLS",
		Captures: map[string]testcapture.Node{
			"a": {PacketFilterRules: json.RawMessage(`null`)},
			"b": {PacketFilterRules: json.RawMessage(`[]`)},
			"c": {PacketFilterRules: json.RawMessage(`[{"SrcIPs":["*"]}]`)},
		},
	}

	header := testcapture.CommentHeader(c)
	if !strings.Contains(header, "Nodes with filter rules: 1 of 3") {
		t.Errorf("expected '1 of 3' in header; got:\n%s", header)
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
