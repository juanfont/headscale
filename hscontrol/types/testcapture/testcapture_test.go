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

	"github.com/google/go-cmp/cmp"
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
		ToolVersion:   "capture-test-0.0.0",
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
		ToolVersion:   "capture-test-0.0.0",
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
// comparing the bytes. The [testcapture.Capture] struct embeds tailcfg view types
// with unexported pointer fields that go-cmp can't traverse, so a
// JSON round-trip is the simplest way to verify [testcapture.Write]+[testcapture.Read] produced
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

	if !strings.Contains(header, "tool version:") || !strings.Contains(header, "capture-test-0.0.0") {
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
// JSON-encoded string) still deserialises into a valid [testcapture.Input], with
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

	// Round-trip: the new [testcapture.Input.MarshalJSON] must emit the object form so
	// [testcapture.Input.UnmarshalJSON] re-reads it identically.
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

// v1File is a single-shot capture in the form [testcapture.Write] gives it.
const v1File = `// acl-v1
//
// refused policy, baseline kept
//
// Nodes with filter rules: 1 of 1
// Captured at:    2026-04-07T12:34:56Z
// tool version:   tscap/dev
// schema version: 1
{
	"schema_version": 1,
	"test_id":        "acl-v1",
	"description":    "refused policy, baseline kept",
	"category":       "acl",
	"captured_at":    "2026-04-07T12:34:56Z",
	"tool_version":   "tscap/dev",
	"tailnet":        "example.com",
	"error":          true,
	"input": {
		"api_response_code": 400,
		"api_response_body": {"message": "src=tag not found: \"tag:nonexistent\""},
		"tailnet": {
			"dns":      {"magic_dns": false, "nameservers": [], "search_paths": [], "split_dns": {}},
			"settings": {}
		},
		"scenario_hujson": "{\"id\":\"acl-v1\"}",
		"full_policy": {
			"acls": [{"action": "accept", "src": ["tag:nonexistent"], "dst": ["*:*"]}]
		}
	},
	"topology": {
		"users": [{"id": 1, "name": "odin", "email": "odin@example.com"}],
		"nodes": {"user1": {
			"hostname":        "user1",
			"tags":            null,
			"ipv4":            "100.90.199.68",
			"ipv6":            "fd7a:115c:a1e0::2d01:c747",
			"user":            "odin",
			"routable_ips":    [],
			"approved_routes": []
		}}
	},
	"captures": {"user1": {"packet_filter_rules": [{
		"SrcIPs":   ["100.64.0.0/10"],
		"DstPorts": [{"IP": "*", "Ports": {"First": 0, "Last": 65535}}]
	}]}}
}
`

// TestWrite_V1FileUnchanged asserts that the step fields leave a single-shot
// file byte for byte as it was: no new keys and no Steps header line.
func TestWrite_V1FileUnchanged(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.hujson")
	out := filepath.Join(dir, "out.hujson")

	err := os.WriteFile(in, []byte(v1File), 0o600)
	if err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c, err := testcapture.Read(in)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	err = testcapture.Write(out, c)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if string(got) != v1File {
		t.Errorf("v1 file changed on rewrite\n--- want ---\n%s\n--- got ---\n%s", v1File, got)
	}
}

func sampleStepsCapture(t *testing.T) *testcapture.Capture {
	t.Helper()

	frame, err := testcapture.ParseMapResponse([]byte(`{
    "ControlTime": "2026-10-17T09:13:15Z",
    "PacketFilter": []
}`))
	if err != nil {
		t.Fatalf("ParseMapResponse: %v", err)
	}

	frame.OffsetMS = 1200

	c := sampleACLCapture()
	c.TestID = "route-approval"
	c.ClientVersion = "1.102.5, capver 142"
	c.NodeIDs = map[string]tailcfg.NodeID{"user1": 101, "tagged-server": 102, "tagged-server#2": 103}
	c.Steps = []testcapture.Step{
		{
			Name:   "b0-join",
			At:     time.Date(2026, 4, 7, 12, 40, 0, 0, time.UTC),
			Result: "observed",
			Actions: []testcapture.Action{
				{Kind: "join", Node: "tagged-server", Key: "K-router", RequestTags: &[]string{}},
				{Kind: "cli", Node: "tagged-server", Args: []string{"set", "--advertise-routes=10.99.1.0/24"}, Exit: new(0)},
				{
					Kind:      "api",
					Principal: "admin",
					Method:    "POST",
					Path:      "/device/{device:tagged-server}/routes",
					Header:    map[string]string{"Content-Type": "application/json"},
					Body:      json.RawMessage(`{"routes":["10.99.1.0/24"]}`),
					Status:    200,
					Response:  json.RawMessage(`{"advertisedRoutes":["10.99.1.0/24"],"enabledRoutes":[]}`),
					OffsetMS:  15,
				},
				{
					Kind:     "token",
					Client:   "C-read",
					Scope:    new("devices:routes:read devices:core:read devices:routes:read"),
					Status:   200,
					Response: json.RawMessage(`{"scope":"devices:routes:read devices:core:read","token_type":"Bearer"}`),
				},
				{Kind: "token", Client: "C-read", Status: 200},
			},
			Captures: map[string]testcapture.Node{
				"tagged-server": {BackendState: "Running"},
			},
			Register: map[string][]testcapture.RegisterAttempt{
				"tagged-server": {{NodeKey: "nk-1", NodeKeyExpired: new(false), MachineAuthorized: new(true)}},
			},
			Frames: map[string][]testcapture.Frame{"user1": {frame}},
		},
		{
			Name:   "b1-policy",
			At:     time.Date(2026, 4, 7, 12, 41, 0, 0, time.UTC),
			Result: "expected-refusal",
			Actions: []testcapture.Action{
				{
					Kind:       "policy",
					Method:     "POST",
					Path:       "/acl",
					Header:     map[string]string{"If-Match": "etag-1"},
					Body:       json.RawMessage(`""`),
					Status:     400,
					RespHeader: map[string]string{"ETag": "etag-1"},
					Response:   json.RawMessage(`{"message":"empty policy","data":null}`),
				},
			},
			Captures: map[string]testcapture.Node{
				"user1": {BackendState: "NeedsLogin", ErrMessage: "invalid key"},
			},
		},
	}

	return c
}

func TestWriteReadRoundtrip_Steps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route-approval.hujson")
	in := sampleStepsCapture(t)

	err := testcapture.Write(path, in)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	out, err := testcapture.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	equalViaJSON(t, in, out)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	header := strings.Join(extractHeaderLines(strings.Split(string(raw), "\n")), "\n")
	if !strings.Contains(header, "Steps: 2") {
		t.Errorf("header missing steps line; got:\n%s", header)
	}

	// Sent-empty tags and a zero-length body must stay apart from absent.
	if tags := out.Steps[0].Actions[0].RequestTags; tags == nil || len(*tags) != 0 {
		t.Errorf("RequestTags = %v, want sent empty", tags)
	}

	if out.Steps[0].Actions[1].RequestTags != nil {
		t.Errorf("RequestTags on cli action = %v, want nil", out.Steps[0].Actions[1].RequestTags)
	}

	if got := string(out.Steps[1].Actions[0].Body); got != `""` {
		t.Errorf("zero-length body = %s, want \"\"", got)
	}

	// A token scope keeps order and repeats; an unsent one stays nil.
	want := "devices:routes:read devices:core:read devices:routes:read"
	if got := out.Steps[0].Actions[3].Scope; got == nil || *got != want {
		t.Errorf("Scope = %v, want %q", got, want)
	}

	if got := out.Steps[0].Actions[4].Scope; got != nil {
		t.Errorf("Scope = %q, want nil when none was sent", *got)
	}

	if out.ClientVersion != in.ClientVersion {
		t.Errorf("ClientVersion = %q, want %q", out.ClientVersion, in.ClientVersion)
	}
}

func TestWrite_RefusesSecrets(t *testing.T) {
	tests := []struct {
		name string
		edit func(c *testcapture.Capture)
	}{
		{
			name: "auth key in output",
			edit: func(c *testcapture.Capture) {
				c.Steps[0].Actions[1].Output = "joined with tskey-auth-k123CNTRL-abc"
			},
		},
		{
			name: "login URL in register attempt",
			edit: func(c *testcapture.Capture) {
				c.Steps[0].Register["tagged-server"][0].AuthURL = "https://login.tailscale.com/a/1a2b3c"
			},
		},
		{
			name: "auth key in description",
			edit: func(c *testcapture.Capture) {
				c.Description = "tskey-client-k123-abc"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			c := sampleStepsCapture(t)
			tt.edit(c)

			err := testcapture.Write(filepath.Join(dir, "x.hujson"), c)
			if !errors.Is(err, testcapture.ErrSecret) {
				t.Fatalf("Write = %v, want ErrSecret", err)
			}

			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}

			if len(entries) != 0 {
				t.Errorf("refused Write left %d files behind", len(entries))
			}
		})
	}
}

// TestAppendRegisterLine feeds a stock client's log through the parser: an
// expired node key, the regenerated key's auth URL and the follow-up that
// completes once the login is approved.
func TestAppendRegisterLine(t *testing.T) {
	lines := []string{
		// auto.go's report format; the client logged no login error here.
		"[v1] TryLogin: context canceled",
		"2026/10/17 09:12:42 control: doLogin(regen=false, hasUrl=false)",
		"2026/10/17 09:12:43 control: RegisterReq: onode= node=[cCOGA] fup=false nks=false",
		"2026/10/17 09:12:43 control: creating new noise client",
		"2026/10/17 09:12:43 control: RegisterReq: got response; nodeKeyExpired=true, machineAuthorized=true; authURL=false",
		"2026/10/17 09:12:43 control: server reports new node key [cCOGA] has expired",
		"2026/10/17 09:12:43 control: doLogin(regen=true, hasUrl=false)",
		"2026/10/17 09:12:43 control: Generating a new nodekey.",
		"2026/10/17 09:12:43 control: RegisterReq: onode=[cCOGA] node=[ufHM+] fup=false nks=false",
		"2026/10/17 09:12:43 control: RegisterReq: got response; nodeKeyExpired=false, machineAuthorized=false; authURL=true",
		"2026/10/17 09:12:43 control: AuthURL is https://login.tailscale.com/a/REDACTED",
		"2026/10/17 09:12:43 control: direct.WaitLoginURL",
		"2026/10/17 09:12:43 control: RegisterReq: onode=[cCOGA] node=[ufHM+] fup=true nks=false",
		"2026/10/17 09:12:43 Switching ipn state NoState -> NeedsLogin (WantRunning=true, nm=false)",
		"2026/10/17 09:13:15 control: RegisterReq: got response; nodeKeyExpired=false, machineAuthorized=true; authURL=false\n",
		"2026/10/17 09:13:15 control: No AuthURL",
		`2026/10/17 09:13:17 RAW-STDERR: [{"logtail":{"client_time":"2026-10-17T09:13:15.108564694Z","proc_id":102272285,"proc_seq":87},"metrics":"N2anetmon_link_change_eqS0204N40controlclient_auto_status_queuedS0402N50gauge_localbackend_current_watch_ipn_busS0602N1eprofiles_switchS0802N28gauge_profiles_countS0a02N5agauge_dns_manager_linux_mode_systemd_resolvedS0c02","text":"control: RegisterReq: got response; nodeKeyExpired=false, machineAuthorized=true; authURL=false\n"}`,
	}

	var (
		got     []testcapture.RegisterAttempt
		matched int
	)

	for _, l := range lines {
		var ok bool

		got, ok = testcapture.AppendRegisterLine(got, l)
		if ok {
			matched++
		}
	}

	want := []testcapture.RegisterAttempt{
		{Err: "context canceled"},
		{NodeKey: "[cCOGA]", NodeKeyExpired: new(true), MachineAuthorized: new(true)},
		{
			NodeKey:           "[ufHM+]",
			OldNodeKey:        "[cCOGA]",
			NodeKeyExpired:    new(false),
			MachineAuthorized: new(false),
			AuthURL:           "https://login.tailscale.com/a/REDACTED",
		},
		{
			NodeKey:           "[ufHM+]",
			OldNodeKey:        "[cCOGA]",
			Followup:          true,
			NodeKeyExpired:    new(false),
			MachineAuthorized: new(true),
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("attempts (-want +got):\n%s", diff)
	}

	if matched != 8 {
		t.Errorf("matched %d lines, want 8", matched)
	}

	// A follow-up still waiting for approval has no answer yet.
	pending, _ := testcapture.AppendRegisterLine(nil, lines[12])
	if pending[0].MachineAuthorized != nil {
		t.Errorf("unanswered attempt has MachineAuthorized = %v", *pending[0].MachineAuthorized)
	}
}

// TestParseMapResponse_KeepsEmpty asserts that a deny-all frame read back
// from a file stays distinct from one that leaves the filter unchanged:
// typed marshalling drops the empty PacketFilter, Empty keeps it. The same
// holds for patch fields, where an empty value clears and an absent one
// leaves the field.
func TestParseMapResponse_KeepsEmpty(t *testing.T) {
	f, err := testcapture.ParseMapResponse([]byte(`{
    "ControlTime": "2026-10-17T09:13:15Z",
    "PacketFilter": [],
    "PeersRemoved": null,
    "PeersChangedPatch": [
        {"NodeID": 101, "Endpoints": [], "CapMap": {}, "Online": null},
        {"NodeID": 102, "DERPRegion": 2}
    ],
    "Domain": "example.com"
}`))
	if err != nil {
		t.Fatalf("ParseMapResponse: %v", err)
	}

	unchanged, err := testcapture.ParseMapResponse([]byte(`{"ControlTime": "2026-10-17T09:13:15Z"}`))
	if err != nil {
		t.Fatalf("ParseMapResponse: %v", err)
	}

	path := filepath.Join(t.TempDir(), "frames.hujson")

	err = testcapture.Write(path, &testcapture.Capture{
		SchemaVersion: testcapture.SchemaVersion,
		TestID:        "frames",
		Steps: []testcapture.Step{{
			Name:   "s1",
			Result: "observed",
			Frames: map[string][]testcapture.Frame{"user1": {f, unchanged}},
		}},
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	c, err := testcapture.Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	frames := c.Steps[0].Frames["user1"]

	got := frames[0]
	if got.Response == nil || got.Response.PacketFilter != nil || got.Response.Domain != "example.com" {
		t.Errorf("Response = %+v, want Domain set and PacketFilter dropped", got.Response)
	}

	if p := got.Response.PeersChangedPatch; len(p) != 2 || p[0].Endpoints != nil || p[1].DERPRegion != 2 {
		t.Errorf("PeersChangedPatch = %+v, want two patches, Endpoints dropped", p)
	}

	want := map[string]string{
		"PacketFilter":                   "[]",
		"PeersRemoved":                   "null",
		"PeersChangedPatch[0].Endpoints": "[]",
		"PeersChangedPatch[0].CapMap":    "{}",
		"PeersChangedPatch[0].Online":    "null",
	}
	if diff := cmp.Diff(want, got.Empty); diff != "" {
		t.Errorf("Empty (-want +got):\n%s", diff)
	}

	if frames[1].Empty != nil {
		t.Errorf("Empty = %v for a frame with no empty keys, want nil", frames[1].Empty)
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
