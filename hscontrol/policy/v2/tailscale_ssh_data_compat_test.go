// This file is "generated" by Claude.
// It contains a data-driven test that reads SSH-*.json test files captured
// from Tailscale SaaS. Each file contains:
//   - The SSH section of the policy
//   - The expected SSHPolicy rules for each of 5 test nodes
//
// The test loads each JSON file, constructs a full policy from the SSH section,
// applies it through headscale's SSH policy compilation, and compares the output
// against Tailscale's actual behavior.
//
// Tests that are known to fail due to unimplemented features or known
// differences are skipped with a TODO comment explaining the root cause.
// As headscale's SSH implementation improves, tests should be removed
// from the skip list.
//
// Test data source: testdata/ssh_results/SSH-*.json
// Captured from: Tailscale SaaS API + tailscale debug localapi

package v2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// sshTestFile represents the JSON structure of a captured SSH test file.
type sshTestFile struct {
	TestID     string                    `json:"test_id"`
	PolicyFile string                    `json:"policy_file"`
	SSHSection json.RawMessage           `json:"ssh_section"`
	Nodes      map[string]sshNodeCapture `json:"nodes"`
}

// sshNodeCapture represents the expected SSH rules for a single node.
type sshNodeCapture struct {
	Rules json.RawMessage `json:"rules"`
}

// setupSSHDataCompatUsers returns the 3 test users for SSH data-driven
// compatibility tests. The user configuration matches the Tailscale test
// environment with email domains preserved for localpart matching:
//   - kratail2tid@example.com (converted from @passkey)
//   - kristoffer@dalby.cc (kept as-is — different domain for localpart exclusion)
//   - monitorpasskeykradalby@example.com (converted from @passkey)
func setupSSHDataCompatUsers() types.Users {
	return types.Users{
		{
			Model: gorm.Model{ID: 1},
			Name:  "kratail2tid",
			Email: "kratail2tid@example.com",
		},
		{
			Model: gorm.Model{ID: 2},
			Name:  "kristoffer",
			Email: "kristoffer@dalby.cc",
		},
		{
			Model: gorm.Model{ID: 3},
			Name:  "monitorpasskeykradalby",
			Email: "monitorpasskeykradalby@example.com",
		},
	}
}

// setupSSHDataCompatNodes returns the 5 test nodes for SSH data-driven
// compatibility tests. Node GivenNames match the keys in the JSON files:
//   - user1 (owned by kratail2tid)
//   - user-kris (owned by kristoffer)
//   - user-mon (owned by monitorpasskeykradalby)
//   - tagged-server (tag:server)
//   - tagged-prod (tag:prod)
func setupSSHDataCompatNodes(users types.Users) types.Nodes {
	return types.Nodes{
		&types.Node{
			ID:        1,
			GivenName: "user1",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("100.90.199.68"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        2,
			GivenName: "user-kris",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("100.110.121.96"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::1737:7960"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        3,
			GivenName: "user-mon",
			User:      &users[2],
			UserID:    &users[2].ID,
			IPv4:      ptrAddr("100.103.90.82"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        4,
			GivenName: "tagged-server",
			IPv4:      ptrAddr("100.108.74.26"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
			Tags:      []string{"tag:server"},
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        5,
			GivenName: "tagged-prod",
			IPv4:      ptrAddr("100.103.8.15"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::5b37:80f"),
			Tags:      []string{"tag:prod"},
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}
}

// convertSSHPolicyEmails converts Tailscale SaaS email domains to
// headscale-compatible format in the raw policy JSON.
//
// Tailscale uses provider-specific email formats:
//   - kratail2tid@passkey (passkey auth)
//   - kristoffer@dalby.cc (email auth — kept as-is)
//   - monitorpasskeykradalby@passkey (passkey auth)
//
// The @passkey domain is converted to @example.com. The @dalby.cc domain
// is kept as-is to preserve localpart matching semantics (kristoffer should
// NOT match localpart:*@example.com, just as it doesn't match
// localpart:*@passkey in Tailscale SaaS).
func convertSSHPolicyEmails(s string) string {
	s = strings.ReplaceAll(s, "@passkey", "@example.com")

	return s
}

// constructSSHFullPolicy builds a complete headscale policy from the
// ssh_section captured from Tailscale SaaS.
//
// The base policy includes:
//   - groups matching the Tailscale test environment
//   - tagOwners for tag:server and tag:prod
//   - A permissive ACL allowing all traffic (matches the grants wildcard
//     in the original Tailscale policy)
//   - The SSH section from the test file
func constructSSHFullPolicy(sshSection json.RawMessage) string {
	// Base policy template with groups, tagOwners, and ACLs
	// User references match the converted email addresses.
	const basePolicyPrefix = `{
	"groups": {
		"group:admins": ["kratail2tid@example.com"],
		"group:developers": ["kristoffer@dalby.cc", "kratail2tid@example.com"],
		"group:empty": []
	},
	"tagOwners": {
		"tag:server": ["kratail2tid@example.com"],
		"tag:prod": ["kratail2tid@example.com"]
	},
	"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]`

	// Handle null or empty SSH section
	if len(sshSection) == 0 || string(sshSection) == "null" {
		// No SSH section at all (like SSH-E4)
		return basePolicyPrefix + "\n}"
	}

	sshStr := string(sshSection)

	// Convert Tailscale email domains
	sshStr = convertSSHPolicyEmails(sshStr)

	return basePolicyPrefix + `,
	"ssh": ` + sshStr + "\n}"
}

// loadSSHTestFile loads and parses a single SSH test JSON file.
func loadSSHTestFile(t *testing.T, path string) sshTestFile {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test file %s", path)

	var tf sshTestFile

	err = json.Unmarshal(content, &tf)
	require.NoError(t, err, "failed to parse test file %s", path)

	return tf
}

// sshSkipReasons documents why each skipped test fails and what needs to be
// fixed. Tests are grouped by root cause to identify high-impact changes.
//
// 37 of 39 tests are expected to pass.
var sshSkipReasons = map[string]string{
	// user:*@domain source alias not yet implemented.
	// These tests use "src": ["user:*@passkey"] which requires UserWildcard
	// alias type support. Will be added in a follow-up PR that implements
	// user:*@domain across all contexts (ACLs, grants, tagOwners, autoApprovers).
	"SSH-B5":  "user:*@domain source alias not yet implemented",
	"SSH-D10": "user:*@domain source alias not yet implemented",
}

// TestSSHDataCompat is a data-driven test that loads all SSH-*.json test files
// captured from Tailscale SaaS and compares headscale's SSH policy compilation
// against the real Tailscale behavior.
//
// Each JSON file contains:
//   - The SSH section of the policy
//   - Expected SSH rules per node (5 nodes)
//
// The test constructs a full headscale policy from the SSH section, converts
// Tailscale user email formats to headscale format, and runs the policy
// through unmarshalPolicy and compileSSHPolicy.
func TestSSHDataCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "ssh_results", "SSH-*.json"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no SSH-*.json test files found in testdata/ssh_results/",
	)

	t.Logf("Loaded %d SSH test files", len(files))

	users := setupSSHDataCompatUsers()
	nodes := setupSSHDataCompatNodes(users)

	for _, file := range files {
		tf := loadSSHTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Check if this test is in the skip list
			if reason, ok := sshSkipReasons[tf.TestID]; ok {
				t.Skipf(
					"TODO: %s — see sshSkipReasons comments for details",
					reason,
				)

				return
			}

			// Construct full policy from SSH section
			policyJSON := constructSSHFullPolicy(tf.SSHSection)

			pol, err := unmarshalPolicy([]byte(policyJSON))
			require.NoError(
				t,
				err,
				"%s: policy should parse successfully\nPolicy:\n%s",
				tf.TestID,
				policyJSON,
			)

			for nodeName, capture := range tf.Nodes {
				t.Run(nodeName, func(t *testing.T) {
					node := findNodeByGivenName(nodes, nodeName)
					require.NotNilf(
						t,
						node,
						"node %s not found in test setup",
						nodeName,
					)

					// Compile headscale SSH policy for this node
					gotSSH, err := pol.compileSSHPolicy(
						"unused-server-url",
						users,
						node.View(),
						nodes.ViewSlice(),
					)
					require.NoError(
						t,
						err,
						"%s/%s: failed to compile SSH policy",
						tf.TestID,
						nodeName,
					)

					// Parse expected rules from JSON capture
					var wantRules []*tailcfg.SSHRule
					if len(capture.Rules) > 0 &&
						string(capture.Rules) != "null" {
						err = json.Unmarshal(capture.Rules, &wantRules)
						require.NoError(
							t,
							err,
							"%s/%s: failed to unmarshal expected rules",
							tf.TestID,
							nodeName,
						)
					}

					// Build expected SSHPolicy from the rules
					var wantSSH *tailcfg.SSHPolicy
					if len(wantRules) > 0 {
						wantSSH = &tailcfg.SSHPolicy{Rules: wantRules}
					}

					// Normalize: treat empty-rules SSHPolicy as nil
					if gotSSH != nil && len(gotSSH.Rules) == 0 {
						gotSSH = nil
					}

					// Compare headscale output against Tailscale expected.
					// EquateEmpty treats nil and empty slices as equal.
					// Sort principals within rules (order doesn't matter).
					// Do NOT sort rules — order matters (first-match-wins).
					opts := cmp.Options{
						cmpopts.SortSlices(func(a, b *tailcfg.SSHPrincipal) bool {
							return a.NodeIP < b.NodeIP
						}),
						cmpopts.EquateEmpty(),
					}
					if diff := cmp.Diff(wantSSH, gotSSH, opts...); diff != "" {
						t.Errorf(
							"%s/%s: SSH policy mismatch (-tailscale +headscale):\n%s",
							tf.TestID,
							nodeName,
							diff,
						)
					}
				})
			}
		})
	}
}
