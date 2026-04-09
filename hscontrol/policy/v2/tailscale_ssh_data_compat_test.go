// This file implements a data-driven test runner for SSH compatibility tests.
// It loads HuJSON golden files from testdata/ssh_results/ssh-*.hujson, captured
// from Tailscale SaaS by tscap, and compares headscale's SSH policy compilation
// against the captured SSH rules.
//
// Each file is a testcapture.Capture containing:
//   - The full policy that was POSTed to Tailscale SaaS (we use tf.Input.FullPolicy
//     directly instead of reconstructing it from a sub-section)
//   - The expected SSH rules for each of the 8 test nodes (in tf.Captures[name].SSHRules)
//
// Tests known to fail due to unimplemented features or known differences are
// skipped with a TODO comment explaining the root cause.
//
// Test data source: testdata/ssh_results/ssh-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)


// setupSSHDataCompatUsers returns the 3 test users for SSH data-driven
// compatibility tests. Users get norse-god names; nodes get original-151
// pokémon names — matching the anonymized identifiers tscap writes into
// the capture files (see github.com/kradalby/tscap/anonymize).
func setupSSHDataCompatUsers() types.Users {
	return types.Users{
		{
			Model: gorm.Model{ID: 1},
			Name:  "odin",
			Email: "odin@example.com",
		},
		{
			Model: gorm.Model{ID: 2},
			Name:  "thor",
			Email: "thor@example.com",
		},
		{
			Model: gorm.Model{ID: 3},
			Name:  "freya",
			Email: "freya@example.com",
		},
	}
}

// setupSSHDataCompatNodes returns the test nodes for SSH data-driven
// compatibility tests. Node GivenNames match the anonymized pokémon names:
//   - bulbasaur (owned by odin)
//   - ivysaur (owned by thor)
//   - venusaur (owned by freya)
//   - beedrill (tag:server)
//   - kakuna (tag:prod)
func setupSSHDataCompatNodes(users types.Users) types.Nodes {
	return types.Nodes{
		&types.Node{
			ID:        1,
			GivenName: "bulbasaur",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("100.90.199.68"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        2,
			GivenName: "ivysaur",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("100.110.121.96"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::1737:7960"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        3,
			GivenName: "venusaur",
			User:      &users[2],
			UserID:    &users[2].ID,
			IPv4:      ptrAddr("100.103.90.82"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        4,
			GivenName: "beedrill",
			IPv4:      ptrAddr("100.108.74.26"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
			Tags:      []string{"tag:server"},
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		&types.Node{
			ID:        5,
			GivenName: "kakuna",
			IPv4:      ptrAddr("100.103.8.15"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::5b37:80f"),
			Tags:      []string{"tag:prod"},
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}
}

// loadSSHTestFile loads and parses a single SSH capture HuJSON file.
func loadSSHTestFile(t *testing.T, path string) *testcapture.Capture {
	t.Helper()

	c, err := testcapture.Read(path)
	require.NoError(t, err, "failed to read test file %s", path)

	return c
}

// sshSkipReasons documents why each skipped test fails and what needs to be
// fixed. Tests are grouped by root cause to identify high-impact changes.
var sshSkipReasons = map[string]string{
	// user:*@passkey wildcard pattern not supported in headscale.
	// headscale does not support passkey authentication and has no
	// equivalent for this wildcard pattern.
	"ssh-b5":  "user:*@passkey wildcard not supported in headscale",
	"ssh-d10": "user:*@passkey wildcard not supported in headscale",
}

// TestSSHDataCompat is a data-driven test that loads all ssh-*.hujson test
// files captured from Tailscale SaaS and compares headscale's SSH policy
// compilation against the real Tailscale behavior.
//
// Each capture file contains:
//   - The full policy that was POSTed to the SaaS API (Input.FullPolicy)
//   - Expected SSH rules per node (Captures[name].SSHRules)
//
// The test converts Tailscale user email formats to headscale format and runs
// the captured policy through unmarshalPolicy and compileSSHPolicy.
func TestSSHDataCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "ssh_results", "ssh-*.hujson"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no ssh-*.hujson test files found in testdata/ssh_results/",
	)

	t.Logf("Loaded %d SSH test files", len(files))

	users := setupSSHDataCompatUsers()

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

			// Skip captures the SaaS rejected — no expected SSH rules to compare against.
			if tf.Error {
				t.Skipf("%s: SaaS rejected the policy (api_response_code=%d); no expected SSH rules captured", tf.TestID, tf.Input.APIResponseCode)
				return
			}

			// Build nodes per-scenario from this file's topology.
			// tscap uses clean-slate mode, so each scenario has
			// different node IPs.
			nodes := buildGrantsNodesFromCapture(users, tf)

			// Use the captured full policy verbatim. Anonymization in
			// tscap already rewrites SaaS emails to @example.com.
			policyJSON := tf.Input.FullPolicy

			pol, err := unmarshalPolicy(policyJSON)
			require.NoError(
				t,
				err,
				"%s: policy should parse successfully\nPolicy:\n%s",
				tf.TestID,
				policyJSON,
			)

			for nodeName, capture := range tf.Captures {
				t.Run(nodeName, func(t *testing.T) {
					node := findNodeByGivenName(nodes, nodeName)
					if node == nil {
						t.Skipf("node %s not in this test's node set", nodeName)
						return
					}

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
					if len(capture.SSHRules) > 0 &&
						string(capture.SSHRules) != "null" {
						err = json.Unmarshal(capture.SSHRules, &wantRules)
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
					//
					// Ignore SSHAction fields that are known to differ
					// between headscale and Tailscale SaaS for "check"
					// actions:
					//
					//   - SessionDuration: headscale defaults to a
					//     12-hour check window; SaaS emits 0s when the
					//     scenario policy does not specify a checkPeriod.
					//
					//   - AllowAgentForwarding / AllowLocalPortForwarding
					//     / AllowRemotePortForwarding: headscale hardcodes
					//     these to true for both accept and check actions
					//     (filter.go sshAccept / sshCheck); SaaS emits
					//     false for check actions.
					//
					//   - HoldAndDelegate: headscale uses a URL template
					//     containing "/from/…?ssh_user=$SSH_USER&local_user=…"
					//     so its own SSH check handler can identify the
					//     requested SSH user; SaaS uses "…?local_user=…"
					//     without the ssh_user query parameter. Comparing
					//     the literal template would flag every check
					//     action — we still assert presence via a
					//     separate check below.
					opts := cmp.Options{
						cmpopts.SortSlices(func(a, b *tailcfg.SSHPrincipal) bool {
							return a.NodeIP < b.NodeIP
						}),
						cmpopts.EquateEmpty(),
						cmpopts.IgnoreFields(tailcfg.SSHAction{},
							"SessionDuration",
							"AllowAgentForwarding",
							"AllowLocalPortForwarding",
							"AllowRemotePortForwarding",
							"HoldAndDelegate",
						),
					}
					if diff := cmp.Diff(wantSSH, gotSSH, opts...); diff != "" {
						t.Errorf(
							"%s/%s: SSH policy mismatch (-tailscale +headscale):\n%s",
							tf.TestID,
							nodeName,
							diff,
						)
					}

					// Separate presence check: the fields ignored by
					// the diff above must still be populated on matching
					// rules. This catches regressions where headscale
					// would silently drop the HoldAndDelegate URL or
					// flip Accept to false while we are not looking.
					if wantSSH != nil && gotSSH != nil {
						for i, wantRule := range wantSSH.Rules {
							if i >= len(gotSSH.Rules) {
								break
							}

							gotRule := gotSSH.Rules[i]
							if wantRule.Action == nil || gotRule.Action == nil {
								continue
							}

							wantIsCheck := wantRule.Action.HoldAndDelegate != ""
							gotIsCheck := gotRule.Action.HoldAndDelegate != ""

							assert.Equalf(t, wantIsCheck, gotIsCheck,
								"%s/%s rule %d: HoldAndDelegate presence mismatch",
								tf.TestID, nodeName, i,
							)
						}
					}
				})
			}
		})
	}
}
