// This file implements a data-driven test runner for SSH compatibility tests.
// It loads HuJSON golden files from testdata/ssh_results/ssh-*.hujson, captured
// from Tailscale SaaS by tscap, and compares headscale's SSH policy compilation
// against the captured SSH rules.
//
// Each capture is one of:
//   - APIResponseCode == 200 — SaaS accepted the policy; the captured
//     per-node SSH rules in tf.Captures[name].SSHRules are the source of
//     truth, and headscale's compileSSHPolicy must produce the same shape.
//   - APIResponseCode != 200 — SaaS rejected the policy at the API; the
//     captured Message is the body the user saw. headscale must reject
//     the same input with an error whose text contains that body as a
//     substring (mirroring sshtester_compat_test.go).
//
// Tests known to diverge are listed in sshSkipReasons (200 path) or
// sshRejectSkipReasons (!= 200 path) with a TODO explaining the gap.
//
// Test data source: testdata/ssh_results/ssh-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"path/filepath"
	"strings"
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
//
// odin and freya live on @example.com; thor lives on @example.org so
// that "localpart:*@example.com" resolves to exactly two users
// (matching SaaS output) and the "user on a different email domain"
// case stays covered by scenarios like ssh-d1 that use
// "localpart:*@example.org".
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
			Email: "thor@example.org",
		},
		{
			Model: gorm.Model{ID: 3},
			Name:  "freya",
			Email: "freya@example.com",
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

// sshSkipReasons documents APIResponseCode == 200 captures where SaaS
// accepted the policy but headscale either does not yet support the
// shape or rejects it stricter than SaaS does. Each entry should
// describe the gap a follow-up PR needs to close (or justify why
// headscale is intentionally stricter).
var sshSkipReasons = map[string]string{
	// USER_PASSKEY_WILDCARD (2 tests)
	//
	// headscale does not support passkey authentication and has no
	// equivalent for the user:*@passkey wildcard pattern.
	"ssh-b5":  "user:*@passkey wildcard not supported in headscale",
	"ssh-d10": "user:*@passkey wildcard not supported in headscale",

	// AUTOGROUP_AS_SSH_USER (4 tests)
	//
	// SaaS accepts `users: ["autogroup:X"]` on an `ssh` rule for
	// every autogroup name (member, self, tagged, internet); the
	// resolution then produces zero principals at compile time for
	// the ones that don't map to actual logins. headscale's
	// validate() restricts users-side autogroups to just
	// `autogroup:nonroot` via autogroupForSSHUser, so the policy
	// fails to parse. Either widen autogroupForSSHUser to mirror
	// SaaS (and let compilation drop unsupported entries) or
	// document that headscale is intentionally stricter.
	"ssh-malformed-user-autogroup-internet": "headscale rejects `users: [autogroup:internet]`; SaaS accepts and compiles to zero principals",
	"ssh-malformed-user-autogroup-member":   "headscale rejects `users: [autogroup:member]`; SaaS accepts and compiles to zero principals",
	"ssh-malformed-user-autogroup-self":     "headscale rejects `users: [autogroup:self]`; SaaS accepts and compiles to zero principals",
	"ssh-malformed-user-autogroup-tagged":   "headscale rejects `users: [autogroup:tagged]`; SaaS accepts and compiles to zero principals",

	// LOCALPART_SHAPE (4 tests)
	//
	// SaaS accepts every shape under the `localpart:` prefix
	// (`localpart:`, `localpart:foo`, `localpart:*@`, and
	// `localpart:foo@example.com`) and compiles each to zero
	// principals. headscale's SSHUser.ParseLocalpart enforces the
	// strict `localpart:*@<domain>` shape and returns errors for
	// every other form — see hscontrol/policy/v2/types.go
	// ParseLocalpart and the call site in validate(). The strict
	// path is arguably correct (these strings can never produce a
	// useful principal) but it surfaces as a parse error rather
	// than the SaaS behaviour of silently producing zero
	// principals.
	"ssh-malformed-user-localpart-empty":     "headscale rejects `localpart:` (missing @); SaaS accepts and compiles to zero principals",
	"ssh-malformed-user-localpart-no-at":     "headscale rejects `localpart:foo` (missing @); SaaS accepts and compiles to zero principals",
	"ssh-malformed-user-localpart-no-domain": "headscale rejects `localpart:*@` (empty domain); SaaS accepts and compiles to zero principals",
	"ssh-malformed-user-localpart-no-glob":   "headscale rejects `localpart:foo@example.com` (local part not *); SaaS accepts and compiles to zero principals",

	// CHECK_PERIOD_MIN (2 tests)
	//
	// SaaS allows `checkPeriod: "0s"` and any sub-minute value;
	// headscale's SSHCheckPeriodMin = 1 minute rejects both. The
	// minimum may be a deliberate hardening, but it diverges from
	// SaaS — needs an explicit decision.
	"ssh-malformed-checkperiod-zero":      "headscale rejects checkPeriod `0s`; SaaS accepts",
	"ssh-malformed-checkperiod-too-short": "headscale rejects checkPeriod `30s`; SaaS accepts (no minimum)",
}

// sshRejectSkipReasons documents APIResponseCode != 200 captures where
// headscale and SaaS legitimately disagree on whether the policy should
// be rejected (or where headscale rejects with different wording).
var sshRejectSkipReasons = map[string]string{
	// WORDING_DIFFERS (4 tests)
	//
	// headscale rejects these inputs but with different error
	// text, so the SaaS message is not a substring of headscale's.
	"ssh-malformed-action-deny":           `headscale rejects "deny" with 'invalid SSH action: "deny", must be one of: accept, check' vs SaaS '"deny" is not a valid action'`,
	"ssh-malformed-action-empty":          `headscale rejects empty action with 'invalid SSH action: "", must be one of: accept, check' vs SaaS 'action must be specified'`,
	"ssh-malformed-checkperiod-malformed": `headscale rejects malformed duration with 'not a valid duration string: "abc"' vs SaaS 'time: invalid duration "abc"'`,
	"ssh-malformed-checkperiod-too-long":  "headscale rejects 200h with 'checkPeriod above maximum of 168 hours (1 week)' vs SaaS 'checkPeriod 200h0m0s is above the max (168h)'",

	// MISSING_VALIDATIONS (5 tests)
	//
	// SaaS rejects these inputs; headscale accepts them today.
	// Fixes belong in hscontrol/policy/v2/types.go validate().
	"ssh-malformed-action-missing":    "headscale accepts missing `action`; SaaS rejects with `action must be specified`",
	"ssh-malformed-acceptenv-empty":   "headscale accepts `acceptEnv: [\"\"]`; SaaS rejects with `acceptEnv values cannot be empty`",
	"ssh-malformed-users-empty-array": "headscale accepts empty `users: []`; SaaS rejects with `users must be specified`",
	"ssh-malformed-users-missing":     "headscale accepts missing `users`; SaaS rejects with `users must be specified`",
	"ssh-malformed-user-empty":        `headscale accepts empty username ""; SaaS rejects with 'user "" is not valid'`,
	"ssh-malformed-user-wildcard":     `headscale accepts wildcard "*"; SaaS rejects with 'user "*" is not valid' (same gap as sshtester_compat_test.go's sshtest-user-wildcard)`,

	// DOMAIN_NOT_ASSOCIATED (5 tests)
	//
	// SaaS validates that email domains in user:*@domain and
	// localpart:*@domain expressions are configured tailnet
	// domains. headscale has no concept of "associated tailnet
	// domains" — it only has users with email addresses. These
	// policies are legitimately rejected by SaaS but not by
	// headscale.
	"ssh-b4": "domain validation: headscale has no 'associated tailnet domains' concept",
	"ssh-d1": "domain validation: headscale has no 'associated tailnet domains' concept",
	"ssh-e1": "domain validation: headscale has no 'associated tailnet domains' concept",
	"ssh-e2": "domain validation: headscale has no 'associated tailnet domains' concept",
	"ssh-malformed-user-localpart-multi-glob": "domain validation: headscale has no 'associated tailnet domains' concept (same gap as ssh-b4/d1/e1/e2)",
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

	allHujson, err := filepath.Glob(
		filepath.Join("testdata", "ssh_results", "*.hujson"),
	)
	require.NoError(t, err, "failed to glob all hujson files")
	require.Lenf(t, files, len(allHujson),
		"ssh_results/ contains hujson files not picked up by the ssh-*.hujson loader; "+
			"loader sees %d, directory has %d. Stale fixtures should be deleted.",
		len(files), len(allHujson),
	)

	t.Logf("Loaded %d SSH test files", len(files))

	users := setupSSHDataCompatUsers()

	for _, file := range files {
		tf := loadSSHTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Build nodes per-scenario from this file's topology.
			// tscap uses clean-slate mode, so each scenario has
			// different node IPs.
			nodes := buildGrantsNodesFromCapture(users, tf)

			// Use the captured full policy as is. Anonymization in
			// tscap already rewrites SaaS emails to @example.com.
			policyJSON := []byte(tf.Input.FullPolicy)

			// Branch on the SaaS response code. Captures with
			// APIResponseCode != 200 are policies SaaS rejected at
			// the API; headscale must reject the same input. The
			// 200 path falls through to the existing per-node SSH
			// rule comparison.
			if tf.Input.APIResponseCode != 200 {
				if reason, ok := sshRejectSkipReasons[tf.TestID]; ok {
					t.Skipf(
						"TODO: %s — see sshRejectSkipReasons for details",
						reason,
					)

					return
				}

				pm, parseErr := NewPolicyManager(policyJSON, users, nodes.ViewSlice())

				var got error

				switch {
				case parseErr != nil:
					got = parseErr
				default:
					_, setErr := pm.SetPolicy(policyJSON)
					got = setErr
				}

				require.Error(t, got, "tailscale rejected; headscale must reject too")

				if tf.Input.APIResponseBody == nil ||
					tf.Input.APIResponseBody.Message == "" {
					return
				}

				want := tf.Input.APIResponseBody.Message
				if !strings.Contains(got.Error(), want) {
					t.Errorf(
						"error body mismatch\n  tailscale wants: %q\n  headscale got:   %q",
						want,
						got.Error(),
					)
				}

				return
			}

			// APIResponseCode == 200: SaaS accepted; headscale must
			// match the captured per-node SSH rules.
			if reason, ok := sshSkipReasons[tf.TestID]; ok {
				t.Skipf(
					"TODO: %s — see sshSkipReasons comments for details",
					reason,
				)

				return
			}

			pol, err := unmarshalPolicy(policyJSON)
			require.NoError(
				t,
				err,
				"%s: policy should parse successfully\nPolicy:\n%s",
				tf.TestID,
				tf.Input.FullPolicy,
			)

			for nodeName, capture := range tf.Captures {
				t.Run(nodeName, func(t *testing.T) {
					node := findNodeByGivenName(nodes, nodeName)
					require.NotNilf(t, node,
						"golden node %s not found in test setup", nodeName)

					// Compile headscale SSH policy for this node
					gotSSH, err := pol.compileSSHPolicy(
						"https://unused",
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

					// Build expected SSHPolicy from the typed rules.
					var wantSSH *tailcfg.SSHPolicy
					if len(capture.SSHRules) > 0 {
						wantSSH = &tailcfg.SSHPolicy{Rules: capture.SSHRules}
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
