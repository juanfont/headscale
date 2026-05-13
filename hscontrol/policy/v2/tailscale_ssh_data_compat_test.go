// Replay golden HuJSON captures under testdata/ssh_results/ssh-*.hujson:
// the 200 path compares headscale's compileSSHPolicy output node-by-node
// against the captured SSHRules; the non-200 path requires headscale to
// reject the same input with the captured error body as a substring.
// Divergences are listed in sshSkipReasons (200) and sshRejectSkipReasons
// (non-200) with the engine gap each represents.

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

// setupSSHDataCompatUsers returns three users straddling two email
// domains so that "localpart:*@example.com" resolves to exactly two
// users (odin, freya) and the cross-domain case stays covered through
// thor on @example.org.
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

// sshSkipReasons documents captures the upstream control plane accepts
// but headscale cannot yet represent. Each entry names the feature gap.
var sshSkipReasons = map[string]string{
	"ssh-b5":  "headscale has no passkey authentication; user:*@passkey wildcard unsupported",
	"ssh-d10": "headscale has no passkey authentication; user:*@passkey wildcard unsupported",
}

// sshRejectSkipReasons documents captures the upstream control plane
// rejects for reasons headscale cannot apply. Each entry names the
// feature gap.
var sshRejectSkipReasons = map[string]string{
	"ssh-b4": "headscale has no associated-tailnet-domains config; user:*@domain / localpart:*@domain are not domain-validated",
	"ssh-d1": "headscale has no associated-tailnet-domains config; user:*@domain / localpart:*@domain are not domain-validated",
	"ssh-e1": "headscale has no associated-tailnet-domains config; user:*@domain / localpart:*@domain are not domain-validated",
	"ssh-e2": "headscale has no associated-tailnet-domains config; user:*@domain / localpart:*@domain are not domain-validated",
	"ssh-malformed-user-localpart-multi-glob": "headscale has no associated-tailnet-domains config; user:*@domain / localpart:*@domain are not domain-validated",
}

// TestSSHDataCompat loads every ssh-*.hujson capture, parses the policy
// it pinned, and compiles the same per-node SSH rules to compare against
// the captured shape. Non-200 captures replay the rejection path: the
// recorded error body must appear as a substring of headscale's
// rejection.
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

			// Each capture pins its own topology IPs, so nodes are
			// rebuilt from the capture rather than a shared fixture.
			nodes := buildGrantsNodesFromCapture(users, tf)

			policyJSON := []byte(tf.Input.FullPolicy)

			if tf.Input.APIResponseCode != 200 {
				if reason, ok := sshRejectSkipReasons[tf.TestID]; ok {
					t.Skipf("skipping: %s", reason)
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

			if reason, ok := sshSkipReasons[tf.TestID]; ok {
				t.Skipf("skipping: %s", reason)
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
