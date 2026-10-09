// Replay golden HuJSON captures under testdata/ssh_results/ssh-*.hujson:
// the 200 path compares headscale's compileSSHPolicy output node-by-node
// against the captured SSHRules; the non-200 path requires headscale to
// reject the same input with the captured error body as a substring.
// Divergences are listed in sshSkipReasons (200) and sshRejectSkipReasons
// (non-200) with the engine gap each represents.

package v2

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
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

					// Nil and empty SSHPolicy differ on the wire: nil
					// keeps the client's previous rules, empty clears
					// them. Take presence from the captured netmap.
					wantSSH := &tailcfg.SSHPolicy{Rules: capture.SSHRules}
					if capture.Netmap != nil && capture.Netmap.SSHPolicy == nil {
						wantSSH = nil
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

					// EquateEmpty hides "rules":null vs "rules":[];
					// pin the captured shape separately.
					if gotSSH != nil && capture.Netmap != nil &&
						capture.Netmap.SSHPolicy != nil {
						assert.Equalf(t,
							capture.Netmap.SSHPolicy.Rules == nil,
							gotSSH.Rules == nil,
							"%s/%s: rules null-vs-[] mismatch", tf.TestID, nodeName,
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

// sshLocalUser maps sshUser to a local user the way tailssh does for one
// rule: an exact entry wins, then "*"; "" means the rule does not apply.
func sshLocalUser(users map[string]string, sshUser string) string {
	local, ok := users[sshUser]
	if !ok {
		local = users["*"]
	}

	if local == "=" {
		return sshUser
	}

	return local
}

// assertSSHCheckParamsMatchRules checks SSHCheckParams against check rules as
// tailssh reads them: (src, dst, local user) must be found exactly when a
// holdAndDelegate rule for dst lists src as a principal and maps some SSH
// user to that local user.
func assertSSHCheckParamsMatchRules(
	t *testing.T,
	pm *PolicyManager,
	nodes types.Nodes,
	rulesFor func(dst *types.Node) []*tailcfg.SSHRule,
) {
	t.Helper()

	byIP := make(map[string]*types.Node)

	for _, n := range nodes {
		for _, ip := range n.IPs() {
			byIP[ip.String()] = n
		}
	}

	candidates := []string{"root", "nonroot-probe"}

	for _, dst := range nodes {
		for _, rule := range rulesFor(dst) {
			for user := range rule.SSHUsers {
				if user != "*" && !slices.Contains(candidates, user) {
					candidates = append(candidates, user)
				}
			}
		}
	}

	for _, dst := range nodes {
		want := make(map[types.NodeID]map[string]bool)

		for _, rule := range rulesFor(dst) {
			if rule.Action == nil || rule.Action.HoldAndDelegate == "" {
				continue
			}

			for _, p := range rule.Principals {
				src, ok := byIP[p.NodeIP]
				require.Truef(t, ok, "principal %q is not a node", p.NodeIP)

				if want[src.ID] == nil {
					want[src.ID] = make(map[string]bool)
				}

				for _, user := range candidates {
					if local := sshLocalUser(rule.SSHUsers, user); local != "" {
						want[src.ID][local] = true
					}
				}
			}
		}

		for _, src := range nodes {
			for _, user := range candidates {
				_, got := pm.SSHCheckParams(src.ID, dst.ID, user)
				assert.Equalf(t, want[src.ID][user], got,
					"SSHCheckParams(%s -> %s as %s)", src.Hostname, dst.Hostname, user)
			}
		}
	}
}

// TestSSHCheckParamsMatchesCaptures pins SSHCheckParams, which decides the
// SSH check callback, to the check rules Tailscale sent.
func TestSSHCheckParamsMatchesCaptures(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "ssh*_results", "*.hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	users := setupSSHDataCompatUsers()

	for _, file := range files {
		tf := loadSSHTestFile(t, file)
		if tf.Input.APIResponseCode != 200 {
			continue
		}

		if _, skip := sshSkipReasons[tf.TestID]; skip {
			continue
		}

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			nodes := buildGrantsNodesFromCapture(users, tf)

			pm, err := NewPolicyManager(
				[]byte(tf.Input.FullPolicy), users, nodes.ViewSlice(),
			)
			require.NoError(t, err)

			assertSSHCheckParamsMatchRules(t, pm, nodes,
				func(dst *types.Node) []*tailcfg.SSHRule {
					return tf.Captures[dst.GivenName].SSHRules
				})
		})
	}
}

// TestSSHCheckParamsMatchesCompiledRules pins SSHCheckParams to headscale's
// own compiled rules for shapes the captures lack, such as a user whose
// email localpart is root.
func TestSSHCheckParamsMatchesCompiledRules(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{Name: "root", Email: "root@example.com"},
		{Name: "alice", Email: "alice@example.com"},
	}
	users[0].ID = 1
	users[1].ID = 2

	nodes := types.Nodes{
		node("root-1", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
		node("root-2", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
		node("alice-1", "100.64.0.3", "fd7a:115c:a1e0::3", users[1]),
		node("server", "100.64.0.4", "fd7a:115c:a1e0::4", users[1]),
	}
	for i, n := range nodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec
	}

	nodes[3].Tags = []string{"tag:server"}

	check := func(dst string, users ...string) string {
		usersJSON, err := json.Marshal(users)
		require.NoError(t, err)

		return fmt.Sprintf(`{"action": "check", "src": ["autogroup:member"], "dst": [%q], "users": %s}`,
			dst, usersJSON)
	}

	for name, rules := range map[string][]string{
		"localpart on tag":            {check("tag:server", "localpart:*@example.com")},
		"localpart on self":           {check("autogroup:self", "localpart:*@example.com")},
		"localpart then root":         {check("tag:server", "localpart:*@example.com"), check("autogroup:self", "root")},
		"nonroot and literal on self": {check("autogroup:self", "autogroup:nonroot", "deploy")},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pol := fmt.Sprintf(`{"tagOwners": {"tag:server": ["alice@"]}, "ssh": [%s]}`,
				strings.Join(rules, ","))

			pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
			require.NoError(t, err)

			assertSSHCheckParamsMatchRules(t, pm, nodes,
				func(dst *types.Node) []*tailcfg.SSHRule {
					sshPol, err := pm.SSHPolicy("", dst.View())
					require.NoError(t, err)

					return sshPol.Rules
				})
		})
	}
}
