// Compatibility tests for the policy `sshTests` block, replaying captures
// recorded against a real Tailscale SaaS tailnet. The runner mirrors the
// pattern in policytester_compat_test.go: a single Glob over a testdata
// directory, one t.Run per file. Each capture is one of:
//
//   - APIResponseCode != 200 — the policy was rejected by SaaS, the
//     captured Message is the body the user saw, and headscale must
//     reject the same input with an error string that contains the same
//     body (substring match, allowing wrapping like "test(s) failed:\n…").
//   - APIResponseCode == 200 — SaaS accepted the policy (its sshTests
//     block passed); headscale's evaluateSSHTests must also pass.
//
// Captures live in testdata/sshtest_results/*.hujson. Scenarios in
// knownSSHTesterDivergences are skipped with their tracking note —
// these are real Tailscale ↔ headscale divergences that need engine-level
// fixes in follow-up PRs.
//
// Source format: github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
)

// knownSSHTesterDivergences tracks scenarios where headscale and SaaS
// disagree on whether a policy is accepted. Each entry should describe
// the engine area a follow-up PR needs to touch.
var knownSSHTesterDivergences = map[string]string{
	// SaaS resolves an IP-literal sshTests src to the owning node's
	// user identity and matches it against compiled SSH principals;
	// headscale's resolveSSHTestSource returns srcUserID=0 for any
	// non-Username alias and only consults principal NodeIPs, so an
	// IP that names a user-owned node misses every accept rule keyed
	// by that user. Fix in hscontrol/policy/v2/sshtest.go — extend
	// resolveSSHTestSource to recover the owning user when the src
	// resolves to exactly one user-owned node.
	"sshtest-ip-literal-src": "headscale does not map an IP-literal sshTests src to the owning node's user; SaaS does",

	// SaaS rejects `users: ["*"]` on an `ssh` rule at policy-parse
	// time with `user "*" is not valid`; headscale accepts the
	// wildcard and proceeds to evaluate sshTests against it. Fix in
	// hscontrol/policy/v2/types.go — reject `*` as an SSH login user
	// during SSH-rule validation.
	"sshtest-user-wildcard": "headscale accepts `users: [\"*\"]` on ssh rules; SaaS rejects with `user \"*\" is not valid`",
}

func TestSSHTesterCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "sshtest_results", "*.hujson"))
	require.NoError(t, err, "failed to glob test files")

	if len(files) == 0 {
		t.Skip("no sshtest captures yet")
	}

	users := setupSSHDataCompatUsers()
	nodes := setupSSHDataCompatNodes(users)

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err, "reading %s", file)

		t.Run(c.TestID, func(t *testing.T) {
			t.Parallel()

			if reason, skip := knownSSHTesterDivergences[c.TestID]; skip {
				t.Skip(reason)
			}

			policyJSON := []byte(c.Input.FullPolicy)

			pm, parseErr := NewPolicyManager(policyJSON, users, nodes.ViewSlice())

			if c.Input.APIResponseCode == 200 {
				require.NoError(t, parseErr,
					"tailscale accepted this policy; headscale must parse it")

				_, setErr := pm.SetPolicy(policyJSON)
				require.NoError(t, setErr,
					"tailscale accepted this policy; headscale sshTests must pass")

				return
			}

			var got error

			switch {
			case parseErr != nil:
				got = parseErr
			default:
				_, setErr := pm.SetPolicy(policyJSON)
				got = setErr
			}

			require.Error(t, got, "tailscale rejected; headscale must reject too")

			if c.Input.APIResponseBody == nil || c.Input.APIResponseBody.Message == "" {
				return
			}

			want := c.Input.APIResponseBody.Message
			if !strings.Contains(got.Error(), want) {
				t.Errorf("error body mismatch\n  tailscale wants: %q\n  headscale got:   %q", want, got.Error())
			}
		})
	}
}
