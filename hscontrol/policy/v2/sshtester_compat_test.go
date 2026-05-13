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
	// SaaS parse-accepts a bare IPv6 sshTests dst but engine-rejects
	// the same input with "test(s) failed" while the matching IPv4
	// scenario engine-passes. The two captures share the same topology
	// and the same policy shape, so the asymmetry is in the SaaS
	// sshTests evaluator's IPv6 handling, not in any rule the user
	// wrote. Headscale's evaluator resolves both literals to the
	// tagged node that carries them and the assertion passes — a
	// follow-up needs to either reproduce the SaaS-side IPv6 quirk or
	// confirm this is a SaaS bug we will not match.
	"sshtest-malformed-dst-bare-ipv6": "engine: SaaS rejects bare IPv6 sshTests dst; headscale accepts (IPv4 mirror passes both sides)",
}

func TestSSHTesterCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "sshtest_results", "*.hujson"))
	require.NoError(t, err, "failed to glob test files")

	if len(files) == 0 {
		t.Skip("no sshtest captures yet")
	}

	users := setupSSHDataCompatUsers()

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err, "reading %s", file)

		t.Run(c.TestID, func(t *testing.T) {
			t.Parallel()

			if reason, skip := knownSSHTesterDivergences[c.TestID]; skip {
				t.Skip(reason)
			}

			// Per-capture nodes mean the topology IPs (which a
			// policy `hosts` mapping references by literal IP)
			// resolve to real nodes in the test fixture. Without
			// this the static fixture's IPs do not overlap with
			// the captures and host-alias dsts resolve to no
			// nodes — that path is now a load-bearing failure.
			nodes := buildGrantsNodesFromCapture(users, c)

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
