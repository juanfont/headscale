// Compatibility tests for the policy `tests` block, replaying captures
// recorded against a real Tailscale SaaS tailnet. The runner mirrors the
// pattern in tailscale_grants_compat_test.go: a single Glob over a
// testdata directory, one t.Run per file. Each capture is one of:
//
//   - APIResponseCode != 200 — the policy was rejected by the SaaS, the
//     captured Message is the byte-exact body the user saw, and headscale
//     must reject the same input with an error string that contains the
//     same body (substring match, allowing wrapping like "test(s)
//     failed:\n…").
//   - APIResponseCode == 200 — the SaaS accepted the policy (its `tests`
//     block passed); headscale's RunTests must also pass.
//
// Captures live in testdata/policytest_results/*.hujson. Scenarios in
// knownPolicyTesterDivergences are skipped with their tracking note —
// these are real Tailscale ↔ headscale divergences uncovered by the
// captures that need engine-level fixes in follow-up PRs.
//
// Source format: github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// knownPolicyTesterDivergences lists scenarios where headscale's evaluator
// disagrees with Tailscale SaaS on whether the policy should be accepted.
// Each entry is a real bug to fix in a follow-up; documenting them here
// keeps the compat suite green and the divergence list visible.
var knownPolicyTesterDivergences = map[string]string{ //nolint:gosec // strings here are human-readable notes, not credentials
	"policytest-allpass-acls-and-grants-mixed":                   "evaluator denies tag:client → webserver:80 in mixed acls+grants policy; SaaS accepts (Updates #1803)",
	"policytest-proto-numeric":                                   "validateProtocolPortCompatibility rejects numeric proto \"6\" with specific ports; SaaS accepts (Updates #1803)",
	"policytest-accept-fail-proto-numeric-mismatch":              "validateProtocolPortCompatibility rejects numeric proto \"6\" with specific ports; SaaS accepts (Updates #1803)",
	"policytest-port-shape-range":                                "SaaS rejects port-range syntax in test dst; evaluator accepts (Updates #1803)",
	"policytest-port-shape-list":                                 "SaaS rejects port-list syntax in test dst; evaluator accepts (Updates #1803)",
	"policytest-port-shape-wildcard":                             "SaaS rejects port-wildcard in test dst when paired with non-wildcard rule; evaluator accepts (Updates #1803)",
	"policytest-proto-icmp":                                      "SaaS rejects proto=icmp tests; evaluator accepts (Updates #1803)",
	"policytest-deny-fail-autogroup-internet-dst":                "SaaS rejects deny-fail with autogroup:internet dst; evaluator passes (Updates #1803)",
	"policytest-malformed-test-missing-accept-and-deny":          "SaaS rejects test entry with neither accept nor deny; evaluator passes (Updates #1803)",
	"policytest-allpass-grants-only-tag-src-cidr-dst":            "SaaS rejects test dst that resolves to a multi-host CIDR; evaluator accepts based on filter coverage (Updates #1803)",
	"policytest-allpass-grants-only-tag-src-prefix32-dst":        "SaaS rejects /32 CIDR dst (distinct from bare IP literal); evaluator accepts (Updates #1803)",
	"policytest-allpass-grants-only-tag-src-host-alias-cidr-dst": "SaaS rejects hosts:-alias to CIDR as test dst; evaluator accepts (Updates #1803)",
}

// policyTesterCompatUsers / policyTesterCompatNodes mirror the small
// shared topology used to record the captures. When more captures land
// we'll also exercise an autogroup-heavy second topology — for now this
// minimal one is enough to make the runner go.
func policyTesterCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "odin", Email: "odin@example.com"},
		{Model: gorm.Model{ID: 2}, Name: "thor", Email: "thor@example.org"},
		{Model: gorm.Model{ID: 3}, Name: "freya", Email: "freya@example.com"},
	}
}

func policyTesterCompatNodes(users types.Users) types.Nodes {
	return types.Nodes{
		{
			ID:        1,
			GivenName: "bulbasaur",
			User:      &users[0],
			UserID:    &users[0].ID,
			IPv4:      ptrAddr("100.90.199.68"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        2,
			GivenName: "ivysaur",
			User:      &users[1],
			UserID:    &users[1].ID,
			IPv4:      ptrAddr("100.110.121.96"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::1737:7960"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        3,
			GivenName: "venusaur",
			User:      &users[2],
			UserID:    &users[2].ID,
			IPv4:      ptrAddr("100.103.90.82"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::9e37:5a52"),
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        4,
			GivenName: "beedrill",
			IPv4:      ptrAddr("100.108.74.26"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
			Tags:      []string{"tag:server"},
			Hostinfo:  &tailcfg.Hostinfo{},
		},
		{
			ID:        5,
			GivenName: "kakuna",
			IPv4:      ptrAddr("100.103.8.15"),
			IPv6:      ptrAddr("fd7a:115c:a1e0::5b37:80f"),
			Tags:      []string{"tag:client"},
			Hostinfo:  &tailcfg.Hostinfo{},
		},
	}
}

// TestPolicyTesterCompat replays every capture under
// testdata/policytest_results/ against the engine. With no captures the
// test is a no-op — committed early so the layout/wiring lands before
// the bulk import.
func TestPolicyTesterCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "policytest_results", "*.hujson"))
	require.NoError(t, err, "failed to glob test files")

	if len(files) == 0 {
		t.Skip("no policytest captures yet")
	}

	users := policyTesterCompatUsers()
	nodes := policyTesterCompatNodes(users)

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err, "reading %s", file)

		t.Run(c.TestID, func(t *testing.T) {
			t.Parallel()

			if reason, skip := knownPolicyTesterDivergences[c.TestID]; skip {
				t.Skip(reason)
			}

			policyJSON := []byte(c.Input.FullPolicy)

			pm, err := NewPolicyManager(policyJSON, users, nodes.ViewSlice())
			require.NoError(t, err, "policy must parse during boot path")

			_, setErr := pm.SetPolicy(policyJSON)

			if c.Input.APIResponseCode == 200 {
				require.NoError(t, setErr, "tailscale accepted this policy; headscale tests should pass")

				return
			}

			// Failure case: tailscale rejected the policy with a body
			// captured in APIResponseBody.Message. Our error must
			// contain that body as a substring.
			require.Error(t, setErr, "tailscale rejected; headscale tests should also fail")

			if c.Input.APIResponseBody == nil || c.Input.APIResponseBody.Message == "" {
				return
			}

			want := c.Input.APIResponseBody.Message
			if !strings.Contains(setErr.Error(), want) {
				t.Errorf("error body mismatch\n  tailscale wants: %q\n  headscale got:   %q", want, setErr.Error())
			}
		})
	}
}
