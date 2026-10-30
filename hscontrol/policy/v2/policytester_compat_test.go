// Compatibility tests for the policy `tests` and `sshTests` blocks, replaying
// captures recorded against a real Tailscale SaaS tailnet. Each capture is
// checked in steps, see [runTesterCompat]:
//
//   - verdict: SaaS accepted the policy (200) exactly when headscale does;
//   - message: a refusal's message is contained in headscale's error;
//   - breakdown: the failures SaaS lists in its error data are the ones
//     headscale's evaluators report, see [requireFailureBreakdown];
//   - label: no node hostname appears in one report and not the other.
//
// Captures live in testdata/policytest_results/*.hujson; the sshTests ones
// are replayed by sshtester_compat_test.go.
//
// Source format: github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	tsapi "tailscale.com/client/tailscale/v2"
)

// knownPolicyTesterDivergences lists checks where headscale's evaluator
// differs from Tailscale SaaS, keyed <test_id>/<check>.
var knownPolicyTesterDivergences = map[string]string{ //nolint:gosec // strings here are human-readable notes, not credentials
	"policytest-accept-fail-proto-icmp-not-allowed/breakdown": testEntryErrors,
	"policytest-proto-icmp/breakdown":                         testEntryErrors,

	"policytest-dst-unknown-group/breakdown":      testUnknownAlias,
	"policytest-src-unknown-group/breakdown":      testUnknownAlias,
	"policytest-src-unknown-user-email/breakdown": testUnknownAlias,
}

const (
	testEntryErrors  = "TEST_ENTRY_ERRORS: SaaS reports the first shape error of a tests entry, headscale every one"
	testUnknownAlias = "TEST_UNKNOWN_ALIAS: SaaS reports a test naming an unknown user or group as not reached, headscale as an evaluation error"
)

// TestPolicyTesterCompat replays every capture under
// testdata/policytest_results/ against the engine.
func TestPolicyTesterCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "policytest_results", "*.hujson"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no policytest captures")

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err, "reading %s", file)

		t.Run(c.TestID, func(t *testing.T) {
			t.Parallel()

			runTesterCompat(t, c, knownPolicyTesterDivergences)
		})
	}
}

// runTesterCompat replays one tests or sshTests capture. SaaS validates the
// policy and runs both blocks in one POST; headscale parses first and runs
// the blocks in SetPolicy, so an error from either step is its refusal.
func runTesterCompat(t *testing.T, c *testcapture.Capture, skips map[string]string) {
	t.Helper()

	users := setupSSHDataCompatUsers()

	// Each capture pins its own topology IPs; range and address tests mean
	// nothing against other nodes.
	_ = runTesterCompatFor(t, c, skips, c.TestID+"/", users, buildGrantsNodesFromCapture(users, c))
}

// runTesterCompatFor is [runTesterCompat] against the given users and nodes,
// with its checks keyed under key. It returns headscale's refusal, if any.
func runTesterCompatFor(
	t *testing.T,
	c *testcapture.Capture,
	skips map[string]string,
	key string,
	users types.Users,
	nodes types.Nodes,
) error {
	t.Helper()

	policyJSON := []byte(c.Input.FullPolicy)

	pm, err := NewPolicyManager(policyJSON, users, nodes.ViewSlice())
	if err == nil {
		_, err = pm.SetPolicy(policyJSON)
	} else {
		pm = nil
	}

	var body testcapture.APIResponseBody
	if c.Input.APIResponseBody != nil {
		body = *c.Input.APIResponseBody
	}

	saasRefused := c.Input.APIResponseCode != http.StatusOK

	compatCheck(t, skips, key+"verdict", func() string {
		switch {
		case saasRefused && err == nil:
			return fmt.Sprintf("SaaS refused with %q; headscale accepted", body.Message)
		case !saasRefused && err != nil:
			return fmt.Sprintf("SaaS accepted; headscale refused: %v", err)
		}

		return ""
	})

	if !saasRefused || err == nil {
		compatChecksNotRun(t, skips, key+"message", key+"breakdown", key+"label")

		return err
	}

	compatCheck(t, skips, key+"message", func() string {
		if strings.Contains(err.Error(), body.Message) {
			return ""
		}

		return fmt.Sprintf("tailscale wants: %q\nheadscale got:   %q", body.Message, err.Error())
	})

	if len(body.Data) == 0 {
		compatChecksNotRun(t, skips, key+"breakdown", key+"label")

		return err
	}

	requireFailureBreakdown(t, skips, key+"breakdown", body.Data, c.Input.FullPolicy, pm, err)

	compatCheck(t, skips, key+"label", func() string {
		return cmp.Diff(nodeLabels(c, fmt.Sprint(body.Data)), nodeLabels(c, err.Error()))
	})

	return err
}

var (
	// [acl test error]: address "tag:server:22" (protocol "tcp"): want: Accept, got: Drop.
	saasTestFailRE = regexp.MustCompile(
		`^\[acl test error\]: address "(.+)" \(protocol "[^"]*"\): want: (Accept|Drop), got: (?:Accept|Drop)$`)

	// [ssh test error]: src "a" at "ip", dst "b" at "ip", ssh user "root": want: "accept" got: "deny".
	saasSSHTestFailRE = regexp.MustCompile(
		`^\[ssh test error\]: src ".*" at ".*", dst "([^"]*)" at "[^"]*", ssh user "(.*)": want: "(accept|check|deny)" got: "[a-z]+"$`)
)

// requireFailureBreakdown compares the failures SaaS lists in its error data
// with the ones headscale's evaluators report, as sorted lines of
// "src -> dst: want" (tests), "src/user: want @ dst" (sshTests) and
// "src: error" for an entry that could not be evaluated. Repeats are kept.
// Both name an sshTests src and dst as written.
func requireFailureBreakdown(
	t *testing.T,
	skips map[string]string,
	key string,
	data []tsapi.APIErrorData,
	policy string,
	pm *PolicyManager,
	refusal error,
) {
	t.Helper()

	var want []string

	for _, d := range data {
		for _, line := range d.Errors {
			if m := saasTestFailRE.FindStringSubmatch(line); m != nil {
				want = append(want, fmt.Sprintf("%s -> %s: %s", d.User, m[1], testWant(m[2] == "Accept")))

				continue
			}

			if m := saasSSHTestFailRE.FindStringSubmatch(line); m != nil {
				want = append(want, fmt.Sprintf("%s/%s: %s @ %s", d.User, m[2], m[3], m[1]))

				continue
			}

			want = append(want, d.User+": error")
		}
	}

	slices.Sort(want)

	compatCheck(t, skips, key, func() string {
		if pm != nil {
			return cmp.Diff(want, testerBreakdown(pm))
		}

		got, err := parseRefusalBreakdown(policy, refusal)
		if err != nil {
			return err.Error()
		}

		return cmp.Diff(want, got)
	})
}

// parseRefusalEntryRE finds the entries a parse-time refusal names; the
// parser reports tests and sshTests entries by index.
var parseRefusalEntryRE = regexp.MustCompile(`(?m)^\s*(test|sshTest) (\d+)\b`)

// parseRefusalBreakdown renders a refusal headscale gave before running the
// tests: one "src: error" per entry it names.
func parseRefusalBreakdown(policy string, refusal error) ([]string, error) {
	type entry struct {
		Src string `json:"src"`
	}

	var raw struct {
		Tests    []entry `json:"tests"`
		SSHTests []entry `json:"sshTests"`
	}

	err := json.Unmarshal([]byte(policy), &raw)
	if err != nil {
		return nil, fmt.Errorf("reading test entries: %w", err)
	}

	var out []string

	for _, m := range parseRefusalEntryRE.FindAllStringSubmatch(refusal.Error(), -1) {
		entries := raw.Tests
		if m[1] == "sshTest" {
			entries = raw.SSHTests
		}

		i, err := strconv.Atoi(m[2])
		if err != nil || i >= len(entries) {
			return nil, fmt.Errorf("refusal names %s %s, which the policy does not have: %w", m[1], m[2], refusal)
		}

		out = append(out, entries[i].Src+": error")
	}

	slices.Sort(out)

	return out, nil
}

func testWant(accept bool) string {
	if accept {
		return "accept"
	}

	return "deny"
}

// testerBreakdown runs both blocks as the boot path does and renders the
// failures as [requireFailureBreakdown] does.
func testerBreakdown(pm *PolicyManager) []string {
	var out []string

	for _, res := range runPolicyTests(pm.pol, pm.filter, pm.users, pm.nodes).Results {
		for range res.Errors {
			out = append(out, res.Src+": error")
		}

		for _, dst := range res.AcceptFail {
			out = append(out, fmt.Sprintf("%s -> %s: %s", res.Src, dst, testWant(true)))
		}

		for _, dst := range res.DenyFail {
			out = append(out, fmt.Sprintf("%s -> %s: %s", res.Src, dst, testWant(false)))
		}
	}

	for _, res := range runSSHPolicyTests(pm.pol, pm.users, pm.nodes).Results {
		for range res.Errors {
			out = append(out, res.Src+": error")
		}

		for want, fails := range map[string]map[string][]string{
			"accept": res.AcceptFail,
			"deny":   res.DenyFail,
			"check":  res.CheckFail,
		} {
			for user, dsts := range fails {
				for _, dst := range dsts {
					out = append(out, fmt.Sprintf("%s/%s: %s @ %s", res.Src, user, want, dst))
				}
			}
		}
	}

	slices.Sort(out)

	return out
}

// nodeLabels lists the capture's hostnames that text names while the policy
// does not, so they are there only because the report labels nodes.
func nodeLabels(c *testcapture.Capture, text string) []string {
	var out []string

	for _, n := range c.Topology.Nodes {
		if !strings.Contains(c.Input.FullPolicy, n.Hostname) && strings.Contains(text, n.Hostname) {
			out = append(out, n.Hostname)
		}
	}

	slices.Sort(out)

	return out
}

// compatCheck runs one check of a capture as a subtest named after the last
// element of key; mismatch returns "" when headscale matches SaaS. A key in
// skips is a known difference that must still differ, so the fix that makes
// it match has to delete the entry.
func compatCheck(t *testing.T, skips map[string]string, key string, mismatch func() string) {
	t.Helper()

	t.Run(path.Base(key), func(t *testing.T) {
		diff := mismatch()
		reason, listed := skips[key]

		switch {
		case listed && diff == "":
			t.Errorf("matches SaaS; delete the skip entry %q (%s)", key, reason)
		case listed:
			t.Skip(reason)
		case diff != "":
			t.Error(diff)
		}
	})
}

// compatChecksNotRun fails for a listed check that cannot run, since its
// entry could never go stale.
func compatChecksNotRun(t *testing.T, skips map[string]string, keys ...string) {
	t.Helper()

	for _, key := range keys {
		if _, listed := skips[key]; listed {
			t.Errorf("check %q does not run for this capture; delete its skip entry", key)
		}
	}
}
