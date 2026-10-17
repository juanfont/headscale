// Replay golden HuJSON captures under testdata/sshtest_results/*.hujson with
// the checks of [runTesterCompat]. Divergences are listed in
// knownSSHTesterDivergences with the engine gap each represents.

package v2

import (
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
)

// knownSSHTesterDivergences names the engine gap for each check where
// headscale and upstream disagree, keyed <test_id>/<check>.
var knownSSHTesterDivergences = map[string]string{
	"sshtest-accept-fail-no-ssh-rule/label":            sshTestNodeLabel,
	"sshtest-accept-fail-wrong-login-user/label":       sshTestNodeLabel,
	"sshtest-both-tests-pass-sshTests-fail/label":      sshTestNodeLabel,
	"sshtest-deny-fail-policy-allows/label":            sshTestNodeLabel,
	"sshtest-malformed-empty-user/label":               sshTestNodeLabel,
	"sshtest-mixed-acls-tcp22-allow-no-ssh-rule/label": sshTestNodeLabel,
	"sshtest-user-localpart-domain-mismatch/label":     sshTestNodeLabel,
	"sshtest-user-nonroot-blocks-root/label":           sshTestNodeLabel,
}

const sshTestNodeLabel = "SSHTEST_NODE_LABEL: headscale names each failing dst node by hostname; SaaS names the dst as written"

func TestSSHTesterCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "sshtest_results", "*.hujson"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no sshtest captures")

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err, "reading %s", file)

		t.Run(c.TestID, func(t *testing.T) {
			t.Parallel()

			runTesterCompat(t, c, knownSSHTesterDivergences)
		})
	}
}
