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
	"sshtest-malformed-dst-bare-ipv6/verdict": "bare-IPv6 sshTests dst: upstream parse-accepts then engine-rejects; headscale accepts (IPv4 mirror passes both sides)",

	"sshtest-accept-fail-no-ssh-rule/label":            sshTestNodeLabel,
	"sshtest-accept-fail-wrong-login-user/label":       sshTestNodeLabel,
	"sshtest-both-tests-pass-sshTests-fail/label":      sshTestNodeLabel,
	"sshtest-deny-fail-policy-allows/label":            sshTestNodeLabel,
	"sshtest-malformed-empty-user/label":               sshTestNodeLabel,
	"sshtest-mixed-acls-tcp22-allow-no-ssh-rule/label": sshTestNodeLabel,
	"sshtest-user-localpart-domain-mismatch/label":     sshTestNodeLabel,
	"sshtest-user-nonroot-blocks-root/label":           sshTestNodeLabel,
	"sshtest-fail-label-host-alias/label":              sshTestNodeLabel,
	"sshtest-fail-label-ip-dst/label":                  sshTestNodeLabel,
	"sshtest-fail-label-same-node-twice/label":         sshTestNodeLabel,
	"sshtest-fail-label-user-dst/label":                sshTestNodeLabel,
	"sshtest-group-split-actions-check/label":          sshTestNodeLabel,
	"sshtest-repeated-names/label":                     sshTestNodeLabel,
	"sshtest-report-multi/label":                       sshTestNodeLabel,
	"sshtest-src-unassigned-ip-accept/label":           sshTestNodeLabel,

	"sshtest-src-cidr24-deny/message":           sshTestSrcRange,
	"sshtest-src-cidr31-empty-accept/message":   sshTestSrcRange,
	"sshtest-src-cidr31-empty-deny/verdict":     sshTestSrcRange,
	"sshtest-src-cidr31-hole-accept/message":    sshTestSrcRange,
	"sshtest-src-cidr31-members-accept/verdict": sshTestSrcRange,
	"sshtest-src-hosts-cidr-deny/verdict":       sshTestSrcRange,

	"sshtest-fail-label-autogroup-member/message": sshTestDstMember,
	"sshtest-check-reason-mixed-alias/message":    sshTestDstMember,

	"sshtest-group-split-actions-accept/verdict": "SSHTEST_SRC_ONE_RULE: SaaS needs one accept rule to cover a group source; headscale lets each member pass through its own accept or check rule",
	"sshtest-group-split-actions-deny/verdict":   "SSHTEST_SRC_ONE_RULE: SaaS denies a group source no single rule covers; headscale fails the deny because each member is let in",

	"sshtest-fail-label-same-node-twice/breakdown": "SSHTEST_PER_ALIAS: SaaS reports each dst alias, also two naming one node; headscale checks each node once",
	"sshtest-fail-label-ip-no-device/breakdown":    sshTestNoDevice,
	"sshtest-report-multi/breakdown":               "SSHTEST_PER_ALIAS+SSHTEST_NO_DEVICE: SaaS reports one line per dst alias and a deviceless alias as not reached; headscale one per node and an error",
	"sshtest-src-unassigned-ip-accept/breakdown":   "SSHTEST_SRC_LABEL: SaaS labels a single-address source as written, headscale as a /32 prefix",
}

const (
	sshTestNodeLabel = "SSHTEST_NODE_LABEL: headscale names each failing dst node by hostname; SaaS names the dst as written"
	sshTestSrcRange  = "SSHTEST_SRC_RANGE: SaaS refuses a CIDR, or a host alias holding one, as an sshTests source when parsing; headscale evaluates it"
	sshTestDstMember = "SSHTEST_DST_MEMBER: SaaS refuses autogroup:member as an sshTests destination when parsing; headscale evaluates it"
	sshTestNoDevice  = "SSHTEST_NO_DEVICE: SaaS reports a dst that selects no device as not reached; headscale as an error"
)

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
