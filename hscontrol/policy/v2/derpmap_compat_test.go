// This file replays Tailscale SaaS captures of a policy derpMap and checks
// headscale accepts and rejects the same ones. Where SaaS words the error
// itself rather than passing on a JSON decode error, headscale must use the
// same words.
//
// Test data source: testdata/nodeattrs_results/nodeattrs-derpmap-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// derpMapSkipReasons lists the policies SaaS rejects for a reason headscale
// cannot check. An entry headscale starts to reject fails, so a fix must
// delete it.
//
//	TAILSCALE_DERP_IPS — SaaS rejects a custom node on the IP of one of its
//	    DERP servers. That takes Tailscale's live server list; the one in the
//	    tailscale.com module is a stale fallback.
var derpMapSkipReasons = map[string]string{
	"nodeattrs-derpmap-node-tailscale-ip": "TAILSCALE_DERP_IPS",
}

func TestDERPMapPolicyCompat(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "nodeattrs_results", "nodeattrs-derpmap-*.hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, file := range files {
		tf := loadGrantTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			pol, err := unmarshalPolicy(convertPolicyUserEmails(tf.Input.FullPolicy))
			if err == nil {
				err = pol.validate()
			}

			if reason, ok := derpMapSkipReasons[tf.TestID]; ok {
				require.NoError(t, err, "headscale refuses this policy; delete derpMapSkipReasons[%q]", tf.TestID)
				t.Skip(reason)
			}

			if tf.Input.APIResponseCode == http.StatusOK {
				require.NoError(t, err)

				return
			}

			msg := tf.Input.APIResponseBody.Message

			require.Error(t, err)

			// SaaS names its own DERP servers by host; headscale has no list of
			// them and rejects them by their domain.
			msg = strings.Replace(msg, "Tailscale host name", "Tailscale hostname or subdomain", 1)

			if !strings.HasPrefix(msg, "json:") {
				assert.Contains(t, err.Error(), msg)
			}
		})
	}
}
