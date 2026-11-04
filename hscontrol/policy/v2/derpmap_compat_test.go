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

			if tf.Input.APIResponseCode == http.StatusOK {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)

			msg := tf.Input.APIResponseBody.Message
			if !strings.HasPrefix(msg, "json:") {
				assert.Contains(t, err.Error(), msg)
			}
		})
	}
}
