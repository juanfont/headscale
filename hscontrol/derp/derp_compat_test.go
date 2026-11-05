// This file replays Tailscale SaaS captures of a tailnet policy derpMap
// against [ApplyPolicy] and the derp.paths loader.
//
// Test data source: ../policy/v2/testdata/nodeattrs_results/nodeattrs-derpmap-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package derp

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
)

const derpCaptures = "../policy/v2/testdata/nodeattrs_results/"

// policyDERPMap returns the derpMap of a capture's policy as written.
func policyDERPMap(t *testing.T, c *testcapture.Capture) json.RawMessage {
	t.Helper()

	policy, err := hujson.Standardize([]byte(c.Input.FullPolicy))
	require.NoError(t, err)

	var p struct {
		DERPMap json.RawMessage `json:"derpMap"`
	}

	require.NoError(t, json.Unmarshal(policy, &p))

	return p.DERPMap
}

// TestApplyPolicySaaSCompat checks that the map a SaaS client got is SaaS's
// default map with the policy's derpMap applied as [ApplyPolicy] applies it,
// and that no SaaS client ever got HomeParams.
func TestApplyPolicySaaSCompat(t *testing.T) {
	// Its policy sets no regions, so its clients got the default map.
	plain, err := testcapture.Read(derpCaptures + "nodeattrs-derpmap-homeparams-regionscore.hujson")
	require.NoError(t, err)

	var base *tailcfg.DERPMap
	for _, node := range plain.Captures {
		base = node.Netmap.DERPMap
	}

	require.NotEmpty(t, base.Regions)
	require.NoError(t, validateRegions(base), "Tailscale's own map must pass the rules every DERP map does")

	files, err := filepath.Glob(derpCaptures + "nodeattrs-derpmap-*.hujson")
	require.NoError(t, err)

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err)

		t.Run(c.TestID, func(t *testing.T) {
			var pol *tailcfg.DERPMap
			if c.Input.APIResponseCode == http.StatusOK {
				require.NoError(t, json.Unmarshal(policyDERPMap(t, c), &pol))
			}

			for name, node := range c.Captures {
				if node.Netmap == nil || node.Netmap.DERPMap == nil {
					continue
				}

				got := node.Netmap.DERPMap
				assert.Nil(t, got.HomeParams, "SaaS sent HomeParams to %s", name)

				// A rejected policy leaves the default map in place.
				if diff := cmp.Diff(ApplyPolicy(base, pol).Regions, got.Regions); diff != "" {
					t.Errorf("%s: regions mismatch (-headscale +SaaS):\n%s", name, diff)
				}
			}
		})
	}
}

// TestLoadDERPMapFromPathSaaSDecodeErrors checks a derp.paths file holding a
// derpMap SaaS cannot decode (wrong type, unknown key) fails to load too.
// SaaS's region rules do not apply: a file is the whole map, not an overlay.
func TestLoadDERPMapFromPathSaaSDecodeErrors(t *testing.T) {
	files, err := filepath.Glob(derpCaptures + "nodeattrs-derpmap-*.hujson")
	require.NoError(t, err)

	var checked int

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err)

		body := c.Input.APIResponseBody
		if body == nil || !strings.HasPrefix(body.Message, "json:") {
			continue
		}

		checked++

		t.Run(c.TestID, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "derp.json")
			require.NoError(t, os.WriteFile(path, policyDERPMap(t, c), 0o600))

			_, err := loadDERPMapFromPath(path)
			require.Error(t, err, "SaaS: %s", body.Message)
		})
	}

	require.NotZero(t, checked)
}
