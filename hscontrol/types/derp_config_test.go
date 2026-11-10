package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDERPURLsMalformed: a malformed derp.urls entry stops the load, naming
// the key, instead of being skipped, as it once was after crashing startup
// on the nil *url.URL url.Parse returns.
func TestDERPURLsMalformed(t *testing.T) {
	useConfig(t, map[string]any{"derp.urls": []string{
		"https://controlplane.tailscale.com/derpmap/default",
		"://bad",
	}})

	_, err := src.decode()
	require.ErrorContains(t, err, "derp.urls is not an http:// or https:// URL")
}
