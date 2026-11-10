package types

import (
	"testing"
)

// TestDerpConfigSkipsMalformedURL ensures a malformed derp.urls entry is
// skipped (as the "ignoring..." log promises) rather than dereferencing the
// nil *url.URL that url.Parse returns on error, which crashed the server at
// startup.
func TestDerpConfigSkipsMalformedURL(t *testing.T) {
	useConfig(t, map[string]any{"derp.urls": []string{
		"https://controlplane.tailscale.com/derpmap/default",
		"://bad",
	}})

	cfg := derpConfig("")

	if len(cfg.URLs) != 1 {
		t.Fatalf("expected the malformed derp.urls entry to be skipped, got %d urls: %v",
			len(cfg.URLs), cfg.URLs)
	}
}
