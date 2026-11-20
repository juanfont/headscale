package libhs

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	out := os.Getenv("CONF_OUT")
	if out == "" {
		out = "RESULT.md"
	}
	kit.Conformance(t, "lib-headscale", Adapter{}, out)
}
