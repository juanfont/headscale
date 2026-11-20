package headscale

import (
	"os"
	"testing"

	"spike/cmdline"
	"spike/kit"
)

func TestConformance(t *testing.T) {
	out := os.Getenv("CONF_OUT")
	if out == "" {
		out = "RESULT.md"
	}
	kit.Conformance(t, "final", Adapter{}, out)
}

// TestCheck: the tree the specs build is one the library reads unambiguously.
func TestCheck(t *testing.T) {
	if err := cmdline.Check(Root(kit.NewTree())); err != nil {
		t.Fatal(err)
	}
}
