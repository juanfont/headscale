package ownfix

import (
	"path/filepath"
	"testing"

	"spike/kit"
	grammar "spike/own-grammar"
)

// The fixes must keep kit v2 green.
func TestConformance(t *testing.T) {
	kit.Conformance(t, "ownfix", Adapter{}, filepath.Join(t.TempDir(), "conformance.md"))
	kit.Conformance(t, "delivered", grammar.Adapter{}, filepath.Join(t.TempDir(), "delivered.md"))
}
