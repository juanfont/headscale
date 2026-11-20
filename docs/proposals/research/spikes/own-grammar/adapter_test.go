package own

import (
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "own-grammar", Adapter{}, "RESULT.md")
}
