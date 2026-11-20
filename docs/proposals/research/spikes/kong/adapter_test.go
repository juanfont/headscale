package kongadapter

import (
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "kong", Adapter{}, "RESULT.md")
}
