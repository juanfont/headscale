package cobraadapter

import (
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "cobra", Adapter{}, "conformance.md")
}
