package creachadair

import (
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "creachadair", Adapter{}, "conformance.md")
}
