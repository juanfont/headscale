package urfave

import (
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "urfave", Adapter{}, "conformance.md")
}
