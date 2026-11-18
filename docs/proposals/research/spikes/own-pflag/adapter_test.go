package own

import (
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "own-pflag", Adapter{}, "RESULT.md")
}
