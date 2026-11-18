package cobraadapter

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "cobra", Adapter{}, os.Getenv("CONF_OUT"))
}
