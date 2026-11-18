package kongadapter

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "kong", Adapter{}, os.Getenv("CONF_OUT"))
}
