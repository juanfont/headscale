package creachadair

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "creachadair", Adapter{}, os.Getenv("CONF_OUT"))
}
