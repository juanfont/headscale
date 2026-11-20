package own

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "own-pflag", Adapter{}, os.Getenv("CONF_OUT"))
}
