package own

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "own-grammar-fix", Adapter{}, os.Getenv("CONF_OUT"))
}
