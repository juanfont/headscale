package urfave

import (
	"os"
	"testing"

	"spike/kit"
)

func TestConformance(t *testing.T) {
	kit.Conformance(t, "urfave", Adapter{}, os.Getenv("CONF_OUT"))
}
