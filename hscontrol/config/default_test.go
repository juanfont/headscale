package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateHintsNameDefaults: the defaults Validate's hints quote, which
// types cannot read from Default, are Default's.
func TestValidateHintsNameDefaults(t *testing.T) {
	d := Default()

	cfg := Default()
	cfg.Tuning.NodeStoreBatchSize = 0
	cfg.Tuning.NodeStoreBatchTimeout = 0

	err := Validate(&cfg)
	require.ErrorContains(t, err, fmt.Sprintf("(default: %d)", d.Tuning.NodeStoreBatchSize))
	require.ErrorContains(t, err, fmt.Sprintf("(default: %s)", d.Tuning.NodeStoreBatchTimeout))
}
