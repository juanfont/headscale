package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// writeExample writes the generated example as config.yaml in a new
// directory, which it returns.
func writeExample(t *testing.T) string {
	t.Helper()

	d := config.Default()

	out, err := config.GenerateExample(&d, config.ExampleOptions{Docs: true})
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), out, 0o600))

	return dir
}

func TestConfigFileLoading(t *testing.T) {
	l, err := config.Load(filepath.Join(writeExample(t), "config.yaml"), true, nil)
	require.NoError(t, err)

	assertDefaultConfig(t, l.Config)
}

func TestConfigLoading(t *testing.T) {
	l, err := config.Load(writeExample(t), false, nil)
	require.NoError(t, err)

	assertDefaultConfig(t, l.Config)
}

// assertDefaultConfig checks the example loaded as the defaults it prints.
func assertDefaultConfig(t *testing.T, cfg *types.Config) {
	t.Helper()

	want := config.Default()
	if diff := cmp.Diff(&want, cfg,
		cmpopts.EquateEmpty(),
		cmpopts.EquateComparable(netip.Prefix{}),
		cmpopts.IgnoreFields(types.Config{}, "ConfigDir"),
		cmpopts.IgnoreUnexported(types.Config{}),
	); diff != "" {
		t.Errorf("example loads as (-default +loaded):\n%s", diff)
	}
}
