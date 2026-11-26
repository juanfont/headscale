package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

// TestReleases: the lookup reads the tag names, and its request ends with
// its context rather than at the exit of the process.
func TestReleases(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no lookup on this system")
	}

	arrived, ended := make(chan struct{}), make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("hang") {
			close(arrived)
			<-r.Context().Done()
			close(ended)

			return
		}

		_, _ = w.Write([]byte(`[{"name": "v0.30.1"}, {"name": "v0.31.0-beta.1"}]`))
	}))

	t.Cleanup(func() { s.CloseClientConnections(); s.Close() })

	tags, err := releases(s.URL)(t.Context())
	require.NoError(t, err)
	require.Equal(t, []string{"v0.30.1", "v0.31.0-beta.1"}, tags)

	ctx, cancel := context.WithCancel(t.Context())

	go func() { <-arrived; cancel() }()

	_, err = releases(s.URL + "?hang")(ctx)
	require.ErrorIs(t, err, context.Canceled)

	select {
	case <-ended:
	case <-time.After(10 * time.Second):
		t.Fatal("the request to GitHub outlived its context")
	}
}
