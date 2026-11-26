package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestListPagesThroughBinary: the built CLI reads a page of users list by
// the one rule: rows null, a row null and a row with no member are an
// answer it cannot read, exit 1; an empty page is an empty list.
func TestListPagesThroughBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}

	bin := filepath.Join(t.TempDir(), "headscale")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	version := types.GetVersionInfo().Version

	for _, tt := range []struct {
		name, page, stdout, stderr string
		code                       int
	}{
		{name: "an empty page", page: `{"users": []}`, stdout: "[]\n"},
		{name: "rows null", page: `{"users": null}`, stderr: "its users is null.", code: 1},
		{name: "a row null", page: `{"users": [null]}`, stderr: "its users[0] is null.", code: 1},
		{name: "a row empty", page: `{"users": [{}]}`, stderr: "it has no users[0].created.", code: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Headscale-Version", version)
				_, _ = w.Write([]byte(tt.page))
			}))
			t.Cleanup(s.Close)

			var stdout, stderr bytes.Buffer

			cmd := exec.CommandContext(t.Context(), bin, "users", "list", "-o", "json")
			cmd.Env = append(os.Environ(), "HEADSCALE_CLI_ADDRESS="+s.URL, "HEADSCALE_CLI_API_KEY=key", "HOME="+t.TempDir())
			cmd.Stdout, cmd.Stderr = &stdout, &stderr

			_ = cmd.Run()
			require.Equal(t, tt.code, cmd.ProcessState.ExitCode(), stderr.String())
			require.Equal(t, tt.stdout, stdout.String())
			require.Contains(t, stderr.String(), tt.stderr)
		})
	}
}
