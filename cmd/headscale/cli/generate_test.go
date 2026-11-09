package cli

import (
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	apiv1 "github.com/juanfont/headscale/hscontrol/api/v1"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// serveConfig serves handler on a unix socket at sock, as the server's
// API would.
func serveConfig(t *testing.T, sock string, handler http.HandlerFunc) {
	t.Helper()

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "unix", sock)
	require.NoError(t, err)

	srv := httptest.NewUnstartedServer(handler)
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
}

// TestGenerateConfigRunningRoundTrip: a server holding every key away from
// its default prints, through the real v1 API, generated client and CLI, a
// file that loads back to the same typed values, but for the cli section,
// which is left out, and credentials, which are redacted: literal secrets
// and DNS provider settings, and URL userinfo. Values compare as loaded,
// not rendered, so a renderer that drops or reorders cannot hide it.
func TestGenerateConfigRunningRoundTrip(t *testing.T) {
	d := config.Default()
	defaults := typedLeaves(&d)
	redacted := types.Secret("literal").Redacted()
	opts := cmp.Options{cmpopts.EquateComparable(netip.Prefix{})}

	const userinfo = "marker-user:marker-pass@"

	// Every leaf at its example, every bool at !default. Secrets and the
	// provider's credential are file: references, URLs have no userinfo.
	written := map[string]any{}

	for _, f := range types.ConfigFields(&d) {
		var v any
		if f.Field.Type.Kind() == reflect.Bool {
			v = !f.Value.Bool()
		} else {
			tag, ok := f.Field.Tag.Lookup("example")
			require.True(t, ok, "%s: no example", f.Path)
			require.NoError(t, json.Unmarshal([]byte(tag), &v), f.Path)
		}

		written[f.Path] = v
	}

	// database.type's example is its default, which would hide a dropped key.
	written["database.type"] = string(types.DatabasePostgres)

	// literal is written with a credential in every place one can hide.
	literal := maps.Clone(written)
	markers := []string{"marker-user", "marker-pass"}
	secretPaths, providerPaths, urlPaths := map[string]bool{}, map[string]bool{}, map[string]bool{}

	for _, f := range types.ConfigFields(&d) {
		switch v := written[f.Path]; {
		case f.Field.Type == reflect.TypeFor[types.Secret]():
			literal[f.Path] = "marker-secret-" + f.Path
			markers = append(markers, "marker-secret-"+f.Path)
			secretPaths[f.Path] = true
		case f.Field.Type == reflect.TypeFor[map[string]any]():
			settings := maps.Clone(v.(map[string]any))
			settings["marker_token"] = "marker-provider-token"
			settings["marker_zone"] = 987654321
			literal[f.Path] = settings
			markers = append(markers, "marker-provider-token", "987654321")
			providerPaths[f.Path] = true
		case strings.Contains(fmt.Sprint(v), "://"):
			literal[f.Path] = withUserinfo(v, userinfo)
			urlPaths[f.Path] = true
		}
	}

	writtenCfg := loadLeaves(t, written)
	want := typedLeaves(writtenCfg)

	for path, v := range want {
		assert.False(t, cmp.Equal(defaults[path], v, opts), "%s: example is the default", path)
	}

	// A dropped list element must show: the example lists two proxies.
	require.Len(t, writtenCfg.TrustedProxies, 2)

	dir, err := os.MkdirTemp("", "hs") // short: a socket path is limited
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	for _, tt := range []struct {
		name   string
		cfg    *types.Config
		redact bool
	}{
		{name: "as written", cfg: writtenCfg},
		{name: "literal credentials", cfg: loadLeaves(t, literal), redact: true},
	} {
		sock := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "-")+".sock")
		mux, _ := apiv1.Handler(apiv1.Backend{Cfg: tt.cfg})
		serveConfig(t, sock, apiv1.WithLocalTrust(mux).ServeHTTP)
		cliConfig := writeFile(t, dir, filepath.Base(sock)+".yaml", "unix_socket: "+sock+"\n")

		for _, docs := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, docs %t", tt.name, docs), func(t *testing.T) {
				args := []string{"-c", cliConfig, "generate", "config", "--running"}
				if !docs {
					args = append(args, "--no-docs")
				}

				stdout, stderr, err := runHeadscale(t, nil, args...)
				require.NoError(t, err, stderr)
				assert.Equal(t, docs, regexp.MustCompile(`(?m)^\s*#`).MatchString(stdout), "documentation comments")

				var doc map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(stdout), &doc), stdout)
				assert.NotContains(t, doc, "cli")

				if tt.redact {
					for _, m := range markers {
						assert.NotContains(t, stdout, m)
					}
				}

				got := typedLeaves(loadFile(t, writeFile(t, t.TempDir(), "running.yaml", stdout)))

				for _, f := range types.ConfigFields(tt.cfg) {
					expect := f.Value.Interface()

					switch {
					case strings.HasPrefix(f.Path, "cli."):
						expect = defaults[f.Path] // left out, so loaded as the default
					case tt.redact && secretPaths[f.Path]:
						expect = types.Secret(redacted)
					case tt.redact && providerPaths[f.Path]:
						settings := maps.Clone(want[f.Path].(map[string]any))
						settings["marker_token"], settings["marker_zone"] = redacted, redacted
						expect = settings
					case tt.redact && urlPaths[f.Path]:
						expect = want[f.Path] // userinfo stripped
					}

					if diff := cmp.Diff(expect, got[f.Path], opts); diff != "" {
						t.Errorf("%s (-want +got):\n%s", f.Path, diff)
					}
				}
			})
		}
	}
}

// withUserinfo is v, a URL or a list of them, with userinfo added to each.
func withUserinfo(v any, userinfo string) any {
	switch x := v.(type) {
	case string:
		return strings.Replace(x, "://", "://"+userinfo, 1)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = withUserinfo(e, userinfo)
		}

		return out
	}

	return v
}

// loadLeaves loads a file that sets each dotted path of leaves to its value.
func loadLeaves(t *testing.T, leaves map[string]any) *types.Config {
	t.Helper()

	nested := map[string]any{}

	for path, v := range leaves {
		m := nested
		parts := strings.Split(path, ".")

		for _, p := range parts[:len(parts)-1] {
			if m[p] == nil {
				m[p] = map[string]any{}
			}

			m = m[p].(map[string]any)
		}

		m[parts[len(parts)-1]] = v
	}

	b, err := json.Marshal(nested)
	require.NoError(t, err)

	return loadFile(t, writeFile(t, t.TempDir(), "config.json", string(b)))
}

// loadFile is path as config.Load reads it, which must be without warnings.
func loadFile(t *testing.T, path string) *types.Config {
	t.Helper()

	l, err := config.Load(path, true, nil)
	require.NoError(t, err)
	require.Empty(t, l.Warnings)

	return l.Config
}

// typedLeaves is every leaf of cfg by dotted path, as cfg holds it.
func typedLeaves(cfg *types.Config) map[string]any {
	leaves := map[string]any{}
	for _, f := range types.ConfigFields(cfg) {
		leaves[f.Path] = f.Value.Interface()
	}

	return leaves
}

// TestGenerateConfigCommand: generate config prints the example and only
// it, whatever config and variables are around; --running prints what the
// server answers, as it answers it, and nothing when it fails, with its own
// load warnings on stderr whatever its log settings.
func TestGenerateConfigCommand(t *testing.T) {
	const (
		running       = "# Documented.\nserver_url: https://running.example.com\n"
		runningNoDocs = "server_url: https://running.example.com\n"
	)

	home := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(home, ".headscale"), 0o700))
	writeFile(t, filepath.Join(home, ".headscale"), "config.yaml", "bogus_key: 1\n")

	dir := t.TempDir()
	broken := writeFile(t, dir, "broken.yaml", "bogus_key: 1\n")

	serveConfig(t, filepath.Join(dir, "ok.sock"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/config" {
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/yaml")

		if r.URL.Query().Get("docs") == "false" {
			_, _ = w.Write([]byte(runningNoDocs))
		} else {
			_, _ = w.Write([]byte(running))
		}
	})
	serveConfig(t, filepath.Join(dir, "failing.sock"), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":500,"title":"Internal Server Error","detail":"rendering configuration"}`))
	})

	socket := func(name string) string {
		return writeFile(t, dir, name+".yaml", "unix_socket: "+filepath.Join(dir, name+".sock")+"\ncli:\n  timeout: 1s\n")
	}
	ok, failing, absent := socket("ok"), socket("failing"), socket("absent")
	logging := func(name, setting string) string {
		return writeFile(t, dir, name+".yaml", "unix_socket: "+filepath.Join(dir, "ok.sock")+"\nlog:\n  "+setting+"\n")
	}

	env := []string{"HOME=" + home, "HEADSCALE_BOGUS=1"}
	// The console form: log.format: json does not apply.
	const warning = "WRN unknown environment variable HEADSCALE_BOGUS"

	tests := []struct {
		name       string
		args       []string
		wantErr    bool
		wantStdout []string
		hideStdout []string
		wantExact  string   // all of stdout, when set
		wantStderr []string // nil when stderr must be empty
		wantLoaded bool     // stdout loads to Default()
	}{
		{name: "example", args: []string{"generate", "config"}, wantStdout: []string{"# Every key"}, wantLoaded: true},
		{name: "alias", args: []string{"gen", "config"}, wantLoaded: true},
		{name: "no docs", args: []string{"generate", "config", "--no-docs"}, hideStdout: []string{"#"}, wantLoaded: true},
		{name: "running", args: []string{"-c", ok, "generate", "config", "--running"}, wantExact: running, wantStderr: []string{warning}},
		{name: "running no docs", args: []string{"-c", ok, "generate", "config", "--running", "--no-docs"}, wantExact: runningNoDocs, wantStderr: []string{warning}},
		{name: "running log level error", args: []string{"-c", logging("error", "level: error"), "generate", "config", "--running"}, wantExact: running, wantStderr: []string{warning}},
		{name: "running log level disabled", args: []string{"-c", logging("disabled", "level: disabled"), "generate", "config", "--running"}, wantExact: running, wantStderr: []string{warning}},
		{name: "running log format json", args: []string{"-c", logging("json", "format: json"), "generate", "config", "--running"}, wantExact: running, wantStderr: []string{warning}},
		{name: "running server error", args: []string{"-c", failing, "generate", "config", "--running"}, wantErr: true, wantStderr: []string{warning, "rendering configuration"}},
		{name: "running without a server", args: []string{"-c", absent, "generate", "config", "--running"}, wantErr: true, wantStderr: []string{warning, "asking the server for its configuration"}},
		{name: "running broken", args: []string{"-c", broken, "generate", "config", "--running"}, wantErr: true, wantStderr: []string{warning, "bogus_key"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runHeadscale(t, env, tt.args...)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, stdout)
			} else {
				require.NoError(t, err, stderr)

				var doc map[string]any
				require.NoError(t, yaml.Unmarshal([]byte(stdout), &doc), stdout)
				assert.NotContains(t, stdout, "HEADSCALE_BOGUS")
			}

			if tt.wantStderr == nil {
				assert.Empty(t, stderr)
			}

			for _, s := range tt.wantStderr {
				assert.Contains(t, stderr, s)
			}

			for _, s := range tt.wantStdout {
				assert.Contains(t, stdout, s)
			}

			for _, s := range tt.hideStdout {
				assert.NotContains(t, stdout, s)
			}

			if tt.wantExact != "" {
				assert.Equal(t, tt.wantExact, stdout)
			}

			if tt.wantLoaded {
				path := writeFile(t, t.TempDir(), "config.yaml", stdout)

				l, err := config.Load(path, true, nil)
				require.NoError(t, err)

				want := config.Default()
				if diff := cmp.Diff(&want, l.Config,
					cmpopts.EquateEmpty(),
					cmpopts.EquateComparable(netip.Prefix{}),
					cmpopts.IgnoreFields(types.Config{}, "ConfigDir"),
					cmpopts.IgnoreUnexported(types.Config{}),
				); diff != "" {
					t.Errorf("stdout loads as (-default +loaded):\n%s", diff)
				}
			}
		})
	}
}

// TestGenerateNixOSOptionsCommand: generate nixos-options prints the
// options and only them, whatever config is around.
func TestGenerateNixOSOptionsCommand(t *testing.T) {
	broken := writeFile(t, t.TempDir(), "broken.yaml", "bogus_key: 1\n")

	want, err := config.GenerateNixOptions(nil)
	require.NoError(t, err)

	tests := []struct {
		name       string
		args       []string
		wantStdout string
		wantStderr string // "" when stderr must be empty
	}{
		{name: "development", args: []string{"generate", "nixos-options"}, wantStdout: string(want)},
		// A test binary has no VCS stamp: commit unknown.
		{name: "release from a dev build", args: []string{"generate", "nixos-options", "--release"}, wantStderr: "commit unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runHeadscale(t, []string{"HEADSCALE_BOGUS=1"}, append([]string{"-c", broken}, tt.args...)...)
			if tt.wantStderr == "" {
				require.NoError(t, err, stderr)
				assert.Empty(t, stderr)
			} else {
				require.Error(t, err)
				assert.Contains(t, stderr, tt.wantStderr)
			}

			assert.Equal(t, tt.wantStdout, stdout)
		})
	}
}

func TestReleaseStamp(t *testing.T) {
	tests := []struct {
		name    string
		info    types.VersionInfo
		wantErr bool
	}{
		{name: "release", info: types.VersionInfo{Version: "v1.2.3", Commit: "abc"}},
		{name: "dirty", info: types.VersionInfo{Version: "v1.2.3", Commit: "abc", Dirty: true}, wantErr: true},
		{name: "unknown commit", info: types.VersionInfo{Version: "dev", Commit: "unknown"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := releaseStamp(&tt.info)
			if tt.wantErr {
				require.ErrorIs(t, err, errNotRelease)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, &tt.info, got)
		})
	}
}
