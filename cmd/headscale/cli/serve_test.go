package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/cli/command"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// serveFiles writes config.yaml in the working directory.
func serveFiles(tb testing.TB, f *fixture) {
	tb.Helper()
	writeServeConfig(tb, f, "config.yaml")
}

// writeServeConfig writes the config of a server that a test can run
// beside others to path: on loopback with a port of its own and no metrics
// listener, a DERP map from a file, and its socket in a directory short
// enough for a socket path. {socket} is the socket.
func writeServeConfig(tb testing.TB, f *fixture, path string) {
	tb.Helper()

	dir := tb.TempDir()

	// t.TempDir is under the test's name, too long for a socket path.
	short, err := os.MkdirTemp("", "hs") //nolint:usetesting // see above
	require.NoError(tb, err)
	tb.Cleanup(func() { _ = os.RemoveAll(short) })

	derp := filepath.Join(dir, "derp.yaml")
	require.NoError(tb, os.WriteFile(derp, []byte(derpMap), 0o600))

	f.vars["socket"] = filepath.Join(short, "s")
	f.vars["data"] = dir

	config := f.expand(`server_url: http://127.0.0.1:8080
listen_addr: 127.0.0.1:0
metrics_listen_addr: ""
unix_socket: {socket}
noise:
  private_key_path: {data}/noise.key
database:
  type: sqlite
  sqlite:
    path: {data}/db.sqlite
derp:
  urls: []
  paths: [{data}/derp.yaml]
disable_check_updates: true
log:
  level: error
`)

	//nolint:gosec // a path of the test
	require.NoError(tb, os.WriteFile(path, []byte(config), 0o600))
}

// answersOnSocket waits until the server at {socket} answers debug health,
// and keeps the answer as {answered}.
func answersOnSocket(ctx context.Context, f *fixture) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	env := append(
		slices.Clone(f.env),
		"HEADSCALE_UNIX_SOCKET="+f.vars["socket"],
		"HEADSCALE_CLI_TIMEOUT=1s",
	)

	for {
		var out, errOut bytes.Buffer
		//nolint:contextcheck // Env.Context carries it
		if command.Run(
			Tree(),
			[]string{"debug", "health"},
			command.Env{Context: ctx, Stdout: &out, Stderr: &errOut, Environ: env},
		) == 0 {
			f.vars["answered"] = out.String()

			return
		}

		f.vars["answered"] = errOut.String()

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func servedOnSocket(tb testing.TB, f *fixture, _ result) {
	tb.Helper()
	require.Equal(tb, "healthy\n", f.vars["answered"], "serve answered on its socket")
}

var serveCases = []cliCase{
	// The fixture's environment names the socket of its own server.
	{
		name: "serves until it is stopped",
		args: "serve",
		env: []string{
			"HEADSCALE_CONFIG={dir}/config.yaml",
			"HEADSCALE_UNIX_SOCKET={socket}",
		},
		until: answersOnSocket,
		check: servedOnSocket,
	},
	{
		name:  "a config file",
		args:  "serve -c config.yaml",
		env:   []string{"HEADSCALE_UNIX_SOCKET={socket}"},
		until: answersOnSocket,
		check: servedOnSocket,
	},
	{
		name:   "a value that is wrong is 78",
		args:   "serve -c wrong.yaml",
		code:   78,
		stderr: "Error: initializing: creating new headscale: Fatal config error: server_url is missing a scheme\n  current: server_url: \"ftp://headscale.example.com\"\n  hint: prefix the URL with https:// (recommended) or http://\n\n",
	},
	{
		name:   "an unknown key is 78",
		args:   "serve -c bad.yaml",
		code:   78,
		stderr: "Error: loading config file bad.yaml: Fatal config error: unknown configuration key bogus_key (bad.yaml:2:1)\n\n",
	},
	{
		name:   "a syntax error is 78",
		args:   "serve -c syntax.yaml",
		code:   78,
		stderr: "Error: loading config file syntax.yaml: Fatal config error: cannot parse config file syntax.yaml\n  why: yaml: line 2: did not find expected node content\n\n",
	},
	{
		name:   "a config file that does not exist is 1",
		args:   "serve -c nope.yaml",
		code:   1,
		stderr: "Error: the config file nope.yaml does not exist.\n",
	},
	{
		name: "a key that cannot be written is 1",
		args: "serve -c unwritable.yaml",
		code: 1,
		setup: func(tb testing.TB, f *fixture) {
			tb.Helper()
			require.NoError(
				tb,
				os.WriteFile(
					"unwritable.yaml",
					[]byte(
						validConfig+"disable_check_updates: true\nnoise:\n  private_key_path: config.yaml/noise.key\n",
					),
					0o600,
				),
			)
		},
		stderr: "Error: initializing: creating new headscale: reading or creating Noise protocol private key: reading private key file: open {dir}/config.yaml/noise.key: not a directory\n",
		env:    []string{"HEADSCALE_UNIX_SOCKET={socket}"},
	},
	{
		name:   "no --output",
		args:   "serve -o json",
		code:   1,
		stderr: "Error: --output does not apply to `serve`.\nRun `headscale serve --help`.\n",
	},
	{
		name:   "no arguments",
		args:   "serve now",
		code:   1,
		stderr: "Error: `serve` takes no arguments, got 1.\n\n  headscale serve\n",
	},
}

// TestServe runs serve in a directory that holds its config.yaml, as the
// example does.
func TestServe(t *testing.T) { //nolint:paralleltest // it changes the working directory
	keepLog(t)
	runCasesIn(t, map[string]string{
		"bad.yaml":    validConfig + "bogus_key: 1\n",
		"wrong.yaml":  "server_url: ftp://headscale.example.com\n",
		"syntax.yaml": validConfig + "derp: [\n",
	}, serveFiles, serveCases)
}

// TestServeFindsItsConfig: without --config, serve searches; what it finds
// decides its exit code as a named file does.
//
//nolint:paralleltest // it changes the working directory
func TestServeFindsItsConfig(t *testing.T) {
	// The search always looks in /etc/headscale; a host config there
	// would be found, or serve would start on it.
	if found, _ := filepath.Glob("/etc/headscale/config.*"); len(found) > 0 {
		t.Skipf("the search would find %v", found)
	}

	keepLog(t)

	none := []string{"HEADSCALE_CONFIG=", "XDG_CONFIG_DIRS={dir}/xdg"}

	runCasesIn(t, nil, nil, []cliCase{
		{
			name:   "no file found is 1",
			args:   "serve",
			env:    none,
			code:   1,
			stderr: "Error: initializing: creating new headscale: Fatal config error: server_url is required\n  hint: set server_url to the URL clients connect to, e.g. https://headscale.example.com\n\n",
		},
		{
			// The help names the order of the names in a directory.
			name: "config.json comes before config.yaml",
			args: "serve",
			env:  none,
			code: 78,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				require.NoError(
					tb,
					os.WriteFile(
						"config.json",
						[]byte(`{"server_url": "ftp://headscale.example.com"}`),
						0o600,
					),
				)
				require.NoError(
					tb,
					os.WriteFile(
						"config.yaml",
						[]byte(validConfig+"bogus_key: 1\n"),
						0o600,
					),
				)
				tb.Cleanup(
					func() { _ = os.Remove("config.json"); _ = os.Remove("config.yaml") },
				)
			},
			stderr: "Error: initializing: creating new headscale: Fatal config error: server_url is missing a scheme\n  current: server_url: \"ftp://headscale.example.com\"\n  hint: prefix the URL with https:// (recommended) or http://\n\n",
		},
		{
			// The working directory is searched last.
			name: "an old format found is 78",
			args: "serve",
			env:  none,
			code: 78,
			setup: func(tb testing.TB, f *fixture) {
				tb.Helper()
				require.NoError(
					tb,
					os.WriteFile(
						"config.toml",
						[]byte("server_url = \"https://headscale.example.com\"\n"),
						0o600,
					),
				)
			},
			stderr: "Error: loading config: Fatal config error: unsupported config file format \".toml\": use .json, .yaml, .yml or .hujson (config.toml)\n\n",
		},
	})
}

// keepLog gives zerolog's global level and logger back when t ends. serve
// is the server, and sets them for the process as the server does: the one
// command that changes state outside the CLI's packages. Its tests do not
// run in parallel with tests that log, and none of them sets log.format:
// json in this process, which would point every server's log at one test.
func keepLog(t *testing.T) {
	t.Helper()

	level, logger := zerolog.GlobalLevel(), log.Logger

	t.Cleanup(func() {
		zerolog.SetGlobalLevel(level)

		log.Logger = logger
	})
}

// TestServeWarnsOnAConfigItCannotLoad runs serve as a process on a config
// it cannot load, named by --config or by HEADSCALE_CONFIG: what the
// environment warns about is logged all the same, though every command
// starts with the log off, before the error and its exit code.
func TestServeWarnsOnAConfigItCannotLoad(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	for name, body := range map[string]string{
		"bad.yaml":    validConfig + "bogus_key: 1\n",
		"syntax.yaml": validConfig + "derp: [\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}

	for _, tt := range []struct {
		name, file string
		code       int
		err        string
	}{
		{name: "an unknown key", file: "bad.yaml", code: 78, err: "Error: loading config file "},
		{name: "a syntax error", file: "syntax.yaml", code: 78, err: "Error: loading config file "},
		{name: "a file that does not exist", file: "nope.yaml", code: 1, err: "Error: the config file " + filepath.Join(dir, "nope.yaml") + " does not exist.\n"},
	} {
		for _, by := range []string{"--config", "HEADSCALE_CONFIG"} {
			t.Run(tt.name+", by "+by, func(t *testing.T) {
				t.Parallel()

				file := filepath.Join(dir, tt.file)
				args, env := []string{
					"serve",
				}, []string{
					"HOME=" + dir,
					"HEADSCALE_BOGUS=1",
				}

				if by == "--config" {
					args = append(args, "-c", file)
				} else {
					env = append(env, "HEADSCALE_CONFIG="+file)
				}

				line, err := json.Marshal(args)
				require.NoError(t, err)

				//nolint:gosec // this test binary
				cmd := exec.CommandContext(t.Context(), os.Args[0])

				cmd.Env = append(env, childLine+"="+string(line))

				var stdout, stderr bytes.Buffer

				cmd.Stdout, cmd.Stderr = &stdout, &stderr

				_ = cmd.Run()

				require.Equal(t, tt.code, cmd.ProcessState.ExitCode(), stderr.String())
				require.Contains(
					t,
					stderr.String(),
					"WRN unknown environment variable HEADSCALE_BOGUS\n",
				)
				require.Contains(t, stderr.String(), tt.err)
				require.Less(
					t,
					strings.Index(stderr.String(), "WRN"),
					strings.Index(stderr.String(), "Error: "),
					"the warning comes first",
				)
				require.Empty(t, stdout.String())
			})
		}
	}
}

// TestServeStopsOnASignal runs serve as a process: it answers on its
// socket, and exits 0 on the signal a service manager sends. A process has
// zerolog's global logger of its own, which log.format: json points at
// stdout.
func TestServeStopsOnASignal(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		sig  syscall.Signal
		env  []string
		// stdout checks what serve wrote there; nil wants nothing.
		stdout func(t *testing.T, stdout string)
	}{
		{name: "SIGTERM", sig: syscall.SIGTERM},
		{name: "SIGINT", sig: syscall.SIGINT},
		{
			name: "a JSON log on stdout", sig: syscall.SIGTERM, env: []string{"HEADSCALE_LOG_FORMAT=json", "HEADSCALE_LOG_LEVEL=info"},
			stdout: func(t *testing.T, stdout string) {
				t.Helper()

				lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
				require.Greater(t, len(lines), 1, stdout)

				for _, l := range lines {
					var rec struct{ Level, Message string }
					require.NoError(t, json.Unmarshal([]byte(l), &rec), l)
					require.NotEmpty(t, rec.Level, l)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := &fixture{vars: map[string]string{}}
			dir := t.TempDir()
			f.env = []string{
				"HOME=" + dir,
				"HEADSCALE_CONFIG=" + filepath.Join(dir, "none.yaml"),
			}
			require.NoError(
				t,
				os.WriteFile(filepath.Join(dir, "none.yaml"), nil, 0o600),
			)

			cfg := filepath.Join(t.TempDir(), "config.yaml")
			writeServeConfig(t, f, cfg)

			line, err := json.Marshal([]string{"serve", "-c", cfg})
			require.NoError(t, err)

			//nolint:gosec // this test binary
			cmd := exec.CommandContext(t.Context(), os.Args[0])

			cmd.Env = append(
				append(slices.Clone(f.env), tt.env...),
				childLine+"="+string(line),
			)

			// The failure message below reads what the child said so far
			// while it runs, so the buffers are safe to read then.
			var stdout, stderr lockedBuffer

			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			require.NoError(t, cmd.Start())

			// A failure before the wait below ends the test: the context kills
			// serve, and this reaps it.
			waited := false

			t.Cleanup(func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			answersOnSocket(ctx, f)
			require.Equal(
				t,
				"healthy\n",
				f.vars["answered"],
				"serve answered on its socket; stderr:\n%s",
				stderr.String(),
			)

			require.NoError(t, cmd.Process.Signal(tt.sig))

			waited = true

			require.NoError(t, cmd.Wait(), stderr.String())
			require.Equal(t, 0, cmd.ProcessState.ExitCode())

			if tt.stdout == nil {
				require.Empty(t, stdout.String())

				return
			}

			require.Empty(t, stderr.String())
			tt.stdout(t, stdout.String())
		})
	}
}

// lockedBuffer is a bytes.Buffer that a running child writes to while the
// test reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.b.String()
}
