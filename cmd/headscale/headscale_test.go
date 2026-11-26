package main

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/juanfont/headscale/cmd/headscale/newcli"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
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

// oldArgs, when set, makes the test binary run the old CLI on its lines.
const oldArgs = "OLD_CLI_TEST_ARGS"

// TestOldCLIProcess is the child of runOld: the old CLI reads os.Args and
// exits the process.
func TestOldCLIProcess(t *testing.T) {
	args, ok := os.LookupEnv(oldArgs)
	if !ok {
		t.Skip("run by runOld")
	}

	os.Args = append([]string{"headscale"}, strings.Split(args, "\n")...)

	consoleLog(zerolog.DebugLevel) // as main
	cli.Execute()
	os.Exit(0)
}

// newArgs, when set, makes the test binary run the new CLI on its lines.
const newArgs = "NEW_CLI_TEST_ARGS"

// TestNewCLIProcess is the child of startServe for the new CLI.
func TestNewCLIProcess(t *testing.T) {
	args, ok := os.LookupEnv(newArgs)
	if !ok {
		t.Skip("run by startServe")
	}

	consoleLog(zerolog.InfoLevel) // as main
	os.Exit(command.Run(newcli.Tree(), strings.Split(args, "\n"), command.OSEnv()))
}

// serveUntilSignal runs serve of one CLI as a process, the old one when
// child is oldArgs, until it serves on socket, and stops it with SIGTERM.
// It returns the first line of stdout and of stderr, each without the time
// that a console log line starts with, and the exit code.
func serveUntilSignal(t *testing.T, child, socket string, env []string, args ...string) (string, string, int) {
	t.Helper()

	test := map[string]string{oldArgs: "^TestOldCLIProcess$", newArgs: "^TestNewCLIProcess$"}[child]
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run="+test) //nolint:gosec // this test binary

	cmd.Env = append(slices.Clone(env), child+"="+strings.Join(args, "\n"))

	// A failed wait prints stderr while serve still runs.
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

	require.Eventually(t, func() bool {
		_, err := os.Stat(socket)
		return err == nil
	}, time.Minute, 20*time.Millisecond, "serve made no socket; stderr:\n%s", &stderr)

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))

	waited = true

	code := 0
	if exit, ok := errors.AsType[*exec.ExitError](cmd.Wait()); ok {
		code = exit.ExitCode()
	}

	first := func(s string) string {
		line, _, _ := strings.Cut(s, "\n")
		if at, rest, ok := strings.Cut(line, " "); ok && strings.Contains(at, ":") {
			return rest
		}

		return line
	}

	return first(stdout.String()), first(stderr.String()), code
}

// TestOldAndNewServeUntilASignal: serve of both CLIs starts, logs the same
// first line on each stream, and exits 0 on SIGTERM.
func TestOldAndNewServeUntilASignal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// t.TempDir is under the test's name, too long for a socket path.
	short, err := os.MkdirTemp("", "hs") //nolint:usetesting // see above
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(short) })

	socket := filepath.Join(short, "s")
	derp := filepath.Join(dir, "derp.yaml")
	cfg := filepath.Join(dir, "config.yaml")

	require.NoError(t, os.WriteFile(derp, []byte("regions:\n  900:\n    regionid: 900\n    regioncode: test\n    nodes:\n      - name: 900a\n        regionid: 900\n        hostname: derp.example.com\n"), 0o600))
	require.NoError(t, os.WriteFile(cfg, []byte(`server_url: http://127.0.0.1:8080
listen_addr: 127.0.0.1:0
metrics_listen_addr: ""
unix_socket: `+socket+`
noise:
  private_key_path: `+dir+`/noise.key
database:
  type: sqlite
  sqlite:
    path: `+dir+`/db.sqlite
derp:
  urls: []
  paths: [`+derp+`]
disable_check_updates: true
`), 0o600))

	env := []string{"HOME=" + dir}

	oldOut, oldErr, oldCode := serveUntilSignal(t, oldArgs, socket, env, "serve", "-c", cfg)

	// The second starts as the first did: with no key and no database.
	for _, f := range []string{"noise.key", "db.sqlite", "db.sqlite-shm", "db.sqlite-wal"} {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, f)))
	}

	newOut, newErr, newCode := serveUntilSignal(t, newArgs, socket, env, "serve", "-c", cfg)

	require.Equal(t, 0, oldCode, oldErr)
	require.Equal(t, oldCode, newCode, "exit code")
	require.Equal(t, oldOut, newOut, "first line of stdout")
	require.NotEmpty(t, oldErr, "serve logs at info")
	require.Equal(t, oldErr, newErr, "first line of stderr")
}

// runOld runs the old CLI, as main does, in a child process.
func runOld(t *testing.T, dir string, env []string, args ...string) (string, string, int) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestOldCLIProcess$") //nolint:gosec // this test binary

	cmd.Env = append(slices.Clone(env), oldArgs+"="+strings.Join(args, "\n"))
	cmd.Dir = dir

	var stdout, stderr bytes.Buffer

	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	code := 0

	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		code = exit.ExitCode()
	} else {
		require.NoError(t, err)
	}

	return stdout.String(), stderr.String(), code
}

// runNew runs the new CLI in dir, as the old one runs there.
func runNew(t *testing.T, dir string, env []string, args ...string) (string, string, int) {
	t.Helper()

	var stdout, stderr bytes.Buffer

	t.Chdir(dir)

	code := command.Run(newcli.Tree(), args, command.Env{Stdout: &stdout, Stderr: &stderr, Environ: env})

	return stdout.String(), stderr.String(), code
}

// TestOldAndNewCLIAgree: where the new commands print what the old ones
// printed, both CLIs print the same lines on the same streams and exit
// with the same code. What differs on purpose is in the tests of package
// newcli.
func TestOldAndNewCLIAgree(t *testing.T) { //nolint:paralleltest // runNew changes the working directory
	dir := t.TempDir()
	for name, body := range map[string]string{
		"ok.yaml":       "server_url: https://headscale.example.com\nnoise:\n  private_key_path: noise.key\n",
		"bad.yaml":      "server_url: https://headscale.example.com\nbogus_key: 1\n",
		"wrong.yaml":    "server_url: ftp://headscale.example.com\ndisable_check_updates: true\n",
		"failing.json":  `{"acls": [], "tests": [{"src": "alice@", "accept": ["bob@:22"]}]}`,
		"all.yaml":      "server_url: https://headscale.example.com\npolicy:\n  path: failing.json\nderp:\n  paths: [empty.yaml]\nnoise:\n  private_key_path: noise.key\n",
		"empty.yaml":    "{}",
		"records.json":  "{",
		"derp-bad.yaml": "regions: 1\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}

	env := []string{"HOME=" + dir, "HEADSCALE_CONFIG=" + filepath.Join(dir, "ok.yaml"), "HEADSCALE_DISABLE_CHECK_UPDATES=true", "HEADSCALE_BOGUS=1"}

	for _, tt := range []struct {
		old, now []string
		// warns is a case where the old CLI logs what the config warns
		// about and the new one writes "warning: ": stderr is compared
		// without those lines.
		warns bool
	}{
		{old: []string{"generate", "config"}, now: []string{"generate", "config"}},
		{old: []string{"generate", "config", "--minimal"}, now: []string{"generate", "config", "--minimal"}},
		{old: []string{"generate", "config", "--no-docs"}, now: []string{"generate", "config", "--no-docs"}},
		{old: []string{"generate", "config", "--minimal", "--no-docs"}, now: []string{"generate", "config", "--minimal", "--no-docs"}},
		{old: []string{"generate", "nixos-options"}, now: []string{"generate", "nixos-options"}},
		{old: []string{"generate", "nixos-options", "--release"}, now: []string{"generate", "nixos-options", "--release"}},
		{old: []string{"check", "config", "-f", "bad.yaml"}, now: []string{"check", "config", "bad.yaml"}, warns: true},
		{old: []string{"check", "config", "-f", "wrong.yaml"}, now: []string{"check", "config", "wrong.yaml"}, warns: true},
		{old: []string{"check", "all", "-f", "all.yaml"}, now: []string{"check", "all", "all.yaml"}, warns: true},
		{old: []string{"check", "all", "-f", "bad.yaml"}, now: []string{"check", "all", "bad.yaml"}, warns: true},
		{old: []string{"check", "all", "-f", "ok.yaml"}, now: []string{"check", "all", "ok.yaml"}, warns: true},
		{old: []string{"check", "derp-map", "-f", "derp-bad.yaml"}, now: []string{"check", "derp-map", "derp-bad.yaml"}},
		{old: []string{"check", "extra-records", "-f", "records.json"}, now: []string{"check", "extra-records", "records.json"}},
		{old: []string{"serve", "-c", "wrong.yaml"}, now: []string{"serve", "-c", "wrong.yaml"}, warns: true},
		{old: []string{"serve", "-c", "bad.yaml"}, now: []string{"serve", "-c", "bad.yaml"}, warns: true},
		// The child's os.Args at init are the test binary's, so the old
		// mockoidc reads the config here, as it does not in a release.
		{old: []string{"mockoidc"}, now: []string{"debug", "mockoidc"}, warns: true},
	} {
		t.Run(strings.Join(tt.now, " "), func(t *testing.T) {
			oldOut, oldErr, oldCode := runOld(t, dir, env, tt.old...)
			newOut, newErr, newCode := runNew(t, dir, env, tt.now...)

			if tt.warns {
				oldErr, newErr = withoutWarnings(oldErr), withoutWarnings(newErr)
			}

			require.Equal(t, oldCode, newCode, "exit code; stderr old:\n%s\nnew:\n%s", oldErr, newErr)
			require.Equal(t, oldOut, newOut, "stdout")
			require.Equal(t, oldErr, newErr, "stderr")
		})
	}
}

// withoutWarnings drops the line of the warning the environment gives, as
// the old CLI logs it and as the new one writes it.
func withoutWarnings(stderr string) string {
	var kept []string

	for l := range strings.Lines(stderr) {
		if !strings.Contains(l, "unknown environment variable HEADSCALE_BOGUS") {
			kept = append(kept, l)
		}
	}

	return strings.Join(kept, "")
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
