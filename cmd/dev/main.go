// cmd/dev starts a local headscale development server with a pre-created
// user and pre-auth key, ready for connecting tailscale nodes via mts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	port = flag.Int("port", 8080, "headscale listen port")
	keep = flag.Bool("keep", false, "keep state directory on exit")
)

var errHealthTimeout = errors.New("health check timed out")

var errEmptyAuthKey = errors.New("auth keys create printed no key")

// maxDevPort is the highest --port value that keeps the derived metrics
// port (port+1010) inside the valid 1..65535 TCP range.
const maxDevPort = 64525

const devConfig = `---
server_url: http://127.0.0.1:%d
listen_addr: 127.0.0.1:%d
metrics_listen_addr: 127.0.0.1:%d

noise:
  private_key_path: %s/noise_private.key

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential

database:
  type: sqlite
  sqlite:
    path: %s/db.sqlite
    write_ahead_log: true

derp:
  server:
    enabled: false
  urls:
    - https://controlplane.tailscale.com/derpmap/default
  auto_update_enabled: false

dns:
  magic_dns: true
  base_domain: headscale.dev
  override_local_dns: false

log:
  level: debug
  format: text

policy:
  mode: database

unix_socket: %s/headscale.sock
unix_socket_permission: "0770"
`

func main() {
	flag.Parse()
	log.SetFlags(0)

	if *port < 1 || *port > maxDevPort {
		log.Fatalf(
			"--port must be in 1..%d (higher values overflow the derived metrics port); got %d",
			maxDevPort, *port,
		)
	}

	http.DefaultClient.Timeout = 2 * time.Second
	http.DefaultClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

func run() error {
	metricsPort := *port + 1010 // default 9090

	tmpDir, err := os.MkdirTemp("", "headscale-dev-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}

	if !*keep {
		defer os.RemoveAll(tmpDir)
	}

	// Write config.
	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := fmt.Sprintf(
		devConfig,
		*port, *port, metricsPort,
		tmpDir, tmpDir, tmpDir,
	)

	err = os.WriteFile(configPath, []byte(configContent), 0o600)
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	// Build headscale.
	fmt.Println("Building headscale...")

	hsBin := filepath.Join(tmpDir, "headscale")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	build := exec.CommandContext(ctx, "go", "build", "-o", hsBin, "./cmd/headscale")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr

	err = build.Run()
	if err != nil {
		return fmt.Errorf("building headscale: %w", err)
	}

	// Start headscale serve.
	fmt.Println("Starting headscale server...")

	serve := exec.CommandContext(ctx, hsBin, "serve", "-c", configPath)
	serve.Stdout = os.Stdout
	serve.Stderr = os.Stderr

	err = serve.Start()
	if err != nil {
		return fmt.Errorf("starting headscale: %w", err)
	}

	// Wait for server to be ready.
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/health", *port)

	err = waitForHealth(ctx, healthURL, 30*time.Second)
	if err != nil {
		return fmt.Errorf("waiting for headscale: %w", err)
	}

	// Create user.
	fmt.Println("Creating user and pre-auth key...")

	_, err = runHS(ctx, hsBin, configPath, "users", "create", "dev")
	if err != nil {
		return fmt.Errorf("creating user: %w", err)
	}

	// stdout carries the key alone.
	keyOut, err := runHS(ctx, hsBin, configPath, "auth", "keys", "create", "dev", "--reusable", "-e", "24h")
	if err != nil {
		return fmt.Errorf("creating pre-auth key: %w", err)
	}

	authKey := strings.TrimSpace(string(keyOut))
	if authKey == "" {
		return errEmptyAuthKey
	}

	// The key stays out of the terminal: tailscale up reads it from a file
	// (--auth-key=file:), which goes with the state directory.
	keyPath := filepath.Join(tmpDir, "authkey")

	err = os.WriteFile(keyPath, []byte(authKey+"\n"), 0o600)
	if err != nil {
		return fmt.Errorf("writing auth key: %w", err)
	}

	// Print banner.
	fmt.Printf(
		`
=== Headscale Dev Environment ===
  Server:  http://127.0.0.1:%d
  Metrics: http://127.0.0.1:%d
  Debug:   http://127.0.0.1:%d/debug/ping
  Config:  %s
  State:   %s

Pre-auth key: %s (reusable, 24h)

Connect nodes with mts:
  go tool mts server run                  # start mts (once, another terminal)
  go tool mts server add node1            # create a node
  go tool mts node1 up --login-server=http://127.0.0.1:%d %s
  go tool mts node1 status                # check connection

Manage headscale:
  %s -c %s nodes list
  %s -c %s users list

Press Ctrl+C to stop.
`,
		*port, metricsPort, metricsPort,
		configPath, tmpDir,
		keyPath,
		*port, shellQuote("--auth-key=file:"+keyPath),
		shellQuote(hsBin), shellQuote(configPath),
		shellQuote(hsBin), shellQuote(configPath),
	)

	// Wait for headscale to exit.
	err = serve.Wait()
	if err != nil {
		// Context cancellation is expected on Ctrl+C.
		if ctx.Err() != nil {
			fmt.Println("\nShutting down...")

			return nil
		}

		return fmt.Errorf("headscale exited: %w", err)
	}

	return nil
}

// waitForHealth polls the health endpoint until it returns 200 or the
// timeout expires.
func waitForHealth(ctx context.Context, url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("creating request: %w", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}

		// Busy-wait is acceptable for a dev tool polling a local server.
		time.Sleep(200 * time.Millisecond) //nolint:forbidigo
	}

	return errHealthTimeout
}

// runHS executes a headscale CLI command and returns its stdout.
func runHS(ctx context.Context, bin, config string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"-c", config}, args...)
	cmd := exec.CommandContext(ctx, bin, fullArgs...)
	cmd.Stderr = os.Stderr

	return cmd.Output()
}

// shellQuote is s as one word of a POSIX shell, for a command the banner
// prints to copy: as it is when it holds only characters no shell treats
// specially, else in single quotes, each single quote written as '\”.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=@%+,-") == "" {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
