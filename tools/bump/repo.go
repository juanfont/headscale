package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// repo is a checkout the bump operates on. Every helper runs from the
// repository root so relative paths in the Makefile recipes and the
// //go:generate directives resolve the way they do for a developer.
type repo struct {
	Root string
	// System is the Nix system double (e.g. x86_64-linux) used to address
	// flake checks.
	System string
}

// tailLines is how much of a failing command's output is carried into the
// report. Enough to see a compiler error, short enough to paste into a pull
// request body.
const tailLines = 40

// cmdError carries the tail of a failed command's output so the reason an
// area was dropped survives all the way into the pull request body.
type cmdError struct {
	Argv []string
	Tail string
	Err  error
}

func (e *cmdError) Error() string {
	return fmt.Sprintf("%s: %v\n%s", strings.Join(e.Argv, " "), e.Err, e.Tail)
}

func (e *cmdError) Unwrap() error { return e.Err }

func openRepo(ctx context.Context) (*repo, error) {
	out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return nil, fmt.Errorf("locating repository root: %w", err)
	}

	r := &repo{Root: strings.TrimSpace(string(out))}

	sys, err := r.run(ctx, "nix", "eval", "--impure", "--raw", "--expr", "builtins.currentSystem")
	if err != nil {
		return nil, err
	}

	r.System = strings.TrimSpace(sys)

	return r, nil
}

// run executes argv in the repository root and returns its combined output.
func (r *repo) run(ctx context.Context, argv ...string) (string, error) {
	return r.runIn(ctx, r.Root, argv...)
}

// runIn executes argv in dir, which may be relative to the repository root.
func (r *repo) runIn(ctx context.Context, dir string, argv ...string) (string, error) {
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(r.Root, dir)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // argv is built from repo state, not user input
	cmd.Dir = dir

	// Streams stay separate: nix writes progress and a dirty-tree warning to
	// stderr, and folding that into stdout corrupts every value parsed out of
	// a command run through the devShell.
	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	cmd.Env = append(os.Environ(), "GOWORK=off", "NIX_CONFIG=warn-dirty = false")

	err := cmd.Run()
	if err != nil {
		return stdout.String(), &cmdError{
			Argv: argv,
			Tail: tail(stderr.String() + stdout.String()),
			Err:  err,
		}
	}

	return stdout.String(), nil
}

// nixRun executes argv inside `nix develop`. It re-enters the shell on every
// call on purpose: a single long-lived shell would pin every later command to
// the toolchain that was locked before the flake area ran.
func (r *repo) nixRun(ctx context.Context, argv ...string) (string, error) {
	return r.nixRunIn(ctx, r.Root, argv...)
}

func (r *repo) nixRunIn(ctx context.Context, dir string, argv ...string) (string, error) {
	full := append([]string{"nix", "develop", "--fallback", "--command"}, argv...)

	return r.runIn(ctx, dir, full...)
}

// path joins a repository-relative path onto the root.
func (r *repo) path(rel ...string) string {
	return filepath.Join(append([]string{r.Root}, rel...)...)
}

// readFile reads a repository-relative file.
func (r *repo) readFile(rel string) (string, error) {
	b, err := os.ReadFile(r.path(rel))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", rel, err)
	}

	return string(b), nil
}

// writeFile writes a repository-relative file, preserving its current mode.
func (r *repo) writeFile(rel, content string) error {
	name := r.path(rel)

	mode := os.FileMode(0o644)
	if fi, err := os.Stat(name); err == nil { //nolint:noinlineerr
		mode = fi.Mode().Perm()
	}

	err := os.WriteFile(name, []byte(content), mode)
	if err != nil {
		return fmt.Errorf("writing %s: %w", rel, err)
	}

	return nil
}

// tail returns the last tailLines lines of s.
func tail(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > tailLines {
		lines = lines[len(lines)-tailLines:]
	}

	return strings.Join(lines, "\n")
}
