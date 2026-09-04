package main

import (
	"context"
	"errors"
	"fmt"
	"log"
)

// Gate levels, from cheapest to most thorough.
const (
	gateNone  = "none"
	gateQuick = "quick"
	gateFull  = "full"
)

var errUnknownGate = errors.New("unknown gate level (want none|quick|full)")

// flakeChecks are the same derivations nix-checks.yml evaluates on a pull
// request. Running them here is close to free: this job runs on the default
// branch, so its binary-cache writes are readable by every later pull request
// job, which then gets a cache hit instead of a rebuild.
var flakeChecks = []string{"build", "gotest", "golangci-lint", "formatting"}

// dockerGates stand in for the integration matrix. They are the two images
// whose builder pin actually breaks, plus the wasm client, which is cheap and
// exercises the go.mod pairing.
var dockerGates = []struct {
	File   string
	Target string
}{
	{File: "Dockerfile.tailscale-HEAD", Target: "build-env"},
	{File: "Dockerfile.derper"},
	{File: "Dockerfile.wasmclient"},
}

// finalGate judges the accumulated tree. The ~170-job arm integration matrix is
// deliberately left to the pull request's own CI rather than duplicated here.
func finalGate(ctx context.Context, r *repo, level string) error {
	switch level {
	case gateNone:
		return nil
	case gateQuick:
		return nixCheck(ctx, r, "build")
	case gateFull:
	default:
		return fmt.Errorf("%w: %s", errUnknownGate, level)
	}

	for _, check := range flakeChecks {
		err := nixCheck(ctx, r, check)
		if err != nil {
			return err
		}
	}

	for _, d := range dockerGates {
		argv := []string{"docker", "build", "--file", d.File}
		if d.Target != "" {
			argv = append(argv, "--target", d.Target)
		}

		log.Printf("gate: %s", d.File)

		if _, err := r.run(ctx, append(argv, ".")...); err != nil { //nolint:noinlineerr
			return err
		}
	}

	return nil
}

func nixCheck(ctx context.Context, r *repo, name string) error {
	log.Printf("gate: nix check %s", name)

	_, err := r.run(ctx, "nix", "build", "--fallback", "-L",
		fmt.Sprintf(".#checks.%s.%s", r.System, name))

	return err
}

// enforceFinalGate drops committed areas newest-first until the tree passes.
// Popping from the tip is safe because every area is exactly one commit, and it
// is the cheapest correct answer: the gate cannot say which area broke, only
// that the combination did.
func enforceFinalGate(ctx context.Context, r *repo, results []result, level string) ([]result, error) {
	for {
		err := finalGate(ctx, r, level)
		if err == nil {
			return results, nil
		}

		newest := -1

		for i, res := range results {
			if res.Commit != "" {
				newest = i
			}
		}

		if newest < 0 {
			return results, fmt.Errorf("gate fails on an unmodified tree: %w", err)
		}

		log.Printf("gate failed, dropping area %s", results[newest].Area)

		if _, err := r.run(ctx, "git", "reset", "--hard", "HEAD~1"); err != nil { //nolint:noinlineerr
			return results, err
		}

		results[newest].State = stateDropped
		results[newest].Reason = reasonOf(err)
		results[newest].Log = logOf(err)
		results[newest].Commit = ""
	}
}
