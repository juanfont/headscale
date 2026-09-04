package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// Modules whose versions are not independent. Each pair moves as one unit or
// not at all; see the NOTE blocks in go.mod for why.
const (
	modTailscale = "tailscale.com"
	modGvisor    = "gvisor.dev/gvisor"
	modSqlite    = "modernc.org/sqlite"
	modLibc      = "modernc.org/libc"
	modTSClient  = "tailscale.com/client/tailscale/v2"
)

var errLockstepDrift = errors.New("lockstep pair drifted after tidy")

// atom is a set of modules that must be upgraded together. Splitting a pair
// across two atoms would let the bisect keep one half of a lockstep rule.
type atom struct {
	Name  string
	Apply func(ctx context.Context, r *repo) (string, error)
}

// modState is the pair of files a dependency update touches, held in memory so
// the bisect can rewind to an intermediate point that was never committed.
type modState struct {
	mod []byte
	sum []byte
}

func saveModState(r *repo) (modState, error) {
	mod, err := os.ReadFile(r.path("go.mod"))
	if err != nil {
		return modState{}, fmt.Errorf("reading go.mod: %w", err)
	}

	sum, err := os.ReadFile(r.path("go.sum"))
	if err != nil {
		return modState{}, fmt.Errorf("reading go.sum: %w", err)
	}

	return modState{mod: mod, sum: sum}, nil
}

func (s modState) restore(r *repo) error {
	err := os.WriteFile(r.path("go.mod"), s.mod, 0o644) //nolint:gosec // tracked source file
	if err != nil {
		return fmt.Errorf("restoring go.mod: %w", err)
	}

	err = os.WriteFile(r.path("go.sum"), s.sum, 0o644) //nolint:gosec // tracked source file
	if err != nil {
		return fmt.Errorf("restoring go.sum: %w", err)
	}

	return nil
}

// parseGoMod reads and parses the repository's go.mod.
func parseGoMod(r *repo) (*modfile.File, error) {
	b, err := os.ReadFile(r.path("go.mod"))
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	f, err := modfile.Parse("go.mod", b, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	return f, nil
}

// moduleVersion asks the go command what a module currently resolves to,
// which is the authority after MVS has had its say.
func moduleVersion(ctx context.Context, r *repo, path string) (string, error) {
	out, err := r.nixRun(ctx, "go", "list", "-m", "-f", "{{.Version}}", path)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}

// tailscaleAtom moves tailscale.com to the tip of main and drags gvisor to
// whatever that exact commit requires.
//
// `go get -u tailscale.com` is wrong here: the pin is a pseudo-version that
// sorts above the newest release tag, so -u either no-ops or downgrades.
func tailscaleAtom(ctx context.Context, r *repo) (string, error) {
	before, err := moduleVersion(ctx, r, modTailscale)
	if err != nil {
		return "", err
	}

	if _, err := r.nixRun(ctx, "go", "get", modTailscale+"@main"); err != nil { //nolint:noinlineerr
		return "", err
	}

	after, err := moduleVersion(ctx, r, modTailscale)
	if err != nil {
		return "", err
	}

	gvisor, err := partnerVersion(ctx, modTailscale, after, modGvisor)
	if err != nil {
		return "", err
	}

	if _, err := r.nixRun(ctx, "go", "get", modGvisor+"@"+gvisor); err != nil { //nolint:noinlineerr
		return "", err
	}

	// A separate module with ordinary release tags, so -u is correct.
	if _, err := r.nixRun(ctx, "go", "get", "-u", modTSClient); err != nil { //nolint:noinlineerr
		return "", err
	}

	if before == after {
		return "tailscale.com unchanged", nil
	}

	return fmt.Sprintf("tailscale.com %s -> %s (gvisor %s)", before, after, gvisor), nil
}

// sqliteAtom moves modernc.org/sqlite and pins modernc.org/libc to the version
// that release requires. See go.mod's NOTE block: a mismatched libc breaks at
// runtime on some architectures rather than at build time.
func sqliteAtom(ctx context.Context, r *repo) (string, error) {
	before, err := moduleVersion(ctx, r, modSqlite)
	if err != nil {
		return "", err
	}

	latest, err := latestVersion(ctx, modSqlite)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoLockstepSource, err)
	}

	libc, err := partnerVersion(ctx, modSqlite, latest, modLibc)
	if err != nil {
		return "", err
	}

	// One invocation: resolving them separately lets MVS see an inconsistent
	// intermediate state.
	if _, err := r.nixRun(ctx, "go", "get", modLibc+"@"+libc, modSqlite+"@"+latest); err != nil { //nolint:noinlineerr
		return "", err
	}

	if before == latest {
		return "modernc.org/sqlite unchanged", nil
	}

	return fmt.Sprintf("modernc.org/sqlite %s -> %s (libc %s)", before, latest, libc), nil
}

// restAtom upgrades every direct requirement that is not owned by a lockstep
// atom.
func restAtom(ctx context.Context, r *repo) (string, error) {
	f, err := parseGoMod(r)
	if err != nil {
		return "", err
	}

	owned := map[string]bool{
		modTailscale: true,
		modTSClient:  true,
		modSqlite:    true,
		modGvisor:    true,
		modLibc:      true,
	}

	var paths []string

	for _, req := range f.Require {
		if req.Indirect || owned[req.Mod.Path] {
			continue
		}

		paths = append(paths, req.Mod.Path)
	}

	if len(paths) == 0 {
		return "no direct requirements", nil
	}

	if _, err := r.nixRun(ctx, append([]string{"go", "get", "-u"}, paths...)...); err != nil { //nolint:noinlineerr
		return "", err
	}

	return fmt.Sprintf("%d direct requirements", len(paths)), nil
}

func goModAtoms() []atom {
	return []atom{
		{Name: "tailscale", Apply: tailscaleAtom},
		{Name: "sqlite", Apply: sqliteAtom},
		{Name: "rest", Apply: restAtom},
	}
}

// lockstepPairs are the indirect dependencies whose version is dictated by
// another module rather than by minimal version selection.
var lockstepPairs = []struct{ owner, dep string }{
	{modTailscale, modGvisor},
	{modSqlite, modLibc},
}

// repin drags each lockstep dependency back to the version its owner requires.
// Upgrading unrelated modules routinely raises a shared indirect past its
// owner's pin, so without this the common case is a whole dependency batch
// failing the assertion below and being dropped wholesale.
func repin(ctx context.Context, r *repo) error {
	for _, p := range lockstepPairs {
		ownerVer, err := moduleVersion(ctx, r, p.owner)
		if err != nil {
			return err
		}

		want, err := partnerVersion(ctx, p.owner, ownerVer, p.dep)
		if err != nil {
			return err
		}

		have, err := moduleVersion(ctx, r, p.dep)
		if err != nil {
			return err
		}

		if have == want {
			continue
		}

		_, err = r.nixRun(ctx, "go", "get", p.dep+"@"+want)
		if err != nil {
			return err
		}
	}

	return nil
}

// checkLockstep re-reads the resolved versions and asserts the pairs still
// agree. MVS is allowed to raise an indirect above what its owner pins when a
// third module demands it; that is exactly the failure this catches.
func checkLockstep(ctx context.Context, r *repo) error {
	for _, p := range lockstepPairs {
		ownerVer, err := moduleVersion(ctx, r, p.owner)
		if err != nil {
			return err
		}

		want, err := partnerVersion(ctx, p.owner, ownerVer, p.dep)
		if err != nil {
			return err
		}

		got, err := moduleVersion(ctx, r, p.dep)
		if err != nil {
			return err
		}

		if got != want {
			return fmt.Errorf("%w: %s requires %s %s, go.mod resolved %s",
				errLockstepDrift, p.owner, p.dep, want, got)
		}
	}

	return nil
}

// lockstepNotes are the prose blocks in go.mod that explain why the pairs
// exist. `go mod tidy` re-sorts requires and can detach a comment from the line
// it documents, silently dropping the reasoning; assert attachment, not mere
// presence.
var lockstepNotes = []struct{ module, needle string }{
	{modSqlite, "issues/2188"},
	{modGvisor, "gvisor must be updated in lockstep"},
	{modLibc, "keep in lockstep with modernc.org/sqlite"},
}

var (
	errNoteDetached = errors.New("lockstep note no longer attached to its require")
	errToolBlockOne = errors.New("go.mod tool block disappeared")
)

func checkModComments(r *repo) error {
	f, err := parseGoMod(r)
	if err != nil {
		return err
	}

	for _, note := range lockstepNotes {
		if !noteAttached(f, note.module, note.needle) {
			return fmt.Errorf("%w: %s (%q)", errNoteDetached, note.module, note.needle)
		}
	}

	if len(f.Tool) == 0 {
		return errToolBlockOne
	}

	return nil
}

// noteAttached reports whether the require line for module carries a preceding
// comment containing needle.
func noteAttached(f *modfile.File, module, needle string) bool {
	for _, req := range f.Require {
		if req.Mod.Path != module || req.Syntax == nil {
			continue
		}

		var sb strings.Builder
		for _, c := range req.Syntax.Before {
			sb.WriteString(c.Token)
			sb.WriteString("\n")
		}

		if strings.Contains(sb.String(), needle) {
			return true
		}
	}

	return false
}

var errToolchainAhead = errors.New("dependencies require a newer Go than the devShell provides")

// checkToolchain catches a dependency that dragged go.mod's go directive above
// the toolchain nixpkgs ships.
//
// The go command papers over this by downloading the newer toolchain, so
// `go build` succeeds and nothing looks wrong. The nix builders set
// GOTOOLCHAIN=local and fail outright, which is why this has to be an explicit
// check rather than something the build would surface on its own.
func checkToolchain(ctx context.Context, r *repo) error {
	goMod, err := r.readFile("go.mod")
	if err != nil {
		return err
	}

	want, err := goDirective(goMod)
	if err != nil {
		return err
	}

	have, err := goVersion(ctx, r)
	if err != nil {
		return err
	}

	if semver.Compare("v"+want, "v"+have) > 0 {
		return fmt.Errorf("%w: go.mod now requires go %s, the devShell provides %s",
			errToolchainAhead, want, have)
	}

	return nil
}

// settle runs the steps every dependency change needs before it can be judged:
// tidy, restore the lockstep pins that the upgrade may have disturbed, tidy
// again, then assert go.mod's hand-written rules survived.
func settle(ctx context.Context, r *repo) error {
	_, err := r.nixRun(ctx, "go", "mod", "tidy")
	if err != nil {
		return err
	}

	err = repin(ctx, r)
	if err != nil {
		return err
	}

	_, err = r.nixRun(ctx, "go", "mod", "tidy")
	if err != nil {
		return err
	}

	err = checkLockstep(ctx, r)
	if err != nil {
		return err
	}

	err = checkToolchain(ctx, r)
	if err != nil {
		return err
	}

	return checkModComments(r)
}

// atomGate is the signal that one dependency set is viable. It runs once per
// bisect step, so it stays well short of the full nix checks the final gate
// runs over the finished tree.
func atomGate(ctx context.Context, r *repo) error {
	if _, err := r.nixRun(ctx, "go", "build", "./..."); err != nil { //nolint:noinlineerr
		return err
	}

	if _, err := r.nixRun(ctx, "go", "vet", "./..."); err != nil { //nolint:noinlineerr
		return err
	}

	// Lint belongs here, not only in the final gate. A dependency that
	// deprecates an API the tree still uses compiles and vets cleanly and fails
	// staticcheck, so without this the whole area is dropped for one module's
	// sake instead of the bisect narrowing to that module.
	_, err := r.nixRun(ctx, "golangci-lint", "run", "--timeout", "10m")

	return err
}

// applyGoMod upgrades dependencies, then refreshes the vendor hash that
// flake.nix reads. Skipping that refresh is the classic way to hand over a
// pull request that cannot nix build.
func applyGoMod(ctx context.Context, r *repo) (change, error) {
	kept, drops, err := applyAtoms(ctx, r, goModAtoms())
	if err != nil {
		return change{}, err
	}

	touched, err := changedFiles(ctx, r)
	if err != nil {
		return change{}, err
	}

	if len(touched) == 0 {
		return change{Empty: true, Drops: drops}, nil
	}

	if _, err := r.nixRun(ctx, "go", "run", "./cmd/vendorhash", "update"); err != nil { //nolint:noinlineerr
		return change{}, err
	}

	return change{
		Summary: "update dependencies",
		Detail:  kept,
		Drops:   drops,
	}, nil
}

var errTidyNotIdempotent = errors.New("go mod tidy is not idempotent")

// gateGoMod re-runs the settling steps and asserts they are a no-op. A tidy
// that still has work to do means the committed go.mod is not what the go
// command would produce, and check-generated would say so later and louder.
func gateGoMod(ctx context.Context, r *repo) error {
	before, err := saveModState(r)
	if err != nil {
		return err
	}

	if err := settle(ctx, r); err != nil { //nolint:noinlineerr
		return err
	}

	after, err := saveModState(r)
	if err != nil {
		return err
	}

	if !bytes.Equal(before.mod, after.mod) || !bytes.Equal(before.sum, after.sum) {
		return errTidyNotIdempotent
	}

	_, err = r.nixRun(ctx, "go", "run", "./cmd/vendorhash", "check")

	return err
}
