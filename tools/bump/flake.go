package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// lockNode is the slice of a flake.lock entry that identifies what an input is
// pinned to.
type lockNode struct {
	Locked struct {
		Rev          string `json:"rev"`
		LastModified int64  `json:"lastModified"`
	} `json:"locked"`
}

type flakeLock struct {
	Nodes map[string]lockNode `json:"nodes"`
}

func readLock(r *repo) (flakeLock, error) {
	var lock flakeLock

	b, err := r.readFile("flake.lock")
	if err != nil {
		return lock, err
	}

	if err := json.Unmarshal([]byte(b), &lock); err != nil { //nolint:noinlineerr
		return lock, fmt.Errorf("parsing flake.lock: %w", err)
	}

	return lock, nil
}

// lockDiff reports the inputs whose revision moved: one detailed line each,
// plus the bare names for the commit subject.
func lockDiff(before, after flakeLock) ([]string, []string) {
	var detail, names []string

	for name, post := range after.Nodes {
		pre, ok := before.Nodes[name]
		if !ok || post.Locked.Rev == "" || pre.Locked.Rev == post.Locked.Rev {
			continue
		}

		detail = append(detail, fmt.Sprintf("%s %s -> %s", name, short(pre.Locked.Rev), short(post.Locked.Rev)))
		names = append(names, name)
	}

	sort.Strings(detail)
	sort.Strings(names)

	return detail, names
}

func short(rev string) string {
	if len(rev) > 7 {
		return rev[:7]
	}

	return rev
}

// applyFlake refreshes every flake input. Because flake.nix asks for
// buildGoLatestModule and go_latest, this is also how Go and every devShell
// tool get a new version.
func applyFlake(ctx context.Context, r *repo) (change, error) {
	before, err := readLock(r)
	if err != nil {
		return change{}, err
	}

	if _, err := r.run(ctx, "nix", "flake", "update"); err != nil { //nolint:noinlineerr
		return change{}, err
	}

	after, err := readLock(r)
	if err != nil {
		return change{}, err
	}

	moved, names := lockDiff(before, after)
	if len(moved) == 0 {
		return change{Empty: true}, nil
	}

	detail := moved

	if tools, err := toolVersions(ctx, r); err == nil { //nolint:noinlineerr
		detail = append(detail, tools...)
	}

	return change{
		Summary: shortList(names),
		Detail:  detail,
	}, nil
}

// shortList keeps a commit subject readable when many inputs move at once.
func shortList(names []string) string {
	const maxNamed = 3

	if len(names) <= maxNamed {
		return strings.Join(names, ", ")
	}

	return fmt.Sprintf("%s and %d more", strings.Join(names[:maxNamed], ", "), len(names)-maxNamed)
}

// gateFlake proves the flake still evaluates before anything expensive runs.
func gateFlake(ctx context.Context, r *repo) error {
	_, err := r.run(ctx, "nix", "eval", "--raw",
		fmt.Sprintf(".#packages.%s.headscale.name", r.System))

	return err
}

// goVersion is the Go the devShell now provides, without the "go" prefix.
func goVersion(ctx context.Context, r *repo) (string, error) {
	out, err := r.nixRun(ctx, "go", "env", "GOVERSION")
	if err != nil {
		return "", err
	}

	return strings.TrimPrefix(strings.TrimSpace(out), "go"), nil
}

// toolVersions reports the versions that most often decide whether a lock bump
// turns the pull request red.
func toolVersions(ctx context.Context, r *repo) ([]string, error) {
	goVer, err := goVersion(ctx, r)
	if err != nil {
		return nil, err
	}

	versions := []string{"go " + goVer}

	if out, err := r.nixRun(ctx, "golangci-lint", "version"); err == nil { //nolint:noinlineerr
		versions = append(versions, strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]))
	}

	return versions, nil
}
