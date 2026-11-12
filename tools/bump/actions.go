package main

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// actionsLock records the commit every action ref runs. Workflows name a
// readable tag; GitHub runs the commit locked here and rejects one that is
// missing or no longer reachable from that tag.
const actionsLock = ".github/workflows/actions.lock"

// actionRef matches a remote action and the ref it names. Local `./` and `$/`
// actions never match: they run from this repository's own commit.
var actionRef = regexp.MustCompile(`(?m)(uses:\s+)([\w.-]+)/([\w.-]+)((?:/[\w./-]+)?)@([\w.-]+)`)

// isVersionRef reports whether a ref names a release rather than a branch. A
// branch ref is deliberate; the lockfile advances it on --relock.
func isVersionRef(ref string) bool {
	return strings.HasPrefix(ref, "v") && len(ref) > 1 && ref[1] >= '0' && ref[1] <= '9'
}

// actionFiles lists every file that can name a remote action: the workflows
// and this repository's composite actions, whose pins the lockfile also holds.
func actionFiles(r *repo) ([]string, error) {
	var files []string

	for _, pattern := range []string{".github/workflows/*.y*ml", ".github/actions/*/action.y*ml"} {
		matches, err := filepath.Glob(r.path(pattern))
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", pattern, err)
		}

		for _, m := range matches {
			rel, err := filepath.Rel(r.Root, m)
			if err != nil {
				return nil, err
			}

			files = append(files, rel)
		}
	}

	sort.Strings(files)

	return files, nil
}

// applyActions moves every release ref to the newest release, then has
// gh-actions-lock resolve the commits. The lock tool, not this one, owns SHAs:
// it also locks transitive actions and checks the repository identity.
func applyActions(ctx context.Context, r *repo) (change, error) {
	files, err := actionFiles(r)
	if err != nil {
		return change{}, err
	}

	lockBefore, err := r.readFile(actionsLock)
	if err != nil {
		return change{}, err
	}

	// One lookup per action, not per occurrence: checkout alone appears twenty
	// times, and the API budget is not unlimited.
	latest := map[string]string{}
	moved := map[string]string{}

	var touched []string

	for _, file := range files {
		content, err := r.readFile(file)
		if err != nil {
			return change{}, err
		}

		updated, err := rewriteActions(ctx, content, latest, moved)
		if err != nil {
			return change{}, err
		}

		if updated == content {
			continue
		}

		err = r.writeFile(file, updated)
		if err != nil {
			return change{}, err
		}

		touched = append(touched, file)
	}

	// --relock also advances branch refs, which no tag rewrite can see. Never
	// --accept-moved: a release tag that moved is for a human to look at.
	_, err = r.nixRun(ctx, "gh-actions-lock", "--no-interactive", "--relock")
	if err != nil {
		return change{}, err
	}

	lockAfter, err := r.readFile(actionsLock)
	if err != nil {
		return change{}, err
	}

	if len(touched) == 0 && lockAfter == lockBefore {
		return change{Empty: true}, nil
	}

	relocked, err := lockMoves(lockBefore, lockAfter)
	if err != nil {
		return change{}, err
	}

	details := make([]string, 0, len(moved)+len(relocked)+1)
	for _, line := range moved {
		details = append(details, line)
	}

	sort.Strings(details)
	details = append(details, relocked...)

	summary := fmt.Sprintf("%d action pins", len(moved)+len(relocked))
	if len(details) == 0 {
		// The lock tool rewrote the file without moving a commit, such as
		// after its own upgrade changed the format.
		summary = "the actions lockfile"
	}

	if len(touched) > 0 {
		details = append(details, "files: "+strings.Join(touched, ", "))
	}

	return change{Summary: summary, Detail: details}, nil
}

// rewriteActions moves every release ref in one file to the newest release,
// recording what moved.
func rewriteActions(ctx context.Context, content string, latest, moved map[string]string) (string, error) {
	var failure error

	updated := actionRef.ReplaceAllStringFunc(content, func(match string) string {
		m := actionRef.FindStringSubmatch(match)
		owner, name, sub, ref := m[2], m[3], m[4], m[5]

		if !isVersionRef(ref) {
			return match
		}

		slug := owner + "/" + name

		want, ok := latest[slug]
		if !ok {
			var err error

			want, err = latestRelease(ctx, owner, name)
			if err != nil {
				// One unreachable action must not abandon the rest; record it
				// and leave that ref where it is.
				failure = err

				return match
			}

			latest[slug] = want
		}

		if want == ref {
			return match
		}

		moved[slug] = fmt.Sprintf("%s %s -> %s", slug, ref, want)

		return m[1] + slug + sub + "@" + want
	})

	if failure != nil && len(moved) == 0 {
		return "", failure
	}

	return updated, nil
}

// lockMoves reports the refs that kept their name while the commit under them
// moved: a branch the relock advanced. A tag move shows up as a new entry
// instead, and rewriteActions already reported it.
func lockMoves(before, after string) ([]string, error) {
	pre, err := lockedCommits(before)
	if err != nil {
		return nil, err
	}

	post, err := lockedCommits(after)
	if err != nil {
		return nil, err
	}

	var moves []string

	for ref, commit := range post {
		if old, ok := pre[ref]; ok && old != commit {
			moves = append(moves, fmt.Sprintf("%s %s -> %s", ref, short(old), short(commit)))
		}
	}

	sort.Strings(moves)

	return moves, nil
}

// lockedCommits maps each lockfile entry to the commit it runs.
func lockedCommits(content string) (map[string]string, error) {
	var lock struct {
		Dependencies map[string]struct {
			Commit string `yaml:"commit"`
		} `yaml:"dependencies"`
	}

	if err := yaml.Unmarshal([]byte(content), &lock); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("parsing %s: %w", actionsLock, err)
	}

	commits := make(map[string]string, len(lock.Dependencies))
	for ref, dep := range lock.Dependencies {
		commits[ref] = strings.TrimPrefix(dep.Commit, "sha1-")
	}

	return commits, nil
}

func actionAreas() []area {
	return []area{{
		Name:    "actions",
		Apply:   applyActions,
		Message: func(c change) string { return ".github: bump " + c.Summary },
	}}
}
