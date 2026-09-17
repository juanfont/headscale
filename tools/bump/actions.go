package main

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// actionPin matches a SHA-pinned action reference together with the trailing
// comment that says which version the SHA is. Both have to move, or the comment
// starts lying about what is running.
var actionPin = regexp.MustCompile(
	`(?m)(uses:\s+)([\w.-]+)/([\w.-]+)((?:/[\w./-]+)?)@([0-9a-f]{40})(\s+#\s*)(\S+)`)

// isVersionRef reports whether a pin comment names a release rather than a
// branch. A branch pin is deliberate and keeps following that branch.
func isVersionRef(ref string) bool {
	return strings.HasPrefix(ref, "v") && len(ref) > 1 && ref[1] >= '0' && ref[1] <= '9'
}

// workflowFiles lists the workflow definitions, which is the only place action
// pins live.
func workflowFiles(r *repo) ([]string, error) {
	var files []string

	for _, ext := range []string{"*.yml", "*.yaml"} {
		matches, err := filepath.Glob(r.path(".github", "workflows", ext))
		if err != nil {
			return nil, fmt.Errorf("listing workflows: %w", err)
		}

		for _, m := range matches {
			files = append(files, filepath.Join(".github", "workflows", filepath.Base(m)))
		}
	}

	sort.Strings(files)

	return files, nil
}

// actionTarget is where one action should end up.
type actionTarget struct {
	SHA string
	Ref string
}

// resolveAction decides what a pin should point at. A release pin follows the
// newest release; a branch pin follows that branch's head.
func resolveAction(ctx context.Context, owner, name, ref string) (actionTarget, error) {
	want := ref

	if isVersionRef(ref) {
		latest, err := latestRelease(ctx, owner, name)
		if err != nil {
			return actionTarget{}, err
		}

		want = latest
	}

	sha, err := commitOfRef(ctx, owner, name, want)
	if err != nil {
		return actionTarget{}, err
	}

	return actionTarget{SHA: sha, Ref: want}, nil
}

// applyActions refreshes every SHA-pinned action reference. This replaces the
// separate actions-version workflow, so there is one bot, one token and one
// pull request to review.
func applyActions(ctx context.Context, r *repo) (change, error) {
	files, err := workflowFiles(r)
	if err != nil {
		return change{}, err
	}

	// One lookup per action, not per occurrence: checkout alone appears twenty
	// times, and the API budget is not unlimited.
	resolved := map[string]actionTarget{}
	moved := map[string]string{}

	var touched []string

	for _, file := range files {
		content, err := r.readFile(file)
		if err != nil {
			return change{}, err
		}

		updated, err := rewriteActions(ctx, content, resolved, moved)
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

		touched = append(touched, filepath.Base(file))
	}

	if len(moved) == 0 {
		return change{Empty: true}, nil
	}

	details := make([]string, 0, len(moved))
	for _, line := range moved {
		details = append(details, line)
	}

	sort.Strings(details)

	return change{
		Summary: fmt.Sprintf("%d action pins", len(moved)),
		Detail:  append(details, "files: "+strings.Join(touched, ", ")),
	}, nil
}

// rewriteActions rewrites every pin in one file, recording what moved.
func rewriteActions(ctx context.Context, content string, resolved map[string]actionTarget, moved map[string]string) (string, error) {
	var failure error

	updated := actionPin.ReplaceAllStringFunc(content, func(match string) string {
		m := actionPin.FindStringSubmatch(match)
		owner, name, sub, sha, sep, ref := m[2], m[3], m[4], m[5], m[6], m[7]

		key := owner + "/" + name + "@" + ref

		target, ok := resolved[key]
		if !ok {
			var err error

			target, err = resolveAction(ctx, owner, name, ref)
			if err != nil {
				// One unreachable action must not abandon the rest; record it
				// and leave that pin where it is.
				failure = err

				return match
			}

			resolved[key] = target
		}

		if target.SHA == sha {
			return match
		}

		if ref == target.Ref {
			// A branch pin keeps its name; only the commit under it moved.
			moved[owner+"/"+name] = fmt.Sprintf("%s/%s %s %s -> %s",
				owner, name, ref, sha[:7], target.SHA[:7])
		} else {
			moved[owner+"/"+name] = fmt.Sprintf("%s/%s %s -> %s", owner, name, ref, target.Ref)
		}

		return m[1] + owner + "/" + name + sub + "@" + target.SHA + sep + target.Ref
	})

	if failure != nil && len(moved) == 0 {
		return "", failure
	}

	return updated, nil
}

func actionAreas() []area {
	return []area{{
		Name:    "actions",
		Apply:   applyActions,
		Message: func(c change) string { return ".github: bump " + c.Summary },
	}}
}
