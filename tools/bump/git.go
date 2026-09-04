package main

import (
	"context"
	"fmt"
	"strings"
)

// changedFiles lists paths that differ from HEAD, tracked or not.
func changedFiles(ctx context.Context, r *repo) ([]string, error) {
	out, err := r.run(ctx, "git", "status", "--porcelain", "--untracked-files=all")
	if err != nil {
		return nil, err
	}

	var files []string

	for line := range strings.Lines(out) {
		line = strings.TrimRight(line, "\n")
		if len(line) < 4 {
			continue
		}

		path := strings.TrimSpace(line[3:])
		// Renames read as "old -> new"; the destination is what matters.
		if _, dst, ok := strings.Cut(path, " -> "); ok {
			path = dst
		}

		files = append(files, strings.Trim(path, `"`))
	}

	return files, nil
}

func headSHA(ctx context.Context, r *repo) (string, error) {
	out, err := r.run(ctx, "git", "rev-parse", "HEAD")

	return strings.TrimSpace(out), err
}

// treeSHA identifies the content of the working commit, independent of message
// or parentage. It is what the pull request marker records so a rerun can tell
// "nothing new" from "same change, previously rejected".
func treeSHA(ctx context.Context, r *repo) (string, error) {
	out, err := r.run(ctx, "git", "rev-parse", "HEAD^{tree}")

	return strings.TrimSpace(out), err
}

// resetTo rewinds the worktree to sha, leaving nothing behind. Every dropped
// area goes through here, which is why a drop cannot leave a partial edit in
// the pull request.
func resetTo(ctx context.Context, r *repo, sha string) error {
	if _, err := r.run(ctx, "git", "reset", "--hard", sha); err != nil { //nolint:noinlineerr
		return err
	}

	_, err := r.run(ctx, "git", "clean", "-fd")

	return err
}

func commitAll(ctx context.Context, r *repo, message string) error {
	if _, err := r.run(ctx, "git", "add", "--all"); err != nil { //nolint:noinlineerr
		return err
	}

	// The bot's own commits are machine-generated and already gated; the
	// hooks re-run the same checks far more slowly.
	_, err := r.run(ctx, "git", "commit", "--no-verify", "--message", message)

	return err
}

// startBranch rebuilds the working branch from the base every run. The branch
// therefore never accumulates history, never conflicts, and the bot keeps no
// state on disk between runs.
func startBranch(ctx context.Context, r *repo, remote, base, branch string) error {
	if _, err := r.run(ctx, "git", "fetch", remote, base); err != nil { //nolint:noinlineerr
		return err
	}

	_, err := r.run(ctx, "git", "checkout", "-B", branch, remote+"/"+base)

	return err
}

// remoteBranchSHA is the tip of branch on remote, or "" when it does not exist.
func remoteBranchSHA(ctx context.Context, r *repo, remote, branch string) string {
	out, err := r.run(ctx, "git", "ls-remote", "--heads", remote, branch)
	if err != nil {
		return ""
	}

	fields := strings.Fields(out)
	if len(fields) == 0 {
		return ""
	}

	return fields[0]
}

func forcePush(ctx context.Context, r *repo, remote, branch string) error {
	_, err := r.run(ctx, "git", "push", "--force", remote, "HEAD:refs/heads/"+branch)
	if err != nil {
		return fmt.Errorf("pushing %s: %w", branch, err)
	}

	return nil
}
