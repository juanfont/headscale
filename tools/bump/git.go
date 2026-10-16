package main

import (
	"context"
	"errors"
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

var errRebaseConflict = errors.New("hand-pushed commits do not rebase cleanly")

// startBranch rebuilds the working branch from the base every run, so it never
// accumulates history and the bot keeps no state on disk between runs. The
// exception is an open pull request holding commits someone pushed by hand:
// rebuilding would erase them, so the branch is rebased onto the base and the
// run builds on top. It returns the subjects of the commits it carried.
func startBranch(ctx context.Context, r *repo, remote, base, branch string, carry bool) ([]string, error) {
	if _, err := r.run(ctx, "git", "fetch", remote, base); err != nil { //nolint:noinlineerr
		return nil, err
	}

	var hand []string

	if carry {
		var err error

		hand, err = handCommits(ctx, r, remote, base, branch)
		if err != nil {
			return nil, err
		}
	}

	start := remote + "/" + base
	if len(hand) > 0 {
		start = remote + "/" + branch
	}

	if _, err := r.run(ctx, "git", "checkout", "-B", branch, start); err != nil { //nolint:noinlineerr
		return nil, err
	}

	if len(hand) == 0 {
		return nil, nil
	}

	if _, err := r.run(ctx, "git", "rebase", remote+"/"+base); err != nil { //nolint:noinlineerr
		_, _ = r.run(ctx, "git", "rebase", "--abort")

		return nil, fmt.Errorf("%w onto %s: %w", errRebaseConflict, base, err)
	}

	return hand, nil
}

// handCommits lists, oldest first, the subjects of commits on the remote branch
// authored by anyone but the configured committer.
func handCommits(ctx context.Context, r *repo, remote, base, branch string) ([]string, error) {
	if _, err := r.run(ctx, "git", "fetch", remote, branch); err != nil { //nolint:noinlineerr
		return nil, err
	}

	self, err := r.run(ctx, "git", "config", "user.email")
	if err != nil {
		return nil, err
	}

	out, err := r.run(ctx, "git", "log", "--reverse", "--format=%ae%x00%s",
		remote+"/"+base+".."+remote+"/"+branch)
	if err != nil {
		return nil, err
	}

	return notAuthoredBy(out, strings.TrimSpace(self)), nil
}

// notAuthoredBy filters `git log --format=%ae%x00%s` output to the subjects of
// commits whose author is not email.
func notAuthoredBy(log, email string) []string {
	var subjects []string

	for line := range strings.Lines(log) {
		author, subject, _ := strings.Cut(strings.TrimRight(line, "\n"), "\x00")
		if author != email {
			subjects = append(subjects, subject)
		}
	}

	return subjects
}

// forcePush replaces branch on remote. A non-empty lease is the tip the run
// started from; the push is refused if anyone moved the branch since.
func forcePush(ctx context.Context, r *repo, remote, branch, lease string) error {
	force := "--force"
	if lease != "" {
		force = "--force-with-lease=refs/heads/" + branch + ":" + lease
	}

	_, err := r.run(ctx, "git", "push", force, remote, "HEAD:refs/heads/"+branch)
	if err != nil {
		return fmt.Errorf("pushing %s: %w", branch, err)
	}

	return nil
}
