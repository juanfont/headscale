package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"
)

// skipLabel lets a maintainer park the bot on a pull request without closing it.
const skipLabel = "no-autoupdate"

// closedCooldown is how long a rejected change is left alone. Reopening the
// same diff the next morning is how an automation earns itself an ignore rule.
const closedCooldown = 7 * 24 * time.Hour

var errHumanCommits = errors.New("branch has commits the bot did not push")

type prState struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	Body       string `json:"body"`
	HeadRefOid string `json:"headRefOid"`
	Labels     []struct {
		Name string `json:"name"`
	} `json:"labels"`
	ClosedAt  time.Time `json:"closedAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (p *prState) hasLabel(name string) bool {
	for _, l := range p.Labels {
		if l.Name == name {
			return true
		}
	}

	return false
}

// lookupPR finds the most recent pull request for branch, in any state.
func lookupPR(ctx context.Context, r *repo, slug, branch string) (*prState, error) {
	out, err := r.run(ctx, "gh", "pr", "list",
		"--repo", slug,
		"--head", branch,
		"--state", "all",
		"--limit", "5",
		"--json", "number,state,body,headRefOid,labels,closedAt,updatedAt")
	if err != nil {
		return nil, err
	}

	var prs []prState
	if err := json.Unmarshal([]byte(out), &prs); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("decoding gh pr list: %w", err)
	}

	if len(prs) == 0 {
		return nil, nil //nolint:nilnil // absence is the normal first-run case
	}

	newest := &prs[0]
	for i := range prs {
		if prs[i].UpdatedAt.After(newest.UpdatedAt) {
			newest = &prs[i]
		}
	}

	return newest, nil
}

// publishOptions carries everything the pull request lifecycle needs that is
// not derived from the working tree.
type publishOptions struct {
	Slug   string
	Remote string
	Branch string
	Base   string
	Title  string
	Force  bool
}

// publish force-pushes the rebuilt branch and puts it in front of a human:
// reusing the open pull request if there is one, opening a new one once the
// last was merged, and staying out of the way when the last was rejected.
func publish(ctx context.Context, r *repo, opt publishOptions, results []result) error {
	tree, err := treeSHA(ctx, r)
	if err != nil {
		return err
	}

	head, err := headSHA(ctx, r)
	if err != nil {
		return err
	}

	now := markerOf(results, tree, head)
	body := renderBody(results, now)

	pr, err := lookupPR(ctx, r, opt.Slug, opt.Branch)
	if err != nil {
		return err
	}

	if pr != nil && pr.hasLabel(skipLabel) {
		log.Printf("pull request #%d is labelled %s; leaving it alone", pr.Number, skipLabel)

		return nil
	}

	if pr != nil && pr.State == "OPEN" {
		return updateOpen(ctx, r, opt, pr, body, now)
	}

	if pr != nil && pr.State == "CLOSED" {
		prev, ok := parseMarker(pr.Body)
		if ok && prev.Tree == tree && !opt.Force && time.Since(pr.ClosedAt) < closedCooldown {
			log.Printf("identical tree was closed unmerged in #%d on %s; skipping",
				pr.Number, pr.ClosedAt.Format(time.DateOnly))

			return nil
		}

		body = fmt.Sprintf("Previously closed unmerged: #%d\n\n%s", pr.Number, body)
	}

	if err := forcePush(ctx, r, opt.Remote, opt.Branch); err != nil { //nolint:noinlineerr
		return err
	}

	return createPR(ctx, r, opt, body)
}

// updateOpen refreshes an existing pull request in place, but refuses to
// force-push over work the bot did not author.
func updateOpen(ctx context.Context, r *repo, opt publishOptions, pr *prState, body string, now marker) error {
	prev, hadMarker := parseMarker(pr.Body)

	remoteTip := remoteBranchSHA(ctx, r, opt.Remote, opt.Branch)
	if hadMarker && prev.Head != "" && remoteTip != "" && remoteTip != prev.Head {
		_, _ = r.run(ctx, "gh", "pr", "comment", strconv.Itoa(pr.Number), "--repo", opt.Slug,
			"--body", "This branch has commits the automation did not push, so it has paused. "+
				"Merge or close this pull request to resume.")

		return fmt.Errorf("%w: %s is at %s, expected %s", errHumanCommits, opt.Branch, remoteTip, prev.Head)
	}

	err := forcePush(ctx, r, opt.Remote, opt.Branch)
	if err != nil {
		return err
	}

	if _, err := r.run(ctx, "gh", "pr", "edit", strconv.Itoa(pr.Number), "--repo", opt.Slug, "--body", body); err != nil { //nolint:noinlineerr
		return err
	}

	// Only speak up when the outcome actually changed. A daily "still the
	// same" comment trains the reader to ignore the thread.
	if hadMarker && changedAreas(prev, now) {
		if _, err := r.run(ctx, "gh", "pr", "comment", strconv.Itoa(pr.Number), "--repo", opt.Slug, //nolint:noinlineerr
			"--body", "The set of applied areas changed since the last run; see the updated description."); err != nil {
			return err
		}
	}

	log.Printf("updated pull request #%d", pr.Number)

	return nil
}

func createPR(ctx context.Context, r *repo, opt publishOptions, body string) error {
	out, err := r.run(ctx, "gh", "pr", "create",
		"--repo", opt.Slug,
		"--base", opt.Base,
		"--head", opt.Branch,
		"--title", opt.Title,
		"--body", body)
	if err != nil {
		// The branch is already pushed at this point, so a failure here costs
		// the pull request, not the work. Say so: the usual cause is a token
		// without pull request write, and the fix is a token change plus a
		// re-run, not redoing the bump by hand.
		return fmt.Errorf("%w (branch %s is pushed; open the pull request by hand or fix the token and re-run)",
			err, opt.Branch)
	}

	log.Printf("opened pull request %s", strings.TrimSpace(out))

	return nil
}
