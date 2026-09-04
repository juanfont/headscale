// Command bump keeps headscale's pinned versions current and puts the result
// in front of a maintainer as a single reviewable pull request.
//
// The pins are interlocked. flake.nix asks nixpkgs for the newest Go, so a lock
// update moves the compiler and every devShell tool at once. Two Dockerfiles
// compile a tailscale tree cloned from an unpinned branch, so their builder
// image has to keep up with upstream's go directive. go.mod carries two pairs
// that must move together. The capability-version table is scraped from
// tailscale's published tags, so it goes stale without anyone touching the
// repository.
//
// Each of those is an area: applied, gated, and committed on its own, so one
// failure costs one commit rather than the whole pull request.
//
//	bump plan     resolve every source of truth and print what would change
//	bump run      apply, gate, and open or update the pull request
//	bump verify   assert the pins are mutually consistent
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

type runFlags struct {
	DryRun bool   `flag:"dry-run,default=false,Rebuild the branch locally and report, but run no final gate and touch no remote"`
	NoPR   bool   `flag:"no-pr,default=false,Push nothing and open no pull request"`
	Areas  string `flag:"areas,Comma-separated areas to run (default: all)"`
	Skip   string `flag:"skip,Comma-separated areas to skip"`
	Force  bool   `flag:"force,default=false,Open a pull request even if an identical one was closed unmerged"`
	Branch string `flag:"branch,default=automation/version-bump,Branch to push"`
	Base   string `flag:"base,default=main,Base branch"`
	Remote string `flag:"remote,default=origin,Git remote"`
	Repo   string `flag:"repo,GitHub repository (default: the one the job runs in)"`
	Gate   string `flag:"gate,default=full,Final gate level: none, quick or full"`
}

var runCfg runFlags

func main() {
	log.SetFlags(0)
	log.SetPrefix("bump: ")

	root := command.C{
		Name: "bump",
		Help: "Keep headscale's pinned versions current",
		Commands: []*command.C{
			{
				Name: "plan",
				Help: "Resolve every source of truth and print what would change",
				Run:  func(env *command.Env) error { return cmdPlan(env.Context()) },
			},
			{
				Name:     "run",
				Help:     "Apply, gate, and open or update the pull request",
				SetFlags: command.Flags(flax.MustBind, &runCfg),
				Run:      func(env *command.Env) error { return cmdRun(env.Context()) },
			},
			{
				Name: "verify",
				Help: "Assert the pins are mutually consistent",
				Run:  func(env *command.Env) error { return cmdVerify(env.Context()) },
			},
			command.HelpCommand(nil),
		},
	}

	command.RunOrFail(root.NewEnv(nil), os.Args[1:])
}

// selector turns the --areas and --skip flags into a predicate.
func selector(only, skip string) func(string) bool {
	set := func(s string) map[string]bool {
		m := map[string]bool{}

		for part := range strings.SplitSeq(s, ",") {
			if part = strings.TrimSpace(part); part != "" {
				m[part] = true
			}
		}

		return m
	}

	wanted, skipped := set(only), set(skip)

	return func(name string) bool {
		if skipped[name] {
			return false
		}

		return len(wanted) == 0 || wanted[name]
	}
}

func cmdRun(ctx context.Context) error {
	gate := runCfg.Gate
	noPR := runCfg.NoPR

	if runCfg.DryRun {
		gate, noPR = gateNone, true
	}

	r, err := openRepo(ctx)
	if err != nil {
		return err
	}

	if err := startBranch(ctx, r, runCfg.Remote, runCfg.Base, runCfg.Branch); err != nil { //nolint:noinlineerr
		return err
	}

	results, err := runAreas(ctx, r, allAreas(), selector(runCfg.Areas, runCfg.Skip))
	if err != nil {
		return err
	}

	results, err = enforceFinalGate(ctx, r, results, gate)
	if err != nil {
		return err
	}

	tree, err := treeSHA(ctx, r)
	if err != nil {
		return err
	}

	head, err := headSHA(ctx, r)
	if err != nil {
		return err
	}

	body := renderBody(results, markerOf(results, tree, head), gate)

	if err := writeStepSummary(body); err != nil { //nolint:noinlineerr
		return err
	}

	if !anyApplied(results) {
		log.Print("nothing moved")

		return nil
	}

	if noPR {
		fmt.Print(body)

		return nil
	}

	slug, err := currentSlug(ctx, r, runCfg.Repo)
	if err != nil {
		return err
	}

	return publish(ctx, r, publishOptions{
		Slug:   slug,
		Remote: runCfg.Remote,
		Branch: runCfg.Branch,
		Base:   runCfg.Base,
		Title:  "all: bump pinned versions",
		Gate:   gate,
		Force:  runCfg.Force,
	}, results)
}

func anyApplied(results []result) bool {
	for _, res := range results {
		if res.Commit != "" {
			return true
		}
	}

	return false
}

// writeStepSummary mirrors the report into the workflow run page, so a run that
// opens no pull request still says why.
func writeStepSummary(body string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}

	//nolint:gosec // the path is the workflow runner's own summary file
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening step summary: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(body); err != nil { //nolint:noinlineerr
		return fmt.Errorf("writing step summary: %w", err)
	}

	return nil
}
