package main

import (
	"context"
	"fmt"
)

// cmdPlan resolves every upstream the bump reads and prints the gap against
// what is committed. It writes nothing, so it is the safe way to ask "what
// would tonight's run do" before trusting the automation.
func cmdPlan(ctx context.Context) error {
	r, err := openRepo(ctx)
	if err != nil {
		return err
	}

	for _, line := range planLines(ctx, r) {
		fmt.Println(line) //nolint:forbidigo // plan output is the point
	}

	return nil
}

func planLines(ctx context.Context, r *repo) []string {
	lines := []string{"flake.lock: `nix flake update` moves nixpkgs, flake-utils and flake-checks"}

	lines = append(lines, planBuilders(ctx, r)...)
	lines = append(lines, planLockstep(ctx, r)...)

	if version, err := oapiVersion(r); err != nil { //nolint:noinlineerr
		lines = append(lines, "oapi-codegen: "+err.Error())
	} else if latest, err := latestVersion(ctx, "github.com/oapi-codegen/oapi-codegen/v2"); err != nil { //nolint:noinlineerr
		lines = append(lines, "oapi-codegen: "+err.Error())
	} else {
		lines = append(lines, gap("Makefile oapi-codegen", version, latest))
	}

	return lines
}

func planBuilders(ctx context.Context, r *repo) []string {
	var lines []string

	tsGo, err := tailscaleGo(ctx)
	if err != nil {
		return []string{"tailscale go directive: " + err.Error()}
	}

	nixGo, err := goVersion(ctx, r)
	if err != nil {
		return []string{"devShell Go: " + err.Error()}
	}

	ourMod, err := r.readFile("go.mod")
	if err != nil {
		return []string{err.Error()}
	}

	ourGo, err := goDirective(ourMod)
	if err != nil {
		return []string{err.Error()}
	}

	lines = append(lines, fmt.Sprintf("go: go.mod %s, devShell %s, tailscale main %s", ourGo, nixGo, tsGo))

	for _, set := range []struct {
		pins []goPin
		want string
	}{
		{tailscaleBuilders, tsGo},
		{localBuilders, higher(nixGo, ourGo)},
	} {
		for _, pin := range set.pins {
			content, err := r.readFile(pin.File)
			if err != nil {
				lines = append(lines, err.Error())

				continue
			}

			have, ok := currentGolangTag(content)
			if !ok {
				lines = append(lines, pin.File+": no golang builder image found")

				continue
			}

			lines = append(lines, gap(pin.File+" golang", have, set.want))
		}
	}

	return lines
}

func planLockstep(ctx context.Context, r *repo) []string {
	var lines []string

	for _, pair := range []struct{ owner, dep, target string }{
		{modSqlite, modLibc, ""},
		{modTailscale, modGvisor, "main"},
	} {
		have, err := moduleVersion(ctx, r, pair.owner)
		if err != nil {
			lines = append(lines, pair.owner+": "+err.Error())

			continue
		}

		want := have

		if pair.target == "" {
			if latest, err := latestVersion(ctx, pair.owner); err == nil { //nolint:noinlineerr
				want = latest
			}
		}

		partner, err := partnerVersion(ctx, pair.owner, want, pair.dep)
		if err != nil {
			lines = append(lines, pair.dep+": "+err.Error())

			continue
		}

		haveDep, err := moduleVersion(ctx, r, pair.dep)
		if err != nil {
			lines = append(lines, pair.dep+": "+err.Error())

			continue
		}

		lines = append(lines, gap(pair.owner, have, want), gap(pair.dep+" (pinned by "+pair.owner+")", haveDep, partner))
	}

	return lines
}

// gap renders one pin as either current or lagging.
func gap(what, have, want string) string {
	if have == want {
		return fmt.Sprintf("%s: %s (current)", what, have)
	}

	return fmt.Sprintf("%s: %s -> %s", what, have, want)
}
