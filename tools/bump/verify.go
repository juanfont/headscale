package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/mod/semver"
)

var errInvariants = errors.New("version pins are inconsistent")

// finding is one violated invariant, phrased so the fix is obvious.
type finding string

// cmdVerify asserts the pins agree with each other and with their upstreams. It
// is deliberately separate from run: the same checks catch a hand-written
// commit that breaks a lockstep rule, not just a bad automated one.
func cmdVerify(ctx context.Context) error {
	r, err := openRepo(ctx)
	if err != nil {
		return err
	}

	findings := make([]finding, 0, 4)

	findings = append(findings, verifyLockstep(ctx, r)...)
	findings = append(findings, verifyBuilders(ctx, r)...)
	findings = append(findings, verifyToolchain(ctx, r)...)
	findings = append(findings, verifyVendorHash(ctx, r)...)

	if len(findings) == 0 {
		log.Print("all version pins agree")

		return nil
	}

	for _, f := range findings {
		log.Printf("- %s", f)
	}

	return fmt.Errorf("%w: %d finding(s)", errInvariants, len(findings))
}

func verifyLockstep(ctx context.Context, r *repo) []finding {
	var findings []finding

	err := checkLockstep(ctx, r)
	if err != nil {
		findings = append(findings, finding(err.Error()))
	}

	err = checkModComments(r)
	if err != nil {
		findings = append(findings, finding(err.Error()))
	}

	return findings
}

// verifyBuilders checks the floor relation, not equality: a newer builder
// compiles an older module, and only the reverse fails.
func verifyBuilders(ctx context.Context, r *repo) []finding {
	var findings []finding

	ourMod, err := r.readFile("go.mod")
	if err != nil {
		return []finding{finding(err.Error())}
	}

	ourGo, err := goDirective(ourMod)
	if err != nil {
		return []finding{finding(err.Error())}
	}

	tsGo, tsErr := tailscaleGo(ctx)

	for _, check := range []struct {
		pins  []goPin
		floor string
		err   error
	}{
		{tailscaleBuilders, tsGo, tsErr},
		{localBuilders, ourGo, nil},
	} {
		if check.err != nil {
			findings = append(findings, finding("could not resolve the tailscale go directive: "+check.err.Error()))

			continue
		}

		for _, pin := range check.pins {
			content, err := r.readFile(pin.File)
			if err != nil {
				findings = append(findings, finding(err.Error()))

				continue
			}

			have, ok := currentGolangTag(content)
			if !ok {
				findings = append(findings, finding(pin.File+": no golang builder image found"))

				continue
			}

			if semver.Compare("v"+have, "v"+check.floor) < 0 {
				findings = append(findings, finding(fmt.Sprintf(
					"%s: golang %s is below the %s required by %s", pin.File, have, check.floor, pin.Why)))
			}
		}
	}

	return findings
}

// verifyToolchain reports, but never edits, a go.mod directive that has fallen
// behind the toolchain the build actually uses. Raising it is a promise to
// downstream packagers, so it stays a human decision.
func verifyToolchain(ctx context.Context, r *repo) []finding {
	nixGo, err := goVersion(ctx, r)
	if err != nil {
		return []finding{finding(err.Error())}
	}

	ourMod, err := r.readFile("go.mod")
	if err != nil {
		return []finding{finding(err.Error())}
	}

	ourGo, err := goDirective(ourMod)
	if err != nil {
		return []finding{finding(err.Error())}
	}

	if semver.Compare("v"+ourGo, "v"+nixGo) > 0 {
		return []finding{finding(fmt.Sprintf(
			"go.mod requires go %s but the devShell provides %s", ourGo, nixGo))}
	}

	return nil
}

func verifyVendorHash(ctx context.Context, r *repo) []finding {
	out, err := r.nixRun(ctx, "go", "run", "./cmd/vendorhash", "check")
	if err != nil {
		return []finding{finding("flakehashes.json is stale: " + strings.TrimSpace(out))}
	}

	return nil
}
