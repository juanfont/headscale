package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// tailscaleGoModURL is the go directive that the two builder stages cloning
// tailscale must be able to satisfy.
const tailscaleGoModURL = "https://raw.githubusercontent.com/tailscale/tailscale/main/go.mod"

const dockerHubTagURL = "https://hub.docker.com/v2/repositories/library/%s/tags/%s"

var (
	errNoGoDirective = errors.New("no go directive found")
	errTagMissing    = errors.New("image tag does not exist")
)

// golangFrom matches the version inside a golang builder image reference,
// leaving any registry prefix and OS suffix untouched.
var golangFrom = regexp.MustCompile(`(?m)^(FROM\s+\S*golang:)(\d[\w.]*)(-[\w.]+)?`)

// goPin is a Dockerfile whose golang builder must satisfy some minimum.
type goPin struct {
	File string
	// Why names the thing that sets the floor, for the report.
	Why string
}

// tailscaleBuilders clone tailscale from an unpinned branch, so their floor is
// upstream's go directive rather than ours.
var tailscaleBuilders = []goPin{
	{File: "Dockerfile.tailscale-HEAD", Why: "tailscale main"},
	{File: "Dockerfile.derper", Why: "tailscale main"},
}

// localBuilders compile this repository, so they track the toolchain the nix
// build uses and must not fall below go.mod's own directive.
var localBuilders = []goPin{
	{File: "Dockerfile.integration", Why: "devShell Go"},
	{File: "Dockerfile.wasmclient", Why: "devShell Go"},
}

// currentGolangTag reports the version pinned in a Dockerfile's builder stage.
func currentGolangTag(content string) (string, bool) {
	m := golangFrom.FindStringSubmatch(content)
	if m == nil {
		return "", false
	}

	return m[2], true
}

// golangTagSuffix reports the OS variant of a builder image, such as "-alpine".
func golangTagSuffix(content string) string {
	m := golangFrom.FindStringSubmatch(content)
	if m == nil {
		return ""
	}

	return m[3]
}

// setGolangTag rewrites every golang builder reference to want.
func setGolangTag(content, want string) string {
	return golangFrom.ReplaceAllString(content, "${1}"+want+"${3}")
}

// goDirective extracts the version from a go.mod's go line.
func goDirective(goMod string) (string, error) {
	for line := range strings.Lines(goMod) {
		if rest, ok := strings.CutPrefix(line, "go "); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				return fields[0], nil
			}
		}
	}

	return "", errNoGoDirective
}

// tailscaleGo reads the go directive at the tip of tailscale's default branch.
func tailscaleGo(ctx context.Context) (string, error) {
	body, err := fetch(ctx, tailscaleGoModURL)
	if err != nil {
		return "", err
	}

	return goDirective(string(body))
}

// tagExists asks the registry whether a tag is published. Rewriting a
// Dockerfile to a tag that has not been pushed yet turns a bump into an outage.
func tagExists(ctx context.Context, image, tag string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf(dockerHubTagURL, image, tag), nil)
	if err != nil {
		return fmt.Errorf("building tag request: %w", err)
	}

	client := &http.Client{Timeout: proxyTimeout}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("checking %s:%s: %w", image, tag, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s:%s (%s)", errTagMissing, image, tag, resp.Status)
	}

	return nil
}

// higher returns whichever Go version sorts later.
func higher(a, b string) string {
	if semver.Compare("v"+a, "v"+b) >= 0 {
		return a
	}

	return b
}

// bumpBuilders raises each pin to want, and reports what moved.
func bumpBuilders(ctx context.Context, r *repo, pins []goPin, want string) ([]string, error) {
	var moved []string

	for _, pin := range pins {
		content, err := r.readFile(pin.File)
		if err != nil {
			return nil, err
		}

		have, ok := currentGolangTag(content)
		if !ok {
			return nil, fmt.Errorf("%s: %w", pin.File, errNoGoDirective)
		}

		if semver.Compare("v"+have, "v"+want) >= 0 {
			continue
		}

		// Probe only a tag that is about to be written. nixpkgs can ship a Go
		// release before the image is published, and a pin that needs no change
		// must not be held up by a tag nobody is going to reference.
		err = tagExists(ctx, "golang", want+golangTagSuffix(content))
		if err != nil {
			return nil, err
		}

		err = r.writeFile(pin.File, setGolangTag(content, want))
		if err != nil {
			return nil, err
		}

		moved = append(moved, fmt.Sprintf("%s golang %s -> %s (%s)", pin.File, have, want, pin.Why))
	}

	return moved, nil
}

// applyDockerGo brings every golang builder image up to the version its
// consumer requires. The relation is a floor, not equality: a newer toolchain
// compiles an older module, and only the reverse fails.
func applyDockerGo(ctx context.Context, r *repo) (change, error) {
	tsGo, err := tailscaleGo(ctx)
	if err != nil {
		return change{}, err
	}

	nixGo, err := goVersion(ctx, r)
	if err != nil {
		return change{}, err
	}

	ourMod, err := r.readFile("go.mod")
	if err != nil {
		return change{}, err
	}

	ourGo, err := goDirective(ourMod)
	if err != nil {
		return change{}, err
	}

	localWant := higher(nixGo, ourGo)

	moved, err := bumpBuilders(ctx, r, tailscaleBuilders, tsGo)
	if err != nil {
		return change{}, err
	}

	movedLocal, err := bumpBuilders(ctx, r, localBuilders, localWant)
	if err != nil {
		return change{}, err
	}

	moved = append(moved, movedLocal...)
	if len(moved) == 0 {
		return change{Empty: true}, nil
	}

	return change{
		Summary: fmt.Sprintf("golang builders to %s / %s", tsGo, localWant),
		Detail:  moved,
	}, nil
}

// gateDockerGo re-reads what was written and re-checks the floors, so a bad
// rewrite is caught before anything is committed.
func gateDockerGo(ctx context.Context, r *repo) error {
	tsGo, err := tailscaleGo(ctx)
	if err != nil {
		return err
	}

	ourMod, err := r.readFile("go.mod")
	if err != nil {
		return err
	}

	ourGo, err := goDirective(ourMod)
	if err != nil {
		return err
	}

	for _, check := range []struct {
		pins  []goPin
		floor string
	}{
		{tailscaleBuilders, tsGo},
		{localBuilders, ourGo},
	} {
		for _, pin := range check.pins {
			content, err := r.readFile(pin.File)
			if err != nil {
				return err
			}

			have, ok := currentGolangTag(content)
			if !ok {
				return fmt.Errorf("%s: %w", pin.File, errNoGoDirective)
			}

			if semver.Compare("v"+have, "v"+check.floor) < 0 {
				return fmt.Errorf("%s: golang %s is below the required %s: %w",
					pin.File, have, check.floor, errTagMissing)
			}
		}
	}

	return nil
}
