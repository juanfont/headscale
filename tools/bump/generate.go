package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// generatedPaths is every file the generators are allowed to touch. Anything
// outside it means a generator reached further than expected, and the area is
// dropped rather than committed.
var generatedPaths = map[string]bool{
	"hscontrol/types/types_clone.go":          true,
	"hscontrol/types/types_view.go":           true,
	"hscontrol/capver/capver_generated.go":    true,
	"hscontrol/capver/capver_test_data.go":    true,
	"gen/client/v1/client.gen.go":             true,
	"gen/client/v2/client.gen.go":             true,
	".github/workflows/test-integration.yaml": true,
}

// oapiPin finds the oapi-codegen version the Makefile pins, so the clients are
// regenerated with the same tool a developer running `make client` would get.
var oapiPin = regexp.MustCompile(`github\.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@(v[\w.\-]+)`)

var (
	errNoOapiPin  = errors.New("no oapi-codegen pin found in Makefile")
	errStrayWrite = errors.New("generator wrote outside the generated set")
)

func oapiVersion(r *repo) (string, error) {
	mk, err := r.readFile("Makefile")
	if err != nil {
		return "", err
	}

	m := oapiPin.FindStringSubmatch(mk)
	if m == nil {
		return "", errNoOapiPin
	}

	return m[1], nil
}

// generateClients repeats the Makefile's client recipe. The bot does not shell
// out to make, but check-generated.yml still runs the real target and diffs, so
// any drift between the two surfaces on the bot's own pull request.
func generateClients(ctx context.Context, r *repo) error {
	version, err := oapiVersion(r)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp("", "headscale-openapi-3.0.*.yaml")
	if err != nil {
		return fmt.Errorf("creating temporary spec: %w", err)
	}

	spec := tmp.Name()

	tmp.Close()
	defer os.Remove(spec)

	tool := "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@" + version

	for _, step := range [][]string{
		{"go", "run", "./cmd/gen-openapi", "-downgrade", spec},
		{"go", "run", tool, "-generate", "types,client", "-package", "clientv1", "-o", "gen/client/v1/client.gen.go", spec},
		{"go", "run", "./cmd/gen-openapi", "-api", "v2", "-downgrade", spec},
		{"go", "run", tool, "-generate", "types,client", "-package", "clientv2", "-o", "gen/client/v2/client.gen.go", spec},
	} {
		if _, err := r.nixRun(ctx, step...); err != nil {
			return err
		}
	}

	return nil
}

// applyGenerate refreshes every checked-in generated file. Most of the churn
// here is not caused by this repository at all: the capability-version table is
// scraped from tailscale's published tags, so it goes stale on an untouched
// tree the moment upstream ships a release.
func applyGenerate(ctx context.Context, r *repo) (change, error) {
	if _, err := r.nixRun(ctx, "go", "generate", "./..."); err != nil {
		return change{}, err
	}

	if err := generateClients(ctx, r); err != nil {
		return change{}, err
	}

	// go generate ./... skips dot-directories, so the integration matrix
	// generator has to be invoked from inside .github/workflows.
	if _, err := r.nixRunIn(ctx, ".github/workflows", "go", "generate"); err != nil {
		return change{}, err
	}

	touched, err := changedFiles(ctx, r)
	if err != nil {
		return change{}, err
	}

	if len(touched) == 0 {
		return change{Empty: true}, nil
	}

	return change{
		Summary: strings.Join(touched, ", "),
		Detail:  touched,
	}, nil
}

// gateGenerate refuses a generator run that reached outside the known set.
func gateGenerate(ctx context.Context, r *repo) error {
	touched, err := changedFiles(ctx, r)
	if err != nil {
		return err
	}

	for _, f := range touched {
		if !generatedPaths[f] {
			return fmt.Errorf("%w: %s", errStrayWrite, f)
		}
	}

	return nil
}

// applyFormat re-runs the repository formatters. A toolchain bump can change
// what "formatted" means: a newer prettier out of nixpkgs reformats files no
// bump touched, and the formatting check then fails on a tree the bot never
// edited. Running last means it also tidies whatever the generators emitted.
func applyFormat(ctx context.Context, r *repo) (change, error) {
	if _, err := r.nixRun(ctx, "make", "fmt"); err != nil { //nolint:noinlineerr
		return change{}, err
	}

	touched, err := changedFiles(ctx, r)
	if err != nil {
		return change{}, err
	}

	if len(touched) == 0 {
		return change{Empty: true}, nil
	}

	return change{
		Summary: fmt.Sprintf("%d file(s) reformatted", len(touched)),
		Detail:  touched,
	}, nil
}
