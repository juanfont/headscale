package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/mod/semver"
)

const (
	pypiURL = "https://pypi.org/pypi/%s/json"

	providerRegistryURL = "https://registry.opentofu.org/v1/providers/tailscale/tailscale/versions"
	// providerPinFile holds the provider releases the servertest Terraform
	// tests run against.
	providerPinFile = "hscontrol/servertest/apiv2_test.go"
	// testedProviders is how many of the newest provider releases are tested:
	// the latest, and the ones before it that users still run.
	testedProviders = 3
)

var (
	// preCommitRev matches the pinned revision of the upstream hook repository.
	preCommitRev = regexp.MustCompile(`(?m)^(\s*- repo: https://github\.com/pre-commit/pre-commit-hooks\n\s*rev: )(\S+)`)

	// pyRequirement splits "mkdocs-materialx[imaging]~=10.1" into its parts.
	pyRequirement = regexp.MustCompile(`^([A-Za-z0-9._-]+)(\[[^\]]*\])?~=(\d+)\.(\d+)$`)

	// providerPin captures the body of the tested provider release list.
	providerPin   = regexp.MustCompile(`(?m)^(var terraformProviderVersions = \[\]string\{)([^}]*)\}`)
	quotedVersion = regexp.MustCompile(`"([^"]+)"`)
)

// applyOapiCodegen moves the generator pin in the Makefile. The generate area
// reads the pin back out of the Makefile, so the clients are regenerated with
// whatever this lands on.
func applyOapiCodegen(ctx context.Context, r *repo) (change, error) {
	have, err := oapiVersion(r)
	if err != nil {
		return change{}, err
	}

	want, err := latestVersion(ctx, "github.com/oapi-codegen/oapi-codegen/v2", have)
	if err != nil {
		return change{}, err
	}

	if want == have {
		return change{Empty: true}, nil
	}

	content, err := r.readFile("Makefile")
	if err != nil {
		return change{}, err
	}

	// Both invocations carry the pin; leaving one behind would generate the
	// two clients with different tools.
	updated := strings.ReplaceAll(content,
		"oapi-codegen/v2/cmd/oapi-codegen@"+have,
		"oapi-codegen/v2/cmd/oapi-codegen@"+want)

	err = r.writeFile("Makefile", updated)
	if err != nil {
		return change{}, err
	}

	return change{
		Summary: fmt.Sprintf("oapi-codegen %s to %s", have, want),
		Detail:  []string{fmt.Sprintf("Makefile oapi-codegen %s -> %s", have, want)},
	}, nil
}

// gateOapiCodegen asserts no invocation kept the old pin.
func gateOapiCodegen(_ context.Context, r *repo) error {
	content, err := r.readFile("Makefile")
	if err != nil {
		return err
	}

	version, err := oapiVersion(r)
	if err != nil {
		return err
	}

	want := strings.Count(content, "oapi-codegen/v2/cmd/oapi-codegen@")

	got := strings.Count(content, "oapi-codegen/v2/cmd/oapi-codegen@"+version)
	if got != want {
		return fmt.Errorf("%w: %d of %d oapi-codegen invocations use %s",
			errNoMatchingTag, got, want, version)
	}

	return nil
}

// applyPreCommit moves the only external hook revision. Every other hook in the
// config is language: system and follows the devShell.
func applyPreCommit(ctx context.Context, r *repo) (change, error) {
	content, err := r.readFile(".pre-commit-config.yaml")
	if err != nil {
		return change{}, err
	}

	m := preCommitRev.FindStringSubmatch(content)
	if m == nil {
		return change{}, fmt.Errorf("%w: pre-commit-hooks rev", errNoMatchingTag)
	}

	want, err := latestRelease(ctx, "pre-commit", "pre-commit-hooks")
	if err != nil {
		return change{}, err
	}

	if want == m[2] {
		return change{Empty: true}, nil
	}

	err = r.writeFile(".pre-commit-config.yaml", preCommitRev.ReplaceAllString(content, "${1}"+want))
	if err != nil {
		return change{}, err
	}

	return change{
		Summary: fmt.Sprintf("pre-commit-hooks %s to %s", m[2], want),
		Detail:  []string{fmt.Sprintf(".pre-commit-config.yaml rev %s -> %s", m[2], want)},
	}, nil
}

// pypiVersion is the newest published version of a distribution.
func pypiVersion(ctx context.Context, name string) (string, error) {
	body, err := fetch(ctx, fmt.Sprintf(pypiURL, name))
	if err != nil {
		return "", err
	}

	var meta struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}

	if err := json.Unmarshal(body, &meta); err != nil { //nolint:noinlineerr
		return "", fmt.Errorf("decoding PyPI metadata for %s: %w", name, err)
	}

	return meta.Info.Version, nil
}

// applyDocsRequirements raises the compatible-release floors in the docs
// requirements. "~=X.Y" already admits newer patch and minor releases, so this
// is about keeping the recorded floor honest rather than unblocking an upgrade.
func applyDocsRequirements(ctx context.Context, r *repo) (change, error) {
	const file = "docs/requirements.txt"

	content, err := r.readFile(file)
	if err != nil {
		return change{}, err
	}

	var (
		out     strings.Builder
		details []string
	)

	for line := range strings.Lines(content) {
		bumped, detail, err := bumpRequirement(ctx, line)
		if err != nil {
			return change{}, err
		}

		out.WriteString(bumped)

		if detail != "" {
			details = append(details, detail)
		}
	}

	if len(details) == 0 {
		return change{Empty: true}, nil
	}

	err = r.writeFile(file, out.String())
	if err != nil {
		return change{}, err
	}

	return change{
		Summary: fmt.Sprintf("%d docs requirement floors", len(details)),
		Detail:  details,
	}, nil
}

// bumpRequirement returns the line to write and, when it moved, a description.
func bumpRequirement(ctx context.Context, line string) (string, string, error) {
	trimmed := strings.TrimRight(line, "\n")

	m := pyRequirement.FindStringSubmatch(trimmed)
	if m == nil {
		return line, "", nil
	}

	name, extras, have := m[1], m[2], m[3]+"."+m[4]

	latest, err := pypiVersion(ctx, name)
	if err != nil {
		return "", "", err
	}

	parts := strings.SplitN(latest, ".", 3)
	if len(parts) < 2 {
		return line, "", nil
	}

	want := parts[0] + "." + parts[1]
	if semver.Compare("v"+want, "v"+have) <= 0 {
		return line, "", nil
	}

	return fmt.Sprintf("%s%s~=%s\n", name, extras, want),
		fmt.Sprintf("%s ~=%s -> ~=%s", name, have, want), nil
}

// newestProviders is the newest testedProviders releases of the
// tailscale/tailscale Terraform provider, oldest first.
func newestProviders(ctx context.Context) ([]string, error) {
	body, err := fetch(ctx, providerRegistryURL)
	if err != nil {
		return nil, err
	}

	var listing struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}

	if err := json.Unmarshal(body, &listing); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("decoding provider versions: %w", err)
	}

	versions := make([]string, 0, len(listing.Versions))
	for _, v := range listing.Versions {
		versions = append(versions, v.Version)
	}

	newest := newestReleases(versions, testedProviders)
	if len(newest) == 0 {
		return nil, fmt.Errorf("%w: tailscale/tailscale provider release", errNoMatchingTag)
	}

	return newest, nil
}

// newestReleases is the newest n stable versions, oldest first. A
// prerelease is not something users run, so it is never tested.
func newestReleases(versions []string, n int) []string {
	stable := slices.DeleteFunc(slices.Clone(versions), func(v string) bool {
		return !semver.IsValid("v"+v) || semver.Prerelease("v"+v) != ""
	})

	slices.SortFunc(stable, func(a, b string) int { return semver.Compare("v"+a, "v"+b) })

	return stable[max(0, len(stable)-n):]
}

// currentProviders reads the tested provider releases out of servertest.
func currentProviders(r *repo) ([]string, error) {
	content, err := r.readFile(providerPinFile)
	if err != nil {
		return nil, err
	}

	m := providerPin.FindStringSubmatch(content)
	if m == nil {
		return nil, fmt.Errorf("%w: terraformProviderVersions in %s", errNoMatchingTag, providerPinFile)
	}

	var versions []string
	for _, q := range quotedVersion.FindAllStringSubmatch(m[2], -1) {
		versions = append(versions, q[1])
	}

	return versions, nil
}

// applyProviders moves the tested Terraform provider releases to the newest
// ones, so a provider release that breaks headscale shows up here rather than
// on whichever pull request runs first after it.
func applyProviders(ctx context.Context, r *repo) (change, error) {
	have, err := currentProviders(r)
	if err != nil {
		return change{}, err
	}

	want, err := newestProviders(ctx)
	if err != nil {
		return change{}, err
	}

	if slices.Equal(have, want) {
		return change{Empty: true}, nil
	}

	content, err := r.readFile(providerPinFile)
	if err != nil {
		return change{}, err
	}

	list := `"` + strings.Join(want, `", "`) + `"`

	err = r.writeFile(providerPinFile, providerPin.ReplaceAllString(content, "${1}"+list+"}"))
	if err != nil {
		return change{}, err
	}

	return change{
		Summary: "Terraform provider " + strings.Join(want, ", "),
		Detail: []string{fmt.Sprintf("%s terraformProviderVersions %s -> %s",
			providerPinFile, strings.Join(have, ", "), strings.Join(want, ", "))},
	}, nil
}

func toolAreas() []area {
	return []area{
		{
			Name:    "tools:oapi-codegen",
			Apply:   applyOapiCodegen,
			Gate:    gateOapiCodegen,
			Message: func(c change) string { return "Makefile: bump " + c.Summary },
		},
		{
			Name:    "tools:pre-commit",
			Apply:   applyPreCommit,
			Message: func(c change) string { return "prek: bump " + c.Summary },
		},
		{
			Name:    "tools:docs",
			Apply:   applyDocsRequirements,
			Message: func(c change) string { return "docs: raise " + c.Summary },
		},
		{
			Name:    "tools:terraform-provider",
			Apply:   applyProviders,
			Message: func(c change) string { return "servertest: test " + c.Summary },
		},
	}
}
