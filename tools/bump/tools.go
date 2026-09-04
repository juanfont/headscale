package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

const pypiURL = "https://pypi.org/pypi/%s/json"

var (
	// preCommitRev matches the pinned revision of the upstream hook repository.
	preCommitRev = regexp.MustCompile(`(?m)^(\s*- repo: https://github\.com/pre-commit/pre-commit-hooks\n\s*rev: )(\S+)`)

	// pyRequirement splits "mkdocs-materialx[imaging]~=10.1" into its parts.
	pyRequirement = regexp.MustCompile(`^([A-Za-z0-9._-]+)(\[[^\]]*\])?~=(\d+)\.(\d+)$`)
)

// applyOapiCodegen moves the generator pin in the Makefile. The generate area
// reads the pin back out of the Makefile, so the clients are regenerated with
// whatever this lands on.
func applyOapiCodegen(ctx context.Context, r *repo) (change, error) {
	have, err := oapiVersion(r)
	if err != nil {
		return change{}, err
	}

	want, err := latestVersion(ctx, "github.com/oapi-codegen/oapi-codegen/v2")
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
	}
}
