package main

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// imageBump is a base image reference the bot keeps current. Each becomes its
// own area, and therefore its own commit, so a distribution jump can be dropped
// without taking the rest of the day's bump with it.
type imageBump struct {
	Name string
	// Prefix is the commit subject's package field.
	Prefix string
	Files  []string
	// Ref captures the reference in two groups: everything up to the value,
	// and the value itself. Only the second is rewritten.
	Ref *regexp.Regexp
	// Resolve returns the value that should be pinned, given the current one.
	Resolve func(ctx context.Context, have string) (string, error)
	// Verify proves the resolved reference is actually published, so a bump
	// cannot point CI at an image that does not exist yet.
	Verify func(ctx context.Context, want string) error
}

// Every reference is captured whole, so a value that folds two things together
// (a Rust version and the Debian codename it is built on) moves as one piece.
var (
	alpineRef     = regexp.MustCompile(`(?m)^(FROM\s+alpine:)(\S+)`)
	debianRef     = regexp.MustCompile(`(?m)^(FROM\s+debian:)(\S+)`)
	nodeRef       = regexp.MustCompile(`(?m)^(FROM\s+node:)(\S+)`)
	rustRef       = regexp.MustCompile(`(?m)^(FROM\s+rust:)(\S+)`)
	distrolessRef = regexp.MustCompile(`(gcr\.io/distroless/base-debian)(\d+)`)

	alpineTag = regexp.MustCompile(`^(\d+\.\d+)$`)
	nodeTag   = regexp.MustCompile(`^(\d+)-alpine$`)
)

func imageBumps() []imageBump {
	return []imageBump{
		{
			Name:   "alpine",
			Prefix: "Dockerfile",
			Files:  []string{"Dockerfile.derper", "Dockerfile.tailscale-HEAD"},
			Ref:    alpineRef,
			Resolve: func(ctx context.Context, _ string) (string, error) {
				return highestTag(ctx, "alpine", "3.", alpineTag, nil)
			},
			Verify: func(ctx context.Context, want string) error {
				return tagExists(ctx, "alpine", want)
			},
		},
		{
			Name:   "debian",
			Prefix: "Dockerfile",
			Files:  []string{"Dockerfile.integration", "Dockerfile.integration-ci", "Dockerfile.tailscale-rs"},
			Ref:    debianRef,
			Resolve: func(ctx context.Context, _ string) (string, error) {
				code, err := debianStableCodename(ctx)
				if err != nil {
					return "", err
				}

				return code + "-slim", nil
			},
			Verify: func(ctx context.Context, want string) error {
				return tagExists(ctx, "debian", want)
			},
		},
		{
			Name:   "node",
			Prefix: "Dockerfile",
			Files:  []string{"Dockerfile.wasmclient"},
			Ref:    nodeRef,
			Resolve: func(ctx context.Context, _ string) (string, error) {
				// Node ships even majors as long-term support; an odd major is
				// a short-lived Current release, not something to pin to.
				major, err := highestTag(ctx, "node", "-alpine", nodeTag, isEvenMajor)
				if err != nil {
					return "", err
				}

				return major + "-alpine", nil
			},
			Verify: func(ctx context.Context, want string) error {
				return tagExists(ctx, "node", want)
			},
		},
		{
			Name:   "rust",
			Prefix: "Dockerfile",
			Files:  []string{"Dockerfile.tailscale-rs"},
			Ref:    rustRef,
			// The Rust tag carries the Debian codename it is built on, so it
			// has to follow whatever the debian area settles on.
			Resolve: func(ctx context.Context, _ string) (string, error) {
				code, err := debianStableCodename(ctx)
				if err != nil {
					return "", err
				}

				pattern := regexp.MustCompile(`^(\d+\.\d+)-` + code + `$`)

				version, err := highestTag(ctx, "rust", "-"+code, pattern, nil)
				if err != nil {
					return "", err
				}

				return version + "-" + code, nil
			},
			Verify: func(ctx context.Context, want string) error {
				return tagExists(ctx, "rust", want)
			},
		},
		{
			Name:    "distroless",
			Prefix:  "ko",
			Files:   []string{".goreleaser.yml", ".github/workflows/container-main.yml"},
			Ref:     distrolessRef,
			Resolve: resolveDistroless,
			Verify: func(ctx context.Context, want string) error {
				if !gcrRepositoryPublished(ctx, "distroless/base-debian"+want) {
					return fmt.Errorf("%w: distroless/base-debian%s", errTagMissing, want)
				}

				return nil
			},
		},
	}
}

func isEvenMajor(v string) bool {
	n, err := strconv.Atoi(v)

	return err == nil && n%2 == 0
}

// resolveDistroless follows Debian stable, not whatever repository names
// happen to resolve. Distroless carries the release in the repository name and
// creates the next one well before it has anything in it, so "newer name
// exists" is not the same question as "newer base is usable".
func resolveDistroless(ctx context.Context, have string) (string, error) {
	stable, err := debianStableMajor(ctx)
	if err != nil {
		return "", err
	}

	// Distroless can lag a Debian release; staying put is the right answer
	// until it catches up.
	if !gcrRepositoryPublished(ctx, "distroless/base-debian"+stable) {
		return have, nil
	}

	return stable, nil
}

// currentImageRef reads the pinned value out of the first file that has one.
func currentImageRef(r *repo, def imageBump) (string, error) {
	for _, file := range def.Files {
		content, err := r.readFile(file)
		if err != nil {
			return "", err
		}

		m := def.Ref.FindStringSubmatch(content)
		if m != nil {
			return m[2], nil
		}
	}

	return "", fmt.Errorf("%w: %s in %s", errNoMatchingTag, def.Name, strings.Join(def.Files, ", "))
}

func applyImage(def imageBump) func(context.Context, *repo) (change, error) {
	return func(ctx context.Context, r *repo) (change, error) {
		have, err := currentImageRef(r, def)
		if err != nil {
			return change{}, err
		}

		want, err := def.Resolve(ctx, have)
		if err != nil {
			return change{}, err
		}

		if want == have {
			return change{Empty: true}, nil
		}

		err = def.Verify(ctx, want)
		if err != nil {
			return change{}, err
		}

		var touched []string

		for _, file := range def.Files {
			content, err := r.readFile(file)
			if err != nil {
				return change{}, err
			}

			updated := def.Ref.ReplaceAllString(content, "${1}"+want)
			if updated == content {
				continue
			}

			err = r.writeFile(file, updated)
			if err != nil {
				return change{}, err
			}

			touched = append(touched, file)
		}

		if len(touched) == 0 {
			return change{Empty: true}, nil
		}

		return change{
			Summary: fmt.Sprintf("%s %s to %s", def.Name, have, want),
			Detail:  []string{fmt.Sprintf("%s %s -> %s in %s", def.Name, have, want, strings.Join(touched, ", "))},
		}, nil
	}
}

// gateImage re-reads the written value and re-checks it is published, so a bad
// rewrite is caught before it is committed.
func gateImage(def imageBump) func(context.Context, *repo) error {
	return func(ctx context.Context, r *repo) error {
		have, err := currentImageRef(r, def)
		if err != nil {
			return err
		}

		return def.Verify(ctx, have)
	}
}

func imageAreas() []area {
	defs := imageBumps()
	areas := make([]area, 0, len(defs))

	for _, def := range defs {
		areas = append(areas, area{
			Name:    "image:" + def.Name,
			Apply:   applyImage(def),
			Gate:    gateImage(def),
			Message: func(c change) string { return def.Prefix + ": bump " + c.Summary },
		})
	}

	return areas
}
