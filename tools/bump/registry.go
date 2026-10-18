package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/mod/semver"
)

const (
	dockerHubTagsURL = "https://hub.docker.com/v2/repositories/library/%s/tags?page_size=100&name=%s"
	dockerHubTagURL2 = "https://hub.docker.com/v2/repositories/library/%s/tags/%s"
	gcrTagsURL       = "https://gcr.io/v2/%s/tags/list"
)

var errNoMatchingTag = errors.New("no matching tag published")

type hubTags struct {
	Results []struct {
		Name   string `json:"name"`
		Digest string `json:"digest"`
	} `json:"results"`
}

// dockerHubTags lists tags of an official image whose name contains filter.
// One page is enough: the listing is ordered newest first, and every reference
// this tool tracks is a rolling tag that is rebuilt constantly.
func dockerHubTags(ctx context.Context, image, filter string) ([]string, error) {
	body, err := fetch(ctx, fmt.Sprintf(dockerHubTagsURL, image, filter))
	if err != nil {
		return nil, err
	}

	var tags hubTags
	if err := json.Unmarshal(body, &tags); err != nil { //nolint:noinlineerr
		return nil, fmt.Errorf("decoding tags of %s: %w", image, err)
	}

	names := make([]string, 0, len(tags.Results))
	for _, t := range tags.Results {
		names = append(names, t.Name)
	}

	return names, nil
}

// highestTag returns the newest version captured by pattern across an image's
// published tags. pattern must have exactly one capture group.
func highestTag(ctx context.Context, image, filter string, pattern *regexp.Regexp, keep func(string) bool) (string, error) {
	names, err := dockerHubTags(ctx, image, filter)
	if err != nil {
		return "", err
	}

	best := ""

	for _, name := range names {
		m := pattern.FindStringSubmatch(name)
		if m == nil {
			continue
		}

		if keep != nil && !keep(m[1]) {
			continue
		}

		if best == "" || semver.Compare("v"+m[1], "v"+best) > 0 {
			best = m[1]
		}
	}

	if best == "" {
		return "", fmt.Errorf("%w: %s matching %s", errNoMatchingTag, image, pattern)
	}

	return best, nil
}

// dockerHubDigest is the manifest a tag points at. Two names sharing a digest
// are the same image, which is how a codename is matched to the release it
// currently stands for.
func dockerHubDigest(ctx context.Context, image, tag string) (string, error) {
	body, err := fetch(ctx, fmt.Sprintf(dockerHubTagURL2, image, tag))
	if err != nil {
		return "", err
	}

	var info struct {
		Digest string `json:"digest"`
	}

	if err := json.Unmarshal(body, &info); err != nil { //nolint:noinlineerr
		return "", fmt.Errorf("decoding %s:%s: %w", image, tag, err)
	}

	if info.Digest == "" {
		return "", fmt.Errorf("%w: %s:%s has no digest", errNoMatchingTag, image, tag)
	}

	return info.Digest, nil
}

var debianSlimMajor = regexp.MustCompile(`^(\d+)-slim$`)

// debianStableMajor is the newest released Debian version.
//
// The numeric tags are the signal: Debian publishes 11-slim, 12-slim and
// 13-slim, but nothing numeric for the release under development. Codename tags
// cannot be used for this, because forky-slim exists today and is testing.
func debianStableMajor(ctx context.Context) (string, error) {
	return highestTag(ctx, "debian", "-slim", debianSlimMajor, nil)
}

// debianStableCodename is the codename of the newest released Debian, found by
// matching the numeric tag to the codename tag that carries the same image.
//
// stable-slim is not usable here: Docker Hub builds it separately, so it has a
// different digest from the release it aliases.
func debianStableCodename(ctx context.Context) (string, error) {
	major, err := debianStableMajor(ctx)
	if err != nil {
		return "", err
	}

	want, err := dockerHubDigest(ctx, "debian", major+"-slim")
	if err != nil {
		return "", err
	}

	body, err := fetch(ctx, fmt.Sprintf(dockerHubTagsURL, "debian", "-slim"))
	if err != nil {
		return "", err
	}

	var tags hubTags
	if err := json.Unmarshal(body, &tags); err != nil { //nolint:noinlineerr
		return "", fmt.Errorf("decoding debian tags: %w", err)
	}

	codename := regexp.MustCompile(`^([a-z]+)-slim$`)

	for _, t := range tags.Results {
		m := codename.FindStringSubmatch(t.Name)
		// stable, testing and friends are moving aliases, not codenames.
		if m == nil || t.Digest != want || isDebianAlias(m[1]) {
			continue
		}

		return m[1], nil
	}

	return "", fmt.Errorf("%w: no debian codename matches %s-slim", errNoMatchingTag, major)
}

func isDebianAlias(name string) bool {
	switch name {
	case "stable", "testing", "unstable", "oldstable", "oldoldstable", "sid", "experimental":
		return true
	default:
		return false
	}
}

// gcrRepositoryPublished reports whether a Google Container Registry repository
// has any images. Existence alone is not enough: gcr answers 200 with an empty
// tag list for a repository that was never pushed, so base-debian99 looks just
// as real as base-debian13.
func gcrRepositoryPublished(ctx context.Context, repo string) bool {
	body, err := fetch(ctx, fmt.Sprintf(gcrTagsURL, repo))
	if err != nil {
		return false
	}

	var listing struct {
		Tags []string `json:"tags"`
	}

	if err := json.Unmarshal(body, &listing); err != nil { //nolint:noinlineerr
		return false
	}

	return len(listing.Tags) > 0
}
