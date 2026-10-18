package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
)

const githubAPI = "https://api.github.com"

var errNoRelease = errors.New("no published release")

// githubToken is resolved once. Unauthenticated GitHub allows sixty requests an
// hour, which the action-pin sweep alone would exhaust, so a token is worth
// looking for even outside CI.
var githubToken = sync.OnceValue(func() string {
	for _, env := range []string{"GH_TOKEN", "GITHUB_TOKEN"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}

	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(out))
})

// githubJSON performs an authenticated GET against the GitHub REST API.
func githubJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubAPI+path, nil)
	if err != nil {
		return fmt.Errorf("building request for %s: %w", path, err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")

	if token := githubToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: proxyTimeout}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %w: %s", path, errHTTPStatus, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	if err := json.Unmarshal(body, out); err != nil { //nolint:noinlineerr
		return fmt.Errorf("decoding %s: %w", path, err)
	}

	return nil
}

// latestRelease is the tag of a repository's newest published release.
func latestRelease(ctx context.Context, owner, name string) (string, error) {
	var release struct {
		TagName string `json:"tag_name"`
	}

	err := githubJSON(ctx, fmt.Sprintf("/repos/%s/%s/releases/latest", owner, name), &release)
	if err != nil {
		return "", err
	}

	if release.TagName == "" {
		return "", fmt.Errorf("%w for %s/%s", errNoRelease, owner, name)
	}

	return release.TagName, nil
}

// commitOfRef resolves a tag or branch to the commit it points at, following
// annotated tags the way an action pin must.
func commitOfRef(ctx context.Context, owner, name, ref string) (string, error) {
	var commit struct {
		SHA string `json:"sha"`
	}

	err := githubJSON(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, name, ref), &commit)
	if err != nil {
		return "", err
	}

	if commit.SHA == "" {
		return "", fmt.Errorf("%w: %s/%s@%s", errNoRelease, owner, name, ref)
	}

	return commit.SHA, nil
}

// currentSlug is the repository the run is acting on. It defaults to whatever
// the job is running in rather than a constant: a hardcoded upstream slug let a
// fork push its branch and then try to open the pull request on someone else's
// repository, which fails at the very last step of a long run.
func currentSlug(ctx context.Context, r *repo, override string) (string, error) {
	if override != "" {
		return override, nil
	}

	if env := os.Getenv("GITHUB_REPOSITORY"); env != "" {
		return env, nil
	}

	out, err := r.run(ctx, "gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}
