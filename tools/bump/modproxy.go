package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// proxyBase is the module mirror. It is deliberately the same source the go
// command already trusts: immutable per version, so the go.mod read back here
// is the one that will actually be resolved, not whatever a branch tip happens
// to hold at fetch time.
const proxyBase = "https://proxy.golang.org"

const proxyTimeout = 30 * time.Second

// errNoLockstepSource means the partner version could not be established. The
// caller must move neither half of the pair: a libc without its sqlite is the
// exact breakage the lockstep rule exists to prevent.
var errNoLockstepSource = errors.New("lockstep source unavailable")

// fetch performs a GET and returns the body, or an error naming the status.
func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}

	client := &http.Client{Timeout: proxyTimeout}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %w: %s", url, errHTTPStatus, resp.Status)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}

	return b, nil
}

var errHTTPStatus = errors.New("unexpected status")

// latestVersion resolves a module's newest version through the proxy.
func latestVersion(ctx context.Context, path string) (string, error) {
	esc, err := module.EscapePath(path)
	if err != nil {
		return "", fmt.Errorf("escaping %s: %w", path, err)
	}

	body, err := fetch(ctx, proxyBase+"/"+esc+"/@latest")
	if err != nil {
		return "", err
	}

	var info struct {
		Version string `json:"Version"`
	}

	if err := json.Unmarshal(body, &info); err != nil { //nolint:noinlineerr
		return "", fmt.Errorf("decoding @latest for %s: %w", path, err)
	}

	if info.Version == "" {
		return "", fmt.Errorf("%w: empty @latest for %s", errNoLockstepSource, path)
	}

	return info.Version, nil
}

// modFileOf fetches and parses the go.mod of the exact path@version.
func modFileOf(ctx context.Context, path, version string) (*modfile.File, error) {
	escPath, err := module.EscapePath(path)
	if err != nil {
		return nil, fmt.Errorf("escaping %s: %w", path, err)
	}

	escVer, err := module.EscapeVersion(version)
	if err != nil {
		return nil, fmt.Errorf("escaping version %s: %w", version, err)
	}

	body, err := fetch(ctx, proxyBase+"/"+escPath+"/@v/"+escVer+".mod")
	if err != nil {
		return nil, err
	}

	f, err := modfile.Parse(path+"@"+version+"/go.mod", body, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod of %s@%s: %w", path, version, err)
	}

	return f, nil
}

// requiredVersion reports the version of dep that f requires.
func requiredVersion(f *modfile.File, dep string) (string, bool) {
	for _, req := range f.Require {
		if req.Mod.Path == dep {
			return req.Mod.Version, true
		}
	}

	return "", false
}

// partnerVersion resolves the version of dep that owner@ownerVersion pins. It
// is the whole of the lockstep rule: the partner is never guessed, only read
// off the owner's own go.mod.
func partnerVersion(ctx context.Context, owner, ownerVersion, dep string) (string, error) {
	f, err := modFileOf(ctx, owner, ownerVersion)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoLockstepSource, err)
	}

	v, ok := requiredVersion(f, dep)
	if !ok {
		return "", fmt.Errorf("%w: %s@%s does not require %s", errNoLockstepSource, owner, ownerVersion, dep)
	}

	return v, nil
}
