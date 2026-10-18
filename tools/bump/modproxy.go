package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// proxyBase is the module mirror. It is deliberately the same source the go
// command already trusts: immutable per version, so the go.mod read back here
// is the one that will actually be resolved, not whatever a branch tip happens
// to hold at fetch time.
// It is a var only so the tests can point it at a fake proxy; nothing changes
// it at runtime.
var proxyBase = "https://proxy.golang.org"

const proxyTimeout = 30 * time.Second

// errNoLockstepSource means the partner version could not be established. The
// caller must move neither half of the pair: a libc without its sqlite is the
// exact breakage the lockstep rule exists to prevent.
var errNoLockstepSource = errors.New("lockstep source unavailable")

// errStrayTag means @latest sorts above the pinned version but was committed
// no later than it.
var errStrayTag = errors.New("newest tag is older than the pinned version")

// errModuleMoved means the newest version under this path declares a different
// module path.
var errModuleMoved = errors.New("module has moved to a new path")

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

// versionInfo is the proxy's @latest and @v/<version>.info response.
type versionInfo struct {
	Version string
	Time    time.Time
}

// fetchInfo reads one of the proxy's info endpoints. ref is "@latest" or
// "@v/<escaped version>.info".
func fetchInfo(ctx context.Context, path, ref string) (versionInfo, error) {
	esc, err := module.EscapePath(path)
	if err != nil {
		return versionInfo{}, fmt.Errorf("escaping %s: %w", path, err)
	}

	body, err := fetch(ctx, proxyBase+"/"+esc+"/"+ref)
	if err != nil {
		return versionInfo{}, err
	}

	var info versionInfo
	if err := json.Unmarshal(body, &info); err != nil { //nolint:noinlineerr
		return versionInfo{}, fmt.Errorf("decoding %s for %s: %w", ref, path, err)
	}

	return info, nil
}

// versionTime is when version of path was committed. Pseudo-versions carry it
// in their own name, so only tagged versions cost a round trip.
func versionTime(ctx context.Context, path, version string) (time.Time, error) {
	if module.IsPseudoVersion(version) {
		return module.PseudoVersionTime(version)
	}

	esc, err := module.EscapeVersion(version)
	if err != nil {
		return time.Time{}, fmt.Errorf("escaping version %s: %w", version, err)
	}

	info, err := fetchInfo(ctx, path, "@v/"+esc+".info")

	return info.Time, err
}

// latestVersion resolves a module's newest usable version through the proxy.
// current is the version already in use, or "" when the module is not required
// yet. When nothing newer exists it returns current unchanged.
//
// Two things the proxy will hand back that the go command does not protect
// against, both of which have to be refused rather than committed:
//
//   - A stray tag. Forks carry tags that sort above the branch the real work
//     happens on, and @latest reports them. Semver says newer; the commit date
//     says otherwise, and the commit date is the one telling the truth.
//   - A module that has moved. Releases keep being tagged under the new path,
//     the proxy still serves them under the old one, and go get then refuses
//     the result with an error that does not say why.
func latestVersion(ctx context.Context, path, current string) (string, error) {
	info, err := fetchInfo(ctx, path, "@latest")
	if err != nil {
		return "", err
	}

	if info.Version == "" {
		return "", fmt.Errorf("%w: empty @latest for %s", errNoLockstepSource, path)
	}

	if !semver.IsValid(info.Version) {
		return "", fmt.Errorf("%w: proxy returned %q for %s", errStrayTag, info.Version, path)
	}

	if current != "" && semver.Compare(info.Version, current) <= 0 {
		return current, nil
	}

	f, err := modFileOf(ctx, path, info.Version)
	if err != nil {
		return "", err
	}

	if f.Module != nil && f.Module.Mod.Path != path {
		return "", fmt.Errorf("%w: %s@%s declares %s; change the import path by hand",
			errModuleMoved, path, info.Version, f.Module.Mod.Path)
	}

	if current == "" {
		return info.Version, nil
	}

	curTime, err := versionTime(ctx, path, current)
	if err != nil {
		return "", err
	}

	if !info.Time.After(curTime) {
		return "", fmt.Errorf("%w: %s@%s is dated %s, the pinned %s is dated %s",
			errStrayTag, path, info.Version, info.Time.Format(time.DateOnly),
			current, curTime.Format(time.DateOnly))
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

// describeChange renders one module's move, as a compare link when the path
// names a repository a link can be built for. Reviewing fifty version numbers
// means opening fifty tabs otherwise.
func describeChange(path, from, to string) string {
	link := compareLink(path, from, to)
	if link == "" {
		return fmt.Sprintf("%s %s -> %s", path, from, to)
	}

	return fmt.Sprintf("%s %s -> [%s](%s)", path, from, to, link)
}

// compareLink is the GitHub compare URL between two versions of a module, or
// "" when one cannot be built. The repository is the first three path
// segments; anything past that is a subdirectory with its own tag prefix.
func compareLink(path, from, to string) string {
	if !strings.HasPrefix(path, "github.com/") {
		return ""
	}

	trimmed, _, ok := module.SplitPathVersion(path)
	if !ok {
		return ""
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) < 3 {
		return ""
	}

	sub := strings.Join(parts[3:], "/")

	return fmt.Sprintf("https://%s/compare/%s...%s",
		strings.Join(parts[:3], "/"), gitRef(sub, from), gitRef(sub, to))
}

// gitRef is the tag or commit one module version points at. A pseudo-version
// names a commit; a tagged version inside a subdirectory carries that
// subdirectory as a prefix.
func gitRef(sub, version string) string {
	if module.IsPseudoVersion(version) {
		if rev, err := module.PseudoVersionRev(version); err == nil { //nolint:noinlineerr
			return rev
		}
	}

	if sub != "" {
		return sub + "/" + version
	}

	return version
}
