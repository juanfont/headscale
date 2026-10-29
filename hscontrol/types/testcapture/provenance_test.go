package testcapture_test

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// traceableSince is when tscap and saasprobe began refusing builds that
// name no commit. Older captures predate that, and many say tscap/dev.
var traceableSince = time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

// untraceable lists, by path under hscontrol/, captures taken since
// traceableSince that name no commit. Capture one again with a build of a
// pushed tscap commit, then delete its entry: a listed file that names a
// commit, or is gone, fails.
var untraceable = map[string]bool{
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-accept-agent.hujson":   true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-accept-default.hujson": true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-accept-local.hujson":   true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-accept-remote.hujson":  true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-check-agent.hujson":    true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-check-default.hujson":  true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-check-local.hujson":    true,
	"policy/v2/testdata/ssh_results/forwarding/ssh-forwarding-check-remote.hujson":   true,
}

var (
	// toolCommit is tool_version as a build of a commit stamps it.
	toolCommit = regexp.MustCompile(`^(tscap/|saasprobe )[0-9a-f]{40}$`)

	capturedAtField  = regexp.MustCompile(`^\s*"captured_at":\s*"([^"]+)"`)
	toolVersionField = regexp.MustCompile(`^\s*"tool_version":\s*"([^"]*)"`)
)

// TestCapturesNameTheirCommit keeps every golden capture traceable to the
// code that made it, so it can be made again. It walks every testdata folder,
// so a capture in a new folder is checked too.
func TestCapturesNameTheirCommit(t *testing.T) {
	root := filepath.Join("..", "..")
	listed := map[string]bool{}
	captures := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		rel = filepath.ToSlash(rel)
		if d.IsDir() || filepath.Ext(path) != ".hujson" || !strings.Contains("/"+rel, "/testdata/") {
			return nil
		}

		capturedAt, tool, ok := provenance(t, path)
		if !ok {
			// A policy or scenario file, not a capture.
			return nil
		}

		captures++

		switch {
		case untraceable[rel]:
			listed[rel] = true

			if toolCommit.MatchString(tool) {
				t.Errorf("%s names a commit now; delete its untraceable entry", rel)
			}
		case !capturedAt.Before(traceableSince) && !toolCommit.MatchString(tool):
			t.Errorf("%s: tool_version %q names no commit; capture it again with a build of a pushed tscap commit", rel, tool)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if captures == 0 {
		t.Fatal("no golden captures found")
	}

	for rel := range untraceable {
		if !listed[rel] {
			t.Errorf("%s is listed as untraceable but is no capture; delete its entry", rel)
		}
	}
}

// provenance reads captured_at and tool_version from the top of a file,
// and reports whether it is a capture; the whole corpus is too large to
// decode in a unit test.
func provenance(t *testing.T, path string) (time.Time, string, bool) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var (
		capturedAt    time.Time
		tool          string
		haveAt, haveV bool
	)

	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for (!haveAt || !haveV) && s.Scan() {
		if m := capturedAtField.FindStringSubmatch(s.Text()); m != nil {
			capturedAt, err = time.Parse(time.RFC3339Nano, m[1])
			if err != nil {
				t.Fatalf("%s: captured_at: %v", path, err)
			}

			haveAt = true
		}

		if m := toolVersionField.FindStringSubmatch(s.Text()); m != nil {
			tool, haveV = m[1], true
		}
	}

	if haveAt != haveV {
		t.Fatalf("%s: has only one of captured_at and tool_version (scan: %v)", path, s.Err())
	}

	return capturedAt, tool, haveAt
}
