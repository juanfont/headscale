package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

// fakeProxy serves the three module proxy endpoints the resolver reads. The
// interesting cases here are ones the real proxy only produces occasionally
// and never on demand, so they cannot be reached from a live lookup.
type fakeProxy struct {
	latest map[string]versionInfo // module path -> @latest
	info   map[string]versionInfo // "path@version" -> .info
	gomod  map[string]string      // "path@version" -> go.mod contents
}

// serve points proxyBase at the fake for the rest of the test.
func (p fakeProxy) serve(t *testing.T) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		if mod, ok := strings.CutSuffix(path, "/@latest"); ok {
			writeInfo(w, p.latest, mod)

			return
		}

		mod, rest, ok := strings.Cut(path, "/@v/")
		if !ok {
			http.NotFound(w, r)

			return
		}

		if version, ok := strings.CutSuffix(rest, ".info"); ok {
			writeInfo(w, p.info, mod+"@"+version)

			return
		}

		version, found := strings.CutSuffix(rest, ".mod")
		if !found {
			http.NotFound(w, r)

			return
		}

		body, ok := p.gomod[mod+"@"+version]
		if !ok {
			http.NotFound(w, r)

			return
		}

		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	previous := proxyBase
	proxyBase = srv.URL

	t.Cleanup(func() { proxyBase = previous })
}

func writeInfo(w http.ResponseWriter, from map[string]versionInfo, key string) {
	info, ok := from[key]
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)

		return
	}

	body, err := json.Marshal(info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	_, _ = w.Write(body)
}

func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}

	return t
}

func modOf(path string) string {
	return "module " + path + "\n\ngo 1.24\n"
}

func TestLatestVersion(t *testing.T) {
	const path = "github.com/example/thing"

	tests := []struct {
		name    string
		proxy   fakeProxy
		current string
		want    string
		wantErr error
	}{
		{
			name: "upgrade",
			proxy: fakeProxy{
				latest: map[string]versionInfo{path: {Version: "v1.3.0", Time: day("2026-09-01")}},
				info:   map[string]versionInfo{path + "@v1.2.0": {Version: "v1.2.0", Time: day("2026-06-01")}},
				gomod:  map[string]string{path + "@v1.3.0": modOf(path)},
			},
			current: "v1.2.0",
			want:    "v1.3.0",
		},
		{
			name: "nothing newer",
			proxy: fakeProxy{
				latest: map[string]versionInfo{path: {Version: "v1.2.0", Time: day("2026-06-01")}},
			},
			current: "v1.2.0",
			want:    "v1.2.0",
		},
		{
			// A fork carrying a tag that sorts above the branch real work
			// happens on. Semver says newer, the commit date says otherwise.
			name: "stray tag dated before the pinned version",
			proxy: fakeProxy{
				latest: map[string]versionInfo{path: {Version: "v0.91.0", Time: day("2024-02-01")}},
				info: map[string]versionInfo{
					path + "@v0.90.0": {Version: "v0.90.0", Time: day("2026-06-01")},
				},
				gomod: map[string]string{path + "@v0.91.0": modOf(path)},
			},
			current: "v0.90.0",
			wantErr: errStrayTag,
		},
		{
			// The pinned version is a pseudo-version, so its date comes out of
			// the version string itself with no round trip.
			name: "stray tag against a pseudo-version",
			proxy: fakeProxy{
				latest: map[string]versionInfo{path: {Version: "v1.9.0", Time: day("2024-01-01")}},
				gomod:  map[string]string{path + "@v1.9.0": modOf(path)},
			},
			current: "v1.8.1-0.20260601120000-abcdef123456",
			wantErr: errStrayTag,
		},
		{
			name: "module moved to a new path",
			proxy: fakeProxy{
				latest: map[string]versionInfo{path: {Version: "v2.0.0", Time: day("2026-09-01")}},
				gomod:  map[string]string{path + "@v2.0.0": modOf("example.org/thing")},
			},
			current: "v1.2.0",
			wantErr: errModuleMoved,
		},
		{
			name: "not previously required",
			proxy: fakeProxy{
				latest: map[string]versionInfo{path: {Version: "v1.0.0", Time: day("2026-09-01")}},
				gomod:  map[string]string{path + "@v1.0.0": modOf(path)},
			},
			current: "",
			want:    "v1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.proxy.serve(t)

			got, err := latestVersion(context.Background(), path, tt.current)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("latestVersion() error = %v, want %v", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("latestVersion() error = %v", err)
			}

			if got != tt.want {
				t.Errorf("latestVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompareLink(t *testing.T) {
	tests := []struct {
		name string
		path string
		from string
		to   string
		want string
	}{
		{
			name: "plain repository",
			path: "github.com/spf13/cobra",
			from: "v1.8.0",
			to:   "v1.9.0",
			want: "https://github.com/spf13/cobra/compare/v1.8.0...v1.9.0",
		},
		{
			name: "major version suffix is not part of the repository",
			path: "github.com/oapi-codegen/oapi-codegen/v2",
			from: "v2.7.1",
			to:   "v2.8.0",
			want: "https://github.com/oapi-codegen/oapi-codegen/compare/v2.7.1...v2.8.0",
		},
		{
			name: "subdirectory tags carry the subdirectory",
			path: "github.com/example/repo/sub/mod",
			from: "v1.0.0",
			to:   "v1.1.0",
			want: "https://github.com/example/repo/compare/sub/mod/v1.0.0...sub/mod/v1.1.0",
		},
		{
			name: "pseudo-versions name commits",
			path: "github.com/example/repo",
			from: "v0.0.0-20260101000000-aaaaaaaaaaaa",
			to:   "v0.0.0-20260201000000-bbbbbbbbbbbb",
			want: "https://github.com/example/repo/compare/aaaaaaaaaaaa...bbbbbbbbbbbb",
		},
		{
			name: "non-github paths get no link",
			path: "modernc.org/sqlite",
			from: "v1.52.0",
			to:   "v1.58.0",
			want: "",
		},
		{
			name: "a bare host is not a repository",
			path: "github.com/example",
			from: "v1.0.0",
			to:   "v1.1.0",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareLink(tt.path, tt.from, tt.to); got != tt.want {
				t.Errorf("compareLink() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDescribeChange(t *testing.T) {
	got := describeChange("github.com/spf13/cobra", "v1.8.0", "v1.9.0")
	want := "github.com/spf13/cobra v1.8.0 -> " +
		"[v1.9.0](https://github.com/spf13/cobra/compare/v1.8.0...v1.9.0)"

	if got != want {
		t.Errorf("describeChange() = %q, want %q", got, want)
	}

	plain := describeChange("modernc.org/sqlite", "v1.52.0", "v1.58.0")
	if plain != "modernc.org/sqlite v1.52.0 -> v1.58.0" {
		t.Errorf("describeChange() without a link = %q", plain)
	}
}

func TestCheckDowngrades(t *testing.T) {
	parse := func(t *testing.T, requires string) *modfile.File {
		t.Helper()

		f, err := modfile.Parse("go.mod", []byte("module example.com/app\n\ngo 1.24\n\nrequire (\n"+requires+")\n"), nil)
		if err != nil {
			t.Fatal(err)
		}

		return f
	}

	tests := []struct {
		name    string
		before  string
		after   string
		wantErr bool
	}{
		{
			name:   "upgrade",
			before: "\tgithub.com/a/b v1.0.0\n",
			after:  "\tgithub.com/a/b v1.1.0\n",
		},
		{
			name:    "downgrade",
			before:  "\tgithub.com/a/b v1.2.0\n",
			after:   "\tgithub.com/a/b v1.1.0\n",
			wantErr: true,
		},
		{
			// repin lowers these on purpose, back to what their owner requires.
			name:   "lockstep partners may move backwards",
			before: "\t" + modGvisor + " v0.0.0-20260301000000-aaaaaaaaaaaa\n\t" + modLibc + " v1.76.0\n",
			after:  "\t" + modGvisor + " v0.0.0-20260101000000-bbbbbbbbbbbb\n\t" + modLibc + " v1.75.6\n",
		},
		{
			name:   "a new requirement is not a downgrade",
			before: "\tgithub.com/a/b v1.0.0\n",
			after:  "\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v0.1.0\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDowngrades(parse(t, tt.before), parse(t, tt.after))

			if tt.wantErr {
				if !errors.Is(err, errDowngrade) {
					t.Fatalf("checkDowngrades() error = %v, want %v", err, errDowngrade)
				}

				return
			}

			if err != nil {
				t.Errorf("checkDowngrades() error = %v", err)
			}
		})
	}
}
