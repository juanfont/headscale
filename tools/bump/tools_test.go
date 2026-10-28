package main

import (
	"slices"
	"strings"
	"testing"
)

func TestPyRequirementParse(t *testing.T) {
	tests := []struct {
		name         string
		line         string
		pkg, extras  string
		major, minor string
		match        bool
	}{
		{
			name: "plain", line: "mike~=2.1",
			pkg: "mike", major: "2", minor: "1", match: true,
		},
		{
			name: "with extras", line: "mkdocs-materialx[imaging]~=10.1",
			pkg: "mkdocs-materialx", extras: "[imaging]", major: "10", minor: "1", match: true,
		},
		{name: "comment", line: "# a note"},
		{name: "blank", line: ""},
		{name: "exact pin is not ours to move", line: "mike==2.1.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := pyRequirement.FindStringSubmatch(test.line)
			if (m != nil) != test.match {
				t.Fatalf("match = %v, want %v", m != nil, test.match)
			}

			if m == nil {
				return
			}

			for i, want := range map[int]string{1: test.pkg, 2: test.extras, 3: test.major, 4: test.minor} {
				if m[i] != want {
					t.Errorf("group %d = %q, want %q", i, m[i], want)
				}
			}
		})
	}
}

func TestPreCommitRevRewrite(t *testing.T) {
	const config = `repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v6.0.0
    hooks:
      - id: check-json
  - repo: local
    hooks:
      - id: prettier
`

	m := preCommitRev.FindStringSubmatch(config)
	if m == nil {
		t.Fatal("pattern did not match the config")
	}

	if m[2] != "v6.0.0" {
		t.Fatalf("captured %q, want v6.0.0", m[2])
	}

	got := preCommitRev.ReplaceAllString(config, "${1}v6.1.0")
	if want := "rev: v6.1.0"; !strings.Contains(got, want) {
		t.Errorf("rewrite did not contain %q:\n%s", want, got)
	}

	// The local repo block has no rev; nothing else may be touched.
	if !strings.Contains(got, "  - repo: local") {
		t.Error("rewrite disturbed the local hooks block")
	}
}

func TestNewestReleases(t *testing.T) {
	versions := []string{"0.9.0", "0.29.3", "0.10.0", "0.30.0-rc1", "0.29.1", "latest", "0.29.2"}

	got := newestReleases(versions, 3)
	if want := []string{"0.29.1", "0.29.2", "0.29.3"}; !slices.Equal(got, want) {
		t.Errorf("newestReleases = %v, want %v", got, want)
	}

	if got := newestReleases([]string{"0.1.0"}, 3); !slices.Equal(got, []string{"0.1.0"}) {
		t.Errorf("fewer releases than wanted = %v, want all of them", got)
	}
}

// TestProviderPinInTree reads the real pin, so renaming the list in servertest
// fails here rather than in the nightly bump.
func TestProviderPinInTree(t *testing.T) {
	r := &repo{Root: "../.."}

	have, err := currentProviders(r)
	if err != nil {
		t.Fatal(err)
	}

	if len(have) != testedProviders {
		t.Fatalf("servertest tests %d provider releases, want %d: %v", len(have), testedProviders, have)
	}

	content, err := r.readFile(providerPinFile)
	if err != nil {
		t.Fatal(err)
	}

	got := providerPin.ReplaceAllString(content, `${1}"9.9.9"}`)
	if !strings.Contains(got, `var terraformProviderVersions = []string{"9.9.9"}`) {
		t.Error("rewrite did not land on the list")
	}
}
