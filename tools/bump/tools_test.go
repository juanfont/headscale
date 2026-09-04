package main

import (
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
