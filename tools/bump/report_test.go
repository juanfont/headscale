package main

import (
	"os"
	"strings"
	"testing"
)

func mustRead(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	return b
}

// The marker is the bot's only persistent state. If it does not survive a round
// trip through a pull request body, every run looks like a first run.
func TestMarkerRoundTrip(t *testing.T) {
	results := []result{
		{Area: "flake", State: stateApplied, Commit: "abc"},
		{Area: "gomod", State: stateDropped, Reason: "`go build ./...` failed"},
	}

	want := markerOf(results, "tree-sha", "head-sha")
	body := renderBody(results, want)

	got, ok := parseMarker(body)
	if !ok {
		t.Fatalf("parseMarker found no marker in:\n%s", body)
	}

	if got.Tree != want.Tree || got.Head != want.Head {
		t.Errorf("marker = %+v, want %+v", got, want)
	}

	if got.Areas["gomod"] != string(stateDropped) {
		t.Errorf("gomod state = %q, want %q", got.Areas["gomod"], stateDropped)
	}
}

func TestParseMarkerAbsent(t *testing.T) {
	for _, body := range []string{"", "a human wrote this", markerPrefix + "not json -->"} {
		if _, ok := parseMarker(body); ok {
			t.Errorf("parseMarker(%q) reported a marker", body)
		}
	}
}

func TestChangedAreas(t *testing.T) {
	base := marker{Areas: map[string]string{"flake": "applied", "gomod": "applied"}}

	tests := []struct {
		name string
		now  marker
		want bool
	}{
		{name: "identical", now: marker{Areas: map[string]string{"flake": "applied", "gomod": "applied"}}},
		{name: "state changed", now: marker{Areas: map[string]string{"flake": "applied", "gomod": "dropped"}}, want: true},
		{name: "area added", now: marker{Areas: map[string]string{"flake": "applied", "gomod": "applied", "generate": "applied"}}, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := changedAreas(base, test.now); got != test.want {
				t.Errorf("changedAreas = %v, want %v", got, test.want)
			}
		})
	}
}

// A summary containing a pipe would otherwise split the markdown table.
func TestCellEscapesTableBreakers(t *testing.T) {
	got := cell("a | b\nc")
	if strings.ContainsAny(got, "|\n") && !strings.Contains(got, `\|`) {
		t.Errorf("cell = %q, still breaks the table", got)
	}

	if cell("") != "—" {
		t.Errorf("cell(\"\") = %q, want an em dash", cell(""))
	}
}

func TestSelector(t *testing.T) {
	tests := []struct {
		name string
		only string
		skip string
		area string
		want bool
	}{
		{name: "default runs everything", area: "flake", want: true},
		{name: "explicit selection", only: "flake,gomod", area: "flake", want: true},
		{name: "not selected", only: "flake", area: "gomod"},
		{name: "skip wins over selection", only: "flake", skip: "flake", area: "flake"},
		{name: "whitespace tolerated", only: " flake , gomod ", area: "gomod", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := selector(test.only, test.skip)(test.area); got != test.want {
				t.Errorf("selector(%q, %q)(%q) = %v, want %v", test.only, test.skip, test.area, got, test.want)
			}
		})
	}
}
