package main

import (
	"slices"
	"testing"
)

// The bot's own commits are rebuilt every run; only someone else's are carried.
func TestNotAuthoredBy(t *testing.T) {
	const bot = "41898282+github-actions[bot]@users.noreply.github.com"

	log := bot + "\x00flake.lock: update nixpkgs\n" +
		"dev@example.com\x00noise: fix deprecation\n" +
		bot + "\x00go.mod: update dependencies\n" +
		"dev@example.com\x00capver: regenerate\n"

	got := notAuthoredBy(log, bot)

	want := []string{"noise: fix deprecation", "capver: regenerate"}
	if !slices.Equal(got, want) {
		t.Errorf("notAuthoredBy = %q, want %q", got, want)
	}

	if got := notAuthoredBy("", bot); len(got) != 0 {
		t.Errorf("empty log carried %q", got)
	}
}
