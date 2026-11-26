// Package argtest draws argv for parser and command tests.
package argtest

import (
	"iter"
	"slices"

	"pgregory.net/rapid"
)

// Option draws one-token and two-token spellings, preserving value verbatim.
func Option(t *rapid.T, name, value string) []string {
	if rapid.Bool().Draw(t, "inline") {
		return []string{name + "=" + value}
	}

	return []string{name, value}
}

// Interleave inserts each option at a whole-argument boundary, retaining command word order.
func Interleave(t *rapid.T, path []string, options ...[]string) []string {
	return slices.Concat(InterleaveChunks(t, path, options...)...)
}

// InterleaveChunks keeps flag and value words together so an oracle can distinguish them.
func InterleaveChunks(t *rapid.T, path []string, options ...[]string) [][]string {
	units := pathChunks(path)
	for _, option := range options {
		slot := rapid.IntRange(0, len(units)).Draw(t, "option slot")
		units = slices.Insert(units, slot, option)
	}

	return units
}

// Placements enumerates interleavings for a finite set of option chunks.
func Placements(path []string, options ...[]string) iter.Seq[[]string] {
	return func(yield func([]string) bool) {
		var walk func([][]string, int) bool

		walk = func(units [][]string, i int) bool {
			if i == len(options) {
				return yield(slices.Concat(units...))
			}

			for slot := 0; slot <= len(units); slot++ {
				if !walk(slices.Insert(slices.Clone(units), slot, options[i]), i+1) {
					return false
				}
			}

			return true
		}
		walk(pathChunks(path), 0)
	}
}

func pathChunks(path []string) [][]string {
	units := make([][]string, len(path))
	for i, word := range path {
		units[i] = []string{word}
	}

	return units
}
