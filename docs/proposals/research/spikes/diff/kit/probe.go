package kit

// Not part of kit-v2: the differential harness's way in. It reuses the
// suite's runOnce so outcomes are the exact strings the kit grades.

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
)

type rawKey struct{}

// Shared makes every probe use one tree instead of a fresh one: the tree is
// read-only after build, and building it is most of a probe's cost.
var Shared bool

var shared = NewTree()

// Probe runs argv once through a and returns the graded outcome and the raw
// Call the adapter handed to Exec ("" when Exec was not called).
func Probe(a Adapter, argv []string) (outcome, raw string) {
	var c *Call
	outcome = runOnceCtx(a, argv, func(x Call) { c = &x })
	if c != nil {
		raw = RawString(*c)
	}
	return outcome, raw
}

// ProbeCall is Probe with the raw Call itself, for the fuzz properties.
func ProbeCall(a Adapter, argv []string) (string, *Call) {
	var c *Call
	o := runOnceCtx(a, argv, func(x Call) { c = &x })
	return o, c
}

// RawString prints a Call with flag names normalised to long names.
func RawString(c Call) string {
	t := shared
	m := map[string][]string{}
	for k, vs := range c.Flags {
		n := t.long(k)
		m[n] = append(m[n], vs...)
	}
	s := strings.Join(c.Path, " ") + " " + quote(c.Args)
	for _, k := range slices.Sorted(maps.Keys(m)) {
		s += " " + k + "=" + quote(m[k])
	}
	return s
}

// ProbeComplete formats a Tab answer as the suite does: sorted words, +files.
func ProbeComplete(a Adapter, argv []string) string {
	ctx, rec := withRecorder(context.Background())
	comp, err := a.Complete(ctx, tree(), slices.Clone(argv))
	if err != nil {
		return "error: " + err.Error()
	}
	words := make([]string, len(comp.Words))
	for i, w := range comp.Words {
		words[i], _, _ = strings.Cut(w, "\t")
	}
	slices.Sort(words)
	s := fmt.Sprintf("%q", words)
	if comp.Files {
		s += " +files"
	}
	if rec.calls != 0 {
		s += " (a command ran)"
	}
	return s
}

// CompleteWords is ProbeComplete's word list, unformatted.
func CompleteWords(a Adapter, argv []string) ([]string, bool, error) {
	ctx, _ := withRecorder(context.Background())
	comp, err := a.Complete(ctx, NewTree(), slices.Clone(argv))
	words := make([]string, len(comp.Words))
	for i, w := range comp.Words {
		words[i], _, _ = strings.Cut(w, "\t")
	}
	return words, comp.Files, err
}

// Long is the tree's flag-name normaliser ("-o", "--output=x" -> "output").
func (t *Tree) Long(word string) string { return t.long(word) }

// Run is the suite's runOnce: the graded outcome only.
func RunOnce(a Adapter, argv []string) string { return runOnce(a, argv) }

func tree() *Tree {
	if Shared {
		return shared
	}
	return NewTree()
}

// SharedTree is the probe tree (shared or fresh, as Shared says).
func SharedTree() *Tree { return tree() }
