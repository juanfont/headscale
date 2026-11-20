package kit

// Corpus additions: the only file that is not a copy of spikes/kit-v2. They
// let spikes/corpus build small trees and run one argv outside the suite.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Build makes a tree from defs, as NewTree does from the kit's own.
func Build(defs ...Def) *Tree { return build(defs) }

// Record is the Run of every corpus spec.
func Record[In any](ctx context.Context, in In) error { return record(ctx, in) }

// RunOnce is the suite's runOnce on a tree of the caller's choosing.
func RunOnce(a Adapter, mk func() *Tree, argv []string) string {
	ctx, rec := withRecorder(context.Background())
	t := mk()
	in := strings.NewReader("y\n")
	var out, errb bytes.Buffer
	err := a.Run(ctx, t, slices.Clone(argv), Stdio{in, &out, &errb})
	var ue *UsageError
	got, wantOut := "", ""
	switch {
	case errors.As(err, &ue):
		o := Outcome{Kind: string(ue.Kind), Path: ue.Path, Word: ue.Word}
		if c, ok := t.find(ue.Path); ok {
			o.Path = c.Path
		}
		if ue.Kind != UnknownCommand && ue.Kind != ArgCount {
			o.Word = t.long(ue.Word)
		}
		got = o.String()
	case err != nil:
		got = "error: " + err.Error()
	case rec.outcome == "":
		got = "nothing: Exec was not called"
	default:
		got, wantOut = rec.outcome, rec.outcome+"\n"
	}
	if rec.calls > 1 {
		got += fmt.Sprintf(" (Exec called %d times)", rec.calls)
	}
	if out.String() != wantOut {
		got += fmt.Sprintf(" (stdout %q)", out.String())
	}
	if errb.Len() > 0 {
		got += fmt.Sprintf(" (stderr %q)", errb.String())
	}
	return got
}

// Want renders an expected outcome the way RunOnce prints one; a flag word
// is normalised to its long name as RunOnce does.
func Want(t *Tree, kind, path string, args []string, flags map[string][]string, word string) string {
	o := Outcome{Kind: kind, Path: strings.Fields(path), Args: args, Flags: flags, Word: word}
	if o.Flags == nil {
		o.Flags = map[string][]string{}
	}
	if kind != string(UnknownCommand) && kind != string(ArgCount) {
		o.Word = t.long(word)
	}
	return o.String()
}

// Calls counts Exec calls under a fresh recorder: Complete must make none.
func CompleteOnce(a Adapter, t *Tree, argv []string) (Completion, int, error) {
	ctx, rec := withRecorder(context.Background())
	c, err := a.Complete(ctx, t, slices.Clone(argv))
	return c, rec.calls, err
}
