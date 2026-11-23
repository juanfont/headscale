package cmdline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline/argtest"
	"pgregory.net/rapid"
)

var errTestCallback = errors.New("command failed")

func TestCommandErrorIdentity(t *testing.T) {
	sentinel := errTestCallback

	var result error

	calls := 0

	tree, err := New(Group{Name: "prog", Commands: []Node{
		Command[struct{}]{Name: "run", Run: func(context.Context, struct{}) error {
			calls++
			return result
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"sentinel", sentinel},
		{"same-text-new-error", errors.New(sentinel.Error())}, //nolint:err113 // Distinct errors can have equal text.
		{"wrapped", fmt.Errorf("inner: %w", sentinel)},
		{"joined", errors.Join(sentinel, io.EOF)},
		{"typed-nil", (*fs.PathError)(nil)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result = tt.err
			before := calls

			line, err := tree.Parse([]string{"run"})
			if err != nil {
				t.Fatal(err)
			}

			first, second := line.Run(t.Context()), line.Run(t.Context())
			// Even a wrapper that preserves errors.Is changes the command's return value.
			if first != result || second != ErrRan || calls != before+1 { //nolint:err113,errorlint // Run preserves exact error identity.
				t.Fatalf("first=%T %v, want exact %T %v; second=%v calls=%d", first, first, result, result, second, calls-before)
			}
		})
	}
}

type lookupLabel string

type lookupPair struct {
	Target lookupLabel           `arg:"target"`
	Peers  Repeat[[]lookupLabel] `flag:"peers" short:"p"`
}

var errLookup = errors.New("unknown label")

func TestRapidLateFields(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		item := rapid.SampledFrom([]string{"alice", "bob", "unknown"})
		target := item.Draw(rt, "target")
		lists := rapid.SliceOfN(rapid.SliceOfN(item, 1, 4), 0, 5).Draw(rt, "lists")
		pos := rapid.IntRange(0, len(lists)).Draw(rt, "target position")
		argv := []string{rapid.SampledFrom([]string{"show", "get"}).Draw(rt, "command")}

		type lookup struct {
			item, word, value, flag, arg string
			at                           int
		}

		var wantCalls []lookup

		for i := 0; i <= len(lists); i++ {
			if pos == i {
				wantCalls = append(wantCalls, lookup{target, target, target, "", "target", len(argv)})
				argv = append(argv, target)
			}

			if i == len(lists) {
				break
			}

			separator := rapid.SampledFrom([]string{",", ", "}).Draw(rt, "separator")
			raw := strings.Join(lists[i], separator)

			word := rapid.SampledFrom([]string{"-p", "--peers"}).Draw(rt, "flag")
			for _, v := range lists[i] {
				wantCalls = append(wantCalls, lookup{v, word, raw, "peers", "", len(argv)})
			}

			argv = append(argv, argtest.Option(rt, word, raw)...)
		}

		var (
			looked []string
			input  lookupPair
		)

		calls := 0
		ctx := rt.Context()

		tree, err := New(Group{Name: "app", Commands: []Node{Command[lookupPair]{Name: "show", Aliases: []string{"get"}, Run: func(got context.Context, in lookupPair) error {
			if got != ctx {
				rt.Fatal("callback context changed")
			}

			calls++
			input = in

			return nil
		}}}}, LateReader(func(got context.Context, s string) (lookupLabel, error) {
			if got != ctx {
				rt.Fatal("lookup context changed")
			}

			looked = append(looked, s)
			if s == "unknown" {
				return "", errLookup
			}

			return lookupLabel(s), nil
		}))
		if err != nil {
			rt.Fatal(err)
		}

		line, err := tree.Parse(argv)

		pre, ok := Get[lookupPair](line)
		if err != nil || !ok || pre.Target != "" || pre.Peers != nil || len(looked) != 0 || calls != 0 {
			rt.Fatalf("%q: pre-run input=%+v error=%v reads=%q calls=%d", argv, pre, err, looked, calls)
		}

		first := line.Run(ctx)

		second := line.Run(ctx)
		if second != ErrRan { //nolint:err113,errorlint // A second invocation returns this sentinel.
			rt.Fatalf("%q: second Run=%v", argv, second)
		}

		var trace []string
		for _, step := range wantCalls {
			trace = append(trace, step.item)
			if step.item != "unknown" {
				continue
			}

			e, ok := errors.AsType[*UsageError](first)

			want := &UsageError{Kind: Unresolved, Path: []string{"show"}, At: step.at, Word: step.word, Value: step.value, Flag: step.flag, Arg: step.arg, Err: errLookup}
			if !ok || !reflect.DeepEqual(e, want) || e.Err != errLookup || !slices.Equal(trace, looked) || calls != 0 { //nolint:err113,errorlint // A reader's exact error is part of the diagnostic.
				rt.Fatalf("%q: error=%#v trace=%q calls=%d; want %+v trace=%q", argv, e, looked, calls, step, trace)
			}

			return
		}

		if first != nil || calls != 1 || !slices.Equal(looked, trace) || string(input.Target) != target || len(input.Peers) != len(lists) {
			rt.Fatalf("%q: error=%v calls=%d trace=%q input=%+v", argv, first, calls, looked, input)
		}

		for i, values := range input.Peers {
			if !slices.EqualFunc(values, lists[i], func(a lookupLabel, b string) bool { return string(a) == b }) {
				rt.Fatalf("%q: occurrence %d = %q want %q", argv, i, values, lists[i])
			}
		}
	})
}
