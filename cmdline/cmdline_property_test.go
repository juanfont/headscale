package cmdline

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline/argtest"
	"pgregory.net/rapid"
)

type siteOption struct {
	Site Opt[string] `flag:"site" short:"s"`
}

type areaOption struct {
	Area Opt[string] `flag:"area" short:"a"`
}

// The declaration and token slot determine visibility before any words are rendered.
//
// Bound: each line draws one flag, so two inherited flags that overwrite
// one another pass.
func TestRapidNestedScope(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		site := rapid.Bool().Draw(rt, "leaf takes site")
		area := rapid.Bool().Draw(rt, "leaf takes area")

		var flags []any
		if site {
			flags = append(flags, siteOption{})
		}

		if area {
			flags = append(flags, areaOption{})
		}

		calls := 0

		tree, err := New(
			Group{Name: "app", Flags: []any{siteOption{}}, Commands: []Node{
				Group{
					Name:    "users",
					Aliases: []string{"people"},
					Flags:   []any{areaOption{}},
					Commands: []Node{
						Command[struct{}]{
							Name:    "list",
							Aliases: []string{"ls"},
							Flags:   flags,
							Run:     func(context.Context, struct{}) error { calls++; return nil },
						},
					},
				},
			}},
		)
		if err != nil {
			fatalf(rt, "%v", err)
		}

		path := []string{
			rapid.SampledFrom([]string{"users", "people"}).Draw(rt, "group"),
			rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "leaf"),
		}
		slot := rapid.IntRange(0, 2).Draw(rt, "slot")
		kind := rapid.SampledFrom([]string{"site", "area", "unknown"}).Draw(rt, "flag")

		name := "--" + kind
		if kind == "unknown" {
			name += "x" + rapid.StringOfN(rapid.RuneFrom([]rune("abcxyz")), 0, 9, 9).
				Draw(rt, "unknown spelling")
		} else if rapid.Bool().Draw(rt, "short") {
			name = "-" + kind[:1]
		}

		value := rapid.OneOf(rapid.SampledFrom([]string{"", "--", "-s", "ls", "people", "=x", "white space"}), rapid.StringN(0, 32, 80)).
			Draw(rt, "value")
		words := argtest.Option(rt, name, value)
		argv := slices.Concat(path[:slot], words, path[slot:])
		line, err := tree.Parse(argv)
		runErr := line.Run(rt.Context())
		canonical := []string{"users", "list"}
		errDepth := -1

		switch {
		case kind == "unknown" || (kind == "area" && slot == 0):
			errDepth = slot
		case kind == "site" && !site, kind == "area" && !area:
			errDepth = 2
		}

		if errDepth >= 0 {
			e, ok := errors.AsType[*UsageError](err)
			//nolint:err113,errorlint // A refused line returns the exact parse error.
			if !ok || e.Kind != UnknownFlag || e.At != slot || e.Word != name ||
				!slices.Equal(e.Path, canonical[:errDepth]) ||
				runErr != err ||
				calls != 0 {
				fatalf(
					rt,
					"%q: error=%+v run=%v calls=%d; want unknown flag %s at %d on %q",
					argv,
					e,
					runErr,
					calls,
					name,
					slot,
					canonical[:errDepth],
				)
			}

			return
		}

		if err != nil || runErr != nil || calls != 1 ||
			!slices.Equal(line.Command.Path, canonical) {
			fatalf(
				rt,
				"%q: unexpected parse=%v run=%v calls=%d path=%q",
				argv,
				err,
				runErr,
				calls,
				line.Command.Path,
			)
		}

		s, hasSite := Get[siteOption](line)
		a, hasArea := Get[areaOption](line)

		var wantSite, wantArea Opt[string]
		if kind == "site" {
			wantSite = Some(value)
		} else {
			wantArea = Some(value)
		}

		if hasSite != site || hasArea != area || s.Site != wantSite ||
			a.Area != wantArea {
			fatalf(
				rt,
				"%q: site=(%v,%t) area=(%v,%t) want (%v,%t) (%v,%t)",
				argv,
				s.Site,
				hasSite,
				a.Area,
				hasArea,
				wantSite,
				site,
				wantArea,
				area,
			)
		}
	})
}

// Sibling names and aliases share a namespace; separate groups may reuse either.
//
// Bound: generated groups have distinct fixed names and no aliases, and a
// refused declaration is not held to its reason.
func TestRapidSiblingDeclarations(t *testing.T) {
	var validTrees, invalidTrees, validReuse, dispatched int

	rapid.Check(t, func(rt *rapid.T) {
		words := rapid.SampledFrom(
			[]string{"list", "show", "ls", "edit", "change", "get"},
		)
		leaf := rapid.SliceOfN(words, 1, 3)
		group := rapid.SliceOfN(leaf, 1, 3)
		branches := rapid.SliceOfN(group, 1, 3).Draw(rt, "declarations")

		type route struct{ group, word, canonical string }

		groups := make([]Node, 0, len(branches))

		var routes []route

		valid := true
		previous := make(map[string]string)
		reuse := false

		var ran []string

		for i, leaves := range branches {
			groupName := fmt.Sprintf("group%d", i)
			seen := make(map[string]bool)

			var children []Node

			for _, names := range leaves {
				canonical := names[0]
				for _, name := range names {
					if seen[name] {
						valid = false
					}

					if first, ok := previous[name]; ok && first != groupName {
						reuse = true
					}

					previous[name] = groupName
					seen[name] = true
					routes = append(routes, route{groupName, name, canonical})
				}

				children = append(children, Command[struct{}]{
					Name: canonical, Aliases: names[1:],
					Run: func(context.Context, struct{}) error {
						ran = append(ran, groupName+"/"+canonical)
						return nil
					},
				})
			}

			groups = append(groups, Group{Name: groupName, Commands: children})
		}

		tree, err := New(Group{Name: "app", Commands: groups})
		if (err == nil) != valid || (tree != nil) != valid {
			fatalf(
				rt,
				"declarations %v: valid=%t tree returned=%t error=%v",
				branches,
				valid,
				tree != nil,
				err,
			)
		}

		if !valid {
			invalidTrees++
			return
		}

		validTrees++

		word := words.Draw(rt, "completion word")
		prefix := word[:rapid.IntRange(0, len(word)).Draw(rt, "prefix length")]

		for i, leaves := range branches {
			var names, aliases []string

			for _, leaf := range leaves {
				if strings.HasPrefix(leaf[0], prefix) {
					names = append(names, leaf[0])
				}

				for _, alias := range leaf[1:] {
					if strings.HasPrefix(alias, prefix) {
						aliases = append(aliases, alias)
					}
				}
			}

			want := names
			if len(want) == 0 {
				want = aliases
			}

			got, directive := tree.Complete([]string{fmt.Sprintf("group%d", i)}, prefix)
			if !slices.Equal(got, want) || directive != NoFiles {
				fatalf(
					rt,
					"siblings %v, prefix %q: got %q (%v), want %q (%v)",
					leaves,
					prefix,
					got,
					directive,
					want,
					NoFiles,
				)
			}
		}

		if reuse {
			validReuse++
		}

		for _, route := range routes {
			argv := []string{route.group, route.word}

			line, err := tree.Parse(argv)
			if err != nil {
				fatalf(rt, "%q refused: %v", argv, err)
			}

			dispatched++
			ran = nil

			err = line.Run(rt.Context())
			if err != nil ||
				!slices.Equal(ran, []string{route.group + "/" + route.canonical}) ||
				!slices.Equal(
					line.Command.Path,
					[]string{route.group, route.canonical},
				) {
				fatalf(
					rt,
					"%q: canonical path=%q callbacks=%q error=%v",
					argv,
					line.Command.Path,
					ran,
					err,
				)
			}
		}
	})
	t.Logf(
		"model classes valid=%d invalid=%d valid-cross-group-reuse=%d dispatches=%d",
		validTrees,
		invalidTrees,
		validReuse,
		dispatched,
	)
}

type dispatchID string

type dispatchFlags struct {
	Label Opt[string] `flag:"label" short:"l"`
}

type dispatchInput struct {
	Target Opt[dispatchID]    `arg:"target"`
	IDs    Repeat[dispatchID] `flag:"id"`
}

type dispatchExample struct {
	leaf    string
	label   Opt[string]
	input   dispatchInput
	reads   []string
	invalid bool
}

// This grammar has one group and two command words with distinct callbacks.
// Model the words directly so the reader, typed setters and Run share no oracle.
func modelDispatch(words []string) dispatchExample {
	var m dispatchExample

	ended := false

	for i := 0; i < len(words); i++ {
		word := words[i]
		switch {
		case !ended && word == "--" && m.leaf != "":
			ended = true
		case !ended && len(word) > 1 && word[0] == '-':
			flag, value, inline := strings.Cut(word, "=")
			if flag != "--label" && flag != "-l" &&
				(flag != "--id" || m.leaf != "set") {
				m.invalid = true
				return m
			}

			if !inline {
				i++
				if i == len(words) {
					m.invalid = true
					return m
				}

				value = words[i]
			}

			if flag == "--id" {
				m.reads = append(m.reads, value)
				m.input.IDs = append(m.input.IDs, dispatchID(value))
			} else {
				if _, given := m.label.Get(); given {
					m.invalid = true
					return m
				}

				m.label = Some(value)
			}
		case m.leaf == "":
			switch word {
			case "set", "change":
				m.leaf = "set"
			case "show":
				m.leaf = "show"
			default:
				m.invalid = true
				return m
			}
		default:
			if _, given := m.input.Target.Get(); given || m.leaf == "show" {
				m.invalid = true
				return m
			}

			m.reads = append(m.reads, word)
			m.input.Target = Some(dispatchID(word))
		}
	}

	return m
}

func checkDispatch(tb interface {
	Fatalf(format string, args ...any)
}, words []string,
) {
	want := modelDispatch(words)

	var (
		calls, reads []string
		input        dispatchInput
	)

	tree, err := New(
		Group{Name: "prog", Flags: []any{dispatchFlags{}}, Commands: []Node{
			Command[dispatchInput]{
				Name:    "set",
				Aliases: []string{"change"},
				Flags:   []any{dispatchFlags{}},
				Run: func(_ context.Context, in dispatchInput) error {
					calls = append(calls, "set")
					input = in

					return nil
				},
			},
			Command[struct{}]{
				Name:  "show",
				Flags: []any{dispatchFlags{}},
				Run: func(context.Context, struct{}) error {
					calls = append(calls, "show")
					return nil
				},
			},
		}},
		LateReader(func(_ context.Context, s string) (dispatchID, error) {
			reads = append(reads, s)
			if s == "bad" {
				return "", errNoPeer
			}

			return dispatchID(s), nil
		}),
	)
	if err != nil {
		tb.Fatalf("declare fixture: %v", err)
	}

	line, parseErr := tree.Parse(words)
	if (parseErr != nil) != want.invalid || len(reads) != 0 || len(calls) != 0 {
		tb.Fatalf(
			"%q: parse=%v want rejection=%v, reads=%q calls=%q",
			words,
			parseErr,
			want.invalid,
			reads,
			calls,
		)
	}

	first := line.Run(context.Background())
	second := line.Run(context.Background())

	if parseErr != nil || want.leaf == "" {
		expected := ErrGroup
		if parseErr != nil {
			expected = parseErr
		}

		if !errors.Is(first, expected) || !errors.Is(second, expected) ||
			len(reads)+len(calls) != 0 {
			tb.Fatalf(
				"%q: Run=(%v, %v) want %v twice, reads=%q calls=%q",
				words,
				first,
				second,
				expected,
				reads,
				calls,
			)
		}

		return
	}

	global, ok := Get[dispatchFlags](line)
	if !ok || global.Label != want.label ||
		!slices.Equal(line.Command.Path, []string{want.leaf}) ||
		!errors.Is(second, ErrRan) {
		tb.Fatalf(
			"%q: path=%q flags=%+v present=%t second=%v; want leaf=%s label=%+v and ErrRan",
			words,
			line.Command.Path,
			global,
			ok,
			second,
			want.leaf,
			want.label,
		)
	}

	if bad := slices.Index(want.reads, "bad"); bad >= 0 {
		ue, ok := errors.AsType[*UsageError](first)
		if !ok || ue.Kind != Unresolved || !errors.Is(first, errNoPeer) ||
			len(calls) != 0 ||
			!slices.Equal(reads, want.reads[:bad+1]) {
			tb.Fatalf(
				"%q: Run=%v reads=%q want=%q calls=%q",
				words,
				first,
				reads,
				want.reads[:bad+1],
				calls,
			)
		}

		return
	}

	if first != nil || !slices.Equal(calls, []string{want.leaf}) ||
		!slices.Equal(reads, want.reads) ||
		!reflect.DeepEqual(input, want.input) {
		tb.Fatalf(
			"%q: Run=%v calls=%q reads=%q input=%+v; want leaf=%q reads=%q input=%+v",
			words,
			first,
			calls,
			reads,
			input,
			want.leaf,
			want.reads,
			want.input,
		)
	}
}

// Bound: a refusal is held to its presence, not its kind;
// TestDispatchShortLines shares the model.
func TestRapidDispatch(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Independent chunks let Rapid shrink one token or a meaningful pair.
		chunks := rapid.SliceOfN(rapid.SampledFrom([][]string{
			{"set"},
			{"change"},
			{"show"},
			{"--"},
			{""},
			{"-"},
			{"x"},
			{"bad"},
			{"--label"},
			{"-l"},
			{"--label="},
			{"-l=x"},
			{"--id"},
			{"--id=x"},
			{"--id=bad"},
			{"--id", "2"},
			{"--label", "--"},
			{"set", "x"},
			{"change", "--id=x"},
		}), 0, 12).Draw(rt, "chunks")
		checkDispatch(stable{rt}, slices.Concat(chunks...))
	})
}

// stable fails a Rapid draw through fatalf, for a helper that a plain test
// shares.
type stable struct{ rt *rapid.T }

func (s stable) Fatalf(format string, args ...any) {
	s.rt.Helper()
	fatalf(s.rt, format, args...)
}

func TestDispatchShortLines(t *testing.T) {
	alphabet := []string{"set", "change", "show", "--", "-l", "", "--id=x", "bad"}

	var visit func([]string)

	visit = func(words []string) {
		checkDispatch(t, words)

		if len(words) < 4 {
			for _, w := range alphabet {
				visit(append(words, w))
			}
		}
	}
	visit(nil)
}
