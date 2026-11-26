package cmdline

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/juanfont/headscale/cmdline/argtest"
	"github.com/juanfont/headscale/cmdline/reader"
	"pgregory.net/rapid"
)

// Keep the declaration alphabet finite: reflect retains constructed types for the process lifetime.
//
// Bound: no typed value of the generated struct is read, only the raw flag
// and its descriptor.
func TestRapidFieldDeclarations(t *testing.T) {
	var valid, malformed, duplicate int

	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.SampledFrom([]string{"label", "sort", "value"}).Draw(rt, "name")
		help := rapid.SampledFrom([]string{"short help", "a \"quote\"", "a:b", "path\\leaf", "café"}).
			Draw(rt, "help")

		tags := []string{"flag:" + strconv.Quote(name), "help:" + strconv.Quote(help)}
		if rapid.Bool().Draw(rt, "reverse tags") {
			slices.Reverse(tags)
		}

		fault := rapid.SampledFrom([]string{"valid", "bad escape", "unterminated", "duplicate"}).
			Draw(rt, "declaration")
		switch fault {
		case "bad escape":
			tags = append(tags, `short:"\q"`)
		case "unterminated":
			tags = append(tags, `short:"s`)
		case "duplicate":
			tags = append(tags, "flag:"+strconv.Quote(name))
		}

		tag := reflect.StructTag(strings.Join(tags, " "))
		typ := reflect.StructOf(
			[]reflect.StructField{
				{Name: "Value", Type: reflect.TypeFor[string](), Tag: tag},
			},
		)
		flags := reflect.New(typ).Elem().Interface()
		called := false

		tree, err := New(
			Command[struct{}]{
				Name:  "app",
				Flags: []any{flags},
				Run:   func(context.Context, struct{}) error { called = true; return nil },
			},
		)
		if fault != "valid" {
			if err == nil || tree != nil {
				fatalf(rt, "New accepted bad declaration %q", tag)
			}

			if fault == "duplicate" {
				duplicate++
			} else {
				malformed++
			}

			return
		}

		if err != nil {
			fatalf(rt, "New(%q): %v", tag, err)
		}

		line, err := tree.Parse(argtest.Option(rt, "--"+name, help))
		if err != nil || len(line.Command.Flags) != 1 ||
			line.Command.Flags[0].Name != name ||
			line.Command.Flags[0].Help != help ||
			len(line.Flags) != 1 ||
			line.Flags[0].Value != help ||
			line.Run(rt.Context()) != nil ||
			!called {
			fatalf(
				rt,
				"tag=%q parsed flags=%v metadata=%v error=%v called=%t",
				tag,
				line.Flags,
				line.Command.Flags,
				err,
				called,
			)
		}

		valid++
	})
	t.Logf(
		"model classes accepted-tags=%d malformed-tags=%d duplicate-tags=%d",
		valid,
		malformed,
		duplicate,
	)
}

func TestRapidIntegerWidths(t *testing.T) {
	type input struct {
		I8  int8   `flag:"i8"`
		I16 int16  `flag:"i16"`
		I32 int32  `flag:"i32"`
		I64 int64  `flag:"i64"`
		U8  uint8  `flag:"u8"`
		U16 uint16 `flag:"u16"`
		U32 uint32 `flag:"u32"`
		U64 uint64 `flag:"u64"`
	}

	calls := 0

	var observed input

	tree, err := New(
		Command[input]{
			Name: "app",
			Run:  func(_ context.Context, in input) error { calls++; observed = in; return nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var valid, overflow, badSyntax int

	rapid.Check(t, func(rt *rapid.T) {
		signed := rapid.Bool().Draw(rt, "signed")
		bits := rapid.SampledFrom([]int{8, 16, 32, 64}).Draw(rt, "bits")
		one := big.NewInt(1)
		minimum := new(big.Int)
		power := bits
		field := "U" + strconv.Itoa(bits)

		if signed {
			power--
			field = "I" + strconv.Itoa(bits)
		}

		limit := new(big.Int).Lsh(one, uint(power))
		if signed {
			minimum.Neg(limit)
		}

		maximum := new(big.Int).Sub(limit, one)
		v := new(big.Int)

		switch rapid.SampledFrom([]string{"maximum", "minimum", "zero", "interior"}).
			Draw(rt, "base") {
		case "maximum":
			v.Set(maximum)
		case "minimum":
			v.Set(minimum)
		case "interior":
			// Over the whole interval, both signs for a signed type.
			span := new(big.Int).Sub(maximum, minimum)
			span.Add(span, one)
			v.SetUint64(rapid.Uint64().Draw(rt, "interior"))
			v.Mod(v, span)
			v.Add(v, minimum)
		}

		v.Add(v, big.NewInt(int64(rapid.IntRange(-3, 3).Draw(rt, "offset"))))
		negative := v.Sign() < 0
		text := new(big.Int).Abs(v).String()

		text = strings.Repeat(
			"0",
			rapid.IntRange(0, 4).Draw(rt, "leading zeroes"),
		) + text
		if negative {
			text = "-" + text
		} else if signed && rapid.Bool().Draw(rt, "plus") {
			text = "+" + text
		}

		var reason error

		switch {
		case rapid.IntRange(0, 5).Draw(rt, "lexical branch") == 0:
			text = rapid.SampledFrom([]string{"1.0", "1_0", "0x10", "", "--"}).
				Draw(rt, "nondecimal")
			reason = strconv.ErrSyntax
		case negative && !signed:
			reason = strconv.ErrSyntax
		case v.Cmp(minimum) < 0 || v.Cmp(maximum) > 0:
			reason = strconv.ErrRange
		}

		name := strings.ToLower(field)
		argv := argtest.Option(rt, "--"+name, text)
		calls = 0
		line, parseErr := tree.Parse(argv)
		runErr := line.Run(rt.Context())

		if reason != nil {
			e, ok := errors.AsType[*UsageError](parseErr)
			if !ok || e.Kind != BadValue || e.Flag != name || e.At != 0 ||
				e.Value != text ||
				!errors.Is(e, reason) ||
				!errors.Is(runErr, parseErr) ||
				calls != 0 {
				fatalf(
					rt,
					"argv=%q parse=%v run=%v calls=%d want %v",
					argv,
					parseErr,
					runErr,
					calls,
					reason,
				)
			}

			if errors.Is(reason, strconv.ErrRange) {
				overflow++
			} else {
				badSyntax++
			}

			return
		}

		if parseErr != nil || runErr != nil || calls != 1 {
			fatalf(
				rt,
				"argv=%q parse=%v run=%v calls=%d",
				argv,
				parseErr,
				runErr,
				calls,
			)
		}

		value := reflect.ValueOf(observed).FieldByName(field).Interface()
		if fmt.Sprint(value) != v.String() {
			fatalf(rt, "argv=%q got %v want %s", argv, value, v)
		}

		valid++
	})
	t.Logf(
		"model classes valid-width=%d range-errors=%d syntax-errors=%d",
		valid,
		overflow,
		badSyntax,
	)
}

// Word offsets belong to the original argv even when aliases and split values have different widths.
//
// Bound: the completion check runs only on a line with no refusal and no
// --; a replay of a parser failure can run out of draws.
//
//nolint:gocyclo // one model of the reader, branch by branch
func TestRapidReaderMatch(t *testing.T) {
	flag := reader.Flag{Name: "label", Short: 'ø', Repeat: true}
	leaf := &reader.Command{
		Name:    "show",
		Aliases: []string{"view"},
		Flags:   []reader.Flag{flag},
	}
	root := &reader.Command{
		Name:     "app",
		Flags:    []reader.Flag{flag},
		Commands: []*reader.Command{leaf},
	}

	stem := rapid.StringOfN(rapid.RuneFrom(nil, unicode.Letter, unicode.Nd), 1, 10, 40)
	unrecognized := rapid.OneOf(
		rapid.SampledFrom([]string{"Label", "LABEL", "Show", "VIEW"}),
		rapid.Map(stem, func(s string) string { return "other-" + s }),
	)
	positionals := rapid.OneOf(
		rapid.SampledFrom([]string{"", "-", "show", "α", "a=b", "two words"}),
		rapid.Custom(func(rt *rapid.T) string {
			word := stem.Draw(rt, "stem")

			edge := rapid.SampledFrom([]string{" ", "\t", "\u00a0"}).Draw(rt, "space")
			if rapid.Bool().Draw(rt, "leading") {
				return edge + word
			}

			return word + edge
		}),
	)

	var failures, afterEnd, unusual, spaced, mixedCase, generated, callbacks, suppressed int

	rapid.Check(t, func(rt *rapid.T) {
		text := rapid.OneOf(
			rapid.SampledFrom(
				[]string{
					"",
					"--",
					"-ø",
					"--label=",
					"view",
					"a=b",
					"two words",
					"α",
					"-",
				},
			),
			rapid.String(),
		)

		var (
			argv, args, path []string
			at               []int
			flags            []reader.Given
			values           []string
		)

		option := func() {
			val := text.Draw(rt, "option value")
			spell := rapid.SampledFrom([]string{"-ø", "--label"}).
				Draw(rt, "flag spelling")

			flags = append(
				flags,
				reader.Given{Name: "label", Value: val, At: len(argv)},
			)
			values = append(values, val)

			argv = append(argv, argtest.Option(rt, spell, val)...)
			if strings.ContainsAny(val, "=- ") || val == "" {
				unusual++
			}
		}
		for range rapid.IntRange(0, 3).Draw(rt, "leading options") {
			option()
		}

		where := rapid.SampledFrom([]string{"group", "leaf", "ended"}).
			Draw(rt, "stop at")
		command := root

		if where != "group" {
			argv = append(
				argv,
				rapid.SampledFrom([]string{"show", "view"}).Draw(rt, "leaf spelling"),
			)
			path = []string{"show"}
			command = leaf

			for range rapid.IntRange(0, 5).Draw(rt, "leaf fields") {
				if rapid.Bool().Draw(rt, "is option") {
					option()
					continue
				}

				val := positionals.Draw(rt, "positional")
				if strings.TrimSpace(val) != val {
					spaced++
				}

				args = append(args, val)
				at = append(at, len(argv))
				argv = append(argv, val)
			}
		}

		var wantErr *reader.Error

		if where == "ended" {
			argv = append(argv, "--")
			for _, val := range rapid.SliceOfN(text, 0, 6).Draw(rt, "literal tail") {
				args = append(args, val)
				at = append(at, len(argv))
				argv = append(argv, val)
				afterEnd++
			}
		} else if rapid.Bool().Draw(rt, "include refusal") {
			errorsAt := []reader.ErrorKind{reader.UnknownFlag, reader.MissingValue}
			if where == "group" {
				errorsAt = append(errorsAt, reader.UnknownCommand)
			}

			kind := rapid.SampledFrom(errorsAt).Draw(rt, "error kind")

			word := "-ø"
			if kind != reader.MissingValue {
				word = unrecognized.Draw(rt, "unknown spelling")
				if strings.HasPrefix(word, "other-") {
					generated++
				} else {
					mixedCase++
				}

				if kind == reader.UnknownFlag {
					word = "--" + word
				}
			}

			wantErr = &reader.Error{Kind: kind, Path: path, Word: word, At: len(argv)}
			if kind == reader.UnknownFlag &&
				rapid.Bool().Draw(rt, "inline unknown value") {
				word += "=" + text.Draw(rt, "unknown value")
			}

			argv = append(argv, word)
			if kind != reader.MissingValue {
				argv = append(
					argv,
					rapid.SliceOfN(text, 0, 4).Draw(rt, "unread suffix")...)
			}

			failures++
		}

		m, err := reader.Parse(root, argv)
		if wantErr == nil && err != nil ||
			wantErr != nil && !reflect.DeepEqual(err, wantErr) {
			fatalf(rt, "%q: error %#v want %#v", argv, err, wantErr)
		}

		if m.Command != command || !slices.Equal(m.Path, path) ||
			!slices.Equal(m.Flags, flags) ||
			!slices.Equal(m.Args, args) ||
			!slices.Equal(m.ArgAt, at) ||
			!slices.Equal(m.Values("label"), values) {
			fatalf(
				rt,
				"%q: got path=%q flags=%+v args=%q positions=%v; want path=%q flags=%+v args=%q positions=%v",
				argv,
				m.Path,
				m.Flags,
				m.Args,
				m.ArgAt,
				path,
				flags,
				args,
				at,
			)
		}

		if wantErr == nil && where != "ended" {
			if checkValueCompletion(rt, root, argv, m, text.Draw(rt, "cursor value")) {
				callbacks++
			} else {
				suppressed++
			}
		}
	})
	t.Logf(
		"model classes refused-lines=%d literal-tail-words=%d special-option-values=%d spaced-positionals=%d mixed-case-refusals=%d generated-refusals=%d value-callbacks=%d repeat-suppressions=%d",
		failures,
		afterEnd,
		unusual,
		spaced,
		mixedCase,
		generated,
		callbacks,
		suppressed,
	)
}

// Completing a value sees the same prior words and offsets that Parse returned.
func checkValueCompletion(
	t *rapid.T,
	root *reader.Command,
	argv []string,
	parsed *reader.Match,
	prefix string,
) bool {
	t.Helper()

	flag := &parsed.Command.Flags[0]

	saved := *flag
	defer func() { *flag = saved }()

	flag.Repeat = rapid.Bool().Draw(t, "repeatable")
	seen := 0
	flag.Complete = func(line *reader.Match, cur string) ([]string, reader.Directive) {
		seen++

		if cur != prefix || line.Command != parsed.Command ||
			!slices.Equal(line.Path, parsed.Path) ||
			!slices.Equal(line.Args, parsed.Args) ||
			!slices.Equal(line.ArgAt, parsed.ArgAt) ||
			!slices.Equal(line.Flags, parsed.Flags) {
			fatalf(
				t,
				"callback on %q: prefix=%q want %q, flags=%v args=%q at=%v, parsed flags=%v args=%q at=%v",
				argv,
				cur,
				prefix,
				line.Flags,
				line.Args,
				line.ArgAt,
				parsed.Flags,
				parsed.Args,
				parsed.ArgAt,
			)
		}

		return []string{"choice"}, reader.NoSpace | reader.KeepOrder
	}
	spell := rapid.SampledFrom([]string{"--label", "-ø"}).Draw(t, "cursor option")
	form := argtest.Option(t, spell, prefix)
	words := append(slices.Clone(argv), form[:len(form)-1]...)

	got, dir := reader.Complete(root, words, form[len(form)-1])
	if !flag.Repeat && len(parsed.Values(flag.Name)) != 0 {
		if seen != 0 || len(got) != 0 || dir != reader.NoFiles {
			fatalf(
				t,
				"already given %q invoked callback %d times: %q %v",
				spell,
				seen,
				got,
				dir,
			)
		}

		return false
	}

	if seen != 1 || !slices.Equal(got, []string{"choice"}) ||
		dir != reader.NoSpace|reader.KeepOrder {
		fatalf(
			t,
			"value completion for %q invoked callback %d times: %q %v",
			spell,
			seen,
			got,
			dir,
		)
	}

	return true
}

// fatalf fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
