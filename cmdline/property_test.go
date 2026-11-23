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
func TestRapidFieldDeclarations(t *testing.T) {
	var valid, malformed, duplicate int

	rapid.Check(t, func(rt *rapid.T) {
		name := rapid.SampledFrom([]string{"label", "sort", "value"}).Draw(rt, "name")
		help := rapid.SampledFrom([]string{"short help", "a \"quote\"", "a:b", "path\\leaf", "café"}).Draw(rt, "help")

		tags := []string{"flag:" + strconv.Quote(name), "help:" + strconv.Quote(help)}
		if rapid.Bool().Draw(rt, "reverse tags") {
			slices.Reverse(tags)
		}

		fault := rapid.SampledFrom([]string{"valid", "bad escape", "unterminated", "duplicate"}).Draw(rt, "declaration")
		switch fault {
		case "bad escape":
			tags = append(tags, `short:"\q"`)
		case "unterminated":
			tags = append(tags, `short:"s`)
		case "duplicate":
			tags = append(tags, "flag:"+strconv.Quote(name))
		}

		tag := reflect.StructTag(strings.Join(tags, " "))
		typ := reflect.StructOf([]reflect.StructField{{Name: "Value", Type: reflect.TypeFor[string](), Tag: tag}})
		flags := reflect.New(typ).Elem().Interface()
		called := false

		tree, err := New(Command[struct{}]{Name: "app", Flags: []any{flags}, Run: func(context.Context, struct{}) error { called = true; return nil }})
		if fault != "valid" {
			if err == nil || tree != nil {
				rt.Fatalf("New accepted bad declaration %q", tag)
			}

			if fault == "duplicate" {
				duplicate++
			} else {
				malformed++
			}

			return
		}

		if err != nil {
			rt.Fatalf("New(%q): %v", tag, err)
		}

		line, err := tree.Parse(argtest.Option(rt, "--"+name, help))
		if err != nil || len(line.Command.Flags) != 1 || line.Command.Flags[0].Name != name || line.Command.Flags[0].Help != help ||
			len(line.Flags) != 1 || line.Flags[0].Value != help || line.Run(rt.Context()) != nil || !called {
			rt.Fatalf("tag=%q parsed flags=%v metadata=%v error=%v called=%t", tag, line.Flags, line.Command.Flags, err, called)
		}

		valid++
	})
	t.Logf("model classes accepted-tags=%d malformed-tags=%d duplicate-tags=%d", valid, malformed, duplicate)
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

	tree, err := New(Command[input]{Name: "app", Run: func(_ context.Context, in input) error { calls++; observed = in; return nil }})
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

		switch rapid.SampledFrom([]string{"maximum", "minimum", "zero", "interior"}).Draw(rt, "base") {
		case "maximum":
			v.Set(maximum)
		case "minimum":
			v.Set(minimum)
		case "interior":
			v.SetUint64(rapid.Uint64().Draw(rt, "interior"))
			v.Mod(v, limit)
		}

		v.Add(v, big.NewInt(int64(rapid.IntRange(-3, 3).Draw(rt, "offset"))))
		negative := v.Sign() < 0
		text := new(big.Int).Abs(v).String()

		text = strings.Repeat("0", rapid.IntRange(0, 4).Draw(rt, "leading zeroes")) + text
		if negative {
			text = "-" + text
		} else if signed && rapid.Bool().Draw(rt, "plus") {
			text = "+" + text
		}

		var reason error

		switch {
		case rapid.IntRange(0, 5).Draw(rt, "lexical branch") == 0:
			text = rapid.SampledFrom([]string{"1.0", "1_0", "0x10", "", "--"}).Draw(rt, "nondecimal")
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
			if !ok || e.Kind != BadValue || e.Flag != name || e.At != 0 || e.Value != text || !errors.Is(e, reason) || !errors.Is(runErr, parseErr) || calls != 0 {
				rt.Fatalf("argv=%q parse=%v run=%v calls=%d want %v", argv, parseErr, runErr, calls, reason)
			}

			if errors.Is(reason, strconv.ErrRange) {
				overflow++
			} else {
				badSyntax++
			}

			return
		}

		if parseErr != nil || runErr != nil || calls != 1 {
			rt.Fatalf("argv=%q parse=%v run=%v calls=%d", argv, parseErr, runErr, calls)
		}

		value := reflect.ValueOf(observed).FieldByName(field).Interface()
		if fmt.Sprint(value) != v.String() {
			rt.Fatalf("argv=%q got %v want %s", argv, value, v)
		}

		valid++
	})
	t.Logf("model classes valid-width=%d range-errors=%d syntax-errors=%d", valid, overflow, badSyntax)
}

// Word offsets belong to the original argv even when aliases and split values have different widths.
func TestRapidReaderMatch(t *testing.T) {
	flag := reader.Flag{Name: "label", Short: 'ø', Repeat: true}
	leaf := &reader.Command{Name: "show", Aliases: []string{"view"}, Flags: []reader.Flag{flag}}
	root := &reader.Command{Name: "app", Flags: []reader.Flag{flag}, Commands: []*reader.Command{leaf}}

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

	var failures, afterEnd, unusual, spaced, mixedCase, generated int

	rapid.Check(t, func(rt *rapid.T) {
		text := rapid.OneOf(rapid.SampledFrom([]string{"", "--", "-ø", "--label=", "view", "a=b", "two words", "α", "-"}), rapid.String())

		var (
			argv, args, path []string
			at               []int
			flags            []reader.Given
			values           []string
		)

		option := func() {
			val := text.Draw(rt, "option value")
			spell := rapid.SampledFrom([]string{"-ø", "--label"}).Draw(rt, "flag spelling")

			flags = append(flags, reader.Given{Name: "label", Value: val, At: len(argv)})
			values = append(values, val)

			argv = append(argv, argtest.Option(rt, spell, val)...)
			if strings.ContainsAny(val, "=- ") || val == "" {
				unusual++
			}
		}
		for range rapid.IntRange(0, 3).Draw(rt, "leading options") {
			option()
		}

		where := rapid.SampledFrom([]string{"group", "leaf", "ended"}).Draw(rt, "stop at")
		command := root

		if where != "group" {
			argv = append(argv, rapid.SampledFrom([]string{"show", "view"}).Draw(rt, "leaf spelling"))
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
			if kind == reader.UnknownFlag && rapid.Bool().Draw(rt, "inline unknown value") {
				word += "=" + text.Draw(rt, "unknown value")
			}

			argv = append(argv, word)
			if kind != reader.MissingValue {
				argv = append(argv, rapid.SliceOfN(text, 0, 4).Draw(rt, "unread suffix")...)
			}

			failures++
		}

		m, err := reader.Parse(root, argv)
		if wantErr == nil && err != nil || wantErr != nil && !reflect.DeepEqual(err, wantErr) {
			rt.Fatalf("%q: error %#v want %#v", argv, err, wantErr)
		}

		if m.Command != command || !slices.Equal(m.Path, path) || !slices.Equal(m.Flags, flags) || !slices.Equal(m.Args, args) || !slices.Equal(m.ArgAt, at) || !slices.Equal(m.Values("label"), values) {
			rt.Fatalf("%q: got path=%q flags=%+v args=%q positions=%v; want path=%q flags=%+v args=%q positions=%v", argv, m.Path, m.Flags, m.Args, m.ArgAt, path, flags, args, at)
		}
	})
	t.Logf("model classes refused-lines=%d literal-tail-words=%d special-option-values=%d spaced-positionals=%d mixed-case-refusals=%d generated-refusals=%d", failures, afterEnd, unusual, spaced, mixedCase, generated)
}
