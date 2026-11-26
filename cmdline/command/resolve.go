package command

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/table"
)

// Entity is one type of target: the word that a sentence names
// it by, the lookup that finds it by a word, the columns of the candidates
// an ambiguous word lists, and how a message names one.
type Entity struct {
	t      reflect.Type
	kind   string
	lookup cmdline.Option
	check  func() error
	name   func(v any) string
}

// EntityOf is the entity of type T; the compiler holds that find, the
// candidates and name are all of T.
func EntityOf[T any](
	kind string,
	find func(ctx context.Context, word string) (T, error),
	cands table.Columns[T],
	name func(T) string,
) Entity {
	return Entity{
		t:      reflect.TypeFor[T](),
		kind:   kind,
		lookup: cmdline.LateReader(find),
		check:  cands.Check,
		//nolint:forcetypeassert // the builder passes only a T
		name: func(v any) string { return name(v.(T)) },
	}
}

// EmptyWord is an empty target: it names nothing, so a lookup refuses it
// before any call.
func EmptyWord(
	kind string,
) error {
	return &LookupError{Text: "an empty word names no " + kind + "."}
}

// Resolve finds the one row that word names. An exact ID ends the search.
// Otherwise every row that word equals in any of its fields is a match,
// once however many fields it matches in; more than one is an error that
// lists them, with the default columns of cols, and each other column of
// cols that word equals in a candidate, so the list says why it matched.
func Resolve[T any](
	rows []T,
	word, kind string,
	cols table.Columns[T],
	id func(T) string,
	fields func(T) []string,
) (T, error) {
	var zero T

	if i := slices.IndexFunc(rows, func(r T) bool { return id(r) == word }); i >= 0 {
		return rows[i], nil
	}

	var matches []T

	for _, r := range rows {
		if word != "" && slices.Contains(fields(r), word) {
			matches = append(matches, r)
		}
	}

	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return zero, &LookupError{
			Text: "no " + kind + " matches " + strconv.Quote(word) + ".",
		}
	}

	var b bytes.Buffer

	// The candidates show no time, so no clock is needed.
	_ = table.Render(&b, matches, cols.Showing(matches, word), time.Time{})

	var list strings.Builder

	for line := range strings.Lines(b.String()) {
		list.WriteString("  " + line)
	}

	return zero, &LookupError{
		Text: strconv.Quote(
			word,
		) + " matches " + strconv.Itoa(
			len(matches),
		) + " " + kind + "s. Use the ID to select one:\n\n" +
			strings.TrimSuffix(
				list.String(),
				"\n",
			),
	}
}

// LookupError is a word that names no entity, or more than one.
type LookupError struct{ Text string }

func (e *LookupError) Error() string { return e.Text }
