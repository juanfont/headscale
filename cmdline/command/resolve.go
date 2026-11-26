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
// an ambiguous word lists, how a message names one, and the read of one by
// its ID. A type whose JSON has a revision needs the read: after a write the
// server refused because the target changed, the builder reads the target
// again and runs the command once more.
type Entity struct {
	t      reflect.Type
	kind   string
	lookup cmdline.Option
	check  func() error
	name   func(v any) string
	read   readByID
}

// readByID reads one entity again by its ID.
type readByID func(ctx context.Context, id string) (any, error)

// EntityOf is the entity of type T. read is nil for a type with no
// revision; the compiler holds that find, the candidates, name and read
// are all of T.
func EntityOf[T any](
	kind string,
	find func(ctx context.Context, word string) (T, error),
	cands table.Columns[T],
	name func(T) string,
	read func(ctx context.Context, id string) (T, error),
) Entity {
	e := Entity{
		t:      reflect.TypeFor[T](),
		kind:   kind,
		lookup: cmdline.LateReader(find),
		check:  cands.Check,
		//nolint:forcetypeassert // the builder passes only a T
		name: func(v any) string { return name(v.(T)) },
	}

	if read != nil {
		e.read = func(ctx context.Context, id string) (any, error) { return read(ctx, id) }
	}

	return e
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
// The errors quote said, the word as the person typed it.
func Resolve[T any](
	rows []T,
	word, said, kind string,
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
			Text: "no " + kind + " matches " + strconv.Quote(said) + ".",
		}
	}

	var b bytes.Buffer

	// The candidates show no time, so no clock is needed.
	_ = table.Render(&b, matches, cols.Showing(matches, word), time.Time{}, nil)

	var list strings.Builder

	for line := range strings.Lines(b.String()) {
		list.WriteString("  " + line)
	}

	return zero, &LookupError{
		Text: strconv.Quote(
			said,
		) + " matches " + strconv.Itoa(
			len(matches),
		) + " " + kind + "s. Use the ID to select one:\n\n" +
			strings.TrimSuffix(
				list.String(),
				"\n",
			),
	}
}

// LookupError is a word that names no entity, or more than one. Hinted is
// a word of another kind, which the command's hint follows.
type LookupError struct {
	Text   string
	Hinted bool
}

func (e *LookupError) Error() string { return e.Text }
