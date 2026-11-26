package command

import (
	"context"
	"reflect"

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

// LookupError is a word that names no entity, or more than one.
type LookupError struct{ Text string }

func (e *LookupError) Error() string { return e.Text }
