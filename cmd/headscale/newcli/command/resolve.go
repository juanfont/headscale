package command

import (
	"bytes"
	"context"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

// entity is one type of target: the word that a problem's object names
// it by, the lookup that finds it by a word, the columns of the candidates
// an ambiguous word lists, how a message names one, and the read of one by
// its ID. A type whose JSON has a revision needs the read: after a write the
// server refused because the target changed, the builder reads the target
// again and runs the command once more.
type entity struct {
	t      reflect.Type
	kind   string
	lookup cmdline.Option
	check  func() error
	name   func(v any) string
	read   readByID
}

// readByID reads one entity again by its ID.
type readByID func(ctx context.Context, id string) (any, error)

// entityOf is the entity of type T. read is nil for a type with no
// revision; the compiler holds that find, the candidates, name and read
// are all of T.
func entityOf[T any](kind string, find func(ctx context.Context, word string) (T, error), cands table.Columns[T], name func(T) string, read func(ctx context.Context, id string) (T, error)) entity {
	e := entity{
		t:      reflect.TypeFor[T](),
		kind:   kind,
		lookup: cmdline.LateReader(find),
		check:  cands.Check,
		name:   func(v any) string { return name(v.(T)) }, //nolint:forcetypeassert // the builder passes only a T
	}

	if read != nil {
		e.read = func(ctx context.Context, id string) (any, error) { return read(ctx, id) }
	}

	return e
}

// entities are the entities of Headscale. A function, not a variable, so
// no test or command can change what another tree sees.
func entities() []entity {
	return []entity{
		entityOf("user", findUser, userCandidates(), func(u clientv0.User) string { return u.LoginName }, nil),
	}
}

// emptyWord is an empty target: it names nothing, so a lookup refuses it
// before any call.
func emptyWord(kind string) error { return &lookupError{text: "an empty word names no " + kind + "."} }

// findUser is the user that word names: the user with that ID, else the one
// user whose email, username or provider identifier it is.
func findUser(ctx context.Context, word string) (clientv0.User, error) {
	if word == "" {
		return clientv0.User{}, emptyWord("user")
	}

	users, err := ctxOf(ctx).API.ListUsers(ctx)
	if err != nil {
		return clientv0.User{}, err
	}

	return resolve(users, word, "user", userCandidates(),
		func(u clientv0.User) string { return u.Id },
		func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
	)
}

// userCandidates are the columns of the users an ambiguous word matches;
// the provider identifier shows when the word is one.
func userCandidates() table.Columns[clientv0.User] {
	return table.Columns[clientv0.User]{
		{Name: "id", Field: "id", Default: true},
		{Name: "name", Field: "name", Default: true},
		{Name: "email", Field: "email", Default: true},
		{Name: "provider", Field: "provider", Default: true},
		{Name: "provider-id", Field: "providerId", Kind: table.Text},
	}
}

// resolve finds the one row that word names. An exact ID ends the search.
// Otherwise every row that word equals in any of its fields is a match,
// once however many fields it matches in; more than one is an error that
// lists them, with the default columns of cols, and each other column of
// cols that word equals in a candidate, so the list says why it matched.
func resolve[T any](rows []T, word, kind string, cols table.Columns[T], id func(T) string, fields func(T) []string) (T, error) {
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
		return zero, &lookupError{text: "no " + kind + " matches " + strconv.Quote(word) + "."}
	}

	var b bytes.Buffer

	// The candidates show no time, so no clock is needed.
	_ = table.Render(&b, matches, cols.Showing(matches, word), time.Time{}, nil)

	var list strings.Builder

	for line := range strings.Lines(b.String()) {
		list.WriteString("  " + line)
	}

	return zero, &lookupError{text: strconv.Quote(word) + " matches " + strconv.Itoa(len(matches)) + " " + kind + "s. Use the ID to select one:\n\n" +
		strings.TrimSuffix(list.String(), "\n")}
}

// lookupError is a word that names no entity, or more than one.
type lookupError struct{ text string }

func (e *lookupError) Error() string { return e.text }
