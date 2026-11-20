package command

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

// lookups are the late readers of the entity types: an argument or a flag
// of such a type is looked up when the line is right, with the client of
// the run, before Run.
var lookups = []cmdline.Option{
	cmdline.LateReader(findUser),
}

// candidates are the columns of the candidates each lookup lists, checked
// when a tree is built like the columns of a command, since a wrong one
// shows only when a word matches two rows.
var candidates = []interface{ Check() error }{userCandidates}

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

	return resolve(users, word, "user", userCandidates,
		func(u clientv0.User) string { return u.Id },
		func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
	)
}

// userCandidates are the columns of the users an ambiguous word matches;
// the provider identifier shows when the word is one.
var userCandidates = table.Columns[clientv0.User]{
	{Name: "id", Field: "id", Default: true},
	{Name: "name", Field: "name", Default: true},
	{Name: "email", Field: "email", Default: true},
	{Name: "provider", Field: "provider", Default: true},
	{Name: "provider-id", Field: "providerId", Kind: table.Text},
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
