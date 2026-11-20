package command

import (
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/script"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
)

// Words is a fixed set of words, for [OneOf].
type Words interface{ Words() []string }

// OneOf is a word of W: Tab offers W's words, and any other word is a
// mistake of the line.
type OneOf[W Words] string

func (o *OneOf[W]) UnmarshalText(b []byte) error {
	var w W

	words := w.Words()
	if !slices.Contains(words, string(b)) {
		return errors.New("it is one of " + strings.Join(words, ", ")) //nolint:err113 // the words are W's
	}

	*o = OneOf[W](b)

	return nil
}

func (OneOf[W]) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	var w W

	return cmdline.Words(prefix, w.Words()...), cmdline.NoFiles
}

// Shells are the shells that [Script] writes for.
type Shells struct{}

func (Shells) Words() []string { return []string{"bash", "zsh", "fish", "powershell"} }

// Script writes the completion script of shell for the program: cobra's
// scripts, which call the hidden entry point that [Run] answers.
func Script(w io.Writer, shell OneOf[Shells], program string) error {
	return script.Write(w, string(shell), program)
}

// NowNever are the words of a node's expiry: now, which expires the node
// at the server's clock, and never.
type NowNever struct{}

func (NowNever) Words() []string { return []string{"now", "never"} }

// NoWords are the words of an expiry that takes a time alone, such as a
// key's: never and now are words it refuses, as any other word.
type NoWords struct{}

func (NoWords) Words() []string { return nil }

// Expiry is the value of an expiry flag, read by the one time parser of
// the CLI: a time, a date at midnight UTC, a duration from now, or one of
// the words of W. The command declares with W what it takes: a node takes
// now and never; a type W with no words takes a time alone, and a word is
// a mistake of the line. A default is the flag's default tag, such as
// default:"1h".
type Expiry[W Words] struct {
	word string
	in   time.Duration
	at   time.Time
}

var errZero = errors.New("a duration from now is longer than 0")

func (e *Expiry[W]) UnmarshalText(b []byte) error {
	var w W

	s := string(b)
	if slices.Contains(w.Words(), s) {
		*e = Expiry[W]{word: s}

		return nil
	}

	d, t, ahead, err := table.ReadTime(s)

	switch {
	case errors.Is(err, table.ErrTooLong):
		return err
	case err != nil:
		return errors.New("it is " + oneOf(append([]string{"a time", "a date", "a duration such as 90d"}, w.Words()...))) //nolint:err113 // the words are W's
	case ahead && d == 0:
		return errZero
	case ahead:
		*e = Expiry[W]{in: d}
	default:
		*e = Expiry[W]{at: t}
	}

	return nil
}

// oneOf is "a, b or c".
func oneOf(words []string) string {
	if len(words) == 1 {
		return words[0]
	}

	return strings.Join(words[:len(words)-1], ", ") + " or " + words[len(words)-1]
}

// Word is the word that was given, such as now; "" for a time.
func (e Expiry[W]) Word() string { return e.word }

// At is the time of the expiry for a command that runs at now: a duration
// counts from now. The zero time for a word.
func (e Expiry[W]) At(now time.Time) time.Time {
	switch {
	case e.word != "":
		return time.Time{}
	case e.in > 0:
		return now.Add(e.in)
	}

	return e.at
}

// Owned is an owner as a question or a sentence about its object says it:
// "owned by User 3 (alice)", "tagged tag:ci, tag:build", or "with no
// owner".
func Owned(o nullable.Nullable[clientv0.Owner]) string {
	name, tagged := OwnerName(o)

	switch {
	case name == "":
		return "with no owner"
	case tagged:
		return "tagged " + name
	}

	return "owned by " + name
}

// OwnerName is the owner itself, as messages name it, and whether it is
// tags: "User 3 (alice)", or
// the tags, "tag:ci, tag:build"; "" for no owner.
func OwnerName(o nullable.Nullable[clientv0.Owner]) (string, bool) {
	owner, err := o.Get()
	if err != nil {
		return "", false
	}

	u, err := owner.User.Get()
	if err == nil {
		return table.Entity("user", u.Id, u.LoginName), false
	}

	tags := make([]string, 0, len(owner.Tags))
	for _, t := range owner.Tags {
		tags = append(tags, table.Visible(t, ""))
	}

	return strings.Join(tags, ", "), true
}

// Owner is the owner of a new key, one argument: a user, looked up as a
// target is, or tags, comma separated, each starting with tag:.
type Owner struct {
	user clientv0.User
	tags []string
}

// User is the user that owns the key; false for tags.
func (o Owner) User() (clientv0.User, bool) { return o.user, o.user.Id != "" }

// Tags are the tags that own the key; none for a user.
func (o Owner) Tags() []string { return o.tags }

// findOwner reads an owner: its form needs no call, a user is looked up.
func findOwner(ctx context.Context, word string) (Owner, error) {
	var tags, users []string

	// Space around an item is dropped, as in every list.
	items := strings.Split(word, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}

	for _, w := range items {
		switch {
		case w == "" && len(items) == 1:
			return Owner{}, emptyWord("owner")
		case w == "":
			return Owner{}, &lookupError{text: "the owner list has an empty item."}
		case strings.HasPrefix(w, "tag:"):
			tags = append(tags, w)
		default:
			users = append(users, table.Visible(w, ""))
		}
	}

	switch {
	case len(users) > 0 && len(tags) > 0:
		return Owner{}, &lookupError{text: "a key is owned by one user or by tags, not both."}
	case len(users) > 1:
		return Owner{}, &lookupError{text: "a key is owned by one user. Got " + strconv.Itoa(len(users)) + ": " + strings.Join(users, ", ") + "."}
	case len(tags) > 0:
		return Owner{tags: tags}, nil
	}

	u, err := findUser(ctx, items[0])

	return Owner{user: u}, err
}
