package command

import (
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
)

// How a credential ends: an auth key, an API key and an OAuth client are
// each revoked by their delete, and the record stays until the server
// removes it. The question, the call, the read after it and the sentences
// are here once, and the tree refuses a delete of a credential that is not
// made by NewEnd, so no kind can say less than another: a delete beside a
// Secret command, or of a target with revoked.

var (
	errNotEnd   = errors.New("a delete of a credential, beside a Secret or of a target with revoked, is made by NewEnd")
	errEndAlone = errors.New("NewEnd is the delete of a credential, and no Secret beside it makes one")
	errOwn      = errors.New("NewEnd needs Own, or NeverOwn for a kind that the CLI never calls with, and not both")
)

// Ended is what the end of a credential reads of it.
type Ended struct {
	// ID is what its delete and its read take; Name is the credential as
	// messages name it, "API key 2 (tr81ys)".
	ID, Name string
	// Owned is its owner as a question says it, "owned by User 3
	// (alice)"; "" for a kind that has none.
	Owned string
	// For is what it is for, which the question shows after the name for
	// a kind whose name tells one from another by an ID alone: an OAuth
	// client's description.
	For string
	// Revoked and Removal are the fields of the API.
	Revoked, Removal nullable.Nullable[time.Time]
}

// EndSpec is the delete of a credential, of type T, the target of In.
type EndSpec[In, T any] struct {
	Short   string
	Long    string
	Example []string

	Target func(in In) T
	Of     func(t T) Ended
	// Revoke is the delete of the API, and Get the read of the record
	// after it.
	Revoke func(c Ctx, id string) error
	Get    func(c Ctx, id string) (T, error)
	// Own reports whether the CLI calls with the credential, as GET /me
	// says. A kind that no call is made with says so with NeverOwn; the
	// tree refuses a kind that says neither.
	Own      func(me clientv0.Me, t T) bool
	NeverOwn bool
}

// ownSentence follows the question when the CLI deletes the credential it
// calls with: the delete works, and every call after it is refused.
const ownSentence = "This CLI calls with it: once it is revoked, the server refuses the CLI."

// OwnWarning is a Prompt.Warning: sentence when own reports that the
// credential the CLI calls with goes with the change. GET /me is made only
// when a person reads the answer, and only when the CLI calls with a
// credential: the socket has none. A CLI that cannot read who it is asks
// all the same. A question asked again does not ask the server again.
func OwnWarning(c Ctx, sentence string, own func(me clientv0.Me) bool) func() string {
	if c.API == nil || c.API.socket != nil {
		return nil
	}

	return func() string {
		me, err := c.API.whoAmI(c)
		if err == nil && own(me) {
			return sentence
		}

		return ""
	}
}

// NewEnd makes the delete of a credential: a revoked one is not asked
// about, a read after the delete learns when the record is removed, and a
// read that fails, as when the CLI revoked its own credential, is no error.
func NewEnd[In, T any](s EndSpec[In, T]) Node {
	n := New(Spec[In, T]{
		Name: "delete", Aliases: []string{"rm"}, Short: s.Short, Long: s.Long, Example: s.Example,
		Confirm: func(c Ctx, in In) (Prompt, error) {
			t := s.Target(in)
			e := s.Of(t)

			if isSet(e.Revoked) {
				return Prompt{}, nil
			}

			q := "Delete " + e.Name
			if e.For != "" {
				q += " (" + table.Visible(e.For, "") + ")"
			}

			if e.Owned != "" {
				q += ", " + e.Owned
			}

			q += "?"

			p := Prompt{Question: q, Action: "delete " + e.Name}

			if s.Own != nil {
				p.Warning = OwnWarning(c, ownSentence, func(me clientv0.Me) bool { return s.Own(me, t) })
			}

			return p, nil
		},
		Run: func(c Ctx, in In) (T, error) {
			var zero T

			id := s.Of(s.Target(in)).ID

			err := s.Revoke(c, id)
			if err != nil {
				return zero, err
			}

			t, err := s.Get(c, id)
			if err != nil {
				return zero, ErrNotRead
			}

			return t, nil
		},
		Done: func(in In, out T, now time.Time) string { return ended(s.Of(s.Target(in)), s.Of(out), now) },
	})

	l := n.(*leaf) //nolint:forcetypeassert // New makes a leaf
	l.end = true

	check := l.check
	l.check = func() error {
		if (s.Own != nil) == s.NeverOwn {
			return errors.Join(check(), errOwn)
		}

		return check()
	}

	return l
}

// ended is the sentence of a delete: before is the credential as the
// command found it, after as it was read after the delete, with no ID when
// that read failed.
func ended(before, after Ended, now time.Time) string {
	s := before.Name + " is revoked."
	if isSet(before.Revoked) {
		s = before.Name + " was revoked already."
	}

	if after.ID == "" {
		return s
	}

	removal, err := after.Removal.Get()

	switch {
	case err != nil:
		return s + " Its record is kept."
	case !removal.After(now):
		return s + " Its record is due for removal."
	}

	return s + " Its record is removed " + table.Ago(removal, now) + "."
}

func isSet(t nullable.Nullable[time.Time]) bool {
	_, err := t.Get()

	return err == nil
}

// revokable reports whether t, the target of a command, is a credential:
// a struct with a field revoked.
func revokable(t reflect.Type) bool {
	if t == nil || t.Kind() != reflect.Struct {
		return false
	}

	for f := range t.Fields() {
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name == "revoked" {
			return true
		}
	}

	return false
}
