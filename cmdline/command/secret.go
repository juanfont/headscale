package command

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// A secret shown once, Spec.Secret: the result of a command that makes a
// credential holds a secret that the server keeps only a hash of. It goes
// to stdout alone, so KEY=$(…) captures it, after the note with its ID on
// stderr, so that the ID is known whatever happens to stdout. A secret
// that does not reach stdout is lost while the credential works: the error
// says so, with the command that revokes it.

var (
	errNotEnd = errors.New(
		"a delete of a credential, beside a Secret or of a target with revoked, is made by NewEnd",
	)
	errEndAlone = errors.New(
		"NewEnd is the delete of a credential, and no Secret beside it makes one",
	)
	errSecret = errors.New(
		"a result that holds a secret, a field key or secret at any depth, is printed by Secret, and only such a result has Secret",
	)
	errSecretNote = errors.New(
		"a Secret needs Done, the note on stderr, and no Columns",
	)
	errSecretID = errors.New(
		"a Secret's result is a struct with a text id, which the sentence of a lost secret names",
	)
	errSecretEnds = errors.New(
		"a Secret needs list and delete beside it, which the sentence of a lost secret names",
	)
	errSecretRow = errors.New(
		"a row holds a secret, a field key or secret at any depth: no list shows one",
	)
	errOpaque = errors.New(
		"is an interface: no check can see whether it holds a secret",
	)
)

// secretNames are the JSON names of a field that holds a secret.
func secretNames() []string { return []string{"key", "secret"} }

// holdsSecret reports whether a value of t can hold a secret: a field named
// as one, at any depth, through pointers, slices and maps. An interface
// can hold anything, and is an error.
func (p *program) holdsSecret(t reflect.Type) (bool, error) {
	if t.Kind() == reflect.Interface {
		return false, fmt.Errorf("%v %w", t, errOpaque)
	}

	seen := map[reflect.Type]bool{}

	var walk func(reflect.Type) bool

	walk = func(t reflect.Type) bool {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
			t = t.Elem()
		}

		if t.Kind() != reflect.Struct || seen[t] {
			return false
		}

		seen[t] = true

		for f := range t.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if f.IsExported() && slices.Contains(secretNames(), name) || walk(f.Type) {
				return true
			}
		}

		return false
	}

	return walk(t), nil
}

// checkSecret is what is wrong with the secret of a spec whose result is
// of type out.
func (p *program) checkSecret(out reflect.Type, secret, done, columns bool) []error {
	held, err := p.holdsSecret(out)

	switch {
	case err != nil:
		return []error{err}
	case held != secret:
		return []error{errSecret}
	case !secret:
		return nil
	case !done || columns:
		return []error{errSecretNote}
	case out.Kind() != reflect.Struct || !hasJSON(out, "id"):
		return []error{errSecretID}
	}

	return nil
}

// checkRows is what is wrong with the rows of a list: one that can hold a
// secret.
func (p *program) checkRows(row reflect.Type) []error {
	held, err := p.holdsSecret(row)

	switch {
	case err != nil:
		return []error{err}
	case held:
		return []error{errSecretRow}
	}

	return nil
}

// secretEnds is what is wrong with the ends of a credential among nodes,
// the commands of the group at path: a Secret command makes a credential,
// so list and delete stand beside it and the delete is made by NewEnd; and
// NewEnd stands only beside a Secret.
func secretEnds(path []string, nodes []Node) []error {
	names := make([]string, 0, len(nodes))
	secret := false

	for _, n := range nodes {
		names = append(names, nameOf(n))

		if l, ok := n.(*leaf); ok && l.secret {
			secret = true
		}
	}

	at := func(name string) string { return strings.Join(append(slices.Clone(path), name), " ") }

	var errs []error

	for _, n := range nodes {
		l, ok := n.(*leaf)

		switch {
		case !ok:
		case l.secret && (!slices.Contains(names, "list") || !slices.Contains(names, "delete")):
			errs = append(errs, specError(at(l.name)+": "+errSecretEnds.Error()))
		case secret && l.name == "delete" && !l.end:
			errs = append(errs, specError(at(l.name)+": "+errNotEnd.Error()))
		case !secret && l.end:
			errs = append(errs, specError(at(l.name)+": "+errEndAlone.Error()))
		}
	}

	return errs
}

// printSecret prints the result of a Spec.Secret command: the note, then
// the secret alone; with -o json the object. Both are written past the rule at the
// edge, and the result passes the guard of every result.
func printSecret[Out any](c *run, out Out, secret string, done func() string) error {
	raw, err := jsonOf(c, out)
	if err != nil {
		return err
	}

	id := jsonText(reflect.ValueOf(out), "id")

	if secret == "" {
		return c.lost(id, "the answer has no secret.")
	}

	if c.json {
		err = writeJSON(c.raw, raw)
	} else {
		// The ID first: a stdout that fails, or a closed pipe that ends the
		// process, still leaves it.
		_ = writeText(c.stderr, done())
		err = writeText(c.raw, secret)
	}

	if err != nil {
		return c.lost(id, "the secret cannot be written: "+cause(err)+".")
	}

	return nil
}

// lostAnswer is err with what follows for a Secret command: an answer
// that cannot be read, none, or a server fault after the write may be a
// credential that was made.
func (c *run) lostAnswer(err error) error {
	if c.tree.prog.MayBeMade == nil || !c.tree.prog.MayBeMade(err) {
		return err
	}

	return c.lost("", c.tree.sentence(err))
}

// lost is a secret that reached nobody, said with why and the command that
// revokes it: delete by the ID, or list to find it when the ID is unknown.
func (c *run) lost(id, why string) error {
	path := c.line.Command.Path
	group := strings.Join(append([]string{c.program}, path[:len(path)-1]...), " ")

	if id == "" {
		//nolint:err113 // a sentence of the CLI
		return fmt.Errorf(
			"%s\nIf a new one was made, it works, and nobody holds its secret. Find it and revoke it:\n  %s list",
			why,
			group,
		)
	}

	//nolint:err113 // a sentence of the CLI
	return fmt.Errorf(
		"%s\nThe new one, ID %s, works, and nobody holds its secret. Revoke it:\n  %s delete %s",
		why,
		id,
		group,
		id,
	)
}

// CreatedNote is the note of a create, on stderr before the secret: the new
// credential as messages name it, for its owner when it has one, what it
// is, and that its secret is shown this once, the secret named as word. A
// semicolon ends the owner, a colon the name with no owner, so the commas
// of a list do not run into what follows.
func CreatedNote(name, owner, what, word string) string {
	s := name
	if owner != "" {
		s += " for " + owner
	}

	switch {
	case what == "":
	case owner != "":
		s += "; " + what
	default:
		s += ": " + what
	}

	return s + ".\nThis is the only time the " + word + " is shown."
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
