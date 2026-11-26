package command

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/juanfont/headscale/cmdline"
)

// The rule at the edge: a word that has the form of a credential of the
// program, its Prefix (hskey-) or another spelling its server takes
// (tskey-client-), in any case and anywhere in a word, leaves the program
// as its kind and no more, hskey-auth-***. Run holds it on stdout and
// stderr, so no error, note, prompt, cell or sheet line repeats a secret,
// whether the server sent it or a person typed it. Three ways lead past the
// rule: the secret that a Spec.Secret command declares, on stdout; the -o
// json of that command; and the JSON of any result, which is the server's
// data and not the program's sentence, so it is printed as the server sent
// it. That last way rests on the start-up check (secret.go): no type that
// holds a field key or secret, at any depth, is printed by a command that
// does not declare it, and no list row holds one.

// Credentials is the form of the credentials of a program.
type Credentials struct {
	// Prefix starts a credential of the program: "hskey-".
	Prefix string
	// Kinds are the words after Prefix that name a kind of credential; any
	// other word may be part of a secret, so it is not shown.
	Kinds []string
	// Fronts are every start of a word that is a credential: Prefix, and
	// any other spelling the server takes.
	Fronts []string
}

// masked is s with every credential in it written as its kind. A word
// that holds no more than the kind, such as hskey-auth- in a help text,
// stays as it is.
func (cr *Credentials) masked(s string) string { return cr.each(s, cr.kindOf) }

// each is s with every word that has the form of a credential replaced by
// f of it.
func (cr *Credentials) each(s string, f func(w string) string) string {
	var b strings.Builder

	for {
		i, front := cr.At(s)
		if i < 0 {
			b.WriteString(s)

			return b.String()
		}

		j := i + len(front)
		for j < len(s) && credentialRune(rune(s[j])) {
			j++
		}

		// The masked form of older output, hskey-auth-<prefix>-***.
		if strings.HasPrefix(s[j:], "***") {
			j += 3
		}

		b.WriteString(s[:i])
		b.WriteString(f(s[i:j]))
		s = s[j:]
	}
}

// At is the first index in s of a word that has the form of a credential,
// in any case, and the front it starts with. -1 when s holds none.
func (cr *Credentials) At(s string) (int, string) {
	at, front := -1, ""

	for _, f := range cr.Fronts {
		i := indexFold(s, f)
		if i >= 0 && (at < 0 || i < at) {
			at, front = i, f
		}
	}

	return at, front
}

// kindOf is the credential w as it may be shown.
func (cr *Credentials) kindOf(w string) string {
	// A front other than Prefix names its kind whole, tskey-client-.
	if _, front := cr.At(w); front != cr.Prefix {
		if strings.TrimSuffix(w[len(front):], "***") == "" {
			return w
		}

		return front + "***"
	}

	rest := strings.TrimSuffix(w[len(cr.Prefix):], "***")
	kind, after, _ := strings.Cut(rest, "-")

	switch {
	case !slices.Contains(cr.Kinds, strings.ToLower(kind)):
		if rest == "" {
			return w
		}

		return cr.Prefix + "***"
	case after == "":
		return w
	}

	return cr.Prefix + strings.ToLower(kind) + "-***"
}

// indexFold is the first index of the ASCII word sub in s, in any case.
func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return i
		}
	}

	return -1
}

// credentialRune is a character a credential is made of: base64 URL-safe.
func credentialRune(c rune) bool {
	return c == '-' || c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' ||
		'A' <= c && c <= 'Z'
}

// masking writes through masked. A write can end inside a word, so the
// word waits for the next write or for Flush.
type masking struct {
	w    io.Writer
	cred *Credentials
	held []byte
}

func (m *masking) Write(p []byte) (int, error) {
	m.held = append(m.held, p...)

	i := bytes.LastIndexFunc(
		m.held,
		func(r rune) bool { return !credentialRune(r) && r != '*' },
	)
	if i < 0 {
		return len(p), nil
	}

	// Cut after the whole rune, so the writer below sees no half of one.
	_, size := utf8.DecodeRune(m.held[i:])
	out := m.cred.masked(string(m.held[:i+size]))
	m.held = slices.Clone(m.held[i+size:])

	_, err := io.WriteString(m.w, out)

	return len(p), err
}

// Flush writes the word that waits.
func (m *masking) Flush() error {
	if len(m.held) == 0 {
		return nil
	}

	out := m.cred.masked(string(m.held))
	m.held = nil

	_, err := io.WriteString(m.w, out)

	return err
}

// The rule on the way in: a value typed on the line that has the form of a
// credential is not sent, so that a key pasted in the wrong place is not
// stored as a name, sent in a body, or answered back in a problem's
// details. It is refused before any call, with its kind and no more. A
// field whose type names the kind it takes, [TakesCredential], takes that
// kind only. A target is not a value: its lookup reads the word and puts
// none of it in a request. An owner's lookup holds its tags to the rule,
// and looks a user up. A path is not a value either: the CLI reads the
// file, it does not send the path.

// TakesCredential is the type of a value that is a credential of one kind,
// such as the ID of an auth request: Credential is the word after the
// Prefix.
type TakesCredential interface{ Credential() string }

var errCredentialKind = errors.New(
	"takes a kind of credential that is none of the program's Kinds",
)

// textField is a field of an input struct that holds text a request may
// carry: its index, the flag or argument as messages name it, and the kind
// of credential it takes, "" for none.
type textField struct {
	index      int
	word, kind string
}

// inputRule is the check of the rule on the way in for In, and the fields
// that take a kind of credential, which the tree checks against the
// program's kinds when it is built.
func inputRule[In any]() (
	func(*cmdline.Line, *Credentials) error,
	[]textField,
	error,
) {
	var kinds []textField

	t := reflect.TypeFor[In]()
	if t.Kind() != reflect.Struct {
		return func(*cmdline.Line, *Credentials) error { return nil },
			nil, nil
	}

	var (
		fields []textField
		errs   []error
	)

	for i, sf := range slices.Collect(t.Fields()) {
		word := "--" + sf.Tag.Get("flag")
		if arg := sf.Tag.Get("arg"); arg != "" {
			word = "<" + arg + ">"
		}

		ft := sf.Type
		if get, ok := ft.MethodByName("Get"); ok && get.Type.NumOut() == 2 {
			ft = get.Type.Out(0)
		}

		if ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}

		if ft.Kind() != reflect.String || ft == reflect.TypeFor[Path]() {
			continue
		}

		f := textField{index: i, word: word}

		if k, ok := reflect.TypeAssert[TakesCredential](reflect.Zero(ft)); ok {
			f.kind = k.Credential()
			kinds = append(kinds, f)
		}

		fields = append(fields, f)
	}

	return func(line *cmdline.Line, cr *Credentials) error {
		in, _ := cmdline.Get[In](line)
		v := reflect.ValueOf(in)

		for _, f := range fields {
			for _, s := range valuesOf(v.Field(f.index)) {
				err := cr.typed(f, s)
				if err != nil {
					return err
				}
			}
		}

		return nil
	}, kinds, errors.Join(errs...)
}

// checkKinds is what is wrong with kinds, the kinds of credential that the
// fields of a command take: one that is none of the program's.
func (cr *Credentials) checkKinds(kinds []textField) error {
	for _, f := range kinds {
		if !slices.Contains(cr.Kinds, f.kind) {
			return fmt.Errorf("%s %w", f.word, errCredentialKind)
		}
	}

	return nil
}

// Check refuses s, a value typed for word (--name, <owner>), when it holds
// a credential: a value that is sent is held to the rule on the way in.
func (cr *Credentials) Check(word, s string) error {
	return cr.typed(textField{word: word}, s)
}

// valuesOf are the words of a text field: none for an Opt not given, each
// item of a list.
func valuesOf(v reflect.Value) []string {
	if get := v.MethodByName("Get"); get.IsValid() && get.Type().NumOut() == 2 {
		out := get.Call(nil)
		if !out[1].Bool() {
			return nil
		}

		v = out[0]
	}

	if v.Kind() != reflect.Slice {
		return []string{v.String()}
	}

	out := make([]string, 0, v.Len())
	for i := range v.Len() {
		out = append(out, v.Index(i).String())
	}

	return out
}

// typed refuses s, the value of f, when it holds a credential f does not
// take.
func (cr *Credentials) typed(f textField, s string) error {
	var refused string

	cr.each(s, func(w string) string {
		// The kind is the word after the front's first dash, as in
		// tskey-client-.
		_, after, _ := strings.Cut(w, "-")

		kind, _, _ := strings.Cut(after, "-")
		if refused == "" && cr.kindOf(w) != w &&
			(f.kind == "" || !strings.EqualFold(kind, f.kind)) {
			refused = cr.kindOf(w)
		}

		return w
	})

	switch {
	case refused == "":
		return nil
	case f.kind == "":
		//nolint:err113,staticcheck // a sentence of the CLI
		return fmt.Errorf("%s takes no credential: %s is not sent.", f.word, refused)
	}

	//nolint:err113,staticcheck // a sentence of the CLI
	return fmt.Errorf(
		"%s takes only a credential %s%s-: %s is not sent.",
		f.word,
		cr.Prefix,
		f.kind,
		refused,
	)
}
