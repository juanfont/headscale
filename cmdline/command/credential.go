package command

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
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
