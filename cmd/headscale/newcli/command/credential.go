package command

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// The rule at the edge: a word that has the form of a Headscale credential,
// hskey- in any case and anywhere in a word, leaves the CLI as its kind
// and no more, hskey-auth-***. Run holds it on stdout and stderr, so no
// error, note, prompt, cell or sheet line repeats a secret, whether the
// server sent it or a person typed it. The JSON of a result is the server's
// data, not the CLI's sentence, and is written as it came, past the rule.
//
// A key from before 0.28 is 48 hex characters with no hskey-: it has no
// form to tell it from other text, and the rule does not see it.

// credentialKinds are the words after hskey- that name a kind of
// credential; any other word may be part of a secret, so it is not shown.
func credentialKinds() []string {
	return []string{"auth", "api", "authreq", "client", "oauthtok", "reg"}
}

const hskey = "hskey-"

// masked is s with every credential in it written as its kind. A word
// that holds no more than the kind, such as hskey-auth- in a help text,
// stays as it is.
func masked(s string) string {
	var b strings.Builder

	for {
		i := indexFold(s, hskey)
		if i < 0 {
			b.WriteString(s)

			return b.String()
		}

		j := i + len(hskey)
		for j < len(s) && credentialRune(rune(s[j])) {
			j++
		}

		// The masked form of older output, hskey-auth-<prefix>-***.
		if strings.HasPrefix(s[j:], "***") {
			j += 3
		}

		b.WriteString(s[:i])
		b.WriteString(kindOf(s[i:j]))
		s = s[j:]
	}
}

// kindOf is the credential w as it may be shown.
func kindOf(w string) string {
	rest := strings.TrimSuffix(w[len(hskey):], "***")
	kind, after, _ := strings.Cut(rest, "-")

	switch {
	case !slices.Contains(credentialKinds(), strings.ToLower(kind)):
		if rest == "" {
			return w
		}

		return hskey + "***"
	case after == "":
		return w
	}

	return hskey + strings.ToLower(kind) + "-***"
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
	return c == '-' || c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// masking writes through masked. A write can end inside a word, so the
// word waits for the next write or for Flush.
type masking struct {
	w    io.Writer
	held []byte
}

func (m *masking) Write(p []byte) (int, error) {
	m.held = append(m.held, p...)

	i := bytes.LastIndexFunc(m.held, func(r rune) bool { return !credentialRune(r) && r != '*' })
	if i < 0 {
		return len(p), nil
	}

	// Cut after the whole rune, so the writer below sees no half of one.
	_, size := utf8.DecodeRune(m.held[i:])
	out := masked(string(m.held[:i+size]))
	m.held = slices.Clone(m.held[i+size:])

	_, err := io.WriteString(m.w, out)

	return len(p), err
}

// Flush writes the word that waits.
func (m *masking) Flush() error {
	if len(m.held) == 0 {
		return nil
	}

	out := masked(string(m.held))
	m.held = nil

	_, err := io.WriteString(m.w, out)

	return err
}
