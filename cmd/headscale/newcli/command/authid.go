package command

import (
	"errors"
	"strings"
)

// AuthID is the ID of an auth request, typed whole: a secret that lets
// whoever holds it put a machine into the tailnet. It is no entity, so no
// lookup reads it and Tab offers nothing; it goes to the server in the path
// of the request it names and in no other.
type AuthID string

func (AuthID) Credential() string { return "authreq" }

// UnmarshalText takes any word; the input rule checks it whole, so that a
// word of another kind gets that rule's sentence. The URL the node shows
// ends in the ID, and a person pastes it whole: the ID is taken from it, and
// nothing else of it is kept, so no request or message carries the rest.
func (a *AuthID) UnmarshalText(b []byte) error {
	s := string(b)
	if i := strings.LastIndex(s, "/"+authIDPrefix); i >= 0 {
		s = s[i+1:]
	}

	*a = AuthID(s)

	return nil
}

// errNotAuthID: the form of an auth ID is not part of the API, which calls
// it opaque. The CLI takes only a word the edge masks whole.
var errNotAuthID = errors.New(
	"is not an auth ID: it starts with hskey-authreq-, as the end of the URL the node shows",
)

// maxAuthID is the longest auth ID the CLI takes. One of today is 38
// characters; the bound leaves room for a longer random part and refuses
// what is plainly more than one ID, such as two pasted together.
const maxAuthID = 100

func (AuthID) Whole(s string) error {
	cr := credentials()

	rest, ok := strings.CutPrefix(s, authIDPrefix)
	if !ok || len(s) > maxAuthID || !cr.MaskedWhole(rest) {
		return errNotAuthID
	}

	return nil
}

const authIDPrefix = hskey + "authreq-"
