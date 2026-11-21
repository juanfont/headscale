package command

import (
	"bytes"
	"context"
	"net/netip"
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
		entityOf("authKey", findAuthKey, authKeyCandidates(), func(k clientv0.AuthKey) string { return k.Prefix }, nil),
		entityOf("apiKey", findAPIKey, apiKeyCandidates(), func(k clientv0.ApiKey) string { return k.Prefix }, nil),
		entityOf("oauthClient", findOAuthClient, oauthClientCandidates(), func(clientv0.OAuthClient) string { return "" }, nil),
		entityOf("node", findNode, nodeCandidates(), func(n clientv0.Node) string { return n.Name }, func(ctx context.Context, id string) (clientv0.Node, error) {
			return ctxOf(ctx).API.GetNode(ctx, id)
		}),
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

	u, err := resolve(users, word, word, "user", userCandidates(),
		func(u clientv0.User) string { return u.Id },
		func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
	)
	// No username has a colon: a tag where a user is wanted is a mistake of
	// the kind, which a command's hint may say more of.
	if err != nil && strings.HasPrefix(word, "tag:") {
		return u, &lookupError{text: "a tag is not a user.", hinted: true}
	}

	return u, err
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

// findNode is the node that word names: the node with that ID, else the
// node with that tailnet IP, else the one node whose name or hostname it is.
func findNode(ctx context.Context, word string) (clientv0.Node, error) {
	if word == "" {
		return clientv0.Node{}, emptyWord("node")
	}

	nodes, err := ctxOf(ctx).API.ListNodes(ctx)
	if err != nil {
		return clientv0.Node{}, err
	}

	// An IP is compared as an address, so fd7a:0::1 finds fd7a::1. No ID
	// reads as an address, so an ID still wins.
	ip, err := netip.ParseAddr(word)
	if err == nil {
		for _, n := range nodes {
			if slices.ContainsFunc(n.Addresses, func(a string) bool { b, err := netip.ParseAddr(a); return err == nil && b == ip }) {
				return n, nil
			}
		}
	}

	return resolve(nodes, word, word, "node", nodeCandidates(),
		func(n clientv0.Node) string { return n.Id },
		func(n clientv0.Node) []string { return []string{n.Name, n.Hostname} },
	)
}

// findAuthKey is the auth key that word names: the key with that ID, else
// the one whose prefix it is. A key as older output masks it names the key
// by its prefix; a whole key is refused before any call, so neither a
// request nor a message carries its secret.
func findAuthKey(ctx context.Context, word string) (clientv0.AuthKey, error) {
	if word == "" {
		return clientv0.AuthKey{}, emptyWord("auth key")
	}

	part, err := credentialWord(authKeyTyped(), word)
	if err != nil {
		return clientv0.AuthKey{}, err
	}

	keys, err := ctxOf(ctx).API.ListAuthKeys(ctx)
	if err != nil {
		return clientv0.AuthKey{}, err
	}

	return matchAuthKey(keys, part, word)
}

// typed is a kind of credential as a person types it to name one: the kind
// in its secret, the sentence that refuses the whole secret, the word for
// the part of it that names it, and whether its masked form names it: only
// a form that some output printed does.
type typed struct {
	kind, refused, part string
	masked              bool
}

func authKeyTyped() typed {
	return typed{"auth", "a key is named by its ID or its prefix, never by the whole key.", "prefix", true} //nolint:goconst // the word of a sentence
}

func apiKeyTyped() typed {
	t := authKeyTyped()
	t.kind = "api"

	return t
}

func oauthClientTyped() typed {
	return typed{"client", "an OAuth client is named by its ID, never by its secret.", "ID", false}
}

// credentialWord is the word that names a credential of kind k: the word,
// or the part of the masked form hskey-<kind>-<part>-*** that names it. A
// whole secret is refused before any call: matched by the part inside it,
// a wrong secret behind a right prefix would show a key that works, and
// delete would revoke it. The part is matched, never quoted: a secret typed
// in the masked form is a part that holds the secret, so a message names
// the word as it was typed, which the edge masks.
func credentialWord(k typed, word string) (string, error) {
	kind := hskey + k.kind + "-"

	if indexFold(word, hskey) != 0 {
		return word, nil
	}

	rest, ours := "", len(word) >= len(kind) && strings.EqualFold(word[:len(kind)], kind)
	if ours {
		rest = word[len(kind):]
	}

	if part, masked := strings.CutSuffix(rest, "-***"); masked && k.masked {
		return part, nil
	}

	text := k.refused

	// A secret of today is hskey-<kind>-<part>-<secret>, and its part is no
	// secret.
	if len(rest) > keyPrefixLength && rest[keyPrefixLength] == '-' {
		text += " Its " + k.part + " is " + rest[:keyPrefixLength] + "."
	}

	return "", &lookupError{text: text}
}

// keyPrefixLength is the length of the prefix of a key, and of the ID of
// an OAuth client, of today.
const keyPrefixLength = 12

// matchAuthKey is the key that part names; said is the word as typed.
func matchAuthKey(keys []clientv0.AuthKey, part, said string) (clientv0.AuthKey, error) {
	return resolve(keys, part, said, "auth key", authKeyCandidates(),
		func(k clientv0.AuthKey) string { return k.Id },
		func(k clientv0.AuthKey) []string { return []string{k.Prefix} },
	)
}

// authKeyCandidates are the columns of the keys an ambiguous word matches.
func authKeyCandidates() table.Columns[clientv0.AuthKey] {
	return table.Columns[clientv0.AuthKey]{
		{Name: "id", Field: "id", Default: true},
		{Name: "prefix", Field: "prefix", Default: true},
		{Name: "owner", Field: "owner", Default: true},
		{Name: "state", Field: "state", Default: true},
	}
}

// findAPIKey is the API key that word names: the key with that ID, else
// the one whose prefix it is, as findAuthKey.
func findAPIKey(ctx context.Context, word string) (clientv0.ApiKey, error) {
	if word == "" {
		return clientv0.ApiKey{}, emptyWord("API key")
	}

	part, err := credentialWord(apiKeyTyped(), word)
	if err != nil {
		return clientv0.ApiKey{}, err
	}

	keys, err := ctxOf(ctx).API.ListAPIKeys(ctx)
	if err != nil {
		return clientv0.ApiKey{}, err
	}

	return resolve(keys, part, word, "API key", apiKeyCandidates(),
		func(k clientv0.ApiKey) string { return k.Id },
		func(k clientv0.ApiKey) []string { return []string{k.Prefix} },
	)
}

// apiKeyCandidates are the columns of the keys an ambiguous word matches.
func apiKeyCandidates() table.Columns[clientv0.ApiKey] {
	return table.Columns[clientv0.ApiKey]{
		{Name: "id", Field: "id", Default: true},
		{Name: "prefix", Field: "prefix", Default: true},
		{Name: "owner", Field: "owner", Default: true},
		{Name: "state", Field: "state", Default: true},
	}
}

// findOAuthClient is the OAuth client whose ID word is. The list is walked
// so that no word, a secret pasted by mistake least of all, is put in a
// path.
func findOAuthClient(ctx context.Context, word string) (clientv0.OAuthClient, error) {
	if word == "" {
		return clientv0.OAuthClient{}, emptyWord("OAuth client")
	}

	_, err := credentialWord(oauthClientTyped(), word)
	if err != nil {
		return clientv0.OAuthClient{}, err
	}

	clients, err := ctxOf(ctx).API.ListOAuthClients(ctx)
	if err != nil {
		return clientv0.OAuthClient{}, err
	}

	return resolve(clients, word, word, "OAuth client", oauthClientCandidates(),
		func(o clientv0.OAuthClient) string { return o.Id },
		func(clientv0.OAuthClient) []string { return nil },
	)
}

// oauthClientCandidates are the columns of a client; an ID matches one
// client at most, so no list of candidates shows them.
func oauthClientCandidates() table.Columns[clientv0.OAuthClient] {
	return table.Columns[clientv0.OAuthClient]{
		{Name: "id", Field: "id", Default: true},
		{Name: "description", Field: "description", Default: true},
	}
}

// nodeCandidates are the columns of the nodes an ambiguous word matches.
func nodeCandidates() table.Columns[clientv0.Node] {
	return table.Columns[clientv0.Node]{
		{Name: "id", Field: "id", Default: true},
		{Name: "name", Field: "name", Default: true},
		{Name: "hostname", Field: "hostname", Default: true},
		{Name: "owner", Field: "owner", Default: true},
	}
}

// resolve finds the one row that word names. An exact ID ends the search.
// Otherwise every row that word equals in any of its fields is a match,
// once however many fields it matches in; more than one is an error that
// lists them, with the default columns of cols, and each other column of
// cols that word equals in a candidate, so the list says why it matched.
// The errors quote said, the word as the person typed it.
func resolve[T any](rows []T, word, said, kind string, cols table.Columns[T], id func(T) string, fields func(T) []string) (T, error) {
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
		return zero, &lookupError{text: "no " + kind + " matches " + strconv.Quote(said) + "."}
	}

	var b bytes.Buffer

	// The candidates show no time, so no clock is needed.
	_ = table.Render(&b, matches, cols.Showing(matches, word), time.Time{}, nil)

	var list strings.Builder

	for line := range strings.Lines(b.String()) {
		list.WriteString("  " + line)
	}

	return zero, &lookupError{text: strconv.Quote(said) + " matches " + strconv.Itoa(len(matches)) + " " + kind + "s. Use the ID to select one:\n\n" +
		strings.TrimSuffix(list.String(), "\n")}
}

// lookupError is a word that names no entity, or more than one. hinted is
// a word of another kind, which the command's hint follows.
type lookupError struct {
	text   string
	hinted bool
}

func (e *lookupError) Error() string { return e.text }
