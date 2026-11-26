package command

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	lib "github.com/juanfont/headscale/cmdline/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

// entities are the entities of Headscale. A function, not a variable, so
// no test or command can change what another tree sees.
func entities() []lib.Entity {
	return []lib.Entity{
		lib.EntityOf(
			"user",
			findUser,
			userCandidates(),
			func(u clientv0.User) string { return u.LoginName },
			nil,
		),
		lib.EntityOf(
			"authKey",
			findAuthKey,
			authKeyCandidates(),
			func(k clientv0.AuthKey) string { return k.Prefix },
			nil,
		),
		lib.EntityOf(
			"node",
			findNode,
			nodeCandidates(),
			func(n clientv0.Node) string { return n.Name },
			func(ctx context.Context, id string) (clientv0.Node, error) {
				api := lib.CtxOf[*API](ctx).API
				n, err := clientv0.Got(api.GetNodeWithResponse(ctx, id))

				return n, api.errorOf(err)
			},
		),
	}
}

// findUser is the user that word names: the user with that ID, else the one
// user whose email, username or provider identifier it is.
func findUser(ctx context.Context, word string) (clientv0.User, error) {
	if word == "" {
		return clientv0.User{}, lib.EmptyWord("user")
	}

	api := lib.CtxOf[*API](ctx).API

	users, err := api.ListUsersAll(
		ctx,
		&clientv0.ListUsersParams{PageSize: api.PageSize},
	)
	if err != nil {
		err = api.errorOf(err)

		return clientv0.User{}, err
	}

	return lib.Resolve(
		users,
		word,
		word,
		"user",
		userCandidates(),
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

// findNode is the node that word names: the node with that ID, else the
// node with that tailnet IP, else the one node whose name or hostname it is.
func findNode(ctx context.Context, word string) (clientv0.Node, error) {
	if word == "" {
		return clientv0.Node{}, lib.EmptyWord("node")
	}

	api := lib.CtxOf[*API](ctx).API

	nodes, err := api.ListNodesAll(
		ctx,
		&clientv0.ListNodesParams{PageSize: api.PageSize},
	)
	if err != nil {
		err = api.errorOf(err)

		return clientv0.Node{}, err
	}

	// An IP is compared as an address, so fd7a:0::1 finds fd7a::1. No ID
	// reads as an address, so an ID still wins.
	ip, err := netip.ParseAddr(word)
	if err == nil {
		for _, n := range nodes {
			at := func(a string) bool {
				b, err := netip.ParseAddr(a)

				return err == nil && b == ip
			}
			if slices.ContainsFunc(n.Addresses, at) {
				return n, nil
			}
		}
	}

	return lib.Resolve(nodes, word, word, "node", nodeCandidates(),
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
		return clientv0.AuthKey{}, lib.EmptyWord("auth key")
	}

	part, err := credentialWord(authKeyTyped(), word)
	if err != nil {
		return clientv0.AuthKey{}, err
	}

	api := lib.CtxOf[*API](ctx).API

	keys, err := api.ListAuthKeysAll(
		ctx,
		&clientv0.ListAuthKeysParams{PageSize: api.PageSize},
	)
	if err != nil {
		err = api.errorOf(err)

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
	//nolint:goconst // the word of a sentence
	return typed{
		"auth",
		"a key is named by its ID or its prefix, never by the whole key.",
		"prefix",
		true,
	}
}

// credentialWord is the word that names a credential of kind k: the word,
// or the part of the masked form hskey-<kind>-<part>-*** that names it. A
// whole secret is refused before any call: matched by the part inside it,
// a wrong secret behind a right prefix would show a key that works, and
// delete would revoke it. The part is matched, never quoted: a secret typed
// in the masked form is a part that holds the secret, so a message names
// the word as it was typed, which the edge masks.
func credentialWord(k typed, word string) (string, error) {
	cr := credentials()
	if at, _ := cr.At(word); at != 0 {
		return word, nil
	}

	// The kind is the word after the front's first dash: hskey-client- and
	// tskey-client- both name a client.
	_, after, _ := strings.Cut(word, "-")
	kind, rest, _ := strings.Cut(after, "-")

	if !strings.EqualFold(kind, k.kind) {
		rest = ""
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

	return "", &lib.LookupError{Text: text}
}

// keyPrefixLength is the length of the prefix of a key, and of the ID of
// an OAuth client, of today.
const keyPrefixLength = 12

// matchAuthKey is the key that part names; said is the word as typed.
func matchAuthKey(
	keys []clientv0.AuthKey,
	part, said string,
) (clientv0.AuthKey, error) {
	return lib.Resolve(keys, part, said, "auth key", authKeyCandidates(),
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
