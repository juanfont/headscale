package command

import (
	"context"
	"net/netip"
	"slices"

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
