package newcli

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
)

var nodesGroup = command.Group{
	Name:     "nodes",
	Short:    "Manage nodes",
	OldNames: []string{"node"},
	Commands: []command.Node{
		nodesList,
		nodesGet,
		nodesSet,
		nodesExpire,
		nodesDelete,
		nodesUpdateClient,
		command.Group{
			Name:     "routes",
			Short:    "Manage the routes of a node",
			Commands: []command.Node{routesList, routesSet, routesClear},
		},
		command.Group{
			Name:     "tags",
			Short:    "Manage the tags of a node",
			Commands: []command.Node{tagsList, tagsSet},
		},
	},
}

var nodeColumns = table.Columns[clientv0.Node]{
	{Name: "id", Field: "id", Default: true, Help: "Node ID"},
	{
		Name:    "name",
		Field:   "name",
		Default: true,
		Help:    "Name in headscale (MagicDNS uses it)",
	},
	{Name: "owner", Field: "owner", Default: true, Help: "Owning user, or the tags"},
	{Name: "ip", Field: "addresses", Default: true, Help: "Tailnet IP addresses"},
	{
		Name:    "version",
		Field:   "clientVersion",
		Default: true,
		Kind:    table.Version,
		Help:    "Tailscale client version",
	},
	{
		Name:    "online",
		Field:   "connectedToControl",
		Default: true,
		Help:    "Whether the node is connected",
	},
	{Name: "last-seen", Field: "lastSeen", Default: true, Help: "Time of last contact"},
	//nolint:goconst // a column is named as its field
	{
		Name:    "expiry",
		Field:   "expiry",
		Default: true,
		Ahead:   true,
		Invalid: expiryInvalid,
		Help:    "When the node key expires",
	},
	{Name: "hostname", Field: "hostname", Help: "Hostname the node reports"},
	{Name: "os", Field: "os", Help: "Operating system"},
	{
		Name:   "enabled-routes",
		Field:  "enabledRoutes",
		Header: "enabled",
		List:   table.Stacked,
		Fold:   table.Exit(),
		Help:   "Routes the admin approved",
	},
	{
		Name:   "advertised-routes",
		Field:  "advertisedRoutes",
		Header: "advertised",
		List:   table.Stacked,
		Fold:   table.Exit(),
		Help:   "Routes the node announces",
	},
	{
		Name:   "serving-routes",
		Field:  "servingRoutes",
		Header: "serving",
		List:   table.Stacked,
		Fold:   table.Exit(),
		Help:   "Routes in use",
	},
	{
		Name:  "public-ip",
		Field: `attributes["ip:publicAddress"]`,
		Help:  "Last seen public address",
	},
	{Name: "ephemeral", Field: "ephemeral", Help: "Whether the node is ephemeral"},
	{
		Name:  "update-available",
		Field: "updateAvailable",
		Help:  "Whether a newer Tailscale client exists",
	},
	{
		Name:  "register-method",
		Field: "registerMethod",
		Help:  "How the node joined: authKey, cli or oidc",
	},
	{
		Name:  "auth-key",
		Field: "authKeyId",
		Kind:  table.ID,
		Help:  "ID of the auth key the node joined with",
	},
	{Name: "machine-key", Field: "machineKey", Help: "Machine key"},
	{Name: "node-key", Field: "nodeKey", Help: "Node key"},
	{Name: "disco-key", Field: "discoKey", Help: "Disco key"},
	//nolint:goconst // a column is named as its field
	{Name: "created", Field: "created", Help: "When the node registered"},
	{
		Name:  "problems",
		Field: "problems",
		Help:  "Health checks the node fails, by code, as debug health counts them",
	},
}

// routeColumns are the columns of nodes list, with the routes by default.
var routeColumns = func() table.Columns[clientv0.Node] {
	cols := slices.Clone(nodeColumns)
	for i := range cols {
		cols[i].Default = slices.Contains(
			[]string{
				"id",
				"name",
				"enabled-routes",
				"advertised-routes",
				"serving-routes",
			},
			cols[i].Name,
		)
	}

	return cols
}()

var nodeBlocks = table.Blocks[clientv0.Node]{{Title: "Attributes", Field: "attributes"}}

// expiryInvalid is a node whose stored expiry the API cannot send: its
// expiry is null, and its problems name it.
func expiryInvalid(
	n clientv0.Node,
) bool {
	return slices.Contains(n.Problems, "node_expiry_invalid")
}

// node names a node in a message, as tables show it.
func node(n clientv0.Node) string { return table.Entity("node", n.Id, n.Name) }

func visibleList(list []string) string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, table.Visible(s, ""))
	}

	return strings.Join(out, ", ")
}

var nodesList = command.NewList(command.ListSpec[command.NoInput, clientv0.Node]{
	Name:  "list",
	Short: "List the nodes",
	Long: `List every node, with its owner, addresses, client and times.

OWNER is the user that owns the node, or its tags: a node is owned by one
or the other. --filter owner=alice finds the nodes of a user, named as
users get names one; --filter owner=tag:ci the nodes with that tag.
PROBLEMS names the health checks a node fails, which debug health counts.

With -o json the command prints an array of the nodes as the API gives
them; --filter and --sort apply to it as to the table.`,
	Example: []string{
		"headscale nodes list",
		"headscale nodes list --columns +os,+hostname --sort -last-seen",
		"headscale nodes list --filter owner=alice -o json",
		"headscale nodes ls --filter 'last-seen>30d'",
		"headscale nodes list --filter 'version<1.80'",
		"headscale nodes list --filter problems=node_expiry_invalid",
	},
	Aliases: []string{"ls"},
	Columns: nodeColumns,
	NoRows:  "No nodes.",
	Run: func(c command.Ctx, _ command.NoInput) ([]clientv0.Node, error) {
		return c.API.ListNodesAll(
			c,
			&clientv0.ListNodesParams{PageSize: c.API.PageSize},
		)
	},
})

type nodeIn struct {
	Node clientv0.Node `arg:"node" help:"<node> is an ID, a tailnet IP, a name or a hostname."`
}

var nodesGet = command.New(command.Spec[nodeIn, clientv0.Node]{
	Name:  "get",
	Short: "Show one node",
	Long: `Show one node, with every column of nodes list and its attributes.

An ID wins, then a tailnet IP; the name and the hostname are searched
together, and a word that matches more than one node is an error that lists
them. Attributes are the node attributes of the server, under their
Tailscale names.

With -o json the command prints the node as the API gives it.`,
	Example: []string{
		"headscale nodes get mynode",
		"headscale nodes get 12 -o json",
		"headscale nodes get 100.64.0.12",
	},
	Columns: nodeColumns,
	Blocks:  nodeBlocks,
	Run:     func(_ command.Ctx, in nodeIn) (clientv0.Node, error) { return in.Node, nil },
})

// expiryOf is an expiry as the API takes it: the word now, a time, or
// null for never.
func expiryOf(
	e command.Expiry[command.NowNever],
	now time.Time,
) nullable.Nullable[string] {
	switch e.Word() {
	case "never":
		return nullable.NewNullNullable[string]()
	case "now":
		return nullable.NewNullableWithValue("now")
	}

	return nullable.NewNullableWithValue(e.At(now).UTC().Format(time.RFC3339))
}

type nodesSetIn struct {
	Node   clientv0.Node                                 `arg:"node"    help:"<node> is an ID, a tailnet IP, a name or a hostname."`
	Name   command.Opt[string]                           `flag:"name"   help:"New name of the node"`
	Expiry command.Opt[command.Expiry[command.NowNever]] `flag:"expiry" help:"New expiry of the node key"                           short:"e"`
}

var nodesSet = command.New(command.Spec[nodesSetIn, clientv0.Node]{
	Name:  "set",
	Short: "Change the name or expiry of a node",
	Long: `Change the name of a node, the expiry of its key, or both.

A flag you do not pass leaves the field alone, and at least one is needed.
--name "" gives the node the name made from its hostname again. --expiry
takes a time (2999-08-27T10:00:00Z), a date (midnight UTC), a duration from
now (90d), now, which expires the node like nodes expire, or never. A time
in the past is an error. Both fields change in one call, or neither does.

With -o json the command prints the node after the change.`,
	Example: []string{
		"headscale nodes set mynode --name web-1",
		"headscale nodes set mynode --expiry 2999-08-27T10:00:00Z",
		"headscale nodes set mynode --expiry 2999-08-27",
		"headscale nodes set mynode --expiry 90d",
		"headscale nodes set mynode --expiry now",
		"headscale nodes set mynode --expiry never",
		"headscale nodes set mynode --name web-1 --expiry never",
		"headscale nodes set 12 --name web-1 -o json | jq -r .name",
	},
	NeedsChange: true,
	Run: func(c command.Ctx, in nodesSetIn) (clientv0.Node, error) {
		body := clientv0.UpdateNodeBody{Name: set(in.Name)}

		if e, ok := in.Expiry.Get(); ok {
			body.Expiry = expiryOf(e, c.Now())
		}

		return clientv0.Got(
			c.API.UpdateNodeWithApplicationMergePatchPlusJSONBodyWithResponse(
				c,
				in.Node.Id,
				&clientv0.UpdateNodeParams{IfMatch: c.IfMatch(in.Node.Id)},
				body,
			),
		)
	},
	Done: func(in nodesSetIn, out clientv0.Node, now time.Time) string {
		var b strings.Builder

		subject := node(out)

		if name, ok := in.Name.Get(); ok {
			b.WriteString(node(out) + " was " + table.Visible(in.Node.Name, "") + ".")

			if name == "" {
				b.WriteString(" The name is made from its hostname again.")
			}

			subject = "It"
		}

		e, ok := in.Expiry.Get()
		if !ok {
			return b.String()
		}

		if b.Len() > 0 {
			b.WriteString(" ")
		}

		t, err := out.Expiry.Get()

		switch {
		case e.Word() == "now":
			b.WriteString(subject + " is now expired. It must log in again.")
		case err != nil:
			b.WriteString(subject + " does not expire.")
		default:
			b.WriteString(subject + " expires " + table.When(t, now) + ".")
		}

		return b.String()
	},
})

var nodesExpire = command.New(command.Spec[nodeIn, clientv0.Node]{
	Name:  "expire",
	Short: "Log a node out",
	Long: `Expire the key of a node now: the node is logged out and must log in
again. It keeps its record, so this can be undone by a new login. It does
the same as nodes set --expiry now, at the server's clock.

With -o json the command prints the node after the change.`,
	Example: []string{"headscale nodes expire mynode"},
	Run: func(c command.Ctx, in nodeIn) (clientv0.Node, error) {
		return clientv0.Got(c.API.ExpireNodeWithResponse(
			c,
			in.Node.Id,
			&clientv0.ExpireNodeParams{IfMatch: c.IfMatch(in.Node.Id)},
		))
	},
	Done: func(_ nodeIn, out clientv0.Node, _ time.Time) string {
		return node(out) + " is now expired. It must log in again."
	},
})

var nodesDelete = command.New(command.Spec[nodeIn, command.NoOutput]{
	Name:  "delete",
	Short: "Delete a node",
	Long: `Delete a node and its record. It cannot be undone: the node must be
registered again. The command asks first; --force does not ask.

With -o json the command prints nothing; the exit code says it worked.`,
	Example: []string{
		"headscale nodes delete mynode",
		"headscale nodes delete 12 --force",
	},
	Aliases: []string{"rm"},
	Confirm: func(_ command.Ctx, in nodeIn) (command.Prompt, error) {
		return command.Prompt{
			Question: "Delete " + node(
				in.Node,
			) + ", " + command.Owned(
				in.Node.Owner,
			) + "?",
			Action: "delete " + node(in.Node),
		}, nil
	},
	Run: func(c command.Ctx, in nodeIn) (command.NoOutput, error) {
		return command.NoOutput{}, clientv0.Done(c.API.DeleteNodeWithResponse(
			c,
			in.Node.Id,
			&clientv0.DeleteNodeParams{IfMatch: c.IfMatch(in.Node.Id)},
		))
	},
	Done: func(in nodeIn, _ command.NoOutput, _ time.Time) string { return node(in.Node) + " deleted." },
})

var nodesUpdateClient = command.New(command.Spec[nodeIn, clientv0.Node]{
	Name:  "update-client",
	Short: "Ask a node to update its Tailscale client",
	Long: `Ask a connected node to update its Tailscale client. The command ends
when the node started the update, not when it is done.

A node can refuse: when it is not connected, when it does not allow remote
updates (tailscale set --auto-update allows them), when its client refuses,
with the client's text, or when it does not answer in time.

With -o json the command prints the node.`,
	Example: []string{"headscale nodes update-client mynode"},
	Run: func(c command.Ctx, in nodeIn) (clientv0.Node, error) {
		return clientv0.Got(c.API.UpdateNodeClientWithResponse(c, in.Node.Id))
	},
	Done: func(_ nodeIn, out clientv0.Node, _ time.Time) string {
		return "Client update started on " + node(out) + "."
	},
})

type nodeViewIn struct {
	Node command.Opt[clientv0.Node] `arg:"node" help:"<node> narrows the list to one node: an ID, a tailnet IP, a name or a hostname."`
}

var routesList = command.NewList(command.ListSpec[nodeViewIn, clientv0.Node]{
	Name:  "list",
	Short: "List routes",
	Long: `List the nodes that have routes, with three route columns. ENABLED is
what the admin approved, ADVERTISED what the node announces, SERVING what is
in use. exit stands for the two exit routes, 0.0.0.0/0 and ::/0.

A node that has no enabled, advertised or serving route is left out. A
node argument shows that node alone. The view has every column of
nodes list.

With -o json the command prints an array of the nodes as the API gives
them.`,
	Example: []string{
		"headscale nodes routes list",
		"headscale nodes routes list mynode",
		"headscale nodes routes ls --filter enabled-routes=exit",
	},
	Aliases: []string{"ls"},
	Columns: routeColumns,
	NoRows:  "No nodes have routes.",
	Run: func(c command.Ctx, in nodeViewIn) ([]clientv0.Node, error) {
		if n, ok := in.Node.Get(); ok {
			return []clientv0.Node{n}, nil
		}

		nodes, err := c.API.ListNodesAll(
			c,
			&clientv0.ListNodesParams{PageSize: c.API.PageSize},
		)

		return slices.DeleteFunc(nodes, func(n clientv0.Node) bool {
			return len(
				n.EnabledRoutes,
			)+len(
				n.AdvertisedRoutes,
			)+len(
				n.ServingRoutes,
			) == 0
		}), err
	},
})

type routesSetIn struct {
	Node   clientv0.Node `arg:"node"   help:"<node> is an ID, a tailnet IP, a name or a hostname."`
	Routes []string      `arg:"routes" help:"<routes> are IP prefixes, comma separated; exit is 0.0.0.0/0 and ::/0."`
}

// clearHint names routes clear for the node of the line.
func clearHint(args []string) string {
	if len(args) == 0 || len(args) > 2 || args[0] == "" {
		return ""
	}

	return "To remove all routes: headscale nodes routes clear " + args[0]
}

var routesSet = command.New(command.Spec[routesSetIn, clientv0.Node]{
	Name:  "set",
	Short: "Replace the enabled routes of a node",
	Long: `Replace the enabled routes of a node with the given list. It does not
add: a route left out is no longer enabled. routes clear removes them all.

exit is the pair 0.0.0.0/0 and ::/0, an exit node, and mixes with subnet
routes. The server enables both when given one of them.

With -o json the command prints the node after the change.`,
	Example: []string{
		"headscale nodes routes set 12 10.0.0.0/8,192.168.0.0/24",
		"headscale nodes routes approve 12 10.0.0.0/8,192.168.0.0/24",
		"headscale nodes routes set 14 exit",
		"headscale nodes routes set 14 10.0.0.0/8,exit",
		"headscale nodes routes set 14 0.0.0.0/0",
	},
	Aliases: []string{"approve"},
	Hint:    clearHint,
	// Checked after the parser, so any word is still an argument of the
	// line, and before the lookup, so a bad route costs no call.
	Valid: func(in routesSetIn) error {
		for _, r := range in.Routes {
			p, err := netip.ParsePrefix(r)
			if r != "exit" && (err != nil || p.Masked() != p) {
				//nolint:err113,staticcheck // a sentence of the CLI
				return errors.New(
					strconv.Quote(
						r,
					) + " is not a route: a route is an IP prefix with no host bits, such as 10.0.0.0/8, or exit.",
				)
			}
		}

		return nil
	},
	Run: func(c command.Ctx, in routesSetIn) (clientv0.Node, error) {
		var routes []string

		for _, r := range in.Routes {
			if r == "exit" {
				routes = append(routes, table.Exit()["exit"]...)
			} else {
				routes = append(routes, r)
			}
		}

		return clientv0.Got(c.API.SetNodeRoutesWithResponse(
			c,
			in.Node.Id,
			&clientv0.SetNodeRoutesParams{IfMatch: c.IfMatch(in.Node.Id)},
			clientv0.SetNodeRoutesBody{Routes: routes},
		))
	},
	Done: func(_ routesSetIn, out clientv0.Node, _ time.Time) string {
		return node(
			out,
		) + " enabled routes: " + visibleList(
			table.Folded(out.EnabledRoutes, table.Exit()),
		) + "."
	},
})

var routesClear = command.New(command.Spec[nodeIn, clientv0.Node]{
	Name:  "clear",
	Short: "Remove all enabled routes of a node",
	Long: `Remove every enabled route of a node, the exit routes included. The
node keeps advertising its routes, so they can be enabled again.

With -o json the command prints the node after the change.`,
	Example: []string{"headscale nodes routes clear 12"},
	Run: func(c command.Ctx, in nodeIn) (clientv0.Node, error) {
		return clientv0.Got(c.API.SetNodeRoutesWithResponse(
			c,
			in.Node.Id,
			&clientv0.SetNodeRoutesParams{IfMatch: c.IfMatch(in.Node.Id)},
			clientv0.SetNodeRoutesBody{Routes: []string{}},
		))
	},
	Done: func(_ nodeIn, out clientv0.Node, _ time.Time) string {
		return node(out) + " has no enabled routes now."
	},
})

var tagColumns = table.Columns[clientv0.Tag]{
	{Name: "tag", Field: "tag", Default: true, Help: "Tag"},
	{Name: "count", Field: "nodeCount", Default: true, Help: "Nodes that have the tag"},
	{
		Name:    "in-policy",
		Field:   "inPolicy",
		Default: true,
		Help:    "Whether tagOwners of the policy names the tag",
	},
	{
		Name:    "nodes",
		Field:   "nodes",
		Default: true,
		List:    table.Cut,
		Help:    "Names of the nodes that have the tag",
	},
}

var tagsList = command.NewList(command.ListSpec[nodeViewIn, clientv0.Tag]{
	Name:  "list",
	Short: "List tags and their nodes",
	Long: `List every tag that the policy names or that a node has, one row per
tag: a tag no node has counts 0, and a tag that is gone from the policy
but still on a node is not in the policy.

A node argument keeps the rows of the tags that node has; COUNT and NODES
still cover every node.

NODES is truncated to fit your terminal. For all nodes of a tag:

  headscale nodes list --filter owner=tag:ci -o json | jq -r '.[].name'

With -o json the command prints an array of the tags as the API gives
them.`,
	Example: []string{
		"headscale nodes tags list",
		"headscale nodes tags list builder",
		"headscale nodes tags list builder -o json",
		"headscale nodes tags ls --filter in-policy=no",
	},
	Aliases: []string{"ls"},
	Columns: tagColumns,
	NoRows:  "No tags.",
	Run: func(c command.Ctx, in nodeViewIn) ([]clientv0.Tag, error) {
		// No node lists every tag.
		var node *string
		if n, ok := in.Node.Get(); ok {
			node = &n.Id
		}

		return c.API.ListTagsAll(
			c,
			&clientv0.ListTagsParams{PageSize: c.API.PageSize, Node: node},
		)
	},
})

type tagsSetIn struct {
	Node clientv0.Node `arg:"node" help:"<node> is an ID, a tailnet IP, a name or a hostname."`
	Tags []string      `arg:"tags" help:"<tags> are the tags, comma separated, each named in tagOwners of the policy."`
}

var tagsSet = command.New(command.Spec[tagsSetIn, clientv0.Node]{
	Name:  "set",
	Short: "Replace the tags of a node",
	Long: `Replace the tags of a node with the given list. A tag that tagOwners of
the policy does not name is refused.

A node is owned by a user or by its tags. Tagging a node that a user owns
ends that ownership for good, so the command asks first; --force does not
ask. A tagged node needs at least one tag.

With -o json the command prints the node after the change.`,
	Example: []string{
		"headscale nodes tags set 13 tag:ci,tag:build,tag:test",
		"headscale nodes tags set mynode tag:server --force",
	},
	EmptyList: "A tagged node needs at least one tag.",
	Confirm: func(_ command.Ctx, in tagsSetIn) (command.Prompt, error) {
		o, _ := in.Node.Owner.Get()
		if !o.User.IsSpecified() || o.User.IsNull() {
			return command.Prompt{}, nil
		}

		return command.Prompt{
			Question: node(
				in.Node,
			) + " is " + command.Owned(
				in.Node.Owner,
			) + ".\nTagging removes that ownership and cannot be undone.\nContinue?",
			Action: "tag " + node(in.Node),
		}, nil
	},
	Run: func(c command.Ctx, in tagsSetIn) (clientv0.Node, error) {
		return clientv0.Got(c.API.SetNodeTagsWithResponse(
			c,
			in.Node.Id,
			&clientv0.SetNodeTagsParams{IfMatch: c.IfMatch(in.Node.Id)},
			clientv0.SetNodeTagsBody{Tags: in.Tags},
		))
	},
	Done: func(_ tagsSetIn, out clientv0.Node, _ time.Time) string {
		o, _ := out.Owner.Get()

		return node(out) + " tags: " + visibleList(o.Tags) + "."
	},
})
