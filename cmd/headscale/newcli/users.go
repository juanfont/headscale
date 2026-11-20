package newcli

import (
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

var usersGroup = command.Group{
	Name:     "users",
	Short:    "Manage users",
	OldNames: []string{"user"},
	Commands: []command.Node{usersList, usersGet, usersCreate, usersSet, usersDelete},
}

var userColumns = table.Columns[clientv0.User]{
	{Name: "id", Field: "id", Default: true, Help: "User ID"},
	{Name: "name", Field: "name", Default: true, Help: "Username; empty for some users from OIDC"},
	{Name: "display-name", Field: "displayName", Default: true, Help: "Display name"},
	{Name: "email", Field: "email", Default: true, Help: "Email address"},
	{Name: "provider", Field: "provider", Default: true, Help: "Where the user comes from: local or oidc"},
	{Name: "count", Field: "nodeCount", Default: true, Help: "Nodes the user owns, tagged nodes not counted"},
	{Name: "nodes", Field: "nodes", Default: true, List: table.Cut, Help: "Names of the nodes the user owns"},
	{Name: "login-name", Field: "loginName", Help: "What headscale shows for the user: the email, else the username, else the provider identifier"},
	{Name: "profile-pic-url", Field: "profilePicUrl", Help: "URL of the profile picture"},
	{Name: "provider-id", Field: "providerId", Kind: table.Text, Help: "Identifier at the identity provider"},
	{Name: "created", Field: "created", Help: "When the user was created"}, //nolint:goconst // a column is named as its field
}

// user names a user in a message, as tables show it.
func user(u clientv0.User) string { return table.Entity("user", u.Id, u.LoginName) }

var usersList = command.NewList(command.ListSpec[command.NoInput, clientv0.User]{
	Name:  "list",
	Short: "List the users",
	Long: `List every user, local and from OIDC, with the nodes each one owns.

NAME is the stored username; a user from OIDC can have none. COUNT and
NODES are the nodes the user owns; a tagged node is owned by its tags and
is in neither.

NODES is truncated to fit your terminal. For all nodes of a user:

  headscale users get carol -o json | jq -r '.nodes[].name'

With -o json the command prints an array of the users as the API gives
them; --filter and --sort apply to it as to the table.`,
	Example: []string{
		"headscale users list",
		"headscale users list --filter provider=oidc --sort -count",
		"headscale users ls --columns +login-name,-nodes",
		"headscale users list --filter email=carol@example.com -o json",
	},
	Aliases: []string{"ls"},
	Columns: userColumns,
	NoRows:  "No users.",
	Run: func(c command.Ctx, _ command.NoInput) ([]clientv0.User, error) {
		return c.API.ListUsers(c)
	},
})

type usersGetIn struct {
	User clientv0.User `arg:"user" help:"<user> is an ID, an email, a username or a provider identifier."`
}

var usersGet = command.New(command.Spec[usersGetIn, clientv0.User]{
	Name:  "get",
	Short: "Show one user",
	Long: `Show one user, with every column of users list.

An ID wins; the email, the username and the provider identifier are
searched together, and a word that matches more than one user is an error
that lists them.

With -o json the command prints the user as the API gives it.`,
	Example: []string{
		"headscale users get alice",
		"headscale users get carol@example.com -o json",
	},
	Columns: userColumns,
	Run: func(_ command.Ctx, in usersGetIn) (clientv0.User, error) {
		return in.User, nil
	},
})

type usersCreateIn struct {
	Name          string `arg:"name"`
	DisplayName   string `flag:"display-name" help:"Display name"`
	Email         string `flag:"email"        help:"Email address"`
	ProfilePicURL string `flag:"picture-url"  help:"Profile picture: an absolute http or https URL"`
}

var usersCreate = command.New(command.Spec[usersCreateIn, clientv0.User]{
	Name:  "create",
	Short: "Create a local user",
	Long: `Create a local user with a username.

The server checks the values: the username, --email as one address, and
--picture-url as an absolute http or https URL. A username or an email
that equals the username, the email or the provider identifier of another
user, in any case, is refused: a policy names a user by these texts.

With -o json the command prints the new user.`,
	Example: []string{
		"headscale users create dave",
		`headscale users create dave --display-name "Dave D" --email dave@example.com`,
	},
	Run: func(c command.Ctx, in usersCreateIn) (clientv0.User, error) {
		return c.API.CreateUser(c, clientv0.CreateUserBody{
			Name:          in.Name,
			DisplayName:   given(in.DisplayName),
			Email:         given(in.Email),
			ProfilePicUrl: given(in.ProfilePicURL),
		})
	},
	Done: func(_ usersCreateIn, out clientv0.User, _ time.Time) string {
		return user(out) + " created."
	},
})

// given is a field of a create: left out when the flag gives nothing.
func given(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}

type usersSetIn struct {
	User          clientv0.User       `arg:"user"          help:"<user> is an ID, an email, a username or a provider identifier."`
	Name          command.Opt[string] `flag:"name"         help:"New username"`
	DisplayName   command.Opt[string] `flag:"display-name" help:"New display name; \"\" clears it"`
	Email         command.Opt[string] `flag:"email"        help:"New email address; \"\" clears it"`
	ProfilePicURL command.Opt[string] `flag:"picture-url"  help:"New profile picture URL; \"\" clears it"`
}

var usersSet = command.New(command.Spec[usersSetIn, clientv0.User]{
	Name:  "set",
	Short: "Change a local user",
	Long: `Change any field of a local user, the username included.

A flag you do not pass leaves the field alone, and at least one is needed.
An empty value clears the field; a user needs a username, so --name ""
is refused. The server checks the values as for users create. All given
fields change in one call, or none do. An OAuth access token cannot change
the username or the email; an API key can.

A user from OIDC is refused: the identity provider owns its fields, and the
next login would overwrite them.

With -o json the command prints the user after the change.`,
	Example: []string{
		`headscale users set alice --display-name "Alice A" --email a@b.c`,
		"headscale users set alice --name alice2",
		"headscale users set 3 --name alice2 --email a@b.c",
		`headscale users set alice --picture-url ""`,
	},
	NeedsChange: true,
	Run: func(c command.Ctx, in usersSetIn) (clientv0.User, error) {
		return c.API.UpdateUser(c, in.User.Id, clientv0.UpdateUserBody{
			Name:          set(in.Name),
			DisplayName:   set(in.DisplayName),
			Email:         set(in.Email),
			ProfilePicUrl: set(in.ProfilePicURL),
		})
	},
	Done: func(in usersSetIn, out clientv0.User, _ time.Time) string {
		var changed []string

		for _, f := range []struct {
			flag command.Opt[string]
			word string
		}{{in.Name, "name"}, {in.DisplayName, "display name"}, {in.Email, "email"}, {in.ProfilePicURL, "picture URL"}} {
			if _, ok := f.flag.Get(); ok {
				changed = append(changed, f.word)
			}
		}

		return user(out) + " updated: " + strings.Join(changed, ", ") + "."
	},
})

// set is a field of a merge patch: left out when the flag is not given.
func set(o command.Opt[string]) *string {
	v, ok := o.Get()
	if !ok {
		return nil
	}

	return &v
}

type usersDeleteIn struct {
	User      clientv0.User `arg:"user"        help:"<user> is an ID, an email, a username or a provider identifier."`
	WithNodes bool          `flag:"with-nodes" help:"Delete the nodes of the user too"`
}

// ownUser follows the question when the CLI calls with an API key of the
// user: the key goes with the user.
const ownUser = "This CLI calls with an API key of this user: once the user is deleted, the server refuses the CLI."

var usersDelete = command.New(command.Spec[usersDeleteIn, clientv0.DeletedUser]{
	Name:  "delete",
	Short: "Delete a user with its keys",
	Long: `Delete a user together with its auth keys and its API keys, revoked and
expired ones too, so the counts may be more than the lists show by default.
Tagged keys and OAuth clients the user made stay.

A user who still owns nodes is refused; --with-nodes deletes the nodes too.
It is one step on the server: all of it, or nothing.

The command asks the server first what the delete would remove, and shows
it: the nodes by name, and the keys counted. The delete then removes only
what was shown. When that changed in between, nothing is removed, and the
command asks again with what is there now; with --force it tries once more
without asking. A second change is an error. A node or a key that comes or
goes is a change; a rename, an expiry or a revoke is not.

With -o json the command prints what was removed.`,
	Example: []string{
		"headscale users delete bob",
		"headscale users delete alice --with-nodes",
		"headscale users delete alice --with-nodes --force",
	},
	Aliases: []string{"rm"},
	Changed: clientv0.ProblemCodeUserChanged,
	Confirm: func(c command.Ctx, in usersDeleteIn) (command.Prompt, error) {
		d, err := c.API.DeleteUser(c, in.User.Id, in.WithNodes, true)
		if err != nil {
			return command.Prompt{}, err
		}

		names := make([]string, 0, len(d.Nodes))
		for _, n := range d.Nodes {
			names = append(names, n.Name)
		}

		q := "Delete " + user(in.User)
		if r := removed(d); r != "" {
			q += ", " + r
		}

		return command.Prompt{
			Question: q + "?",
			Action:   "delete " + user(in.User),
			List:     names,
			Guard:    d.Expect,
			Warning: command.OwnWarning(c, ownUser, func(me clientv0.Me) bool {
				cred, err := me.Credential.Get()
				if err != nil || cred.Kind != clientv0.CredentialKindApiKey {
					return false
				}

				o, err := cred.Owner.Get()
				if err != nil {
					return false
				}

				u, err := o.User.Get()

				return err == nil && u.Id == in.User.Id
			}),
		}, nil
	},
	Run: func(c command.Ctx, in usersDeleteIn) (clientv0.DeletedUser, error) {
		out, err := c.API.DeleteUser(c, in.User.Id, in.WithNodes, false)

		// A second try would say no user matches: say how to tell.
		return out, command.MayBeMade(err, "To look: headscale users get "+in.User.Id+"\n"+
			"If no user matches, the delete was made.\n"+
			"The delete removes all of it or nothing: a user that is still there lost nothing.")
	},
	Done: func(in usersDeleteIn, out clientv0.DeletedUser, _ time.Time) string {
		if r := removed(out); r != "" {
			return user(in.User) + " deleted with " + r + "."
		}

		return user(in.User) + " deleted."
	},
})

// removed is what a delete of a user removes beside it, counted: "3 nodes
// and 2 auth keys"; a count of zero is left out.
func removed(d clientv0.DeletedUser) string {
	var parts []string

	for _, c := range []struct {
		n    int
		noun string
	}{{len(d.Nodes), "node"}, {int(d.AuthKeyCount), "auth key"}, {int(d.ApiKeyCount), "API key"}} {
		if c.n > 0 {
			parts = append(parts, table.Count(c.n, c.noun))
		}
	}

	if len(parts) < 2 {
		return strings.Join(parts, "")
	}

	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}
