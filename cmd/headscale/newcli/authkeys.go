package newcli

import (
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

var authGroup = command.Group{
	Name:  "auth",
	Short: "Authentication of nodes to headscale",
	Commands: []command.Node{
		command.Group{
			Name:     "keys",
			Short:    "Manage auth keys",
			OldNames: []string{"preauthkeys", "preauth"},
			Commands: []command.Node{
				authKeysList,
				authKeysGet,
				authKeysCreate,
				authKeysDelete,
			},
		},
	},
}

var authKeyColumns = table.Columns[clientv0.AuthKey]{
	{Name: "id", Field: "id", Default: true, Help: "Auth key ID"},
	{
		Name:    "prefix",
		Field:   "prefix",
		Default: true,
		Help:    "The part of the key that is not secret",
	},
	{
		Name:    "owner",
		Field:   "owner",
		Default: true,
		Help:    "The user, or the tags, that a node joining with the key gets",
	},
	{Name: "state", Field: "state", Help: "valid, used, expired or revoked"},
	{
		Name:    "reusable",
		Field:   "reusable",
		Default: true,
		Help:    "Whether more than one node may join with the key",
	},
	{
		Name:    "ephemeral",
		Field:   "ephemeral",
		Default: true,
		Help:    "Whether a node that joins is removed some time after it disconnects",
	},
	//nolint:goconst // a column is named as its field
	{
		Name:    "expiry",
		Field:   "expiry",
		Default: true,
		Ahead:   true,
		Help:    "When the key stops working",
	},
	//nolint:goconst // a column is named as its field
	{Name: "created", Field: "created", Default: true, Help: "When the key was made"},
	{Name: "description", Field: "description", Help: "What the key is for"},
}

// authKey names an auth key in a message, as tables show it.
func authKey(
	k clientv0.AuthKey,
) string {
	return table.Entity("authKey", k.Id, k.Prefix)
}

var authKeysList = command.NewList(command.ListSpec[command.NoInput, clientv0.AuthKey]{
	Name:  "list",
	Short: "List the auth keys",
	Long: `List the auth keys that work: the ones in the state valid.

A key that is used (single-use, and a node joined with it), expired or
revoked is hidden; --all shows every key and adds the STATE column, and a
filter on state shows the keys it names. A revoked key is listed until the
server removes its record. No list shows the secret of a key; only auth
keys create prints it, once.

--filter owner=alice finds the keys of a user, named as users get names
one; --filter owner=tag:ci the keys for that tag.

With -o json the command prints an array of the keys as the API gives
them, the hidden ones left out as in the table.`,
	Example: []string{
		"headscale auth keys list",
		"headscale auth keys list --all",
		"headscale auth keys list --filter owner=tag:ci",
		"headscale auth keys list --filter state=expired",
		"headscale auth keys ls --filter 'expiry<7d' -o json",
	},
	Aliases: []string{"ls"},
	Columns: authKeyColumns,
	NoRows:  "No auth keys.",
	Only:    "state=valid",
	Run: func(c command.Ctx, _ command.NoInput) ([]clientv0.AuthKey, error) {
		return c.API.ListAuthKeysAll(
			c,
			&clientv0.ListAuthKeysParams{PageSize: c.API.PageSize},
		)
	},
})

type authKeyIn struct {
	Key clientv0.AuthKey `arg:"key" help:"<key> is an ID or a prefix; hskey-auth-<prefix>-*** names the key too."`
}

var authKeysGet = command.New(command.Spec[authKeyIn, clientv0.AuthKey]{
	Name:  "get",
	Short: "Show one auth key",
	Long: `Show the stored details of one auth key, in any state, with every column
of auth keys list. It never shows the secret: the server keeps only a hash
of it.

An ID wins over a prefix.

With -o json the command prints the key as the API gives it, with who made
it (createdBy), when it was revoked and when its record is removed.`,
	Example: []string{
		"headscale auth keys get ab12cd",
		"headscale auth keys get 7 -o json",
	},
	Columns: authKeyColumns,
	Run:     func(_ command.Ctx, in authKeyIn) (clientv0.AuthKey, error) { return in.Key, nil },
})

type authKeysCreateIn struct {
	Owner       command.Owner                   `arg:"owner"        help:"<owner> is a user (an ID, an email, a username or a provider identifier), or tags, comma separated, each named in tagOwners of the policy."`
	Reusable    bool                            `flag:"reusable"    help:"Let more than one node join with the key"`
	Ephemeral   bool                            `flag:"ephemeral"   help:"Remove a node that joined with the key some time after it disconnects"`
	Expiry      command.Expiry[command.NoWords] `default:"1h"       flag:"expiry"                                                                                                                                     help:"When the key stops working: a time, a date or a duration from now" short:"e"`
	Description string                          `flag:"description" help:"What the key is for, shown by list and get"                                                                                                 short:"d"`
}

var authKeysCreate = command.New(
	command.Spec[authKeysCreateIn, clientv0.CreatedAuthKey]{
		Name:  "create",
		Short: "Create an auth key",
		Long: `Create a key that lets a node join the tailnet. A node that joins with it
is owned by the owner of the key: a user, or tags, never both. A tag must
be in tagOwners of the policy.

--expiry says when the key expires, its default under Flags: a time
(2999-08-27T10:00:00Z), a date (midnight UTC) or a duration from now (90d).
A key must expire; there is no upper limit. A time in the past is an
error.

The key is printed on stdout, alone, so a script can capture it:

  KEY=$(headscale auth keys create tag:ci)

Its ID, owner and expiry go to stderr. This is the only time the key is
shown: the server keeps only a hash of it.

With -o json the command prints the new key as the API gives it, the
secret in the field key.`,
		Example: []string{
			"headscale auth keys create alice",
			"headscale auth keys create alice --reusable --expiry 24h",
			`headscale auth keys create tag:ci,tag:build --ephemeral -d "CI runners"`,
			"headscale auth keys create tag:ci --expiry 2999-08-27",
			"headscale auth keys create tag:ci -o json | jq -r .key",
		},
		Run: func(c command.Ctx, in authKeysCreateIn) (clientv0.CreatedAuthKey, error) {
			body := clientv0.CreateAuthKeyBody{
				Description: given(in.Description),
				Expiry:      new(in.Expiry.At(c.Now()).UTC()),
			}

			if u, ok := in.Owner.User(); ok {
				body.UserId = &u.Id
			} else {
				body.Tags = new(in.Owner.Tags())
			}

			if in.Reusable {
				body.Reusable = &in.Reusable
			}

			if in.Ephemeral {
				body.Ephemeral = &in.Ephemeral
			}

			return clientv0.Got(c.API.CreateAuthKeyWithResponse(c, body))
		},
		Secret: func(out clientv0.CreatedAuthKey) string { return out.Key },
		Done: func(_ authKeysCreateIn, out clientv0.CreatedAuthKey, now time.Time) string {
			var what []string

			if out.Reusable {
				what = append(what, "reusable")
			}

			if out.Ephemeral {
				what = append(what, "ephemeral")
			}

			t, err := out.Expiry.Get()
			if err == nil {
				what = append(what, "expires "+table.Ago(t, now))
			}

			owner, _ := command.OwnerName(out.Owner)

			return command.CreatedNote(
				table.Entity("authKey", out.Id, out.Prefix),
				owner,
				strings.Join(what, ", "),
				"key",
			)
		},
	},
)

var authKeysDelete = command.NewEnd(command.EndSpec[authKeyIn, clientv0.AuthKey]{
	Short: "Revoke an auth key",
	Long: `Revoke an auth key: it stops working at once. Nodes that joined with it
are not touched. The command asks first; --force does not ask.

The record stays, in the state revoked, so that list --all and get show
what was stopped. The server removes it after the retention time,
credentials.revoked_retention; a retention of 0 keeps
it, and so does a node that still refers to the key. Deleting a revoked key
succeeds and changes nothing, and does not ask.

With -o json the command prints the revoked key as the API gives it, with
removal, the time its record is removed; nothing when that read fails.`,
	Example: []string{
		"headscale auth keys delete 7",
		"headscale auth keys rm ab12cd --force",
		"headscale auth keys delete 7 --force -o json | jq -r .removal",
	},
	Target: func(in authKeyIn) clientv0.AuthKey { return in.Key },
	Of: func(k clientv0.AuthKey) command.Ended {
		return command.Ended{
			ID:      k.Id,
			Name:    authKey(k),
			Owned:   command.Owned(k.Owner),
			Revoked: k.Revoked,
			Removal: k.Removal,
		}
	},
	Revoke: func(c command.Ctx, id string) error { return clientv0.Done(c.API.DeleteAuthKeyWithResponse(c, id)) },
	Get: func(c command.Ctx, id string) (clientv0.AuthKey, error) {
		return clientv0.Got(c.API.GetAuthKeyWithResponse(c, id))
	},
	// An auth key lets a node join; no API call is made with one.
	NeverOwn: true,
})
