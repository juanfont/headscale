package newcli

import (
	"cmp"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

var apiGroup = command.Group{
	Name:  "api",
	Short: "Authentication towards the headscale API",
	Commands: []command.Node{
		apiWhoami,
		command.Group{
			Name:  "keys",
			Short: "Manage API keys",
			Commands: []command.Node{
				apiKeysList,
				apiKeysGet,
				apiKeysCreate,
				apiKeysDelete,
			},
		},
		command.Group{
			Name:  "oauth-clients",
			Short: "Manage OAuth clients",
			Commands: []command.Node{
				oauthClientsList,
				oauthClientsGet,
				oauthClientsCreate,
				oauthClientsDelete,
			},
		},
	},
}

var apiWhoami = command.New(command.Spec[command.NoInput, clientv0.Me]{
	Name:  "whoami",
	Short: "Show who the server sees calling",
	Long: `Show who the server sees calling: who or what the call is from (the
principal), how the call is proven (the credential), and what the server
lets it do.

The key owner is not who is calling: it is the user recorded on the API
key. "Tags: any" means that tags do not limit the caller; a token shows the
tags it may give out, and none when it may give no tag. A line that does
not apply is left out: the socket has no credential.

With -o json the command prints the answer of GET /me as it is.`,
	Example: []string{
		"headscale api whoami",
		"headscale api whoami -o json",
	},
	Run: func(c command.Ctx, _ command.NoInput) (clientv0.Me, error) {
		return clientv0.Got(c.API.GetMeWithResponse(c))
	},
	Done: whoami,
})

// whoami is a report, not the sheet of an entity: one line for each part of
// GET /me, with its words as labels, several of them made of more than one
// field. A later kind of login only adds lines.
func whoami(_ command.NoInput, me clientv0.Me, now time.Time) string {
	var b strings.Builder

	line := func(label, value string) {
		b.WriteString(label + ":" + strings.Repeat(" ", 12-len(label)) + value + "\n")
	}

	principals := map[clientv0.PrincipalKind]string{
		clientv0.PrincipalKindApiKey:      "API key",
		clientv0.PrincipalKindOauthClient: "OAuth client",
		clientv0.PrincipalKindLocal:       "local (unix socket)",
	}
	line(
		"Principal",
		cmp.Or(
			principals[me.Principal.Kind],
			table.Visible(string(me.Principal.Kind), ""),
		),
	)

	cred, err := me.Credential.Get()
	hasCred := err == nil

	if hasCred {
		line("Credential", table.Entity(string(cred.Kind), cred.Id, cred.Prefix))

		if cred.Kind == clientv0.CredentialKindApiKey {
			line("Key owner", keyOwner(cred))
		}

		client, err := cred.Client.Get()
		if err == nil {
			line("Client", table.Visible(client.Id, "")+described(client.Description))
		}
	}

	line("Scopes", table.Visible(strings.Join(me.Authorization.Scopes, ", "), ""))

	tags, err := me.Authorization.Tags.Get()

	switch {
	case err != nil:
		line("Tags", "any")
	case len(tags) == 0:
		line("Tags", "none")
	default:
		line("Tags", table.Visible(strings.Join(tags, ", "), ""))
	}

	line("Resources", table.Visible(string(me.Authorization.Resources), ""))

	if hasCred {
		expiry, _ := cred.Expiry.Get()
		line("Expiry", table.When(expiry, now))
	}

	return b.String()
}

// keyOwner is the user recorded on an API key; the line applies to every
// API key, so a key with no owner says none.
func keyOwner(cred clientv0.Credential) string {
	o, err := cred.Owner.Get()
	if err != nil {
		return "none"
	}

	u, err := o.User.Get()
	if err == nil {
		return table.Entity("user", u.Id, u.LoginName)
	}

	if len(o.Tags) > 0 {
		return table.Visible(strings.Join(o.Tags, ", "), "")
	}

	return "none"
}

func described(d string) string {
	if d == "" {
		return ""
	}

	return " (" + table.Visible(d, "") + ")"
}

var apiKeyColumns = table.Columns[clientv0.APIKey]{
	{Name: "id", Field: "id", Default: true, Help: "API key ID"},
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
		Help:    "The user recorded on the key; it does not limit what the key may do",
	},
	{Name: "state", Field: "state", Help: "valid, expired or revoked"},
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
	{
		Name:    "last-seen",
		Field:   "lastSeen",
		Default: true,
		Help:    "When the key was last used, to the minute",
	},
}

// apiKey names an API key in a message, as tables show it.
func apiKey(k clientv0.APIKey) string { return table.Entity("apiKey", k.Id, k.Prefix) }

var apiKeysList = command.NewList(command.ListSpec[command.NoInput, clientv0.APIKey]{
	Name:  "list",
	Short: "List the API keys",
	Long: `List the API keys that work: the ones in the state valid.

An expired or revoked key is hidden; --all shows every key and adds the
STATE column, and a filter on state shows the keys it names. A revoked key
is listed until the server removes its record. No list shows the secret
of a key; only api keys create prints it, once.

OWNER is the user recorded on the key, - for none; every API key may do
everything, with or without an owner. LAST SEEN is when the key was last
used, to the minute.

With -o json the command prints an array of the keys as the API gives
them, the hidden ones left out as in the table.`,
	Example: []string{
		"headscale api keys list",
		"headscale api keys list --all",
		"headscale api keys list --filter owner=alice",
		"headscale api keys ls --filter 'last-seen>30d' -o json",
	},
	Aliases: []string{"ls"},
	Columns: apiKeyColumns,
	NoRows:  "No API keys.",
	Only:    "state=valid",
	Run: func(c command.Ctx, _ command.NoInput) ([]clientv0.APIKey, error) {
		return c.API.ListAPIKeysAll(
			c,
			&clientv0.ListAPIKeysParams{PageSize: c.API.PageSize},
		)
	},
})

type apiKeyIn struct {
	Key clientv0.APIKey `arg:"key" help:"<key> is an ID or a prefix; hskey-api-<prefix>-*** names the key too."`
}

var apiKeysGet = command.New(command.Spec[apiKeyIn, clientv0.APIKey]{
	Name:  "get",
	Short: "Show one API key",
	Long: `Show the stored details of one API key, in any state, with every column
of api keys list. It never shows the secret: the server keeps only a hash
of it.

An ID wins over a prefix.

With -o json the command prints the key as the API gives it, with when it
was revoked and when its record is removed.`,
	Example: []string{
		"headscale api keys get 2",
		"headscale api keys get tr81ys -o json",
	},
	Columns: apiKeyColumns,
	Run:     func(_ command.Ctx, in apiKeyIn) (clientv0.APIKey, error) { return in.Key, nil },
})

type apiKeysCreateIn struct {
	User   command.Opt[clientv0.User]      `flag:"user"   help:"The owner of the key: a user, named as users get names one. It does not limit what the key may do" short:"u"`
	Expiry command.Expiry[command.NoWords] `default:"90d" flag:"expiry"                                                                                            help:"When the key stops working: a time, a date or a duration from now" short:"e"`
}

var apiKeysCreate = command.New(command.Spec[apiKeysCreateIn, clientv0.CreatedAPIKey]{
	Name:  "create",
	Short: "Create an API key",
	Long: `Create an API key. Every API key may do everything that the API allows,
with or without an owner: keep it as a password of the server.

--user gives the key an owner. The owner does not limit the key; the key
is deleted with its user, and the Tailscale API (/api/v2) makes the auth
keys that this key asks for owned by that user.

--expiry says when the key expires, its default under Flags: a time
(2999-08-27T10:00:00Z), a date (midnight UTC) or a duration from now (30d).
A key must expire; there is no upper limit. A time in the past is an
error.

The key is printed on stdout, alone, so a script can capture it:

  KEY=$(headscale api keys create)

Its ID, owner and expiry go to stderr. This is the only time the key is
shown: the server keeps only a hash of it. Only an API key or the socket
can make one; an OAuth access token cannot.

With -o json the command prints the new key as the API gives it, the
secret in the field key.`,
	Example: []string{
		"headscale api keys create",
		"headscale api keys create --expiry 30d",
		"headscale api keys create --user alice --expiry 90d",
		"headscale api keys create -u alice -o json | jq -r .key",
	},
	Run: func(c command.Ctx, in apiKeysCreateIn) (clientv0.CreatedAPIKey, error) {
		body := clientv0.CreateAPIKeyBody{Expiry: new(in.Expiry.At(c.Now()).UTC())}

		if u, ok := in.User.Get(); ok {
			body.UserId = &u.Id
		}

		return clientv0.Got(c.API.CreateAPIKeyWithResponse(c, body))
	},
	Secret: func(out clientv0.CreatedAPIKey) string { return out.Key },
	Done: func(_ apiKeysCreateIn, out clientv0.CreatedAPIKey, now time.Time) string {
		what := ""

		t, err := out.Expiry.Get()
		if err == nil {
			what = "expires " + table.Ago(t, now)
		}

		owner, _ := command.OwnerName(out.Owner)

		return command.CreatedNote(
			table.Entity("apiKey", out.Id, out.Prefix),
			owner,
			what,
			"key",
		)
	},
})

var apiKeysDelete = command.NewEnd(command.EndSpec[apiKeyIn, clientv0.APIKey]{
	Short: "Revoke an API key",
	Long: `Revoke an API key: it stops working at once. The command asks first;
--force does not ask. When the key is the one this CLI calls with, the
question says so, and so does the error when no terminal can answer: the
delete works, and every later call with the key is refused.

The record stays, in the state revoked, so that list --all and get show
what was stopped. The server removes it after the retention time,
credentials.revoked_retention; a retention of 0 keeps
it. Deleting a revoked key succeeds and changes nothing, and does not ask.

With -o json the command prints the revoked key as the API gives it, with
removal, the time its record is removed; nothing when that read fails, as
it does after the CLI revoked the key it calls with.`,
	Example: []string{
		"headscale api keys delete tr81ys",
		"headscale api keys rm 2 --force",
		"headscale api keys delete 2 --force -o json | jq -r .removal",
	},
	Target: func(in apiKeyIn) clientv0.APIKey { return in.Key },
	Of: func(k clientv0.APIKey) command.Ended {
		return command.Ended{
			ID:      k.Id,
			Name:    apiKey(k),
			Owned:   command.Owned(k.Owner),
			Revoked: k.Revoked,
			Removal: k.Removal,
		}
	},
	Revoke: func(c command.Ctx, id string) error { return clientv0.Done(c.API.DeleteAPIKeyWithResponse(c, id)) },
	Get: func(c command.Ctx, id string) (clientv0.APIKey, error) {
		return clientv0.Got(c.API.GetAPIKeyWithResponse(c, id))
	},
	Own: func(me clientv0.Me, k clientv0.APIKey) bool {
		cred, err := me.Credential.Get()

		return err == nil && cred.Kind == clientv0.CredentialKindApiKey &&
			cred.Id == k.Id
	},
})

var oauthClientColumns = table.Columns[clientv0.OAuthClient]{
	{
		Name:    "id",
		Field:   "id",
		Kind:    table.Text,
		Default: true,
		Help:    "OAuth client ID, which is no number",
	},
	{
		Name:    "scopes",
		Field:   "scopes",
		Default: true,
		Help:    "The scopes the client may give its tokens",
	},
	{
		Name:    "tags",
		Field:   "tags",
		Default: true,
		Help:    "The tags the client may give its tokens",
	},
	{
		Name:    "description",
		Field:   "description",
		Default: true,
		Help:    "What the client is for",
	},
	{
		Name:    "created",
		Field:   "created",
		Default: true,
		Help:    "When the client was made",
	},
	{Name: "state", Field: "state", Help: "valid or revoked"},
}

// oauthClient names an OAuth client in a message.
func oauthClient(
	o clientv0.OAuthClient,
) string {
	return table.Entity("oauthClient", o.Id, "")
}

var oauthClientsList = command.NewList(
	command.ListSpec[command.NoInput, clientv0.OAuthClient]{
		Name:  "list",
		Short: "List the OAuth clients",
		Long: `List the OAuth clients that work: the ones in the state valid, in the
order they were made.

A revoked client is hidden; --all shows every client and adds the STATE
column, and a filter on state shows the clients it names. A revoked client
is listed until the server removes its record. No list shows the secret of
a client; only api oauth-clients create prints it, once.

An OAuth client has no expiry. Its ID is no number: it sorts as text, and
a filter compares it with = and :, never with < or >.

With -o json the command prints an array of the clients as the API gives
them, with who made each (createdBy), the hidden ones left out as in the
table.`,
		Example: []string{
			"headscale api oauth-clients list",
			"headscale api oauth-clients list --all",
			"headscale api oauth-clients ls --filter tags=tag:ci -o json",
		},
		Aliases: []string{"ls"},
		Columns: oauthClientColumns,
		NoRows:  "No OAuth clients.",
		Only:    "state=valid",
		Run: func(c command.Ctx, _ command.NoInput) ([]clientv0.OAuthClient, error) {
			return c.API.ListOAuthClientsAll(
				c,
				&clientv0.ListOAuthClientsParams{PageSize: c.API.PageSize},
			)
		},
	},
)

type oauthClientIn struct {
	Client clientv0.OAuthClient `arg:"client" help:"<client> is the ID of the client."`
}

var oauthClientsGet = command.New(command.Spec[oauthClientIn, clientv0.OAuthClient]{
	Name:  "get",
	Short: "Show one OAuth client",
	Long: `Show the stored details of one OAuth client, in any state, with every
column of api oauth-clients list. A client is named by its ID only. It
never shows the secret: the server keeps only a hash of it.

With -o json the command prints the client as the API gives it, with who
made it (createdBy), when it was revoked and when its record is removed.`,
	Example: []string{
		"headscale api oauth-clients get c9f2aa000001",
		"headscale api oauth-clients get c9f2aa000001 -o json",
	},
	Columns: oauthClientColumns,
	Run:     func(_ command.Ctx, in oauthClientIn) (clientv0.OAuthClient, error) { return in.Client, nil },
})

type oauthClientsCreateIn struct {
	Scopes      []string `arg:"scopes"       help:"<scopes> are the scopes the client may give its tokens, comma separated, such as devices:core,auth_keys; devices:core and auth_keys need --tags."`
	Tags        []string `flag:"tags"        help:"The tags the client may give its tokens, comma separated, each named in tagOwners of the policy"`
	Description string   `flag:"description" help:"What the client is for, shown by list and get"                                                                                                    short:"d"`
}

var oauthClientsCreate = command.New(
	command.Spec[oauthClientsCreateIn, clientv0.CreatedOAuthClient]{
		Name:  "create",
		Short: "Create an OAuth client",
		Long: `Create an OAuth client: an ID and a secret that a program trades at
POST /api/v2/oauth/token for short-lived access tokens, with the scopes and
the tags of the client. Scopes are required; the scopes devices:core and
auth_keys need at least one tag. A tag must be in tagOwners of the policy.

An OAuth client has no expiry. It works until it is deleted.

The secret is printed on stdout, alone, so a script can capture it:

  SECRET=$(headscale api oauth-clients create devices:core --tags tag:ci)

The client ID, its scopes and its tags go to stderr. This is the only time
the secret is shown: the server keeps only a hash of it. An OAuth access
token makes a client with only scopes it holds and tags it owns.

With -o json the command prints the new client as the API gives it, the
secret in the field key.`,
		Example: []string{
			"headscale api oauth-clients create devices:core:read",
			"headscale api oauth-clients create devices:core,auth_keys --tags tag:ci",
			`headscale api oauth-clients create devices:core --tags tag:ci -d "CI"`,
			"headscale api oauth-clients create devices:core --tags tag:ci -o json | jq -r '.id, .key'",
		},
		Run: func(c command.Ctx, in oauthClientsCreateIn) (clientv0.CreatedOAuthClient, error) {
			body := clientv0.CreateOAuthClientBody{
				Scopes:      in.Scopes,
				Description: given(in.Description),
			}
			if len(in.Tags) > 0 {
				body.Tags = &in.Tags
			}

			return clientv0.Got(c.API.CreateOAuthClientWithResponse(c, body))
		},
		Secret: func(out clientv0.CreatedOAuthClient) string { return out.Key },
		Done: func(_ oauthClientsCreateIn, out clientv0.CreatedOAuthClient, _ time.Time) string {
			what := "scopes " + visibleList(out.Scopes)
			if len(out.Tags) > 0 {
				what += "; tags " + visibleList(out.Tags)
			}

			return command.CreatedNote(
				table.Entity("oauthClient", out.Id, ""),
				"",
				what,
				"secret",
			)
		},
	},
)

var oauthClientsDelete = command.NewEnd(
	command.EndSpec[oauthClientIn, clientv0.OAuthClient]{
		Short: "Revoke an OAuth client",
		Long: `Revoke an OAuth client: it stops working at once, and every access token
it gave is refused from its next request. The command asks first, and
names the client with its description; --force does not ask. When the CLI
calls with a token of the client, the question says so, and so does the
error when no terminal can answer.

The record stays, in the state revoked, so that list --all and get show
what was stopped. The server removes it after the retention time,
credentials.revoked_retention; a retention of 0 keeps
it. Deleting a revoked client succeeds and changes nothing, and does not
ask.

With -o json the command prints the revoked client as the API gives it,
with removal, the time its record is removed; nothing when that read
fails.`,
		Example: []string{
			"headscale api oauth-clients delete c9f2aa000001",
			"headscale api oauth-clients rm c9f2aa000001 --force",
			"headscale api oauth-clients delete c9f2aa000001 --force -o json | jq -r .removal",
		},
		Target: func(in oauthClientIn) clientv0.OAuthClient { return in.Client },
		Of: func(o clientv0.OAuthClient) command.Ended {
			return command.Ended{
				ID:      o.Id,
				Name:    oauthClient(o),
				For:     o.Description,
				Revoked: o.Revoked,
				Removal: o.Removal,
			}
		},
		Revoke: func(c command.Ctx, id string) error { return clientv0.Done(c.API.DeleteOAuthClientWithResponse(c, id)) },
		Get: func(c command.Ctx, id string) (clientv0.OAuthClient, error) {
			return clientv0.Got(c.API.GetOAuthClientWithResponse(c, id))
		},
		Own: func(me clientv0.Me, o clientv0.OAuthClient) bool {
			cred, err := me.Credential.Get()
			if err != nil {
				return false
			}

			client, err := cred.Client.Get()

			return err == nil && client.Id == o.Id
		},
	},
)
