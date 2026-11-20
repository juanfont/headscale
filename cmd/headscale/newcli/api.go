package newcli

import (
	"cmp"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

var apiGroup = command.Group{
	Name:     "api",
	Short:    "Authentication towards the headscale API",
	Commands: []command.Node{apiWhoami},
}

var apiWhoami = command.New(command.Spec[command.NoInput, clientv0.Me]{
	Name:  "whoami",
	Short: "Show what the CLI is connected as",
	Long: `Show what the CLI is connected as: who or what is calling (the
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
		return c.API.Me(c)
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
	line("Principal", cmp.Or(principals[me.Principal.Kind], string(me.Principal.Kind)))

	cred, err := me.Credential.Get()
	hasCred := err == nil

	if hasCred {
		line("Credential", table.Entity(string(cred.Kind), cred.Id, cred.Prefix))

		if cred.Kind == clientv0.CredentialKindApiKey {
			line("Key owner", keyOwner(cred))
		}

		client, err := cred.Client.Get()
		if err == nil {
			line("Client", client.Id+described(client.Description))
		}
	}

	line("Scopes", strings.Join(me.Authorization.Scopes, ", "))

	tags, err := me.Authorization.Tags.Get()

	switch {
	case err != nil:
		line("Tags", "any")
	case len(tags) == 0:
		line("Tags", "none")
	default:
		line("Tags", strings.Join(tags, ", "))
	}

	line("Resources", string(me.Authorization.Resources))

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
		return strings.Join(o.Tags, ", ")
	}

	return "none"
}

func described(d string) string {
	if d == "" {
		return ""
	}

	return " (" + d + ")"
}
