package newcli

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

var debugGroup = command.Group{
	Name:     "debug",
	Short:    "A health check and test tools",
	Commands: []command.Node{debugHealth, debugCreateNode},
}

// errUnhealthy is a 200 whose body says the server is not healthy; a
// healthcheck must not pass on it.
//
//nolint:staticcheck // a sentence of the CLI
var errUnhealthy = errors.New("the server is not healthy.")

var debugHealth = command.New(command.Spec[command.NoInput, clientv0.Health]{
	Name:  "health",
	Short: "Check that the server is healthy",
	Long: `Ask the running server whether it is healthy.

It prints healthy and exits 0, or prints the reasons on stderr and exits 1.
A container healthcheck relies on the exit code.

A warning is something an admin should know that does not stop the
server, such as a node whose stored data is not valid. Each warning is
printed on stderr, a warning about nodes with the nodes list command that
shows them, and the command still exits 0, so a healthcheck does not
restart the server over one.

With -o json the command prints the answer of GET /health, warnings
included, and writes no warning on stderr.`,
	Example: []string{
		"headscale debug health",
		"headscale debug health -o json",
	},
	OldNames: []string{"health"},
	Run: func(c command.Ctx, _ command.NoInput) (clientv0.Health, error) {
		h, err := clientv0.Got(c.API.GetHealthWithResponse(c))

		switch {
		case err != nil:
			return h, err
		case !h.Healthy:
			return h, errUnhealthy
		}

		for _, w := range h.Warnings {
			c.Note("warning: " + table.Visible(w.Message, ""))

			if hint := healthHint(w.Code); hint != "" {
				c.Note("  " + hint)
			}
		}

		return h, nil
	},
	Done: func(command.NoInput, clientv0.Health, time.Time) string { return "healthy" },
})

// healthHint is what to run about a warning; "" for none.
func healthHint(code clientv0.HealthMessageCode) string {
	switch code { //nolint:exhaustive // the others have no command
	case clientv0.HealthMessageCodePolicyFileInvalid,
		clientv0.HealthMessageCodePolicyStoredInvalid:
		return "To see why: headscale policy reload"
	case clientv0.HealthMessageCodePolicyUserAmbiguous:
		return "To see them: headscale policy get | headscale policy set - --dry-run"
	case clientv0.HealthMessageCodePolicyNotStored:
		return "To put the stored policy in force: headscale policy reload"
	}

	// A check of one node is a code that nodes list has in problems.
	if strings.HasPrefix(string(code), "node_") {
		return "To see them: headscale nodes list --filter problems=" + table.Visible(
			string(code),
			"",
		)
	}

	return ""
}

type debugCreateNodeIn struct {
	Hostname command.Opt[string]         `flag:"name"  help:"The hostname of the made-up node; required"`
	AuthID   command.Opt[command.AuthID] `flag:"key"   help:"The auth ID it waits under, hskey-authreq- and the rest; required"`
	Routes   []string                    `flag:"route" help:"Routes it advertises once it is registered, comma separated"`
}

var (
	//nolint:staticcheck // a sentence of the CLI
	errNoName = errors.New("--name is required: the hostname of the made-up node.")
	//nolint:staticcheck // a sentence of the CLI
	errNoKey = errors.New("--key is required: the auth ID it waits under.")
)

var debugCreateNode = command.New(command.Spec[debugCreateNodeIn, command.NoOutput]{
	Name:  "create-node",
	Short: "Make a registration of a made-up node, for tests",
	Long: `Make a registration that waits under the auth ID given with --key, as a
node that wants to join would. auth register answers it with a user; the
node never connects. It is a test tool: it is unstable, and it prints one
fixed sentence, with no -o json.

The auth ID is yours: hskey-authreq- and 24 lower-case hex digits. The
command does not print it back, and the help shows an ID it holds as
hskey-authreq-***, so keep it for auth register:

  id="hskey-authreq-$(openssl rand -hex 12)"
  headscale debug create-node --name fake-1 --key "$id"
  headscale auth register "$id" alice`,
	Example: []string{
		`headscale debug create-node --name fake-1 --key "$id"`,
		`headscale debug create-node --name fake-2 --key "$id" --route 10.0.0.0/8,192.168.0.0/24`,
	},
	NoJSON: true,
	Valid: func(in debugCreateNodeIn) error {
		if _, ok := in.Hostname.Get(); !ok {
			return errNoName
		}

		if _, ok := in.AuthID.Get(); !ok {
			return errNoKey
		}

		return nil
	},
	Run: func(c command.Ctx, in debugCreateNodeIn) (command.NoOutput, error) {
		name, _ := in.Hostname.Get()
		id, _ := in.AuthID.Get()

		// routes is required, so none is the empty list, not null.
		_, err := clientv0.Got(
			c.API.CreateDebugNodeWithResponse(c, clientv0.CreateDebugNodeBody{
				AuthId:   string(id),
				Hostname: name,
				Routes:   append([]string{}, in.Routes...),
			}),
		)

		return command.NoOutput{}, err
	},
	Done: func(in debugCreateNodeIn, _ command.NoOutput, _ time.Time) string {
		name, _ := in.Hostname.Get()

		return "Registration of " + strconv.Quote(
			name,
		) + " waits: headscale auth register <auth-id> <user> answers it."
	},
})
