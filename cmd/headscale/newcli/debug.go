package newcli

import (
	"errors"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

var debugGroup = command.Group{
	Name:     "debug",
	Short:    "A health check and test tools",
	Commands: []command.Node{debugHealth},
}

// errUnhealthy is a 200 whose body says the server is not healthy; a
// healthcheck must not pass on it.
var errUnhealthy = errors.New("the server is not healthy.") //nolint:staticcheck // a sentence of the CLI

var debugHealth = command.New(command.Spec[command.NoInput, clientv0.Health]{
	Name:  "health",
	Short: "Check that the server is healthy",
	Long: `Ask the running server whether it is healthy.

It prints healthy and exits 0, or prints the reasons on stderr and exits 1.
A container healthcheck relies on the exit code.

A warning is something an admin should know that does not stop the
server, such as a node whose stored data is not valid. Each warning is
printed on stderr, and the command still exits 0, so a healthcheck does not
restart the server over one.

With -o json the command prints the answer of GET /health, warnings
included, and writes no warning on stderr.`,
	Example: []string{
		"headscale debug health",
		"headscale debug health -o json",
	},
	OldNames: []string{"health"},
	Run: func(c command.Ctx, _ command.NoInput) (clientv0.Health, error) {
		h, err := c.API.Health(c)

		switch {
		case err != nil:
			return h, err
		case !h.Healthy:
			return h, errUnhealthy
		}

		for _, w := range h.Warnings {
			c.Note("warning: " + table.Visible(w.Message, ""))
		}

		return h, nil
	},
	Done: func(command.NoInput, clientv0.Health, time.Time) string { return "healthy" },
})
