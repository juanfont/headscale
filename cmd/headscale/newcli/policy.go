package newcli

import (
	"bytes"
	"errors"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/offline"
	"github.com/oapi-codegen/nullable"
)

var policyGroup = command.Group{
	Name:     "policy",
	Short:    "Read, check and replace the policy",
	Commands: []command.Node{policyGet, policySet, policyReload},
}

type policyGetIn struct {
	Bypass bool `flag:"bypass-server-and-access-database-directly" help:"Open the database of a stopped server, with no server: the rescue path when a policy keeps it from starting"`
}

var policyGet = command.New(command.Spec[policyGetIn, clientv0.Policy]{
	Name:  "get",
	Short: "Print the policy",
	Long: `Print the policy in force exactly as it is stored, comments, tabs and
line ends included, so that policy get > file and policy set file give the
same policy back. In file mode it is the file the server last took. With
none in force it prints nothing, and says so on stderr.

With -o json the command prints the policy object of the API: policy,
updated, mode and path.

With --bypass-server-and-access-database-directly the command does not talk
to the server: it reads the policy the server would start with, from the
database (or the policy file in file mode) that the config names. It needs
the server's full config, and asks first, since the server must be
stopped; --force answers.`,
	Example: []string{
		"headscale policy get > policy.hujson",
		"headscale policy get -o json | jq -r .updated",
		"headscale policy get --bypass-server-and-access-database-directly > p.hujson",
	},
	Local:       true,
	NeedsServer: func(in policyGetIn) bool { return !in.Bypass },
	ReadsConfig: true,
	Confirm: func(_ command.Ctx, in policyGetIn) (command.Prompt, error) {
		return bypassPrompt(in.Bypass, false), nil
	},
	Run: func(c command.Ctx, in policyGetIn) (clientv0.Policy, error) {
		p, err := readPolicy(c, in.Bypass)
		if err == nil && p.Policy == "" {
			c.Note(noPolicy(p))
		}

		return p, err
	},
	Verbatim: func(p clientv0.Policy) string { return p.Policy },
})

type policySetIn struct {
	File   command.Path `arg:"file"                                        help:"<file> is the policy, HuJSON; - reads it from stdin."`
	DryRun bool         `flag:"dry-run"                                    help:"Run every check of set against the users and nodes, and change nothing"`
	Bypass bool         `flag:"bypass-server-and-access-database-directly" help:"Open the database of a stopped server, with no server: the rescue path when a policy keeps it from starting"`
}

var policySet = command.New(command.Spec[policySetIn, clientv0.Policy]{
	Name:  "set",
	Short: "Replace the policy",
	Long: `Replace the whole policy with a file, sent as it is. It does not ask:
you hold the file, and the server refuses a policy that is not valid and
keeps the one in force. A refusal names each problem and each failed test,
at its line of the file. A file of - is read from stdin.

--dry-run runs every check of set against the users and nodes of the
server, the tests of the policy included, and changes nothing. In file mode
set is refused, and --dry-run still works.

With -o json the command prints the policy object of the API.

With --bypass-server-and-access-database-directly the command does not talk
to the server: it runs the same checks against the users and nodes in the
database that the config names, and stores the policy there. It needs the
server's full config, and asks first, since the server must be stopped;
--force answers, and stdin as the file needs it.`,
	Example: []string{
		"headscale policy set policy.hujson",
		"headscale policy set policy.hujson --dry-run",
		"generate-policy.sh | headscale policy set -",
		"headscale policy set p.hujson --dry-run --bypass-server-and-access-database-directly",
		"headscale policy set p.hujson --bypass-server-and-access-database-directly",
	},
	Local:       true,
	NeedsServer: func(in policySetIn) bool { return !in.Bypass },
	ReadsConfig: true,
	Confirm: func(c command.Ctx, in policySetIn) (command.Prompt, error) {
		p := bypassPrompt(in.Bypass, !in.DryRun)
		if !in.Bypass || in.DryRun {
			return p, nil
		}

		// PostgreSQL may be shared by a server on another host, which the
		// socket does not see: the sessions of the database are all there
		// is to tell.
		n, err := offline.Sessions(c, c.ConfigFile, c.Environ)
		if err != nil {
			return p, bypassError(err)
		}

		if n > 0 {
			p.Question = strings.Replace(
				p.Question,
				"\nContinue?",
				"\nThe database has "+table.Count(
					n,
					"other session",
				)+" open; a server on another host would be one, and cannot be told from another client.\nContinue?",
				1,
			)
		}

		return p, nil
	},
	Run: func(c command.Ctx, in policySetIn) (clientv0.Policy, error) {
		pol, err := c.ReadFile(in.File)
		if err != nil {
			return clientv0.Policy{}, err
		}

		if !in.Bypass {
			// The policy file is the body, as it is. No If-Match: the person
			// holds the file, and the last writer wins.
			var dry *bool
			if in.DryRun {
				dry = new(true)
			}

			return clientv0.Got(c.API.SetPolicyWithBodyWithResponse(
				c,
				&clientv0.SetPolicyParams{DryRun: dry},
				"application/hujson",
				bytes.NewReader(pol),
			))
		}

		return viaDatabase(c, !in.DryRun, func(d *offline.DB) (clientv0.Policy, error) {
			if in.DryRun {
				err := d.CheckPolicy(pol)
				if err != nil {
					return clientv0.Policy{}, err
				}

				// Only where the policy is kept: a policy file that cannot
				// be read does not fail a check of another text.
				doc, _ := d.Policy()

				// A dry run answers what the write would, with nothing stored.
				return policyOf(c, string(pol), nil, string(doc.Mode), doc.Path), nil
			}

			doc, err := d.SetPolicy(pol)

			return policyOf(c, doc.Data, doc.Updated, string(doc.Mode), doc.Path), err
		})
	},
	Done: func(in policySetIn, _ clientv0.Policy, _ time.Time) string {
		if in.DryRun {
			return "Policy is valid for this server. Nothing was changed."
		}

		return "Policy updated."
	},
})

var policyReload = command.New(command.Spec[command.NoInput, clientv0.Policy]{
	Name:  "reload",
	Short: "Read the policy again from where it is kept",
	Long: `Ask the server to read the policy again from where it is kept, the
policy file or the database, and put it in force. The server reads the
file by itself when it is saved; reload is for knowing at once whether it
took it. A policy it refuses leaves the one in force, and the refusal names
each problem at its line.

With -o json the command prints the policy object of the API, as it is in
force now.`,
	Example: []string{"headscale policy reload"},
	Run: func(c command.Ctx, _ command.NoInput) (clientv0.Policy, error) {
		return clientv0.Got(c.API.ReloadPolicyWithResponse(c))
	},
	Done: func(_ command.NoInput, p clientv0.Policy, _ time.Time) string {
		switch {
		case p.Mode == clientv0.PolicyModeFile && p.Path == "":
			return noPolicy(p)
		case p.Mode == clientv0.PolicyModeFile:
			return "Policy reloaded from " + p.Path + "."
		case p.Policy == "":
			return "Policy reloaded from the database. " + noPolicy(p)
		}

		return "Policy reloaded from the database."
	},
})

// bypassPrompt is the question of the database bypass: the server must be
// stopped. A run without it asks nothing.
func bypassPrompt(bypass, write bool) command.Prompt {
	switch {
	case !bypass:
		return command.Prompt{}
	case write:
		return command.Prompt{
			Question: "This writes the policy to the database directly. Headscale must not be running.\nContinue?",
			Action:   "write the policy to the database directly",
		}
	}

	return command.Prompt{
		Question: "This reads the database directly. Headscale must not be running.\nContinue?",
		Action:   "read the database directly",
	}
}

// noPolicy says that no policy is in force, which allows all.
func noPolicy(p clientv0.Policy) string {
	if p.Mode == clientv0.PolicyModeFile && p.Path == "" {
		return "No policy file is set (policy.path), so no policy is in force: all traffic is allowed."
	}

	return "No policy is in force: all traffic is allowed."
}

// readPolicy is the policy in force, from the server or, with bypass, the
// one a stopped server would start with.
func readPolicy(c command.Ctx, bypass bool) (clientv0.Policy, error) {
	if !bypass {
		return clientv0.Got(c.API.GetPolicyWithResponse(c))
	}

	return viaDatabase(c, false, func(d *offline.DB) (clientv0.Policy, error) {
		doc, err := d.Policy()

		return policyOf(c, doc.Data, doc.Updated, string(doc.Mode), doc.Path), err
	})
}

// viaDatabase runs do on the database that the config names, with the
// server stopped: read-only unless write. A policy the database refuses is
// the problem the server would answer, so it reads the same.
func viaDatabase(
	c command.Ctx,
	write bool,
	do func(d *offline.DB) (clientv0.Policy, error),
) (clientv0.Policy, error) {
	d, err := offline.Open(c, c.ConfigFile, c.Environ, write)
	if err != nil {
		return clientv0.Policy{}, bypassError(err)
	}

	defer d.Close()

	for _, w := range d.Warnings {
		c.Note("warning: " + w)
	}

	if d.OthersOpen() {
		c.Note(
			"warning: another program has the database " + d.Where() + " open, such as a server: what it stores may not be the policy in force.",
		)
	}

	p, err := do(d)

	if refused, ok := errors.AsType[*offline.RefusedError](err); ok {
		return p, &command.ProblemError{
			Problem: clientv0.Problem{
				Code:    clientv0.ProblemCodePolicyInvalid,
				Details: config.PolicyRefusal(refused.Policy, refused.Err),
			},
		}
	}

	if ro, ok := errors.AsType[*offline.ReadOnlyError](err); ok {
		return p, &command.ProblemError{
			Problem: clientv0.Problem{
				Code:    clientv0.ProblemCodePolicyReadOnly,
				Details: map[string]any{"path": ro.Path},
			},
		}
	}

	return p, err
}

// bypassError says a socket that answered, or could not be asked, in the
// words of the command.
func bypassError(err error) error {
	if running, ok := errors.AsType[*offline.RunningError](err); ok {
		//nolint:err113 // a sentence of the CLI
		return errors.New(
			"a server is running: it answers on " + running.Socket + ". Run the command without --bypass-server-and-access-database-directly.",
		)
	}

	if socket, ok := errors.AsType[*offline.SocketError](err); ok {
		//nolint:err113 // a sentence of the CLI
		return errors.New(
			"the socket " + socket.Socket + " cannot be asked whether a server listens (" + socket.Err.Error() + "), so one may be running. Run the command as a user who may open the socket, or stop the server and remove the socket.",
		)
	}

	return err
}

// policyOf is a policy of the database as the API answers it: updated to
// the microsecond, null when nothing is stored, and -o json in the order of
// the server's keys.
func policyOf(
	c command.Ctx,
	data string,
	updated *time.Time,
	mode, path string,
) clientv0.Policy {
	p := clientv0.Policy{
		Policy:  data,
		Mode:    clientv0.PolicyMode(mode),
		Path:    path,
		Updated: nullable.NewNullNullable[time.Time](),
	}
	if updated != nil {
		p.Updated.Set(updated.UTC().Truncate(time.Microsecond))
	}

	c.Answer(p, struct {
		Policy  string                       `json:"policy"`
		Updated nullable.Nullable[time.Time] `json:"updated"`
		Mode    clientv0.PolicyMode          `json:"mode"`
		Path    string                       `json:"path"`
	}{p.Policy, p.Updated, p.Mode, p.Path})

	return p
}
