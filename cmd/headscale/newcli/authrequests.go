package newcli

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

type authRegisterIn struct {
	AuthID command.AuthID `arg:"auth-id" help:"<auth-id> is the ID the node shows, hskey-authreq- and the rest, as at the end of its URL."`
	User   clientv0.User  `arg:"user"    help:"<user> is an ID, an email, a username or a provider identifier."`
}

var authRegister = command.New(command.Spec[authRegisterIn, clientv0.Node]{
	Name:  "register",
	Short: "Register a node that waits to join",
	Long: `Answer a registration: the node that shows the auth ID joins the tailnet,
owned by the user. A node that asked for tags the user may give joins
tagged instead.

The auth ID is a secret: whoever holds it can put that machine into the
tailnet. The command sends it to the server and prints it nowhere. A
request that timed out or was answered already is gone. An SSH check is
answered with auth approve, not here.

With -o json the command prints the new node.`,
	Example: []string{
		"headscale auth register hskey-authreq-0123456789abcdef01234567 alice",
		"headscale auth register hskey-authreq-0123456789abcdef01234567 3 -o json",
	},
	Hint: func(args []string) string {
		if len(args) == 2 && strings.HasPrefix(args[1], "tag:") {
			return "A node joins tagged when it asks for tags its user may give (tailscale up --advertise-tags): register it to that user."
		}

		return ""
	},
	Run: func(c command.Ctx, in authRegisterIn) (clientv0.Node, error) {
		n, err := c.API.RegisterAuthRequest(c, in.AuthID, in.User.Id)

		p, ok := errors.AsType[*command.ProblemError](err)
		if ok && p.Problem.Code == clientv0.ProblemCodeTagsNotPermitted {
			return n, notPermitted(in.User, p.Problem.Details["tags"])
		}

		return n, answeredAgain(err)
	},
	Done: func(_ authRegisterIn, out clientv0.Node, _ time.Time) string {
		owner, tagged := command.OwnerName(out.Owner)

		switch {
		case owner == "":
			return node(out) + " registered."
		case tagged:
			return node(out) + " registered, tagged " + owner + "."
		}

		return node(out) + " registered to " + owner + "."
	},
})

type authIDIn struct {
	AuthID command.AuthID `arg:"auth-id" help:"<auth-id> is the ID the node shows, hskey-authreq- and the rest, as at the end of its URL."`
}

var authApprove = command.New(command.Spec[authIDIn, command.Said]{
	Name:  "approve",
	Short: "Let an SSH check pass",
	Long: `Answer an SSH check with yes: the SSH connection that waits for it goes on.

The command reads the request first, so its message says which nodes the
check is between. The auth ID is a secret, which the command sends to the
server and prints nowhere. A registration is answered with auth register,
not here. A request that timed out or was answered already is gone.

With -o json the command prints nothing; the exit code says it worked.`,
	Example: []string{"headscale auth approve hskey-authreq-0123456789abcdef01234567"},
	Run: func(c command.Ctx, in authIDIn) (command.Said, error) {
		r, err := readRequest(c, in.AuthID)
		if err != nil {
			return command.Said{}, err
		}

		return command.Said{What: answered(r)}, answeredAgain(c.API.ApproveAuthRequest(c, in.AuthID))
	},
	Done: func(_ authIDIn, out command.Said, _ time.Time) string { return out.What + " approved." },
})

var authReject = command.New(command.Spec[authIDIn, command.Said]{
	Name:  "reject",
	Short: "Refuse a registration or an SSH check",
	Long: `Answer an auth request with no: a node that waits to join must start
again, and an SSH connection that waits for a check is refused.

The command reads the request first and asks, with what it is; --force
does not ask. The auth ID is a secret, which the command sends to the
server and prints nowhere. A request that timed out or was answered
already is gone.

With -o json the command prints nothing; the exit code says it worked.`,
	Example: []string{
		"headscale auth reject hskey-authreq-0123456789abcdef01234567",
		"headscale auth reject hskey-authreq-0123456789abcdef01234567 --force",
	},
	Confirm: func(c command.Ctx, in authIDIn) (command.Prompt, error) {
		r, err := readRequest(c, in.AuthID)
		if err != nil {
			return command.Prompt{}, err
		}

		q := "Reject the " + answeredLower(r) + "?"
		if r.Kind == clientv0.AuthRequestKindRegistration {
			q += " The node must start again."
		}

		return command.Prompt{Question: q, Action: "reject the " + answeredLower(r)}, nil
	},
	Run: func(c command.Ctx, in authIDIn) (command.Said, error) {
		// Read once a run: the question read it already.
		r, err := readRequest(c, in.AuthID)
		if err != nil {
			return command.Said{}, err
		}

		return command.Said{What: answered(r)}, answeredAgain(c.API.RejectAuthRequest(c, in.AuthID))
	},
	Done: func(_ authIDIn, out command.Said, _ time.Time) string { return out.What + " rejected." },
})

// readRequest is the auth request id, of a kind this CLI knows: an answer
// to a kind it does not know would be sent blind.
func readRequest(c command.Ctx, id command.AuthID) (clientv0.AuthRequest, error) {
	r, err := c.API.GetAuthRequest(c, id)
	if err == nil && r.Kind != clientv0.AuthRequestKindRegistration && r.Kind != clientv0.AuthRequestKindSshCheck {
		err = errors.New("the server calls this auth request " + strconv.Quote(string(r.Kind)) + ", a kind this CLI does not know. It was not answered.") //nolint:err113 // a sentence of the CLI
	}

	return r, err
}

// notPermitted is tags_not_permitted on register: the node asked for tags
// that user may not give.
func notPermitted(u clientv0.User, tags any) error {
	list, _ := tags.([]any)

	names := make([]string, 0, len(list))
	for _, t := range list {
		s, _ := t.(string)
		names = append(names, table.Visible(s, ""))
	}

	what, owns, them := "the tags", "them", "them"

	switch len(names) {
	case 0:
	case 1:
		what, owns, them = names[0], "the tag", "it"
	default:
		what = strings.Join(names, ", ")
	}

	return errors.New(user(u) + " may not give " + what + ", which the node asked for. Register it to a user that owns " + owns + ", or the node must ask without " + them + ".") //nolint:err113 // a sentence of the CLI
}

// answered is the auth request r as a message names it: Registration of
// "newlaptop", SSH check from Node 12 (mynode) to Node 13 (builder). It
// never names the ID, which is the secret.
func answered(r clientv0.AuthRequest) string {
	s := answeredLower(r)

	return strings.ToUpper(s[:1]) + s[1:]
}

// answeredLower is answered in the middle of a sentence.
func answeredLower(r clientv0.AuthRequest) string {
	switch r.Kind {
	case clientv0.AuthRequestKindRegistration:
		return "registration of " + strconv.Quote(r.Hostname)
	case clientv0.AuthRequestKindSshCheck:
		return "SSH check from " + checkNode(r.Source) + " to " + checkNode(r.Destination)
	}

	return "auth request of the kind " + strconv.Quote(string(r.Kind))
}

// checkNode is a node of an SSH check; one that is gone has no name.
func checkNode(n interface {
	Get() (clientv0.SSHCheckNodeReference, error)
},
) string {
	v, err := n.Get()
	if err != nil {
		return "a node"
	}

	return table.Entity("node", v.Id, v.Name)
}

// answeredAgain is err with what to do when the answer of a write was
// lost: the same command again is safe, since a request that was answered
// is gone and the command says so.
func answeredAgain(err error) error {
	return command.MayBeMade(err, "To look, run the same command again: a request that was answered is gone, and it says so.")
}
