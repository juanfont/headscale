package kit

import "context"

// The kit's tree: the hard cases of 001, nothing else.

// NoInput is the input of a command that takes nothing.
type NoInput struct{}

type nodeIn struct {
	Node string `arg:"node"`
}

type nodesSetIn struct {
	Node   string  `arg:"node"`
	Name   *string `flag:"name" help:"New name of the node"`
	Expiry *string `flag:"expiry" short:"e" help:"New expiry of the node key"`
}

type routesSetIn struct {
	Node   string   `arg:"node"`
	Routes []string `arg:"routes"`
}

type usersDeleteIn struct {
	User      string `arg:"user"`
	WithNodes bool   `flag:"with-nodes" help:"Delete the nodes of the user too"`
}

type authKeysCreateIn struct {
	Owner       string   `arg:"owner"`
	Expiry      string   `flag:"expiry" short:"e" help:"When the key ends"`
	Reusable    bool     `flag:"reusable" help:"Let more than one node join"`
	Tags        []string `flag:"tags" complete:"tag:ci tag:prod" help:"Tags for the nodes that join"` // v2: a value list with colons
	Description string   `flag:"description" short:"d" help:"What the key is for"`
}

type apiKeysCreateIn struct {
	User   string `flag:"user" short:"u" help:"Owner of the key"`
	Expiry string `flag:"expiry" short:"e" help:"When the key ends"`
}

type policySetIn struct {
	File   string `arg:"file" complete:"file"`
	DryRun bool   `flag:"dry-run" help:"Check the policy, do not set it"`
}

type checkConfigIn struct {
	File string `arg:"file" complete:"file"`
}

type completionIn struct {
	Shell string `arg:"shell" complete:"bash zsh fish powershell"`
}

// groupShort is the help text of each group (v3, D28); the root's is "".
var groupShort = map[string]string{
	"":             "Headscale control server",
	"check":        "Check files",
	"nodes":        "Manage nodes",
	"nodes routes": "Manage the routes of a node",
	"users":        "Manage users",
	"auth":         "Manage auth keys",
	"auth keys":    "Manage auth keys",
	"api":          "Manage API access",
	"api keys":     "Manage API keys",
	"policy":       "Manage the policy",
}

var nodeColumns = []string{"id", "name", "owner", "ip", "version", "online", "last-seen", "expiry", "hostname"}

var defs = []Def{
	New(Spec[NoInput]{Use: "serve", Short: "Run the control server", Config: true, Run: record[NoInput]}),
	New(Spec[NoInput]{Use: "version", Short: "Print the version", Output: true, Config: true, Run: record[NoInput]}),
	New(Spec[checkConfigIn]{Use: "check config [file]", Short: "Check a config file", Config: true, Run: record[checkConfigIn]}),
	New(Spec[completionIn]{Use: "completion <shell>", Short: "Print a shell completion script", Run: record[completionIn]}),
	New(Spec[NoInput]{Use: "nodes list", Short: "List the nodes", Aliases: []string{"ls"}, Output: true, Config: true, Columns: nodeColumns, Run: record[NoInput]}),
	New(Spec[nodeIn]{Use: "nodes delete <node>", Short: "Delete a node", Aliases: []string{"rm"}, Confirm: "Delete %s?", Output: true, Config: true, Run: record[nodeIn]}),
	New(Spec[nodesSetIn]{Use: "nodes set <node>", Short: "Change the name or expiry of a node", Output: true, Config: true, Run: record[nodesSetIn]}),
	New(Spec[routesSetIn]{Use: "nodes routes set <node> <routes>", Short: "Replace the enabled routes of a node", Aliases: []string{"approve"}, Output: true, Config: true, Run: record[routesSetIn]}),
	New(Spec[usersDeleteIn]{Use: "users delete <user>", Short: "Delete a user", Aliases: []string{"rm"}, Confirm: "Delete %s?", Output: true, Config: true, Run: record[usersDeleteIn]}),
	New(Spec[authKeysCreateIn]{Use: "auth keys create <owner>", Short: "Create an auth key", Output: true, Config: true, Run: record[authKeysCreateIn]}),
	New(Spec[apiKeysCreateIn]{Use: "api keys create", Short: "Create an API key", Output: true, Config: true, Run: record[apiKeysCreateIn]}),
	New(Spec[policySetIn]{Use: "policy set <file>", Short: "Replace the policy", Confirm: "Replace the policy?", Output: true, Config: true, Run: record[policySetIn]}),
}

// record is every Run: it keeps the filled input struct for the kit's own tests.
func record[In any](ctx context.Context, in In) error {
	rec := ctx.Value(recKey{}).(*recorder)
	rec.mu.Lock()
	rec.in = in
	rec.mu.Unlock()
	return nil
}
