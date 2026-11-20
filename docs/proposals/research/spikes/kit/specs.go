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
	Name   *string `flag:"name"`
	Expiry *string `flag:"expiry" short:"e"`
}

type routesSetIn struct {
	Node   string   `arg:"node"`
	Routes []string `arg:"routes"`
}

type usersDeleteIn struct {
	User      string `arg:"user"`
	WithNodes bool   `flag:"with-nodes"`
}

type authKeysCreateIn struct {
	Owner       string   `arg:"owner"`
	Expiry      string   `flag:"expiry" short:"e"`
	Reusable    bool     `flag:"reusable"`
	Tags        []string `flag:"tags"`
	Description string   `flag:"description" short:"d"`
}

type apiKeysCreateIn struct {
	User   string `flag:"user" short:"u"`
	Expiry string `flag:"expiry" short:"e"`
}

type policySetIn struct {
	File   string `arg:"file" complete:"file"`
	DryRun bool   `flag:"dry-run"`
}

type checkConfigIn struct {
	File string `arg:"file" complete:"file"`
}

type completionIn struct {
	Shell string `arg:"shell" complete:"bash zsh fish powershell"`
}

var nodeColumns = []string{"id", "name", "owner", "ip", "version", "online", "last-seen", "expiry", "hostname"}

var defs = []Def{
	New(Spec[NoInput]{Use: "serve", Config: true, Run: record[NoInput]}),
	New(Spec[NoInput]{Use: "version", Output: true, Config: true, Run: record[NoInput]}),
	New(Spec[checkConfigIn]{Use: "check config [file]", Config: true, Run: record[checkConfigIn]}),
	New(Spec[completionIn]{Use: "completion <shell>", Run: record[completionIn]}),
	New(Spec[NoInput]{Use: "nodes list", Aliases: []string{"ls"}, Output: true, Config: true, Columns: nodeColumns, Run: record[NoInput]}),
	New(Spec[nodeIn]{Use: "nodes delete <node>", Aliases: []string{"rm"}, Confirm: "Delete %s?", Output: true, Config: true, Run: record[nodeIn]}),
	New(Spec[nodesSetIn]{Use: "nodes set <node>", Output: true, Config: true, Run: record[nodesSetIn]}),
	New(Spec[routesSetIn]{Use: "nodes routes set <node> <routes>", Aliases: []string{"approve"}, Output: true, Config: true, Run: record[routesSetIn]}),
	New(Spec[usersDeleteIn]{Use: "users delete <user>", Aliases: []string{"rm"}, Confirm: "Delete %s?", Output: true, Config: true, Run: record[usersDeleteIn]}),
	New(Spec[authKeysCreateIn]{Use: "auth keys create <owner>", Output: true, Config: true, Run: record[authKeysCreateIn]}),
	New(Spec[apiKeysCreateIn]{Use: "api keys create", Output: true, Config: true, Run: record[apiKeysCreateIn]}),
	New(Spec[policySetIn]{Use: "policy set <file>", Confirm: "Replace the policy?", Output: true, Config: true, Run: record[policySetIn]}),
}

// record is every Run: it keeps the filled input struct for the kit's own tests.
func record[In any](ctx context.Context, in In) error {
	rec := ctx.Value(recKey{}).(*recorder)
	rec.mu.Lock()
	rec.in = in
	rec.mu.Unlock()
	return nil
}
