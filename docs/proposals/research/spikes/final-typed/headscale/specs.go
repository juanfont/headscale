package headscale

import (
	"sync"

	"spike/cmdline"
	"spike/kit"
)

// The kit's tree as typed specs: the same commands, flags and arguments as
// kit/specs.go, which the kit keeps for the adapters of other parsers.
// TestTwin holds the two together. The kit accepts any text for a value, so
// the fields are text; a field that completes has a type that says so.

type (
	nodeRow    struct{}
	tagWords   struct{}
	shellWords struct{}
)

func (nodeRow) Columns() []string {
	return []string{"id", "name", "owner", "ip", "version", "online", "last-seen", "expiry", "hostname"}
}
func (tagWords) Words() []string   { return []string{"tag:ci", "tag:prod"} }
func (shellWords) Words() []string { return []string{"bash", "zsh", "fish", "powershell"} }

// NoInput is the input of a command that takes nothing.
type NoInput struct{}

type nodeIn struct {
	Node string `arg:"node"`
}

type nodesSetIn struct {
	Node   string              `arg:"node"`
	Name   cmdline.Opt[string] `flag:"name" help:"New name of the node"`
	Expiry cmdline.Opt[string] `flag:"expiry" short:"e" help:"New expiry of the node key"`
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
	Owner       string           `arg:"owner"`
	Expiry      string           `flag:"expiry" short:"e" help:"When the key ends"`
	Reusable    bool             `flag:"reusable" help:"Let more than one node join"`
	Tags        []Text[tagWords] `flag:"tags" help:"Tags for the nodes that join"`
	Description string           `flag:"description" short:"d" help:"What the key is for"`
}

type apiKeysCreateIn struct {
	User   string `flag:"user" short:"u" help:"Owner of the key"`
	Expiry string `flag:"expiry" short:"e" help:"When the key ends"`
}

type policySetIn struct {
	File   cmdline.Path `arg:"file"`
	DryRun bool         `flag:"dry-run" help:"Check the policy, do not set it"`
}

type checkConfigIn struct {
	File cmdline.Opt[cmdline.Path] `arg:"file"`
}

type completionIn struct {
	Shell Text[shellWords] `arg:"shell"`
}

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

// KitTree is the kit's tree. It is built once: a cmdline.Tree is read-only,
// so every run and every Tab may share it.
var KitTree = sync.OnceValue(func() *Tree {
	t, err := Build(kit.Program, groupShort,
		New(Spec[NoInput]{Path: "serve", Short: "Run the control server", Config: true, Run: kit.Record[NoInput]}),
		New(Spec[NoInput]{Path: "version", Short: "Print the version", Output: true, Config: true, Run: kit.Record[NoInput]}),
		New(Spec[checkConfigIn]{Path: "check config", Short: "Check a config file", Config: true, Run: kit.Record[checkConfigIn]}),
		New(Spec[completionIn]{Path: "completion", Short: "Print a shell completion script", Run: kit.Record[completionIn]}),
		NewList[NoInput, nodeRow](Spec[NoInput]{Path: "nodes list", Short: "List the nodes", Aliases: []string{"ls"}, Output: true, Config: true, Run: kit.Record[NoInput]}),
		New(Spec[nodeIn]{Path: "nodes delete", Short: "Delete a node", Aliases: []string{"rm"}, Confirm: "Delete %s?", Output: true, Config: true, Run: kit.Record[nodeIn]}),
		New(Spec[nodesSetIn]{Path: "nodes set", Short: "Change the name or expiry of a node", Output: true, Config: true, Run: kit.Record[nodesSetIn]}),
		New(Spec[routesSetIn]{Path: "nodes routes set", Short: "Replace the enabled routes of a node", Aliases: []string{"approve"}, Output: true, Config: true, Run: kit.Record[routesSetIn]}),
		New(Spec[usersDeleteIn]{Path: "users delete", Short: "Delete a user", Aliases: []string{"rm"}, Confirm: "Delete %s?", Output: true, Config: true, Run: kit.Record[usersDeleteIn]}),
		New(Spec[authKeysCreateIn]{Path: "auth keys create", Short: "Create an auth key", Output: true, Config: true, Run: kit.Record[authKeysCreateIn]}),
		New(Spec[apiKeysCreateIn]{Path: "api keys create", Short: "Create an API key", Output: true, Config: true, Run: kit.Record[apiKeysCreateIn]}),
		New(Spec[policySetIn]{Path: "policy set", Short: "Replace the policy", Confirm: "Replace the policy?", Output: true, Config: true, Run: kit.Record[policySetIn]}),
	)
	if err != nil {
		panic(err)
	}
	return t
})
