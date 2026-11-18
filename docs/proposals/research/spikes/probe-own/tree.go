// Package own probes the "no framework" option: a spec tree, two argv
// parsers (pflag and our own), one dispatcher, and a __complete answerer.
package own

import "strings"

type Kind int

const (
	Bool   Kind = iota
	String      // one value; given twice is visible to the caller
	Repeat      // values accumulate (--filter, debug --route)
)

type Flag struct {
	Long   string
	Short  string // "" or one ASCII letter
	Kind   Kind
	Help   string
	Values []string // completion words; nil = none
	Comma  bool     // value is a comma list (complete each item)
	Signed bool     // items may carry a +/- prefix (--columns, --sort)
}

type Node struct {
	Name     string
	Aliases  []string
	Short    string
	Children []*Node
	Flags    []Flag // leaf flags; root flags are the globals
	Files    bool   // positional is a file
	ArgWords []string
}

func (n *Node) Leaf() bool { return len(n.Children) == 0 }

func (n *Node) Child(word string) *Node {
	for _, c := range n.Children {
		if c.Name == word {
			return c
		}
		for _, a := range c.Aliases {
			if a == word {
				return c
			}
		}
	}
	return nil
}

func lookup(flags []Flag, name string, short bool) *Flag {
	for i := range flags {
		if (!short && flags[i].Long == name) || (short && flags[i].Short == name && name != "") {
			return &flags[i]
		}
	}
	return nil
}

var (
	output  = Flag{Long: "output", Short: "o", Kind: String, Help: "Output format", Values: []string{"json"}}
	config  = Flag{Long: "config", Short: "c", Kind: String, Help: "Config file"}
	help    = Flag{Long: "help", Short: "h", Kind: Bool, Help: "Show help"}
	columns = []string{"id", "name", "owner", "ip", "last-seen", "online"}
)

func server(extra ...Flag) []Flag { return append([]Flag{output, config, help}, extra...) }

func list() []Flag {
	return server(
		Flag{Long: "columns", Kind: String, Help: "Columns to show", Values: columns, Comma: true, Signed: true},
		Flag{Long: "sort", Kind: String, Help: "Sort by column", Values: columns, Comma: true, Signed: true},
		Flag{Long: "filter", Kind: Repeat, Help: "Keep rows that match", Values: columns},
		Flag{Long: "list-columns", Kind: Bool, Help: "List the columns"},
	)
}

// Tree returns a fresh tree; no package state, so tests may run in parallel.
func Tree() *Node {
	force := Flag{Long: "force", Kind: Bool, Help: "Do not ask"}
	return &Node{Name: "headscale", Flags: []Flag{output, config, help}, Children: []*Node{
		{Name: "version", Short: "Print the version", Flags: server()},
		{Name: "nodes", Short: "Manage nodes", Children: []*Node{
			{Name: "list", Aliases: []string{"ls"}, Short: "List the nodes", Flags: list()},
			{Name: "delete", Aliases: []string{"rm"}, Short: "Delete a node", Flags: server(force)},
			{Name: "set", Short: "Change a node", Flags: server(Flag{Long: "name", Kind: String, Help: "New name"})},
			{Name: "routes", Short: "Manage routes", Children: []*Node{
				{Name: "set", Aliases: []string{"approve"}, Short: "Replace the routes", Flags: server()},
			}},
		}},
		{Name: "auth", Short: "Auth keys", Children: []*Node{
			{Name: "keys", Short: "Auth keys", Children: []*Node{
				{Name: "create", Short: "Create a key", Flags: server(
					Flag{Long: "expiry", Short: "e", Kind: String, Help: "When the key ends"},
					Flag{Long: "reusable", Kind: Bool, Help: "Let more than one node join"},
					Flag{Long: "tags", Kind: String, Help: "Tags", Comma: true},
				)},
			}},
		}},
		{Name: "policy", Short: "Policy", Children: []*Node{
			{Name: "set", Short: "Set the policy", Files: true, Flags: server()},
		}},
		{Name: "check", Short: "Check files", Children: []*Node{
			{Name: "config", Short: "Check the config", Flags: []Flag{config, help}},
		}},
		{Name: "completion", Short: "Shell completion script", Flags: []Flag{help},
			ArgWords: []string{"bash", "zsh", "fish", "powershell"}},
		{Name: "debug", Short: "Debug", Children: []*Node{
			{Name: "create-node", Short: "Create a test node", Flags: []Flag{config, help,
				{Long: "name", Kind: String, Help: "Name"},
				{Long: "user", Short: "u", Kind: String, Help: "User"},
				{Long: "key", Short: "k", Kind: String, Help: "Key"},
				{Long: "route", Short: "r", Kind: Repeat, Help: "Route"},
			}},
		}},
	}}
}

func pathString(p []string) string { return strings.Join(p, " ") }
