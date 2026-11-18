// Probe: cobra stripped down to a parser and a completer.
// Everything user-visible (help, errors, suggestions, version) is "ours";
// cobra only finds the command, parses flags and answers __complete.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type Kind int

const (
	Bool   Kind = iota
	String      // one value; a second occurrence is an error (D6)
	Repeat      // --filter: values accumulate in order
)

type Flag struct {
	Name, Short string
	Kind        Kind
	Values      []string // completion values (static, from the spec)
	Comma       bool     // completion is a comma list with +/- prefixes
}

type Spec struct {
	Path    []string
	Aliases []string
	Flags   []Flag
	Output  bool // takes -o/--output
	Config  bool // takes -c/--config
}

// Parsed is what our builder would receive.
type Parsed struct {
	Path  []string
	Args  []string
	Flags map[string]Value
}

type Value struct {
	Given  bool
	Values []string
}

// Our error types: the only thing the rest of headscale would see.
type UnknownCommandError struct {
	Path []string
	Word string
}

func (e *UnknownCommandError) Error() string {
	return fmt.Sprintf("unknown command %q for %q", e.Word, strings.Join(e.Path, " "))
}

type FlagError struct {
	Path   []string
	Flag   string // as typed, without dashes
	Reason string // unknown, needs-value, given-twice
}

func (e *FlagError) Error() string {
	return fmt.Sprintf("%s: flag %q on %q", e.Reason, e.Flag, strings.Join(e.Path, " "))
}

type HelpRequest struct{ Path []string }

// onceValue makes a repeated single-value flag an error and keeps "given".
type onceValue struct {
	v string
	n int
}

// Set only counts: cobra's __complete parses the same flag set twice, so an
// error here would break completion. The leaf checks n > 1 before running.
func (o *onceValue) Set(s string) error {
	o.n++
	o.v = s
	return nil
}
func (o *onceValue) String() string { return o.v }
func (o *onceValue) Type() string   { return "string" }

type repeatValue struct{ vs []string }

func (r *repeatValue) Set(s string) error { r.vs = append(r.vs, s); return nil }
func (r *repeatValue) String() string     { return strings.Join(r.vs, ",") }
func (r *repeatValue) Type() string       { return "stringArray" }

type Env struct {
	Stdout, Stderr io.Writer
	Run            func(ctx context.Context, p Parsed) error
	Help           func(path []string)
}

func cmdPath(c *cobra.Command) []string {
	var p []string
	for ; c.HasParent(); c = c.Parent() {
		p = append([]string{c.Name()}, p...)
	}
	return p
}

func addGlobal(fs *pflag.FlagSet, output, config bool) {
	if fs.Lookup("help") == nil {
		fs.BoolP("help", "h", false, "")
	}
	if output {
		fs.VarP(&onceValue{}, "output", "o", "")
	}
	if config {
		fs.VarP(&onceValue{}, "config", "c", "")
	}
}

// Build makes a fresh tree; no package state is written.
func Build(specs []Spec, env *Env) *cobra.Command {
	root := newGroup("headscale", env)
	root.Flags().Bool("version", false, "")
	// D3: -o/-c persistent on the root so Find skips their values at every
	// level and __complete still completes subcommands after them. Hidden so
	// they are not completed where the leaf lacks them; leaves that take them
	// define visible local ones that shadow these.
	addGlobal(root.PersistentFlags(), true, true)
	_ = root.PersistentFlags().MarkHidden("output")
	_ = root.PersistentFlags().MarkHidden("config")
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.DisableSuggestions = true
	root.CompletionOptions.DisableDefaultCmd = true
	// No `help` command: cobra always adds one; give it a name no word can match.
	root.SetHelpCommand(&cobra.Command{Use: "", Hidden: true})
	root.SetHelpFunc(func(c *cobra.Command, _ []string) { env.Help(cmdPath(c)) })

	groups := map[string]*cobra.Command{"": root}
	for _, s := range specs {
		parent := root
		for i := range s.Path[:len(s.Path)-1] {
			key := strings.Join(s.Path[:i+1], " ")
			g, ok := groups[key]
			if !ok {
				g = newGroup(s.Path[i], env)
				parent.AddCommand(g)
				groups[key] = g
			}
			parent = g
		}
		parent.AddCommand(newLeaf(s, env))
	}
	return root
}

func newGroup(name string, env *Env) *cobra.Command {
	g := &cobra.Command{
		Use:  name,
		Args: cobra.ArbitraryArgs, // keeps cobra's legacyArgs (string error) out
		// Unknown flags on a group go to args, so "nodes register --user x"
		// reaches us as an unknown command, not as an unknown flag.
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlagsHandling: pflag.PassUnknownFlagToArgs},
		RunE: func(c *cobra.Command, args []string) error {
			if v, _ := c.Flags().GetBool("version"); v {
				fmt.Fprintln(env.Stdout, "headscale vTEST")
				return nil
			}
			for _, a := range args {
				if !strings.HasPrefix(a, "-") {
					return &UnknownCommandError{Path: cmdPath(c), Word: a}
				}
			}
			if len(args) > 0 {
				return &FlagError{Path: cmdPath(c), Flag: strings.TrimLeft(args[0], "-"), Reason: "unknown"}
			}
			env.Help(cmdPath(c))
			return nil
		},
	}
	g.Flags().BoolP("help", "h", false, "")
	return g
}

func newLeaf(s Spec, env *Env) *cobra.Command {
	vals := map[string]pflag.Value{}
	c := &cobra.Command{
		Use:     s.Path[len(s.Path)-1],
		Aliases: s.Aliases,
		Args:    cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			p := Parsed{Path: cmdPath(c), Args: args, Flags: map[string]Value{}}
			var twice *FlagError
			c.Flags().VisitAll(func(f *pflag.Flag) {
				if o, ok := f.Value.(*onceValue); ok && o.n > 1 && twice == nil {
					twice = &FlagError{Path: p.Path, Flag: f.Name, Reason: "given-twice"}
				}
				// Inherited -o/-c given to a leaf that does not take them.
				if f.Changed && c.LocalFlags().Lookup(f.Name) == nil && twice == nil {
					twice = &FlagError{Path: p.Path, Flag: f.Name, Reason: "unknown"}
				}
				v := Value{Given: f.Changed}
				switch x := f.Value.(type) {
				case *onceValue:
					v.Values = []string{x.v}
				case *repeatValue:
					v.Values = x.vs
				default:
					v.Values = []string{f.Value.String()}
				}
				p.Flags[f.Name] = v
			})
			if twice != nil {
				return twice
			}
			return env.Run(c.Context(), p)
		},
		ValidArgsFunction: func(c *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			return []cobra.Completion{"node1\tfirst node", "node2\tsecond node"}, cobra.ShellCompDirectiveNoFileComp
		},
	}
	addGlobal(c.Flags(), s.Output, s.Config)
	if s.Output {
		_ = c.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]cobra.Completion{"json"}, cobra.ShellCompDirectiveNoFileComp))
	}
	for _, f := range s.Flags {
		var v pflag.Value
		switch f.Kind {
		case Bool:
			c.Flags().BoolP(f.Name, f.Short, false, "help for "+f.Name)
			continue
		case String:
			v = &onceValue{}
		case Repeat:
			v = &repeatValue{}
		}
		vals[f.Name] = v
		c.Flags().VarP(v, f.Name, f.Short, "help for "+f.Name)
		if len(f.Values) > 0 {
			_ = c.RegisterFlagCompletionFunc(f.Name, valueCompleter(f))
		}
	}
	return c
}

// valueCompleter completes "id,na" -> "id,name" and keeps +/- prefixes.
func valueCompleter(f Flag) cobra.CompletionFunc {
	return func(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if !f.Comma {
			return f.Values, cobra.ShellCompDirectiveNoFileComp
		}
		head, cur := "", toComplete
		if i := strings.LastIndex(toComplete, ","); i >= 0 {
			head, cur = toComplete[:i+1], toComplete[i+1:]
		}
		sign := ""
		if cur != "" && (cur[0] == '+' || cur[0] == '-') {
			sign, cur = cur[:1], cur[1:]
		}
		var out []cobra.Completion
		for _, v := range f.Values {
			if strings.HasPrefix(v, cur) {
				out = append(out, head+sign+v)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
}

// Execute runs one command line on a fresh tree and turns cobra/pflag errors
// into ours without reading message text.
func Execute(ctx context.Context, specs []Spec, env *Env, args []string) error {
	root := Build(specs, env)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	root.SetIn(strings.NewReader(""))
	if args == nil {
		args = []string{} // nil makes cobra read os.Args
	}
	root.SetArgs(fixDashValue(root, args))
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return nil
	}
	path := cmdPath(cmd)
	var ne *pflag.NotExistError
	var vr *pflag.ValueRequiredError
	var iv *pflag.InvalidValueError
	switch {
	case errors.As(err, &ne):
		return &FlagError{Path: path, Flag: ne.GetSpecifiedName(), Reason: "unknown"}
	case errors.As(err, &vr):
		return &FlagError{Path: path, Flag: vr.GetFlag().Name, Reason: "needs-value"}
	case errors.As(err, &iv):
		return &FlagError{Path: path, Flag: iv.GetFlag().Name, Reason: "invalid"}
	}
	return err
}

// fixDashValue: cobra treats a word being completed that starts with '-' as a
// flag name even after a value flag ("--sort -last<TAB>"). Joining it to
// "--sort=-last" makes cobra complete the value.
func fixDashValue(root *cobra.Command, args []string) []string {
	n := len(args)
	if n < 3 || !strings.HasPrefix(args[0], "__complete") || !strings.HasPrefix(args[n-1], "-") {
		return args
	}
	prev := args[n-2]
	if !strings.HasPrefix(prev, "-") || strings.Contains(prev, "=") {
		return args
	}
	leaf, _, err := root.Find(args[1 : n-2])
	if err != nil {
		return args
	}
	var f *pflag.Flag
	if strings.HasPrefix(prev, "--") {
		f = leaf.Flags().Lookup(prev[2:])
	} else if len(prev) == 2 {
		f = leaf.Flags().ShorthandLookup(prev[1:])
	}
	if f == nil || f.NoOptDefVal != "" {
		return args
	}
	out := append([]string{}, args[:n-2]...)
	return append(out, "--"+f.Name+"="+args[n-1])
}

var demoSpecs = []Spec{
	{Path: []string{"nodes", "list"}, Aliases: []string{"ls"}, Output: true, Config: true, Flags: []Flag{
		{Name: "columns", Kind: String, Comma: true, Values: []string{"id", "name", "owner", "ip", "os", "last-seen"}},
		{Name: "sort", Kind: String, Values: []string{"id", "-id", "name", "-name", "last-seen", "-last-seen"}},
		{Name: "filter", Kind: Repeat},
		{Name: "list-columns", Kind: Bool},
	}},
	{Path: []string{"nodes", "delete"}, Aliases: []string{"rm"}, Output: true, Config: true, Flags: []Flag{{Name: "force", Kind: Bool}}},
	{Path: []string{"nodes", "set"}, Output: true, Config: true, Flags: []Flag{{Name: "name", Kind: String}, {Name: "expiry", Short: "e", Kind: String}}},
	{Path: []string{"nodes", "routes", "set"}, Aliases: []string{"approve"}, Output: true, Config: true},
	{Path: []string{"policy", "set"}, Output: true, Config: true},
	{Path: []string{"users", "create"}, Output: true, Config: true},
	{Path: []string{"check", "config"}, Config: true},
	{Path: []string{"completion"}},
	{Path: []string{"api", "oauth-clients", "delete"}, Aliases: []string{"rm"}, Output: true, Config: true, Flags: []Flag{{Name: "force", Kind: Bool}}},
}

func main() {
	env := &Env{
		Stdout: os.Stdout, Stderr: os.Stderr,
		Help: func(p []string) { fmt.Fprintf(os.Stdout, "HELP %v\n", p) },
	}
	if len(os.Args) == 3 && os.Args[1] == "completion" {
		root := Build(demoSpecs, env)
		switch os.Args[2] {
		case "bash":
			_ = root.GenBashCompletionV2(os.Stdout, true)
		case "zsh":
			_ = root.GenZshCompletion(os.Stdout)
		case "fish":
			_ = root.GenFishCompletion(os.Stdout, true)
		case "powershell":
			_ = root.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return
	}
	env.Run = func(_ context.Context, p Parsed) error {
		fmt.Fprintf(os.Stdout, "RUN %v args=%q\n", p.Path, p.Args)
		return nil
	}
	if err := Execute(context.Background(), demoSpecs, env, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
