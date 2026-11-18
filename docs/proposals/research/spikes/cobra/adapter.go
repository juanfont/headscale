// Package cobraadapter turns the kit's tree into cobra commands. Cobra is
// used as parser and completer only: help, errors, suggestions, --version and
// the completion command are the kit's.
package cobraadapter

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"spike/kit"
)

type Adapter struct{}

// values records every value given, in order; the kit refuses repeats (D6).
// It never errors in Set: cobra's __complete parses the same flags twice (#2527).
type values struct {
	vs   []string
	bool bool
}

func (v *values) Set(s string) error { v.vs = append(v.vs, s); return nil }

// String is read back by cobra's GetBool("help"): a bool must parse.
func (v *values) String() string {
	if v.bool {
		if len(v.vs) == 0 {
			return "false"
		}
		return v.vs[len(v.vs)-1]
	}
	return strings.Join(v.vs, ",")
}
func (v *values) Type() string {
	if v.bool {
		return "bool"
	}
	return "string"
}
func (v *values) IsBoolFlag() bool { return v.bool }

func addFlag(fs *pflag.FlagSet, f kit.Flag) {
	v := &values{bool: f.Kind == kit.Bool}
	fl := fs.VarPF(v, f.Name, f.Short, "")
	if v.bool {
		fl.NoOptDefVal = "true"
	}
}

func path(c *cobra.Command) []string {
	var p []string
	for ; c.HasParent(); c = c.Parent() {
		p = append([]string{c.Name()}, p...)
	}
	return p
}

// given collects the flags that were given, by long name, every value.
func given(c *cobra.Command) map[string][]string {
	m := map[string][]string{}
	c.Flags().VisitAll(func(f *pflag.Flag) {
		if v, ok := f.Value.(*values); ok && f.Changed {
			m[f.Name] = slices.Clone(v.vs)
		}
	})
	return m
}

// state is one run; nothing is shared between runs.
type state struct {
	ctx     context.Context
	t       *kit.Tree
	std     kit.Stdio
	execErr error
}

func (s *state) exec(c kit.Call) error { return s.t.Exec(s.ctx, s.std, c) }

// build makes a fresh cobra tree. Flag value completion is registered only
// when completing: cobra keeps those functions in a package-level map.
func (s *state) build(completing bool) *cobra.Command {
	byPath := map[string]*cobra.Command{}
	var root *cobra.Command
	for _, kc := range s.t.Commands {
		var c *cobra.Command
		if kc.Leaf {
			c = s.leaf(kc, completing)
		} else {
			c = s.group(kc)
		}
		key := strings.Join(kc.Path, " ")
		byPath[key] = c
		if len(kc.Path) == 0 {
			root = c
			continue
		}
		byPath[strings.Join(kc.Path[:len(kc.Path)-1], " ")].AddCommand(c)
	}
	root.Use = kit.Program
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.DisableSuggestions = true
	root.CompletionOptions.DisableDefaultCmd = true
	// Cobra always adds a `help` command (D8 forbids one). An empty name is never
	// matched by Find, so `headscale help` reaches the root as an unknown word.
	root.SetHelpCommand(&cobra.Command{Use: "", Hidden: true})
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		s.execErr = s.exec(kit.Call{Path: path(c), Flags: map[string][]string{"help": {"true"}}})
	})
	return root
}

// group: runnable, so an unknown word or nothing reaches us instead of
// cobra's help-and-exit-0 (non-root) or its string error (root).
func (s *state) group(kc kit.Command) *cobra.Command {
	g := &cobra.Command{
		Args: cobra.ArbitraryArgs,
		// Unknown flags go to args, so an old command with its old flags
		// (`preauthkeys create --user x`) is still an unknown command (D5).
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlagsHandling: pflag.PassUnknownFlagToArgs},
		RunE: func(c *cobra.Command, args []string) error {
			p := path(c)
			// Workaround: split the args cobra handed back into unknown flags and
			// words, and report a flag that hid a real subcommand from Find as the flag.
			var words, dashed []string // WA
			for _, a := range args {   // WA
				if len(a) > 1 && a[0] == '-' { // WA
					dashed = append(dashed, a) // WA
				} else { // WA
					words = append(words, a) // WA
				} // WA
			} // WA
			if len(dashed) > 0 && (len(words) == 0 || c.HasSubCommands() && hasChild(c, words[0])) { // WA
				return &kit.UsageError{Kind: kit.UnknownFlag, Path: p, Word: dashed[0]} // WA
			}
			if len(words) > 0 {
				return &kit.UsageError{Kind: kit.UnknownCommand, Path: p, Word: words[0]}
			}
			return s.exec(kit.Call{Path: p, Flags: given(c)})
		},
	}
	if len(kc.Path) > 0 {
		g.Use = kc.Path[len(kc.Path)-1]
		g.Aliases = kc.Aliases
	}
	for _, f := range kc.Flags {
		if f.Global {
			// D3: globals are persistent on the root so Find steps over their
			// values at every level and Tab still completes subcommands after
			// them; hidden so leaves without them do not offer them. Leaves
			// that take them shadow them with visible local flags; a leaf
			// without them gets the inherited value and Exec refuses it.
			addFlag(g.PersistentFlags(), f)
			_ = g.PersistentFlags().MarkHidden(f.Name)
			continue
		}
		addFlag(g.Flags(), f)
	}
	g.ValidArgsFunction = func(c *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
		// Cobra completes names only (#1852); aliases are valid words too.
		var out []cobra.Completion
		for _, sub := range c.Commands() {
			for _, a := range sub.Aliases {
				if len(args) == 0 && strings.HasPrefix(a, toComplete) {
					out = append(out, a)
				}
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
	return g
}

func hasChild(c *cobra.Command, w string) bool { // WA
	return slices.ContainsFunc(c.Commands(), func(x *cobra.Command) bool { return x.Name() == w || x.HasAlias(w) }) // WA
}

func (s *state) leaf(kc kit.Command, completing bool) *cobra.Command {
	c := &cobra.Command{
		Use:     kc.Path[len(kc.Path)-1],
		Aliases: kc.Aliases,
		Args:    cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return s.exec(kit.Call{Path: path(c), Flags: given(c), Args: args})
		},
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
			if len(args) >= len(kc.Args) {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			a := kc.Args[len(args)]
			if a.File {
				return nil, cobra.ShellCompDirectiveDefault
			}
			return listValues(a.Values, toComplete), cobra.ShellCompDirectiveNoFileComp
		},
	}
	for _, f := range kc.Flags {
		addFlag(c.Flags(), f)
		if completing && f.Values != nil {
			vals := f.Values
			_ = c.RegisterFlagCompletionFunc(f.Name, func(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
				out, dir := listValues(vals, toComplete), cobra.ShellCompDirectiveNoFileComp|cobra.ShellCompDirectiveNoSpace
				// Workaround: cobra's fish script fails (`string split: -last-seen:
				// unknown option`) on one no-space candidate that starts with '-'.
				if len(out) == 1 && strings.HasPrefix(out[0], "-") { // WA
					dir = cobra.ShellCompDirectiveNoFileComp // WA
				}
				return out, dir
			})
		}
	}
	return c
}

// listValues completes the last item of a comma list and keeps a +/- sign:
// "id,na" -> "id,name", "+ho" -> "+hostname" (same pattern as gh and kubectl).
func listValues(vals []string, toComplete string) []cobra.Completion {
	head, cur := "", toComplete
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		head, cur = toComplete[:i+1], toComplete[i+1:]
	}
	sign := ""
	if cur != "" && (cur[0] == '+' || cur[0] == '-') {
		sign, cur = cur[:1], cur[1:]
	}
	var out []cobra.Completion
	for _, v := range vals {
		if strings.HasPrefix(v, cur) {
			out = append(out, head+sign+v)
		}
	}
	return out
}

func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	s := &state{ctx: ctx, t: t, std: std}
	root := s.build(false)
	root.SetOut(std.Out)
	root.SetErr(std.Err)
	root.SetIn(std.In)
	root.SetArgs(append([]string{}, argv...)) // never nil: nil makes cobra read os.Args
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return s.execErr // help path: cobra calls our help func and returns nil
	}
	var ue *kit.UsageError
	if errors.As(err, &ue) {
		return err
	}
	p := path(cmd)
	var ne *pflag.NotExistError
	var vr *pflag.ValueRequiredError
	var iv *pflag.InvalidValueError
	switch {
	case errors.As(err, &ne):
		w := "--" + ne.GetSpecifiedName()
		if ne.GetSpecifiedShortnames() != "" {
			w = "-" + ne.GetSpecifiedName()
		}
		return &kit.UsageError{Kind: kit.UnknownFlag, Path: p, Word: w}
	case errors.As(err, &vr):
		return &kit.UsageError{Kind: kit.MissingValue, Path: p, Word: "--" + vr.GetFlag().Name}
	case errors.As(err, &iv):
		return &kit.UsageError{Kind: kit.BadValue, Path: p, Word: "--" + iv.GetFlag().Name}
	}
	return err
}

// CompleteRaw answers cobra's __complete protocol: candidate lines, then
// ":<directive>". The binary calls it for `headscale __complete …`; Complete
// calls it in-process. No command runs.
func (Adapter) CompleteRaw(ctx context.Context, t *kit.Tree, argv []string, out io.Writer) error {
	s := &state{ctx: ctx, t: t, std: kit.Stdio{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard}}
	root := s.build(true)
	root.SetOut(out)
	root.SetErr(io.Discard)
	root.SetArgs(append([]string{cobra.ShellCompRequestCmd}, dashValue(root, argv)...)) // WA
	_, err := root.ExecuteContextC(ctx)
	return err
}

// Workaround (argv before cobra): cobra reads a word under the cursor that
// starts with '-' as a flag name even right after a flag that takes a value
// (`--sort -la<Tab>`, #2243). Join the two into `--sort=-la`.
func dashValue(root *cobra.Command, argv []string) []string {
	n := len(argv)                                                                                                             // WA
	if n < 2 || !strings.HasPrefix(argv[n-1], "-") || !strings.HasPrefix(argv[n-2], "-") || strings.Contains(argv[n-2], "=") { // WA
		return argv // WA
	}
	leaf, _, err := root.Find(argv[:n-2]) // WA
	if err != nil {                       // WA
		return argv // WA
	}
	prev := strings.TrimLeft(argv[n-2], "-")                               // WA
	f := leaf.Flags().Lookup(prev)                                         // WA
	if f == nil && len(prev) == 1 && !strings.HasPrefix(argv[n-2], "--") { // WA
		f = leaf.Flags().ShorthandLookup(prev) // WA
	}
	if f == nil || f.NoOptDefVal != "" { // WA
		return argv // WA
	}
	return append(slices.Clone(argv[:n-2]), "--"+f.Name+"="+argv[n-1]) // WA
}

func (a Adapter) Complete(ctx context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	var b bytes.Buffer
	if err := a.CompleteRaw(ctx, t, argv, &b); err != nil {
		return kit.Completion{}, err
	}
	var comp kit.Completion
	sc := bufio.NewScanner(&b)
	for sc.Scan() {
		line := sc.Text()
		if d, ok := strings.CutPrefix(line, ":"); ok {
			dir, err := strconv.Atoi(d)
			if err != nil {
				return comp, fmt.Errorf("bad directive %q", line)
			}
			comp.Files = cobra.ShellCompDirective(dir)&cobra.ShellCompDirectiveNoFileComp == 0
			continue
		}
		if line != "" { // the hidden empty-named help command
			comp.Words = append(comp.Words, line)
		}
	}
	return comp, sc.Err()
}

func (Adapter) Script(t *kit.Tree, shell string, w io.Writer) error {
	s := &state{ctx: context.Background(), t: t}
	root := s.build(false)
	switch shell {
	case "bash":
		return root.GenBashCompletionV2(w, true)
	case "zsh":
		return root.GenZshCompletion(w)
	case "fish":
		return root.GenFishCompletion(w, true)
	case "powershell":
		return root.GenPowerShellCompletionWithDesc(w)
	}
	return fmt.Errorf("no completion for shell %q", shell)
}
