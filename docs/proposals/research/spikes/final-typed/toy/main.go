// Command toy is a second, small program on cmdline. It shares nothing with
// Headscale's layer and makes other choices: the library's own error text,
// exit code 2, a group alone is a mistake, help printed from the tree as
// data.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"spike/cmdline"
	"spike/cmdline/script"
)

// Level reads itself, and offers its words on Tab.
type Level string

var levels = []string{"low", "mid", "high"}

func (l *Level) UnmarshalText(b []byte) error {
	if !slices.Contains(levels, string(b)) {
		return fmt.Errorf("want one of %s", strings.Join(levels, ", "))
	}
	*l = Level(b)
	return nil
}

func (Level) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, levels...), cmdline.NoFiles
}

// Host is looked up in the store when the command runs.
type Host struct {
	Name string
	Addr netip.Addr
}

// Complete offers the hosts of the store that --store names on the line.
func (Host) Complete(line *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	file := "hosts"
	for _, g := range line.Flags {
		if g.Name == "store" {
			file = g.Value
		}
	}
	var names []string
	for name := range stores[file] {
		names = append(names, name)
	}
	slices.Sort(names)
	return cmdline.Words(prefix, names...), cmdline.NoFiles
}

var stores = map[string]map[string]string{
	"hosts": {"alpha": "10.0.0.1", "beta": "10.0.0.2"},
	"lab":   {"gamma": "fd00::3"},
}

type storeKey struct{}

func findHost(ctx context.Context, word string) (Host, error) {
	addr, ok := ctx.Value(storeKey{}).(map[string]string)[word]
	if !ok {
		return Host{}, errors.New("no such host")
	}
	return Host{word, netip.MustParseAddr(addr)}, nil
}

type pingIn struct {
	Host    Host                    `arg:"host" help:"The host to ping"`
	Count   int                     `flag:"count" short:"n" default:"3" help:"How many times"`
	Wait    time.Duration           `flag:"wait" default:"1s" help:"Time between two pings"`
	From    cmdline.Opt[netip.Addr] `flag:"from" help:"Source address"`
	Level   Level                   `flag:"level" default:"mid" help:"How much to print"`
	Via     []Host                  `flag:"via" help:"Hosts to go through"`
	Label   cmdline.Repeat[string]  `flag:"label" short:"l" help:"A label; may be given more than once"`
	Store   cmdline.Path            `flag:"store" default:"hosts" help:"The store of hosts"`
	Verbose bool                    `flag:"verbose" short:"v" help:"Say more"`
}

type shellIn struct {
	Shell string `arg:"shell"`
}

type helpFlag struct {
	Help bool `flag:"help" short:"h" help:"Show help"`
}

func tree(out io.Writer) *cmdline.Tree {
	t, err := cmdline.New(
		cmdline.Group{Name: "toy", Help: "A toy", Flags: []any{helpFlag{}}, Commands: []cmdline.Node{
			cmdline.Group{Name: "net", Help: "Network tools", Flags: []any{helpFlag{}}, Commands: []cmdline.Node{
				cmdline.Command[pingIn]{Name: "ping", Aliases: []string{"p"}, Help: "Ping a host", Flags: []any{helpFlag{}}, Run: func(_ context.Context, in pingIn) error {
					from, given := in.From.Get()
					_, err := fmt.Fprintf(out, "ping %s (%s) n=%d wait=%s from=%v/%v level=%s via=%v labels=%q verbose=%v\n",
						in.Host.Name, in.Host.Addr, in.Count, in.Wait, from, given, in.Level, in.Via, []string(in.Label), in.Verbose)
					return err
				}},
			}},
			cmdline.Command[shellIn]{Name: "completion", Help: "Write a completion script", Run: func(_ context.Context, in shellIn) error {
				return script.Write(out, in.Shell, "toy")
			}},
		}},
		cmdline.Reader(time.ParseDuration),
		cmdline.LateReader(findHost),
	)
	if err != nil {
		panic(err)
	}
	return t
}

// help prints a command from the tree's data.
func help(w io.Writer, c *cmdline.Info) {
	fmt.Fprintf(w, "%s\n\n  %s\n", c.Help, c.Usage)
	for _, s := range c.Commands {
		fmt.Fprintf(w, "  %-28s %s\n", s.Usage, s.Help)
	}
	for _, a := range c.Args {
		fmt.Fprintf(w, "  <%s>  %s\n", a.Name, a.Help)
	}
	for _, f := range c.Flags {
		name := "--" + f.Name
		if f.Short != "" {
			name = "-" + f.Short + ", " + name
		}
		if !f.Bool {
			name += " " + strings.ToLower(f.Type.Name())
		}
		text := f.Help
		if f.Default != "" {
			text += " (default " + f.Default + ")"
		}
		fmt.Fprintf(w, "  %-28s %s\n", name, text)
	}
}

func run(args []string, out, errw io.Writer) int {
	t := tree(out)
	if t.Serve(out, args) {
		return 0
	}
	line, err := t.Parse(args)
	if h, _ := cmdline.Get[helpFlag](line); h.Help { // also next to a wrong count
		help(out, line.Command)
		return 0
	}
	if err == nil && len(line.Command.Commands) > 0 {
		err = fmt.Errorf("%s: a command is needed", line.Command.Usage)
	}
	if err == nil {
		store, _ := cmdline.Get[pingIn](line)
		err = line.Run(context.WithValue(context.Background(), storeKey{}, stores[string(store.Store)]))
	}
	if err != nil {
		fmt.Fprintln(errw, "toy:", err)
		return 2
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
