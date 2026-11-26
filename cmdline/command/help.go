package command

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"

	"github.com/juanfont/headscale/cmdline"
)

// help writes the help of c: the whole tree at the root, the sub-tree and
// examples at a group, and the long text, usage, examples and flags at a
// command.
// It is written whole once; a write that fails stops the run.
func (t *Tree) help(w io.Writer, c *cmdline.Info) error {
	at := strings.Join(c.Path, " ")

	var b bytes.Buffer

	switch l, ok := t.leaves[at]; {
	case len(c.Path) == 0:
		t.rootHelp(&b, c)
	case ok:
		t.commandHelp(&b, c, l)
	default:
		t.groupHelp(&b, c)
	}

	_, err := w.Write(b.Bytes())

	return err
}

func (t *Tree) rootHelp(w io.Writer, root *cmdline.Info) {
	fmt.Fprintf(w, "%s\n", t.short)

	var local, server, debug []*cmdline.Info

	for _, c := range runnable(root) {
		l := t.leaves[strings.Join(c.Path, " ")]

		switch {
		case c.Path[0] == "debug":
			debug = append(debug, c)
		case l.local:
			local = append(local, c)
		default:
			server = append(server, c)
		}
	}

	wd := width(runnable(root), 0)
	section(w, "Local commands (no server needed):", local, 0, wd)
	section(w, "Server commands (talk to "+t.prog.Server+"):", server, 0, wd)
	section(w, "Debug:", debug, 0, wd)

	fmt.Fprintf(w, "\nServer commands take -o json, which prints the API object.\n")
	fmt.Fprintf(w, "See `%s <command> --help` for examples.\n", t.name)
}

func (t *Tree) groupHelp(w io.Writer, g *cmdline.Info) {
	fmt.Fprintf(w, "%s\n", g.Help)

	cmds := runnable(g)
	section(w, "Commands:", cmds, len(g.Path), width(cmds, len(g.Path)))

	fmt.Fprintf(w, "\nExamples:\n\n")

	for _, c := range cmds {
		if l := t.leaves[strings.Join(c.Path, " ")]; len(l.example) > 0 {
			fmt.Fprintf(w, "  %s\n", l.example[0])
		}
	}
}

func (t *Tree) commandHelp(w io.Writer, c *cmdline.Info, l *leaf) {
	fmt.Fprintf(w, "%s\n\nUsage:\n\n  %s [flags]\n", strings.TrimSpace(l.long), c.Usage)

	for _, a := range c.Args {
		if a.Help != "" {
			fmt.Fprintf(w, "\n  %s\n", a.Help)
		}
	}

	if len(c.Aliases) > 0 {
		fmt.Fprintf(w, "\nAliases: %s\n", strings.Join(c.Aliases, ", "))
	}

	fmt.Fprintf(w, "\nExamples:\n\n")

	for _, e := range l.example {
		fmt.Fprintf(w, "  %s\n", e)
	}

	fmt.Fprintf(w, "\nFlags:\n\n")

	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)

	for _, f := range c.Flags {
		short := "    "
		if f.Short != "" {
			short = "-" + f.Short + ", "
		}

		name := "--" + f.Name
		if !f.Bool {
			name += " " + typeWord(f.Type)
		}

		help := f.Help
		if f.Name == "filter" && l.filter != "" {
			help = strings.Replace(help, "match;", "match, such as "+l.filter+";", 1)
		}

		if f.Name == "all" && l.only != "" {
			help += ", not only " + l.only
		}

		if f.Default != "" {
			help += " (default " + f.Default + ")"
		}

		fmt.Fprintf(tw, "  %s%s\t%s\n", short, name, help)
	}

	tw.Flush()
}

// section lists the commands under a heading: the path below the group at
// depth, the arguments, the short text and the aliases. The short texts
// line up across the sections of one help.
func section(w io.Writer, heading string, cmds []*cmdline.Info, depth, width int) {
	if len(cmds) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s\n\n", heading)

	for _, c := range cmds {
		short := c.Help
		if len(c.Aliases) > 0 {
			short += " (alias: " + strings.Join(c.Aliases, ", ") + ")"
		}

		fmt.Fprintf(w, "  %-*s%s\n", width, usage(c, depth), short)
	}
}

// usage is the path of c below depth, with its arguments.
func usage(c *cmdline.Info, depth int) string {
	var b strings.Builder

	b.WriteString(strings.Join(c.Path[depth:], " "))

	for _, a := range c.Args {
		if a.Optional {
			b.WriteString(" [" + a.Name + "]")
		} else {
			b.WriteString(" <" + a.Name + ">")
		}
	}

	return b.String()
}

// width is the column of the short texts: three spaces past the widest
// usage.
func width(cmds []*cmdline.Info, depth int) int {
	w := 0
	for _, c := range cmds {
		w = max(w, len(usage(c, depth)))
	}

	return w + 3
}

// runnable lists every command below c that runs, in the order of the
// tree.
func runnable(c *cmdline.Info) []*cmdline.Info {
	var out []*cmdline.Info

	for _, s := range c.Commands {
		if len(s.Commands) == 0 {
			out = append(out, s)
		}

		out = append(out, runnable(s)...)
	}

	return out
}

// typeWord names the type of a flag's value in the help.
func typeWord(t reflect.Type) string {
	switch t.Kind() { //nolint:exhaustive // every other value is text
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	default:
		return "string"
	}
}
