package command

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmdline"
)

// Reference is the reference page of the tree that runs, in Markdown: what
// the program's Doc.Reference prints.
func (c *run) Reference() string { return c.tree.reference() }

// Man is the man page of the tree that runs, in roff: what the program's
// Doc.Man prints.
func (c *run) Man() string { return c.tree.man() }

// docPage is what both pages hold, read from the specs as the help reads
// them: the whole tree, the flags of more than one command, and the help
// of each command in the order of the tree.
type docPage struct {
	tree     string
	flags    [][3]string // flag, short, the commands that take it
	shorts   [][3]string // short, long, the commands that take it
	aliases  [][3]string // alias, the command word it stands for, where
	commands []pageCommand
}

type pageCommand struct {
	path, short, help, columns string
}

func (t *Tree) docPage() docPage {
	var p docPage

	root := t.parser.Root()

	var b strings.Builder
	t.rootHelp(&b, root)
	p.tree = b.String()

	cmds := runnable(root)

	takes := func(name string) []*cmdline.Info {
		var out []*cmdline.Info

		for _, c := range cmds {
			if slices.ContainsFunc(
				c.Flags,
				func(f cmdline.Flag) bool { return f.Name == name },
			) {
				out = append(out, c)
			}
		}

		return out
	}

	p.flags = [][3]string{
		{"--output", "-o", t.on(takes("output"), cmds)},
		{"--config", "-c", t.on(takes("config"), cmds)},
		{"--help", "-h", "every command"},
	}

	// A program with no Version has no --version.
	if t.prog.Version != nil {
		p.flags = append(p.flags, [3]string{"--version", "", "`" + t.name + "` alone"})
	}

	global := []string{"output", "config", "help"}
	seen := map[string]bool{}

	for _, c := range cmds {
		for _, f := range c.Flags {
			if f.Short == "" || seen[f.Short] {
				continue
			}

			seen[f.Short] = true

			on := "see [Global flags](#global-flags)"
			if !slices.Contains(global, f.Name) {
				on = paths(takes(f.Name))
			}

			p.shorts = append(p.shorts, [3]string{"-" + f.Short, "--" + f.Name, on})
		}
	}

	slices.SortFunc(
		p.shorts,
		func(a, b [3]string) int { return strings.Compare(a[0], b[0]) },
	)

	for _, alias := range t.prog.Aliases {
		var where []*cmdline.Info

		means := ""

		for _, c := range cmds {
			if slices.Contains(c.Aliases, alias) {
				where = append(where, c)
				means = "`" + c.Name + "`"
			}
		}

		if len(where) > 0 {
			p.aliases = append(
				p.aliases,
				[3]string{"`" + alias + "`", means, paths(where)},
			)
		}
	}

	for _, c := range cmds {
		l := t.leaves[strings.Join(c.Path, " ")]

		var help, columns strings.Builder

		t.commandHelp(&help, c, l)

		if l.list {
			_ = listColumns(&columns, l.info, false)
		}

		p.commands = append(
			p.commands,
			pageCommand{
				path:    t.line(c.Path),
				short:   c.Help,
				help:    help.String(),
				columns: columns.String(),
			},
		)
	}

	return p
}

// on says which commands take a flag: every server command, and the local
// ones that take it by name.
func (t *Tree) on(have, all []*cmdline.Info) string {
	var server, local []*cmdline.Info

	for _, c := range all {
		if !t.leaves[strings.Join(c.Path, " ")].local {
			server = append(server, c)
		}
	}

	for _, c := range have {
		if t.leaves[strings.Join(c.Path, " ")].local {
			local = append(local, c)
		}
	}

	if !slices.ContainsFunc(
		server,
		func(c *cmdline.Info) bool { return !slices.Contains(have, c) },
	) {
		if len(local) == 0 {
			return "every server command"
		}

		return "every server command, and " + paths(local)
	}

	return paths(have)
}

// paths names commands by their paths, in backquotes.
func paths(cmds []*cmdline.Info) string {
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = "`" + strings.Join(c.Path, " ") + "`"
	}

	return strings.Join(names, ", ")
}

func (t *Tree) reference() string {
	p := t.docPage()

	var b strings.Builder

	fmt.Fprintf(
		&b,
		"<!-- Generated from the command specs by `%s`; do not edit. -->\n\n",
		t.prog.Doc.Reference,
	)
	b.WriteString("# Command line reference\n\n")
	b.WriteString("!!! note \"Generated page\"\n\n")
	fmt.Fprintf(
		&b,
		"    This page is generated from the command specs in `%s` by `%s`.\n",
		t.prog.Doc.Source,
		t.prog.Doc.Reference,
	)
	fmt.Fprintf(
		&b,
		"    Edit the specs, not this page. `man %s` shows the same.\n\n",
		t.name,
	)
	b.WriteString("## Command tree\n\n")
	fence(&b, p.tree)

	b.WriteString("## Global flags\n\n")
	mdTable(&b, [3]string{"Flag", "Short", "On"}, p.flags, func(r [3]string) [3]string {
		if r[1] != "" {
			r[1] = "`" + r[1] + "`"
		}

		return [3]string{"`" + r[0] + "`", r[1], r[2]}
	})

	b.WriteString("## Short flags\n\n")
	b.WriteString(
		"A short flag has one meaning in the whole CLI. Every other flag is long only.\n\n",
	)
	mdTable(
		&b,
		[3]string{"Short", "Long", "On"},
		p.shorts,
		func(r [3]string) [3]string {
			return [3]string{"`" + r[0] + "`", "`" + r[1] + "`", r[2]}
		},
	)

	b.WriteString("## Aliases\n\n")
	mdTable(
		&b,
		[3]string{"Alias", "Means", "On"},
		p.aliases,
		func(r [3]string) [3]string { return r },
	)

	b.WriteString("## Commands\n\n")

	for _, c := range p.commands {
		fmt.Fprintf(&b, "### %s\n\n%s.\n\n", c.path, c.short)
		fence(&b, c.help)

		if c.columns != "" {
			b.WriteString("Columns:\n\n")
			fence(&b, c.columns)
		}
	}

	return strings.TrimSuffix(b.String(), "\n")
}

// fence writes text as a fenced block of plain text.
func fence(w io.Writer, text string) {
	fmt.Fprintf(w, "```text\n%s\n```\n\n", strings.TrimRight(text, "\n"))
}

// mdTable writes rows as a table, with each column as wide as its widest
// cell, as mdformat writes one.
func mdTable(
	w io.Writer,
	head [3]string,
	rows [][3]string,
	cells func([3]string) [3]string,
) {
	all := make([][3]string, 0, 1+len(rows))

	all = append(all, head)
	for _, r := range rows {
		all = append(all, cells(r))
	}

	var width [3]int

	for _, r := range all {
		for i, c := range r {
			width[i] = max(width[i], len([]rune(c)), 3)
		}
	}

	line := func(r [3]string) {
		for i, c := range r {
			fmt.Fprintf(w, "| %s%s ", c, strings.Repeat(" ", width[i]-len([]rune(c))))
		}

		fmt.Fprintln(w, "|")
	}

	line(all[0])

	for i := range width {
		fmt.Fprintf(w, "| %s ", strings.Repeat("-", width[i]))
	}

	fmt.Fprintln(w, "|")

	for _, r := range all[1:] {
		line(r)
	}

	fmt.Fprintln(w)
}

func (t *Tree) man() string {
	p := t.docPage()

	var b strings.Builder

	// No date: the page changes only with the specs, which a date would
	// not follow.
	fmt.Fprintf(
		&b,
		".\\\" Generated from the command specs by `%s`; do not edit.\n",
		t.prog.Doc.Man,
	)
	fmt.Fprintf(
		&b,
		".TH %s 1 \"\" \"%s\" \"User Commands\"\n",
		strings.ToUpper(t.name),
		t.name,
	)
	fmt.Fprintf(
		&b,
		".SH NAME\n%s\n",
		fill(t.name+" \\- "+roff(strings.TrimPrefix(t.short, t.name+" is "))),
	)
	fmt.Fprintf(&b, ".SH SYNOPSIS\n.B %s\n.I command\n.RI [ flags ]\n", t.name)
	b.WriteString(".SH DESCRIPTION\n")
	b.WriteString(
		fill(
			"This page holds every command of "+t.name+": the tree, the flags that more than one command takes, and the help of each command.",
		) + "\n",
	)
	b.WriteString(".SH COMMANDS\n")
	noFill(&b, p.tree)

	b.WriteString(".SH GLOBAL FLAGS\n")

	for _, f := range p.flags {
		name := "\\-\\-" + strings.TrimPrefix(f[0], "--")
		if f[1] != "" {
			name = "\\-" + strings.TrimPrefix(f[1], "-") + ", " + name
		}

		fmt.Fprintf(&b, ".TP\n.B %s\n%s\n", name, fill("On "+roff(unquote(f[2]))+"."))
	}

	b.WriteString(
		".SH SHORT FLAGS\n" + fill(
			"A short flag has one meaning in the whole CLI. Every other flag is long only.",
		) + "\n",
	)

	for _, s := range p.shorts {
		on := s[2]
		if strings.HasPrefix(on, "see ") {
			on = "see GLOBAL FLAGS"
		}

		fmt.Fprintf(
			&b,
			".TP\n.B \\-%s\n%s\n",
			strings.TrimPrefix(s[0], "-"),
			fill(roff(s[1])+", on "+roff(unquote(on))+"."),
		)
	}

	b.WriteString(".SH ALIASES\n")

	for _, a := range p.aliases {
		fmt.Fprintf(
			&b,
			".TP\n.B %s\n%s\n",
			roff(unquote(a[0])),
			fill(roff(unquote(a[1]))+", on "+roff(unquote(a[2]))+"."),
		)
	}

	b.WriteString(".SH COMMAND HELP\n")

	for _, c := range p.commands {
		fmt.Fprintf(&b, ".SS \"%s\"\n%s\n.PP\n", roff(c.path), fill(roff(c.short)+"."))
		noFill(&b, c.help)

		if c.columns != "" {
			b.WriteString(".PP\nColumns:\n.PP\n")
			noFill(&b, c.columns)
		}
	}

	b.WriteString(".SH SEE ALSO\n" + t.prog.Doc.SeeAlso + "\n")

	return b.String()
}

// noFill writes text as roff that keeps its lines and spaces.
func noFill(w io.Writer, text string) {
	fmt.Fprintf(w, ".nf\n%s\n.fi\n", roff(strings.TrimRight(text, "\n")))
}

// fill breaks text, which roff fills again, into lines of at most 80
// bytes, so a reader of the source sees whole lines.
func fill(text string) string {
	var (
		lines []string
		line  string
	)

	for w := range strings.FieldsSeq(text) {
		if line != "" && len(line)+1+len(w) > 80 {
			lines = append(lines, line)
			line = ""
		}

		line = strings.TrimPrefix(line+" "+w, " ")
	}

	return strings.Join(append(lines, line), "\n")
}

// roff escapes text for roff: a backslash, a dash, and a line that would
// read as a request.
func roff(text string) string {
	text = strings.NewReplacer(`\`, `\e`, "-", `\-`).Replace(text)

	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, ".") || strings.HasPrefix(l, "'") {
			lines[i] = `\&` + l
		}
	}

	return strings.Join(lines, "\n")
}

// unquote drops the backquotes and links of Markdown.
func unquote(s string) string {
	return strings.ReplaceAll(s, "`", "")
}
