package command

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/table"
)

// listFlags are the flags the builder gives every list. The parser keeps
// their values as text; the builder checks them against the columns of the
// list the line reaches, which only it knows, and Tab asks it for the
// names.
type listFlags struct {
	Columns     []columnWord                 `flag:"columns"      help:"Columns to show: a list, or +name and -name to change the default"`
	ListColumns bool                         `flag:"list-columns" help:"List the columns, the API field behind each, and exit"`
	Filter      cmdline.Repeat[[]filterWord] `flag:"filter"       help:"Keep the rows that match; may be repeated"`
	Sort        sortWord                     `flag:"sort"         help:"Column to sort by; -name sorts in reverse"`
}

// columnWord is an item of --columns: a column, or one with + or - to
// change the default columns.
type columnWord string

// sortWord is the value of --sort: a column, with - to reverse.
type sortWord string

// filterWord is one condition of --filter.
type filterWord string

func (w *columnWord) UnmarshalText(b []byte) error { *w = columnWord(b); return nil }
func (w *sortWord) UnmarshalText(b []byte) error   { *w = sortWord(b); return nil }
func (w *filterWord) UnmarshalText(b []byte) error { *w = filterWord(b); return nil }

// A type of the parser cannot know the list it is read for, so its Tab
// answer is a mark, with the command the line reached, that Run turns into
// the names of the columns of that list: after a + or - typed in front for
// --columns and --sort, and with no space after it for --filter, whose
// operator follows.
const (
	columnsMark = "\x00s"
	sortMark    = "\x00o"
	filterMark  = "\x00f"
)

func (columnWord) Complete(
	l *cmdline.Line,
	prefix string,
) ([]string, cmdline.Directive) {
	return marked(columnsMark, l, prefix), cmdline.NoFiles
}

func (sortWord) Complete(l *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return marked(sortMark, l, prefix), cmdline.NoFiles
}

func (filterWord) Complete(
	l *cmdline.Line,
	prefix string,
) ([]string, cmdline.Directive) {
	return marked(filterMark, l, prefix), cmdline.NoFiles | cmdline.NoSpace
}

// marked carries the command that Tab reached: a strict parse of the words
// stops at a mistake before the command, which Tab steps over. A tab or a
// line break in the prefix gets nothing: the answer to the shell is one
// word a line, with a tab before its description.
func marked(mark string, l *cmdline.Line, prefix string) []string {
	if strings.ContainsAny(prefix, "\t\r\n") {
		return nil
	}

	return []string{mark + strings.Join(l.Command.Path, " ") + "\x00" + prefix}
}

// columnNames turns each mark in the Tab answer of a line into the column
// names of the list the mark names.
func (t *Tree) columnNames(answer string) string {
	if !strings.Contains(answer, "\x00") {
		return answer
	}

	var b strings.Builder

	for line := range strings.Lines(answer) {
		before, mark, ok := strings.Cut(line, "\x00")
		if !ok {
			b.WriteString(line)

			continue
		}

		path, rest, _ := strings.Cut(mark[1:], "\x00")

		var names []string

		l := t.leaves[path]
		if l != nil {
			for _, c := range l.info {
				names = append(names, c.Name)
			}
		}

		// An item before the one being typed that the run refuses: no name
		// typed after it makes a line the run takes. A list that mixes plain
		// and signed items is the one the run refuses that Tab goes on in
		// (003-cmdline E6, kit Q35).
		if sealed, ok := strings.CutSuffix(before, ","); ok && l != nil {
			flag := map[byte]string{columnsMark[1]: "columns", filterMark[1]: "filter"}[mark[0]]
			line := &cmdline.Line{
				Command: &cmdline.Info{},
				Flags:   []cmdline.Given{{Name: flag, Value: sealed}},
			}

			// The run refuses a mix, and a list that has taken away every
			// column so far, but typing on can repair either.
			_, err := l.checkList(line, "")
			if err != nil && !strings.Contains(err.Error(), mixedColumns) &&
				!strings.Contains(err.Error(), noColumns) {
				continue
			}
		}

		prefix, sign, ok := signed(mark[0], strings.TrimSuffix(rest, "\n"))
		if !ok {
			continue
		}

		for _, n := range cmdline.Words(prefix, names...) {
			b.WriteString(before + sign + n + "\n")
		}
	}

	return b.String()
}

// signed splits the sign the item being typed starts with off its prefix:
// + or - for --columns, - for --sort, none for --filter. false when the
// sign is not one the flag takes, which Tab then offers nothing for. The
// items before do not count: Tab goes on in a list that mixes plain names
// with + and - (003-cmdline E6, kit Q35), and Run refuses it there.
func signed(mark byte, prefix string) (string, string, bool) {
	if mark == filterMark[1] || prefix == "" || prefix[0] != '+' && prefix[0] != '-' {
		return prefix, "", true
	}

	return prefix[1:], prefix[:1], mark == columnsMark[1] || prefix[0] == '-'
}

// listCheck is the first value of the list flags on line that cols
// refuses, with its place: an unknown column, a column named twice, a
// filter its kind refuses, a --columns that mixes plain names with + and -
// entries, and --columns with -o json, which has the whole object. command
// is the line of the list, for the pointer to --list-columns.
func listCheck[R any](
	cols table.Columns[R],
	line *cmdline.Line,
	command string,
) (int, error) {
	bad := func(g cmdline.Given, err error) error {
		//nolint:errorlint // Find and ParseFilter return it bare
		m, ok := err.(*table.ValueError)
		if ok && m.Unknown {
			return usagef(
				cmdline.BadValue,
				line.Command.Path,
				"--"+g.Name,
				"%s\nRun `%s --list-columns`.",
				m.Text,
				command,
			)
		}

		return usagef(
			cmdline.BadValue,
			line.Command.Path,
			"--"+g.Name,
			"%s",
			err.Error(),
		)
	}

	for _, g := range line.Flags {
		switch g.Name {
		case "sort":
			_, err := cols.Find(strings.TrimPrefix(g.Value, "-"))
			if err != nil {
				return g.At, bad(g, err)
			}
		case "filter":
			for item := range strings.SplitSeq(g.Value, ",") {
				_, err := cols.ParseFilter(item)
				if err != nil {
					return g.At, bad(g, err)
				}
			}
		case "columns":
			err := columnsCheck(cols, g.Value)
			if err != nil {
				return g.At, bad(g, err)
			}

			if len(cols.Pick(trimmedItems(g.Value))) == 0 {
				return g.At, bad(g, &table.ValueError{Text: noColumns})
			}

			if out := slices.IndexFunc(
				line.Flags,
				func(g cmdline.Given) bool { return g.Name == "output" },
			); out >= 0 {
				return max(
						g.At,
						line.Flags[out].At,
					), usagef(
						cmdline.BadValue,
						line.Command.Path,
						"--"+g.Name,
						"--columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {%s}'",
						fieldsOf(cols, g.Value),
					)
			}
		}
	}

	return 0, nil
}

// columnsCheck checks a value of --columns: every name is a column, not
// both added and taken away, and the list is plain or only + and - entries.
// A repeated item counts once.
func columnsCheck[R any](cols table.Columns[R], value string) error {
	seen := map[string]string{}
	signs := 0
	words := strings.Split(value, ",")

	for _, w := range words {
		name := w
		if w != "" && (w[0] == '+' || w[0] == '-') {
			name = w[1:]
			signs++
		}

		_, err := cols.Find(name)
		if err != nil {
			return err
		}

		if item, ok := seen[name]; ok && item != w {
			return &table.ValueError{
				Text: "--columns names " + `"` + name + `"` + " twice.",
			}
		}

		seen[name] = w
	}

	if signs > 0 && signs < len(words) {
		return &table.ValueError{Text: mixedColumns}
	}

	return nil
}

const mixedColumns = "--columns takes a plain list, or only + and - entries. Not both."

// noColumns refuses a --columns that takes away every column the table
// would show; with -o json too, since the mistake is in the line.
const noColumns = "--columns leaves no column to show."

// trimmedItems are the items of a list value, without the space around
// each, as the parser hands them to the run.
func trimmedItems(value string) []string {
	var out []string

	for w := range strings.SplitSeq(value, ",") {
		out = append(out, strings.TrimSpace(w))
	}

	return out
}

// fieldsOf is the jq object of the columns that a value of --columns
// shows, for the hint: a field by its name, a path under the name of its
// column.
func fieldsOf[R any](cols table.Columns[R], value string) string {
	var words, fields []string

	for w := range strings.SplitSeq(value, ",") {
		words = append(words, strings.TrimSpace(w))
	}

	for _, c := range cols.Pick(words) {
		f := c.Field
		if strings.ContainsFunc(
			f,
			func(r rune) bool { return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) },
		) {
			f = strconv.Quote(c.Name) + ": ." + f
		}

		if !slices.Contains(fields, f) {
			fields = append(fields, f)
		}
	}

	return strings.Join(fields, ", ")
}

// filters are the conditions of --filter, read with the columns of the
// list, each owner=<user> resolved to its user like a target, before the
// list is read.
func filters[R any](
	c *run,
	ctx context.Context,
	cols table.Columns[R],
	f listFlags,
) ([]table.Filter[R], error) {
	var out []table.Filter[R]

	for _, group := range f.Filter {
		for _, w := range group {
			cd, err := cols.ParseFilter(string(w))
			if err != nil {
				return nil, err
			}

			if word, ok := cd.User(); ok && c.tree.prog.Owner != nil {
				id, err := c.tree.prog.Owner(ctx, word)
				if err != nil {
					return nil, err
				}

				cd.Resolve(id)
			}

			out = append(out, cd)
		}
	}

	return out, nil
}

// listOf keeps the rows that match every condition and sorts them by
// --sort. The rows are all rows: the walk read every page.
func listOf[R any](
	c *run,
	cols table.Columns[R],
	rows []R,
	conds []table.Filter[R],
	key sortWord,
) ([]R, error) {
	// One clock for the whole list: a row read at two instants could pass
	// last-seen<1h and last-seen>1h together.
	now := c.Now()

	var kept []R

	for _, r := range rows {
		ok := true

		for _, cd := range conds {
			match, err := cd.Match(r, now)
			if err != nil {
				return nil, err
			}

			ok = ok && match
		}

		if ok {
			kept = append(kept, r)
		}
	}

	if key != "" {
		cols.Sort(kept, string(key), now)
	}

	return kept, nil
}

// words are the column names --columns gave, each once.
func (f listFlags) words() []string {
	var out []string

	for _, c := range f.Columns {
		if !slices.Contains(out, string(c)) {
			out = append(out, string(c))
		}
	}

	return out
}

// listColumns writes --list-columns: the declaration as a table, or with
// -o json as the CLI's own objects.
func listColumns(w io.Writer, cols []table.ColumnInfo, asJSON bool) error {
	if !asJSON {
		return table.Declaration(w, cols)
	}

	b, err := json.Marshal(cols)
	if err != nil {
		return err
	}

	return writeJSON(w, b)
}

// filterExample is the value of the first --filter in examples, for the
// help of --filter; "" when no example filters.
func filterExample(examples []string) string {
	for _, e := range examples {
		words := strings.Fields(e)
		for i, w := range words {
			v, ok := strings.CutPrefix(w, "--filter=")
			if !ok && w == "--filter" && i+1 < len(words) {
				v, ok = words[i+1], true
			}

			if ok {
				return strings.Trim(v, `'"`)
			}
		}
	}

	return ""
}
