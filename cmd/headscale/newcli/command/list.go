package command

import (
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
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
// answer is a mark that Run turns into the names of the columns of the
// list the line reaches: after a + or - typed in front for --columns and
// --sort, and with no space after it for --filter, whose operator follows.
const (
	columnsMark = "\x00s"
	filterMark  = "\x00f"
)

func (columnWord) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return []string{columnsMark + prefix}, cmdline.NoFiles
}

func (sortWord) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return []string{columnsMark + prefix}, cmdline.NoFiles
}

func (filterWord) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return []string{filterMark + prefix}, cmdline.NoFiles | cmdline.NoSpace
}

// columnNames turns each mark in the Tab answer of a line into the column
// names of the list that the words before the cursor reach.
func (t *Tree) columnNames(argv []string, answer string) string {
	if !strings.Contains(answer, "\x00") {
		return answer
	}

	var names []string

	if l := t.leaves[t.Reached(argv[1:len(argv)-1])]; l != nil {
		for _, c := range l.info {
			names = append(names, c.Name)
		}
	}

	var b strings.Builder

	for line := range strings.Lines(answer) {
		before, mark, ok := strings.Cut(line, "\x00")
		if !ok {
			b.WriteString(line)

			continue
		}

		prefix, sign := strings.TrimSuffix(mark[1:], "\n"), ""
		if mark[0] == columnsMark[1] && prefix != "" && (prefix[0] == '+' || prefix[0] == '-') {
			sign, prefix = prefix[:1], prefix[1:]
		}

		// A column that --columns names already is not offered again: the
		// line would then name it twice, which is a mistake.
		taken := map[string]bool{}

		if mark[0] == columnsMark[1] {
			for w := range strings.SplitSeq(before, ",") {
				taken[strings.TrimLeft(w, "+-")] = true
			}
		}

		for _, n := range cmdline.Words(prefix, names...) {
			if !taken[n] {
				b.WriteString(before + sign + n + "\n")
			}
		}
	}

	return b.String()
}

// listCheck is the first value of the list flags on line that cols
// refuses, with its place: an unknown column, a column named twice, a
// filter its kind refuses, a --columns that mixes plain names with + and -
// entries, and --columns with -o json, which has the whole object. command
// is the line of the list, for the pointer to --list-columns.
func listCheck[R any](cols table.Columns[R], line *cmdline.Line, command string) (int, error) {
	bad := func(g cmdline.Given, err error) error {
		m, ok := err.(*table.ValueError) //nolint:errorlint // Find and ParseFilter return it bare
		if ok && m.Unknown {
			return usagef(cmdline.BadValue, line.Command.Path, "--"+g.Name, "%s\nRun `%s --list-columns`.", m.Text, command)
		}

		return usagef(cmdline.BadValue, line.Command.Path, "--"+g.Name, "%s", err.Error())
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

			if out := slices.IndexFunc(line.Flags, func(g cmdline.Given) bool { return g.Name == "output" }); out >= 0 {
				return max(g.At, line.Flags[out].At), usagef(cmdline.BadValue, line.Command.Path, "--"+g.Name,
					"--columns works on tables only. JSON has the whole object.\nTo pick fields: ... -o json | jq '.[] | {%s}'", fieldsOf(cols, g.Value))
			}
		}
	}

	return 0, nil
}

// columnsCheck checks a value of --columns: every name is a column, named
// once, and the list is plain or only + and - entries.
func columnsCheck[R any](cols table.Columns[R], value string) error {
	seen := map[string]bool{}
	signs := 0
	words := strings.Split(value, ",")

	for _, w := range words {
		name := strings.TrimLeft(w, "+-")
		if len(name) < len(w) {
			signs++
		}

		_, err := cols.Find(name)
		if err != nil {
			return err
		}

		if seen[name] {
			return &table.ValueError{Text: "--columns names " + `"` + name + `"` + " twice."}
		}

		seen[name] = true
	}

	if signs > 0 && signs < len(words) {
		return &table.ValueError{Text: "--columns takes a plain list, or only + and - entries. Not both."}
	}

	return nil
}

// fieldsOf are the API fields of the columns that a value of --columns
// shows, for the jq hint.
func fieldsOf[R any](cols table.Columns[R], value string) string {
	var fields []string

	for w := range strings.SplitSeq(value, ",") {
		if strings.HasPrefix(w, "-") {
			continue
		}

		c, err := cols.Find(strings.TrimPrefix(w, "+"))
		if err == nil {
			fields = append(fields, c.Field)
		}
	}

	return strings.Join(fields, ", ")
}

// filters are the conditions of --filter, read with the columns of the
// list, each owner=<user> resolved to its user like a target, before the
// list is read.
func filters[R any](c Ctx, cols table.Columns[R], f listFlags) ([]table.Filter[R], error) {
	var out []table.Filter[R]

	for _, group := range f.Filter {
		for _, w := range group {
			cd, err := cols.ParseFilter(string(w))
			if err != nil {
				return nil, err
			}

			if word, ok := cd.User(); ok {
				u, err := findUser(c, word)
				if err != nil {
					return nil, err
				}

				cd.Resolve(u.Id)
			}

			out = append(out, cd)
		}
	}

	return out, nil
}

// listOf keeps the rows that match every condition and sorts them by
// --sort. The rows are all rows: the walk read every page.
func listOf[R any](c Ctx, cols table.Columns[R], rows []R, conds []table.Filter[R], key sortWord) ([]R, error) {
	var kept []R

	for _, r := range rows {
		ok := true

		for _, cd := range conds {
			match, err := cd.Match(r, c.Now())
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
		cols.Sort(kept, string(key), c.Now())
	}

	return kept, nil
}

// words are the column names --columns gave.
func (f listFlags) words() []string {
	out := make([]string, len(f.Columns))
	for i, c := range f.Columns {
		out[i] = string(c)
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
