package command

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/cmdline/table"
)

// The default filter of a list, ListSpec.Only: the API gives every row, and
// the list hides the ones a person rarely wants unless --all, or a filter
// on the column of Only, asks for them.

var (
	errOnlyShown = errors.New(
		"is a Default column: --all adds the column of Only to the defaults",
	)
	errOnlySay = errors.New(
		"a list with Only hides rows, and Long does not say what --all shows",
	)
)

// allFlags is --all, which a list with Only takes.
type allFlags struct {
	All bool `flag:"all" help:"Show every row"`
}

// checkOnly is what is wrong with the default filter of a list: one that
// does not parse, one on a column shown anyway, one Long does not explain.
func checkOnly[Row any](cols table.Columns[Row], only, long string) []error {
	if only == "" {
		return nil
	}

	var errs []error

	o, err := cols.ParseFilter(only)
	if err == nil {
		c, _ := cols.Find(o.Column())
		if c.Default {
			err = fmt.Errorf("column %q %w", c.Name, errOnlyShown)
		}
	}

	if err != nil {
		errs = append(errs, fmt.Errorf("the filter Only %q: %w", only, err))
	}

	if !strings.Contains(long, "--all") {
		errs = append(errs, errOnlySay)
	}

	return errs
}

// applyOnly is the columns and the default filter of a line: --all shows
// the column of Only and filters nothing, a filter on that column replaces
// it, and otherwise it hides rows.
func applyOnly[Row any](
	cols table.Columns[Row],
	only string,
	all bool,
	conds []table.Filter[Row],
) (table.Columns[Row], []table.Filter[Row]) {
	if only == "" {
		return cols, nil
	}

	o, _ := cols.ParseFilter(only)

	switch {
	case all:
		return cols.Shown(o.Column()), nil
	case slices.ContainsFunc(conds, func(c table.Filter[Row]) bool { return c.Column() == o.Column() }):
		return cols, nil
	}

	return cols, []table.Filter[Row]{o}
}

// moreRows is what an empty list says on a terminal when Only hid rows.
func moreRows(noRows string, hidden int) string {
	if hidden == 0 {
		return noRows
	}

	return noRows + " --all shows " + strconv.Itoa(hidden) + " more."
}

// onlyInfo is the columns as --list-columns prints them: the column of
// Only says what the list hides and that --all shows it.
func onlyInfo[Row any](cols table.Columns[Row], only string) []table.ColumnInfo {
	info := cols.Info()
	if only == "" {
		return info
	}

	o, _ := cols.ParseFilter(only)

	for i := range info {
		if info[i].Name == o.Column() {
			info[i].Help = strings.TrimPrefix(
				info[i].Help+"; ",
				"; ",
			) + "the list shows only " + only + ", --all every row and this column"
		}
	}

	return info
}
