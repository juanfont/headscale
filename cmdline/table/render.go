package table

import (
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/clipperhouse/displaywidth"
)

// Screen is a terminal that a table is shown on. Its width is in cells; 0
// cuts nothing.
type Screen struct {
	Width  int
	Colour bool
}

// Render writes rows as a table of shown, [Columns.Pick] choosing the
// columns. For a pipe, screen is nil: no colour, no cut, one line per row,
// lists inline. On a screen a stacked list takes a line per entry, and a
// table wider than the screen gives way in the order of [Column.tier].
func Render[R any](
	w io.Writer,
	rows []R,
	shown Columns[R],
	now time.Time,
	screen *Screen,
) error {
	if screen == nil {
		lines := make([][]string, 0, len(rows)+1)

		header := make([]string, len(shown))
		for i, c := range shown {
			header[i] = c.header()
		}

		lines = append(lines, header)

		for _, r := range rows {
			line := make([]string, len(shown))
			for i, c := range shown {
				line[i] = c.cell(r, now, false)
			}

			lines = append(lines, line)
		}

		return aligned(w, lines)
	}

	return onScreen(w, rows, shown, now, *screen)
}

// shownCell is a cell on a screen: its lines, or the entries of a list
// that gives way by whole entries, and the colour it is drawn in.
type shownCell struct {
	lines   []string
	entries []string
	cut     bool
	tone    string
}

func (s shownCell) natural() int {
	if s.cut {
		return width(strings.Join(s.entries, ", "))
	}

	n := 0
	for _, l := range s.lines {
		n = max(n, width(l))
	}

	return n
}

// floor is the narrowest a list cell gets: its first entry and the count
// of the others, so a cell never hides all it holds nor cuts an entry.
func (s shownCell) floor() int {
	switch {
	case !s.cut || len(s.entries) == 0:
		return 0
	case len(s.entries) == 1:
		return width(s.entries[0])
	}

	return width(s.entries[0] + " … (+" + strconv.Itoa(len(s.entries)-1) + ")")
}

// The colours of a screen: the header bold, a cell that holds nothing dim,
// and a time ahead that has passed, such as an expiry, red.
const (
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
	red   = "\x1b[31m"
	reset = "\x1b[0m"
)

func onScreen[R any](
	w io.Writer,
	rows []R,
	shown Columns[R],
	now time.Time,
	screen Screen,
) error {
	grid := make([][]shownCell, 0, len(rows)+1)

	header := make([]shownCell, len(shown))
	for i, c := range shown {
		header[i] = shownCell{lines: []string{c.header()}, tone: bold}
	}

	grid = append(grid, header)

	for _, r := range rows {
		line := make([]shownCell, len(shown))
		for i, c := range shown {
			line[i] = c.onScreen(r, now)
		}

		grid = append(grid, line)
	}

	widths, floors, tiers := make(
		[]int,
		len(shown),
	), make(
		[]int,
		len(shown),
	), make(
		[]int,
		len(shown),
	)

	for i, c := range shown {
		t, _ := fieldType(reflect.TypeFor[R](), c.Field)
		tiers[i] = c.tier(t)
		floors[i] = max(header[i].natural(), 1)
	}

	for _, line := range grid {
		for i, cell := range line {
			widths[i] = max(widths[i], cell.natural())
			floors[i] = max(floors[i], cell.floor())
		}
	}

	if screen.Width > 0 {
		narrow(widths, floors, tiers, screen.Width)

		// A list that lost entries can be narrower than its share.
		for i := range widths {
			shown := 0

			for _, line := range grid {
				if line[i].cut {
					shown = max(shown, width(FitList(line[i].entries, widths[i])))
				} else {
					shown = max(shown, min(line[i].natural(), widths[i]))
				}
			}

			widths[i] = shown
		}
	}

	var b strings.Builder

	for _, line := range grid {
		height := 1
		for _, cell := range line {
			height = max(height, len(cell.lines))
		}

		for at := range height {
			texts := make([]string, len(line))

			for i, cell := range line {
				switch {
				case cell.cut && at == 0:
					texts[i] = FitList(cell.entries, widths[i])
				case at < len(cell.lines):
					texts[i] = fit(cell.lines[at], widths[i])
				}
			}

			last := len(texts) - 1
			for last > 0 && texts[last] == "" {
				last--
			}

			for i, text := range texts[:last+1] {
				pad := widths[i] - width(text)

				if screen.Colour && line[i].tone != "" && text != "" {
					text = line[i].tone + text + reset
				}

				b.WriteString(text)

				if i < last {
					b.WriteString(strings.Repeat(" ", pad+2))
				}
			}

			b.WriteByte('\n')
		}
	}

	_, err := io.WriteString(w, b.String())

	return err
}

// The tiers of [Column.tier]: the order in which columns give way.
const (
	fixed = iota
	cutList
	inlineList
	plainText
	naming
)

// tier is when a column gives way to the width of a screen. An ID, a
// number, a bool, a time, a version and a stacked list, whose entries are
// routes, never do. A cut list goes first and an inline list next, each
// by whole entries. Then text is cut, and last what names a row, its name
// and its owner, so a word on the screen can be typed back as a target as
// long as the screen allows.
func (c Column[R]) tier(t reflect.Type) int {
	if t == nil {
		return fixed
	}

	ss, _ := steps(c.Field)
	named := len(ss) > 0 && !ss[len(ss)-1].keyed &&
		strings.HasSuffix(strings.ToLower(ss[len(ss)-1].name), "name")

	switch k := c.kind(t); {
	case k == List && c.List == Cut:
		return cutList
	case k == List && c.List == Inline:
		return inlineList
	case k == Owner, k == Text && named:
		return naming
	case k == Text:
		return plainText
	}

	return fixed
}

// narrow takes cells from the columns of the first tier that gives way,
// the widest first, one cell at a time, until the table fits in total or
// each is down to its floor; then from the next tier. What is still too
// wide runs past the edge.
func narrow(widths, floors, tiers []int, total int) {
	sum := func() int {
		n := 2 * (len(widths) - 1)
		for _, w := range widths {
			n += w
		}

		return n
	}

	for tier := cutList; tier <= naming; tier++ {
		for sum() > total {
			widest := -1

			for i, w := range widths {
				if tiers[i] == tier && w > floors[i] &&
					(widest < 0 || w > widths[widest]) {
					widest = i
				}
			}

			if widest < 0 {
				break
			}

			widths[widest]--
		}
	}
}

// fit is text cut to n cells, ending in "…" when cut.
func fit(
	text string,
	n int,
) string {
	return (displaywidth.Options{}).TruncateString(text, n, "…")
}

// FitList is as many entries as fit in n cells, then "… (+K)" for the K
// left out.
func FitList(entries []string, n int) string {
	// Widths add up entry by entry (see width for where they do not), so
	// each prefix of the list is known without joining it: one pass, not
	// one join per cut.
	joined := make([]int, len(entries)+1)
	for i, e := range entries {
		joined[i+1] = joined[i] + width(e) + 2*min(i, 1)
	}

	for k := len(entries); k >= 0; k-- {
		w := joined[k]
		if k < len(entries) {
			// " … (+K)": the space when entries come first, five cells, K.
			w += min(k, 1) + 5
			for left := len(entries) - k; left > 0; left /= 10 {
				w++
			}
		}

		if w > n {
			continue
		}

		s := strings.Join(entries[:k], ", ")
		if k < len(entries) {
			s = strings.TrimSpace(s + " … (+" + strconv.Itoa(len(entries)-k) + ")")
		}

		return s
	}

	return fit("(+"+strconv.Itoa(len(entries))+")", n)
}

// aligned writes lines of cells in columns: each as wide as its widest
// cell on the screen, two spaces apart. The last cell of a line is not
// padded, nor is a cell that only empty cells follow, so a line ends in
// what its cells hold.
func aligned(w io.Writer, lines [][]string) error {
	var widths []int

	for _, line := range lines {
		for i, cell := range line {
			if i == len(widths) {
				widths = append(widths, 0)
			}

			widths[i] = max(widths[i], width(cell))
		}
	}

	var b strings.Builder

	for _, line := range lines {
		last := len(line) - 1
		for last > 0 && line[last] == "" {
			last--
		}

		for i, cell := range line[:last+1] {
			b.WriteString(cell)

			if i < last {
				b.WriteString(strings.Repeat(" ", widths[i]-width(cell)+2))
			}
		}

		b.WriteByte('\n')
	}

	_, err := io.WriteString(w, b.String())

	return err
}

// width counts display cells using the same grapheme boundaries as fit.
// Limit: a cell or list entry is measured alone. A text that begins with a
// mark that joins the space before it (U+FE0F) or ends with a prepend
// character that joins the space after it (U+0600) makes what is written
// differ from what was measured by its own join, and the joins add up: a row
// or list with several such texts can run several cells past the screen,
// which then wraps it. Terminals disagree on these joins, so the renderer
// does not guess, and no text is changed to avoid them.
func width(s string) int { return (displaywidth.Options{}).String(s) }

// onScreen is the cell of row as a terminal shows it. A list that is not
// stacked, and the tags of an owner, give way by whole entries.
func (c Column[R]) onScreen(row R, now time.Time) shownCell {
	text := c.cell(row, now, false)
	cell := shownCell{lines: []string{text}}

	v, ok := field(reflect.ValueOf(row), c.Field)

	var entries []string

	switch {
	case ok && c.kind(v.Type()) == List:
		entries = c.entries(v)
	case ok && c.kind(v.Type()) == Owner:
		if _, user := field(v, "user"); !user {
			tags, _ := field(v, "tags")
			entries = items(tags)
		}
	}

	switch {
	case ok && c.kind(v.Type()) == List && c.List == Stacked:
		for i := range entries {
			entries[i] = Visible(entries[i], "")
		}

		cell.lines = entries
	case len(entries) > 0:
		for i := range entries {
			entries[i] = Visible(entries[i], "")
		}

		return shownCell{entries: entries, cut: true}
	case text == "-":
		cell.tone = dim
	case ok && c.Ahead:
		if t, _ := reflect.TypeAssert[time.Time](v); !t.IsZero() && t.Before(now) {
			cell.tone = red
		}
	}

	return cell
}
