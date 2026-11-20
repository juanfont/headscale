package table

import (
	"io"
	"strings"
	"time"
	"unicode"
)

// Render writes rows as a table of shown, for a pipe: no colour, no
// truncation, one line per row. [Columns.Pick] chooses the columns.
func Render[R any](w io.Writer, rows []R, shown Columns[R], now time.Time) error {
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

// width is the cells s takes on a terminal: two for the wide characters of
// East Asian scripts and for emoji, none for a mark that joins the one
// before it. The ranges are those of wcwidth that a table of names meets.
func width(s string) int {
	n := 0

	for _, r := range s {
		switch {
		case unicode.In(r, unicode.Mn, unicode.Me) || r == 0x200d || r >= 0xfe00 && r <= 0xfe0f:
		case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf && r != 0x303f, r >= 0xac00 && r <= 0xd7a3,
			r >= 0xf900 && r <= 0xfaff, r >= 0xfe30 && r <= 0xfe4f, r >= 0xff00 && r <= 0xff60, r >= 0xffe0 && r <= 0xffe6,
			r >= 0x1f300 && r <= 0x1f6ff, r >= 0x1f900 && r <= 0x1faff, r >= 0x20000 && r <= 0x3fffd:
			n += 2
		default:
			n++
		}
	}

	return n
}
