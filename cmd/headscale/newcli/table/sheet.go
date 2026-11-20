package table

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// Sheet writes one object, one "Label: value" line for every column, also
// for a null field.
func Sheet[R any](w io.Writer, row R, cols Columns[R], now time.Time) error {
	width := 0
	for _, c := range cols {
		width = max(width, len(c.label())+1)
	}

	for _, c := range cols {
		_, err := fmt.Fprintf(w, "%-*s%s\n", width+2, c.label()+":", c.cell(row, now, true))
		if err != nil {
			return err
		}
	}

	return nil
}

// upper are the words that a sheet label keeps in upper case: "public-ip"
// is "Public IP".
var upper = map[string]bool{"id": true, "ip": true, "os": true, "api": true, "dns": true, "url": true}

// label is the name of the column as a sheet labels its line.
func (c Column[R]) label() string {
	words := strings.Split(c.Name, "-")
	for i, w := range words {
		if upper[w] {
			words[i] = strings.ToUpper(w)
		}
	}

	s := strings.Join(words, " ")

	return strings.ToUpper(s[:1]) + s[1:]
}
