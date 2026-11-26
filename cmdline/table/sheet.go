package table

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Sheet writes one object, one "Label: value" line for every column, also
// for a null field, then each block that holds keys.
func Sheet[R any](
	w io.Writer,
	row R,
	cols Columns[R],
	blocks Blocks[R],
	now time.Time,
) error {
	width := 0
	for _, c := range cols {
		width = max(width, len(c.label())+1)
	}

	var b strings.Builder

	for _, c := range cols {
		fmt.Fprintf(&b, "%-*s%s\n", width+2, c.label()+":", c.cell(row, now, true))
	}

	for _, bl := range blocks {
		b.WriteString(bl.text(row))
	}

	_, err := io.WriteString(w, b.String())

	return err
}

// Block is a map of text that a sheet shows after its lines, under a
// title, one key a line in the order of the keys: the attributes of a
// node, whatever keys the server fills.
type Block[R any] struct {
	Title string
	// Field is the JSON path of the map.
	Field string
}

// Blocks are the blocks of a sheet, in order.
type Blocks[R any] []Block[R]

var (
	errNoTitle    = errors.New("a block with no title")
	errTitleTwice = errors.New("is the title of two blocks")
	errFieldTwice = errors.New("is the field of two blocks")
)

// Check reports a block whose field is no map of text, a block with no
// title, and a title or a field that two blocks share.
func (bs Blocks[R]) Check() error {
	var errs []error

	titles, fields := map[string]bool{}, map[string]bool{}

	for _, bl := range bs {
		t, err := fieldType(reflect.TypeFor[R](), bl.Field)

		switch {
		case bl.Title == "":
			errs = append(errs, fmt.Errorf("field %q: %w", bl.Field, errNoTitle))
		case titles[bl.Title]:
			errs = append(errs, fmt.Errorf("block %q %w", bl.Title, errTitleTwice))
		case fields[bl.Field]:
			errs = append(
				errs,
				fmt.Errorf("block %q: field %q %w", bl.Title, bl.Field, errFieldTwice),
			)
		case err != nil:
			errs = append(errs, fmt.Errorf("block %q: %w", bl.Title, err))
		case t.Kind() != reflect.Map || t.Key().Kind() != reflect.String || t.Elem().Kind() != reflect.String:
			errs = append(
				errs,
				fmt.Errorf(
					"block %q: field %q: %v %w",
					bl.Title,
					bl.Field,
					t,
					errNoMap,
				),
			)
		}

		titles[bl.Title], fields[bl.Field] = true, true
	}

	return errors.Join(errs...)
}

// text is the block of row: a blank line, the title, and each key and its
// value; nothing for a map with no keys.
func (bl Block[R]) text(row R) string {
	v, ok := field(reflect.ValueOf(row), bl.Field)
	if !ok || v.Len() == 0 {
		return ""
	}

	keys := make([]string, 0, v.Len())
	for _, k := range v.MapKeys() {
		keys = append(keys, k.String())
	}

	slices.Sort(keys)

	n := 0
	for _, k := range keys {
		n = max(n, width(Visible(k, "")))
	}

	var b strings.Builder

	b.WriteString("\n" + bl.Title + ":\n")

	for _, k := range keys {
		key := Visible(k, "")
		b.WriteString(
			"  " + key + strings.Repeat(
				" ",
				n-width(key)+3,
			) + Visible(
				v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key())).String(),
				"",
			) + "\n",
		)
	}

	return b.String()
}

// label is the name of the column as a sheet labels its line, with a few
// words in upper case: "public-ip" is "Public IP".
func (c Column[R]) label() string {
	words := strings.Split(c.Name, "-")
	for i, w := range words {
		switch w {
		case "id", "ip", "os", "api", "dns", "url":
			words[i] = strings.ToUpper(w)
		}
	}

	s := strings.Join(words, " ")

	return strings.ToUpper(s[:1]) + s[1:]
}
