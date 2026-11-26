// Package table turns API objects into the tables and sheets of the CLI.
//
// A resource declares its columns once, as [Columns] of a type of the
// generated v0 client. A column names the JSON key of the API field it
// shows; the engine finds the field by its JSON tag and takes the kind of
// the column from the Go type of the field. No command has table code of
// its own.
package table

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Kind says how a column is shown, filtered and sorted.
type Kind string

const (
	ID      Kind = "id"
	Text    Kind = "text"
	Number  Kind = "number"
	Bool    Kind = "bool"
	Time    Kind = "time"
	Version Kind = "version"
	List    Kind = "list"
	Owner   Kind = "owner"
)

// Column is one column of a row type R.
type Column[R any] struct {
	// Name is what --columns, --filter and --sort take, in kebab-case.
	Name string
	// Field is the JSON key of the API field, with dots into nested objects:
	// "credential.expiry".
	Field string
	// Header is the label of the column in a table; the name in upper case
	// when empty. A sheet always labels a line by the name.
	Header string
	// Kind is needed only where the Go type of the field cannot say it.
	Kind    Kind
	Default bool
	Help    string
}

// Columns is the declaration of one row type.
type Columns[R any] []Column[R]

var (
	errUnknownField = errors.New("unknown field")
	errNoKind       = errors.New("no kind for")
	errNoName       = errors.New("a column with no name")
	errTwice        = errors.New("is declared twice")
	errWrongKind    = errors.New("cannot show")
)

// Check reports a column with no name or a name given twice, a field the
// type R does not have, a kind that cannot be derived, and a Kind that the
// type of the field contradicts. Building the command tree calls it for
// every declaration.
func (cs Columns[R]) Check() error {
	var errs []error

	seen := map[string]bool{}

	for _, c := range cs {
		switch {
		case c.Name == "":
			errs = append(errs, fmt.Errorf("field %q: %w", c.Field, errNoName))

			continue
		case seen[c.Name]:
			errs = append(errs, fmt.Errorf("column %q %w", c.Name, errTwice))
		}

		seen[c.Name] = true

		t, err := fieldType(reflect.TypeFor[R](), c.Field)
		if err != nil {
			errs = append(errs, fmt.Errorf("column %q: %w", c.Name, err))

			continue
		}

		derived := Column[R]{Field: c.Field}.kind(t)

		switch {
		case c.Kind != "" && text(c.Kind) != text(derived):
			errs = append(
				errs,
				fmt.Errorf("column %q: kind %s %w %v", c.Name, c.Kind, errWrongKind, t),
			)
		case derived == "" && c.Kind == "":
			errs = append(errs, fmt.Errorf("column %q: %w %v", c.Name, errNoKind, t))
		}
	}

	return errors.Join(errs...)
}

// text folds the kinds that are all a string in the API.
func text(k Kind) Kind {
	if k == ID || k == Version {
		return Text
	}

	return k
}

func (c Column[R]) kind(t reflect.Type) Kind {
	switch {
	case c.Kind != "":
		return c.Kind
	case c.Field == "id" || strings.HasSuffix(c.Field, ".id"):
		return ID
	case t == reflect.TypeFor[time.Time]():
		return Time
	case t.Kind() == reflect.Slice:
		return List
	case t.Kind() == reflect.Bool:
		return Bool
	case t.Kind() == reflect.String:
		return Text
	case t.Kind() >= reflect.Int && t.Kind() <= reflect.Float64:
		return Number
	case t.Kind() == reflect.Struct && hasJSON(t, "user") && hasJSON(t, "tags"):
		return Owner
	}

	return ""
}

// Render writes rows as a table of the default columns, for a pipe: no
// colour, no truncation, one line per row.
func Render[R any](w io.Writer, rows []R, cols Columns[R], now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.TabIndent)

	var shown Columns[R]

	for _, c := range cols {
		if c.Default {
			shown = append(shown, c)
		}
	}

	line := make([]string, len(shown))
	for i, c := range shown {
		line[i] = c.header()
	}

	fmt.Fprintln(tw, strings.Join(line, "\t"))

	for _, r := range rows {
		for i, c := range shown {
			line[i] = c.cell(r, now, false)
		}

		fmt.Fprintln(tw, strings.Join(line, "\t"))
	}

	return tw.Flush()
}

// Sheet writes one object, one "Label: value" line for every column, also
// for a null field.
func Sheet[R any](w io.Writer, row R, cols Columns[R], now time.Time) error {
	width := 0
	for _, c := range cols {
		width = max(width, len(c.label())+1)
	}

	for _, c := range cols {
		_, err := fmt.Fprintf(
			w,
			"%-*s%s\n",
			width+2,
			c.label()+":",
			c.cell(row, now, true),
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c Column[R]) header() string {
	if c.Header != "" {
		return strings.ToUpper(c.Header)
	}

	return strings.ToUpper(strings.ReplaceAll(c.Name, "-", " "))
}

// upper are the words that a sheet label keeps in upper case: "public-ip"
// is "Public IP".
var upper = map[string]bool{
	"id":  true,
	"ip":  true,
	"os":  true,
	"api": true,
	"dns": true,
	"url": true,
}

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

// cell is the text of the column for row. A null field is "never" for a
// time and "-" for any other kind.
func (c Column[R]) cell(row R, now time.Time, sheet bool) string {
	v, ok := field(reflect.ValueOf(row), c.Field)
	if !ok {
		t, _ := fieldType(reflect.TypeFor[R](), c.Field)
		if c.kind(t) == Time {
			return "never"
		}

		return "-"
	}

	//nolint:exhaustive // id, number and version print as they are
	switch c.kind(v.Type()) {
	case Text:
		if v.String() == "" {
			return "-"
		}

		return v.String()
	case Bool:
		if v.Bool() {
			return "yes"
		}

		return "no"
	case Time:
		t, _ := reflect.TypeAssert[time.Time](v)
		if sheet {
			return When(t, now)
		}

		return Ago(t, now)
	case List:
		var items []string
		for i := range v.Len() {
			items = append(items, fmt.Sprint(v.Index(i).Interface()))
		}

		if len(items) == 0 && sheet {
			return "-"
		}

		return strings.Join(items, ", ")
	case Owner:
		return ownerCell(v, sheet)
	default:
		return fmt.Sprint(v.Interface())
	}
}

// ownerCell shows a user by its login name in a table, and as an entity in a
// sheet; tags as the list in both. "tagged" is a word of messages.
func ownerCell(v reflect.Value, sheet bool) string {
	if u, ok := field(v, "user"); ok {
		id, _ := field(u, "id")
		login, _ := field(u, "loginName")

		if sheet {
			return Entity("user", id.String(), login.String())
		}

		return login.String()
	}

	tags, _ := field(v, "tags")

	var out []string
	for i := range tags.Len() {
		out = append(out, tags.Index(i).String())
	}

	if len(out) == 0 {
		return "-"
	}

	return strings.Join(out, ", ")
}

// Entity names an entity as every message does: the kind, the ID, and in
// brackets the name that tables show for it. kind is the kind of a problem
// object of v0.
func Entity(kind, id, name string) string {
	words := map[string]string{ //nolint:gosec // kinds of entity, not credentials
		"node":        "Node",
		"user":        "User",
		"authKey":     "Auth key",
		"apiKey":      "API key",
		"oauthClient": "OAuth client",
		"authRequest": "Auth request",
		"oauthToken":  "OAuth access token",
	}

	w, ok := words[kind]
	if !ok {
		w = kind
	}

	if name == "" || kind == "oauthClient" {
		return w + " " + id
	}

	return w + " " + id + " (" + name + ")"
}

// Ago is a time relative to now, as a table shows it: "now", "3d ago",
// "in 89d", and "never" for the zero time. It is rounded, not cut, so a key
// made for 60 days reads "in 60d" right after.
func Ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}

	d := t.Sub(now)

	future := d > 0
	if !future {
		d = -d
	}

	round := func(unit time.Duration) int { return int((d + unit/2) / unit) }

	var n string

	switch {
	case d < time.Minute:
		return "now"
	case round(time.Minute) < 60:
		n = strconv.Itoa(round(time.Minute)) + "m"
	case round(time.Hour) < 24:
		n = strconv.Itoa(round(time.Hour)) + "h"
	default:
		n = strconv.Itoa(round(24*time.Hour)) + "d"
	}

	if future {
		return "in " + n
	}

	return n + " ago"
}

// When is a time as a sheet shows it: relative, and the moment in UTC.
func When(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}

	return Ago(t, now) + " (" + t.UTC().Format("2006-01-02 15:04 UTC") + ")"
}

// field reads the value at the dotted JSON path of v. ok is false for a
// null on the way: a nil pointer, or a nullable that holds no value.
func field(v reflect.Value, path string) (reflect.Value, bool) {
	for name := range strings.SplitSeq(path, ".") {
		var ok bool
		if v, ok = present(v); !ok || v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}

		i := jsonIndex(v.Type(), name)
		if i < 0 {
			return reflect.Value{}, false
		}

		v = v.Field(i)
	}

	return present(v)
}

// present follows pointers and the nullable values of the generated client
// (a map[bool]T that holds its value under true).
func present(v reflect.Value) (reflect.Value, bool) {
	for {
		switch {
		case !v.IsValid():
			return v, false
		case v.Kind() == reflect.Pointer:
			if v.IsNil() {
				return v, false
			}

			v = v.Elem()
		case isNullable(v.Type()):
			v = v.MapIndex(reflect.ValueOf(true))
		default:
			return v, true
		}
	}
}

func isNullable(t reflect.Type) bool {
	return t.Kind() == reflect.Map && t.Key().Kind() == reflect.Bool
}

// fieldType is the type at the dotted JSON path of t, through pointers and
// nullables.
func fieldType(t reflect.Type, path string) (reflect.Type, error) {
	if path == "" {
		return nil, errUnknownField
	}

	for name := range strings.SplitSeq(path, ".") {
		t = elem(t)
		if t.Kind() != reflect.Struct {
			return nil, fmt.Errorf("%w %q: %v is no object", errUnknownField, path, t)
		}

		i := jsonIndex(t, name)
		if i < 0 {
			return nil, fmt.Errorf("%w %q in %s", errUnknownField, path, t)
		}

		t = t.Field(i).Type
	}

	return elem(t), nil
}

func elem(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Pointer || isNullable(t) {
		t = t.Elem()
	}

	return t
}

func jsonIndex(t reflect.Type, name string) int {
	for i := range t.NumField() {
		tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if tag == name {
			return i
		}
	}

	return -1
}

func hasJSON(t reflect.Type, name string) bool { return jsonIndex(t, name) >= 0 }
