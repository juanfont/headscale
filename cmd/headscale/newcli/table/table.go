// Package table turns API objects into the tables and sheets of the CLI.
//
// A resource declares its columns once, as [Columns] of a type of the
// generated v0 client. A column names the JSON key of the API field it
// shows; the engine finds the field by its JSON tag and takes the kind of
// the column from the Go type of the field. No command has table code of
// its own.
package table

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
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
	Kind Kind
	// Ahead is a time that looks forward from now, such as an expiry: a
	// duration in a filter is then the time left, not the age.
	Ahead   bool
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
	errAhead        = errors.New("is no time, so it cannot look ahead")
	errSayKind      = errors.New("is named like an ID or a version: say its Kind, which may be text")
)

// Check reports a column with no name or a name given twice, a field the
// type R does not have, a kind that cannot be derived, a Kind that the
// type of the field contradicts, and Ahead on a column that is no time. A
// text field whose key ends in Id or Version needs its Kind said: the type
// cannot tell an ID or a version from text, and the wrong guess sorts 1.100
// before 1.80. Building the command tree calls it for every declaration.
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
			errs = append(errs, fmt.Errorf("column %q: kind %s %w %v", c.Name, c.Kind, errWrongKind, t))
		case derived == "" && c.Kind == "":
			errs = append(errs, fmt.Errorf("column %q: %w %v", c.Name, errNoKind, t))
		case c.Kind == "" && derived == Text && namedLikeKind(c.Field):
			errs = append(errs, fmt.Errorf("column %q: field %q %w", c.Name, c.Field, errSayKind))
		}

		if c.Ahead && c.kind(t) != Time {
			errs = append(errs, fmt.Errorf("column %q %w", c.Name, errAhead))
		}
	}

	return errors.Join(errs...)
}

// namedLikeKind is a key that reads as an ID or a version: authKeyId,
// clientVersion.
func namedLikeKind(field string) bool {
	key := field[strings.LastIndex(field, ".")+1:]

	return strings.HasSuffix(key, "Id") || strings.HasSuffix(key, "ID") || strings.EqualFold(key, "version") || strings.HasSuffix(key, "Version")
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

func (c Column[R]) header() string {
	if c.Header != "" {
		return strings.ToUpper(c.Header)
	}

	return strings.ToUpper(strings.ReplaceAll(c.Name, "-", " "))
}

// cell is the text of the column for row. A null field is "never" for a
// time and "-" for any other kind.
func (c Column[R]) cell(row R, now time.Time, sheet bool) string {
	return Visible(c.text(row, now, sheet), "")
}

func (c Column[R]) text(row R, now time.Time, sheet bool) string {
	v, ok := field(reflect.ValueOf(row), c.Field)
	if !ok {
		t, _ := fieldType(reflect.TypeFor[R](), c.Field)
		if c.kind(t) == Time {
			return "never"
		}

		return "-"
	}

	switch c.kind(v.Type()) { //nolint:exhaustive // id, number and version print as they are
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
		entries := items(v)
		if len(entries) == 0 && sheet {
			return "-"
		}

		return strings.Join(entries, ", ")
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

// Visible is s with every control character and every bidirectional
// control made visible as an escape, and a backslash doubled so that the
// text \x1b cannot pass for an escape, except the runes in keep. Text from
// the server, which a caller with a narrow token may have set, cannot then
// move the cursor, recolour or reorder an admin's terminal, nor end a line
// and forge the next: every place where such text enters a sentence or a
// cell passes it through Visible with nothing kept.
func Visible(s, keep string) string {
	escaped := func(r rune) bool { return (hidden(r) || r == '\\') && !strings.ContainsRune(keep, r) }
	if !strings.ContainsFunc(s, escaped) {
		return s
	}

	var b strings.Builder

	for _, r := range s {
		switch {
		case !escaped(r):
			b.WriteRune(r)
		case r == '\\':
			b.WriteString(`\\`)
		case r <= 0xff:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}

	return b.String()
}

// VisibleJSON is raw JSON with every control that JSON does not escape
// itself, DEL, C1 and the bidirectional controls, written as \uXXXX. Such a
// rune stands only inside a string, so the JSON stays valid and every
// value the same, but no terminal acts on it.
func VisibleJSON(raw []byte) []byte {
	if !bytes.ContainsFunc(raw, hidden) {
		return raw
	}

	var b bytes.Buffer

	for len(raw) > 0 {
		r, n := utf8.DecodeRune(raw)
		if hidden(r) && r >= 0x7f {
			fmt.Fprintf(&b, "\\u%04x", r)
		} else {
			b.Write(raw[:n])
		}

		raw = raw[n:]
	}

	return b.Bytes()
}

// hidden is a rune that a terminal acts on rather than shows: the C0 and
// C1 controls, DEL, and the marks, embeddings, overrides and isolates of
// bidirectional text.
func hidden(r rune) bool {
	switch {
	case unicode.IsControl(r), r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return true
	}

	return false
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

	id, name = Visible(id, ""), Visible(name, "")

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
