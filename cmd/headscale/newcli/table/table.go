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
	"maps"
	"reflect"
	"slices"
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
	Ahead bool
	// List is how a terminal shows a list; a pipe and a sheet always show
	// it inline.
	List Layout
	// Fold shows the entries of a list that are all one value of the map as
	// its key, in a cell and in a filter: [Exit].
	Fold map[string][]string
	// Invalid, on a time column, is a row whose null time is not "never"
	// but a stored time the API cannot send: the cell says "invalid", and
	// no filter on the time finds the row.
	Invalid func(row R) bool
	Default bool
	Help    string
}

// Layout is how a terminal shows a list in a cell.
type Layout int

const (
	// Inline joins the entries with commas on one line.
	Inline Layout = iota
	// Stacked shows one entry per line.
	Stacked
	// Cut shows as many entries as fit, then "… (+K)".
	Cut
)

// Exit is the fold of a route column: the word exit for the two prefixes
// of an exit node. A function, so no caller can change it for another.
func Exit() map[string][]string { return map[string][]string{"exit": {"0.0.0.0/0", "::/0"}} }

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
	errNoList       = errors.New("is no list, so it has no List layout and no Fold")
	errInvalid      = errors.New("is no time, so it has no Invalid")
	errNoMap        = errors.New("is no map with text keys")
	errPath         = errors.New("is no path: write keys with dots, and a map key as name[\"key\"]")
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

		if (c.List != Inline || c.Fold != nil) && c.kind(t) != List {
			errs = append(errs, fmt.Errorf("column %q %w", c.Name, errNoList))
		}

		if c.Invalid != nil && c.kind(t) != Time {
			errs = append(errs, fmt.Errorf("column %q %w", c.Name, errInvalid))
		}
	}

	return errors.Join(errs...)
}

// namedLikeKind is a key that reads as an ID or a version: authKeyId,
// clientVersion.
func namedLikeKind(field string) bool {
	ss, _ := steps(field)
	if len(ss) == 0 || ss[len(ss)-1].keyed {
		return false
	}

	key := ss[len(ss)-1].name

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

// Heading is the header of the column in a table.
func (c Column[R]) Heading() string { return c.header() }

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

		switch {
		case c.kind(t) == Time && c.invalid(row):
			return "invalid"
		case c.kind(t) == Time:
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
		entries := c.entries(v)
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

// invalid is a row whose null time the column says is invalid.
func (c Column[R]) invalid(row R) bool { return c.Invalid != nil && c.Invalid(row) }

// entries are the entries of a list as a cell shows them: the entries of a
// Fold word as that word, after the others.
func (c Column[R]) entries(v reflect.Value) []string { return Folded(items(v), c.Fold) }

// Folded is entries with the entries of a word of fold shown as that word,
// after the other entries, when all of them are there: a message says
// "10.0.0.0/8, exit" as a table does, whatever order the server sorts.
func Folded(entries []string, fold map[string][]string) []string {
	out := slices.Clone(entries)

	for _, word := range slices.Sorted(maps.Keys(fold)) {
		all := fold[word]
		if !slices.ContainsFunc(all, func(e string) bool { return !slices.Contains(out, e) }) {
			out = append(slices.DeleteFunc(out, func(e string) bool { return slices.Contains(all, e) }), word)
		}
	}

	return out
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

// field reads the value at the JSON path of v. ok is false for a null on
// the way: a nil pointer, a nullable that holds no value, or a map that has
// no such key.
func field(v reflect.Value, path string) (reflect.Value, bool) {
	ss, err := steps(path)
	if err != nil {
		return reflect.Value{}, false
	}

	for _, st := range ss {
		var ok bool
		if v, ok = present(v); !ok || v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}

		i := jsonIndex(v.Type(), st.name)
		if i < 0 {
			return reflect.Value{}, false
		}

		v = v.Field(i)

		if st.keyed {
			if v, ok = present(v); !ok || v.Kind() != reflect.Map {
				return reflect.Value{}, false
			}

			v = v.MapIndex(reflect.ValueOf(st.key).Convert(v.Type().Key()))
		}
	}

	return present(v)
}

// step is one key of a path: the JSON key of a field, and the key into
// the map it holds when keyed.
type step struct {
	name, key string
	keyed     bool
}

// steps reads a path: JSON keys joined by dots, each of which may index a
// map with a quoted key, as attributes["ip:publicAddress"].
func steps(path string) ([]step, error) {
	var out []step

	for rest := path; ; {
		end := strings.IndexAny(rest, ".[")
		if end < 0 {
			end = len(rest)
		}

		st := step{name: rest[:end]}
		rest = rest[end:]

		if strings.HasPrefix(rest, "[") {
			q, err := strconv.QuotedPrefix(rest[1:])
			if err != nil || !strings.HasPrefix(rest[1+len(q):], "]") {
				return nil, errPath
			}

			st.key, _ = strconv.Unquote(q)
			st.keyed = true
			rest = rest[len(q)+2:]
		}

		if st.name == "" {
			return nil, errPath
		}

		out = append(out, st)

		if rest == "" {
			return out, nil
		}

		if rest[0] != '.' {
			return nil, errPath
		}

		rest = rest[1:]
	}
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

// fieldType is the type at the JSON path of t, through pointers,
// nullables and map keys.
func fieldType(t reflect.Type, path string) (reflect.Type, error) {
	if path == "" {
		return nil, errUnknownField
	}

	ss, err := steps(path)
	if err != nil {
		return nil, fmt.Errorf("%q %w", path, err)
	}

	for _, st := range ss {
		t = elem(t)
		if t.Kind() != reflect.Struct {
			return nil, fmt.Errorf("%w %q: %v is no object", errUnknownField, path, t)
		}

		i := jsonIndex(t, st.name)
		if i < 0 {
			return nil, fmt.Errorf("%w %q in %s", errUnknownField, path, t)
		}

		t = t.Field(i).Type

		if st.keyed {
			t = elem(t)
			if t.Kind() != reflect.Map || t.Key().Kind() != reflect.String {
				return nil, fmt.Errorf("field %q: %v %w", path, t, errNoMap)
			}

			t = t.Elem()
		}
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
