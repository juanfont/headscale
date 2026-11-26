// Package shape holds an answer of an API to the type the API's document
// gives it: every member the type requires is there and, unless its type
// lets it be null, not null, at every depth. The generated v0 client checks
// each success with it before it decodes one, so no caller reads a missing
// member as its zero value. Members the type does not know pass: the API is
// open for answers.
package shape

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Error is an answer that is not of its type's shape. Why says what is
// wrong, with the member's path: "it has no id", "its tags[1] is null".
type Error struct{ Why string }

func (e *Error) Error() string { return e.Why }

// Check reads body as an answer to be decoded into out, a pointer: see
// the package. The typed decode checks the kinds of the values; Check
// checks only that a list is a list.
func Check(body []byte, out any) error { return CheckWithout(body, out, "") }

// CheckWithout is Check of an answer whose top-level member skip, which
// may be left out, is not looked at, whatever its value: a page read for
// its rows when its token is at fault.
func CheckWithout(body []byte, out any, skip string) error {
	t := reflect.TypeOf(out)
	if t == nil || t.Kind() != reflect.Pointer {
		return nil
	}

	why := check(t.Elem(), body, skip)
	if why == "" {
		return nil
	}

	return &Error{Why: why}
}

func check(t reflect.Type, body []byte, skip string) string {
	if !json.Valid(body) {
		return "it is not JSON"
	}

	// A number stays text: one beyond float64 in a member this build does
	// not know is still JSON.
	var v any

	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	_ = d.Decode(&v)

	s := learn(t, map[reflect.Type]*shape{})

	obj, ok := v.(map[string]any)
	if !ok && s.fields != nil {
		return "it is not an object"
	}

	// The parsed copy, not the bytes: what is said of the rest stays said
	// of the bytes as they came.
	if skip != "" {
		delete(obj, skip)
	}

	return s.check(v, "")
}

// shape is what the answer type of a member asks of its value: an object
// with fields, a list or a map of elem, or a leaf (nil fields and elem)
// whose kind the typed decode checks.
type shape struct {
	fields []field
	elem   *shape
	list   bool
	// nullable says that an item of a list or a value of a map may be null.
	nullable bool
}

type field struct {
	name             string
	optional, isNull bool
	shape            *shape
}

// learn is the shape of t, each type in it learnt once, so one answer, such
// as a page of a thousand rows, is walked with one plan; learnt ends a type
// that holds itself.
func learn(t reflect.Type, learnt map[reflect.Type]*shape) *shape {
	if s, ok := learnt[t]; ok {
		return s
	}

	s := &shape{}
	learnt[t] = s

	t, _ = unwrap(t)

	switch {
	case open(t):
		// A place the type leaves open takes every value as it comes.
	case reflect.PointerTo(t).Implements(reflect.TypeFor[json.Unmarshaler]()):
		// A type that reads its own JSON, such as a time, is a leaf.
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Map:
		e, nullable := unwrap(t.Elem())
		s.elem = learn(e, learnt)
		s.list = t.Kind() == reflect.Slice
		s.nullable = nullable || open(e)
	case t.Kind() == reflect.Struct:
		s.fields = []field{}

		for f := range t.Fields() {
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" || !f.IsExported() {
				continue
			}

			// A member of an open type: null is one of its values. A
			// pointer of a member that may be left out says only that: the
			// member is absent, or of its type, as nextPageToken.
			optional := strings.Contains(opts, "omitempty")

			_, nullable := unwrap(f.Type)
			nullable = nullable && (!optional || f.Type.Kind() != reflect.Pointer) ||
				open(f.Type)
			s.fields = append(
				s.fields,
				field{
					name:     name,
					optional: optional,
					isNull:   nullable,
					shape:    learn(f.Type, learnt),
				},
			)
		}
	}

	return s
}

// open says that the answer type leaves t open: an any, or a raw message.
// Required and not null is said of what a type declares, so nothing below
// t is checked, and null is one of its values.
func open(t reflect.Type) bool {
	return t.Kind() == reflect.Interface || t == reflect.TypeFor[json.RawMessage]()
}

// unwrap is t without Nullable or a pointer, and whether either let a
// value be null.
func unwrap(t reflect.Type) (reflect.Type, bool) {
	switch {
	case t.Kind() == reflect.Pointer:
		return t.Elem(), true
	case t.Kind() == reflect.Map && t.Key().Kind() == reflect.Bool &&
		strings.HasPrefix(t.Name(), "Nullable["):
		return t.Elem(), true
	}

	return t, false
}

func (s *shape) check(v any, path string) string {
	at := func(p string) string {
		if path == "" {
			return p
		}

		return path + "." + p
	}

	switch {
	case s.fields != nil:
		obj, ok := v.(map[string]any)
		if !ok {
			return "its " + path + " is not an object"
		}

		for _, f := range s.fields {
			mv, ok := obj[f.name]

			switch {
			case !ok && !f.optional:
				return "it has no " + at(f.name)
			case !ok, mv == nil && f.isNull:
			case mv == nil:
				return "its " + at(f.name) + " is null"
			default:
				if why := f.shape.check(mv, at(f.name)); why != "" {
					return why
				}
			}
		}
	case s.elem != nil:
		return s.items(v, path)
	}

	return ""
}

// items checks each item of a list, or value of a map, against elem.
func (s *shape) items(v any, path string) string {
	item := func(p string, iv any) string {
		switch {
		case iv == nil && s.nullable:
		case iv == nil:
			return "its " + p + " is null"
		default:
			return s.elem.check(iv, p)
		}

		return ""
	}

	// Another kind of a map is for the typed decode to say.
	switch c := v.(type) {
	case []any:
		for i, iv := range c {
			if why := item(path+"["+strconv.Itoa(i)+"]", iv); why != "" {
				return why
			}
		}
	case map[string]any:
		if s.list {
			return "its " + path + " is not a list"
		}

		for _, k := range slices.Sorted(maps.Keys(c)) {
			if why := item(path+"["+strconv.Quote(k)+"]", c[k]); why != "" {
				return why
			}
		}
	default:
		if s.list {
			return "its " + path + " is not a list"
		}
	}

	return ""
}
