package shape_test

import (
	"bytes"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/client/shape"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

// shapeOfType is what Check says of body as an answer of type t; "" for
// one of its shape.
func shapeOfType(t reflect.Type, body []byte) string {
	err := shape.Check(body, reflect.New(t).Interface())
	if err == nil {
		return ""
	}

	return err.Error()
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

// open says that the answer type leaves t open: an any, or a raw message.
func open(t reflect.Type) bool {
	return t.Kind() == reflect.Interface || t == reflect.TypeFor[json.RawMessage]()
}

// goodOf is an answer of type t with every member it requires at every
// depth, as a server sends it; a list or a map holds one item, a member
// that may be null is not.
func goodOf(t reflect.Type) any {
	if t.Kind() == reflect.Pointer ||
		t.Kind() == reflect.Map && t.Key().Kind() == reflect.Bool &&
			strings.HasPrefix(t.Name(), "Nullable[") {
		t = t.Elem()
	}

	switch {
	case t == reflect.TypeFor[time.Time]():
		return "2026-01-01T00:00:00Z"
	case t.Kind() == reflect.Struct:
		obj := map[string]any{}

		for f := range t.Fields() {
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name != "" && name != "-" && f.IsExported() &&
				!strings.Contains(opts, "omitempty") {
				obj[name] = goodOf(f.Type)
			}
		}

		return obj
	case t.Kind() == reflect.Slice:
		return []any{goodOf(t.Elem())}
	case t.Kind() == reflect.Map:
		return map[string]any{"k": goodOf(t.Elem())}
	case t.Kind() == reflect.String:
		return "x"
	case t.Kind() == reflect.Bool:
		return false
	case t.Kind() == reflect.Interface:
		return "x"
	}

	return 0
}

// generated client, a good answer passes the rule and decodes; each member
// the type requires, at any depth, is refused when it is missing and,
// unless its type lets it be null, when it is null, with its path in the
// sentence. Each item of a list and value of a map whose element type is
// declared (a subtest names it with that type) is refused when null,
// unless the type lets it be, and when of the wrong kind. Each place the
// type leaves open (an any, the values of a map of any) takes null, a
// nested null, a number no float64 holds and an object.
func TestAnswerShapes(t *testing.T) {
	t.Parallel()

	answers, opens, items := 0, 0, 0

	for m := range reflect.TypeFor[clientv0.ClientWithResponsesInterface]().Methods() {
		for f := range m.Type.Out(0).Elem().Fields() {
			if !strings.HasPrefix(f.Name, "JSON2") || f.Type.Kind() != reflect.Pointer {
				continue
			}

			typ := f.Type.Elem()
			good := goodOf(typ)
			answers++

			body, err := json.Marshal(good)
			require.NoError(t, err)
			require.Empty(t, shapeOfType(typ, body), "%s: a good answer", m.Name)
			require.NoError(
				t,
				clientv0.DecodeResponse(body, reflect.New(typ).Interface()),
				"%s: a good answer",
				m.Name,
			)

			for _, mb := range members(typ, nil) {
				p := pathOf(mb.path)

				if mb.open {
					// The document leaves it open: every value goes, null
					// at any depth and a number no float64 holds too.
					for _, v := range []any{nil, map[string]any{"a": map[string]any{"b": nil}}, "BIGNUM", map[string]any{"a": 1}} {
						body, err := json.Marshal(at(good, mb.path, v))
						require.NoError(t, err)

						body = bytes.ReplaceAll(
							body,
							[]byte(`"BIGNUM"`),
							[]byte(`1e400`),
						)
						require.Empty(
							t,
							shapeOfType(typ, body),
							"%s %s = %s",
							m.Name,
							p,
							body,
						)
						require.NoError(
							t,
							clientv0.DecodeResponse(body, reflect.New(typ).Interface()),
							"%s %s = %s",
							m.Name,
							p,
							body,
						)
					}

					opens++

					continue
				}

				if mb.item != nil {
					items++

					t.Run(m.Name+" "+p+" of "+mb.item.String(), func(t *testing.T) {
						null, err := json.Marshal(at(good, mb.path, nil))
						require.NoError(t, err)

						want := "its " + p + " is null"
						if mb.nullable {
							want = ""
						}

						require.Equal(t, want, shapeOfType(typ, null), "null")

						wrong, err := json.Marshal(
							at(good, mb.path, kindOtherThan(mb.item)),
						)
						require.NoError(t, err)

						if shapeOfType(typ, wrong) == "" {
							require.Error(
								t,
								clientv0.DecodeResponse(
									wrong,
									reflect.New(typ).Interface(),
								),
								"a value of the wrong kind: %s",
								wrong,
							)
						}
					})

					continue
				}

				missing, err := json.Marshal(at(good, mb.path, dropped{}))
				require.NoError(t, err)
				require.Equal(
					t,
					"it has no "+p,
					shapeOfType(typ, missing),
					"%s %s missing",
					m.Name,
					p,
				)

				null, err := json.Marshal(at(good, mb.path, nil))
				require.NoError(t, err)

				want := "its " + p + " is null"
				if mb.nullable {
					want = ""
				}

				require.Equal(t, want, shapeOfType(typ, null), "%s %s null", m.Name, p)
			}
		}
	}

	require.Positive(t, answers)
	require.Positive(t, opens, "no open place in the answers")
	require.Positive(t, items, "no list or map in the answers")
}

// kindOtherThan is a JSON value of a kind that t does not take.
func kindOtherThan(t reflect.Type) any {
	t, _ = unwrap(t)
	if t.Kind() == reflect.String || t == reflect.TypeFor[time.Time]() {
		return 5
	}

	return "x"
}

// member is a member of an answer type at any depth.
type member struct {
	path     []any // a name, or an index of a list or a key of a map
	nullable bool
	// open is a place the type leaves open: any value goes there.
	open bool
	// item is the element type of the list or map this is an item of.
	item reflect.Type
}

// pathOf is path as a sentence names it: a.b[0]["k"].
func pathOf(path []any) string {
	var b strings.Builder

	for _, p := range path {
		switch p := p.(type) {
		case int:
			b.WriteString("[" + strconv.Itoa(p) + "]")
		case mapKey:
			b.WriteString("[" + strconv.Quote(string(p)) + "]")
		default:
			if b.Len() > 0 {
				b.WriteString(".")
			}

			b.WriteString(p.(string)) //nolint:forcetypeassert // a name
		}
	}

	return b.String()
}

// members are the members t declares, at every depth, and the places it
// leaves open.
func members(t reflect.Type, path []any) []member {
	t, _ = unwrap(t)

	switch {
	case t == reflect.TypeFor[time.Time]():
		return nil
	case open(t):
		return []member{{path: path, open: true}}
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Map:
		p := append(slices.Clone(path), any(0))
		if t.Kind() == reflect.Map {
			p = append(slices.Clone(path), mapKey("k"))
		}

		e, nullable := unwrap(t.Elem())
		if open(e) {
			return []member{{path: p, open: true}}
		}

		// An item of a list or a value of a map is held to its element type.
		return append(
			[]member{{path: p, nullable: nullable, item: t.Elem()}},
			members(t.Elem(), p)...)
	case t.Kind() == reflect.Interface:
		return []member{{path: path, open: true}}
	case t.Kind() != reflect.Struct:
		return nil
	}

	var out []member

	for f := range t.Fields() {
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" || !f.IsExported() ||
			strings.Contains(opts, "omitempty") {
			continue
		}

		p := append(slices.Clone(path), name)
		_, nullable := unwrap(f.Type)

		if !open(f.Type) {
			out = append(out, member{path: p, nullable: nullable})
		}

		out = append(out, members(f.Type, p)...)
	}

	return out
}

// dropped is the value at which at removes a member.
type dropped struct{}

// at puts value at path in a copy of good, or removes the member there
// when value is dropped.
func at(v any, path []any, value any) any {
	switch c := v.(type) {
	case map[string]any:
		out := maps.Clone(c)
		key := path[0]

		if k, ok := key.(mapKey); ok {
			key = string(k)
		}

		name := key.(string) //nolint:forcetypeassert // a name or a key

		if len(path) == 1 {
			if _, drop := value.(dropped); drop {
				delete(out, name)
			} else {
				out[name] = value
			}

			return out
		}

		out[name] = at(c[name], path[1:], value)

		return out
	case []any:
		out := slices.Clone(c)
		if len(path) == 1 {
			out[0] = value

			return out
		}

		out[0] = at(c[0], path[1:], value)

		return out
	}

	return v
}

// mapKey is a key of a map in the path of a member.
type mapKey string

// shaped is an object of the API as the client has it: a member the
// document requires, and one it does not.
type shaped struct {
	ID   string  `json:"id"`
	Note *string `json:"note,omitempty"`
}

// TestCheck: an answer is taken only as a JSON object with every member
// its type requires; a member the type does not know is kept, a member
// that may be left out may be null.
func TestCheck(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, body, want string
	}{
		{name: "an object with every member", body: `{"id": "1"}`},
		{name: "a member this build does not know", body: `{"id": "1", "new": 1}`},
		{name: "a member this build does not know, beyond float64", body: `{"id": "1", "new": 1e309, "deep": [{"n": -1E+400}]}`},
		{name: "null", body: "null", want: "it is not an object"},
		{name: "not JSON", body: "<html>", want: "it is not JSON"},
		{name: "another object", body: `{"healthy": true}`, want: "it has no id"},
		{name: "a required member null", body: `{"id": null}`, want: "its id is null"},
		{name: "a member that may be left out, absent", body: `{"id": "1"}`},
		// Left out is absent; null is no string.
		{name: "a member that may be left out, null", body: `{"id": "1", "note": null}`, want: "its note is null"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(
				t,
				tt.want,
				shapeOfType(reflect.TypeFor[shaped](), []byte(tt.body)),
			)
		})
	}
}
