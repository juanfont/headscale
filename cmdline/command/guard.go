package command

import (
	"reflect"
	"strconv"
	"strings"
)

// revision is the target of a command and its revision, which a write on
// the target sends back in If-Match: a server that holds another revision
// refuses the write with precondition_failed, so a change made in between
// is not lost.
type revision struct{ id, rev string }

// IfMatch is the If-Match of a write on the entity id: the revision the
// builder read for the target, when id is the target; nil, which sends
// none, for another. Every call whose operation takes If-Match passes it
// (TestEveryGuardIsSent).
func (c *run) IfMatch(id string) *string {
	g := c.guard.Load()
	if g == nil || g.id != id {
		return nil
	}

	return new(strconv.Quote(g.rev))
}

// guardOf is the revision of the target of in: its first argument that is
// an entity, when that entity has an id and a revision. The builder sets
// it before Run, for the command to pass on.
func guardOf[In any](in In) *revision {
	e, ok := target(reflect.ValueOf(in))
	if !ok {
		return nil
	}

	rev := jsonText(e, "revision")
	if rev == "" {
		return nil
	}

	return &revision{id: jsonText(e, "id"), rev: rev}
}

// target is the field of the target in the input struct v, when it holds
// one: see targetType.
func target(v reflect.Value) (reflect.Value, bool) {
	_, i := targetType(v.Type())
	if i < 0 || jsonText(v.Field(i), "id") == "" {
		return reflect.Value{}, false
	}

	return v.Field(i), true
}

// targetType is the type of the target of the input struct t, and its
// field: the first argument that is an entity, a struct with a text id.
func targetType(t reflect.Type) (reflect.Type, int) {
	if t.Kind() != reflect.Struct {
		return nil, -1
	}

	for f := range t.Fields() {
		if f.Tag.Get("arg") != "" && f.Type.Kind() == reflect.Struct &&
			hasJSON(f.Type, "id") {
			return f.Type, f.Index[0]
		}
	}

	return nil, -1
}

// hasJSON reports whether struct t has a text field under the JSON key
// name.
func hasJSON(t reflect.Type, name string) bool {
	for f := range t.Fields() {
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == name && f.Type.Kind() == reflect.String {
			return true
		}
	}

	return false
}

// jsonText is the string field of struct v under the JSON key name; "" for
// none.
func jsonText(v reflect.Value, name string) string {
	for i := range v.NumField() {
		tag, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("json"), ",")
		if tag == name && v.Field(i).Kind() == reflect.String {
			return v.Field(i).String()
		}
	}

	return ""
}
