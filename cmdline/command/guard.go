package command

import (
	"reflect"
	"strconv"
	"strings"
)

// revision is the guard of a write on the target of a command: what the
// CLI read or showed of it, which the server compares before it writes,
// so a change made in between is not lost. One kind per run: the target's
// revision, sent in If-Match and refused with precondition_failed, or the
// token a question handed over (Prompt.Guard), sent as expect and refused
// with the spec's Changed. The builder refuses a spec that would need both.
type revision struct {
	id, rev string
	token   bool
}

// IfMatch is the If-Match of a write on the entity id: the revision the
// builder read for the target, when id is the target; nil, which sends
// none, for another. Every call whose operation takes If-Match passes it
// (TestEveryGuardIsSent).
func (c *run) IfMatch(id string) *string {
	g := c.guard.Load()
	if g == nil || g.token || g.id != id {
		return nil
	}

	return new(strconv.Quote(g.rev))
}

// Expect is the token of a dry run that a write on the entity id sends
// back, so the server refuses it when what the question showed changed:
// the Guard of the Prompt, which the builder keeps as it keeps a revision;
// nil for another entity, and for the dry run itself, which the builder
// asks before any Guard is set. Every call whose operation takes expect
// passes it (TestEveryGuardIsSent).
func (c *run) Expect(id string) *string {
	g := c.guard.Load()
	if g == nil || !g.token || g.id != id {
		return nil
	}

	return &g.rev
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

// unrevised reports whether the target of in is an entity that has a
// revision, as a node does, and the server sent it none.
func unrevised[In any](in In) bool {
	e, ok := target(reflect.ValueOf(in))

	return ok && hasJSON(e.Type(), "revision") && jsonText(e, "revision") == ""
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
