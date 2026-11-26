package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

// ProblemError is a problem the server answered. Its text is the CLI's own
// sentence, written from the code, the object and the details; the detail
// text of the server is never shown, so an error reads the same whatever
// server version words it. Every text of the server in it passes through
// table.Visible, so it cannot end the line and forge the next.
type ProblemError struct {
	Problem clientv0.Problem
}

// sentence is the text of err. A problem of the server, a server that
// cannot be reached and one of another version have the CLI's own
// sentence, which is printed whatever a command wrapped around it.
func sentence(err error) string {
	if p, ok := errors.AsType[*ProblemError](err); ok {
		return p.Error()
	}

	if c, ok := errors.AsType[*connectError](err); ok {
		return c.Error()
	}

	// Before the version: a write whose answer the version check refused
	// may have been made, and its sentence says so.
	if w, ok := errors.AsType[*writeError](err); ok {
		return w.Error()
	}

	if v, ok := errors.AsType[*versionError](err); ok {
		return v.Error()
	}

	if s, ok := errors.AsType[*slowError](err); ok {
		return s.Error()
	}

	return err.Error()
}

func problemOf(status int, body json.RawMessage) error {
	var p clientv0.Problem

	err := clientv0.DecodeResponse(body, &p)
	if err != nil || p.Code == "" {
		//nolint:err113 // a status, not a condition to test
		return fmt.Errorf("the server answered %d %s", status, http.StatusText(status))
	}

	return &ProblemError{Problem: p}
}

func (e *ProblemError) Error() string {
	p := e.Problem

	switch p.Code { //nolint:exhaustive // the others print their title
	case clientv0.ProblemCodeUnauthorized:
		return "the server did not accept the API key."
	case clientv0.ProblemCodeForbidden:
		return "this credential may not do that." + forbidden(p.Details)
	case clientv0.ProblemCodeNotFound:
		o, err := p.Object.Get()
		if err == nil {
			return table.Entity(string(o.Kind), o.Id, o.Name) + " no longer exists."
		}
	case clientv0.ProblemCodeNameTaken:
		if s, ok := taken(p, "name"); ok {
			return s
		}
	case clientv0.ProblemCodeEmailTaken:
		if s, ok := taken(p, "email"); ok {
			return s
		}
	case preconditionFailed:
		o, err := p.Object.Get()
		if err == nil {
			return table.Entity(
				string(o.Kind),
				o.Id,
				o.Name,
			) + " changed while the command ran. Run it again."
		}
	case clientv0.ProblemCodeUserManagedByOidc:
		o, err := p.Object.Get()
		if err == nil {
			return table.Entity(
				string(o.Kind),
				o.Id,
				o.Name,
			) + " is managed by OIDC and cannot be edited here."
		}
	case clientv0.ProblemCodeUnhealthy:
		return "the server is not healthy:" + messages(p.Details["reasons"])
	case clientv0.ProblemCodeInvalidField:
		var b strings.Builder

		b.WriteString("the server refused a value:")

		for _, f := range p.Errors {
			b.WriteString(
				"\n  " + table.Visible(
					f.Location,
					"",
				) + ": " + table.Visible(
					f.Message,
					"",
				),
			)
		}

		return b.String()
	case clientv0.ProblemCodeTooLarge:
		return "the file is too large for the server."
	case clientv0.ProblemCodeInternal:
		return "the server had an internal error. Its log has the request " + table.Visible(
			p.RequestId,
			"",
		) + "."
	}

	// A code this build does not know.
	return table.Visible(p.Title, "") + " (" + table.Visible(string(p.Code), "") + ")."
}

// flagsOf names, in each entry of an invalid_field problem, the flag or the
// argument of In that filled the body field: body.email is --email, and
// body.profilePicUrl is the flag whose Go field is ProfilePicURL. A field
// matches by its Go name or by its flag or argument name without dashes,
// in any case. A location that no field of In fills stays as the server
// wrote it.
func flagsOf(err error, t reflect.Type) error {
	p, ok := errors.AsType[*ProblemError](err)
	if !ok || p.Problem.Code != clientv0.ProblemCodeInvalidField {
		return err
	}

	if t.Kind() != reflect.Struct {
		return err
	}

	for i, e := range p.Problem.Errors {
		key, ok := strings.CutPrefix(e.Location, "body.")
		if !ok {
			continue
		}

		for sf := range t.Fields() {
			var name, word string

			switch {
			case sf.Tag.Get("flag") != "":
				name = sf.Tag.Get("flag")
				word = "--" + name
			case sf.Tag.Get("arg") != "":
				name = sf.Tag.Get("arg")
				word = "<" + name + ">"
			default:
				continue
			}

			if strings.EqualFold(sf.Name, key) ||
				strings.EqualFold(strings.ReplaceAll(name, "-", ""), key) {
				p.Problem.Errors[i].Location = word

				break
			}
		}
	}

	return err
}

// preconditionFailed is a write whose If-Match no longer matches: the
// target changed after the CLI read it. v0 has no write that takes
// If-Match yet, so the code is not in the client.
const preconditionFailed clientv0.ProblemCode = "precondition_failed"

// forbidden names what the credential lacks, when the problem says it.
func forbidden(details map[string]any) string {
	var scopes []string

	if list, ok := details["scopes"].([]any); ok {
		for _, s := range list {
			scopes = append(scopes, table.Visible(fmt.Sprint(s), ""))
		}
	}

	rule, _ := details["rule"].(string)

	switch {
	case len(scopes) > 0:
		return "\nIt lacks the scope " + strings.Join(scopes, ", ") + "."
	case tokenRules[rule] != "":
		return "\n" + tokenRules[rule]
	case rule != "":
		return "\nA token rule refuses it: " + table.Visible(rule, "") + "."
	}

	return ""
}

// tokenRules are the sentences of the token rules the server names in
// forbidden's details.rule; a rule this build does not know prints its word.
//
//nolint:gosec // rule words and sentences, not credentials
var tokenRules = map[string]string{
	"token_cannot_change_user_name_or_email": "An OAuth access token cannot change the name or the email of a user; an API key can.",
}

// taken is the sentence of name_taken or email_taken, whose details hold
// the text under key: the object names the holder as messages do, which
// for a user can be its email, not the text that is taken.
func taken(p clientv0.Problem, key string) (string, bool) {
	o, err := p.Object.Get()
	if err != nil {
		return "", false
	}

	holder := table.Entity(string(o.Kind), o.Id, o.Name) + "."

	if text, _ := p.Details[key].(string); text != "" {
		return "the " + key + " " + strconv.Quote(text) + " belongs to " + holder, true
	}

	return "the " + key + " belongs to " + holder, true
}

// messages lists the message of each {code, message, details} entry, one
// line each.
func messages(v any) string {
	list, _ := v.([]any)

	var b strings.Builder

	for _, e := range list {
		m, _ := e.(map[string]any)
		text, _ := m["message"].(string)

		if text == "" {
			text, _ = m["code"].(string)
		}

		b.WriteString("\n  " + table.Visible(text, ""))
	}

	return b.String()
}
