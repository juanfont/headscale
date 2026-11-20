package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

// ProblemError is a problem the server answered. Its text is the CLI's own
// sentence, written from the code, the object and the details; the detail
// text of the server is never shown, so an error reads the same whatever
// server version words it. Every text of the server in it passes through
// table.Visible, so it cannot end the line and forge the next.
type ProblemError struct {
	Problem clientv0.Problem

	// What the builder knows of the command that the problem answers, for
	// the sentences that the problem alone cannot write: the target as the
	// command read it, and the expiry it sent, zero when none.
	target clientv0.ProblemObject
	expiry time.Time
}

func problemOf(status int, body []byte) error {
	var p clientv0.Problem

	err := json.Unmarshal(body, &p)
	if err != nil || p.Code == "" {
		return fmt.Errorf("the server answered %d %s", status, http.StatusText(status)) //nolint:err113 // a status, not a condition to test
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
			return e.entity(o) + " no longer exists."
		}
	case clientv0.ProblemCodeNameTaken:
		if s, ok := taken(p, "name"); ok {
			return s
		}
	case clientv0.ProblemCodeEmailTaken:
		if s, ok := taken(p, "email"); ok {
			return s
		}
	case clientv0.ProblemCodePreconditionFailed:
		o, err := p.Object.Get()
		if err == nil {
			return table.Entity(string(o.Kind), o.Id, o.Name) + " changed while the command ran. Run it again."
		}
	case clientv0.ProblemCodeUserManagedByOidc:
		o, err := p.Object.Get()
		if err == nil {
			return table.Entity(string(o.Kind), o.Id, o.Name) + " is managed by OIDC and cannot be edited here."
		}
	case clientv0.ProblemCodeTagsRequired:
		return "the tag list is empty. A tagged node needs at least one tag."
	case clientv0.ProblemCodeTagsNotPermitted:
		return "these tags are not in the policy: " + strings.Join(texts(p.Details["tags"]), ", ")
	case clientv0.ProblemCodeExpiryInPast:
		if e.expiry.IsZero() {
			return "the expiry is in the past."
		}

		s := e.expiry.UTC().Format("2006-01-02 15:04 UTC") + " is in the past."
		if e.target.Kind == "node" {
			s += "\nTo expire the node now: headscale nodes expire " + table.Visible(e.target.Id, "")
		}

		return s
	case clientv0.ProblemCodeUpdateRefused:
		o, err := p.Object.Get()
		if err == nil {
			return refused(table.Entity(string(o.Kind), o.Id, o.Name), p.Details)
		}
	case clientv0.ProblemCodeUnhealthy:
		return "the server is not healthy:" + messages(p.Details["reasons"])
	case clientv0.ProblemCodeInvalidField:
		var b strings.Builder

		b.WriteString("the server refused a value:")

		for _, f := range p.Errors {
			b.WriteString("\n  " + table.Visible(f.Location, "") + ": " + table.Visible(f.Message, ""))
		}

		return b.String()
	case clientv0.ProblemCodeTooLarge:
		return "the file is too large for the server."
	case clientv0.ProblemCodeInternal:
		return "the server had an internal error. Its log has the request " + table.Visible(p.RequestId, "") + "."
	}

	// A code this build does not know.
	return table.Visible(p.Title, "") + " (" + table.Visible(string(p.Code), "") + ")."
}

// entity names o as messages do. The server names no object that is gone,
// so an object with no name that is the command's target has the name the
// command read.
func (e *ProblemError) entity(o clientv0.ProblemObject) string {
	if o.Name == "" && o.Kind == e.target.Kind && o.Id == e.target.Id {
		o.Name = e.target.Name
	}

	return table.Entity(string(o.Kind), o.Id, o.Name)
}

// flagsOf names, in each entry of an invalid_field problem, the flag or the
// argument of In that filled the body field: body.email is --email, and
// body.profilePicUrl is the flag whose Go field is ProfilePicURL. A field
// matches by its Go name or by its flag or argument name without dashes,
// in any case. A location that no field of In fills stays as the server
// wrote it.
func flagsOf[In any](err error) error {
	p, ok := errors.AsType[*ProblemError](err)
	if !ok || p.Problem.Code != clientv0.ProblemCodeInvalidField {
		return err
	}

	t := reflect.TypeFor[In]()
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

			if strings.EqualFold(sf.Name, key) || strings.EqualFold(strings.ReplaceAll(name, "-", ""), key) {
				p.Problem.Errors[i].Location = word

				break
			}
		}
	}

	return err
}

// refused is the sentence of update_refused, one for each reason.
func refused(node string, details map[string]any) string {
	reason, _ := details["reason"].(string)
	text, _ := details["clientError"].(string)

	switch reason {
	case "notConnected":
		return node + " is not connected."
	case "updatesNotAllowed":
		return node + ` does not allow remote updates. Run "tailscale set --auto-update" on it.`
	case "clientRefused":
		if text == "" {
			return node + " refused the update."
		}

		return node + " refused the update: " + table.Visible(text, "")
	case "timeout":
		return node + " did not answer in time."
	}

	return node + " did not start the update (" + table.Visible(reason, "") + ")."
}

// texts are the entries of a list of the details, each made visible.
func texts(v any) []string {
	list, _ := v.([]any)

	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, table.Visible(fmt.Sprint(s), ""))
	}

	return out
}

// forbidden names what the credential lacks, when the problem says it.
func forbidden(details map[string]any) string {
	scopes := texts(details["scopes"])

	rule, _ := details["rule"].(string)

	switch {
	case len(scopes) > 0:
		return "\nIt lacks the scope " + strings.Join(scopes, ", ") + "."
	case tokenRule(rule) != "":
		return "\n" + tokenRule(rule)
	case rule != "":
		return "\nA token rule refuses it: " + table.Visible(rule, "") + "."
	}

	return ""
}

// tokenRule is the sentence of a token rule the server names in
// forbidden's details.rule; "" for a rule this build does not know, which
// prints its word.
func tokenRule(rule string) string {
	switch rule {
	case "token_cannot_change_user_name_or_email":
		return "An OAuth access token cannot change the name or the email of a user; an API key can."
	case "token_must_own_tags":
		return "An OAuth access token gives and takes only tags it holds or owns, and only on a node whose tags are all its own; an API key may give any tag of the policy."
	}

	return ""
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
