package command

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
)

// ProblemError is a problem the server answered. Its text is the CLI's own
// sentence, written from the code, the object and the details; the detail
// text of the server is never shown, so an error reads the same whatever
// server version words it.
type ProblemError struct {
	Problem clientv0.Problem
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
	case clientv0.Unauthorized:
		return "the server did not accept the API key."
	case clientv0.Forbidden:
		return "this credential may not do that." + forbidden(p.Details)
	case clientv0.NotFound:
		o, err := p.Object.Get()
		if err == nil {
			return table.Entity(string(o.Kind), o.Id, o.Name) + " no longer exists."
		}
	case clientv0.Unhealthy:
		return "the server is not healthy:" + messages(p.Details["reasons"])
	case clientv0.InvalidField:
		var b strings.Builder

		b.WriteString("the server refused a value:")

		for _, f := range p.Errors {
			b.WriteString("\n  " + f.Location + ": " + f.Message)
		}

		return b.String()
	case clientv0.TooLarge:
		return "the file is too large for the server."
	case clientv0.Internal:
		return "the server had an internal error. Its log has the request " + p.RequestId + "."
	}

	// A code this build does not know.
	return p.Title + " (" + string(p.Code) + ")."
}

// forbidden names what the credential lacks, when the problem says it.
func forbidden(details map[string]any) string {
	var scopes []string

	if list, ok := details["scopes"].([]any); ok {
		for _, s := range list {
			scopes = append(scopes, fmt.Sprint(s))
		}
	}

	rule, _ := details["rule"].(string)

	switch {
	case len(scopes) > 0:
		return "\nIt lacks the scope " + strings.Join(scopes, ", ") + "."
	case rule != "":
		return "\nA token rule refuses it: " + rule + "."
	}

	return ""
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

		b.WriteString("\n  " + text)
	}

	return b.String()
}
