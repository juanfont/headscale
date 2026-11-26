package command

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	lib "github.com/juanfont/headscale/cmdline/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
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
	// word is the target as it was typed, which the lookup found to be
	// the target alone, for a line that names it again.
	word string
	// changed is a refusal of the builder's guard on the second try: the
	// target changed again, whatever code the command's guard is refused
	// with.
	changed bool
	// kept is a refusal of a reload: the policy in force stays.
	kept bool
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

// problemIn is the problem err holds.
func problemIn(
	err error,
) (*ProblemError, bool) {
	return errors.AsType[*ProblemError](err)
}

// refusalCode is the code of the problem err holds; "" for none.
func refusalCode(err error) string {
	p, ok := problemIn(err)
	if !ok {
		return ""
	}

	return string(p.Problem.Code)
}

// about gives the problem err holds what the builder knows of the
// command it answers.
func about(err error, target lib.Object, word string, expiry time.Time) {
	p, ok := problemIn(err)
	if !ok {
		return
	}

	p.target = clientv0.ProblemObject{
		Kind: clientv0.ProblemObjectKind(target.Kind),
		Id:   target.ID,
		Name: target.Name,
	}
	p.word, p.expiry = word, expiry
}

// mayBeMade reports whether err leaves a write unknown: an answer that
// cannot be read, none, or a server fault after the write.
func mayBeMade(err error) bool {
	_, unread := errors.AsType[*unreadableError](err)
	_, fault := errors.AsType[*faultAfterWriteError](err)

	return unread || sentWrite(err) || fault
}

// faultAfterWriteError is a server fault, 5xx, that answered a write: what
// failed may have come after the change, as a read after a commit or a
// proxy that gave up waiting, so the change may have been made.
type faultAfterWriteError struct{ error }

func (e *faultAfterWriteError) Unwrap() error { return e.error }

// errAuthReq: an auth request's id is the secret the admin typed, which
// nothing the CLI writes repeats, and no field name tells a check so.
var errAuthReq = errors.New(
	"a result or a row holds an auth request, whose id is the secret of the request: no command prints one",
)

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
	if e.changed {
		o, err := e.Problem.Object.Get()
		if err != nil {
			o = e.target
		}

		return e.entity(o) + " changed while the command ran. Run it again."
	}

	return e.text()
}

// text is the sentence of the problem from its code.
func (e *ProblemError) text() string {
	p := e.Problem

	if s := fixed(p.Code); s != "" {
		return s
	}

	switch p.Code { //nolint:exhaustive // the others print their title
	case clientv0.ProblemCodeUnauthorized:
		// True of every credential and of every reason the server has: a
		// typo, a key never made, one expired or revoked.
		return "the server did not accept the credential of this CLI: it is unknown, expired or revoked.\nIt is set by cli.api_key in the config file, or HEADSCALE_CLI_API_KEY."
	case clientv0.ProblemCodeForbidden:
		return "this credential may not do that." + forbidden(
			p.Details,
			e.target.Kind == "node",
		)
	case clientv0.ProblemCodeNotFound:
		if s, ok := e.notFound(); ok {
			return s
		}
	case clientv0.ProblemCodeNameTaken:
		if s, ok := taken(p, "name"); ok {
			return s
		}
	case clientv0.ProblemCodeEmailTaken:
		if s, ok := taken(p, "email"); ok {
			return s
		}
	case clientv0.ProblemCodePreconditionFailed,
		clientv0.ProblemCodeUserHasNodes,
		clientv0.ProblemCodeUserManagedByOidc:
		o, err := p.Object.Get()
		if err == nil {
			return e.aboutObject(o)
		}
	case clientv0.ProblemCodeAuthRequestKind:
		if s := wrongVerb(p.Details["kind"]); s != "" {
			return s
		}
	case clientv0.ProblemCodeTagsRequired:
		if e.target.Kind == "node" {
			return "the tag list is empty. A tagged node needs at least one tag."
		}

		return "the tag list is empty."
	case clientv0.ProblemCodeInvalidScope:
		return listed(
			"unknown scope: ",
			"unknown scopes: ",
			texts(p.Details["scopes"]),
		) + "."
	case clientv0.ProblemCodeScopeRequiresTags:
		scopes := texts(p.Details["scopes"])

		return listed(
			"scope ",
			"scopes ",
			scopes,
		) + map[bool]string{true: " needs", false: " need"}[len(scopes) < 2] + " at least one tag (--tags)."
	case clientv0.ProblemCodeTagsNotPermitted:
		return "these tags are not in the policy: " + strings.Join(
			texts(p.Details["tags"]),
			", ",
		) + "."
	case clientv0.ProblemCodeExpiryInPast:
		if e.expiry.IsZero() {
			return "the expiry is in the past."
		}

		s := e.expiry.UTC().Format("2006-01-02 15:04 UTC") + " is in the past."
		if e.target.Kind == "node" {
			s += "\nTo expire the node now: headscale nodes expire " + table.Visible(
				e.target.Id,
				"",
			)
		}

		return s
	case clientv0.ProblemCodeUpdateRefused:
		o, err := p.Object.Get()
		if err == nil {
			return refused(table.Entity(string(o.Kind), o.Id, o.Name), p.Details)
		}
	case clientv0.ProblemCodeUnhealthy:
		return unhealthy(p.Details["reasons"])
	case clientv0.ProblemCodeRegistrationRefused:
		return registrationRefused(p.Details["reason"])
	case clientv0.ProblemCodeInvalidField:
		return "the server refused a value:" + fieldErrors(p.Errors)
	case clientv0.ProblemCodePolicyInvalid:
		return policyInvalid(p.Details, e.kept)
	case clientv0.ProblemCodePolicyReadOnly:
		return readOnly(p.Details["path"])
	case clientv0.ProblemCodeInternal:
		return "the server had an internal error. Its log has the request " + table.Visible(
			p.RequestId,
			"",
		) + "."
	}

	// A code this build does not know.
	return table.Visible(p.Title, "") + " (" + table.Visible(string(p.Code), "") + ")."
}

// fixed is the sentence of a code that says the same every time; "" for
// another.
func fixed(code clientv0.ProblemCode) string {
	switch code { //nolint:exhaustive // the others need more than the code
	case clientv0.ProblemCodeOwnerConflict:
		// The server answers it for a key with no owner too.
		return "a key needs one owner: one user, or tags, not both."
	case clientv0.ProblemCodeExpiryRequired:
		return "a key must have an expiry."
	case clientv0.ProblemCodeTooLarge:
		return "the file is too large for the server."
	case clientv0.ProblemCodePolicySourceChanging:
		return "the policy changed while the server read it; the policy in force stays. Reload again."
	}

	return ""
}

// policyInvalid is the sentence of policy_invalid: a line for each problem
// and each failed test, at its line and column of the file, in the order
// of the file and those with no place last; how many there are when the
// server cut a list, and how many tests did not run. kept is a reload,
// which leaves the policy in force.
func policyInvalid(details map[string]any, kept bool) string {
	var d clientv0.PolicyInvalidDetails

	b, _ := json.Marshal(details) //nolint:errchkjson // a map that came from JSON
	_ = clientv0.DecodeResponse(b, &d)

	type entry struct {
		line, column int64
		text         string
	}

	var entries []entry

	add := func(line, column nullable.Nullable[int64], placed, unplaced string) {
		l, err := line.Get()
		if err != nil {
			entries = append(entries, entry{line: math.MaxInt64, text: unplaced})

			return
		}

		c, err := column.Get()
		if err != nil {
			entries = append(
				entries,
				entry{
					line: l,
					text: "line " + strconv.FormatInt(l, 10) + ": " + placed,
				},
			)

			return
		}

		entries = append(
			entries,
			entry{
				line:   l,
				column: c,
				text: "line " + strconv.FormatInt(
					l,
					10,
				) + ", column " + strconv.FormatInt(
					c,
					10,
				) + ": " + placed,
			},
		)
	}

	for _, e := range d.PolicyErrors {
		add(e.Line, e.Column, e.Message, e.Message)
	}

	for _, f := range d.FailedTests {
		test, block := "test ", "tests"
		if f.Kind == clientv0.FailedTestKindSsh {
			test, block = "SSH test ", "sshTests"
		}

		said := f.Src + " -> " + f.Dst

		user, err := f.User.Get()
		if err == nil {
			said += " as " + user
		}

		said += ": expected " + string(f.Want) + ", got " + string(f.Got)
		add(
			f.Line,
			f.Column,
			test+said,
			block+"["+strconv.FormatInt(f.Index, 10)+"]: "+said,
		)
	}

	slices.SortStableFunc(entries, func(a, b entry) int {
		return cmp.Or(cmp.Compare(a.line, b.line), cmp.Compare(a.column, b.column))
	})

	var s strings.Builder

	s.WriteString("the policy is not valid.")

	if kept {
		s.WriteString(" The old policy is still in use.")
	}

	for _, e := range entries {
		s.WriteString("\n  " + table.Visible(e.text, ""))
	}

	more := func(all int64, shown int, what string) {
		if all > int64(shown) {
			s.WriteString(
				"\n  " + table.Count(
					int(all),
					what,
				) + " in all; the first " + strconv.Itoa(
					shown,
				) + " are shown.",
			)
		}
	}

	more(d.PolicyErrorCount, len(d.PolicyErrors), "problem")
	more(d.FailedTestCount, len(d.FailedTests), "failed test")

	if d.TestsNotRun > 0 {
		s.WriteString(
			"\n  " + table.Count(
				int(d.TestsNotRun),
				"test",
			) + " did not run, because of the problems above.",
		)
	}

	return s.String()
}

// readOnly is the sentence of policy_read_only: the file to edit, or that
// none is set.
func readOnly(path any) string {
	file, _ := path.(string)
	if file == "" {
		return "no policy file is set (policy.path), and the policy cannot be written while policy.mode is file."
	}

	return "the policy is read from " + table.Visible(file, "") + ". Edit that file."
}

// notFound is the sentence of not_found about its object; false for none.
// An auth request is named by its secret, which no sentence repeats.
func (e *ProblemError) notFound() (string, bool) {
	o, err := e.Problem.Object.Get()

	switch {
	case err != nil:
		return "", false
	case o.Kind == clientv0.ProblemObjectKindAuthRequest:
		return "no auth request has this ID. It may have timed out, or it was answered already.", true
	}

	return e.entity(o) + " no longer exists.", true
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
// argument of In that filled the body field: body.email is --email,
// body.profilePicUrl the flag whose Go field is ProfilePicURL, body.userId
// --user, and body.tags[1] --tags. A field matches by its Go name or by
// its flag or argument name without dashes, with or without Id, in any
// case. A location that no field of In fills stays as the server
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

			// An owner fills the user or the tags; an entity, such as
			// --user, its ID; an item of a list, tags[1], the list.
			root, _, _ := strings.Cut(key, "[")
			owner := sf.Type == reflect.TypeFor[Owner]() &&
				(root == "userId" || root == "tags")
			bare := strings.ReplaceAll(name, "-", "")

			if owner ||
				slices.ContainsFunc(
					[]string{sf.Name, bare, sf.Name + "Id", bare + "Id"},
					func(n string) bool { return strings.EqualFold(n, root) },
				) {
				p.Problem.Errors[i].Location = word

				break
			}
		}
	}

	return err
}

// fieldErrors are the lines of invalid_field, one for each field. flagsOf
// names a field as the flag that filled it; any other is the API's name,
// and the line says so.
func fieldErrors(errs []clientv0.FieldError) string {
	var b strings.Builder

	for _, f := range errs {
		at := table.Visible(f.Location, "")
		if !strings.HasPrefix(at, "--") && !strings.HasPrefix(at, "<") {
			at += " (as the server names it)"
		}

		b.WriteString("\n  " + at + ": " + table.Visible(f.Message, ""))
	}

	return b.String()
}

// unhealthy is the sentence of unhealthy, with its reasons. A cache of auth
// requests that is full, alone, is no fault of the server's health.
func unhealthy(reasons any) string {
	list, _ := reasons.([]any)
	if len(list) == 1 {
		if m, _ := list[0].(map[string]any); m["code"] == string(
			clientv0.HealthMessageCodeAuthRequestsFull,
		) {
			return "the server holds as many auth requests as it takes. Answer some, or wait until they time out, then run the command again."
		}
	}

	return "the server is not healthy:" + messages(reasons)
}

// registrationRefused is the sentence of registration_refused, by its
// reason: the request still waits, and what the machine must do. It names
// no ID.
func registrationRefused(reason any) string {
	switch reason {
	case "nodeKeyInUse":
		return "the node key of this machine belongs to another node already.\n" +
			"Run tailscale logout on the machine, then tailscale up, and answer the request it shows then."
	case "reportTooLarge":
		return "this machine reported more about itself than the server takes.\n" +
			"Have it advertise less, such as fewer routes or tags, and answer the request it shows then."
	}

	text, _ := reason.(string)

	return "the server refused the registration (" + table.Visible(text, "") + ")."
}

// wrongVerb is the sentence of auth_request_kind: the kind the request
// is, and the command that answers it. The line holds <auth-id>, never the
// ID: the edge would mask it, and a line that cannot be run is no help.
func wrongVerb(kind any) string {
	switch kind {
	case string(clientv0.AuthRequestKindRegistration):
		return "this is a registration request. It needs a user:\n  headscale auth register <auth-id> <user>"
	case string(clientv0.AuthRequestKindSshCheck):
		return "this is an SSH check request. Use:\n  headscale auth approve <auth-id>"
	}

	return ""
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

// aboutObject is the sentence of a problem about the object o.
func (e *ProblemError) aboutObject(o clientv0.ProblemObject) string {
	p := e.Problem

	switch p.Code { //nolint:exhaustive // Error sends only these
	case clientv0.ProblemCodeUserHasNodes:
		return hasNodes(o, p.Details["nodes"], e.word)
	case clientv0.ProblemCodeUserManagedByOidc:
		return table.Entity(
			string(o.Kind),
			o.Id,
			o.Name,
		) + " is managed by OIDC and cannot be edited here."
	}

	return table.Entity(
		string(o.Kind),
		o.Id,
		o.Name,
	) + " changed while the command ran. Run it again."
}

// hasNodes is the sentence of user_has_nodes: the nodes the user owns by
// name, all of them, and the line that deletes them together. The line
// names the user by the word typed, which the lookup found to be this
// user alone, when it can be typed again as it is, and by its ID
// otherwise: a word of digits alone is read as an ID, one that starts
// with a dash as a flag.
func hasNodes(user clientv0.ProblemObject, nodes any, word string) string {
	list, _ := nodes.([]any)

	names := make([]string, 0, len(list))
	for _, n := range list {
		m, _ := n.(map[string]any)
		names = append(names, table.Visible(fmt.Sprint(m["name"]), ""))
	}

	if word == "" || strings.HasPrefix(word, "-") ||
		strings.Trim(word, "0123456789") == "" ||
		strings.ContainsFunc(word, func(r rune) bool {
			return !strings.ContainsRune("@.-_+", r) &&
				(r > unicode.MaxASCII || !unicode.IsLetter(r) && !unicode.IsDigit(r))
		}) {
		word = user.Id
	}

	return table.Entity(
		string(user.Kind),
		user.Id,
		user.Name,
	) + " still owns " + table.Count(
		len(names),
		"node",
	) + ": " + strings.Join(
		names,
		", ",
	) +
		".\nDelete or tag them first, or delete them together:\n  headscale users delete " + table.Visible(
		word,
		"",
	) + " --with-nodes"
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

// forbidden names what the credential lacks, when the problem says it; node
// is a command whose target is a node.
func forbidden(details map[string]any, node bool) string {
	scopes := texts(details["scopes"])

	rule, _ := details["rule"].(string)

	switch {
	case len(scopes) == 1:
		return "\nIt lacks the scope " + scopes[0] + "."
	case len(scopes) > 1:
		return "\nIt lacks the scopes " + strings.Join(
			scopes[:len(scopes)-1],
			", ",
		) + " and " + scopes[len(scopes)-1] + "."
	case tokenRule(rule, node) != "":
		return "\n" + tokenRule(rule, node)
	case rule != "":
		return "\nA token rule refuses it: " + table.Visible(rule, "") + "."
	}

	return ""
}

// tokenRule is the sentence of a token rule the server names in
// forbidden's details.rule; "" for a rule this build does not know, which
// prints its word. A rule that covers more than one command says what the
// command at hand does: node is a change of a node.
func tokenRule(rule string, node bool) string {
	switch {
	case rule == "token_must_own_tags" && node:
		return "An OAuth access token gives and takes only tags it holds or owns, and changes only a node whose tags are all its own; an API key may give any tag of the policy."
	case rule == "token_must_own_tags":
		return "An OAuth access token gives a key or an OAuth client only tags it holds or owns; an API key may give any tag of the policy."
	}

	switch rule {
	case "token_cannot_change_user_name_or_email":
		return "An OAuth access token cannot change the name or the email of a user; an API key can."
	case "token_must_hold_scopes":
		return "An OAuth access token makes an OAuth client with only scopes it holds itself."
	case "token_cannot_create_api_key":
		return "An OAuth access token cannot make an API key: an API key may do everything, so only an API key or the socket makes one."
	case "token_cannot_register_node_to_user":
		return "An OAuth access token cannot register a node to a user; an API key can."
	case "token_cannot_approve_ssh_check":
		return "An OAuth access token cannot approve an SSH check; an API key can, and a token may reject one."
	case "token_cannot_create_key_for_user":
		return "An OAuth access token makes only tagged keys; an API key may make a key for a user."
	}

	return ""
}

// listed is the list after one or many: "scope a", "scopes a, b".
func listed(one, many string, list []string) string {
	if len(list) == 1 {
		return one + list[0]
	}

	return many + strings.Join(list, ", ")
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
