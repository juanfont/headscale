package v2

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/tailscale/hujson"
)

// PolicyError is one problem of a policy, with where its text has it. Line
// and Column count from 1, in bytes as hujson does; 0 means the problem has
// no place in the text.
type PolicyError struct {
	Message      string
	Line, Column int
}

// FailedTest is one assertion of a tests or sshTests entry that did not hold.
type FailedTest struct {
	// Kind is acl for an entry of tests, ssh for one of sshTests.
	Kind string
	// Index is the position of the entry in its list, from 0.
	Index    int
	Src, Dst string
	// User is the login user of an ssh assertion, "" for acl.
	User string
	// Want and Got are accept or deny, and for ssh also check.
	Want, Got string
	// Line and Column are where the entry is, as for [PolicyError].
	Line, Column int
}

// Explanation is a refused policy as data. Each list holds at most
// [maxExplained] entries; the counts are how many there are in all.
type Explanation struct {
	Errors          []PolicyError
	ErrorCount      int
	FailedTests     []FailedTest
	FailedTestCount int
	// TestsNotRun is how many entries of tests and sshTests were not run
	// because the policy was refused before them; 0 when they ran, or when
	// the text cannot be read far enough to count them.
	TestsNotRun int
}

// The results of an assertion in a [FailedTest].
const (
	testAccept = "accept"
	testDeny   = "deny"
	testCheck  = "check"
)

// maxExplained bounds each list [Explain] returns: a policy of a few lines
// can fail a test for every pair of a long user and destination list.
const maxExplained = maxTestFailureLines

// Explain is err, which refused the policy b, as data: every problem with
// its place in b, and every assertion of its tests that did not hold, each
// placed at its entry. An entry of tests or sshTests that could not be run
// is a problem, placed at the entry. The messages are sentences for a
// person: the steps that wrap an error and the words of the decoder are
// left out.
func Explain(b []byte, err error) Explanation {
	var (
		problems []PolicyError
		failed   []FailedTest
		ast      *hujson.Value
		notRun   = errors.Is(err, ErrPolicyEmpty) || errors.Is(err, ErrPolicyNotObject) || errors.Is(err, ErrPolicyNUL)
	)

	if err == nil {
		return Explanation{}
	}

	// A blank text is refused by the parser before it is seen as empty; it
	// reads as the empty policy does.
	if len(bytes.TrimSpace(b)) == 0 {
		return Explanation{Errors: []PolicyError{{Message: ErrPolicyEmpty.Error()}}, ErrorCount: 1}
	}

	// The text is read once, and only when a place is looked up: as the
	// decoder reads it, for a place by the decoder's names, and its AST, for
	// a pointer of the decoder, which spells each name as the text does.
	var pt *policyText

	text := func() *policyText {
		if pt == nil {
			pt = readPolicyText(b)
			ast = &pt.ast
		}

		return pt
	}

	// place is where the entry index of the tests block is, by the
	// decoder's name of the block, whatever the text spells it.
	place := func(block string, index int) (int, int) {
		return text().place(block, strconv.Itoa(index))
	}

	ambiguous := map[string]bool{}
	uses := map[string]int{}

	var visit func(error)

	visit = func(err error) {
		switch e := err.(type) { //nolint:errorlint // each wrapper is visited on its own
		case *TestsFailedError:
			for _, f := range e.failed {
				block := testsBlock
				if f.Kind == "ssh" {
					block = sshTestsBlock
				}

				f.Line, f.Column = place(block, f.Index)
				failed = append(failed, f)
			}

			for _, te := range e.unevaluated {
				line, col := place(te.block, te.index)
				problems = append(problems, PolicyError{Message: fmt.Sprintf("%s[%d]: %s", te.block, te.index, te.message), Line: line, Column: col})
			}

			return
		case *ambiguousUserError:
			// One entry per text, where the policy first names it.
			if !ambiguous[e.token] {
				ambiguous[e.token] = true
				line, col := text().namePlace("user", e.token, 0)
				problems = append(problems, PolicyError{Message: e.explain(), Line: line, Column: col})
			}

			return
		case *contextError:
			notRun = notRun || e.beforeTests
			visit(e.err)

			return
		case *testEntryError:
			message := e.err.Error()
			if e.what != "" {
				message = e.what + ": " + message
			}

			line, col := place(e.block, e.index)
			problems = append(problems, PolicyError{Message: fmt.Sprintf("%s[%d]: %s", e.block, e.index, message), Line: line, Column: col})

			return
		case *placedError:
			line, col := e.line, e.column

			if e.pointer != "" {
				text()

				if found := ast.Find(e.pointer); found != nil {
					line, col = lineColumn(b, found.StartOffset)
				}
			}

			problems = append(problems, PolicyError{Message: e.message, Line: line, Column: col})

			return
		}

		// The sentinel beside a list of test problems says nothing of its own.
		// Only the bare sentinel: errors.Is would match its wrapper too.
		if slices.Contains([]error{errPolicyTestsFailed, errSSHPolicyTestsFailed}, err) {
			return
		}

		if multi, ok := err.(interface{ Unwrap() []error }); ok { //nolint:errorlint // the list itself
			for _, e := range multi.Unwrap() {
				visit(e)
			}

			return
		}

		// A wrapper adds context to one problem; it is dropped only when
		// what it wraps has problems of its own to name.
		inner := errors.Unwrap(err)
		if inner != nil && explained(inner) {
			visit(inner)

			return
		}

		if what, name, ok := undefinedName(err); ok {
			// Each use is its own problem, at its own place, in order.
			line, col := text().namePlace(what, name, uses[name])
			uses[name]++
			problems = append(problems, PolicyError{Message: fmt.Sprintf("unknown %s %q", what, name), Line: line, Column: col})

			return
		}

		problems = append(problems, PolicyError{Message: err.Error()})
	}

	visit(err)

	var skipped int

	if notRun {
		for _, block := range []string{testsBlock, sshTestsBlock} {
			if v := text().at(block); v != nil {
				if arr, ok := v.Value.(*hujson.Array); ok {
					skipped += len(arr.Elements)
				}
			}
		}
	}

	return Explanation{
		Errors:          problems[:min(len(problems), maxExplained)],
		ErrorCount:      len(problems),
		FailedTests:     failed[:min(len(failed), maxExplained)],
		FailedTestCount: len(failed),
		TestsNotRun:     skipped,
	}
}

// undefinedName is the tag, group or host that err, or an error it wraps,
// finds not defined, with what it is. Those errors are the sentinel and the
// quoted name, under whatever step wraps them.
func undefinedName(err error) (string, string, bool) {
	kinds := map[error]string{ErrTagNotDefined: "tag", ErrGroupNotDefined: "group", ErrHostNotDefined: "host"}

	for ; err != nil; err = errors.Unwrap(err) {
		inner := errors.Unwrap(err)

		what, ok := kinds[inner]
		if !ok {
			continue
		}

		name, uerr := strconv.Unquote(strings.TrimPrefix(err.Error(), inner.Error()+": "))
		if uerr != nil {
			return "", "", false
		}

		return what, name, true
	}

	return "", "", false
}

// explained reports whether err, or an error it wraps, is one [Explain]
// reads apart.
func explained(err error) bool {
	for ; err != nil; err = errors.Unwrap(err) {
		switch err.(type) { //nolint:errorlint // the chain is walked here
		case *TestsFailedError, *ambiguousUserError, *placedError, *testEntryError, interface{ Unwrap() []error }:
			return true
		}
	}

	return false
}

// lineColumn is where offset n of b is, as hujson counts it.
func lineColumn(b []byte, n int) (int, int) {
	n = min(max(n, 0), len(b))

	return 1 + bytes.Count(b[:n], []byte("\n")), 1 + n - (bytes.LastIndexByte(b[:n], '\n') + 1)
}

// Where [Policy.validate] refuses each kind of undefined name, and where
// [Policy.walkUsernames] reads a user, as paths of the text by the JSON
// names of the fields ("*" is any key or index). A name is placed only
// there: the same spelling elsewhere, an SSH login, a test or a place that
// refuses it in other words, is another thing, and counting it would place
// the problem at the wrong line.
var (
	hostRefs  = []string{"acls/*/src/*", "acls/*/dst/*", "grants/*/src/*", "grants/*/dst/*", "nodeAttrs/*/target/*"}
	tagRefs   = append(slices.Clone(hostRefs), "ssh/*/src/*", "ssh/*/dst/*", "autoApprovers/routes/*/*", "autoApprovers/exitNode/*")
	groupRefs = append(slices.Clone(hostRefs), "ssh/*/src/*", "tagOwners/*/*", "autoApprovers/routes/*/*", "autoApprovers/exitNode/*")
	userRefs  = append(slices.Clone(tagRefs), "tagOwners/*/*", "groups/*/*")
)

// placedAt is every path at which [Explain] places what it finds by
// walking the text, by what it places there: the names, and the entries of
// the tests, also counted when they did not run. Its tests walk it whole.
var placedAt = map[string][]string{
	"host": hostRefs, "tag": tagRefs, "group": groupRefs, "user": userRefs,
	testsBlock: {testsBlock + "/*"}, sshTestsBlock: {sshTestsBlock + "/*"},
}

// The JSON names of the two blocks of tests.
const (
	testsBlock    = "tests"
	sshTestsBlock = "sshTests"
)

// policyText is the text of a policy as the decoder reads it, the one
// answer to which field of the policy a value is in: each value in the
// order of the text, at its path by the JSON names of the fields (the
// decoder's name for a member, whatever its spelling; "" for a member it
// reads into no field), with the type the decoder reads it into.
type policyText struct {
	b      []byte
	ast    hujson.Value
	values []textValue
}

type textValue struct {
	path []string
	v    *hujson.Value
	t    reflect.Type
	// list is the type of the list v is an element of, nil when it is in
	// none.
	list reflect.Type
}

// readPolicyText walks b, which may not parse: then it has no values.
func readPolicyText(b []byte) *policyText {
	pt := &policyText{b: b}

	ast, err := hujson.Parse(bytes.Clone(b))
	if err != nil {
		return pt
	}

	pt.ast = ast

	// The decoder is asked once for each name of each type.
	type member struct {
		name string
		t    reflect.Type
	}

	asked := map[reflect.Type]map[string]member{}

	var walk func(v *hujson.Value, t, list reflect.Type, path []string)

	walk = func(v *hujson.Value, t, list reflect.Type, path []string) {
		for t != nil && t.Kind() == reflect.Pointer {
			t = t.Elem()
		}

		pt.values = append(pt.values, textValue{path: slices.Clone(path), v: v, t: t, list: list})

		switch x := v.Value.(type) {
		case *hujson.Object:
			for i := range x.Members {
				key, _ := x.Members[i].Name.Value.(hujson.Literal)
				m := member{name: key.String()}

				switch {
				case t != nil && t.Kind() == reflect.Struct:
					if asked[t] == nil {
						asked[t] = map[string]member{}
					}

					got, ok := asked[t][m.name]
					if !ok {
						// A member the decoder reads into no field keeps its
						// name as written, and no type.
						got = m
						if name, ft, found := memberOf(t, m.name); found {
							got = member{name: name, t: ft}
						}

						asked[t][m.name] = got
					}

					m = got
				case t != nil && t.Kind() == reflect.Map:
					m.t = t.Elem()
				}

				walk(&x.Members[i].Value, m.t, nil, append(path, m.name))
			}
		case *hujson.Array:
			var elem reflect.Type
			if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
				elem = t.Elem()
			}

			for i := range x.Elements {
				walk(&x.Elements[i], elem, t, append(path, strconv.Itoa(i)))
			}
		}
	}

	walk(&pt.ast, reflect.TypeFor[Policy](), nil, nil)

	return pt
}

// at is the value at path, nil when the text has none.
func (pt *policyText) at(path ...string) *hujson.Value {
	for _, tv := range pt.values {
		if slices.Equal(tv.path, path) {
			return tv.v
		}
	}

	return nil
}

// place is where the value at path starts, 0 and 0 when there is none.
func (pt *policyText) place(path ...string) (int, int) {
	if v := pt.at(path...); v != nil {
		return lineColumn(pt.b, v.StartOffset)
	}

	return 0, 0
}

// namePlace is where the text names name, a host, tag or group as what
// says, or a user, for the n-th time, from 0, or the last time when it names
// it fewer times: at one of the paths [placedAt] gives what, as the decoder
// reads the string there ([decodedName]).
func (pt *policyText) namePlace(what, name string, n int) (int, int) {
	refs := placedAt[what]
	line, col := 0, 0

	for _, tv := range pt.values {
		lit, ok := tv.v.Value.(hujson.Literal)
		if !ok || lit.Kind() != '"' || !slices.ContainsFunc(refs, func(ref string) bool { return pathIs(tv.path, ref) }) {
			continue
		}

		if named, ok := decodedName(tv.list, lit); !ok || named != name {
			continue
		}

		line, col = lineColumn(pt.b, tv.v.StartOffset)

		if n == 0 {
			break
		}

		n--
	}

	return line, col
}

// decodedName is the name the decoder reads the string lit into as an
// element of a list of type list: the alias, without its ports in an ACL
// destination and without the white space it trims, the owner or the user.
// ok is false when it reads no name there.
func decodedName(list reflect.Type, lit hujson.Literal) (string, bool) {
	if list == nil {
		return "", false
	}

	v := reflect.New(list)
	if json.Unmarshal(append(append([]byte{'['}, lit...), ']'), v.Interface(), policyJSONOpts...) != nil || v.Elem().Len() != 1 {
		return "", false
	}

	// An element of an interface is the name's pointer already; another is
	// addressed, as the names' String methods take a pointer.
	elem := v.Elem().Index(0)
	if elem.Kind() != reflect.Interface {
		elem = elem.Addr()
	}

	switch e := elem.Interface().(type) {
	case *AliasWithPorts:
		if e.Alias != nil {
			return e.String(), true
		}
	case fmt.Stringer:
		return e.String(), true
	}

	return "", false
}

// memberOf is the JSON name of the field of the struct type t that the
// decoder reads a member called name into, and the field's type; found is
// false when it reads it into none. The decoder answers, with the options it
// parses a policy with, so the names it takes (any case, with '-' and '_')
// are found by its rule, not by a copy of it.
func memberOf(t reflect.Type, name string) (string, reflect.Type, bool) {
	var (
		fields []reflect.StructField
		of     []int
	)

	for i := range t.NumField() {
		if f := t.Field(i); f.IsExported() && !f.Anonymous {
			fields = append(fields, reflect.StructField{Name: f.Name, Type: reflect.TypeFor[jsontext.Value](), Tag: f.Tag})
			of = append(of, i)
		}
	}

	member, err := json.Marshal(map[string]any{name: nil})
	if err != nil {
		return "", nil, false
	}

	probe := reflect.New(reflect.StructOf(fields)).Elem()
	if json.Unmarshal(member, probe.Addr().Interface(), policyJSONOpts...) != nil {
		return "", nil, false
	}

	for i := range fields {
		if probe.Field(i).Len() > 0 {
			f := t.Field(of[i])
			jsonName, _, _ := strings.Cut(f.Tag.Get("json"), ",")

			return cmp.Or(jsonName, f.Name), f.Type, true
		}
	}

	return "", nil, false
}

// pathIs reports whether path is ref, whose "*" is any segment.
func pathIs(path []string, ref string) bool {
	segs := strings.Split(ref, "/")
	if len(segs) != len(path) {
		return false
	}

	for i, s := range segs {
		if s != "*" && s != path[i] {
			return false
		}
	}

	return true
}

// testEntryError is a tests or sshTests entry whose shape is refused before
// it runs, at index of block; what is the assertion, "" for the entry. It
// reads as these errors always have; [Explain] places it at its entry.
type testEntryError struct {
	block string
	index int
	what  string
	err   error
}

func testEntryErr(block string, index int, what string, err error) error {
	return &testEntryError{block: block, index: index, what: what, err: err}
}

func (e *testEntryError) Error() string {
	switch {
	case e.block == sshTestsBlock:
		return fmt.Sprintf("sshTest %d: %v", e.index, e.err)
	case e.what == "":
		return fmt.Sprintf("test %d: %v", e.index, e.err)
	default:
		return fmt.Sprintf("test %d, %s: %v", e.index, e.what, e.err)
	}
}

func (e *testEntryError) Unwrap() error { return e.err }

// contextError is err with the step of the write where it arose. It reads
// as fmt.Errorf("%s: %w") would; [Explain] answers err alone, which names
// the problem in the policy. beforeTests is a step that refuses the policy
// before its tests run.
type contextError struct {
	context     string
	err         error
	beforeTests bool
}

func (e *contextError) Error() string { return e.context + ": " + e.err.Error() }

func (e *contextError) Unwrap() error { return e.err }

// testError is an entry of tests or sshTests that could not be run.
type testError struct {
	block   string
	index   int
	message string
}

// placedError is a problem of the policy at a place in its text: a JSON
// pointer, or a line and a column. It reads as err; message is what
// [Explain] answers.
type placedError struct {
	err          error
	message      string
	pointer      string
	line, column int
}

func (e *placedError) Error() string { return e.err.Error() }

func (e *placedError) Unwrap() error { return e.err }

// atPointer is err placed at ptr, explained as its own text.
func atPointer(err error, ptr jsontext.Pointer) error {
	return &placedError{err: err, message: err.Error(), pointer: string(ptr)}
}

// duplicatePlaced is err, a name that its object has twice, placed at the
// second time. The decoder knows where: off, the byte offset of that name in
// the text it decoded, which is b with its metadata members stripped and
// standardized. Standardizing keeps offsets and stripping does not, so the
// name is found by its place among the members of its object that the
// stripping keeps, ptr's parent: the k-th there is the k-th kept in b.
func duplicatePlaced(b []byte, err error, ptr jsontext.Pointer, off int64) error {
	placed := &placedError{err: err, message: fmt.Sprintf("%q is named twice in the same object; name it once", ptr.LastToken())}

	// Each parsed anew: a clone drops the trailing commas that the offsets
	// of the decoded text count.
	text, perr := hujson.Parse(bytes.Clone(b))
	if perr != nil {
		return placed
	}

	kept, perr := hujson.Parse(bytes.Clone(b))
	if perr != nil {
		return placed
	}

	decoded, perr := hujson.Parse(bytes.Clone(b))
	if perr != nil {
		return placed
	}

	stripMetadataMembers(&decoded)
	decoded.Standardize()

	inDecoded, ok := objectAt(&decoded, ptr.Parent())
	if !ok {
		return placed
	}

	k := slices.IndexFunc(inDecoded.Members, func(m hujson.ObjectMember) bool { return int64(m.Name.StartOffset) == off })

	inText, ok := objectAt(&text, ptr.Parent())
	if k < 0 || !ok {
		return placed
	}

	// The members the stripping keeps, at their offsets in b, which it
	// leaves; where it did not strip, as in a grant's capability, the same
	// count shows it.
	stripMetadataMembers(&kept)

	inKept, ok := objectAt(&kept, ptr.Parent())

	members := inText.Members
	if ok && len(inKept.Members) == len(inDecoded.Members) {
		members = inKept.Members
	}

	if k < len(members) {
		placed.line, placed.column = lineColumn(b, members[k].Name.StartOffset)
	}

	return placed
}

// objectAt is the object at ptr in v.
func objectAt(v *hujson.Value, ptr jsontext.Pointer) (*hujson.Object, bool) {
	found := v.Find(string(ptr))
	if found == nil {
		return nil, false
	}

	obj, ok := found.Value.(*hujson.Object)

	return obj, ok
}

// semanticPlaced is a decode error of the policy placed where it is: the
// error a type gave for its value, or that the value has the wrong type.
func semanticPlaced(err error) error {
	// The innermost says what is wrong; the pointer is composed through
	// every decode on the way ([decoderPlace]).
	var serr *json.SemanticError

	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := e.(*json.SemanticError); ok { //nolint:errorlint // each in the chain
			serr = s
		}
	}

	if serr == nil {
		return err
	}

	ptr, _ := decoderPlace(err)
	if ptr == "" {
		return &placedError{err: err, message: "the policy must be an object, such as {}", line: 1, column: 1}
	}

	message := "has a value of the wrong type"
	if serr.Err != nil {
		message = serr.Err.Error()
	}

	return &placedError{err: err, message: message, pointer: string(ptr)}
}

// decoderPlace is where the decoder met err, in the text it decoded. A type
// whose method decodes its own bytes again (a test entry, a list of
// aliases, owners or approvers, groups, hosts, an alias with ports, a
// protocol and its ports, an SSH user, the destinations of an SSH test)
// starts a decode of its own: its error is relative to the value it was
// given, which the enclosing error places. So the pointers are joined and
// the offsets added, from the outermost decode in.
func decoderPlace(err error) (jsontext.Pointer, int64) {
	var (
		ptr jsontext.Pointer
		off int64
	)

	for e := err; e != nil; e = errors.Unwrap(e) {
		switch x := e.(type) { //nolint:errorlint // each in the chain
		case *json.SemanticError:
			ptr, off = ptr+x.JSONPointer, off+x.ByteOffset
		case *jsontext.SyntacticError:
			ptr, off = ptr+x.JSONPointer, off+x.ByteOffset
		}
	}

	return ptr, off
}

// hujsonPlaced is a syntax error of hujson at its line and column, which
// hujson writes into the text only.
func hujsonPlaced(err error) error {
	var line, col int

	_, scanErr := fmt.Sscanf(err.Error(), "hujson: line %d, column %d:", &line, &col)
	if scanErr != nil {
		return err
	}

	message := err.Error()

	inner := errors.Unwrap(err)
	if inner != nil {
		message = inner.Error()
	}

	switch {
	case strings.Contains(message, `'\ufeff'`):
		message = "the text has a byte-order mark, which HuJSON does not allow; save the file without it"
	case errors.Is(err, io.ErrUnexpectedEOF):
		message = "the text ends before the policy does"
	}

	return &placedError{err: err, message: message, line: line, column: col}
}

// ambiguousUserError is a user token of the policy that more than one user
// matches. It reads as [ErrMultipleUsersFound] always has.
type ambiguousUserError struct {
	err   error
	token string
	users types.Users
}

func (e *ambiguousUserError) Error() string { return e.err.Error() }

func (e *ambiguousUserError) Unwrap() error { return e.err }

// explain names the token and each user it matches, by ID and name: the
// fault is in the users, not in the text.
func (e *ambiguousUserError) explain() string {
	names := make([]string, len(e.users))
	for i, u := range e.users {
		names[i] = fmt.Sprintf("%d (%s)", u.ID, u.Name)
	}

	return fmt.Sprintf("%q matches more than one user, so it matches none: %s; give the users different names or emails, or name one by its provider identifier",
		e.token, strings.Join(names, ", "))
}
