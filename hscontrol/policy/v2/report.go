package v2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

	// The AST is parsed once, and only when a pointer is looked up.
	find := func(ptr string) *hujson.Value {
		if ast == nil {
			v, perr := hujson.Parse(bytes.Clone(b))
			if perr != nil {
				return nil
			}

			ast = &v
		}

		return ast.Find(ptr)
	}

	place := func(ptr string) (int, int) {
		if found := find(ptr); found != nil {
			return lineColumn(b, found.StartOffset)
		}

		return 0, 0
	}

	ambiguous := map[string]bool{}
	uses := map[string]int{}

	var visit func(error)

	visit = func(err error) {
		switch e := err.(type) { //nolint:errorlint // each wrapper is visited on its own
		case *TestsFailedError:
			for _, f := range e.failed {
				block := "/tests/"
				if f.Kind == "ssh" {
					block = "/sshTests/"
				}

				f.Line, f.Column = place(block + strconv.Itoa(f.Index))
				failed = append(failed, f)
			}

			for _, te := range e.unevaluated {
				line, col := place("/" + te.block + "/" + strconv.Itoa(te.index))
				problems = append(problems, PolicyError{Message: fmt.Sprintf("%s[%d]: %s", te.block, te.index, te.message), Line: line, Column: col})
			}

			return
		case *ambiguousUserError:
			// One entry per text, where the policy first names it.
			if !ambiguous[e.token] {
				ambiguous[e.token] = true
				line, col := stringPlace(b, e.token)
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

			line, col := place("/" + e.block + "/" + strconv.Itoa(e.index))
			problems = append(problems, PolicyError{Message: fmt.Sprintf("%s[%d]: %s", e.block, e.index, message), Line: line, Column: col})

			return
		case *placedError:
			line, col := e.line, e.column
			if e.pointer != "" {
				line, col = place(e.pointer)
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
			line, col := namePlace(b, name, uses[name])
			uses[name]++
			problems = append(problems, PolicyError{Message: fmt.Sprintf("unknown %s %q", what, name), Line: line, Column: col})

			return
		}

		problems = append(problems, PolicyError{Message: err.Error()})
	}

	visit(err)

	var skipped int

	if notRun {
		for _, block := range []string{"/tests", "/sshTests"} {
			if v := find(block); v != nil {
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

// stringPlace is where b first has the string s, as a name or a value.
func stringPlace(b []byte, s string) (int, int) {
	return literalPlace(b, 0, func(lit string) bool { return lit == s })
}

// namePlace is where b names name for the n-th time, from 0, or the last
// time when it names it fewer times: as a string of its own, or as a
// destination, which is the name up to its ports. A name that is not
// defined has no definition, so each is a use.
func namePlace(b []byte, name string, n int) (int, int) {
	return literalPlace(b, n, func(lit string) bool { return lit == name || strings.HasPrefix(lit, name+":") })
}

// literalPlace is where b has, for the n-th time from 0, or the last time,
// a string, as a name or a value, that match takes.
func literalPlace(b []byte, n int, match func(string) bool) (int, int) {
	ast, err := hujson.Parse(bytes.Clone(b))
	if err != nil {
		return 0, 0
	}

	line, col := 0, 0

	for v := range ast.All() {
		if lit, ok := v.Value.(hujson.Literal); ok && lit.Kind() == '"' && match(lit.String()) {
			line, col = lineColumn(b, v.StartOffset)

			if n == 0 {
				break
			}

			n--
		}
	}

	return line, col
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
	case e.block == "sshTests":
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
// second time b has it; ptr is where the decoder met it.
func duplicatePlaced(b []byte, err error, ptr jsontext.Pointer) error {
	name := ptr.LastToken()
	placed := &placedError{err: err, message: fmt.Sprintf("%q is named twice in the same object; name it once", name)}

	ast, perr := hujson.Parse(bytes.Clone(b))
	if perr != nil {
		return placed
	}

	parent := ast.Find(string(ptr.Parent()))
	if parent == nil {
		return placed
	}

	obj, ok := parent.Value.(*hujson.Object)
	if !ok {
		return placed
	}

	seen := 0

	for _, m := range obj.Members {
		if lit, ok := m.Name.Value.(hujson.Literal); ok && lit.String() == name {
			seen++
			if seen == 2 {
				placed.line, placed.column = lineColumn(b, m.Name.StartOffset)

				break
			}
		}
	}

	return placed
}

// semanticPlaced is a decode error of the policy placed where it is: the
// error a type gave for its value, or that the value has the wrong type.
func semanticPlaced(err error) error {
	serr, ok := errors.AsType[*json.SemanticError](err)
	if !ok {
		return err
	}

	if serr.JSONPointer == "" {
		return &placedError{err: err, message: "the policy must be an object, such as {}", line: 1, column: 1}
	}

	message := "has a value of the wrong type"
	if serr.Err != nil {
		message = serr.Err.Error()
	}

	return &placedError{err: err, message: message, pointer: string(serr.JSONPointer)}
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
