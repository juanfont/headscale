package command

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/table"
)

// Run runs one command line, argv without the program name, and returns
// the exit code. The hidden completion entry point is answered before
// anything else, so Tab reads no config and calls no server.
func Run(t *Tree, argv []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}

	// Text of the server is made visible where it enters a sentence or a
	// cell. stderr and the Done text pass once more through a filter that
	// keeps line breaks, tabs and backslashes, so a sentence that forgets
	// can at worst break a line, never drive the terminal. Both streams
	// write a credential as its kind (credential.go).
	if env.Stderr != nil {
		errOut := &masking{w: visible{env.Stderr}, cred: t.cred()}
		defer func() { _ = errOut.Flush() }()

		env.Stderr = errOut
	}

	// JSON is the server's data, not the CLI's sentence: it is written past
	// the rule.
	raw := env.Stdout

	out := &masking{w: env.Stdout, cred: t.cred()}
	defer func() { _ = out.Flush() }()

	env.Stdout = out

	var tab strings.Builder
	if t.parser.Serve(&tab, argv) {
		_, _ = io.WriteString(env.Stdout, t.columnNames(tab.String()))

		return 0
	}

	err := t.run(argv, env, raw)

	switch {
	case err == nil:
		return 0
	case errors.Is(err, errAborted):
		fmt.Fprintln(env.Stderr, "Aborted.")

		return 1
	}

	fmt.Fprintf(env.Stderr, "Error: %s\n", t.sentence(err))

	return 1
}

// sentence is the text of err, as the program says it.
func (t *Tree) sentence(err error) string {
	if t.prog.Sentence != nil {
		return t.prog.Sentence(err)
	}

	return err.Error()
}

// run is the builder: the steps of every command, in one order. raw is
// stdout as it is, for the JSON of a result.
func (t *Tree) run(argv []string, env Env, raw io.Writer) error {
	line, step, err := t.check(argv)
	if err != nil {
		return err
	}

	switch step {
	case stepHelp:
		return t.help(env.Stdout, line.Command)
	case stepVersion:
		ctx := env.Context
		if ctx == nil {
			ctx = context.Background()
		}

		_, err := fmt.Fprintln(env.Stdout, t.prog.Version(ctx))

		return err
	case stepColumns:
		output, _ := cmdline.Get[outputFlags](line)

		return listColumns(
			env.Stdout,
			t.leaves[strings.Join(line.Command.Path, " ")].info,
			output.Output != "",
		)
	case stepRun:
	}

	l := t.leaves[strings.Join(line.Command.Path, " ")]
	output, _ := cmdline.Get[outputFlags](line)
	own, _ := cmdline.Get[ownOutputFlags](line)
	file, _ := cmdline.Get[configFlags](line)

	// A value that the parser takes as any word is checked before any call.
	if l.valid != nil {
		err := l.valid(line, t.cred())
		if err != nil {
			return err
		}
	}

	stdin := env.Stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}

	ctx := env.Context
	if ctx == nil {
		ctx = context.Background()
	}

	c := &run{
		ConfigFile: cmp.Or(
			string(file.Config),
			getenv(env.Environ, t.prog.ConfigEnv),
		),
		stdin:    env.Stdin,
		stdout:   env.Stdout,
		raw:      raw,
		stderr:   env.Stderr,
		program:  t.name,
		Environ:  env.Environ,
		terminal: env.Terminal,
		screen:   env.StdoutTerminal,
		width:    env.Width,
		colour:   env.StdoutTerminal && getenv(env.Environ, "NO_COLOR") == "",
		answers:  bufio.NewReader(stdin),
		line:     line,
		json:     output.Output != "" || own.Output != "",
		now:      env.Now,
		tree:     t,
		server:   l.server(line),
	}

	// A file that is named and not there is a mistake, for every command
	// that takes one; finding none in the default places is not.
	if l.config && c.ConfigFile != "" {
		_, err := os.Stat(c.ConfigFile)
		if errors.Is(err, fs.ErrNotExist) {
			//nolint:err113,staticcheck // a sentence of the CLI
			return fmt.Errorf("the config file %s does not exist.", c.ConfigFile)
		}
	}

	c.api, err = t.prog.session(c, ctx, c.server)
	if err != nil {
		return err
	}

	// The lookups run first, inside Line.Run, with the same client as Run.
	// What a lookup returns keeps its own sentence: not found, or the
	// server that cannot be reached.
	err = line.Run(context.WithValue(ctx, ctxKey{}, c))

	ue, ok := errors.AsType[*cmdline.UsageError](err)

	switch {
	case !ok:
		return err
	case ue.Kind == cmdline.Unresolved:
		return ue.Err
	}

	return t.usage(ue)
}

// step is what the builder does with a line that has no mistake.
type step int

const (
	stepRun step = iota
	stepHelp
	stepVersion
	// stepColumns prints the columns of a list: --list-columns.
	stepColumns
)

// check reads a line and decides its step. A mistake on the line, the
// parser's or the builder's own, is the error; a wrong argument count
// yields to --help.
func (t *Tree) check(argv []string) (*cmdline.Line, step, error) {
	line, err := t.parser.Parse(argv)

	var ue *cmdline.UsageError
	if err != nil && !errors.As(err, &ue) {
		return line, stepRun, err
	}

	err = t.mistake(line, ue)
	if err != nil {
		return line, stepRun, t.hinted(line, err)
	}

	help, _ := cmdline.Get[helpFlags](line)
	version, _ := cmdline.Get[versionFlags](line)
	l := t.leaves[strings.Join(line.Command.Path, " ")]

	switch {
	case help.Help, len(line.Command.Commands) > 0 && !version.Version:
		return line, stepHelp, nil
	case version.Version:
		return line, stepVersion, nil
	case l != nil && l.list && slices.ContainsFunc(line.Flags, func(g cmdline.Given) bool { return g.Name == "list-columns" && g.Value == "true" }):
		return line, stepColumns, nil
	case ue != nil:
		return line, stepRun, t.hinted(line, countError(line))
	case l != nil && l.set:
		return line, stepRun, nothingToChange(line)
	}

	return line, stepRun, nil
}

// hinted is err with the command's hint, when err is a wrong argument count
// or an empty list argument.
func (t *Tree) hinted(line *cmdline.Line, err error) error {
	l := t.leaves[strings.Join(line.Command.Path, " ")]
	ue, ok := errors.AsType[*usageError](err)

	if l == nil || l.hint == nil || !ok || ue.kind != cmdline.ArgCount && !ue.empty {
		return err
	}

	if h := l.hint(line.Args); h != "" {
		sep := "\n"
		if ue.kind == cmdline.ArgCount {
			sep = "\n\n"
		}

		ue.text += sep + h
	}

	return err
}

// nothingGiven is the builder's own kind: a set with none of the flags
// it changes.
const nothingGiven cmdline.Kind = -2

// nothingToChange refuses a set that gives none of its Opt flags, the
// fields it changes; a set with no Opt flag replaces a value it takes as an
// argument.
func nothingToChange(line *cmdline.Line) error {
	var opts []string

	for _, f := range line.Command.Flags {
		if f.Optional {
			opts = append(opts, "--"+f.Name)
		}
	}

	for _, g := range line.Flags {
		if slices.Contains(opts, "--"+g.Name) {
			return nil
		}
	}

	if len(opts) == 0 {
		return nil
	}

	return usagef(
		nothingGiven,
		line.Command.Path,
		strings.Join(opts, ", "),
		"nothing to change. Give at least one of\n  %s",
		strings.Join(opts, ", "),
	)
}

type ctxKey struct{}

// ctxOf is the Ctx of the run, carrying the context that Line.Run gives.
func ctxOf[S any](ctx context.Context) Ctx[S] {
	r, _ := ctx.Value(ctxKey{}).(*run)
	api, _ := r.api.(S)

	return Ctx[S]{Context: ctx, run: r, API: api}
}

// CtxOf is the Ctx of the run of ctx, the context a lookup gets.
func CtxOf[S any](ctx context.Context) Ctx[S] { return ctxOf[S](ctx) }

// getenv is the last value of name, as config.Load reads it.
func getenv(environ []string, name string) string {
	for _, kv := range slices.Backward(environ) {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}

	return ""
}

// ErrNotRead is what a Run returns, with the zero result, when its change
// is made and the object to print cannot be read: text prints Done alone,
// and -o json nothing. Any other zero result is a fault of the command.
var ErrNotRead = errors.New(
	"the change is made, and the object to print cannot be read",
)

// errNotAnswer is a Run of a server command that returns a value no answer
// of the server holds: one it made or changed. -o json prints an answer as
// it came and never encodes one again, so this is a fault of the command,
// found in every mode so that any test of it fails.
var errNotAnswer = errors.New(
	"this command returned an object that the server did not send, so -o json cannot print it",
)

// jsonOf is the JSON of a result: the body that the server sent for it, or,
// on a line that talks to no server, the CLI's own object encoded.
func jsonOf(c *run, v any) (json.RawMessage, error) {
	if !c.server {
		return json.Marshal(v)
	}

	raw, ok := c.tree.prog.Answer(c.api, v)
	if !ok {
		return nil, errNotAnswer
	}

	return raw, nil
}

// printOne prints the result of a Spec: JSON as the server sent it, the
// Done text, or a sheet.
func printOne[Out any](
	c *run,
	out Out,
	cols table.Columns[Out],
	blocks table.Blocks[Out],
	done func() string,
) error {
	if reflect.TypeFor[Out]() == reflect.TypeFor[NoOutput]() {
		if c.json {
			return nil
		}

		return writeText(c.stdout, done())
	}

	raw, err := jsonOf(c, out)

	switch {
	case err != nil:
		return err
	case c.json:
		return writeJSON(c.raw, raw)
	}

	if text := done(); text != "" {
		return writeText(c.stdout, text)
	}

	return table.Sheet(c.stdout, out, cols, blocks, c.Now())
}

// printList prints the rows of a ListSpec: the array of their bodies as
// they came, in the order of rows, or a table. A table with no rows is the
// list's sentence on a terminal, and the header alone in a pipe.
func printList[Row any](
	c *run,
	rows []Row,
	cols table.Columns[Row],
	noRows string,
) error {
	raws := make([][]byte, 0, len(rows))

	for _, r := range rows {
		raw, err := jsonOf(c, r)
		if err != nil {
			return err
		}

		raws = append(raws, raw)
	}

	switch {
	case !c.json && len(rows) == 0 && c.screen:
		return writeText(c.stdout, noRows)
	case !c.json && c.screen:
		return table.Render(
			c.stdout,
			rows,
			cols,
			c.Now(),
			&table.Screen{Width: c.width, Colour: c.colour},
		)
	case !c.json:
		return table.Render(c.stdout, rows, cols, c.Now(), nil)
	}

	return writeJSON(
		c.raw,
		append(append([]byte("["), bytes.Join(raws, []byte(","))...), ']'),
	)
}

// errAborted is a question answered no: not done, and no error to explain.
var errAborted = errors.New("aborted")

// confirm asks p on stderr, after the line before when it is not "",
// unless it asks nothing or --force answers it. Only y or yes goes on; with
// no terminal to answer, nothing does. asked is a question that was shown.
func (c *run) confirm(p Prompt, before string) (bool, error) {
	force, _ := cmdline.Get[forceFlags](c.line)
	if p.Question == "" || force.Force {
		return false, nil
	}

	if !c.terminal {
		//nolint:err113,staticcheck // a sentence of the CLI
		return false, fmt.Errorf(
			"confirmation needed, but there is no terminal.\nRun again with --force to %s.",
			p.Action,
		)
	}

	// A question nobody can see gets no answer, whatever stdin holds.
	if before != "" {
		_, err := io.WriteString(c.stderr, before+"\n")
		if err != nil {
			return false, err
		}
	}

	_, err := io.WriteString(c.stderr, p.Question+" [y/N] ")
	if err != nil {
		return false, err
	}

	reply, _ := c.answers.ReadString('\n')
	if r := strings.ToLower(strings.TrimSpace(reply)); r == "y" || r == "yes" {
		return true, nil
	}

	return true, errAborted
}

// runGuarded runs s on in: the question, when s has one, and Run, with the
// guard the builder stores for the write. A write the server refuses
// because its target changed runs once more on the target read again, and
// the question is asked again, after a line that says why the same
// question comes twice; a second refusal is the error. in is what the last
// try ran on.
func runGuarded[S, In, Out any](
	c Ctx[S],
	s Spec[S, In, Out],
	in In,
) (In, Out, error) {
	asked := false

	attempt := func(in In, again string) (Out, error) {
		if c.server {
			c.guard.Store(guardOf(in))
		}

		if s.Confirm != nil {
			p, err := s.Confirm(c, in)
			if err == nil {
				if !asked {
					again = ""
				}

				asked, err = c.confirm(p, again)
			}

			if err != nil {
				var zero Out

				return zero, c.errorOf(err)
			}
		}

		out, err := s.Run(c, in)

		return out, c.errorOf(err)
	}

	out, err := attempt(in, "")
	if !c.changed(err) {
		return in, out, err
	}

	again, ok, rerr := reread(c, in)

	switch {
	case rerr != nil:
		return in, out, rerr
	case !ok:
		return in, out, err
	}

	out, err = attempt(again, c.named(in)+" changed while the question was open.")

	return again, out, err
}

// changed is a write the server refused because its target changed after
// the CLI read it: the program's Precondition.
func (c *run) changed(err error) bool {
	if err == nil || c.tree.prog.Refusal == nil {
		return false
	}

	return c.tree.prog.Refusal(err) == c.tree.prog.Precondition
}

// fields names in err the flags and arguments of in that filled the body
// fields the server refused (Program.Fields).
func (c *run) fields(err error, in reflect.Type) error {
	if err == nil || c.tree.prog.Fields == nil {
		return err
	}

	return c.tree.prog.Fields(err, in)
}

// errorOf is err as the program says an error of its session.
func (c *run) errorOf(err error) error { return c.tree.prog.Error(c.api, err) }

// reread is in with its target read again by its ID: what a write runs on
// after the server refused it because the target changed. ok is false
// when the target's type has no read.
func reread[S, In any](c Ctx[S], in In) (In, bool, error) {
	e, ok := target(reflect.ValueOf(&in).Elem())
	if !ok {
		return in, false, nil
	}

	read := c.tree.entities[e.Type()].read
	if read == nil {
		return in, false, nil
	}

	got, err := read(c, jsonText(e, "id"))
	if err != nil {
		return in, true, c.errorOf(err)
	}

	e.Set(reflect.ValueOf(got))

	return in, true, nil
}

// named is the target of in as a message names it; "" for none.
func (c *run) named(in any) string {
	o, ok := c.object(in)
	if !ok {
		return ""
	}

	return table.Entity(o.Kind, o.ID, o.Name)
}

// object is the target of in as a problem names an object.
func (c *run) object(in any) (Object, bool) {
	e, ok := target(reflect.ValueOf(in))
	if !ok {
		return Object{}, false
	}

	ent, ok := c.tree.entities[e.Type()]
	if !ok {
		return Object{}, false
	}

	return Object{
		Kind: ent.kind,
		ID:   jsonText(e, "id"),
		Name: ent.name(e.Interface()),
	}, true
}

// expiring is an [Expiry] of any words.
type expiring interface {
	At(now time.Time) time.Time
	Word() string
}

// about gives a refusal of the server what the command knows of it: the
// target as the command read it, the word it was typed as, and the expiry
// the command sent (Program.About).
func (c *run) about(err error, in any) error {
	if err == nil || c.tree.prog.About == nil || c.tree.prog.Refusal == nil ||
		c.tree.prog.Refusal(err) == "" {
		return err
	}

	target, _ := c.object(in)

	var expiry time.Time

	defer func() { c.tree.prog.About(err, target, expiry) }()

	v := reflect.ValueOf(in)
	if v.Kind() != reflect.Struct {
		return err
	}

	for _, f := range v.Fields() {
		// An Opt flag: its value when given.
		if get := f.MethodByName(
			"Get",
		); get.IsValid() && get.Type().NumOut() == 2 &&
			get.Type().Out(1).Kind() == reflect.Bool {
			out := get.Call(nil)
			if !out[1].Bool() {
				continue
			}

			f = out[0]
		}

		if e, ok := reflect.TypeAssert[expiring](f); ok && e.Word() == "" {
			expiry = e.At(c.Now())
		}
	}

	return err
}

// kept are what the last filter on stderr and the Done text keeps: the
// sentence's own line breaks and tabs, and backslashes, which the text of
// the server already has doubled.
const kept = "\n\t\\"

// visible makes control characters in what it writes visible, as
// [table.Visible] does, keeping kept.
type visible struct{ w io.Writer }

func (v visible) Write(p []byte) (int, error) {
	_, err := io.WriteString(v.w, table.Visible(string(p), kept))

	return len(p), err
}

// writeText writes the Done text, ending in one newline.
func writeText(w io.Writer, text string) error {
	if text == "" {
		return nil
	}

	_, err := fmt.Fprintln(w, table.Visible(strings.TrimSuffix(text, "\n"), kept))

	return err
}

// writeJSON writes raw indented, with the controls that JSON leaves raw
// written as escapes: the values are the same, and a terminal does not
// act on them.
func writeJSON(w io.Writer, raw json.RawMessage) error {
	var b bytes.Buffer

	err := json.Indent(&b, bytes.TrimSpace(raw), "", "  ")
	if err != nil {
		return err
	}

	b.WriteByte('\n')

	_, err = w.Write(table.VisibleJSON(b.Bytes()))

	return err
}

// usageError is a mistake on the command line, in the CLI's words. Its
// kind, path and word name the mistake as data, for the tests that hold
// the rules of the line.
type usageError struct {
	text string
	kind cmdline.Kind
	path []string
	// word is what the sentence names: the command word, the flag as
	// typed, --flag or <arg>, or for a count what the command takes.
	word string
	// empty is an empty list argument, which a command's hint follows.
	empty bool
}

func (e *usageError) Error() string { return e.text }

// versionNotAlone is the builder's own kind: --version with another flag.
const versionNotAlone cmdline.Kind = -1

func usagef(kind cmdline.Kind, path []string, word, format string, a ...any) error {
	return &usageError{
		text: fmt.Sprintf(format, a...),
		kind: kind,
		path: path,
		word: word,
	}
}

// mistake returns the leftmost mistake on the line: the parser's, or one
// of the builder's own. Its own are a flag that the group reached does not
// take, and --version with another flag, placed at the second of the two.
// In one word a flag that is not taken comes before the parser's mistake,
// and --version not alone after it. A wrong argument count is no mistake
// here: it yields to --help, so run reports it.
func (t *Tree) mistake(line *cmdline.Line, ue *cmdline.UsageError) error {
	var first error

	at := math.MaxInt
	if ue != nil && ue.Kind != cmdline.ArgCount {
		first, at = t.usage(ue), ue.At
	}

	found := func(err error, pos int, wins bool) {
		if pos < at || pos == at && wins {
			first, at = err, pos
		}
	}

	group := len(line.Command.Commands) > 0
	version, others := -1, 0

	for _, g := range line.Flags {
		own := slices.ContainsFunc(
			line.Command.Flags,
			func(f cmdline.Flag) bool { return f.Name == g.Name },
		)

		switch {
		// -o and -c may stand before the subcommand, also on a line that
		// ends at a group.
		case group && !own && g.Name != "output" && g.Name != "config":
			found(t.unknownFlag(line.Command.Path, "--"+g.Name), g.At, true)
		case g.Name == "version" && g.Value == "true" && others > 0,
			g.Name != "version" && version >= 0:
			found(
				usagef(
					versionNotAlone,
					line.Command.Path,
					"--version",
					"--version takes no other flag.",
				),
				g.At,
				false,
			)
		}

		if g.Name == "version" && g.Value == "true" {
			version = g.At
		} else if g.Name != "version" {
			others++
		}
	}

	if l := t.leaves[strings.Join(line.Command.Path, " ")]; l != nil && l.list {
		pos, err := l.checkList(line, t.line(line.Command.Path))
		if err != nil {
			found(err, pos, false)
		}
	}

	return first
}

// usage writes the sentence of a mistake that the parser found, from its
// fields; the parser's own text is never shown.
func (t *Tree) usage(e *cmdline.UsageError) error {
	what := e.Word

	switch {
	case e.Flag != "":
		what = "--" + e.Flag
	case e.Arg != "":
		what = "<" + e.Arg + ">"
	}

	switch e.Kind { //nolint:exhaustive // a bad value of either kind follows
	case cmdline.UnknownCommand:
		return t.unknownCommand(e.Path, e.Word)
	case cmdline.UnknownFlag:
		return t.unknownFlag(e.Path, e.Word)
	case cmdline.MissingValue:
		return usagef(
			e.Kind,
			e.Path,
			what,
			"%s needs a value.\nRun `%s --help`.",
			what,
			t.line(e.Path),
		)
	case cmdline.Repeated:
		return usagef(
			e.Kind,
			e.Path,
			what,
			"%s is given twice. Only --filter may be repeated.",
			what,
		)
	case cmdline.ArgCount:
		return usagef(e.Kind, e.Path, what, "wrong argument count.")
	}

	name := strings.TrimSuffix(cmp.Or(e.Flag, e.Arg), "s")

	switch {
	case errors.Is(e.Err, cmdline.ErrBool):
		return usagef(
			e.Kind,
			e.Path,
			what,
			"%s takes true or false, not %q.",
			what,
			e.Value,
		)
	case errors.Is(e.Err, cmdline.ErrEmpty):
		text := "the " + name + " list is empty."
		if l := t.leaves[strings.Join(e.Path, " ")]; l != nil && l.emptyList != "" &&
			e.Arg != "" {
			text += " " + l.emptyList
		}

		return &usageError{
			text:  text,
			kind:  e.Kind,
			path:  e.Path,
			word:  what,
			empty: e.Arg != "",
		}
	case errors.Is(e.Err, cmdline.ErrEmptyItem):
		return usagef(e.Kind, e.Path, what, "the %s list has an empty item.", name)
	}

	return usagef(
		e.Kind,
		e.Path,
		what,
		"%q is not a valid %s: %v.",
		e.Value,
		what,
		e.Err,
	)
}

// line is the command line of path, with the program name.
func (t *Tree) line(path []string) string {
	return strings.Join(append([]string{t.name}, path...), " ")
}

// quoted names a command in backquotes: its path, or the program for the
// root.
func (t *Tree) quoted(path []string) string {
	if len(path) == 0 {
		return "`" + t.name + "`"
	}

	return "`" + strings.Join(path, " ") + "`"
}

func (t *Tree) unknownCommand(path []string, word string) error {
	typed := strings.Join(append(slices.Clone(path), word), " ")

	if now, ok := t.oldNames[typed]; ok {
		return usagef(
			cmdline.UnknownCommand,
			path,
			word,
			"unknown command %q. It is now %q.\nRun `%s --help`.",
			typed,
			now,
			t.line(strings.Fields(now)),
		)
	}

	var names []string

	if g, ok := t.groups[strings.Join(path, " ")]; ok {
		for _, c := range g.Commands {
			names = append(names, nameOf(c))
		}
	} else {
		for _, c := range t.parser.Root().Commands {
			names = append(names, c.Name)
		}
	}

	if best := table.Closest(word, names); best != "" {
		return usagef(
			cmdline.UnknownCommand,
			path,
			word,
			"unknown command %q. Did you mean %q?\nRun `%s --help`.",
			typed,
			strings.Join(append(slices.Clone(path), best), " "),
			t.line(path),
		)
	}

	return usagef(
		cmdline.UnknownCommand,
		path,
		word,
		"unknown command %q.\nRun `%s --help`.",
		typed,
		t.line(path),
	)
}

func (t *Tree) unknownFlag(path []string, word string) error {
	if long, ok := t.spellings[word]; ok {
		return usagef(
			cmdline.UnknownFlag,
			path,
			word,
			"%s does not apply to %s.\nRun `%s --help`.",
			long,
			t.quoted(path),
			t.line(path),
		)
	}

	return usagef(
		cmdline.UnknownFlag,
		path,
		word,
		"unknown flag %s for %s.\nRun `%s --help`.",
		word,
		t.quoted(path),
		t.line(path),
	)
}

// countError is the sentence of a wrong argument count, with the usage
// line, from the command's arguments as data.
func countError(line *cmdline.Line) error {
	args, n := line.Command.Args, len(line.Args)

	need := slices.IndexFunc(args, func(a cmdline.Arg) bool { return a.Optional })
	if need < 0 {
		need = len(args)
	}

	plural := func(n int) string {
		if n == 1 {
			return "1 argument"
		}

		return strconv.Itoa(n) + " arguments"
	}

	var what string

	switch {
	case len(args) == 0:
		what = "takes no arguments"
	case need == len(args):
		what = "needs " + plural(need)
	case n > len(args):
		what = "takes at most " + plural(len(args))
	default:
		what = "needs at least " + plural(need)
	}

	return usagef(
		cmdline.ArgCount,
		line.Command.Path,
		fmt.Sprintf("%s, got %d", what, n),
		"`%s` %s, got %d.\n\n  %s",
		strings.Join(line.Command.Path, " "),
		what,
		n,
		line.Command.Usage,
	)
}
