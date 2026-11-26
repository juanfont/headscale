package command

import (
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

	if t.parser.Serve(env.Stdout, argv) {
		return 0
	}

	err := t.run(argv, env)
	if err == nil {
		return 0
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

// run is the builder: the steps of every command, in one order.
func (t *Tree) run(argv []string, env Env) error {
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
	case stepRun:
	}

	l := t.leaves[strings.Join(line.Command.Path, " ")]
	output, _ := cmdline.Get[outputFlags](line)
	own, _ := cmdline.Get[ownOutputFlags](line)
	file, _ := cmdline.Get[configFlags](line)

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
		stderr:   env.Stderr,
		Environ:  env.Environ,
		terminal: env.Terminal,
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
		return line, stepRun, err
	}

	help, _ := cmdline.Get[helpFlags](line)
	version, _ := cmdline.Get[versionFlags](line)

	switch {
	case help.Help, len(line.Command.Commands) > 0 && !version.Version:
		return line, stepHelp, nil
	case version.Version:
		return line, stepVersion, nil
	case ue != nil:
		return line, stepRun, countError(line)
	}

	return line, stepRun, nil
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
		return writeJSON(c.stdout, raw)
	}

	if text := done(); text != "" {
		return writeText(c.stdout, text)
	}

	return table.Sheet(c.stdout, out, cols, c.Now())
}

// printList prints the rows of a ListSpec: the array of their bodies as
// they came, in the order of rows, or a table.
func printList[Row any](c *run, rows []Row, cols table.Columns[Row]) error {
	raws := make([][]byte, 0, len(rows))

	for _, r := range rows {
		raw, err := jsonOf(c, r)
		if err != nil {
			return err
		}

		raws = append(raws, raw)
	}

	if !c.json {
		return table.Render(c.stdout, rows, cols, c.Now())
	}

	return writeJSON(
		c.stdout,
		append(append([]byte("["), bytes.Join(raws, []byte(","))...), ']'),
	)
}

// writeText writes the Done text, ending in one newline.
func writeText(w io.Writer, text string) error {
	if text == "" {
		return nil
	}

	_, err := fmt.Fprintln(w, strings.TrimSuffix(text, "\n"))

	return err
}

// writeJSON writes raw indented.
func writeJSON(w io.Writer, raw json.RawMessage) error {
	var b bytes.Buffer

	err := json.Indent(&b, bytes.TrimSpace(raw), "", "  ")
	if err != nil {
		return err
	}

	b.WriteByte('\n')

	_, err = b.WriteTo(w)

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
		return usagef(e.Kind, e.Path, what, "the %s list is empty.", name)
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

	if best := closest(word, names); best != "" {
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

// closest is the name nearest to word, within two edits, for "Did you
// mean"; "" when none is that near.
func closest(word string, names []string) string {
	best, dist := "", 3

	for _, n := range names {
		if d := distance(word, n); d < dist {
			best, dist = n, d
		}
	}

	return best
}

// distance is the Levenshtein distance of a and b.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := range len(a) {
		cur := make([]int, len(b)+1)
		cur[0] = i + 1

		for j := range len(b) {
			cost := 1
			if a[i] == b[j] {
				cost = 0
			}

			cur[j+1] = min(prev[j+1]+1, cur[j]+1, prev[j]+cost)
		}

		prev = cur
	}

	return prev[len(b)]
}

// errorOf is err as the program says an error of its session.
func (c *run) errorOf(err error) error { return c.tree.prog.Error(c.api, err) }
