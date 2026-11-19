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

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
)

// Run runs one command line, argv without the program name, and returns
// the exit code. The hidden completion entry point is answered before
// anything else, so Tab reads no config and calls no server.
func Run(t *Tree, argv []string, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}

	if env.Version == nil {
		env.Version = types.GetVersionInfo()
	}

	var tab strings.Builder
	if t.parser.Serve(&tab, argv) {
		_, _ = io.WriteString(env.Stdout, t.columnNames(argv, tab.String()))

		return 0
	}

	err := t.run(argv, env)
	if err == nil {
		return 0
	}

	fmt.Fprintf(env.Stderr, "Error: %s\n", sentence(err))

	return 1
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

	if v, ok := errors.AsType[*versionError](err); ok {
		return v.Error()
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
		_, err := fmt.Fprintln(env.Stdout, versionLine(env.Version))

		return err
	case stepColumns:
		output, _ := cmdline.Get[outputFlags](line)

		return listColumns(env.Stdout, t.leaves[strings.Join(line.Command.Path, " ")].info, output.Output != "")
	case stepRun:
	}

	l := t.leaves[strings.Join(line.Command.Path, " ")]
	output, _ := cmdline.Get[outputFlags](line)
	own, _ := cmdline.Get[ownOutputFlags](line)
	file, _ := cmdline.Get[configFlags](line)

	c := &Ctx{
		Context:    context.Background(),
		ConfigFile: cmp.Or(string(file.Config), getenv(env.Environ, "HEADSCALE_CONFIG")),
		stdin:      env.Stdin,
		stdout:     env.Stdout,
		stderr:     env.Stderr,
		Environ:    env.Environ,
		terminal:   env.Terminal,
		screen:     env.StdoutTerminal,
		line:       line,
		json:       output.Output != "" || own.Output != "",
		now:        env.Now,
		build:      env.Version,
		releases:   env.Releases,
	}

	// A file that is named and not there is a mistake, for every command
	// that takes one; finding none in the default places is not.
	if l.config && c.ConfigFile != "" {
		_, err := os.Stat(c.ConfigFile)
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("the config file %s does not exist.", c.ConfigFile) //nolint:err113,staticcheck // a sentence of the CLI
		}
	}

	ctx := context.Background()

	if l.server(line) {
		cfg, err := loadConfig(c.ConfigFile, env.Environ)
		if err != nil {
			return err
		}

		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, cfg.CLI.Timeout)
		defer cancel()

		c.API, err = connect(cfg, env)
		if err != nil {
			return err
		}
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
		return line, stepRun, err
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
		return line, stepRun, countError(line)
	}

	return line, stepRun, nil
}

type ctxKey struct{}

// ctxOf is the Ctx of the run, carrying the context that Line.Run gives.
func ctxOf(ctx context.Context) Ctx {
	c, _ := ctx.Value(ctxKey{}).(*Ctx)
	out := *c
	out.Context = ctx

	return out
}

// loadConfig loads what the CLI needs to reach the server. A missing file
// is normal: the defaults and the environment are enough, and no warning
// is printed, because a server command prints no log line.
func loadConfig(file string, environ []string) (*types.Config, error) {
	l, err := config.Load(file, file != "", environ)
	switch {
	case err != nil && l.File != "":
		return nil, fmt.Errorf("the config file %s cannot be read: %w", l.File, err)
	case err != nil:
		return nil, fmt.Errorf("the configuration cannot be read: %w", err)
	}

	return l.Config, nil
}

// getenv is the last value of name, as config.Load reads it.
func getenv(environ []string, name string) string {
	for _, kv := range slices.Backward(environ) {
		if v, ok := strings.CutPrefix(kv, name+"="); ok {
			return v
		}
	}

	return ""
}

// versionLine is what --version prints: the first line of `version`.
func versionLine(v *types.VersionInfo) string {
	line, _, _ := strings.Cut(v.String(), "\n")

	return line
}

// errNotAnswer is a Run of a server command that returns a value no answer
// of the server holds: one it made or changed. -o json prints an answer as
// it came and never encodes one again, so this is a fault of the command,
// found in every mode so that any test of it fails.
var errNotAnswer = errors.New("this command returned an object that the server did not send, so -o json cannot print it")

// jsonOf is the JSON of a result: the body that the server sent for it, or,
// on a line that talks to no server, the CLI's own object encoded.
func jsonOf(c Ctx, v any) (json.RawMessage, error) {
	if c.API == nil {
		return json.Marshal(v)
	}

	raw, ok := c.API.answerOf(v)
	if !ok {
		return nil, errNotAnswer
	}

	return raw, nil
}

// printOne prints the result of a Spec: JSON as the server sent it, the
// Done text, or a sheet.
func printOne[Out any](c Ctx, out Out, cols table.Columns[Out], done func() string) error {
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
// they came, in the order of rows, or a table. A table with no rows is the
// list's sentence on a terminal, and the header alone in a pipe.
func printList[Row any](c Ctx, rows []Row, cols table.Columns[Row], noRows string) error {
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
	case !c.json:
		return table.Render(c.stdout, rows, cols, c.Now())
	}

	return writeJSON(c.stdout, append(append([]byte("["), bytes.Join(raws, []byte(","))...), ']'))
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
	return &usageError{text: fmt.Sprintf(format, a...), kind: kind, path: path, word: word}
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
		own := slices.ContainsFunc(line.Command.Flags, func(f cmdline.Flag) bool { return f.Name == g.Name })

		switch {
		// -o and -c may stand before the subcommand, also on a line that
		// ends at a group.
		case group && !own && g.Name != "output" && g.Name != "config":
			found(t.unknownFlag(line.Command.Path, "--"+g.Name), g.At, true)
		case g.Name == "version" && g.Value == "true" && others > 0, g.Name != "version" && version >= 0:
			found(usagef(versionNotAlone, line.Command.Path, "--version", "--version takes no other flag."), g.At, false)
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
		return usagef(e.Kind, e.Path, what, "%s needs a value.\nRun `%s --help`.", what, t.line(e.Path))
	case cmdline.Repeated:
		return usagef(e.Kind, e.Path, what, "%s is given twice. Only --filter may be repeated.", what)
	case cmdline.ArgCount:
		return usagef(e.Kind, e.Path, what, "wrong argument count.")
	}

	name := strings.TrimSuffix(cmp.Or(e.Flag, e.Arg), "s")

	switch {
	case errors.Is(e.Err, cmdline.ErrBool):
		return usagef(e.Kind, e.Path, what, "%s takes true or false, not %q.", what, e.Value)
	case errors.Is(e.Err, cmdline.ErrEmpty):
		return usagef(e.Kind, e.Path, what, "the %s list is empty.", name)
	case errors.Is(e.Err, cmdline.ErrEmptyItem):
		return usagef(e.Kind, e.Path, what, "the %s list has an empty item.", name)
	}

	return usagef(e.Kind, e.Path, what, "%q is not a valid %s: %v.", e.Value, what, e.Err)
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
		return usagef(cmdline.UnknownCommand, path, word, "unknown command %q. It is now %q.\nRun `%s --help`.", typed, now, t.line(strings.Fields(now)))
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
		return usagef(cmdline.UnknownCommand, path, word, "unknown command %q. Did you mean %q?\nRun `%s --help`.",
			typed, strings.Join(append(slices.Clone(path), best), " "), t.line(path))
	}

	return usagef(cmdline.UnknownCommand, path, word, "unknown command %q.\nRun `%s --help`.", typed, t.line(path))
}

func (t *Tree) unknownFlag(path []string, word string) error {
	if long, ok := t.spellings[word]; ok {
		return usagef(cmdline.UnknownFlag, path, word, "%s does not apply to %s.\nRun `%s --help`.", long, t.quoted(path), t.line(path))
	}

	return usagef(cmdline.UnknownFlag, path, word, "unknown flag %s for %s.\nRun `%s --help`.", word, t.quoted(path), t.line(path))
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

	return usagef(cmdline.ArgCount, line.Command.Path, fmt.Sprintf("%s, got %d", what, n), "`%s` %s, got %d.\n\n  %s", strings.Join(line.Command.Path, " "), what, n, line.Command.Usage)
}
