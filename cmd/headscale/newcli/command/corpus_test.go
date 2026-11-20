package command

// Rows re-express behaviour recorded in the tests and trackers named in `src`.

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/stretchr/testify/require"
)

// The corpus carries what other parsers learnt into Headscale's tests: each
// row of testdata/corpus.jsonl is a case of an upstream test or issue,
// carried onto one of the trees below, with what the source expects and,
// where Headscale decided otherwise, what it decided. The rows run through
// the builder (check) and the completion entry point (Run with
// __complete), on trees whose values are text.

// text is free text that offers the words of W on Tab.
type text[W Words] string

func (t *text[W]) UnmarshalText(b []byte) error { *t = text[W](b); return nil }

func (text[W]) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	var w W

	return cmdline.Words(prefix, w.Words()...), cmdline.NoFiles
}

type (
	tagWords   struct{}
	shellWords struct{}
	abWords    struct{}
	xyzWords   struct{}
	oneTwo     struct{}
	svcWords   struct{}
	works      struct{}
)

// nodeRow is a node as the corpus's nodes list shows it: a stand-in for
// the corpus and the fuzz targets, which cannot import Headscale's tree.
// The kit runs on Headscale's own nodes list (KitModel).
type nodeRow struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Owner     clientv0.Owner `json:"owner"`
	Addresses []string       `json:"addresses"`
	Version   string         `json:"clientVersion"`
	Online    bool           `json:"connectedToControl"`
	LastSeen  time.Time      `json:"lastSeen"`
	Expiry    time.Time      `json:"expiry"`
	Hostname  string         `json:"hostname"`
}

var nodeColumns = table.Columns[nodeRow]{
	{Name: "id", Field: "id", Default: true, Help: "Node ID"},
	{Name: "name", Field: "name", Default: true, Help: "Name"},
	{Name: "owner", Field: "owner", Default: true, Help: "Owning user, or the tags"},
	{Name: "ip", Field: "addresses", Default: true, Help: "Tailnet IP addresses"},
	{Name: "version", Field: "clientVersion", Default: true, Kind: table.Version, Help: "Client version"},
	{Name: "online", Field: "connectedToControl", Default: true, Help: "Whether the node is connected"},
	{Name: "last-seen", Field: "lastSeen", Default: true, Help: "Time of last contact"},
	{Name: "expiry", Field: "expiry", Default: true, Ahead: true, Help: "When the node key expires"},
	{Name: "hostname", Field: "hostname", Help: "Hostname the node reports"},
}

func (tagWords) Words() []string   { return []string{"tag:ci", "tag:prod"} }
func (shellWords) Words() []string { return []string{"bash", "zsh", "fish", "powershell"} }
func (abWords) Words() []string    { return []string{"alpha", "beta"} }
func (xyzWords) Words() []string   { return []string{"x", "y", "z"} }
func (oneTwo) Words() []string     { return []string{"one", "two"} }
func (svcWords) Words() []string   { return []string{"service", "1-123", "11-123"} }
func (works) Words() []string      { return []string{"works"} }

// The kit's tree: the hard cases of the CLI proposal, thirteen commands.
type (
	nodesDeleteIn struct {
		Node string `arg:"node"`
	}
	nodesSetIn struct {
		Node   string      `arg:"node"`
		Name   Opt[string] `flag:"name"   help:"New name of the node"`
		Expiry Opt[string] `flag:"expiry" help:"New expiry of the node key" short:"e"`
	}
	routesSetIn struct {
		Node   string   `arg:"node"`
		Routes []string `arg:"routes"`
	}
	usersDeleteIn struct {
		User      string `arg:"user"`
		WithNodes bool   `flag:"with-nodes" help:"Delete the nodes of the user too"`
	}
	// The owner, a user or tags, is the one argument of auth keys create.
	authKeysCreateIn struct {
		Owner       string `arg:"owner"`
		Expiry      string `flag:"expiry"      help:"When the key ends"           short:"e"`
		Reusable    bool   `flag:"reusable"    help:"Let more than one node join"`
		Description string `flag:"description" help:"What the key is for"         short:"d"`
	}
	// --tags is the kit's list flag that cannot be repeated.
	oauthClientsCreateIn struct {
		Scopes      []string         `arg:"scopes"`
		Tags        []text[tagWords] `flag:"tags"        help:"Tags the client may give"`
		Description string           `flag:"description" help:"What the client is for"   short:"d"`
	}
	apiKeysCreateIn struct {
		User   string `flag:"user"   help:"Owner of the key"  short:"u"`
		Expiry string `flag:"expiry" help:"When the key ends" short:"e"`
	}
	policySetIn struct {
		File   Path `arg:"file"`
		DryRun bool `flag:"dry-run" help:"Check the policy, do not set it"`
	}
	checkConfigIn struct {
		File Opt[Path] `arg:"file"`
	}
	completionIn struct {
		Shell text[shellWords] `arg:"shell"`
	}
)

// The trees of single commands for the flag tables of pflag, urfave/cli, ff
// and cobra's completion tests.
type (
	pfIn struct {
		A       Opt[string]        `arg:"a"`
		B       Opt[string]        `arg:"b"`
		C       Opt[string]        `arg:"c"`
		Bool    bool               `flag:"bool"    help:"A bool"   short:"b"`
		Verbose bool               `flag:"verbose" help:"A bool"   short:"v"`
		String  Opt[text[abWords]] `flag:"string"  help:"A string" short:"s"`
		List    []text[xyzWords]   `flag:"list"    help:"A list"   short:"l"`
		File    string             `flag:"file"    help:"A string" short:"f"`
		// Filter stands in for a repeated flag of text, as pflag's
		// StringArray and Go's flag.Value are: it is no list's --filter.
		Filter cmdline.Repeat[[]string] `flag:"filter" help:"A repeated string"`
	}
	pfSubIn struct {
		A Opt[text[oneTwo]] `arg:"a"`
	}
	ccIn struct {
		A      Opt[text[svcWords]] `arg:"a"`
		B      Opt[text[svcWords]] `arg:"b"`
		C      Opt[text[svcWords]] `arg:"c"`
		Short  bool                `flag:"short"  help:"A bool"   short:"s"`
		Short2 bool                `flag:"short2" help:"A bool"   short:"d"`
		Short3 text[works]         `flag:"short3" help:"A string" short:"f"`
	}
	othersIn struct {
		A     Opt[string] `arg:"a"`
		B     Opt[string] `arg:"b"`
		C     Opt[string] `arg:"c"`
		D     Opt[string] `arg:"d"`
		E     Opt[string] `arg:"e"`
		Aflag bool        `flag:"aflag" help:"A bool"   short:"a"`
		Bflag bool        `flag:"bflag" help:"A bool"   short:"b"`
		Kflag bool        `flag:"kflag" help:"A bool"   short:"k"`
		Gflag bool        `flag:"gflag" help:"A bool"   short:"g"`
		Str   Opt[string] `flag:"str"   help:"A string" short:"s"`
		Ijk   string      `flag:"ijk"   help:"A string" short:"i"`
		Xxx   []string    `flag:"xxx"   help:"A list"   short:"x"`
	}
)

// cmd is a command of a test tree that is never run: the corpus and the
// kit stop where the builder would run it. server gives it --output and
// --config, as a command that calls the server has; config gives it only
// --config.
func cmd[In any](name, short string, server, config bool, aliases ...string) Node {
	return New(Spec[In, NoOutput]{
		Name: name, Short: short, Long: short + ".", Example: []string{name},
		Aliases: aliases, Local: !server, ReadsConfig: config,
		Run: func(Ctx, In) (NoOutput, error) { return NoOutput{}, errNotRun },
	})
}

// asking is a server command of a test tree that can ask, so it takes the
// builder's --force; like cmd it is never run.
func asking[In any](name, short string, aliases ...string) Node {
	return New(Spec[In, NoOutput]{
		Name: name, Short: short, Long: short + ".", Example: []string{name}, Aliases: aliases,
		Confirm: func(Ctx, In) (Prompt, error) { return Prompt{}, nil },
		Run:     func(Ctx, In) (NoOutput, error) { return NoOutput{}, errNotRun },
	})
}

// list is a list of a test tree, with the builder's list flags; like cmd
// it is never run.
func list[In, R any](name, short string, cols table.Columns[R], aliases ...string) Node {
	return NewList(ListSpec[In, R]{
		Name: name, Short: short, Long: short + ".", Example: []string{name},
		Aliases: aliases, Columns: cols, NoRows: "No rows.",
		Run: func(Ctx, In) ([]R, error) { return nil, errNotRun },
	})
}

var (
	errNotRun   = errors.New("the commands of a test tree do not run")
	errNoAnswer = errors.New("no completion answer")
)

func group(name, short string, nodes ...Node) Group {
	return Group{Name: name, Short: short, Commands: nodes}
}

// kitTree is the kit's tree of thirteen commands, with the nodes list given.
func kitTree(nodesList Node) []Node {
	return []Node{
		cmd[NoInput]("serve", "Run the control server", false, true),
		cmd[NoInput]("version", "Print the version", true, true),
		group("check", "Check files", cmd[checkConfigIn]("config", "Check a config file", false, true)),
		cmd[completionIn]("completion", "Print a shell completion script", false, false),
		group("nodes", "Manage nodes",
			nodesList,
			asking[nodesDeleteIn]("delete", "Delete a node", "rm"),
			cmd[nodesSetIn]("set", "Change the name or expiry of a node", true, true),
			group("routes", "Manage the routes of a node",
				cmd[routesSetIn]("set", "Replace the enabled routes of a node", true, true, "approve")),
		),
		group("users", "Manage users", asking[usersDeleteIn]("delete", "Delete a user", "rm")),
		group("auth", "Manage auth keys", group("keys", "Manage auth keys", cmd[authKeysCreateIn]("create", "Create an auth key", true, true))),
		group("api", "Manage API access",
			group("keys", "Manage API keys", cmd[apiKeysCreateIn]("create", "Create an API key", true, true)),
			group("oauth-clients", "Manage OAuth clients", cmd[oauthClientsCreateIn]("create", "Create an OAuth client", true, true)),
		),
		group("policy", "Manage the policy", asking[policySetIn]("set", "Replace the policy")),
	}
}

// testTrees are the trees of the corpus by name; "" is the kit's tree with
// the stand-in nodes list.
var testTrees = map[string][]Node{
	"": kitTree(list[NoInput]("list", "List the nodes", nodeColumns, "ls")),
	"pf": {
		cmd[pfIn]("run", "Run", true, true, "r", "go"),
		group("grp", "A group",
			cmd[pfSubIn]("sub", "Sub", false, false, "s"),
			cmd[pfSubIn]("grp", "Grp", false, false),
			cmd[NoInput]("other", "Other", false, false, "sub2"),
		),
	},
	"cc":     {cmd[ccIn]("pick", "Pick", false, false)},
	"others": {cmd[othersIn]("test", "Test", false, false)},
}

// corpusAliases are the aliases the trees of the corpus may use.
func corpusAliases() []string { return []string{"ls", "rm", "approve", "r", "go", "s", "sub2"} }

// corpusTree builds a tree of the corpus.
func corpusTree(tb testing.TB, name string) *Tree {
	tb.Helper()

	t, err := build("headscale", "Headscale control server", corpusAliases(), nil, testTrees[name]...)
	require.NoError(tb, err)

	return t
}

// result is what the builder makes of a line, as the corpus and the kit
// compare it.
type result struct {
	kind  string // run, help, version, or the kind of the mistake
	path  []string
	args  []string
	flags map[string][]string
	word  string
}

func (r result) String() string {
	p := strings.Join(r.path, " ")

	switch r.kind {
	case "run":
		var s strings.Builder

		s.WriteString("run " + p + " " + quote(r.args))

		for _, k := range slices.Sorted(maps.Keys(r.flags)) {
			s.WriteString(" " + k + "=" + quote(r.flags[k]))
		}

		return s.String()
	case "help":
		return strings.TrimSpace("help " + p)
	case "version":
		return "version"
	}

	return fmt.Sprintf("%s [%s] %q", r.kind, p, r.word)
}

func quote(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = fmt.Sprintf("%q", s)
	}

	return "[" + strings.Join(q, " ") + "]"
}

var kinds = map[cmdline.Kind]string{
	cmdline.UnknownCommand: "unknown-command",
	cmdline.UnknownFlag:    "unknown-flag",
	cmdline.MissingValue:   "missing-value",
	cmdline.Repeated:       "flag-repeated",
	cmdline.BadValue:       "bad-value",
	cmdline.Unresolved:     "bad-value",
	cmdline.ArgCount:       "arg-count",
	versionNotAlone:        "not-alone",
}

// outcome is what the builder makes of argv: the step it takes, or the
// mistake it reports. A command is not run.
func outcome(t *Tree, argv []string) result {
	line, step, err := t.check(slices.Clone(argv))

	var ue *usageError

	switch {
	case errors.As(err, &ue):
		r := result{kind: kinds[ue.kind], path: ue.path, word: ue.word}
		if ue.kind != cmdline.UnknownCommand && ue.kind != cmdline.ArgCount {
			r.word = t.long(ue.word)
		}

		return r
	case err != nil:
		return result{kind: "error: " + err.Error()}
	case step == stepHelp:
		return result{kind: "help", path: line.Command.Path}
	case step == stepVersion:
		return result{kind: "version"}
	}

	r := result{kind: "run", path: line.Command.Path, args: line.Args, flags: map[string][]string{}}
	for _, g := range line.Flags {
		r.flags[g.Name] = append(r.flags[g.Name], g.Value)
	}

	return r
}

// long turns "--exp=1", "-o", "<routes>" or "output" into a long name, as
// the rows name a flag or an argument.
func (t *Tree) long(word string) string {
	name, _, _ := strings.Cut(strings.TrimLeft(word, "-"), "=")
	name = strings.Trim(name, "<>")

	if len(name) != 1 {
		return name
	}

	var long string

	var walk func(*cmdline.Info)

	walk = func(c *cmdline.Info) {
		for _, f := range c.Flags {
			if f.Short == name {
				long = f.Name
			}
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return cmp.Or(long, name)
}

// tab is the answer of the completion entry point to argv, the last word
// being the cursor word: the words without help, sorted, and the
// directive.
func tab(t *Tree, argv []string) ([]string, cmdline.Directive, error) {
	var out bytes.Buffer

	code := Run(t, append([]string{"__complete"}, argv...), Env{Stdout: &out, Stderr: &out})
	if code != 0 {
		return nil, 0, fmt.Errorf("%w: exit %d: %s", errNoAnswer, code, out.String())
	}

	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")

	var dir cmdline.Directive

	_, err := fmt.Sscanf(lines[len(lines)-1], ":%d", &dir)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: no directive in %q", errNoAnswer, out.String())
	}

	words := []string{}

	for _, l := range lines[:len(lines)-1] {
		w, _, _ := strings.Cut(l, "\t")
		words = append(words, w)
	}

	slices.Sort(words)

	return words, dir, nil
}

// corpusCase is one line of the corpus.
type corpusCase struct {
	ID       string     `json:"id"`
	Src      string     `json:"src"`
	Lic      string     `json:"lic"`
	Kind     string     `json:"kind"`
	Topic    string     `json:"topic"`
	Upstream string     `json:"upstream"`
	Expect   string     `json:"expect"`
	Tree     string     `json:"tree"`
	Argv     []string   `json:"argv"`
	Want     *corpusOut `json:"want"`
	Ours     *corpusOut `json:"ours,omitempty"`
	Why      string     `json:"why,omitempty"`
	Note     string     `json:"note,omitempty"`
}

// corpusOut is an expected outcome. Run: kind is run, help, version or the
// kind of a mistake. Complete: kind "complete" and the fields below it.
type corpusOut struct {
	Kind  string              `json:"kind"`
	Path  string              `json:"path,omitempty"`
	Args  []string            `json:"args,omitempty"`
	Flags map[string][]string `json:"flags,omitempty"`
	Word  string              `json:"word,omitempty"`

	Has     []string `json:"has,omitempty"`
	Not     []string `json:"not,omitempty"`
	Exact   []string `json:"exact,omitempty"` // the whole list, any order; [] means none
	Files   *bool    `json:"files,omitempty"`
	NoSpace *bool    `json:"nospace,omitempty"`
}

// explained is every case that matches neither its source nor its own
// "ours", with the call that says why. A "neither" not listed here, or a
// listed case that is no longer "neither", fails the run.
var explained = map[string]string{
	"cobracmd-020":  "an empty list value is an error; the empty word is the <routes> list",
	"issues-060":    "an empty list value is an error; the empty word is the <routes> list",
	"others-187":    "an empty list value is an error (--filter '')",
	"pflag-041":     "an empty list value is an error (--list=)",
	"pflag-042":     "an empty list value is an error (--filter=); closes the corpus's 'undecided'",
	"cobracomp-004": "after a refused command word Tab completes from the last command understood",
	"cobracomp-050": "-sdf is refused, Tab goes on with the argument; the row's 'ours' predates that call",
	"issues-033":    "`--` where a command word is expected is refused, Tab goes on at the root",
	"others-123":    "`--` where a command word is expected is refused, Tab goes on at the root",
	"cobracomp-065": "--config is a path, Tab offers files",
	"cobracomp-066": "--config is a path, Tab offers files",
	"others-172":    "a free-text flag (--name) offers nothing, not files",
	"others-167":    "no Tab values for bools (--force=<Tab>)",
	"others-168":    "no Tab values for bools",
	"others-169":    "no Tab values for bools; TRUE is no bool word",
	"issues-023":    "`--` where a command word is expected is unknown command `--`",
	"issues-006":    "a word of 2+ bytes that starts with '-' is a flag word ('- h' is unknown flag)",
	"issues-041":    "bytes, not runes: an em dash is no '-', so '—-help' is an argument",
	"others-197":    "the library never strips quotes from the cursor word (--sort=\"<Tab> offers nothing)",
}

func readCorpus(tb testing.TB) []corpusCase {
	tb.Helper()

	f, err := os.Open("testdata/corpus.jsonl")
	require.NoError(tb, err)

	defer f.Close()

	var cases []corpusCase

	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)

	for sc.Scan() {
		dec := json.NewDecoder(strings.NewReader(sc.Text()))
		dec.DisallowUnknownFields()

		var c corpusCase
		require.NoError(tb, dec.Decode(&c), sc.Text())

		cases = append(cases, c)
	}

	require.NoError(tb, sc.Err())

	return cases
}

// golden compares got with the file at path, the record of every row of
// a test, so that a row that moves, a row that goes and a count that
// changes are a diff to read. HEADSCALE_UPDATE_GOLDEN=1 writes got there.
func golden(tb testing.TB, path, got string) {
	tb.Helper()

	if os.Getenv("HEADSCALE_UPDATE_GOLDEN") != "" {
		require.NoError(tb, os.WriteFile(path, []byte(got), 0o600))

		return
	}

	want, err := os.ReadFile(path)
	require.NoError(tb, err)

	if d := gocmp.Diff(strings.Split(string(want), "\n"), strings.Split(got, "\n")); d != "" {
		tb.Errorf("%s differs (-file +now); if the change is meant, HEADSCALE_UPDATE_GOLDEN=1 rewrites it and its diff is the review:\n%s", path, d)
	}
}

// validate says what is wrong with a case as data.
func validate(t *Tree, c corpusCase) string {
	if c.Kind != "run" && c.Kind != "complete" {
		return "kind must be run or complete"
	}

	if c.Src == "" || c.Lic == "" || c.Want == nil {
		return "src, lic and want are required"
	}

	if c.Ours != nil && c.Why == "" {
		return "ours needs why"
	}

	for _, o := range []*corpusOut{c.Want, c.Ours} {
		if o == nil {
			continue
		}

		if (c.Kind == "complete") != (o.Kind == "complete") {
			return "a complete case wants kind complete"
		}

		if o.Kind == "complete" {
			continue
		}

		if t.Reached(strings.Fields(o.Path)) != o.Path {
			return fmt.Sprintf("path %q not in tree %q", o.Path, c.Tree)
		}

		if !slices.Contains([]string{"run", "help", "version", "unknown-command", "unknown-flag", "missing-value", "flag-repeated", "bad-value", "arg-count"}, o.Kind) {
			return "unknown outcome kind " + o.Kind
		}
	}

	return ""
}

// render prints an expected run outcome as the result is printed.
func render(t *Tree, o *corpusOut) string {
	r := result{kind: o.Kind, path: strings.Fields(o.Path), args: o.Args, flags: o.Flags, word: o.Word}
	if r.flags == nil {
		r.flags = map[string][]string{}
	}

	switch o.Kind {
	case "arg-count":
		return fmt.Sprintf("arg-count [%s]", o.Path)
	case "unknown-command":
	default:
		r.word = t.long(o.Word)
	}

	return r.String()
}

// got is what the tree did with a case, in the form render prints, or a
// summary of a Tab answer.
func got(t *Tree, c corpusCase) string {
	if c.Kind == "run" {
		s := outcome(t, c.Argv).String()
		if strings.HasPrefix(s, "arg-count ") {
			s = s[:strings.Index(s, "]")+1]
		}

		return s
	}

	argv := c.Argv
	if len(argv) == 0 {
		argv = []string{""}
	}

	words, dir, err := tab(t, argv)
	if err != nil {
		return "error: " + err.Error()
	}

	return fmt.Sprintf("[%s] files=%v nospace=%v", strings.Join(words, " "), dir&cmdline.NoFiles == 0, dir&cmdline.NoSpace != 0)
}

func matches(t *Tree, got string, o *corpusOut) bool {
	if o.Kind != "complete" {
		return got == render(t, o)
	}

	if strings.HasPrefix(got, "error") {
		return false
	}

	list, rest, _ := strings.Cut(strings.TrimPrefix(got, "["), "] ")
	words := strings.Fields(list)

	for _, w := range o.Has {
		if !slices.Contains(words, w) {
			return false
		}
	}

	for _, w := range o.Not {
		if slices.Contains(words, w) {
			return false
		}
	}

	if o.Exact != nil && !slices.Equal(slices.Sorted(slices.Values(o.Exact)), words) {
		return false
	}

	if o.Files != nil && !strings.Contains(rest, fmt.Sprintf("files=%v", *o.Files)) {
		return false
	}

	if o.NoSpace != nil && !strings.Contains(rest, fmt.Sprintf("nospace=%v", *o.NoSpace)) {
		return false
	}

	return true
}

// verdict is "up" when the tree does what the source expects, "ours" when
// it does what Headscale decided instead, and "neither" otherwise.
func verdict(t *Tree, got string, c corpusCase) string {
	switch {
	case matches(t, got, c.Want):
		return "up"
	case c.Ours != nil && matches(t, got, c.Ours):
		return "ours"
	}

	return "neither"
}

func TestCorpus(t *testing.T) { //nolint:tparallel // the cases are counted in order
	t.Parallel()

	trees := map[string]*Tree{}
	for name := range testTrees {
		trees[name] = corpusTree(t, name)
	}

	cases := readCorpus(t)
	count := map[string]int{}
	ids := map[string]bool{}

	var record strings.Builder

	ran := 0

	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			require.False(t, ids[c.ID], "the id is used twice")

			ids[c.ID] = true

			tree, ok := trees[c.Tree]
			require.True(t, ok, "unknown tree %q", c.Tree)
			require.Empty(t, validate(tree, c))

			g := got(tree, c)
			v := verdict(tree, g, c)
			count[v]++
			ran++

			fmt.Fprintf(&record, "%s\t%s\t%s\n", c.ID, v, g)
			t.Logf("%s: %s", v, g)

			why, ok := explained[c.ID]
			switch {
			case v == "neither" && !ok:
				t.Errorf("matches neither its source nor the decision:\n got  %s\n want %+v\n ours %+v", g, c.Want, c.Ours)
			case v != "neither" && ok:
				t.Errorf("is %s now; take it out of explained (%s)", v, why)
			}
		})
	}

	sum := fmt.Sprintf("%d cases: up %d, ours %d, neither %d", len(cases), count["up"], count["ours"], count["neither"])
	t.Log(sum)

	// A run of some rows (-run) has nothing to compare.
	if ran == len(cases) {
		golden(t, "testdata/corpus-results.tsv", "# "+sum+"\n# id\tverdict\tanswer\n"+record.String())
	}
}

// The lists of the test trees are the builder's, with its list flags, and
// a command that asks takes the builder's --force: no input struct of a
// test tree declares its own. A new field of a spec fails here, so that the
// trees are checked against it.
func TestTestTreesUseTheBuilder(t *testing.T) {
	t.Parallel()

	tree, err := Build("prog", "Prog",
		NewList(ListSpec[NoInput, item]{
			Name: "list", Short: "List items", Long: "List items.", Example: []string{"prog list"},
			Columns: itemColumns, NoRows: "No items.", Run: noop[NoInput, []item],
		}),
		New(Spec[getIn, NoOutput]{
			Name: "delete", Short: "Delete an item", Long: "Delete an item.", Example: []string{"prog delete a"},
			Run: noop[getIn, NoOutput], Done: func(getIn, NoOutput, time.Time) string { return "" },
			Confirm: func(Ctx, getIn) (Prompt, error) { return Prompt{}, nil },
		}),
	)
	require.NoError(t, err)

	names := func(c int) []string {
		flags := tree.parser.Root().Commands[c].Flags

		out := make([]string, 0, len(flags))
		for _, f := range flags {
			out = append(out, f.Name)
		}

		return out
	}

	require.ElementsMatch(t, []string{"columns", "list-columns", "filter", "sort", "output", "config", "help"}, names(0),
		"the list flags changed: the lists of testTrees take them from the builder")
	require.ElementsMatch(t, []string{"count", "output", "config", "force", "help"}, names(1),
		"the builder gives a command that asks a flag of its own")

	for _, in := range []reflect.Type{reflect.TypeFor[nodesDeleteIn](), reflect.TypeFor[usersDeleteIn](), reflect.TypeFor[policySetIn]()} {
		for f := range in.Fields() {
			require.NotEqual(t, "force", f.Tag.Get("flag"), "%s declares --force: the builder gives it to a command with Confirm", in.Name())
		}
	}

	fields := func(typ reflect.Type) []string {
		var out []string
		for f := range typ.Fields() {
			out = append(out, f.Name)
		}

		return out
	}

	known := []string{"Name", "Short", "Long", "Example", "Aliases", "OldNames", "Local", "NeedsServer", "ReadsConfig", "NeedsChange", "Columns", "Blocks", "Confirm", "Hint", "EmptyList", "Valid", "NoRows", "Only", "Run", "Done", "Secret"}
	for _, typ := range []reflect.Type{reflect.TypeFor[Spec[NoInput, NoOutput]](), reflect.TypeFor[ListSpec[NoInput, item]]()} {
		require.Subset(t, known, fields(typ),
			"%s has a new field: if the test trees need it, give it to them; then add it here", typ.Name())
	}
}
