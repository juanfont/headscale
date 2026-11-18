package diff

import (
	"regexp"

	"slices"
	"spike/diff/ownfix"
	grammar "spike/own-grammar"
	"strconv"
	"strings"

	"spike/kit"
)

// Severity: semantic (both accept, different result), acceptance (one
// accepts, one refuses), report (both refuse, differently).
func Severity(a, b string) string {
	switch {
	case a == b:
		return "same"
	case accepts(a) && accepts(b):
		return "semantic"
	case accepts(a) != accepts(b):
		return "acceptance"
	}
	return "report"
}

func accepts(o string) bool { k := Kind(o); return k == "run" || k == "help" || k == "version" }

// Parsed is an outcome string taken apart.
type Parsed struct {
	Kind string
	Path []string
	Word string
	Text string
}

var errRe = regexp.MustCompile(`^(\S+) \[(.*?)\] (".*")$`)

func Parse(o string) Parsed {
	p := Parsed{Kind: Kind(o), Text: o}
	if m := errRe.FindStringSubmatch(o); m != nil {
		p.Path = strings.Fields(m[2])
		p.Word, _ = strconv.Unquote(m[3])
		return p
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(o, p.Kind), " ")
	for _, w := range strings.Fields(rest) {
		if strings.HasPrefix(w, "[") {
			break
		}
		p.Path = append(p.Path, w)
	}
	return p
}

func (p Parsed) err() bool { return !accepts(p.Text) }

// Cause is one bucket of the taxonomy. Class is what the maintainer reads:
// decided (a decision says so; named), unwanted (pflag or cobra behaviour
// nobody would want), harness (an adapter's own code, not the parser under
// test), layer (the kit's Exec, i.e. 001's builder), bug (own-grammar),
// undecided (a question), report (both refuse; only the error named differs).
type Cause struct {
	Name, Class string
	When        func(c *Case) bool
}

// Case is one shrunk difference: A is the own side (grammar, or own-pflag on
// pflag~cobra), B the other.
type Case struct {
	Pair string
	Argv []string
	A, B Parsed
	t    *kit.Tree
}

func (c *Case) has(f func(string) bool) bool { return slices.ContainsFunc(c.Argv, f) }

func (c *Case) other(s string) bool { return strings.HasSuffix(c.Pair, "~"+s) }

func (c *Case) short(letter byte) bool {
	for _, cmd := range c.t.Commands {
		for _, f := range cmd.Flags {
			if f.Short == string(letter) {
				return true
			}
		}
	}
	return false
}

// attached: -ojson, -hc, -c- (a known short with more after it, not "=").
func (c *Case) attached(w string) bool {
	return len(w) >= 3 && w[0] == '-' && w[1] != '-' && w[2] != '=' && c.short(w[1])
}

func isHelp(w string) bool {
	n, _, _ := strings.Cut(w, "=")
	return n == "-h" || n == "--help"
}

// ranOrCount: Exec missed the help flag and went on to run or count arguments.
func ranOrCount(p Parsed) bool {
	return p.Kind == "run" || p.Kind == "arg-count" || p.Kind == "version"
}

func leafPath(t *kit.Tree, p []string) bool { c := find(t, p); return c != nil && c.Leaf }

// RunCauses is ordered: the first that fits names the bucket.
var RunCauses = []Cause{
	{"cobra adapter: pflag's InvalidSyntaxError (`--=`, `---x`) is not mapped to a usage error", "harness", func(c *Case) bool {
		return strings.Contains(c.B.Text, "bad flag syntax")
	}},
	{"cobra adapter: `--help=` / `--help=x` make cobra print \"flag declared as non-bool\" to stdout (cobra reads help back through Value.String)", "harness", func(c *Case) bool {
		return strings.Contains(c.B.Text, "declared as non-bool")
	}},
	{"layer: `--help=1` / `-h=T` runs the command; Exec looks for the text \"true\" before it parses the bool", "layer", func(c *Case) bool {
		return c.has(func(w string) bool {
			_, v, ok := strings.Cut(w, "=")
			b, err := strconv.ParseBool(v)
			return isHelp(w) && ok && err == nil && b && v != "true"
		}) && (c.A.Kind == "help" && ranOrCount(c.B) || c.B.Kind == "help" && ranOrCount(c.A))
	}},
	{"own-pflag pre-scan skips words with `=`: `-oname=` reaches pflag and is read as `-o` with value `name=`", "harness", func(c *Case) bool {
		return c.other("pflag") && c.has(func(w string) bool { return c.attached(w) && strings.Contains(w, "=") }) && c.B.Kind != "unknown-flag"
	}},
	{"Go's flag package: `--h` is `-h` and `-help` is `--help` (no long/short split; referee open question 4)", "undecided", func(c *Case) bool {
		return c.other("stdflag") && c.has(func(w string) bool {
			n, _, _ := strings.Cut(w, "=")
			return len(n) == 3 && strings.HasPrefix(n, "--") && c.short(n[2]) || len(n) > 2 && n[0] == '-' && n[1] != '-' && hasLong(c.t, n[1:])
		})
	}},
	{"pflag reads `-o=` as `-o` with the value `=`, and `-h=` as `-h` then an unknown shorthand `=`", "unwanted", func(c *Case) bool {
		return c.has(func(w string) bool { return len(w) == 3 && w[0] == '-' && w[2] == '=' && w[1] != '-' })
	}},
	{"attached value or grouped shorts (`-ojson`, `-hc`, `-c-`, `-output`): own refuses, pflag reads a value or a group", "decided D11", func(c *Case) bool {
		return c.has(c.attached)
	}},
	{"`-h` with a mistake: the error wins; cobra shows help", "decided D19", func(c *Case) bool {
		return c.has(isHelp) && c.A.err() && c.B.Kind == "help"
	}},
	{"cobra takes a leaf's own flags before or between the command words (only -c/-o may come there)", "decided D3", func(c *Case) bool {
		return c.A.Kind == "unknown-flag" && !leafPath(c.t, c.A.Path) && len(c.B.Path) > len(c.A.Path) && c.B.Kind != "unknown-flag"
	}},
	{"`--` before the command is complete: own says unknown command `--`; cobra drops it and reads on (`nodes --` is help, `-- nodes list` unknown command `nodes`)", "undecided", func(c *Case) bool {
		return c.has(func(w string) bool { return w == "--" }) && !leafPath(c.t, c.A.Path)
	}},
	{"cobra's command search skips `-`, `` and flag-like words (`- nodes` → unknown `-` under nodes; `nodes - list` runs list with `-`)", "unwanted", func(c *Case) bool {
		return c.A.err() && !leafPath(c.t, c.A.Path) && len(c.B.Path) > len(c.A.Path)
	}},
	{"cobra's command search takes the word after an unknown flag as its value (`nodes --version routes -h` is help for nodes)", "unwanted", func(c *Case) bool {
		return c.A.Kind == "help" && c.B.Kind == "help" && len(c.B.Path) < len(c.A.Path)
	}},
	{"layer: Exec lets `-h` win over a root-only flag on a group (`api --version -h` is help; D19 says the error wins, cobra refuses)", "layer", func(c *Case) bool {
		return c.has(isHelp) && c.A.Kind == "help" && len(c.A.Path) > 0 && !leafPath(c.t, c.A.Path) && c.B.Kind == "unknown-flag"
	}},
	{"cobra's command search reads the value of an inherited flag as a command word (`--version api --config keys --help` is help for api keys)", "unwanted", func(c *Case) bool {
		return c.A.Kind == "help" && c.B.Kind == "help" && len(c.B.Path) > len(c.A.Path)
	}},
	{"own drops flags read before a group word when the line ends at a group (`--version nodes` is help, cobra: unknown flag)", "bug", func(c *Case) bool {
		grp := func(p Parsed) bool { return p.Kind == "help" && len(p.Path) > 0 && !leafPath(c.t, p.Path) }
		return grp(c.A) && c.B.err() || c.other("pflag") && grp(c.B) && c.A.Kind == "unknown-flag"
	}},
	{"cobra adapter: unknown flags at a group go to its args (for D5), so the unknown command is named instead of the flag", "harness", func(c *Case) bool {
		return c.other("cobra") && c.A.Kind == "unknown-flag" && c.B.Kind == "unknown-command" && !leafPath(c.t, c.A.Path)
	}},
	{"same wrong word, spelled differently: pflag names one letter of a short group (`-12` → `-1`) or decodes a byte as a rune (`-\\xc3` → `Ã`)", "report", func(c *Case) bool {
		return c.A.Kind == c.B.Kind && slices.Equal(c.A.Path, c.B.Path) && c.sameToken()
	}},
	{"own-pflag adapter: its pre-scan refuses a later single-dash word (`-last-se`) before pflag reaches an earlier mistake", "harness", func(c *Case) bool {
		if !c.other("pflag") || !c.A.err() || c.B.Kind != "unknown-flag" {
			return false
		}
		i := slices.IndexFunc(c.Argv, func(w string) bool { return len(w) > 2 && w[0] == '-' && w[1] != '-' && strings.Contains(w, c.B.Word) })
		return i > 0
	}},
	{"two mistakes on the line, each side names a different one first", "report", func(c *Case) bool {
		return c.A.err() && c.B.err()
	}},
}

// sameToken: both error words come from one dashed argv word.
func (c *Case) sameToken() bool {
	for _, w := range c.Argv {
		if !strings.HasPrefix(w, "-") {
			continue
		}
		n, _, _ := strings.Cut(strings.TrimLeft(w, "-"), "=")
		in := func(x string) bool {
			if x == "" || n == "" {
				return x == n
			}
			r := []rune(x)
			return strings.Contains(n, x) || c.t.Long(w) == x || len(r) == 1 && r[0] == rune(n[0])
		}
		if in(c.A.Word) && in(c.B.Word) {
			return true
		}
	}
	return false
}

var tree = kit.NewTree()

// Classify names the cause of a shrunk difference, "" when no rule fits.
func Classify(mode, pair string, argv []string, a, b string) string {
	if mode != "run" {
		return classifyTab(pair, argv, a, b)
	}
	c := &Case{Pair: pair, Argv: argv, A: Parse(a), B: Parse(b), t: tree}
	for _, r := range RunCauses {
		if r.When(c) {
			return r.Class + ": " + r.Name
		}
	}
	return ""
}

// TabOut is a Tab answer taken apart.
type TabOut struct {
	Words []string
	Files bool
}

var quoted = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

func ParseTab(o string) TabOut {
	var t TabOut
	list, _, _ := strings.Cut(o, "]")
	for _, m := range quoted.FindAllString(list, -1) {
		w, _ := strconv.Unquote(m)
		t.Words = append(t.Words, w)
	}
	t.Files = strings.Contains(o, "+files")
	return t
}

// TabCase is one shrunk Tab difference; Cur is the word under the cursor.
type TabCase struct {
	Pair  string
	Words []string
	Cur   string
	A, B  TabOut
	Atext string
	Btext string
	t     *kit.Tree
}

func (c *TabCase) onlyB() []string {
	var x []string
	for _, w := range c.B.Words {
		if !slices.Contains(c.A.Words, w) {
			x = append(x, w)
		}
	}
	return x
}

func (c *TabCase) onlyA() []string {
	var x []string
	for _, w := range c.A.Words {
		if !slices.Contains(c.B.Words, w) {
			x = append(x, w)
		}
	}
	return x
}

func (c *TabCase) has(f func(string) bool) bool { return slices.ContainsFunc(c.Words, f) }

func all(xs []string, f func(string) bool) bool {
	return len(xs) > 0 && !slices.ContainsFunc(xs, func(x string) bool { return !f(x) })
}

// given: the flag (by long name) appears among the words before the cursor.
func (c *TabCase) given(long string) bool {
	name := strings.TrimPrefix(long, "--")
	return c.has(func(w string) bool { return strings.HasPrefix(w, "-") && w != "--" && c.t.Long(w) == name })
}

// tabWord explains one word that only one side offers; "" when no rule does.
func (c *TabCase) tabWord(w string, onlyCobra bool) string {
	dashCur := strings.HasPrefix(c.Cur, "-")
	switch {
	case onlyCobra && dashCur && len(w) == 2 && w[0] == '-':
		return "undecided: cobra also lists short forms (`-c -h -o`) for a lone `-`; own lists long names only"
	case !onlyCobra && w == "--filter" && c.given(w):
		return "harness: cobra adapter hides --filter once given; it may repeat (D6) but its Value type is not a slice"
	case (!onlyCobra || strings.HasSuffix(c.Pair, "~pflag")) && strings.HasPrefix(w, "--") && c.given(w) && !c.refused():
		return "bug: own offers flags already on the line; cobra leaves them out (D15: each flag once)"
	case !onlyCobra && (w == "--config" || w == "--output" || w == "-c" || w == "-o") && dashCur:
		return "harness: cobra adapter: -c/-o are hidden persistent flags on the root and groups, so `-<Tab>` there offers only --help/--version"
	}
	return ""
}

var TabCauses = []struct {
	Name, Class string
	When        func(c *TabCase) bool
}{
	{"cobra gives nothing once -h/--help/--version is on the line; own completes as usual", "undecided", func(c *TabCase) bool {
		return c.has(func(w string) bool { return isHelp(w) || strings.HasPrefix(w, "--version") }) && len(c.B.Words) == 0 && len(c.A.Words) > 0 && !c.refused()
	}},
	{"malformed flag under the cursor (`--=`, `-=`): cobra completes as if it were empty", "unwanted", func(c *TabCase) bool {
		return strings.HasPrefix(c.Cur, "--=") || strings.HasPrefix(c.Cur, "-=")
	}},
	{"own's Tab reads the previous word as a flag without parsing: a flag-like value (`-c -o <Tab>`, D20), a word after `--`, or an empty word (`nodes ls '' <Tab>`) make it offer flag values", "bug", func(c *TabCase) bool {
		argv := append(slices.Clone(c.Words), c.Cur)
		fixed := Tab(Judge, argv)
		buggy := c.Atext == Tab(ownGrammar, argv) && fixed != c.Atext || strings.HasSuffix(c.Pair, "~pflag") && fixed == c.Atext && fixed != c.Btext
		return buggy && !c.offersGiven()
	}},
	{"cobra completes subcommands after `--` at a group (`nodes -- de<Tab>` → delete), which its own Run then refuses as unknown command", "unwanted", func(c *TabCase) bool {
		return c.has(func(w string) bool { return w == "--" }) && len(c.B.Words) > 0 && len(c.A.Words) == 0
	}},
	{"attached value or grouped shorts earlier on the line (D11): pflag reads them, own refuses, so the two complete from different places", "decided D11", func(c *TabCase) bool {
		return c.has(func(w string) bool {
			return len(w) >= 3 && w[0] == '-' && w[1] != '-' && w[2] != '=' && (&Case{t: c.t}).short(w[1])
		})
	}},
	{"pflag's `-x=` quirk earlier on the line (`-h=`, `-o=`)", "unwanted", func(c *TabCase) bool {
		return c.has(func(w string) bool { return len(w) == 3 && w[0] == '-' && w[2] == '=' && w[1] != '-' })
	}},
	{"cobra's Tab path reads a flag-like value of a value flag as flags (`-o -last-se api <Tab>`: 'api does not support flag e'); its Run reads it as the value (D20), so Tab and Run disagree (#2243 family)", "unwanted", func(c *TabCase) bool {
		for i := 0; i+1 < len(c.Words); i++ {
			w, v := c.Words[i], c.Words[i+1]
			if strings.HasPrefix(w, "-") && !strings.Contains(w, "=") && strings.HasPrefix(v, "-") && valueFlag(c.t, w) {
				return !c.refused() && c.B.Files && len(c.B.Words) == 0
			}
		}
		return false
	}},
	{"a refused word earlier on the line (unknown flag or command): cobra offers files (its parse error returns the Default directive) or skips the word; own completes from the last good command", "undecided", func(c *TabCase) bool {
		return c.refused()
	}},
	{"cobra adapter completes a positional's value list as a comma list (`completion id,<Tab>` → `id,bash`)", "harness", func(c *TabCase) bool {
		return strings.Contains(c.Cur, ",") && len(c.A.Words) == 0 && all(c.B.Words, func(w string) bool { return strings.Contains(w, ",") })
	}},
	{"a flag value with no value list (`--config <Tab>`, `--name <Tab>`): cobra offers files, own nothing", "undecided", func(c *TabCase) bool {
		return c.B.Files && !c.A.Files && slices.Equal(c.A.Words, c.B.Words)
	}},
	{"cobra adapter: its #2243 workaround (`--x -<Tab>` → `--x=-`) does not reach the root's persistent -o, so `headscale -o -<Tab>` gives files", "harness", func(c *TabCase) bool {
		return strings.HasPrefix(c.Cur, "-") && len(c.Words) == 1 && all(c.onlyA(), func(w string) bool { return !strings.HasPrefix(w, "--") })
	}},
}

// refused: a word before the cursor that the own parser refuses as an
// unknown flag or command, judged by running the words through Run.
func (c *TabCase) refused() bool {
	o := Parse(Outcome(Judge, c.Words))
	return o.Kind == "unknown-flag" || o.Kind == "unknown-command" || o.Kind == "bad-value"
}

func classifyTab(pair string, argv []string, a, b string) string {
	if len(argv) == 0 {
		return ""
	}
	c := &TabCase{Pair: pair, Words: argv[:len(argv)-1], Cur: argv[len(argv)-1], A: ParseTab(a), B: ParseTab(b), Atext: a, Btext: b, t: tree}
	for _, r := range TabCauses {
		if r.When(c) {
			return r.Class + ": " + r.Name
		}
	}
	// Word by word: every word only one side offers must be explained.
	var why []string
	for _, side := range []struct {
		ws    []string
		cobra bool
	}{{c.onlyA(), false}, {c.onlyB(), true}} {
		for _, w := range side.ws {
			r := c.tabWord(w, side.cobra)
			if r == "" {
				return ""
			}
			if !slices.Contains(why, r) {
				why = append(why, r)
			}
		}
	}
	if len(why) == 0 || c.A.Files != c.B.Files {
		return ""
	}
	slices.Sort(why)
	return strings.Join(why, " + ")
}

func hasLong(t *kit.Tree, name string) bool {
	for _, c := range t.Commands {
		for _, f := range c.Flags {
			if f.Name == name {
				return true
			}
		}
	}
	return false
}

// TabDelta is what shrinking a Tab difference must keep: the words only one
// side offers and the file flags, so a line keeps its cause while it shrinks.
func TabDelta(a, b string) string {
	c := &TabCase{A: ParseTab(a), B: ParseTab(b)}
	x, y := c.onlyA(), c.onlyB()
	slices.Sort(x)
	slices.Sort(y)
	return strings.Join(x, " ") + " | " + strings.Join(y, " ") + " | " + strconv.FormatBool(c.A.Files) + strconv.FormatBool(c.B.Files)
}

// Judge decides whether a word before the cursor is refused: the own
// grammar with the fixes of this note (B1 changes what `--version nodes` means).
var Judge kit.Adapter = ownfix.Adapter{}

var ownGrammar kit.Adapter = grammar.Adapter{}

// offersGiven: the only difference the fixes make is fix B4 (flags already given).
func (c *TabCase) offersGiven() bool {
	argv := append(slices.Clone(c.Words), c.Cur)
	d := &TabCase{A: ParseTab(Tab(ownGrammar, argv)), B: ParseTab(Tab(Judge, argv)), Words: c.Words, t: c.t}
	return len(d.onlyB()) == 0 && all(d.onlyA(), d.given)
}

// valueFlag: w names a flag that takes a value somewhere in the tree.
func valueFlag(t *kit.Tree, w string) bool {
	name := t.Long(w)
	for _, c := range t.Commands {
		for _, f := range c.Flags {
			if f.Name == name {
				return f.Kind != kit.Bool
			}
		}
	}
	return false
}
