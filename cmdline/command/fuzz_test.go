package command

// Fuzz targets for the builder and Tab, on the kit's tree of the corpus.
// argv is the fuzz string split at NUL: a real argv word cannot hold one.
// Inputs that found bugs are kept in testdata/fuzz, so go test replays
// them.
//
//	go test -run '^$' -fuzz '^FuzzRun$' -fuzztime 2m ./cmd/headscale/newcli/command/

import (
	"errors"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmdline"
)

// The limits of an input, and of the time one line may take.
const (
	maxWords = 64
	maxBytes = 1 << 14
	slow     = time.Second
)

func argvOf(s string) []string { return strings.Split(s, "\x00") }

// readLine is the line as the parser read it, before the builder's own checks:
// the command reached, the flags given and the arguments.
type readLine struct {
	path  []string
	flags map[string][]string
	args  []string
	leaf  bool
}

func (c *readLine) String() string {
	if c == nil {
		return "<no line>"
	}

	var s strings.Builder

	s.WriteString(strings.Join(c.path, " ") + " " + quote(c.args))

	for _, k := range slices.Sorted(maps.Keys(c.flags)) {
		s.WriteString(" " + k + "=" + quote(c.flags[k]))
	}

	return s.String()
}

// probe runs argv through the builder, fails on a slow line, and returns
// the outcome and the line as the parser read it. The line is nil when
// the parser stopped before it read every word.
func probe(tb testing.TB, t *Tree, argv []string) (result, *readLine) {
	tb.Helper()

	start := time.Now()
	o := outcome(t, argv)

	line, err := t.parser.Parse(slices.Clone(argv))
	if d := time.Since(start); d > slow {
		tb.Fatalf("%q took %s", argv, d)
	}

	var ue *cmdline.UsageError
	if err != nil &&
		(!errors.As(err, &ue) || ue.Kind < cmdline.Repeated || !whole(t, line, argv)) {
		return o, nil
	}

	c := &readLine{
		path:  line.Command.Path,
		flags: map[string][]string{},
		args:  line.Args,
		leaf:  len(line.Command.Commands) == 0,
	}
	for _, g := range line.Flags {
		c.flags[g.Name] = append(c.flags[g.Name], g.Value)
	}

	return o, c
}

// whole reports whether the parser read every word of argv: as a command
// word, a flag, its value, an argument or the "--" that ends the flags.
// Next to a bad value it may have stopped at a later word of its own.
func whole(t *Tree, line *cmdline.Line, argv []string) bool {
	bools := map[string]bool{}

	c := t.parser.Root()
	for i := 0; ; i++ {
		for _, f := range c.Flags {
			bools[f.Name] = f.Bool
		}

		if i == len(line.Command.Path) {
			break
		}

		c = c.Commands[slices.IndexFunc(c.Commands, func(s *cmdline.Info) bool { return s.Name == line.Command.Path[i] })]
	}

	used := make([]bool, len(argv))

	for _, g := range line.Flags {
		used[g.At] = true
		if !bools[g.Name] && !strings.Contains(argv[g.At], "=") && g.At+1 < len(argv) {
			used[g.At+1] = true
		}
	}

	for _, at := range line.ArgAt {
		used[at] = true
	}

	var rest []string // the command words, and the "--" of a command that runs

	for i, w := range argv {
		if !used[i] {
			rest = append(rest, w)
		}
	}

	n := len(line.Command.Path)

	return len(rest) == n ||
		len(rest) == n+1 && len(line.Command.Commands) == 0 && rest[n] == "--"
}

// canonical writes a readLine back as a line: the path, --name=value for each
// value, then "--" and the arguments.
func canonicalLine(c *readLine) []string {
	argv := slices.Clone(c.path)
	for _, k := range slices.Sorted(maps.Keys(c.flags)) {
		for _, v := range c.flags[k] {
			argv = append(argv, "--"+k+"="+v)
		}
	}

	if len(c.args) > 0 {
		argv = append(argv, "--")
		argv = append(argv, c.args...)
	}

	return argv
}

// FuzzRun: no panic, no hang, the same result twice, output bounded by
// input, a line survives a round trip through its canonical form, a
// trailing "--" on a leaf changes nothing, and at a group the flags may
// move behind the command words.
//
// The round trip, the group and the "--" compare the line as the parser
// read it, not the builder's verdict: the builder's own rules (--version
// alone, which flags a group takes) are held only to "the same answer
// twice" here, and by the corpus and the kit.
func FuzzRun(f *testing.F) {
	t0 := corpusTree(f, "")
	v := newVocab(t0)

	for i := range 300 {
		//nolint:gosec // seeds, not secrets
		f.Add(strings.Join(v.line(rand.New(rand.NewPCG(99, uint64(i)))), "\x00"))
	}

	for _, l := range []string{
		"", "nodes\x00list", "nodes\x00rm\x0012\x00--force", "-o\x00json\x00nodes\x00ls",
		"nodes\x00set\x0012\x00--name\x00-h", "nodes\x00routes\x00set\x0012\x00--\x00-o", "--version", "--\x00--", "-",
	} {
		f.Add(l)
	}

	f.Fuzz(func(t *testing.T, s string) {
		argv := argvOf(s)
		if len(argv) > maxWords || len(s) > maxBytes {
			t.Skip()
		}

		o1, c1 := probe(t, t0, argv)

		o2, c2 := probe(t, t0, argv)
		if o1.String() != o2.String() || c1.String() != c2.String() {
			t.Fatalf("not the same twice: %q\n%s / %s\n%s / %s", argv, o1, o2, c1, c2)
		}

		if n := len(o1.String()); n > 6*len(s)+1024 {
			t.Fatalf("outcome of %d bytes for %d bytes of input", n, len(s))
		}

		if c1 == nil {
			return
		}

		if _, c := probe(t, t0, canonicalLine(c1)); c.String() != c1.String() {
			t.Fatalf(
				"round trip: %q\n  first  %s\n  canon  %q\n  second %s",
				argv,
				c1,
				canonicalLine(c1),
				c,
			)
		}

		// -o and -c count wherever they stand, so at a group they may move
		// behind the command words.
		if !c1.leaf && !slices.Contains(argv, "--") && len(c1.path) > 0 {
			var path, rest []string

			for _, w := range argv {
				if len(path) < len(c1.path) && w == c1.path[len(path)] {
					path = append(path, w)
				} else {
					rest = append(rest, w)
				}
			}

			unique := !slices.ContainsFunc(
				rest,
				func(w string) bool { return slices.Contains(c1.path, w) },
			)
			if moved := append(path, rest...); len(path) == len(c1.path) && unique {
				if _, c := probe(t, t0, moved); c.String() != c1.String() {
					t.Fatalf(
						"flag place at a group: %q -> %s\n  moved %q -> %s",
						argv,
						c1,
						moved,
						c,
					)
				}
			}
		}

		if c1.leaf && !slices.Contains(argv, "--") {
			if _, c := probe(
				t,
				t0,
				append(slices.Clone(argv), "--"),
			); c.String() != c1.String() {
				t.Fatalf("trailing --: %q\n  without %s\n  with    %s", argv, c1, c)
			}
		}
	})
}

// FuzzLeaf: one leaf, built from fuzz bytes. A value comes back byte for
// byte in all four spellings; after "--" every word is an argument; where
// the flags stand among the arguments changes nothing.
func FuzzLeaf(f *testing.F) {
	f.Add(uint8(0), "x\x00-y\x00--\x00", "-h\x00", uint64(0))
	f.Add(uint8(3), "12", "--force\x00", uint64(7))
	f.Add(uint8(5), "12\x00a b", "-last-seen\x00", uint64(12345))

	t0 := corpusTree(f, "")

	var leaves []*cmdline.Info

	for _, c := range infos(t0.parser.Root()) {
		if len(c.Commands) == 0 {
			leaves = append(leaves, c)
		}
	}

	f.Fuzz(func(t *testing.T, li uint8, pos, val string, perm uint64) {
		if len(pos)+len(val) > 1<<12 {
			t.Skip()
		}

		leaf := leaves[int(li)%len(leaves)]
		path := slices.Clone(leaf.Path)
		vals := argvOf(val)

		var str []cmdline.Flag

		for _, fl := range leaf.Flags {
			if !fl.Bool {
				str = append(str, fl)
			}
		}

		// 1. a value comes back byte for byte, whatever it looks like.
		if len(str) > 0 {
			fl := str[perm%uint64(len(str))]
			v := vals[0]

			forms := [][]string{{"--" + fl.Name, v}, {"--" + fl.Name + "=" + v}}
			if fl.Short != "" {
				forms = append(
					forms,
					[]string{"-" + fl.Short, v},
					[]string{"-" + fl.Short + "=" + v},
				)
			}

			for _, form := range forms {
				_, c := probe(t, t0, append(slices.Clone(path), form...))
				if c == nil || !slices.Equal(c.flags[fl.Name], []string{v}) {
					t.Fatalf("value %q of %q: got %s", v, form, c)
				}
			}
		}

		// 2. after "--" every word is an argument, byte for byte.
		ps := argvOf(pos)

		_, c := probe(t, t0, append(append(slices.Clone(path), "--"), ps...))
		if c == nil || !slices.Equal(c.args, ps) || len(c.flags) != 0 {
			t.Fatalf("after --: %q got %s", ps, c)
		}

		// 3. flags anywhere among the arguments: the same line.
		var plain []string

		for _, p := range ps {
			if p != "--" && (len(p) < 2 || p[0] != '-') {
				plain = append(plain, p)
			}
		}

		var groups [][]string

		for i, v := range vals {
			if len(str) == 0 {
				break
			}

			fl := str[(perm>>8+uint64(i))%uint64(len(str))]
			if perm>>(i%64)&1 == 0 {
				groups = append(groups, []string{"--" + fl.Name + "=" + v})
			} else {
				groups = append(groups, []string{"--" + fl.Name, v})
			}
		}

		lay := func(seed uint64) []string {
			r := rand.New(rand.NewPCG(seed, 1)) //nolint:gosec // a layout, not a secret
			line := slices.Clone(plain)
			at := 0

			for _, g := range groups { // in order, so the values of one flag stay in order
				at += r.IntN(len(line) - at + 1)
				line = slices.Insert(line, at, g...)
				at += len(g)
			}

			return append(slices.Clone(path), line...)
		}

		l1, l2 := lay(perm), lay(perm^0x9e3779b97f4a7c15)
		_, c1 := probe(t, t0, l1)

		_, c2 := probe(t, t0, l2)
		if c1 == nil || c1.String() != c2.String() {
			t.Fatalf(
				"flag place changed the line:\n  %q -> %s\n  %q -> %s",
				l1,
				c1,
				l2,
				c2,
			)
		}
	})
}

// FuzzTab: no panic, no hang, the same answer twice, at most 64
// candidates, and no candidate that the run then refuses because of that
// candidate: as an unknown command or flag, a flag given twice or a bool
// word it cannot take. --version alone is the builder's rule, which Tab
// cannot know, so it is left out. A value flag offered again reads as a
// missing value, not as given twice, so only a bool flag offered again
// fails here (seed FuzzTab-given-flag).
func FuzzTab(f *testing.F) {
	t0 := corpusTree(f, "")
	v := newVocab(t0)

	for i := range 300 {
		//nolint:gosec // seeds, not secrets
		f.Add(strings.Join(v.tabLine(rand.New(rand.NewPCG(98, uint64(i)))), "\x00"))
	}

	f.Fuzz(func(t *testing.T, s string) {
		argv := argvOf(s)
		if len(argv) > maxWords || len(s) > maxBytes {
			t.Skip()
		}

		start := time.Now()
		w1, d1, err1 := tab(t0, argv)

		w2, d2, err2 := tab(t0, argv)
		if d := time.Since(start); d > 2*slow {
			t.Fatalf("%q took %s", argv, d)
		}

		if !slices.Equal(w1, w2) || d1 != d2 || (err1 == nil) != (err2 == nil) {
			t.Fatalf("not the same twice: %q", argv)
		}

		if len(w1) > maxWords {
			t.Fatalf("%d candidates for %q", len(w1), argv)
		}

		words, cur := argv[:len(argv)-1], argv[len(argv)-1]
		before := outcome(t0, words)

		for _, cand := range w1 {
			word := cand
			if n, _, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(cur, "-") {
				word = n + "=" + cand // the scripts put "--x=" back
			}

			o := outcome(t0, append(slices.Clone(words), word))
			isCmd := o.kind == "unknown-command" && o.word == word
			isFlag := strings.HasPrefix(word, "-") && o.word == t0.long(word) &&
				(o.kind == "unknown-flag" || o.kind == "flag-repeated" || o.kind == "bad-value")

			if (isCmd || isFlag) && before.word != o.word {
				t.Fatalf(
					"Tab offered %q after %q; the run refuses it: %s",
					word,
					words,
					o,
				)
			}
		}
	})
}

// infos is every command of the tree, the root first and each group
// before its commands.
func infos(c *cmdline.Info) []*cmdline.Info {
	out := []*cmdline.Info{c} //nolint:prealloc // the size is the whole sub-tree
	for _, s := range c.Commands {
		out = append(out, infos(s)...)
	}

	return out
}

// vocab is what the line generator draws from, read off the tree.
type vocab struct {
	cmds     []*cmdline.Info
	words    []string // every command name and alias
	wrong    []string // no command anywhere, or one at the wrong level
	values   []string // values and arguments, from plain to hostile
	plain    []string // values a user would type
	allFlags []cmdline.Flag
	unknown  []string // flags no command takes, or wrong spellings
}

func newVocab(t *Tree) *vocab {
	v := &vocab{cmds: infos(t.parser.Root())}
	seen := map[string]bool{}

	for _, c := range v.cmds {
		if len(c.Path) > 0 {
			for _, w := range append([]string{c.Name}, c.Aliases...) {
				if !seen[w] {
					seen[w] = true
					v.words = append(v.words, w)
				}
			}
		}

		for _, f := range c.Flags {
			if !slices.ContainsFunc(
				v.allFlags,
				func(g cmdline.Flag) bool { return g.Name == f.Name },
			) {
				v.allFlags = append(v.allFlags, f)
			}
		}
	}

	v.wrong = []string{
		"node",
		"lst",
		"nodess",
		"NODES",
		"Nodes",
		"help",
		"preauthkeys",
		"approve",
		"ls",
		"rm",
		"routes",
		"keys",
		"set",
		"x",
		"nodes\x00",
		"nodés",
		" nodes",
		"nodes ",
	}
	v.plain = []string{
		"12",
		"alice",
		"json",
		"/etc/hs.yaml",
		"10.0.0.0/8",
		"24h",
		"id,name",
		"tag:ci,tag:prod",
		"-last-seen",
		"name=foo",
	}
	long := strings.Repeat("a", 5000)
	v.values = append(
		slices.Clone(v.plain),
		"",
		"-",
		"--",
		"---",
		"-x",
		"-h",
		"--help",
		"-o",
		"--force",
		"--output",
		"-=",
		"--=x",
		"-1",
		"-12",
		"true",
		"false",
		"maybe",
		"TRUE",
		"1",
		"0",
		"t",
		"a=b",
		"=",
		"==",
		",",
		":",
		",,",
		"a,b,",
		"tag:ci",
		"a b",
		"'q'",
		`"q"`,
		`\`,
		"$HOME",
		"*",
		"ñødé",
		"日本語", //nolint:gosmopolitan // hostile values
		"\u200b",
		"🙂",
		"\t",
		"\n",
		"\x00",
		"a\x00b",
		"\xff\xfe",
		"--\xff",
		"-\xff",
		long,
		"--"+long,
		"-o"+long,
	)
	v.values = append(v.values, v.words...)
	v.unknown = []string{
		"--bogus",
		"-x",
		"-X",
		"---force",
		"--no-force",
		"--Force",
		"--forc",
		"-output",
		"--o",
		"--h",
		"-help",
		"--=x",
		"--=",
		"-=",
		"-=x",
		"--\x00",
		"--ñ",
		"-ñ",
		"-oj",
		"-ho",
		"-hc",
		"-oh",
		"--version",
	}

	return v
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func global(f cmdline.Flag) bool { return f.Name == "output" || f.Name == "config" }

func (v *vocab) value(r *rand.Rand) string {
	if r.IntN(3) > 0 {
		return pick(r, v.plain)
	}

	return pick(r, v.values)
}

// flagWords writes one flag in one of its spellings.
func (v *vocab) flagWords(r *rand.Rand, f cmdline.Flag) []string {
	name := "--" + f.Name
	if f.Short != "" && r.IntN(2) == 0 {
		name = "-" + f.Short
	}

	if f.Bool {
		switch r.IntN(8) {
		case 0:
			return []string{name + "=true"}
		case 1:
			return []string{name + "=false"}
		case 2:
			return []string{
				name + "=" + pick(
					r,
					[]string{"", "maybe", "1", "0", "TRUE", "t", "yes"},
				),
			}
		case 3:
			return []string{
				name,
				pick(r, []string{"true", "false"}),
			} // a separate word is an argument
		}

		return []string{name}
	}

	val := v.value(r)

	switch r.IntN(10) {
	case 0, 1, 2:
		return []string{name + "=" + val}
	case 3:
		if f.Short != "" {
			return []string{"-" + f.Short + val}
		}
	case 4:
		return []string{name} // the value is missing, or the next word becomes it
	}

	return []string{name, val}
}

// line builds one command line: mostly a nearly valid readLine of a random
// command, sometimes noise. The same seed gives the same line.
func (v *vocab) line(r *rand.Rand) []string {
	if r.IntN(8) == 0 {
		return v.random(r)
	}

	c := pick(r, v.cmds)
	if len(c.Commands) > 0 && r.IntN(3) > 0 { // favour leaves
		c = pick(r, v.cmds)
	}

	var path []string

	for i := range c.Path {
		w := c.Path[i]
		if pc := v.find(
			c.Path[:i+1],
		); pc != nil && len(pc.Aliases) > 0 &&
			r.IntN(3) == 0 {
			w = pick(r, pc.Aliases)
		}

		path = append(path, w)
	}

	if len(path) > 0 && r.IntN(12) == 0 {
		path[r.IntN(len(path))] = pick(r, append(slices.Clone(v.wrong), v.words...))
	}

	seq := slices.Clone(path)
	for range max(len(c.Args)+pick(r, []int{-1, 0, 0, 0, 0, 1}), 0) {
		seq = append(seq, v.value(r))
	}

	// The command's own flags and the root's, sometimes one from elsewhere.
	pool := append(slices.Clone(c.Flags), v.cmds[0].Flags...)

	for range r.IntN(5) {
		var words []string

		anywhere := false

		switch r.IntN(12) {
		case 0:
			words = []string{pick(r, v.unknown)}
		case 1:
			words = v.flagWords(r, pick(r, v.allFlags))
		default:
			f := pick(r, pool)
			anywhere = global(f)
			words = v.flagWords(r, f)
		}

		reps := 1
		if r.IntN(10) == 0 {
			reps = 2
		}

		for range reps {
			lo := len(path)
			if anywhere || r.IntN(10) == 0 {
				lo = 0
			}

			seq = slices.Insert(seq, lo+r.IntN(len(seq)-lo+1), words...)
		}
	}

	if r.IntN(7) == 0 {
		lo := len(path)
		if r.IntN(5) == 0 {
			lo = 0
		}

		seq = slices.Insert(seq, lo+r.IntN(len(seq)-lo+1), "--")
	}

	for range pick(r, []int{0, 0, 0, 1, 1, 2}) {
		seq = v.mutate(r, seq)
	}

	return seq
}

func (v *vocab) mutate(r *rand.Rand, seq []string) []string {
	if len(seq) == 0 {
		return []string{v.value(r)}
	}

	i := r.IntN(len(seq))

	switch r.IntN(8) {
	case 0:
		seq[i] = pick(r, v.values)
	case 1:
		return slices.Delete(seq, i, i+1)
	case 2:
		return slices.Insert(seq, i, seq[i])
	case 3:
		if i+1 < len(seq) {
			seq[i], seq[i+1] = seq[i+1], seq[i]
		}
	case 4:
		return slices.Insert(
			seq,
			i,
			pick(r, []string{"-h", "--help", "-", "--", "--version"}),
		)
	case 5:
		return slices.Insert(seq, i, pick(r, v.unknown))
	case 6:
		seq[i] += pick(r, []string{"=", "=x", ",", "\x00", "\xff"})
	case 7:
		if seq[i] != "" {
			seq[i] = seq[i][:r.IntN(len(seq[i]))]
		}
	}

	return seq
}

func (v *vocab) random(r *rand.Rand) []string {
	seq := make([]string, r.IntN(13))
	for i := range seq {
		switch r.IntN(5) {
		case 0:
			seq[i] = pick(r, v.words)
		case 1:
			seq[i] = strings.Join(v.flagWords(r, pick(r, v.allFlags)), "=")
		case 2:
			seq[i] = pick(r, v.unknown)
		case 3:
			seq[i] = pick(r, v.values)
		default:
			b := make([]byte, r.IntN(8))
			for j := range b {
				b[j] = pick(r, []byte("-=,: ax\x00\xff"))
			}

			seq[i] = string(b)
		}
	}

	return seq
}

// tabLine cuts a generated line at a random word and a random prefix of
// it: the words before the cursor and the word under it.
func (v *vocab) tabLine(r *rand.Rand) []string {
	seq := v.line(r)
	k := r.IntN(len(seq) + 1)

	cur := ""
	if k < len(seq) && r.IntN(4) > 0 {
		cur = seq[k][:r.IntN(len(seq[k])+1)]
	}

	return append(slices.Clone(seq[:k]), cur)
}

func (v *vocab) find(path []string) *cmdline.Info {
	for _, c := range v.cmds {
		if slices.Equal(c.Path, path) {
			return c
		}
	}

	return nil
}
