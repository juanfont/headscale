// Package diff runs generated command lines through several adapters of the
// kit and groups the differences by cause.
package diff

import (
	"math/rand/v2"
	"slices"
	"strings"

	"spike/kit"
)

// Vocab is everything the generator draws from, read off the kit's tree.
type Vocab struct {
	T        *kit.Tree
	Words    []string // every command name and alias
	Wrong    []string // words that are no command anywhere, or one at the wrong level
	Values   []string // values and positionals, from plain to hostile
	Plain    []string // values a user would type
	AllFlags []kit.Flag
	Unknown  []string // flags no command takes, or wrong spellings
}

func NewVocab() *Vocab {
	t := kit.NewTree()
	v := &Vocab{T: t}
	seen := map[string]bool{}
	for _, c := range t.Commands {
		if len(c.Path) > 0 {
			for _, w := range append([]string{c.Path[len(c.Path)-1]}, c.Aliases...) {
				if !seen[w] {
					seen[w] = true
					v.Words = append(v.Words, w)
				}
			}
		}
		for _, f := range c.Flags {
			if !slices.ContainsFunc(v.AllFlags, func(g kit.Flag) bool { return g.Name == f.Name }) {
				v.AllFlags = append(v.AllFlags, f)
			}
		}
	}
	v.Wrong = []string{"node", "lst", "nodess", "NODES", "Nodes", "help", "preauthkeys", "approve", "ls", "rm",
		"routes", "keys", "set", "x", "nodes\x00", "nodés", " nodes", "nodes "}
	v.Plain = []string{"12", "alice", "json", "/etc/hs.yaml", "10.0.0.0/8", "24h", "id,name", "tag:ci,tag:prod", "-last-seen", "name=foo"}
	long := strings.Repeat("a", 5000)
	v.Values = append(slices.Clone(v.Plain),
		"", "-", "--", "---", "-x", "-h", "--help", "-o", "--force", "--output", "-=", "--=x", "-1", "-12",
		"true", "false", "maybe", "TRUE", "1", "0", "t",
		"a=b", "=", "==", ",", ":", ",,", "a,b,", "tag:ci", "a b", "'q'", `"q"`, `\`, "$HOME", "*",
		"ñødé", "日本語", "​", "🙂", "\t", "\n", "\x00", "a\x00b", "\xff\xfe", "--\xff", "-\xff",
		long, "--"+long, "-o"+long)
	v.Values = append(v.Values, v.Words...)
	v.Unknown = []string{"--bogus", "-x", "-X", "---force", "--no-force", "--Force", "--forc", "-output", "--o",
		"--h", "-help", "--=x", "--=", "-=", "-=x", "--\x00", "--ñ", "-ñ", "-oj", "-ho", "-hc", "-oh", "--version"}
	return v
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func (v *Vocab) value(r *rand.Rand) string {
	if r.IntN(3) > 0 {
		return pick(r, v.Plain)
	}
	return pick(r, v.Values)
}

// flagTokens renders one flag in one of its spellings.
func (v *Vocab) flagTokens(r *rand.Rand, f kit.Flag) []string {
	name := "--" + f.Name
	if f.Short != "" && r.IntN(2) == 0 {
		name = "-" + f.Short
	}
	if f.Kind == kit.Bool {
		switch r.IntN(8) {
		case 0:
			return []string{name + "=true"}
		case 1:
			return []string{name + "=false"}
		case 2:
			return []string{name + "=" + pick(r, []string{"", "maybe", "1", "0", "TRUE", "t", "yes"})}
		case 3:
			return []string{name, pick(r, []string{"true", "false"})} // a separate value is a positional
		}
		return []string{name}
	}
	val := v.value(r)
	switch r.IntN(10) {
	case 0, 1, 2:
		return []string{name + "=" + val}
	case 3:
		if f.Short != "" { // attached -ojson (D11 best effort)
			return []string{"-" + f.Short + val}
		}
	case 4:
		return []string{name} // value missing, or the next word becomes it (D20)
	}
	return []string{name, val}
}

// Line builds one command line: mostly a nearly valid call of a random
// command, sometimes noise. Same seed, same line.
func (v *Vocab) Line(r *rand.Rand) []string {
	if r.IntN(8) == 0 {
		return v.random(r)
	}
	t := v.T
	c := t.Commands[r.IntN(len(t.Commands))]
	if !c.Leaf && r.IntN(3) > 0 { // favour leaves
		c = t.Commands[r.IntN(len(t.Commands))]
	}
	var path []string
	for i := range c.Path {
		w := c.Path[i]
		if pc := find(t, c.Path[:i+1]); pc != nil && len(pc.Aliases) > 0 && r.IntN(3) == 0 {
			w = pick(r, pc.Aliases)
		}
		path = append(path, w)
	}
	if len(path) > 0 && r.IntN(12) == 0 {
		path[r.IntN(len(path))] = pick(r, append(v.Wrong, v.Words...))
	}
	seq := slices.Clone(path)
	nargs := len(c.Args) + pick(r, []int{-1, 0, 0, 0, 0, 1})
	for range max(nargs, 0) {
		seq = append(seq, v.value(r))
	}
	// Flags: the command's own and the globals, sometimes one from elsewhere.
	pool := slices.Clone(c.Flags)
	pool = append(pool, t.Commands[0].Flags...)
	for range r.IntN(5) {
		var toks []string
		global := false
		switch r.IntN(12) {
		case 0:
			toks = []string{pick(r, v.Unknown)}
		case 1:
			toks = v.flagTokens(r, pick(r, v.AllFlags))
		default:
			f := pick(r, pool)
			global = f.Global
			toks = v.flagTokens(r, f)
		}
		reps := 1
		if r.IntN(10) == 0 {
			reps = 2
		}
		for range reps {
			lo := len(path)
			if global || r.IntN(10) == 0 {
				lo = 0
			}
			at := lo + r.IntN(len(seq)-lo+1)
			seq = slices.Insert(seq, at, toks...)
		}
	}
	if r.IntN(7) == 0 {
		lo := len(path)
		if r.IntN(5) == 0 {
			lo = 0
		}
		at := lo + r.IntN(len(seq)-lo+1)
		seq = slices.Insert(seq, at, "--")
	}
	for range pick(r, []int{0, 0, 0, 1, 1, 2}) {
		seq = v.mutate(r, seq)
	}
	return seq
}

func (v *Vocab) mutate(r *rand.Rand, seq []string) []string {
	if len(seq) == 0 {
		return []string{v.value(r)}
	}
	i := r.IntN(len(seq))
	switch r.IntN(8) {
	case 0:
		seq[i] = pick(r, v.Values)
	case 1:
		return slices.Delete(seq, i, i+1)
	case 2:
		return slices.Insert(seq, i, seq[i])
	case 3:
		if i+1 < len(seq) {
			seq[i], seq[i+1] = seq[i+1], seq[i]
		}
	case 4:
		return slices.Insert(seq, i, pick(r, []string{"-h", "--help", "-", "--", "--version"}))
	case 5:
		return slices.Insert(seq, i, pick(r, v.Unknown))
	case 6:
		seq[i] += pick(r, []string{"=", "=x", ",", "\x00", "\xff"})
	case 7:
		if seq[i] != "" {
			seq[i] = seq[i][:r.IntN(len(seq[i]))]
		}
	}
	return seq
}

func (v *Vocab) random(r *rand.Rand) []string {
	n := r.IntN(13)
	seq := make([]string, n)
	for i := range seq {
		switch r.IntN(5) {
		case 0:
			seq[i] = pick(r, v.Words)
		case 1:
			f := pick(r, v.AllFlags)
			seq[i] = strings.Join(v.flagTokens(r, f), "=")
		case 2:
			seq[i] = pick(r, v.Unknown)
		case 3:
			seq[i] = pick(r, v.Values)
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

// TabLine cuts a generated line at a random word and a random prefix of it:
// the words before the cursor and the word under it.
func (v *Vocab) TabLine(r *rand.Rand) []string {
	seq := v.Line(r)
	k := r.IntN(len(seq) + 1)
	cur := ""
	if k < len(seq) && r.IntN(4) > 0 {
		cur = seq[k][:r.IntN(len(seq[k])+1)]
	}
	return append(slices.Clone(seq[:k]), cur)
}

func find(t *kit.Tree, path []string) *kit.Command {
	for i := range t.Commands {
		if slices.Equal(t.Commands[i].Path, path) {
			return &t.Commands[i]
		}
	}
	return nil
}
