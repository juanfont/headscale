package diff

// Fuzz targets for the own parser (Run) and the own Tab answerer. argv is
// the fuzz string split on NUL: a real argv word cannot hold a NUL, so this
// loses nothing a shell can send (the differential generator covers NUL
// inside words). The fixed copy (spike/diff/ownfix) by default, so the
// failing inputs in testdata stay regression seeds; FUZZ_OWN=delivered
// fuzzes the delivered own-grammar.

import (
	"maps"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"spike/diff/ownfix"
	"spike/kit"
	grammar "spike/own-grammar"
)

func own() kit.Adapter {
	if os.Getenv("FUZZ_OWN") == "delivered" {
		return grammar.Adapter{}
	}
	return ownfix.Adapter{}
}

func argvOf(s string) []string { return strings.Split(s, "\x00") }

func seeds(f *testing.F, n int) {
	v := NewVocab()
	for i := range n {
		r := rand.New(rand.NewPCG(99, uint64(i)))
		f.Add(strings.Join(v.Line(r), "\x00"))
	}
	for _, l := range []string{"", "nodes\x00list", "nodes\x00rm\x0012\x00--force", "-o\x00json\x00nodes\x00ls",
		"nodes\x00set\x0012\x00--name\x00-h", "nodes\x00routes\x00set\x0012\x00--\x00-o", "--version", "--\x00--", "-"} {
		f.Add(l)
	}
}

// probe runs argv once, fails on a slow parse, and returns outcome and Call.
func probe(t *testing.T, a kit.Adapter, argv []string) (string, *kit.Call) {
	t.Helper()
	start := time.Now()
	o, c := kit.ProbeCall(a, argv)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("%q took %s", argv, d)
	}
	return o, c
}

func raw(c *kit.Call) string {
	if c == nil {
		return "<no call>"
	}
	return kit.RawString(*c)
}

func isLeaf(c *kit.Call) bool {
	if c == nil {
		return false
	}
	t := kit.NewTree()
	for _, cmd := range t.Commands {
		if cmd.Leaf && slices.Equal(cmd.Path, c.Path) {
			return true
		}
	}
	// an alias in the path: resolve word by word against the tree
	cmd := resolve(t, c.Path)
	return cmd != nil && cmd.Leaf
}

func resolve(t *kit.Tree, words []string) *kit.Command {
	var cur []string
	for _, w := range words {
		next := ""
		for _, c := range t.Commands {
			if len(c.Path) == len(cur)+1 && slices.Equal(c.Path[:len(cur)], cur) && (c.Path[len(cur)] == w || slices.Contains(c.Aliases, w)) {
				next = c.Path[len(cur)]
			}
		}
		if next == "" {
			return nil
		}
		cur = append(cur, next)
	}
	return find(t, cur)
}

// canonical writes a Call back as a line: path, --name=value per value, then
// "--" and the positionals.
func canonical(c *kit.Call) []string {
	argv := slices.Clone(c.Path)
	for _, k := range slices.Sorted(maps.Keys(c.Flags)) {
		for _, v := range c.Flags[k] {
			argv = append(argv, "--"+kit.NewTree().Long(k)+"="+v)
		}
	}
	if len(c.Args) > 0 {
		argv = append(argv, "--")
		argv = append(argv, c.Args...)
	}
	return argv
}

// FuzzRun: no panic, no hang, deterministic, output bounded by input, a
// Call survives a round trip through its canonical line, and "--" appended
// to a line that reached a leaf changes nothing.
func FuzzRun(f *testing.F) {
	seeds(f, 300)
	a := own()
	f.Fuzz(func(t *testing.T, s string) {
		argv := argvOf(s)
		if len(argv) > 64 || len(s) > 1<<14 {
			t.Skip()
		}
		o1, c1 := probe(t, a, argv)
		o2, c2 := probe(t, a, argv)
		if o1 != o2 || raw(c1) != raw(c2) {
			t.Fatalf("not deterministic: %q\n%s / %s\n%s / %s", argv, o1, o2, raw(c1), raw(c2))
		}
		if len(o1) > 6*len(s)+1024 {
			t.Fatalf("outcome %d bytes for %d bytes of input", len(o1), len(s))
		}
		if c1 == nil {
			return
		}
		if _, c := probe(t, a, canonical(c1)); raw(c) != raw(c1) {
			t.Fatalf("round trip: %q\n  first  %s\n  canon  %q\n  second %s", argv, raw(c1), canonical(c1), raw(c))
		}
		// a line that ends at a group: root flags count wherever they stand (D3),
		// so moving them behind the command words changes nothing
		if !isLeaf(c1) && !slices.Contains(argv, "--") && len(c1.Path) > 0 {
			var path, rest []string
			for _, w := range argv {
				if len(path) < len(c1.Path) && w == c1.Path[len(path)] {
					path = append(path, w)
				} else {
					rest = append(rest, w)
				}
			}
			unique := !slices.ContainsFunc(rest, func(w string) bool { return slices.Contains(c1.Path, w) })
			if len(path) == len(c1.Path) && unique {
				if _, c := probe(t, a, append(path, rest...)); raw(c) != raw(c1) {
					t.Fatalf("flag place at a group: %q -> %s\n  moved %q -> %s", argv, raw(c1), append(path, rest...), raw(c))
				}
			}
		}
		if isLeaf(c1) && !slices.Contains(argv, "--") {
			if _, c := probe(t, a, append(slices.Clone(argv), "--")); raw(c) != raw(c1) {
				t.Fatalf("trailing --: %q\n  without %s\n  with    %s", argv, raw(c1), raw(c))
			}
		}
	})
}

// FuzzLeaf: properties of one leaf, built from fuzz bytes. A value is
// returned byte for byte in all its spellings; everything after "--" is a
// positional; moving flags among the positionals changes nothing.
func FuzzLeaf(f *testing.F) {
	f.Add(uint8(0), "x\x00-y\x00--\x00", "-h\x00", uint64(0))
	f.Add(uint8(3), "12", "--force\x00", uint64(7))
	f.Add(uint8(5), "12\x00a b", "-last-seen\x00", uint64(12345))
	a := own()
	t0 := kit.NewTree()
	var leaves []kit.Command
	for _, c := range t0.Commands {
		if c.Leaf {
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
		var str []kit.Flag
		for _, fl := range leaf.Flags {
			if fl.Kind != kit.Bool {
				str = append(str, fl)
			}
		}
		// 1. a value comes back byte for byte, whatever it looks like (D20)
		if len(str) > 0 {
			fl := str[int(perm)%len(str)]
			v := vals[0]
			forms := [][]string{{"--" + fl.Name, v}, {"--" + fl.Name + "=" + v}}
			if fl.Short != "" {
				forms = append(forms, []string{"-" + fl.Short, v}, []string{"-" + fl.Short + "=" + v})
			}
			for _, form := range forms {
				_, c := probe(t, a, append(slices.Clone(path), form...))
				if c == nil || !slices.Equal(c.Flags[fl.Name], []string{v}) {
					t.Fatalf("value %q of %q: got %s", v, form, raw(c))
				}
			}
		}
		// 2. after "--" every word is a positional, byte for byte
		ps := argvOf(pos)
		_, c := probe(t, a, append(append(slices.Clone(path), "--"), ps...))
		if c == nil || !slices.Equal(c.Args, ps) || len(c.Flags) != 0 {
			t.Fatalf("after --: %q got %s", ps, raw(c))
		}
		// 3. flags anywhere among positionals: same Call
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
			fl := str[(int(perm>>8)+i)%len(str)]
			if perm>>(i%64)&1 == 0 {
				groups = append(groups, []string{"--" + fl.Name + "=" + v})
			} else {
				groups = append(groups, []string{"--" + fl.Name, v})
			}
		}
		lay := func(seed uint64) []string {
			r := rand.New(rand.NewPCG(seed, 1))
			line := slices.Clone(plain)
			at := 0
			for _, g := range groups { // keeps the flags' own order: values of one flag stay in order
				at += r.IntN(len(line) - at + 1)
				line = slices.Insert(line, at, g...)
				at += len(g)
			}
			return append(slices.Clone(path), line...)
		}
		l1, l2 := lay(perm), lay(perm^0x9e3779b97f4a7c15)
		_, c1 := probe(t, a, l1)
		_, c2 := probe(t, a, l2)
		if raw(c1) != raw(c2) || c1 == nil {
			t.Fatalf("flag position changed the result:\n  %q -> %s\n  %q -> %s", l1, raw(c1), l2, raw(c2))
		}
	})
}

// FuzzTab: no panic, no hang, deterministic, bounded, and no candidate that
// Run then refuses as an unknown flag or command because of that candidate.
func FuzzTab(f *testing.F) {
	v := NewVocab()
	for i := range 300 {
		f.Add(strings.Join(v.TabLine(rand.New(rand.NewPCG(98, uint64(i)))), "\x00"))
	}
	a := own()
	t0 := kit.NewTree()
	f.Fuzz(func(t *testing.T, s string) {
		argv := argvOf(s)
		if len(argv) > 64 || len(s) > 1<<14 {
			t.Skip()
		}
		start := time.Now()
		w1, files1, err1 := kit.CompleteWords(a, argv)
		w2, files2, err2 := kit.CompleteWords(a, argv)
		if d := time.Since(start); d > time.Second {
			t.Fatalf("%q took %s", argv, d)
		}
		if !slices.Equal(w1, w2) || files1 != files2 || (err1 == nil) != (err2 == nil) {
			t.Fatalf("not deterministic: %q", argv)
		}
		if len(w1) > 64 {
			t.Fatalf("%d candidates for %q", len(w1), argv)
		}
		words, cur := argv[:len(argv)-1], argv[len(argv)-1]
		before := Outcome(a, words)
		for _, cand := range w1 {
			word := cand
			if n, _, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(cur, "-") {
				word = n + "=" + cand // the scripts put "--x=" back
			}
			o := Parse(Outcome(a, append(slices.Clone(words), word)))
			isCmd := o.Kind == "unknown-command" && o.Word == word
			isFlag := o.Kind == "unknown-flag" && strings.HasPrefix(word, "-") && o.Word == t0.Long(word)
			if (isCmd || isFlag) && Parse(before).Word != o.Word {
				t.Fatalf("Tab offered %q after %q; Run refuses it: %s", word, words, o.Text)
			}
		}
	})
}
