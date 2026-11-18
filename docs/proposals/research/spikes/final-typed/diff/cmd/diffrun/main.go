// diffrun generates command lines, runs them through the adapters, and
// writes the differences grouped into buckets by cause.
//
//	./go.sh go run ./cmd/diffrun -n 1000000 -mode run -out results/run.md
package main

import (
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	cobraadapter "spike/cobra"
	"spike/diff"
	hs "spike/final-headscale"
	"spike/kit"
	grammar "spike/own-grammar"
	ownpflag "spike/own-pflag"
)

type bucket struct {
	Pair, Cause, Class string
	Shrunk             int            // diffs shrunk into this bucket
	Est                float64        // Shrunk divided by the pair's sampling rate
	Classes            map[string]int // severity of the unshrunk lines
	Example            []string
	Outcomes           [2]string
	Samples            [][3]string // a few more shrunk lines with both outcomes, for review
}

type pair struct {
	name string
	a, b kit.Adapter
	only func(argv []string) bool // nil: every line
	rate float64                  // share of differing lines that are shrunk and classified
}

func main() {
	n := flag.Int("n", 100000, "lines")
	offset := flag.Int("offset", 0, "first line number (cobra's Tab keeps ~6 KiB per call in a package map: run Tab in chunks)")
	seed := flag.Uint64("seed", 1, "seed")
	mode := flag.String("mode", "run", "run or tab")
	out := flag.String("out", "", "markdown file (and .json next to it)")
	which := flag.String("grammar", "final", "final (spikes/final-typed), or delivered (own-grammar)")
	rate := flag.Float64("rate", 1, "share of differing lines to shrink, own pairs")
	crate := flag.Float64("crate", 0.1, "share of differing lines to shrink, pairs with cobra")
	flag.Parse()
	kit.Shared = true

	var g kit.Adapter = hs.Adapter{}
	if *which == "delivered" {
		g = grammar.Adapter{}
	}
	p, c := kit.Adapter(ownpflag.Adapter{}), kit.Adapter(cobraadapter.Adapter{})
	t := kit.NewTree()
	pairs := []pair{{"grammar~pflag", g, p, nil, *rate}, {"grammar~cobra", g, c, nil, *crate}, {"pflag~cobra", p, c, nil, *crate}}
	if *mode == "run" {
		pairs = append(pairs,
			pair{"grammar~plainpflag", g, diff.PflagPlain{}, func(a []string) bool { return diff.LeafLine(t, a) }, *rate},
			pair{"grammar~stdflag", g, diff.StdFlag{}, func(a []string) bool { return diff.Ordered(t, a) }, *rate})
	}
	probe := diff.Outcome
	if *mode == "tab" {
		probe = diff.Tab
	}

	v := diff.NewVocab()
	var mu sync.Mutex
	buckets := map[string]*bucket{}
	compared, differ, shrunk := map[string]int{}, map[string]int{}, map[string]int{}
	severity := map[string]int{} // pair|class
	patterns := map[string]int{}
	var done atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	workers := runtime.GOMAXPROCS(0)
	for w := range workers {
		wg.Go(func() {
			for i := *offset + w; i < *offset+*n; i += workers {
				r := rand.New(rand.NewPCG(*seed, uint64(i)))
				var argv []string
				if *mode == "tab" {
					argv = v.TabLine(r)
				} else {
					argv = v.Line(r)
				}
				cache := map[kit.Adapter]string{}
				get := func(a kit.Adapter) string {
					if o, ok := cache[a]; ok {
						return o
					}
					cache[a] = probe(a, argv)
					return cache[a]
				}
				og, op, oc := get(g), get(p), get(c)
				pat := "all agree"
				switch {
				case og == op && op == oc:
				case op == oc:
					pat = "grammar alone differs"
				case og == op:
					pat = "cobra alone differs"
				case og == oc:
					pat = "own-pflag alone differs"
				default:
					pat = "all three differ"
				}
				mu.Lock()
				patterns[pat]++
				mu.Unlock()
				for _, pr := range pairs {
					if pr.only != nil && !pr.only(argv) {
						continue
					}
					oa, ob := get(pr.a), get(pr.b)
					cls := diff.Severity(oa, ob)
					mu.Lock()
					compared[pr.name]++
					if oa != ob {
						differ[pr.name]++
						severity[pr.name+"|"+cls]++
					}
					mu.Unlock()
					if oa == ob || r.Float64() >= pr.rate {
						continue
					}
					ka, kb := diff.Kind(oa), diff.Kind(ob)
					delta := diff.TabDelta(oa, ob)
					still := func(x []string) bool {
						if pr.only != nil && !pr.only(x) {
							return false
						}
						xa, xb := probe(pr.a, x), probe(pr.b, x)
						if *mode == "tab" {
							return len(x) > 0 && diff.TabDelta(xa, xb) == delta
						}
						return xa != xb && diff.Kind(xa) == ka && diff.Kind(xb) == kb
					}
					s := diff.Shrink(argv, still)
					sa, sb := probe(pr.a, s), probe(pr.b, s)
					cause := diff.Classify(*mode, pr.name, s, sa, sb)
					if cause == "" && *mode == "tab" {
						cause = "? " + diff.Abstract(t, s)
					} else if cause == "" {
						cause = "? " + ka + " → " + kb + " | " + diff.Abstract(t, s)
					}
					key := pr.name + "|" + cause
					mu.Lock()
					shrunk[pr.name]++
					b := buckets[key]
					if b == nil {
						b = &bucket{Pair: pr.name, Cause: cause, Classes: map[string]int{}}
						buckets[key] = b
					}
					b.Shrunk++
					b.Est += 1 / pr.rate
					b.Classes[cls]++
					if len(b.Samples) < 8 {
						b.Samples = append(b.Samples, [3]string{show(s), sa, sb})
					}
					if b.Example == nil || less(s, b.Example) {
						b.Example, b.Outcomes = s, [2]string{sa, sb}
					}
					mu.Unlock()
				}
				if d := done.Add(1); d%200000 == 0 {
					fmt.Fprintf(os.Stderr, "%d lines, %s\n", d, time.Since(start).Round(time.Second))
				}
			}
		})
	}
	wg.Wait()
	el := time.Since(start)

	all := slices.Collect(maps.Values(buckets))
	slices.SortFunc(all, func(x, y *bucket) int {
		return cmp.Or(cmp.Compare(x.Pair, y.Pair), cmp.Compare(y.Shrunk, x.Shrunk), cmp.Compare(x.Cause, y.Cause))
	})
	var md strings.Builder
	fmt.Fprintf(&md, "# diffrun mode=%s n=%d seed=%d grammar=%s rate=%g crate=%g: %s on %d workers\n\n",
		*mode, *n, *seed, *which, *rate, *crate, el.Round(time.Millisecond), workers)
	md.WriteString("| Three-way pattern (grammar, own-pflag, cobra) | Lines |\n| --- | --- |\n")
	for _, k := range slices.Sorted(maps.Keys(patterns)) {
		fmt.Fprintf(&md, "| %s | %d |\n", k, patterns[k])
	}
	md.WriteString("\n| Pair | Compared | Differ | semantic | acceptance | report | Shrunk | Buckets |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, pr := range pairs {
		nb := 0
		for _, b := range all {
			if b.Pair == pr.name {
				nb++
			}
		}
		fmt.Fprintf(&md, "| %s | %d | %d | %d | %d | %d | %d | %d |\n", pr.name, compared[pr.name], differ[pr.name],
			severity[pr.name+"|semantic"], severity[pr.name+"|acceptance"], severity[pr.name+"|report"], shrunk[pr.name], nb)
	}
	md.WriteString("\n| Pair | Cause | Shrunk | ≈ lines | semantic/acceptance/report | Smallest line | Outcome a | Outcome b |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, b := range all {
		fmt.Fprintf(&md, "| %s | %s | %d | %.0f | %d/%d/%d | `%s` | `%s` | `%s` |\n", b.Pair, esc(b.Cause), b.Shrunk, b.Est,
			b.Classes["semantic"], b.Classes["acceptance"], b.Classes["report"],
			esc(show(b.Example)), esc(trunc(b.Outcomes[0])), esc(trunc(b.Outcomes[1])))
	}
	if *out != "" {
		_ = os.WriteFile(*out, []byte(md.String()), 0o644)
		j, _ := json.MarshalIndent(map[string]any{"buckets": all, "patterns": patterns, "compared": compared, "differ": differ, "severity": severity, "shrunk": shrunk}, "", " ")
		_ = os.WriteFile(strings.TrimSuffix(*out, ".md")+".json", j, 0o644)
	} else {
		fmt.Print(md.String())
	}
	fmt.Fprintf(os.Stderr, "%d lines in %s\n", *n, el)
}

func less(a, b []string) bool {
	la, lb := len(strings.Join(a, " ")), len(strings.Join(b, " "))
	return la < lb || la == lb && strings.Join(a, " ") < strings.Join(b, " ")
}

func show(argv []string) string {
	var s []string
	for _, w := range argv {
		q := fmt.Sprintf("%q", w)
		if w != "" && q == `"`+w+`"` && !strings.ContainsAny(w, " '") {
			q = w
		}
		s = append(s, q)
	}
	return "headscale " + strings.Join(s, " ")
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func trunc(s string) string {
	if len(s) > 140 {
		return s[:140] + "…"
	}
	return s
}
