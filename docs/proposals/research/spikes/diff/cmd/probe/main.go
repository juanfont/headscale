// probe prints what each adapter makes of one line (or of Tab with -tab).
//
//	./go.sh go run ./cmd/probe -- nodes list -o json
//	./go.sh go run ./cmd/probe -lines file   (one line per row, words split on spaces, '' is empty)
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	cobraadapter "spike/cobra"
	"spike/diff"
	"spike/diff/ownfix"
	"spike/kit"
	grammar "spike/own-grammar"
	ownpflag "spike/own-pflag"
)

func main() {
	tab := flag.Bool("tab", false, "complete instead of run")
	lines := flag.String("lines", "", "file of lines")
	flag.Parse()
	as := []diff.Named{{Name: "grammar", A: grammar.Adapter{}}, {Name: "fixed", A: ownfix.Adapter{}}, {Name: "own-pflag", A: ownpflag.Adapter{}},
		{Name: "cobra", A: cobraadapter.Adapter{}}, {Name: "plainpflag", A: diff.PflagPlain{}}, {Name: "stdflag", A: diff.StdFlag{}}}
	one := func(argv []string) {
		fmt.Printf("%q\n", argv)
		for _, a := range as {
			var o, raw string
			if *tab {
				if a.Name == "plainpflag" || a.Name == "stdflag" {
					continue
				}
				o = diff.Tab(a.A, argv)
			} else {
				o, raw = kit.Probe(a.A, argv)
			}
			fmt.Printf("  %-10s %s", a.Name, o)
			if raw != "" {
				fmt.Printf("   raw: %s", raw)
			}
			fmt.Println()
		}
	}
	if *lines != "" {
		f, _ := os.Open(*lines)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			w := strings.Fields(sc.Text())
			for i := range w {
				if w[i] == "''" {
					w[i] = ""
				}
			}
			if *tab && strings.HasSuffix(sc.Text(), " ") {
				w = append(w, "")
			}
			one(w)
		}
		return
	}
	one(flag.Args())
}
