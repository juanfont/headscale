// Command corpus runs the upstream edge-case corpus (corpus.jsonl) through
// the adapters and says, per case and adapter, whether the result matches
// what the source project expects ("up"), what Headscale decided instead
// ("ours"), or neither.
//
//	go run . [-check] [-md out.md] [-tsv out.tsv] corpus.jsonl...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"spike/cmdline"
	hs "spike/final-headscale"
	"spike/kit"
)

// Case is one line of the corpus.
type Case struct {
	ID       string   `json:"id"`
	Src      string   `json:"src"`            // repo@rev file:line Test, or issue URL
	Lic      string   `json:"lic"`            // licence of the source
	Kind     string   `json:"kind"`           // run | complete
	Topic    string   `json:"topic"`          // grammar area
	Upstream string   `json:"upstream"`       // the case as the source wrote it
	Expect   string   `json:"expect"`         // what the source expects, in words
	Tree     string   `json:"tree"`           // "" = the kit's tree
	Argv     []string `json:"argv"`           // on our tree; for complete the last word is the cursor word
	Want     *Out     `json:"want"`           // the source's behaviour, carried onto our tree
	Ours     *Out     `json:"ours,omitempty"` // Headscale's expectation where it differs
	Why      string   `json:"why,omitempty"`  // for ours: "D11", "quirk: …", "undecided: …"
	Note     string   `json:"note,omitempty"`
}

// Out is an expected outcome. Run: kind is run, help, version or a usage
// error kind. Complete: kind "complete" and the fields below it.
type Out struct {
	Kind  string              `json:"kind"`
	Path  string              `json:"path,omitempty"`
	Args  []string            `json:"args,omitempty"`
	Flags map[string][]string `json:"flags,omitempty"`
	Word  string              `json:"word,omitempty"`

	Has     []string `json:"has,omitempty"`
	Not     []string `json:"not,omitempty"`
	Exact   []string `json:"exact,omitempty"` // the whole candidate list, any order; [] means none
	Files   *bool    `json:"files,omitempty"`
	NoSpace *bool    `json:"nospace,omitempty"`
}

type completer func(t *kit.Tree, argv []string) (words []string, dir int, err error)

type adapter struct {
	name string
	a    kit.Adapter
	comp completer
}

func finalComp(t *kit.Tree, argv []string) ([]string, int, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	w, d := cmdline.Complete(hs.Root(t), argv[:len(argv)-1], argv[len(argv)-1])
	return w, int(d), nil
}

var adapters = []adapter{{"final", hs.Adapter{}, finalComp}}

// explained is every case where the final prototype matches neither the
// source nor the corpus's own "ours", with the decision (or the rule of
// rules.md that nobody decided) that says why. A "neither" not listed here,
// or a listed case that is no longer "neither", fails the run.
var explained = map[string]string{
	"cobracmd-020":  "001 L404 / facts: an empty list value is an error; the empty word is the <routes> list",
	"issues-060":    "001 L404 / facts: an empty list value is an error; the empty word is the <routes> list",
	"others-187":    "001 L404 / facts: an empty list value is an error (--filter '')",
	"pflag-041":     "001 L404 / facts: an empty list value is an error (--list=)",
	"pflag-042":     "001 L404 / facts: an empty list value is an error (--filter=); closes the corpus's 'undecided'",
	"cobracomp-004": "D30: after a refused command word Tab completes from the last command understood",
	"cobracomp-050": "D30 (+D11): -sdf is refused, Tab goes on with the positional; the corpus's 'ours' predates D30",
	"issues-033":    "D30 + call: `--` where a command word is expected is refused, Tab goes on at the root",
	"others-123":    "D30 + call: `--` where a command word is expected is refused, Tab goes on at the root",
	"cobracomp-065": "D27: --config is marked as a path, Tab offers files",
	"cobracomp-066": "D27: --config is marked as a path, Tab offers files",
	"others-172":    "D27: a free-text flag (--name) offers nothing, not files",
	"others-167":    "call: no Tab values for bools (--force=<Tab>)",
	"others-168":    "call: no Tab values for bools",
	"others-169":    "call + D26: no Tab values for bools; TRUE is no bool word",
	"issues-023":    "call: `--` where a command word is expected is unknown command `--`",
	"issues-006":    "implied A1: a word of 2+ bytes that starts with '-' is a flag word ('- h' is unknown flag)",
	"issues-041":    "implied A1: bytes, not runes: an em dash is no '-', so '—-help' is a positional",
	"others-197":    "implied H5: the library never strips quotes from the cursor word (--sort=\"<Tab> offers nothing)",
}

const (
	noSpace    = 2
	noFileComp = 4
)

func main() {
	check := flag.Bool("check", false, "only parse the files and validate trees and paths")
	md := flag.String("md", "", "write a markdown table here")
	tsv := flag.String("tsv", "", "write one row per case and adapter here")
	flag.Parse()
	var cases []Case
	ids := map[string]bool{}
	bad := 0
	for _, p := range flag.Args() {
		b, err := os.ReadFile(p)
		if err != nil {
			fail(err)
		}
		for n, l := range strings.Split(string(b), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			var c Case
			dec := json.NewDecoder(strings.NewReader(l))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&c); err != nil {
				fmt.Printf("%s:%d: %v\n", p, n+1, err)
				bad++
				continue
			}
			if msg := validate(c); msg != "" || ids[c.ID] {
				if ids[c.ID] {
					msg += " duplicate id"
				}
				fmt.Printf("%s:%d %s: %s\n", p, n+1, c.ID, msg)
				bad++
			}
			ids[c.ID] = true
			cases = append(cases, c)
		}
	}
	if *check {
		fmt.Printf("%d cases, %d bad\n", len(cases), bad)
		if bad > 0 {
			os.Exit(1)
		}
		return
	}
	var mdw, tsvw io.Writer = io.Discard, io.Discard
	if *md != "" {
		f, err := os.Create(*md)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		mdw = f
	}
	if *tsv != "" {
		f, err := os.Create(*tsv)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		tsvw = f
	}
	fmt.Fprintln(tsvw, "id\tkind\ttopic\tadapter\tverdict\tgot\twant\tours")
	type key struct{ adapter, verdict string }
	count := map[key]int{}
	fmt.Fprintf(mdw, "| id | argv | want (source) | ours | %s |\n|---|---|---|---|%s\n",
		strings.Join(names(), " | "), strings.Repeat("---|", len(adapters)))
	for _, c := range cases {
		mk := trees[c.Tree]
		want := render(mk(), c.Want)
		ours := ""
		if c.Ours != nil {
			ours = render(mk(), c.Ours)
		}
		row := fmt.Sprintf("| %s | `%s` | %s | %s |", c.ID, strings.Join(quoteAll(c.Argv), " "), want, ours)
		for _, a := range adapters {
			got := result(a, mk, c)
			v := verdict(got, c)
			count[key{a.name, v}]++
			row += " " + v + " |"
			fmt.Fprintf(tsvw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.ID, c.Kind, c.Topic, a.name, v, got, want, ours)
		}
		fmt.Fprintln(mdw, row)
	}
	stale := 0
	for _, c := range cases {
		v := verdict(result(adapters[0], trees[c.Tree], c), c)
		if why, ok := explained[c.ID]; (v == "neither") != ok {
			fmt.Printf("UNEXPLAINED %s: %s (explained: %q)\n", c.ID, v, why)
			stale++
		}
	}
	fmt.Printf("%d cases\n", len(cases))
	defer func() {
		if stale > 0 {
			os.Exit(1)
		}
	}()
	for _, a := range adapters {
		fmt.Printf("%-16s up %3d  ours %3d  neither %3d\n", a.name, count[key{a.name, "up"}], count[key{a.name, "ours"}], count[key{a.name, "neither"}])
	}
}

func names() []string {
	var n []string
	for _, a := range adapters {
		n = append(n, a.name)
	}
	return n
}

func quoteAll(l []string) []string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = s
		if s == "" || strings.ContainsAny(s, " |") {
			q[i] = fmt.Sprintf("%q", s)
		}
	}
	return q
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}

func validate(c Case) string {
	if _, ok := trees[c.Tree]; !ok {
		return "unknown tree " + c.Tree
	}
	if c.Kind != "run" && c.Kind != "complete" {
		return "kind must be run or complete"
	}
	if c.Src == "" || c.Lic == "" || c.Want == nil {
		return "src, lic and want are required"
	}
	if c.Ours != nil && c.Why == "" {
		return "ours needs why"
	}
	t := trees[c.Tree]()
	for _, o := range []*Out{c.Want, c.Ours} {
		if o == nil {
			continue
		}
		if (c.Kind == "complete") != (o.Kind == "complete") {
			return "a complete case wants kind complete"
		}
		if o.Kind == "complete" {
			continue
		}
		if !slices.ContainsFunc(t.Commands, func(k kit.Command) bool { return strings.Join(k.Path, " ") == o.Path }) {
			return fmt.Sprintf("path %q not in tree %q", o.Path, c.Tree)
		}
		switch o.Kind {
		case "run", "help", "version", "unknown-command", "unknown-flag", "missing-value", "flag-repeated", "bad-value", "arg-count":
		default:
			return "unknown outcome kind " + o.Kind
		}
	}
	return ""
}

// render prints a run outcome as kit.Outcome does, a completion as a summary.
func render(t *kit.Tree, o *Out) string {
	if o.Kind == "complete" {
		var p []string
		if o.Exact != nil {
			p = append(p, "exact ["+strings.Join(o.Exact, " ")+"]")
		}
		if len(o.Has) > 0 {
			p = append(p, "has "+strings.Join(o.Has, " "))
		}
		if len(o.Not) > 0 {
			p = append(p, "not "+strings.Join(o.Not, " "))
		}
		if o.Files != nil {
			p = append(p, fmt.Sprintf("files=%v", *o.Files))
		}
		if o.NoSpace != nil {
			p = append(p, fmt.Sprintf("nospace=%v", *o.NoSpace))
		}
		return strings.Join(p, "; ")
	}
	if o.Kind == "arg-count" {
		return fmt.Sprintf("arg-count [%s]", o.Path)
	}
	return kit.Want(t, o.Kind, o.Path, o.Args, o.Flags, o.Word)
}

// result is what the adapter did, in the form render prints.
func result(a adapter, mk func() *kit.Tree, c Case) (got string) {
	defer func() {
		if p := recover(); p != nil {
			got = fmt.Sprintf("panic: %v", p)
		}
	}()
	if c.Kind == "run" {
		got = kit.RunOn(a.a, mk, c.Argv)
		if strings.HasPrefix(got, "arg-count ") {
			got = got[:strings.Index(got, "]")+1]
		}
		return got
	}
	if _, calls, err := kit.CompleteOnce(a.a, mk(), c.Argv); err != nil || calls > 0 {
		return fmt.Sprintf("error: %v, %d commands ran", err, calls)
	}
	words, dir, err := a.comp(mk(), c.Argv)
	if err != nil {
		return "error: " + err.Error()
	}
	for i, w := range words {
		words[i], _, _ = strings.Cut(w, "\t")
	}
	slices.Sort(words)
	return fmt.Sprintf("[%s] files=%v nospace=%v", strings.Join(words, " "), dir&noFileComp == 0, dir&noSpace != 0)
}

func verdict(got string, c Case) string {
	switch {
	case matches(got, c.Want, c):
		return "up"
	case c.Ours != nil && matches(got, c.Ours, c):
		return "ours"
	}
	return "neither"
}

func matches(got string, o *Out, c Case) bool {
	if o.Kind != "complete" {
		return got == render(trees[c.Tree](), o)
	}
	if strings.HasPrefix(got, "error") || strings.HasPrefix(got, "panic") {
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
	if o.Exact != nil {
		e := slices.Sorted(slices.Values(o.Exact))
		if !slices.Equal(e, words) {
			return false
		}
	}
	if o.Files != nil && !strings.Contains(rest, fmt.Sprintf("files=%v", *o.Files)) {
		return false
	}
	if o.NoSpace != nil && !strings.Contains(rest, fmt.Sprintf("nospace=%v", *o.NoSpace)) {
		return false
	}
	return true
}
