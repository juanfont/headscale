package kit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Class says what a failing case means.
type Class string

const (
	Must    Class = "MUST"    // decided: a failure fails the adapter
	Observe Class = "OBSERVE" // not decided: record what the framework does
	Stretch Class = "STRETCH" // wanted, not required
)

// Outcome is what one run ended in, in a form the suite compares as text.
type Outcome struct {
	Kind  string // "run", "help", "version", or an ErrKind
	Path  []string
	Args  []string
	Flags map[string][]string
	Word  string
}

func (o Outcome) String() string {
	p := strings.Join(o.Path, " ")
	switch o.Kind {
	case "run":
		s := "run " + p + " " + quote(o.Args)
		for _, k := range slices.Sorted(maps.Keys(o.Flags)) {
			s += " " + k + "=" + quote(o.Flags[k])
		}
		return s
	case "help":
		return strings.TrimSpace("help " + p)
	case "version":
		return "version"
	}
	return fmt.Sprintf("%s [%s] %q", o.Kind, p, o.Word)
}

func quote(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = fmt.Sprintf("%q", s)
	}
	return "[" + strings.Join(q, " ") + "]"
}

type recKey struct{}

// recorder is per run and travels in the context, so runs share nothing.
type recorder struct {
	mu      sync.Mutex
	calls   int
	outcome string
	in      any
}

func withRecorder(ctx context.Context) (context.Context, *recorder) {
	r := &recorder{}
	return context.WithValue(ctx, recKey{}, r), r
}

// Constructors for expected outcomes.

func ran(path string, args []string, kv ...string) Outcome {
	o := Outcome{Kind: "run", Path: strings.Fields(path), Args: args, Flags: map[string][]string{}}
	for i := 0; i < len(kv); i += 2 {
		o.Flags[kv[i]] = append(o.Flags[kv[i]], kv[i+1])
	}
	return o
}

func help(path string) Outcome { return Outcome{Kind: "help", Path: strings.Fields(path)} }

func usage(k ErrKind, path, word string) Outcome {
	return Outcome{Kind: string(k), Path: strings.Fields(path), Word: word}
}

func seen() Outcome { return Outcome{} }

// sh splits a command line on spaces; ” is the empty word. No other quoting.
func sh(line string) []string {
	w := strings.Fields(line)
	for i := range w {
		if w[i] == "''" {
			w[i] = ""
		}
	}
	return w
}

type runCase struct {
	id    string
	class Class
	from  string
	argv  []string
	want  Outcome
}

type compCase struct {
	id        string
	class     Class
	from      string
	argv      []string
	has, not  []string
	wantFiles bool
}

var a1 = []string{"12"}

var runCases = []runCase{
	// The tree, aliases, groups.
	{"T01", Must, "R01", sh("nodes routes set 12 10.0.0.0/8"), ran("nodes routes set", []string{"12", "10.0.0.0/8"})},
	{"T02", Must, "R06", sh("nodes routes approve 12 10.0.0.0/8"), ran("nodes routes set", []string{"12", "10.0.0.0/8"})},
	{"T03", Must, "R06", sh("nodes rm 12"), ran("nodes delete", a1)},
	{"T04", Must, "R06", sh("nodes ls"), ran("nodes list", nil)},
	{"T05", Must, "R05", sh("users rm alice"), ran("users delete", []string{"alice"})},
	{"T06", Must, "R06", sh("auth keys approve x"), usage(UnknownCommand, "auth keys", "approve")},
	{"T07", Must, "R01", sh("auth keys create alice"), ran("auth keys create", []string{"alice"})},
	{"T08", Must, "R01", sh("api keys create"), ran("api keys create", nil)},
	{"T09", Must, "R04", sh("check config"), ran("check config", nil)},
	{"T10", Must, "R04", sh("check config /etc/hs.yaml"), ran("check config", []string{"/etc/hs.yaml"})},
	{"T11", Must, "R67", sh("serve"), ran("serve", nil)},
	{"T12", Must, "R52 D10", sh(""), help("")},
	{"T13", Must, "R03 D10", sh("nodes"), help("nodes")},
	{"T14", Must, "R03 D10", sh("nodes routes"), help("nodes routes")},
	{"T15", Must, "D10", sh("check"), help("check")},

	// Help at every level, and no help command.
	{"H01", Must, "R53", sh("-h"), help("")},
	{"H02", Must, "R53", sh("--help"), help("")},
	{"H03", Must, "R53", sh("nodes -h"), help("nodes")},
	{"H04", Must, "R53", sh("nodes routes --help"), help("nodes routes")},
	{"H05", Must, "R53", sh("nodes routes set -h"), help("nodes routes set")},
	{"H06", Must, "R53", sh("nodes delete --help"), help("nodes delete")},
	{"H07", Must, "R53", sh("nodes delete 12 -h"), help("nodes delete")},
	{"H08", Must, "R53", sh("nodes rm --help"), help("nodes delete")},
	{"H09", Must, "R53", sh("nodes routes approve -h"), help("nodes routes set")},
	{"H10", Must, "R53", sh("auth keys create alice --tags tag:a -h"), help("auth keys create")},
	{"H11", Must, "D8", sh("help"), usage(UnknownCommand, "", "help")},
	{"H12", Must, "D8", sh("help nodes"), usage(UnknownCommand, "", "help")},
	{"H13", Must, "D8", sh("nodes help"), usage(UnknownCommand, "nodes", "help")},
	{"H14", Observe, "R53", sh("nodes list --bogus -h"), seen()},
	{"H15", Observe, "R53", sh("nodes list -h --bogus"), seen()},
	{"H16", Observe, "R53", sh("nodes --help list"), seen()},
	{"H17", Observe, "R53", sh("-h nodes list"), seen()},

	// --version and version.
	{"V01", Must, "D7", sh("--version"), Outcome{Kind: "version"}},
	{"V02", Must, "D7", sh("version"), ran("version", nil)},
	{"V03", Must, "R19", sh("version -o json"), ran("version", nil, "output", "json")},
	{"V04", Observe, "D7", sh("nodes list --version"), seen()},

	// Flag syntax.
	{"F01", Must, "R15", sh("auth keys create alice --expiry 24h"), ran("auth keys create", []string{"alice"}, "expiry", "24h")},
	{"F02", Must, "R15", sh("auth keys create alice --expiry=24h"), ran("auth keys create", []string{"alice"}, "expiry", "24h")},
	{"F03", Must, "R16 D11", sh("nodes list -o json"), ran("nodes list", nil, "output", "json")},
	{"F04", Must, "R16 D11", sh("nodes list -o=json"), ran("nodes list", nil, "output", "json")},
	{"F05", Observe, "R16 D11", sh("nodes list -ojson"), seen()},
	{"F06", Must, "R17", sh("auth keys create alice -e 24h"), ran("auth keys create", []string{"alice"}, "expiry", "24h")},
	{"F07", Must, "R20", sh("nodes delete --force 12"), ran("nodes delete", a1, "force", "true")},
	{"F08", Must, "R20", sh("nodes delete 12 --force"), ran("nodes delete", a1, "force", "true")},
	{"F09", Must, "R20", sh("nodes routes set 12 -o json 10.0.0.0/8"), ran("nodes routes set", []string{"12", "10.0.0.0/8"}, "output", "json")},
	{"F10", Must, "R20 R25", sh("auth keys create --reusable alice -e 1h --tags tag:ci"), ran("auth keys create", []string{"alice"}, "expiry", "1h", "reusable", "true", "tags", "tag:ci")},
	{"F11", Must, "R23", sh("nodes set 12 --name ''"), ran("nodes set", a1, "name", "")},
	{"F12", Must, "R23", sh("nodes set 12 --name="), ran("nodes set", a1, "name", "")},
	{"F13", Must, "R24", sh("nodes set 12 -e 1d"), ran("nodes set", a1, "expiry", "1d")},
	{"F14", Must, "R21", sh("nodes list --sort -last-seen"), ran("nodes list", nil, "sort", "-last-seen")},
	{"F15", Must, "R21", sh("nodes list --sort=-last-seen"), ran("nodes list", nil, "sort", "-last-seen")},
	{"F16", Must, "R21", sh("nodes list --columns -ip"), ran("nodes list", nil, "columns", "-ip")},
	{"F17", Must, "R21", sh("nodes list --columns -ip,+hostname"), ran("nodes list", nil, "columns", "-ip,+hostname")},
	{"F18", Must, "R22", sh("nodes list --filter=owner=tag:ci"), ran("nodes list", nil, "filter", "owner=tag:ci")},
	{"F19", Must, "R22 R27", sh("nodes list --filter name:web,online=true --filter last-seen>30d --filter=expiry<7d"), ran("nodes list", nil, "filter", "name:web,online=true", "filter", "last-seen>30d", "filter", "expiry<7d")},
	{"F20", Must, "R12", sh("policy set -"), ran("policy set", []string{"-"})},
	{"F21", Must, "R12", sh("nodes delete hskey-auth-ab12cd-***"), ran("nodes delete", []string{"hskey-auth-ab12cd-***"})},
	{"F22", Must, "R26", sh("nodes routes set 12 ''"), ran("nodes routes set", []string{"12", ""})},
	{"F23", Must, "G05", sh("users delete -- --with-nodes"), ran("users delete", []string{"--with-nodes"})},
	{"F24", Must, "G05", sh("users delete --force -- -alice"), ran("users delete", []string{"-alice"}, "force", "true")},
	{"F25", Must, "R46", sh("api keys create -u alice --expiry 90d"), ran("api keys create", nil, "user", "alice", "expiry", "90d")},
	{"F26", Observe, "R21", sh("nodes set 12 --name -e"), seen()},
	{"F27", Observe, "R21", sh("nodes list --sort --filter x"), seen()},
	{"F28", Observe, "G21", sh("nodes list -ho json"), seen()},

	// Bool forms (D9).
	{"B01", Must, "D9", sh("nodes delete 12 --force=true"), ran("nodes delete", a1, "force", "true")},
	{"B02", Must, "D9", sh("nodes delete 12 --force=false"), ran("nodes delete", a1, "force", "false")},
	{"B03", Must, "D9", sh("nodes delete 12 --no-force"), usage(UnknownFlag, "nodes delete", "no-force")},
	{"B04", Observe, "D9", sh("nodes delete 12 --force=maybe"), seen()},
	{"B05", Observe, "D6", sh("nodes delete 12 --force --force"), seen()},

	// -c and -o before and after the subcommand (D3).
	{"G01", Must, "D3", sh("-c /etc/hs.yaml nodes list"), ran("nodes list", nil, "config", "/etc/hs.yaml")},
	{"G02", Must, "D3", sh("nodes list -c /etc/hs.yaml"), ran("nodes list", nil, "config", "/etc/hs.yaml")},
	{"G03", Must, "D3", sh("-o json nodes list"), ran("nodes list", nil, "output", "json")},
	{"G04", Must, "D3", sh("--config=/x nodes routes set 12 10.0.0.0/8"), ran("nodes routes set", []string{"12", "10.0.0.0/8"}, "config", "/x")},
	{"G05", Must, "D3 R20", sh("nodes delete 12 -c /x"), ran("nodes delete", a1, "config", "/x")},
	{"G06", Must, "D3", sh("-o json -c /x version"), ran("version", nil, "config", "/x", "output", "json")},
	{"G07", Must, "D3 R19", sh("check config -o json"), usage(UnknownFlag, "check config", "output")},
	{"G08", Must, "D3 R19", sh("-o json check config"), usage(UnknownFlag, "check config", "output")},
	{"G09", Must, "R19", sh("completion bash -c /x"), usage(UnknownFlag, "completion", "config")},
	{"G10", Must, "R19", sh("serve -o json"), usage(UnknownFlag, "serve", "output")},
	{"G11", Observe, "D3 D6", sh("-c /a nodes list -c /b"), seen()},

	// Lists and repeats (D6).
	{"L01", Must, "D6", sh("auth keys create alice --tags tag:a,tag:b"), ran("auth keys create", []string{"alice"}, "tags", "tag:a,tag:b")},
	{"L02", Must, "D6", sh("auth keys create alice --tags tag:a --tags tag:b"), usage(FlagRepeated, "auth keys create", "tags")},
	{"L03", Must, "D6", sh("nodes list -o json -o json"), usage(FlagRepeated, "nodes list", "output")},

	// Typed usage errors (D4, D5).
	{"E01", Must, "D4 D5", sh("nodez"), usage(UnknownCommand, "", "nodez")},
	{"E02", Must, "D4 D5", sh("nodes lst"), usage(UnknownCommand, "nodes", "lst")},
	{"E03", Must, "D4 D5", sh("nodes routes aprove 12 10.0.0.0/8"), usage(UnknownCommand, "nodes routes", "aprove")},
	{"E04", Must, "D4 D5", sh("auth keyz create alice"), usage(UnknownCommand, "auth", "keyz")},
	{"E05", Must, "D4 D3", sh("-c /x nodez"), usage(UnknownCommand, "", "nodez")},
	{"E06", Must, "D5 R08", sh("preauthkeys list"), usage(UnknownCommand, "", "preauthkeys")},
	{"E07", Must, "D5 R08", sh("node ls"), usage(UnknownCommand, "", "node")},
	{"E08", Must, "R09", sh("nodes authorize 12"), usage(UnknownCommand, "nodes", "authorize")},
	{"E09", Must, "D4", sh("nodes list --bogus"), usage(UnknownFlag, "nodes list", "bogus")},
	{"E10", Must, "R18", sh("nodes list --force"), usage(UnknownFlag, "nodes list", "force")},
	{"E11", Must, "R17", sh("auth keys create alice -r"), usage(UnknownFlag, "auth keys create", "r")},
	{"E12", Must, "G20", sh("auth keys create alice --exp 1h"), usage(UnknownFlag, "auth keys create", "exp")},
	{"E13", Must, "D4", sh("nodes list --sort"), usage(MissingValue, "nodes list", "sort")},
	{"E14", Must, "D4", sh("auth keys create alice -e"), usage(MissingValue, "auth keys create", "expiry")},
	{"E15", Must, "D4", sh("nodes list -o"), usage(MissingValue, "nodes list", "output")},
	{"E16", Must, "R32", sh("nodes delete 12 13"), usage(ArgCount, "nodes delete", "needs 1 argument, got 2")},
	{"E17", Must, "R32", sh("nodes delete"), usage(ArgCount, "nodes delete", "needs 1 argument, got 0")},
	{"E18", Must, "R32", sh("nodes routes set 12"), usage(ArgCount, "nodes routes set", "needs 2 arguments, got 1")},
	{"E19", Must, "R32", sh("check config a b"), usage(ArgCount, "check config", "takes at most 1 argument, got 2")},
	{"E20", Must, "R32", sh("nodes list extra"), usage(ArgCount, "nodes list", "takes no arguments, got 1")},
	{"E21", Observe, "D4", sh("--bogus nodes list"), seen()},
}

var compCases = []compCase{
	{"C01", Must, "D1 D8", sh("''"), []string{"serve", "version", "check", "completion", "nodes", "users", "auth", "api", "policy"}, []string{"help"}, false},
	{"C02", Must, "D1", sh("no"), []string{"nodes"}, []string{"users"}, false},
	{"C03", Must, "D1", sh("nodes ''"), []string{"list", "delete", "set", "routes"}, []string{"help"}, false},
	{"C04", Must, "D1", sh("nodes routes ''"), []string{"set"}, nil, false},
	{"C05", Must, "D1 R06", sh("nodes routes ap"), []string{"approve"}, nil, false},
	{"C06", Must, "D1", sh("auth keys c"), []string{"create"}, nil, false},
	{"C07", Must, "D1 D3", sh("-c /x nodes l"), []string{"list"}, nil, false},
	{"C08", Must, "D1 R60", sh("nodes list --"), []string{"--columns", "--sort", "--filter", "--list-columns", "--output", "--config"}, []string{"--force"}, false},
	{"C09", Must, "D1 R18", sh("users delete alice --"), []string{"--force", "--with-nodes"}, []string{"--columns"}, false},
	{"C10", Must, "D1", sh("auth keys create alice --"), []string{"--tags", "--expiry", "--reusable", "--description"}, []string{"--force", "--columns"}, false},
	{"C11", Must, "D1 R60", sh("nodes list -o ''"), []string{"json"}, nil, false},
	{"C12", Must, "D1 R60", sh("nodes list --columns ''"), []string{"id", "name", "owner", "last-seen"}, nil, false},
	{"C13", Must, "D1 R60", sh("nodes list --sort la"), []string{"last-seen"}, []string{"id"}, false},
	{"C14", Must, "D1 R60", sh("nodes list --filter ow"), []string{"owner"}, nil, false},
	{"C15", Must, "D1 R59", sh("completion ''"), []string{"bash", "zsh", "fish"}, nil, false},
	{"C16", Must, "D1", sh("policy set ''"), nil, nil, true},
	{"C17", Must, "D1", sh("check config ''"), nil, nil, true},
	{"C18", Stretch, "R60", sh("nodes list --columns id,na"), []string{"id,name"}, nil, false},
	{"C19", Stretch, "R60", sh("nodes list --columns +ho"), []string{"+hostname"}, nil, false},
	{"C20", Stretch, "R60", sh("nodes list --sort -la"), []string{"-last-seen"}, nil, false},
}

// Row is one line of the result table.
type Row struct {
	ID, From, Input, Want, Got, Status string
	Class                              Class
}

// Report is the result of one suite run.
type Report struct {
	Rows    []Row
	Elapsed time.Duration
}

// Run runs every case twice, all of them in parallel, each run with a fresh
// tree and context. It never fails; Conformance turns MUST failures into errors.
func Run(a Adapter) *Report {
	start := time.Now()
	rows := make([]Row, len(runCases)+len(compCases)+len(shells))
	var wg sync.WaitGroup
	for i, c := range runCases {
		wg.Go(func() { rows[i] = doRun(a, c) })
	}
	for i, c := range compCases {
		wg.Go(func() { rows[len(runCases)+i] = doComplete(a, c) })
	}
	for i, s := range shells {
		wg.Go(func() { rows[len(runCases)+len(compCases)+i] = doScript(a, s.name, s.class) })
	}
	wg.Wait()
	iso := Row{ID: "I01", Class: Must, From: "R49 R56 G26", Input: "every case twice, in parallel, fresh tree each",
		Want: "same outcome both times, no panic", Got: "ok", Status: "PASS"}
	for _, r := range rows {
		if strings.Contains(r.Got, " | second run: ") || strings.Contains(r.Got, "panic: ") {
			iso.Got, iso.Status = "differs or panics: "+r.ID, "FAIL"
			break
		}
	}
	return &Report{Rows: append(rows, iso), Elapsed: time.Since(start)}
}

func twice(f func() string) string {
	var got [2]string
	var wg sync.WaitGroup
	for k := range 2 {
		wg.Go(func() {
			defer func() {
				if p := recover(); p != nil {
					got[k] = fmt.Sprintf("panic: %v", p)
				}
			}()
			got[k] = f()
		})
	}
	wg.Wait()
	if got[0] != got[1] {
		return got[0] + " | second run: " + got[1]
	}
	return got[0]
}

func runOnce(a Adapter, argv []string) string {
	ctx, rec := withRecorder(context.Background())
	t := NewTree()
	in := strings.NewReader("y\n")
	var out, errb bytes.Buffer
	err := a.Run(ctx, t, slices.Clone(argv), Stdio{in, &out, &errb})
	var ue *UsageError
	got, wantOut := "", ""
	switch {
	case errors.As(err, &ue):
		o := Outcome{Kind: string(ue.Kind), Path: ue.Path, Word: ue.Word}
		if c, ok := t.find(ue.Path); ok {
			o.Path = c.Path
		}
		if ue.Kind != UnknownCommand && ue.Kind != ArgCount {
			o.Word = t.long(ue.Word)
		}
		got = o.String()
	case err != nil:
		got = "error: " + err.Error()
	case rec.outcome == "":
		got = "nothing: Exec was not called"
	default:
		got, wantOut = rec.outcome, rec.outcome+"\n"
	}
	if rec.calls > 1 {
		got += fmt.Sprintf(" (Exec called %d times)", rec.calls)
	}
	if out.String() != wantOut {
		got += fmt.Sprintf(" (stdout %q)", out.String())
	}
	if errb.Len() > 0 {
		got += fmt.Sprintf(" (stderr %q)", errb.String())
	}
	if in.Len() != 2 {
		got += " (stdin was read)"
	}
	return got
}

func doRun(a Adapter, c runCase) Row {
	r := Row{ID: c.id, Class: c.class, From: c.from, Input: line(c.argv), Got: twice(func() string { return runOnce(a, c.argv) })}
	switch {
	case c.class == Observe:
		r.Status = "SEEN"
	case r.Got == c.want.String():
		r.Want, r.Status = c.want.String(), "PASS"
	default:
		r.Want, r.Status = c.want.String(), "FAIL"
	}
	return r
}

const mismatch = " (does not match)"

func doComplete(a Adapter, c compCase) Row {
	got := twice(func() string {
		ctx, rec := withRecorder(context.Background())
		comp, err := a.Complete(ctx, NewTree(), slices.Clone(c.argv))
		if err != nil {
			return "error: " + err.Error() + mismatch
		}
		words := make([]string, len(comp.Words))
		for i, w := range comp.Words {
			words[i], _, _ = strings.Cut(w, "\t")
		}
		slices.Sort(words)
		s, ok := strings.Join(words, " "), rec.calls == 0
		if comp.Files {
			s += " +files"
		}
		if !ok {
			s += " (a command ran)"
		}
		for _, w := range c.has {
			ok = ok && slices.Contains(words, w)
		}
		for _, w := range c.not {
			ok = ok && !slices.Contains(words, w)
		}
		if !ok || c.wantFiles && !comp.Files {
			s += mismatch
		}
		return s
	})
	var want []string
	if len(c.has) > 0 {
		want = append(want, "has "+strings.Join(c.has, " "))
	}
	if len(c.not) > 0 {
		want = append(want, "not "+strings.Join(c.not, " "))
	}
	if c.wantFiles {
		want = append(want, "+files")
	}
	r := Row{ID: c.id, Class: c.class, From: c.from, Input: line(c.argv) + "<TAB>", Want: strings.Join(want, "; "), Got: got, Status: "PASS"}
	if strings.Contains(got, mismatch) || strings.Contains(got, " | second run: ") {
		r.Status = "FAIL"
	}
	return r
}

var shells = []struct {
	name  string
	class Class
}{{"bash", Must}, {"zsh", Must}, {"fish", Must}, {"powershell", Stretch}}

func doScript(a Adapter, shell string, class Class) Row {
	r := Row{ID: "S-" + shell, Class: class, From: "D1 D2 R59", Input: "Script(" + shell + ")",
		Want: "non-empty, names " + Program + ", syntax check passes", Status: "FAIL"}
	var b bytes.Buffer
	if err := a.Script(NewTree(), shell, &b); err != nil {
		r.Got = "error: " + err.Error()
		return r
	}
	if !strings.Contains(b.String(), Program) {
		r.Got = fmt.Sprintf("%d bytes, does not name %s", b.Len(), Program)
		return r
	}
	bin := shell
	if shell == "powershell" {
		bin = "pwsh"
	}
	if _, err := exec.LookPath(bin); err != nil {
		r.Got, r.Status = fmt.Sprintf("%d bytes; %s not installed, syntax not checked", b.Len(), bin), "SKIP"
		return r
	}
	cmd := exec.Command(bin, "-n")
	if shell == "powershell" {
		cmd = exec.Command(bin, "-NoProfile", "-Command",
			"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$null, [ref]$e); if ($e) { $e; exit 1 }")
	}
	cmd.Stdin = &b
	if out, err := cmd.CombinedOutput(); err != nil {
		r.Got = fmt.Sprintf("syntax check failed: %v %s", err, out)
		return r
	}
	r.Got, r.Status = "syntax ok", "PASS"
	return r
}

// line shows argv as a shell line.
func line(argv []string) string {
	s := Program
	for _, w := range argv {
		if w == "" || strings.ContainsAny(w, " <>|&;*$'\"\\()!?[]{}#~") {
			w = "'" + w + "'"
		}
		s += " " + w
	}
	return s
}

// Summary counts the rows by class and status.
func (r *Report) Summary() string {
	n := map[string]int{}
	for _, row := range r.Rows {
		n[string(row.Class)+" "+row.Status]++
		n[string(row.Class)]++
	}
	return fmt.Sprintf("MUST %d/%d pass (%d skipped) · STRETCH %d/%d · OBSERVE %d recorded · suite %s",
		n["MUST PASS"], n["MUST"], n["MUST SKIP"], n["STRETCH PASS"], n["STRETCH"], n["OBSERVE"], r.Elapsed.Round(time.Millisecond))
}

// Markdown renders the report as a table to paste into notes.
func (r *Report) Markdown(name string) string {
	cell := func(s string) string { return "`" + strings.ReplaceAll(s, "|", `\|`) + "`" }
	var b strings.Builder
	fmt.Fprintf(&b, "# Conformance: %s\n\n%s\n\n", name, r.Summary())
	b.WriteString("| ID | Class | From | Input | Want | Got | Result |\n| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, row := range r.Rows {
		want := row.Want
		if want != "" {
			want = cell(want)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", row.ID, row.Class, row.From, cell(row.Input), want, cell(row.Got), row.Status)
	}
	return b.String()
}

// Conformance is the one call an adapter's test makes. It writes the table
// to mdPath and fails t for every MUST case that failed.
func Conformance(t *testing.T, name string, a Adapter, mdPath string) {
	t.Helper()
	r := Run(a)
	if err := os.WriteFile(mdPath, []byte(r.Markdown(name)), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, row := range r.Rows {
		if row.Class == Must && row.Status == "FAIL" {
			t.Errorf("%s %s: want %s, got %s", row.ID, row.Input, row.Want, row.Got)
		}
	}
	t.Log(r.Summary())
}
