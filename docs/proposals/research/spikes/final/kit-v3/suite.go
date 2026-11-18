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
	Asked   Class = "CALL"    // v3: the assistant's call, not confirmed by the maintainer; held like MUST so a change shows
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

// noFiles (v2) lists the completion cases where offering files is wrong. An
// adapter that says "files" whenever its answer is empty fails these.
var noFiles = map[string]bool{"C01": true, "C03": true, "C12": true, "N01": true, "N04": true, "N05": true,
	"N08": true, "N09": true, "N10": true, "N11": true, "N16": true, "N18": true,
	"Q04": true, "Q05": true, "Q12": true, "Q13": true, "Q14": true, "Q15": true, "Q16": true, "Q21": true, "Q23": true, "Q25": true, "Q26": true, "Q27": true, "Q30": true, "Q31": true}

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
	{"H14", Must, "D19", sh("nodes list --bogus -h"), usage(UnknownFlag, "nodes list", "bogus")},
	{"H15", Must, "D19", sh("nodes list -h --bogus"), usage(UnknownFlag, "nodes list", "bogus")},
	{"H16", Asked, "001-Q4", sh("nodes --help list"), help("nodes list")},
	{"H17", Asked, "001-Q4", sh("-h nodes list"), help("nodes list")},
	// v3: D19, every flag mistake wins over -h; an argument mistake does not.
	{"H18", Must, "D19 L2", sh("api --version -h"), usage(UnknownFlag, "api", "version")},
	{"H19", Must, "D19 D26", sh("nodes delete 12 --force=maybe -h"), usage(BadValue, "nodes delete", "force")},
	{"H20", Must, "D19 D15", sh("nodes list -o a -o b -h"), usage(FlagRepeated, "nodes list", "output")},
	{"H21", Must, "D19 001-lists", sh("auth keys create alice --tags= -h"), usage(BadValue, "auth keys create", "tags")},
	{"H22", Must, "D35 D19", sh("nodes routes set 12 '' -h"), usage(BadValue, "nodes routes set", "routes")},
	{"H23", Must, "D35", sh("nodes delete 12 13 -h"), help("nodes delete")},

	// --version and version.
	{"V01", Must, "D7", sh("--version"), Outcome{Kind: "version"}},
	{"V02", Must, "D7", sh("version"), ran("version", nil)},
	{"V03", Must, "R19", sh("version -o json"), ran("version", nil, "output", "json")},
	{"V04", Asked, "D7", sh("nodes list --version"), usage(UnknownFlag, "nodes list", "version")},
	{"V05", Asked, "D7 call", sh("--version nodes list"), usage(UnknownFlag, "nodes list", "version")},
	{"V06", Asked, "D7 call", sh("--version x"), usage(UnknownCommand, "", "x")},
	{"V07", Asked, "D7 call", sh("--version -o json"), usage(NotAlone, "", "version")},
	{"V08", Asked, "D7 call D19", sh("--version -h"), usage(NotAlone, "", "version")},
	{"V09", Must, "D7 D15", sh("--version --version"), usage(FlagRepeated, "", "version")},
	{"V10", Asked, "D7 D26", sh("--version=false"), help("")},
	{"V11", Asked, "D7 B1", sh("nodes --version"), usage(UnknownFlag, "nodes", "version")},
	{"V12", Must, "D7 D26", sh("--version=1"), usage(BadValue, "", "version")},

	// Flag syntax.
	{"F01", Must, "R15", sh("auth keys create alice --expiry 24h"), ran("auth keys create", []string{"alice"}, "expiry", "24h")},
	{"F02", Must, "R15", sh("auth keys create alice --expiry=24h"), ran("auth keys create", []string{"alice"}, "expiry", "24h")},
	{"F03", Must, "R16 D11", sh("nodes list -o json"), ran("nodes list", nil, "output", "json")},
	{"F04", Must, "R16 D11", sh("nodes list -o=json"), ran("nodes list", nil, "output", "json")},
	{"F05", Observe, "R16 D11", sh("nodes list -ojson"), seen()}, // v3: D11 says no test fixes either way
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
	{"F22", Must, "001-lists", sh("nodes routes set 12 ''"), usage(BadValue, "nodes routes set", "routes")}, // v3: kit v2 ran it; 001 L404 refuses
	{"F23", Must, "G05", sh("users delete -- --with-nodes"), ran("users delete", []string{"--with-nodes"})},
	{"F24", Must, "G05", sh("users delete --force -- -alice"), ran("users delete", []string{"-alice"}, "force", "true")},
	{"F25", Must, "R46", sh("api keys create -u alice --expiry 90d"), ran("api keys create", nil, "user", "alice", "expiry", "90d")},
	{"F26", Must, "D20", sh("nodes set 12 --name -e"), ran("nodes set", a1, "name", "-e")},
	{"F27", Must, "D20", sh("nodes list --sort --filter x"), usage(ArgCount, "nodes list", "takes no arguments, got 1")},
	{"F28", Observe, "G21 D11", sh("nodes list -ho json"), seen()},

	// Bool forms (D9).
	{"B01", Must, "D9", sh("nodes delete 12 --force=true"), ran("nodes delete", a1, "force", "true")},
	{"B02", Must, "D9", sh("nodes delete 12 --force=false"), ran("nodes delete", a1, "force", "false")},
	{"B03", Must, "D9", sh("nodes delete 12 --no-force"), usage(UnknownFlag, "nodes delete", "no-force")},
	{"B04", Must, "D26", sh("nodes delete 12 --force=maybe"), usage(BadValue, "nodes delete", "force")},
	{"B06", Must, "D26", sh("nodes delete 12 --force=1"), usage(BadValue, "nodes delete", "force")},
	{"B07", Must, "D26", sh("nodes delete 12 --force=TRUE"), usage(BadValue, "nodes delete", "force")},
	{"B08", Must, "D26", sh("nodes delete 12 --force=t"), usage(BadValue, "nodes delete", "force")},
	{"B09", Must, "D26", sh("nodes delete 12 --force="), usage(BadValue, "nodes delete", "force")},
	{"B10", Must, "D26 L1", sh("nodes list -h=1"), usage(BadValue, "nodes list", "help")},
	{"B11", Must, "D9", sh("nodes delete 12 --force true"), usage(ArgCount, "nodes delete", "needs 1 argument, got 2")},
	{"B05", Must, "D15", sh("nodes delete 12 --force --force"), usage(FlagRepeated, "nodes delete", "force")},

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
	{"G11", Must, "D3 D15", sh("-c /a nodes list -c /b"), usage(FlagRepeated, "nodes list", "config")},

	// Lists and repeats (D6).
	{"L01", Must, "D6", sh("auth keys create alice --tags tag:a,tag:b"), ran("auth keys create", []string{"alice"}, "tags", "tag:a,tag:b")},
	{"L02", Must, "D6", sh("auth keys create alice --tags tag:a --tags tag:b"), usage(FlagRepeated, "auth keys create", "tags")},
	{"L03", Must, "D6", sh("nodes list -o json -o json"), usage(FlagRepeated, "nodes list", "output")},
	// v3: an empty list value is an error (001 "Lists as input", DECISIONS facts).
	{"L04", Must, "001-lists", sh("auth keys create alice --tags="), usage(BadValue, "auth keys create", "tags")},
	{"L05", Must, "001-lists", sh("nodes list --filter="), usage(BadValue, "nodes list", "filter")},
	{"L06", Must, "001-lists", sh("nodes list --columns ''"), usage(BadValue, "nodes list", "columns")},
	{"L07", Must, "001-lists", sh("nodes list --filter a --filter ''"), usage(BadValue, "nodes list", "filter")},
	{"L08", Must, "D6", sh("nodes list --filter a --filter b"), ran("nodes list", nil, "filter", "a", "filter", "b")},
	{"L09", Asked, "001-lists", sh("nodes list --columns id,,name"), usage(BadValue, "nodes list", "columns")},
	{"L10", Asked, "001-lists", sh("nodes routes set 12 a,,b"), usage(BadValue, "nodes routes set", "routes")},
	{"L11", Asked, "001-lists", sh("auth keys create alice --tags tag:a,"), usage(BadValue, "auth keys create", "tags")},
	{"L12", Asked, "R19", sh("nodes list -o="), usage(BadValue, "nodes list", "output")},
	{"L13", Must, "R23", sh("nodes set 12 --name="), ran("nodes set", a1, "name", "")},

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
	{"E21", Must, "D35", sh("--bogus nodes list"), usage(UnknownFlag, "", "bogus")},
	// v3: which mistake is reported when there are several.
	{"E22", Must, "D35", sh("nodes list -o a -o b --sort"), usage(FlagRepeated, "nodes list", "output")},
	{"E23", Must, "D35", sh("nodes list --sort a --sort b -o x -o y"), usage(FlagRepeated, "nodes list", "sort")},
	{"E24", Must, "D35", sh("nodes delete 12 13 --force=maybe"), usage(BadValue, "nodes delete", "force")},
	{"E25", Must, "D35", sh("nodez --bogus"), usage(UnknownCommand, "", "nodez")},
	{"E26", Must, "D35", sh("nodes lst --bogus"), usage(UnknownCommand, "nodes", "lst")},
	// v3: D35, the first mistake on the line, whatever its kind.
	{"P01", Must, "D35", sh("-o a -o b check config"), usage(UnknownFlag, "check config", "output")},
	{"P02", Must, "D35", sh("-c a -o j -c b check config"), usage(UnknownFlag, "check config", "output")},
	{"P03", Must, "D35 D26", sh("nodes delete 12 --force=x --bogus"), usage(BadValue, "nodes delete", "force")},
	{"P04", Must, "D35", sh("nodes delete 12 --bogus --force=x"), usage(UnknownFlag, "nodes delete", "bogus")},
	{"P05", Must, "D35", sh("nodes delete 12 13 --bogus"), usage(UnknownFlag, "nodes delete", "bogus")},
	{"P06", Must, "D35 D15", sh("-o a -o b nodez"), usage(FlagRepeated, "", "output")},
	{"P07", Must, "D35", sh("nodes list -o= --bogus"), usage(BadValue, "nodes list", "output")},
	{"P08", Must, "D35", sh("nodes routes set 12 '' --bogus"), usage(BadValue, "nodes routes set", "routes")},
	{"P09", Must, "D35", sh("nodes routes set 12 a --bogus=''"), usage(UnknownFlag, "nodes routes set", "bogus")},
	{"P10", Asked, "D35 D7", sh("-c x --version"), usage(NotAlone, "", "version")},
	{"P11", Must, "D35 D19", sh("nodes list -h -o a -o b"), usage(FlagRepeated, "nodes list", "output")},
	{"P12", Asked, "D35 X3", sh("nodes delete 12 --force --force=x"), usage(FlagRepeated, "nodes delete", "force")},

	// v2: "--" after a positional ends the flags there too (POSIX); one
	// framework keeps parsing flags behind it.
	{"D01", Must, "G05", sh("nodes delete 12 -- --force"), usage(ArgCount, "nodes delete", "needs 1 argument, got 2")},
	{"D02", Must, "G05", sh("nodes routes set 12 -- -o"), ran("nodes routes set", []string{"12", "-o"})},
	{"D03", Must, "G05 R53", sh("nodes routes set 12 -- -h"), ran("nodes routes set", []string{"12", "-h"})},
	{"D04", Must, "G05 D3", sh("-c /x nodes routes set 12 -- --config"), ran("nodes routes set", []string{"12", "--config"}, "config", "/x")},
	{"D05", Must, "G05", sh("nodes routes set 12 -- --"), ran("nodes routes set", []string{"12", "--"})},
	{"D06", Must, "G05", sh("nodes routes set 12 10.0.0.0/8 --"), ran("nodes routes set", []string{"12", "10.0.0.0/8"})},
	{"D07", Must, "G05 R32", sh("nodes list -- extra"), usage(ArgCount, "nodes list", "takes no arguments, got 1")},
	{"D08", Must, "G05 R32", sh("auth keys create alice -- --tags x"), usage(ArgCount, "auth keys create", "needs 1 argument, got 3")},

	// v2: too many arguments with flags between them is a count error, not a command error.
	{"A01", Must, "R32", sh("nodes delete 12 13 --force 14"), usage(ArgCount, "nodes delete", "needs 1 argument, got 3")},
	{"A02", Must, "R32", sh("nodes routes set 12 10.0.0.0/8 -o json extra"), usage(ArgCount, "nodes routes set", "needs 2 arguments, got 3")},
	{"A03", Must, "R32 D3", sh("check config a -c /x b"), usage(ArgCount, "check config", "takes at most 1 argument, got 2")},
	{"A04", Must, "R01", sh("nodes delete list"), ran("nodes delete", []string{"list"})},
	{"A05", Must, "R01", sh("users delete nodes"), ran("users delete", []string{"nodes"})},

	// v2: D15, every flag but --filter once.
	{"R01", Must, "D15", sh("nodes list -o json -o yaml"), usage(FlagRepeated, "nodes list", "output")},
	{"R02", Must, "D15 D3", sh("-o json nodes list -o yaml"), usage(FlagRepeated, "nodes list", "output")},
	{"R03", Must, "D15", sh("nodes list -o json --output yaml"), usage(FlagRepeated, "nodes list", "output")},
	{"R04", Must, "D15 D9", sh("nodes delete 12 --force=true --force"), usage(FlagRepeated, "nodes delete", "force")},
	{"R05", Must, "D15", sh("nodes set 12 --name a --name ''"), usage(FlagRepeated, "nodes set", "name")},
	{"R06", Must, "D15 D3", sh("--config=/a -c /b version"), usage(FlagRepeated, "version", "config")},

	// v2: globals before the subcommand, the decided spellings.
	{"G12", Must, "D3", sh("-c nodes nodes list"), ran("nodes list", nil, "config", "nodes")},
	{"G13", Must, "D3 D11", sh("-o=json nodes list"), ran("nodes list", nil, "output", "json")},
	{"G14", Must, "D3 D11", sh("-c=/x nodes list"), ran("nodes list", nil, "config", "/x")},
	{"G15", Must, "D3 R23", sh("-c '' nodes list"), ran("nodes list", nil, "config", "")},

	// v2: D11's rule applied to the other spellings it implies.
	{"X01", Observe, "D11", sh("auth keys create alice -e24h"), seen()},
	{"X02", Must, "facts", sh("nodes list -output json"), usage(UnknownFlag, "nodes list", "output")},
	{"X03", Must, "facts", sh("nodes list --o json"), usage(UnknownFlag, "nodes list", "output")},
	{"X04", Must, "facts", sh("nodes list --h"), usage(UnknownFlag, "nodes list", "help")},
	{"X05", Must, "facts", sh("nodes list -help"), usage(UnknownFlag, "nodes list", "help")},
	{"X06", Must, "facts", sh("auth keys create alice --exp=1h"), usage(UnknownFlag, "auth keys create", "exp")},

	// v2: a value that looks like help or like the end of flags (kit Q2 is open).
	{"O01", Must, "D20", sh("nodes set 12 --name -h"), ran("nodes set", a1, "name", "-h")},
	{"O02", Must, "D20", sh("nodes set 12 --name --"), ran("nodes set", a1, "name", "--")},
	{"O03", Asked, "D3", sh("nodes -c /x list"), ran("nodes list", nil, "config", "/x")},
	{"O04", Must, "facts D3", sh("nodes --force delete 12"), usage(UnknownFlag, "nodes", "force")},
	{"O05", Must, "D9", sh("nodes list --help=false"), ran("nodes list", nil, "help", "false")},
	{"O06", Asked, "call", sh("nodes --"), usage(UnknownCommand, "nodes", "--")},
	{"O07", Asked, "call", sh("-- nodes list"), usage(UnknownCommand, "", "--")},
	{"O08", Asked, "D3", sh("-c /x nodes"), help("nodes")},
	{"O09", Asked, "D10 D3", sh("-o json"), help("")},
	{"O10", Must, "R12", sh("nodes delete -"), ran("nodes delete", []string{"-"})},
	{"O11", Asked, "D4", sh("- nodes"), usage(UnknownCommand, "", "-")},
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

	// v2: D16, real names first; an alias only when no name fits.
	{"N01", Must, "D16", sh("nodes ''"), []string{"list", "delete", "set", "routes"}, []string{"ls", "rm"}, false},
	{"N02", Must, "D16", sh("nodes l"), []string{"list"}, []string{"ls"}, false},
	{"N03", Must, "D16", sh("nodes r"), []string{"routes"}, []string{"rm"}, false},
	{"N04", Must, "D16", sh("users ''"), []string{"delete"}, []string{"rm"}, false},
	{"N05", Must, "D16", sh("nodes routes ''"), []string{"set"}, []string{"approve"}, false},
	{"N06", Must, "D16 D3", sh("-c /x nodes l"), []string{"list"}, []string{"ls"}, false},
	{"N07", Must, "D16", sh("nodes rm 12 --f"), []string{"--force"}, nil, false},

	// v2: where files are wrong, and where they are wanted behind a flag value.
	{"N08", Must, "D1", sh("nodes delete ''"), nil, nil, false},
	{"N09", Must, "D1", sh("nodes list ''"), nil, nil, false},
	{"N10", Must, "D1 R59", sh("completion ''"), []string{"bash", "zsh", "fish"}, nil, false},
	{"N11", Must, "D1", sh("nodes delete 12 ''"), nil, nil, false},
	{"N12", Must, "D1 D3", sh("check config -c /x ''"), nil, nil, true},
	{"N13", Must, "D1 D3", sh("-c /x check config ''"), nil, nil, true},
	{"N14", Must, "D1", sh("policy set --dry-run ''"), nil, nil, true},

	// v2: Tab offers only the flags the command takes (D3/D18 refusals).
	{"N15", Must, "D1 D3", sh("check config --"), []string{"--config"}, []string{"--output"}, false},
	{"N16", Must, "D1 R19", sh("completion --"), nil, []string{"--config", "--output"}, false},
	{"N17", Must, "D1 R19", sh("serve --"), []string{"--config"}, []string{"--output"}, false},
	{"N18", Must, "D1 D3", sh("-o ''"), []string{"json"}, nil, false},

	// v2: values with a colon (bash splits words on ':').
	{"N19", Stretch, "R60", sh("auth keys create alice --tags tag:p"), []string{"tag:prod"}, nil, false},
	{"N20", Stretch, "R60", sh("auth keys create alice --tags tag:ci,tag:p"), []string{"tag:ci,tag:prod"}, nil, false},
	{"N21", Must, "G05", sh("nodes routes set 12 -- --"), nil, []string{"--output"}, false},

	// v3: D27, files for a flag marked as a path, nothing for other free text.
	{"Q01", Must, "D27", sh("-c ''"), nil, nil, true},
	{"Q02", Must, "D27", sh("nodes list --config ''"), nil, nil, true},
	{"Q03", Must, "D27", sh("nodes list --config="), nil, nil, true},
	{"Q04", Must, "D27", sh("nodes set 12 --name ''"), nil, nil, false},
	{"Q05", Must, "D27", sh("auth keys create alice --description ''"), nil, nil, false},
	// v3: D28, candidates carry the help text ("\t" kept here).
	{"Q06", Must, "D28", sh("nodes ''"), []string{"list\tList the nodes", "delete\tDelete a node", "routes\tManage the routes of a node"}, nil, false},
	{"Q07", Must, "D28", sh("nodes list --"), []string{"--output\tOutput format: json", "--config\tConfig file to use"}, nil, false},
	{"Q08", Must, "D28 D29", sh("nodes list -o"), []string{"-o\tOutput format: json"}, nil, false},
	// v3: D29, long names only on a lone dash; a short typed in full completes.
	{"Q09", Must, "D29", sh("nodes list -"), []string{"--output", "--config", "--help"}, []string{"-o", "-c", "-h"}, false},
	{"Q10", Must, "D29", sh("nodes list --"), []string{"--output"}, []string{"-o", "-c", "-h"}, false},
	{"Q11", Must, "D29", sh("nodes list -c"), []string{"-c"}, nil, false},
	// v3: D30, after a mistake Tab completes from the last command it understood, never files.
	{"Q12", Must, "D30", sh("nodez ''"), []string{"nodes", "serve"}, nil, false},
	{"Q13", Must, "D30", sh("nodes list --bogus --"), []string{"--columns"}, nil, false},
	{"Q14", Must, "D30", sh("nodes lst ''"), []string{"list", "delete"}, nil, false},
	{"Q15", Must, "D30", sh("-1 ''"), []string{"nodes"}, nil, false},
	{"Q16", Must, "D30", sh("nodes list --bogus ''"), nil, nil, false},
	// v3: D15, a flag already given is not offered again; --filter is.
	{"Q17", Must, "D15", sh("nodes list --sort id --"), []string{"--columns"}, []string{"--sort"}, false},
	{"Q18", Must, "D15 D3", sh("-o json nodes list --"), []string{"--columns"}, []string{"--output"}, false},
	{"Q19", Must, "D6", sh("nodes list --filter x --"), []string{"--filter"}, nil, false},
	{"Q20", Must, "D15", sh("serve -h --"), []string{"--config"}, []string{"--help"}, false},
	// v3: D20 on Tab, the word after a value flag is its value.
	{"Q21", Must, "D20", sh("-c -o ''"), []string{"nodes"}, []string{"json"}, false},
	{"Q22", Must, "D20", sh("nodes list --sort -- --"), []string{"--columns"}, []string{"--sort"}, false},
	{"Q23", Must, "G05", sh("nodes routes set 12 -- --output="), nil, []string{"json", "--output=json"}, false},
	{"Q24", Must, "D20", sh("nodes list --sort -"), nil, []string{"--columns"}, false},
	// v3: words that are no flag are not read as one (B5).
	{"Q25", Must, "facts", sh("nodes delete o ''"), nil, []string{"json"}, false},
	{"Q26", Must, "facts", sh("auth keys create alice ---tags="), nil, []string{"tag:ci", "---tags=tag:ci"}, false},
	// v3: the assistant's calls.
	{"Q27", Asked, "call", sh("nodes delete 12 --force="), nil, []string{"true", "false"}, false},
	{"Q28", Asked, "call", sh("-h no"), []string{"nodes"}, nil, false},
	{"Q29", Asked, "call", sh("nodes --"), []string{"--help"}, []string{"--output", "--config", "--version"}, false},
	{"Q30", Asked, "D15", sh("nodes list -o= --output="), nil, []string{"json"}, false},
	{"Q31", Asked, "D15", sh("nodes list -o json -o ''"), nil, []string{"json"}, false},
	{"Q32", Must, "D6", sh("nodes list --filter id --filter ow"), []string{"owner"}, nil, false},
	// v3: a + or - is completed only on lists that take signs (--columns, --sort).
	{"Q33", Asked, "call", sh("nodes list --filter -ow"), nil, []string{"-owner"}, false},
	{"Q34", Asked, "call", sh("auth keys create alice --tags +tag:p"), nil, []string{"+tag:prod"}, false},
	{"Q35", Must, "R60", sh("nodes list --columns id,-ho"), []string{"id,-hostname"}, nil, false},
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

func runOnce(a Adapter, argv []string) string { return runOnceCtx(a, argv, nil) }

func runOnceCtx(a Adapter, argv []string, hook func(Call)) string {
	ctx, rec := withRecorder(context.Background())
	if hook != nil {
		ctx = context.WithValue(ctx, rawKey{}, hook)
	}
	t := shared
	if !Shared {
		t = NewTree()
	}
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
		in := func(w string) bool { // v3: a wanted word with a "\t" must come with that help text (D28)
			return slices.Contains(words, w) || slices.Contains(comp.Words, w)
		}
		if comp.Files {
			s += " +files"
		}
		if !ok {
			s += " (a command ran)"
		}
		for _, w := range c.has {
			ok = ok && in(w)
		}
		for _, w := range c.not {
			ok = ok && !in(w)
		}
		if !ok || c.wantFiles && !comp.Files || noFiles[c.id] && comp.Files {
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
	if noFiles[c.id] {
		want = append(want, "no files")
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
	return fmt.Sprintf("MUST %d/%d pass (%d skipped) · CALL %d/%d · STRETCH %d/%d · OBSERVE %d recorded · suite %s",
		n["MUST PASS"], n["MUST"], n["MUST SKIP"], n["CALL PASS"], n["CALL"], n["STRETCH PASS"], n["STRETCH"], n["OBSERVE"], r.Elapsed.Round(time.Millisecond))
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
		if (row.Class == Must || row.Class == Asked) && row.Status == "FAIL" {
			t.Errorf("%s %s: want %s, got %s", row.ID, row.Input, row.Want, row.Got)
		}
	}
	t.Log(r.Summary())
}
