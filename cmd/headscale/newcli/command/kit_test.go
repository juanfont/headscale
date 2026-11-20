package command_test

// The conformance kit: the rules of the CLI proposal (pull request #3375),
// row by row, on Headscale's real tree. A row that names a command the tree
// does not have yet waits for it: it is reported as skipped, with the
// commands it waits for, and it runs as soon as they are in the tree.
// The kit's own tree of twelve commands (KitModel) says which commands a
// row names.

import (
	"bytes"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline"
	"github.com/stretchr/testify/require"
)

// Class says what a failing row means.
type Class string

const (
	// Must is decided by the proposal: a failure fails the test.
	Must Class = "MUST"
	// Observe is not decided: the row records what the CLI does.
	Observe Class = "OBSERVE"
	// Stretch is wanted, not required.
	Stretch Class = "STRETCH"
	// Asked is a call of the session that wrote the rules, not confirmed by
	// the maintainer; held like Must, so a change shows.
	Asked Class = "CALL"
)

// The kinds of mistake.
const (
	UnknownCommand = "unknown-command"
	UnknownFlag    = "unknown-flag"
	MissingValue   = "missing-value"
	FlagRepeated   = "flag-repeated"
	BadValue       = "bad-value"
	ArgCount       = "arg-count"
	NotAlone       = "not-alone"
)

// Outcome is what a line ends in: run, help, version or a mistake.
type Outcome struct {
	Kind  string
	Path  []string
	Args  []string
	Flags map[string][]string
	Word  string
}

func (o Outcome) String() string { return command.Want(o.Kind, o.Path, o.Args, o.Flags, o.Word) }

func ran(path string, args []string, kv ...string) Outcome {
	o := Outcome{Kind: "run", Path: strings.Fields(path), Args: args, Flags: map[string][]string{}}
	for i := 0; i < len(kv); i += 2 {
		o.Flags[kv[i]] = append(o.Flags[kv[i]], kv[i+1])
	}

	return o
}

func help(path string) Outcome { return Outcome{Kind: "help", Path: strings.Fields(path)} }

func usage(k, path, word string) Outcome {
	return Outcome{Kind: k, Path: strings.Fields(path), Word: word}
}

func seen() Outcome { return Outcome{} }

// sh splits a line at spaces; ” is the empty word.
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

// noFiles (v2) lists the completion cases where offering files is wrong. An
// adapter that says "files" whenever its answer is empty fails these.
var noFiles = map[string]bool{
	"C01": true, "C03": true, "C12": true, "N01": true, "N04": true, "N05": true,
	"N08": true, "N09": true, "N10": true, "N11": true, "N16": true, "N18": true,
	"Q04": true, "Q05": true, "Q12": true, "Q13": true, "Q14": true, "Q15": true, "Q16": true, "Q21": true, "Q23": true, "Q25": true, "Q26": true, "Q27": true, "Q30": true, "Q31": true,
}

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
	{"H20", Must, "D19 D15", sh("nodes list -o json -o json -h"), usage(FlagRepeated, "nodes list", "output")}, // v4: json, D49
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
	// The lists are the builder's, so --filter, the value of --sort, is a bad
	// one: no column has that name. F29 keeps the count with a value that is.
	{"F27", Must, "D20", sh("nodes list --sort --filter x"), usage(BadValue, "nodes list", "sort")},
	{"F28", Observe, "G21 D11", sh("nodes list -ho json"), seen()},
	{"F29", Must, "D20", sh("nodes list --sort -id x"), usage(ArgCount, "nodes list", "takes no arguments, got 1")},

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
	{"L08", Must, "D6", sh("nodes list --filter id=1 --filter name:a"), ran("nodes list", nil, "filter", "id=1", "filter", "name:a")},
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
	{"E22", Must, "D35", sh("nodes list -o json -o json --sort"), usage(FlagRepeated, "nodes list", "output")}, // v4: json, D49
	{"E23", Must, "D35", sh("nodes list --sort id --sort name -o x -o y"), usage(FlagRepeated, "nodes list", "sort")},
	{"E24", Must, "D35", sh("nodes delete 12 13 --force=maybe"), usage(BadValue, "nodes delete", "force")},
	{"E25", Must, "D35", sh("nodez --bogus"), usage(UnknownCommand, "", "nodez")},
	{"E26", Must, "D35", sh("nodes lst --bogus"), usage(UnknownCommand, "nodes", "lst")},
	{"E27", Must, "D35", sh("nodes list --sort a --sort b"), usage(BadValue, "nodes list", "sort")},
	// v3: D35, the first mistake on the line, whatever its kind.
	{"P01", Must, "D35", sh("-o a -o b check config"), usage(UnknownFlag, "check config", "output")},
	{"P02", Must, "D35", sh("-c a -o j -c b check config"), usage(UnknownFlag, "check config", "output")},
	{"P03", Must, "D35 D26", sh("nodes delete 12 --force=x --bogus"), usage(BadValue, "nodes delete", "force")},
	{"P04", Must, "D35", sh("nodes delete 12 --bogus --force=x"), usage(UnknownFlag, "nodes delete", "bogus")},
	{"P05", Must, "D35", sh("nodes delete 12 13 --bogus"), usage(UnknownFlag, "nodes delete", "bogus")},
	{"P06", Must, "D35 D15", sh("-o json -o json nodez"), usage(FlagRepeated, "", "output")}, // v4: json, D49
	{"P07", Must, "D35", sh("nodes list -o= --bogus"), usage(BadValue, "nodes list", "output")},
	{"P08", Must, "D35", sh("nodes routes set 12 '' --bogus"), usage(BadValue, "nodes routes set", "routes")},
	{"P09", Must, "D35", sh("nodes routes set 12 a --bogus=''"), usage(UnknownFlag, "nodes routes set", "bogus")},
	{"P10", Asked, "D35 D7", sh("-c x --version"), usage(NotAlone, "", "version")},
	{"P11", Must, "D35 D19", sh("nodes list -h -o json -o json"), usage(FlagRepeated, "nodes list", "output")}, // v4: json, D49
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
	{"G12", Must, "D3", sh("-c nodes nodes list"), ran("nodes list", nil, "config", "nodes")}, //nolint:dupword // the value is a command word
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

	// v4: D49, --output takes only json. A wrong format is a bad value at its
	// flag, so it is placed on the line like every other mistake (D35).
	{"J01", Must, "D49 D35", sh("nodes list -o a -o b"), usage(BadValue, "nodes list", "output")},
	{"J02", Must, "D49", sh("nodes list -o yaml"), usage(BadValue, "nodes list", "output")},
	{"J03", Must, "D49", sh("nodes list --output=JSON"), usage(BadValue, "nodes list", "output")},
	{"J04", Must, "D49 D3", sh("-o yaml nodes list"), usage(BadValue, "nodes list", "output")},
	{"J05", Must, "D49 D3", sh("-o yaml"), usage(BadValue, "", "output")},
	{"J06", Must, "D49 D35", sh("nodes list -o a -o b --sort"), usage(BadValue, "nodes list", "output")},
	{"J07", Must, "D49 D19", sh("nodes list -o a -o b -h"), usage(BadValue, "nodes list", "output")},
	{"J08", Must, "D49 D35", sh("-o a -o b nodez"), usage(BadValue, "", "output")},
	{"J09", Must, "D49 D19", sh("nodes list -h -o a -o b"), usage(BadValue, "nodes list", "output")},
	{"J10", Must, "D49 D35", sh("nodes list --bogus -o yaml"), usage(UnknownFlag, "nodes list", "bogus")},
	{"J11", Must, "D49 D35", sh("nodes delete 12 13 -o yaml"), usage(BadValue, "nodes delete", "output")},
	{"J12", Must, "D49 D15", sh("nodes list -o json -o yaml"), usage(FlagRepeated, "nodes list", "output")},
	{"J13", Must, "D49 D3", sh("-o yaml check config"), usage(UnknownFlag, "check config", "output")},
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

// line shows argv as a shell line.
func line(argv []string) string {
	s := append(make([]string, 0, 1+len(argv)), "headscale")

	for _, w := range argv {
		if w == "" || strings.ContainsAny(w, " <>|&;*$'\"\\()!?[]{}#~") {
			w = "'" + w + "'"
		}

		s = append(s, w)
	}

	return strings.Join(s, " ")
}

// kit holds the real tree and the kit's own, built once.
type kit struct {
	real, model *command.Tree
}

// waits names the commands of the kit's tree that a row reaches or
// offers and that the real tree does not have.
func (k kit) waits(words []string, also ...string) []string {
	var named []string

	if p := k.model.Reached(words); p != "" {
		named = append(named, p)
	}

	for _, p := range also {
		if p != "" && k.model.Reached(strings.Fields(p)) == p {
			named = append(named, p)
		}
	}

	var out []string

	for _, p := range named {
		if k.real.Reached(strings.Fields(p)) != p && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}

	return out
}

// twice runs f twice at once: a tree is shared by runs in parallel, and
// the same line gives the same answer.
func twice(tb testing.TB, f func() string) string {
	tb.Helper()

	var (
		got [2]string
		wg  sync.WaitGroup
	)

	for i := range 2 {
		wg.Go(func() { got[i] = f() })
	}

	wg.Wait()
	require.Equal(tb, got[0], got[1], "the second run differs")

	return got[0]
}

// failing are rows that the CLI fails for a known reason. Such a row is
// kept as it is and reported; it fails the test once it passes, so the
// list stays true. What it gives instead is in the record of its test
// (testdata/kit-*.tsv), exactly, so that any other answer fails too.
var failing = map[string]string{
	"Q07": "the help texts of --output and --config are 001's (\"Output format: json (the API object)\", \"Config file\"), not the kit's",
	"Q08": "the help text of -o is 001's (\"Output format: json (the API object)\"), not the kit's",
}

// judge fails the row when its class says a failure counts, and says
// what the record holds for it: "pass", or the class of a row that does
// not pass and the exact answer.
func judge(tb testing.TB, id string, class Class, ok bool, answer, msg string) string {
	tb.Helper()

	why, known := failing[id]

	switch {
	case known && ok:
		tb.Errorf("passes now; take it out of failing (%s)", why)
	case known:
		tb.Logf("fails for a known reason: %s\n%s", why, msg)

		return "fails\t" + answer
	case class == Observe:
		tb.Logf("seen: %s", msg)

		return "seen\t" + answer
	case ok:
	case class == Stretch:
		tb.Logf("not reached (stretch): %s", msg)

		return "stretch\t" + answer
	default:
		tb.Error(msg)

		return "FAILS\t" + answer
	}

	return "pass"
}

// kits are the trees the rows run on: Headscale's, and the kit's own,
// which has every command a row names, so every row runs on the builder
// today.
func kits(tb testing.TB) map[string]kit {
	tb.Helper()

	model := command.KitModel(tb, newcli.Tree())

	return map[string]kit{"headscale": {real: newcli.Tree(), model: model}, "model": {real: model, model: model}}
}

// record keeps what every row of a test gave on each tree and, once all
// ran, compares it with path: a row that starts or stops waiting, goes
// away or changes its known failure is a diff to read.
type record struct {
	mu   sync.Mutex
	rows map[string]string // tree, tab, id -> status
}

func newRecord(tb testing.TB, path string, trees []string, ids []string) *record {
	tb.Helper()

	r := &record{rows: map[string]string{}}

	tb.Cleanup(func() {
		r.mu.Lock()
		defer r.mu.Unlock()

		// A run of some rows (-run) has nothing to compare.
		if len(r.rows) != len(trees)*len(ids) {
			return
		}

		var head, body strings.Builder

		for _, tree := range trees {
			count := map[string]int{}

			for _, id := range ids {
				s := r.rows[tree+"\t"+id]
				kind, _, _ := strings.Cut(s, "\t")
				count[kind]++

				body.WriteString(tree + "\t" + id + "\t" + s + "\n")
			}

			fmt.Fprintf(&head, "# %s: %d rows:", tree, len(ids))

			for _, k := range slices.Sorted(maps.Keys(count)) {
				fmt.Fprintf(&head, " %s %d", k, count[k])
			}

			head.WriteString("\n")
		}

		command.Golden(tb, path, head.String()+body.String())
	})

	return r
}

func (r *record) set(tree, id, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rows[tree+"\t"+id] = status
}

// kitTest runs each row on each kit tree and records it. row gives the
// status of the row; a row that waits for commands is skipped.
func kitTest(t *testing.T, path string, ids []string, row func(*testing.T, kit, int) string) {
	t.Helper()

	trees := kits(t)
	rec := newRecord(t, path, slices.Sorted(maps.Keys(trees)), ids)

	for name, k := range trees {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for i, id := range ids {
				t.Run(id, func(t *testing.T) {
					t.Parallel()

					s := row(t, k, i)
					rec.set(name, id, s)

					if w, ok := strings.CutPrefix(s, "waits\t"); ok {
						t.Skipf("waits for %s", w)
					}
				})
			}
		})
	}
}

func waits(w []string) string { return "waits\t" + strings.Join(w, ", ") }

func TestKitRun(t *testing.T) {
	t.Parallel()

	ids := make([]string, len(runCases))
	for i, c := range runCases {
		ids[i] = c.id
	}

	kitTest(t, "testdata/kit-run.tsv", ids, func(t *testing.T, k kit, i int) string {
		t.Helper()

		c := runCases[i]
		if w := k.waits(c.argv, strings.Join(c.want.Path, " ")); len(w) > 0 {
			return waits(w)
		}

		got := twice(t, func() string { return command.Outcome(k.real, c.argv) })

		return judge(t, c.id, c.class, got == c.want.String(), got, line(c.argv)+"\n got  "+got+"\n want "+c.want.String())
	})
}

func TestKitTab(t *testing.T) {
	t.Parallel()

	ids := make([]string, len(compCases))
	for i, c := range compCases {
		ids[i] = c.id
	}

	kitTest(t, "testdata/kit-tab.tsv", ids, func(t *testing.T, k kit, i int) string {
		t.Helper()

		c := compCases[i]
		words := c.argv[:len(c.argv)-1]
		reached := k.model.Reached(words)

		offered := make([]string, 0, len(c.has))

		for _, w := range c.has {
			name, _, _ := strings.Cut(w, "\t")
			offered = append(offered, strings.TrimSpace(reached+" "+name))
		}

		if w := k.waits(words, offered...); len(w) > 0 {
			return waits(w)
		}

		got := twice(t, func() string {
			var out bytes.Buffer

			code := command.Run(k.real, append([]string{"__complete"}, c.argv...), command.Env{Stdout: &out, Stderr: &out})
			if code != 0 {
				return "exit code " + out.String()
			}

			return out.String()
		})

		lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
		cands, dir := lines[:len(lines)-1], lines[len(lines)-1]
		d, err := strconv.Atoi(strings.TrimPrefix(dir, ":"))
		files := err == nil && cmdline.Directive(d)&cmdline.NoFiles == 0

		var cut []string

		for _, w := range cands {
			name, _, _ := strings.Cut(w, "\t")
			cut = append(cut, name)
		}

		// A wanted word with a tab must come with that help text.
		in := func(w string) bool { return slices.Contains(cut, w) || slices.Contains(cands, w) }
		ok := err == nil

		for _, w := range c.has {
			ok = ok && in(w)
		}

		for _, w := range c.not {
			ok = ok && !in(w)
		}

		ok = ok && (!c.wantFiles || files) && (!noFiles[c.id] || !files)

		// The answer as the script gets it, help texts and directive included.
		return judge(t, c.id, c.class, ok, strconv.Quote(got), line(c.argv)+"<TAB>\n got  "+strings.Join(cands, " | ")+" "+dir+
			"\n want has "+strings.Join(c.has, " ")+"; not "+strings.Join(c.not, " ")+
			map[bool]string{true: "; files", false: ""}[c.wantFiles]+map[bool]string{true: "; no files", false: ""}[noFiles[c.id]])
	})
}

// beyondKit are the commands of Headscale that the kit's tree does not
// have. A kit command that Headscale gets under another name would leave
// its rows waiting for ever; here it is a command of neither list.
var beyondKit = []string{
	"api whoami", "debug", "debug health", "users list", "users get", "users create", "users set",
	"nodes get", "nodes expire", "nodes update-client", "nodes routes list", "nodes routes clear", "nodes tags", "nodes tags list", "nodes tags set",
}

func TestKitKnowsHeadscale(t *testing.T) {
	t.Parallel()

	model := command.KitModel(t, newcli.Tree())
	paths := command.Paths(newcli.Tree())

	for _, p := range paths {
		inKit := model.Reached(strings.Fields(p)) == p
		if inKit == slices.Contains(beyondKit, p) {
			t.Errorf("%q: a command of Headscale is either in the kit's tree or in beyondKit, not both or neither", p)
		}
	}

	for _, p := range beyondKit {
		require.Contains(t, paths, p, "beyondKit names a command Headscale does not have")
	}
}

// TestKitScripts: each script names headscale and its shell reads it.
// A shell that is not installed is skipped.
func TestKitScripts(t *testing.T) {
	t.Parallel()

	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			t.Parallel()

			var out, errb bytes.Buffer

			require.Equal(t, 0, command.Run(newcli.Tree(), []string{"completion", shell}, command.Env{Stdout: &out, Stderr: &errb}), errb.String())
			require.Contains(t, out.String(), "headscale")

			cmd := exec.Command(shell, "-n") //nolint:noctx // a syntax check
			if shell == "powershell" {
				cmd = exec.Command("pwsh", "-NoProfile", "-Command", //nolint:noctx // a syntax check
					"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$null, [ref]$e); if ($e) { $e; exit 1 }")
			}

			_, err := exec.LookPath(cmd.Args[0])
			if err != nil {
				t.Skipf("%s is not installed", cmd.Args[0])
			}

			cmd.Stdin = &out
			b, err := cmd.CombinedOutput()
			require.NoError(t, err, string(b))
		})
	}
}

// TestShellLines holds ../testdata/shells/lines.txt, the lines of the
// real-shell Tab job, to the trees: a line that waits names a command of
// the kit's tree that Headscale's lacks, and fails here once Headscale has
// it, so that it is made active; an active line reaches only commands
// Headscale has.
func TestShellLines(t *testing.T) {
	t.Parallel()

	b, err := os.ReadFile("../testdata/shells/lines.txt")
	require.NoError(t, err)

	hs, model := newcli.Tree(), command.KitModel(t, newcli.Tree())
	n := 0

	for row := range strings.Lines(string(b)) {
		row = strings.TrimSuffix(row, "\n")
		if row == "" || strings.HasPrefix(row, "#") {
			continue
		}

		n++

		typed, waits, waiting := strings.Cut(row, "\twaits ")
		before, ok := strings.CutPrefix(typed, "headscale ")
		require.True(t, ok && strings.HasSuffix(typed, "|"), "a line is headscale, the words, then |: %q", row)

		if waiting {
			require.Equal(t, waits, model.Reached(strings.Fields(waits)), "%q waits for %q, which is no command of the kit's tree", typed, waits)
			require.NotEqual(t, waits, hs.Reached(strings.Fields(waits)), "%q waits for %q, which is in the tree now: drop the waits", typed, waits)

			continue
		}

		// The words before the one under the cursor.
		words := strings.Fields(strings.TrimSuffix(before, "|"))
		if !strings.HasSuffix(before, " |") && len(words) > 0 {
			words = words[:len(words)-1]
		}

		p := model.Reached(words)
		require.Equal(t, p, hs.Reached(strings.Fields(p)), "%q reaches %q, which Headscale lacks: it waits for it", typed, p)
	}

	require.Positive(t, n)
}
