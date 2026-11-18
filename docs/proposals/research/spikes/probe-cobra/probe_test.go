package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type result struct {
	parsed *Parsed
	help   []string
	err    error
	stdout string
	stderr string
}

func run(args ...string) result {
	var out, errb bytes.Buffer
	var r result
	env := &Env{Stdout: &out, Stderr: &errb}
	env.Help = func(p []string) { r.help = append([]string{}, p...); fmt.Fprintf(&out, "HELP %v\n", p) }
	env.Run = func(_ context.Context, p Parsed) error { r.parsed = &p; return nil }
	r.err = Execute(context.Background(), demoSpecs, env, args)
	r.stdout, r.stderr = out.String(), errb.String()
	return r
}

func flagErr(t *testing.T, r result) *FlagError {
	t.Helper()
	var fe *FlagError
	if !errors.As(r.err, &fe) {
		t.Fatalf("want FlagError, got %T %v (help=%v parsed=%+v)", r.err, r.err, r.help, r.parsed)
	}
	return fe
}

func cmdErr(t *testing.T, r result) *UnknownCommandError {
	t.Helper()
	var ce *UnknownCommandError
	if !errors.As(r.err, &ce) {
		t.Fatalf("want UnknownCommandError, got %T %v (help=%v parsed=%+v)", r.err, r.err, r.help, r.parsed)
	}
	return ce
}

func ran(t *testing.T, r result, path string, args ...string) *Parsed {
	t.Helper()
	if r.err != nil || r.parsed == nil {
		t.Fatalf("want run of %q, got err=%v help=%v", path, r.err, r.help)
	}
	if got := strings.Join(r.parsed.Path, " "); got != path {
		t.Fatalf("path %q, want %q", got, path)
	}
	if args == nil {
		args = []string{}
	}
	if len(r.parsed.Args) != 0 || len(args) != 0 {
		if !reflect.DeepEqual(r.parsed.Args, args) {
			t.Fatalf("args %q, want %q", r.parsed.Args, args)
		}
	}
	if r.stderr != "" {
		t.Fatalf("stderr not empty: %q", r.stderr)
	}
	return r.parsed
}

func val(p *Parsed, name string) (bool, []string) { v := p.Flags[name]; return v.Given, v.Values }

func TestProbe(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		check func(t *testing.T, r result)
	}{
		// R01, R04, R05, R06: tree, hyphens, aliases per command.
		{"R01 depth 3", []string{"api", "oauth-clients", "delete", "c9f2", "--force"}, func(t *testing.T, r result) {
			p := ran(t, r, "api oauth-clients delete", "c9f2")
			if g, _ := val(p, "force"); !g {
				t.Fatal("force not given")
			}
		}},
		{"R06 rm alias", []string{"nodes", "rm", "12"}, func(t *testing.T, r result) { ran(t, r, "nodes delete", "12") }},
		{"R06 approve alias", []string{"nodes", "routes", "approve", "12", "10.0.0.0/8"}, func(t *testing.T, r result) {
			ran(t, r, "nodes routes set", "12", "10.0.0.0/8")
		}},
		{"R06 no group alias", []string{"node", "ls"}, func(t *testing.T, r result) {
			ce := cmdErr(t, r)
			if ce.Word != "node" || len(ce.Path) != 0 {
				t.Fatalf("%+v", ce)
			}
		}},
		// D5: unknown command, typed, with path; removed command with its old flags.
		{"D5 unknown sub", []string{"nodes", "register", "--user", "x", "--key", "y"}, func(t *testing.T, r result) {
			ce := cmdErr(t, r)
			if ce.Word != "register" || strings.Join(ce.Path, " ") != "nodes" {
				t.Fatalf("%+v", ce)
			}
		}},
		{"D5 unknown sub, flag first", []string{"nodes", "-c", "x", "lst"}, func(t *testing.T, r result) {
			ce := cmdErr(t, r)
			if ce.Word != "lst" {
				t.Fatalf("%+v", ce)
			}
		}},
		{"R09 reserved", []string{"nodes", "authorize", "12"}, func(t *testing.T, r result) { cmdErr(t, r) }},
		{"R08 old top", []string{"preauthkeys", "list"}, func(t *testing.T, r result) {
			if ce := cmdErr(t, r); ce.Word != "preauthkeys" {
				t.Fatalf("%+v", ce)
			}
		}},
		{"unknown flag on group", []string{"nodes", "--bogus"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "bogus" || fe.Reason != "unknown" {
				t.Fatalf("%+v", fe)
			}
		}},
		// D8: no help command.
		{"D8 help is unknown", []string{"help", "nodes"}, func(t *testing.T, r result) {
			if ce := cmdErr(t, r); ce.Word != "help" {
				t.Fatalf("%+v", ce)
			}
		}},
		// R52, R53, G15: help is ours.
		{"R52 no args", nil, func(t *testing.T, r result) {
			if r.err != nil || r.help == nil || len(r.help) != 0 {
				t.Fatalf("%+v", r)
			}
		}},
		{"R53 help wins over args", []string{"nodes", "delete", "--help"}, func(t *testing.T, r result) {
			if r.err != nil || strings.Join(r.help, " ") != "nodes delete" || r.parsed != nil {
				t.Fatalf("%+v", r)
			}
		}},
		{"R53 -h in the middle", []string{"nodes", "set", "12", "-h", "--name", "x"}, func(t *testing.T, r result) {
			if strings.Join(r.help, " ") != "nodes set" {
				t.Fatalf("%+v", r)
			}
		}},
		{"G15 group alone", []string{"nodes", "routes"}, func(t *testing.T, r result) {
			if r.err != nil || strings.Join(r.help, " ") != "nodes routes" {
				t.Fatalf("%+v", r)
			}
		}},
		{"-h before subcommand", []string{"-h", "nodes", "list"}, func(t *testing.T, r result) {
			if strings.Join(r.help, " ") != "nodes list" {
				t.Fatalf("%+v", r)
			}
		}},
		// D7.
		{"D7 --version", []string{"--version"}, func(t *testing.T, r result) {
			if r.err != nil || r.stdout != "headscale vTEST\n" {
				t.Fatalf("%+v", r)
			}
		}},
		{"D7 --version only on root", []string{"nodes", "list", "--version"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "version" {
				t.Fatalf("%+v", fe)
			}
		}},
		// R12, R11: odd positionals.
		{"R12 dash positional", []string{"policy", "set", "-"}, func(t *testing.T, r result) { ran(t, r, "policy set", "-") }},
		{"R12 key with stars", []string{"nodes", "delete", "hskey-auth-ab12cd-***"}, func(t *testing.T, r result) {
			ran(t, r, "nodes delete", "hskey-auth-ab12cd-***")
		}},
		{"R26 empty positional", []string{"nodes", "routes", "set", "12", ""}, func(t *testing.T, r result) {
			ran(t, r, "nodes routes set", "12", "")
		}},
		{"G05 double dash", []string{"users", "create", "--", "-x"}, func(t *testing.T, r result) { ran(t, r, "users create", "-x") }},
		// R16 short forms.
		{"R16 -o json", []string{"nodes", "list", "-o", "json"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "output"); v[0] != "json" {
				t.Fatal(v)
			}
		}},
		{"R16 -ojson", []string{"nodes", "list", "-ojson"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "output"); v[0] != "json" {
				t.Fatal(v)
			}
		}},
		{"R16 -o=json", []string{"nodes", "list", "-o=json"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "output"); v[0] != "json" {
				t.Fatal(v)
			}
		}},
		// R20 interspersed.
		{"R20 flag before arg", []string{"nodes", "delete", "--force", "12"}, func(t *testing.T, r result) { ran(t, r, "nodes delete", "12") }},
		// R21 values starting with '-'.
		{"R21 --sort -last-seen", []string{"nodes", "list", "--sort", "-last-seen"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "sort"); v[0] != "-last-seen" {
				t.Fatal(v)
			}
		}},
		{"R21 --columns -ip,-os", []string{"nodes", "list", "--columns", "-ip,-os"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "columns"); v[0] != "-ip,-os" {
				t.Fatal(v)
			}
		}},
		{"R21 -e -1d", []string{"nodes", "set", "1", "-e", "-1d"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes set", "1"), "expiry"); v[0] != "-1d" {
				t.Fatal(v)
			}
		}},
		// R22.
		{"R22 --filter=owner=tag:ci", []string{"nodes", "list", "--filter=owner=tag:ci", "--filter", "last-seen>30d"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "filter"); !reflect.DeepEqual(v, []string{"owner=tag:ci", "last-seen>30d"}) {
				t.Fatal(v)
			}
		}},
		// R23 / C5: given empty vs not given.
		{"R23 --name empty", []string{"nodes", "set", "12", "--name", ""}, func(t *testing.T, r result) {
			if g, v := val(ran(t, r, "nodes set", "12"), "name"); !g || v[0] != "" {
				t.Fatal(g, v)
			}
		}},
		{"R23 --name=", []string{"nodes", "set", "12", "--name="}, func(t *testing.T, r result) {
			if g, v := val(ran(t, r, "nodes set", "12"), "name"); !g || v[0] != "" {
				t.Fatal(g, v)
			}
		}},
		{"R23 not given", []string{"nodes", "set", "12"}, func(t *testing.T, r result) {
			if g, _ := val(ran(t, r, "nodes set", "12"), "name"); g {
				t.Fatal("given")
			}
		}},
		// D6.
		{"D6 string twice", []string{"nodes", "set", "12", "--name", "a", "--name", "b"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "name" || fe.Reason != "given-twice" {
				t.Fatalf("%+v", fe)
			}
		}},
		{"D6 -o twice", []string{"-o", "json", "nodes", "list", "-ojson"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "output" || fe.Reason != "given-twice" {
				t.Fatalf("%+v", fe)
			}
		}},
		// G06 bool forms.
		{"G06 --force=false", []string{"nodes", "delete", "12", "--force=false"}, func(t *testing.T, r result) {
			if g, v := val(ran(t, r, "nodes delete", "12"), "force"); !g || v[0] != "false" {
				t.Fatal(g, v)
			}
		}},
		{"G06 --force false is a positional", []string{"nodes", "delete", "--force", "false"}, func(t *testing.T, r result) {
			ran(t, r, "nodes delete", "false")
		}},
		// G20 no abbreviations.
		{"G20 --exp", []string{"nodes", "set", "1", "--exp", "1h"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "exp" || strings.Join(fe.Path, " ") != "nodes set" {
				t.Fatalf("%+v", fe)
			}
		}},
		// R18, R31, D4 typed flag errors with path.
		{"R18 --force on list", []string{"nodes", "list", "--force"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "force" || strings.Join(fe.Path, " ") != "nodes list" {
				t.Fatalf("%+v", fe)
			}
		}},
		{"R17 unknown short", []string{"nodes", "delete", "12", "-r"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "r" {
				t.Fatalf("%+v", fe)
			}
		}},
		{"D4 missing value", []string{"nodes", "set", "12", "--name"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "name" || fe.Reason != "needs-value" {
				t.Fatalf("%+v", fe)
			}
		}},
		// D3: -c/-o before or after; refused where the leaf lacks them.
		{"D3 -c before", []string{"-c", "x", "nodes", "list"}, func(t *testing.T, r result) {
			if g, v := val(ran(t, r, "nodes list"), "config"); !g || v[0] != "x" {
				t.Fatal(g, v)
			}
		}},
		{"D3 -c between", []string{"nodes", "-c", "x", "list"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "config"); v[0] != "x" {
				t.Fatal(v)
			}
		}},
		{"D3 --output json before", []string{"--output", "json", "nodes", "list"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "output"); v[0] != "json" {
				t.Fatal(v)
			}
		}},
		{"D3 -ojson before", []string{"-ojson", "nodes", "list"}, func(t *testing.T, r result) {
			if _, v := val(ran(t, r, "nodes list"), "output"); v[0] != "json" {
				t.Fatal(v)
			}
		}},
		{"D3 -o before check config is refused", []string{"-o", "json", "check", "config"}, func(t *testing.T, r result) {
			if fe := flagErr(t, r); fe.Flag != "output" || strings.Join(fe.Path, " ") != "check config" {
				t.Fatalf("%+v", fe)
			}
		}},
		{"D3 -c works on check config", []string{"-c", "x", "check", "config"}, func(t *testing.T, r result) { ran(t, r, "check config") }},
		// Trap: a bool leaf flag before the subcommand is read as taking a value by Find.
		{"trap bool before subcommand", []string{"--force", "nodes", "delete", "12"}, func(t *testing.T, r result) {
			t.Logf("got err=%v (%T) help=%v parsed=%+v", r.err, r.err, r.help, r.parsed)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			c.check(t, run(c.args...))
		})
	}
}

// R49/R56: many fresh trees in parallel; run with -race.
func TestParallelFreshTrees(t *testing.T) {
	for i := range 200 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			r := run("nodes", "list", "--sort", fmt.Sprint(i), "-o", "json")
			if _, v := val(ran(t, r, "nodes list"), "sort"); v[0] != fmt.Sprint(i) {
				t.Fatal(v)
			}
		})
	}
}

// D1: __complete never reaches a leaf RunE (no config, no network) and goes to our stdout.
func TestComplete(t *testing.T) {
	cases := [][]string{
		{"__complete", ""},
		{"__complete", "nodes", ""},
		{"__complete", "nodes", "list", "--columns", "id,na"},
		{"__complete", "nodes", "list", "--columns", "+id,-o"},
		{"__complete", "nodes", "list", "--sort", "-last"},
		{"__complete", "nodes", "list", "--sort=-last"},
		{"__complete", "nodes", "list", "-o", ""},
		{"__complete", "nodes", "list", "--"},
		{"__complete", "nodes", "delete", ""},
		{"__complete", "-c", "x", "nodes", "li"},
		{"__completeNoDesc", "nodes", "delete", ""},
	}
	for _, a := range cases {
		r := run(a...)
		if r.parsed != nil {
			t.Fatalf("%q reached RunE", a)
		}
		t.Logf("%q -> err=%v\n%s", a, r.err, r.stdout)
	}
}

func TestCompleteAfterGlobal(t *testing.T) {
	for _, a := range [][]string{
		{"__complete", "-c", "x", "nodes", "li"},
		{"__complete", "check", "config", "--"},
		{"__complete", "nodes", "list", "-"},
	} {
		r := run(a...)
		t.Logf("%q ->\n%s", a, r.stdout)
	}
}
