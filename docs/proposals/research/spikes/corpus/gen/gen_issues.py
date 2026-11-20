import json, sys

P = "https://github.com/spf13/pflag/issues/"
C = "https://github.com/spf13/cobra/issues/"
K = "https://github.com/alecthomas/kong/issues/"
U = "https://github.com/urfave/cli/issues/"
LIC = {P: "BSD-3-Clause", C: "Apache-2.0", K: "MIT", U: "MIT"}

def run(path, args=None, **flags):
    o = {"kind": "run", "path": path}
    if args: o["args"] = args
    if flags: o["flags"] = {k.replace("_", "-"): v for k, v in flags.items()}
    return o

def err(kind, path, word=""):
    o = {"kind": kind, "path": path}
    if word: o["word"] = word
    return o

def comp(**kw):
    return {"kind": "complete", **kw}

cases = []
def case(repo, num, kind, topic, upstream, expect, argv, want, ours=None, why=None, note=None, tree=None):
    c = {"id": "issues-%03d" % (len(cases) + 1), "src": repo + str(num), "lic": LIC[repo], "kind": kind,
         "topic": topic, "upstream": upstream, "expect": expect}
    if tree: c["tree"] = tree
    c["argv"] = argv; c["want"] = want
    if ours: c["ours"] = ours; c["why"] = why
    if note: c["note"] = note
    cases.append(c)
    return c["id"]

V = "verified in pflag@44b0d47 flag.go parseSingleShortArg"
ids = {}
ids["p541"] = case(P, 541, "run", "short-eq", "-s= (string shorthand, empty value)", "flag set to empty string, next word untouched",
    ["nodes", "set", "n1", "-e="], run("nodes set", ["n1"], expiry=[""]),
    note="PR open; shipped pflag gives the value \"=\" (len>2 check), " + V)
ids["u2293"] = case(U, 2293, "run", "empty-value", "--flag=\"\"", "flag set to empty string",
    ["nodes", "set", "n1", "--name="], run("nodes set", ["n1"], name=[""]), note="fixed in urfave v3; read in issue")
ids["u2223"] = case(U, 2223, "run", "empty-value", "--value1= --value2=bar", "value1 empty, value2 bar; --value2 not swallowed",
    ["nodes", "set", "n1", "--name=", "--expiry=1h"], run("nodes set", ["n1"], name=[""], expiry=["1h"]))
ids["c2358"] = case(C, 2358, "run", "short", "-name wrong, flag --name/-n", "error, not -n=ame",
    ["nodes", "list", "-output", "json"], err("unknown-flag", "nodes list", "-output"),
    note="open; pflag fix PRs #473-#475 closed unmerged; shipped pflag reads -o=utput and json becomes a positional, " + V)
ids["p146"] = case(P, 146, "run", "short", "-option when no shorthand is defined", "read as --option (Go flag style)",
    ["nodes", "list", "-columns", "id"], run("nodes list", columns=["id"]),
    ours=err("unknown-flag", "nodes list", "-columns"),
    why="D11 best effort: -columns may be refused or read as -c olumns, never as --columns",
    note="PR closed unmerged; shipped pflag reads -c=olumns (attached value)")
ids["c2295"] = case(C, 2295, "run", "dash-value", "some-command '- http' (dash, space)", "a positional, not -h",
    ["nodes", "delete", "- h"], run("nodes delete", ["- h"]),
    note="open; shipped pflag: unknown shorthand ' ' (or help when the next letter is h), " + V)
ids["p417"] = case(P, 417, "run", "verbatim", "--name -s x (string flag then a flag)", "reporter: 'flag needs an argument'",
    ["auth", "keys", "create", "u1", "--description", "--reusable"], err("missing-value", "auth keys create", "--description"),
    ours=run("auth keys create", ["u1"], description=["--reusable"]), why="D20",
    note="closed; pflag ships the next word as the value (--description=--reusable)")
ids["c909"] = case(C, 909, "run", "verbatim", "--username $EMPTY --pwd x (unquoted empty var vanishes)", "reporter: username empty, pwd x",
    ["api", "keys", "create", "--user", "--expiry", "1h"], err("missing-value", "api keys create", "--user"),
    ours=err("arg-count", "api keys create"), why="D20",
    note="closed; cobra ships --user=--expiry and 1h a positional")
ids["p288"] = case(P, 288, "run", "bool", "--test false (bool)", "reporter: test=false",
    ["nodes", "delete", "n1", "--force", "false"], run("nodes delete", ["n1"], force=["false"]),
    ours=err("arg-count", "nodes delete"), why="D9",
    note="closed as designed; pflag: bool takes no separate value, false is a positional")
ids["p372"] = case(P, 372, "run", "abbrev", "--exp for --expiry (unambiguous prefix)", "PR: accept unambiguous prefixes",
    ["nodes", "set", "n1", "--exp", "1h"], run("nodes set", ["n1"], expiry=["1h"]),
    ours=err("unknown-flag", "nodes set", "--exp"), why="no abbreviations (DECISIONS facts)",
    note="PR closed unmerged; pflag ships unknown flag")
ids["p311"] = case(P, 311, "run", "dash-value", "app -123 / app -foo as a positional", "reporters: a positional",
    ["nodes", "delete", "-1"], run("nodes delete", ["-1"]),
    ours=err("unknown-flag", "nodes delete", "-1"), why="undecided: is dash+digit a positional? '--' is the way today (DECISIONS facts)",
    note="closed; pflag/cobra ship unknown shorthand '1', maintainers point to '--'")
ids["c124"] = case(C, 124, "run", "dash-dash", "cmd -- -123", "-123 is a positional",
    ["nodes", "delete", "--", "-1"], run("nodes delete", ["-1"]))
ids["p307"] = case(P, 307, "run", "verbatim", "-m \"$(<file)\" with newlines", "value kept whole, newlines included",
    ["auth", "keys", "create", "u1", "-d", "line1\nline2"], run("auth keys create", ["u1"], description=["line1\nline2"]),
    note="issue is about StringSlice CSV splitting; a string flag keeps it verbatim")
ids["p214"] = case(P, 214, "run", "bool", "--no-shave-yaks=true", "request: a bool refuses =true/=false",
    ["nodes", "delete", "n1", "--force=true"], err("bad-value", "nodes delete", "--force"),
    ours=run("nodes delete", ["n1"], force=["true"]), why="D9", note="open request")
ids["p173"] = case(P, 173, "run", "unknown-flag", "--unknown \"\"", "no panic; unknown flag reported",
    ["nodes", "list", "--bogus", ""], err("unknown-flag", "nodes list", "--bogus"))
ids["p154"] = case(P, 154, "run", "bool", "ls -l /", "-l true, / a positional", ["run", "-b", "/"],
    run("run", ["/"], bool=["true"]), tree="pf")
ids["p72"] = case(P, 72, "run", "repeat", "--exclude a --exclude b on a non-list flag", "an error",
    ["nodes", "set", "n1", "--name", "a", "--name", "b"], err("flag-repeated", "nodes set", "--name"),
    note="open; pflag ships last-wins (PR #117 closed); D15 agrees with the reporter")
ids["k441"] = case(K, 441, "run", "repeat", "-o /path -out .ext (meant --out)", "an error: flag given twice",
    ["nodes", "list", "-o", "json", "-output", "json"], err("flag-repeated", "nodes list", "-o"),
    ours=err("unknown-flag", "nodes list", "-output"), why="D11 best effort: -output may be refused",
    note="open; kong reads -o=ut and keeps the last")
ids["p21"] = case(P, 21, "run", "short-eq", "-b=false (bool shorthand)", "b false", ["run", "-b=false"],
    run("run", bool=["false"]), tree="pf")
ids["p12"] = case(P, 12, "run", "short-eq", "-p=foo", "value foo, not =foo", ["nodes", "set", "n1", "-e=1h"],
    run("nodes set", ["n1"], expiry=["1h"]))
ids["k315"] = case(K, 315, "run", "short-eq", "-a=-10", "value -10", ["nodes", "set", "n1", "-e=-1h"],
    run("nodes set", ["n1"], expiry=["-1h"]))
ids["p5"] = case(P, 5, "run", "dash-dash", "cmd -flag1 -- some args after -x", "args once, in order; flags after -- are positionals",
    ["nodes", "routes", "set", "-o", "json", "--", "n1", "--force"], run("nodes routes set", ["n1", "--force"], output=["json"]))
ids["c2528"] = case(C, 2528, "run", "dash-dash", "app -- literal child (TraverseChildren)", "words after -- are positionals, child not run",
    ["--", "nodes", "list"], err("unknown-command", "", "nodes"),
    note="open; root takes no positionals here, so any usage error that does not run nodes list honours the rule")
ids["c2518"] = case(C, 2518, "run", "dash-value", "cat - (lone dash)", "a positional", ["policy", "set", "-"],
    run("policy set", ["-"]))
ids["c2518b"] = case(C, 2518, "run", "dash-value", "root - child", "- stops command discovery; child not run",
    ["nodes", "-", "list"], err("unknown-command", "nodes", "-"), note="PR closed; fix not in cobra@adbc881: cobra dispatches nodes list with - as an argument (cobra column)")
ids["u2418"] = case(U, 2418, "run", "dash-value", "myapp - foo bar", "all three kept as positionals",
    ["nodes", "routes", "set", "-", "10.0.0.0/8"], run("nodes routes set", ["-", "10.0.0.0/8"]))
ids["c2512"] = case(C, 2512, "run", "unknown-flag", "prog --unknown --namespace foo child --bar", "unknown flag --unknown, not unknown command foo",
    ["--bogus", "-c", "x", "nodes", "list"], err("unknown-flag", "", "--bogus"))
ids["c1797"] = case(C, 1797, "run", "unknown-cmd", "cli fooo --bar", "unknown command fooo (before the flag)",
    ["nodes", "lst", "--bogus"], err("unknown-command", "nodes", "lst"))
ids["c2311"] = case(C, 2311, "run", "global", "kubectl create -o yaml svc", "a parent's flag before the subcommand is accepted",
    ["nodes", "-o", "json", "list"], run("nodes list", output=["json"]))
ids["c2092"] = case(C, 2092, "run", "global", "helm --starter . create a (leaf flag before the leaf)", "reporter: unknown flag --starter",
    ["--name", "x", "nodes", "set", "n1"], err("unknown-flag", "", "--name"), note="open, maintainers undecided; cobra@adbc881 accepts the flag (cobra column)")
ids["c2251"] = case(C, 2251, "run", "global", "--cmdflag command (bool persistent flag of command, given before it)", "reporter: accepted",
    ["--list-columns", "nodes", "list"], run("nodes list", list_columns=["true"]),
    ours=err("unknown-flag", "", "--list-columns"), why="D3",
    note="open; contradicts #2092; cobra refuses the bool form, accepts --cmdflag=true")
ids["c2559"] = case(C, 2559, "complete", "complete-dashdash", "prog -- --t<TAB>", "no flags after --",
    ["nodes", "delete", "--", "--f"], comp(**{"not": ["--force"]}))
ids["c2559b"] = case(C, 2559, "complete", "complete-dashdash", "prog -- <TAB>", "no subcommands after --",
    ["--", ""], comp(**{"not": ["nodes", "users"]}), note="open; cobra@adbc881 still offers every command after -- (cobra column)")
ids["c1816"] = case(C, 1816, "complete", "complete-flag", "root __complete 1-ff00:0:1 \"\"", "a word with - as 2nd char is not a flag",
    ["nodes", "set", "1-ff00:0:1", "--n"], comp(has=["--name"]))
ids["c1816b"] = case(C, 1816, "complete", "complete-value", "completion reads a non-flag word as a flag", "a positional is never a flag",
    ["nodes", "delete", "o", ""], comp(exact=[]),
    note="carried: the positional 'o' equals the short of --output; it must not open --output's values")
ids["c1931"] = case(C, 1931, "run", "verbatim", "--description '- watsupnhello' (helm -n)", "whole value is the description; no -n",
    ["auth", "keys", "create", "u1", "--description", "- watsupohello"], run("auth keys create", ["u1"], description=["- watsupohello"]))
ids["c1777"] = case(C, 1777, "run", "global", "app -z one -o one two (value = subcommand name)", "z=one, o=one, command two",
    ["-c", "nodes", "-o", "json", "nodes", "list"], run("nodes list", output=["json"], config=["nodes"]),
    note="fixed by PR #1781")
ids["c1913"] = case(C, 1913, "run", "global", "tester --project configs --config dev configs", "project=configs, command configs",
    ["-c", "nodes", "nodes", "list"], run("nodes list", config=["nodes"]))
ids["c1170"] = case(C, 1170, "complete", "complete-cmd", "prog --localflag x <TAB>", "subcommands still offered after a root flag",
    ["-c", "x", ""], comp(has=["nodes", "users"]))
ids["c1114"] = case(C, 1114, "run", "verbatim", "run --name 'abc def'", "value abc def", ["nodes", "set", "n1", "--name", "abc def"],
    run("nodes set", ["n1"], name=["abc def"]), note="closed: user error (quotes passed literally by the IDE)")
ids["c760"] = case(C, 760, "run", "dash-value", "—-arg (em dash)", "reporter: an error, not a silent positional",
    ["check", "config", "—-help"], err("unknown-flag", "check config", "—-help"),
    note="closed: maintainers do not treat it as a bug; cobra ships a positional")
ids["c615"] = case(C, 615, "run", "bool", "cli --boolflag command", "command is not taken as the bool's value",
    ["-h", "nodes", "list"], {"kind": "help", "path": "nodes list"})
ids["c63"] = case(C, 63, "run", "help", "app -h", "help, not unknown command -h", ["-h"], {"kind": "help", "path": ""})
ids["c415"] = case(C, 415, "complete", "complete-value", "kubectl --log-dir=<TAB>", "values; --log-dir= not doubled",
    ["nodes", "list", "--sort="], comp(has=["id", "name"], **{"not": ["--sort=--sort="]}))
ids["c2"] = case(C, 2, "run", "eq", "--run=\"myApp --startup-args=a, b, c\"", "the whole string is the value",
    ["auth", "keys", "create", "u1", "--description=myApp --startup-args=a, b, c"],
    run("auth keys create", ["u1"], description=["myApp --startup-args=a, b, c"]))
ids["c26"] = case(C, 26, "run", "abbrev", "prefix matching of command names replaced by aliases", "nodes li is unknown",
    ["nodes", "li"], err("unknown-command", "nodes", "li"), note="cobra keeps EnablePrefixMatching opt-in, default off")
ids["u1215"] = case(U, 1215, "run", "abbrev", "call a command by a unique name substring", "request: nodes lis runs nodes list",
    ["nodes", "lis"], run("nodes list"), ours=err("unknown-command", "nodes", "lis"), why="no abbreviations (DECISIONS facts)",
    note="closed; read in issue only")
ids["c1802"] = case(C, 1802, "run", "unknown-cmd", "case-insensitive command names", "default: NODES is unknown",
    ["NODES", "list"], err("unknown-command", "", "NODES"), note="cobra: EnableCaseInsensitive opt-in, default off (verified cobra@adbc881 cobra.go:61)")
ids["c1852"] = case(C, 1852, "complete", "complete-alias", "prog __complete ct (alias ctx)", "alias offered when no name fits",
    ["nodes", "routes", "ap"], comp(has=["approve"]))
ids["u1875"] = case(U, 1875, "complete", "complete-alias", "emu l<TAB> (list, alias ls)", "aliases not offered next to names",
    ["nodes", "l"], comp(exact=["list"]))
ids["c1786"] = case(C, 1786, "complete", "complete-flag", "git --v<TAB>", "--help and --version are completed",
    ["--"], comp(has=["--help", "--version"]))
ids["c2385"] = case(C, 2385, "complete", "complete-list", "--plugins=key1,<TAB>", "next item after a comma, no space",
    ["nodes", "list", "--columns", "id,"], comp(has=["id,name"], nospace=True))
ids["c1629"] = case(C, 1629, "complete", "short-attached", "kubectl -ninfra<TAB>", "values for an attached short value",
    ["nodes", "list", "-oj"], comp(has=["-ojson"]), ours=comp(exact=[]), why="D11 best effort", note="open")
ids["c1257"] = case(C, 1257, "complete", "short-group", "prog -bs <TAB> (bool b, string s)", "values of s",
    ["run", "-bs", ""], comp(has=["alpha", "beta"]), ours=comp(exact=[]), why="D11 best effort", tree="pf",
    note="fixed by PR #1258")
ids["u2254"] = case(U, 2254, "run", "short-group", "-som foo (o, m bools; s string last)", "s=foo, foo not also a positional",
    ["run", "-bs", "foo"], run("run", bool=["true"], string=["foo"]), ours=err("unknown-flag", "run", "-bs"),
    why="D11 best effort", tree="pf")
ids["k662"] = case(K, 662, "run", "missing-value", "--flag (string, end of input)", "missing value error",
    ["nodes", "set", "n1", "--name"], err("missing-value", "nodes set", "--name"))
ids["k290"] = case(K, 290, "run", "dash-value", "--flag -foo (value starting with -)", "reporter: -foo is the value",
    ["nodes", "list", "--sort", "-last-seen"], run("nodes list", sort=["-last-seen"]),
    note="kong refuses unless WithHyphenPrefixedParameters; pflag takes it (D20)")
ids["k170"] = case(K, 170, "run", "negation", "--no-flag (negatable bool)", "flag false",
    ["nodes", "delete", "n1", "--no-force"], run("nodes delete", ["n1"], force=["false"]),
    ours=err("unknown-flag", "nodes delete", "--no-force"), why="D9")
ids["k102"] = case(K, 102, "run", "strings", "-a 1 2 3 (slice flag)", "reporter: a=[1 2 3]",
    ["nodes", "list", "--columns", "id", "name"], run("nodes list", columns=["id", "name"]),
    ours=err("arg-count", "nodes list"), why="D6", note="closed as designed: one value per flag, comma separated")
ids["u2292"] = case(U, 2292, "run", "empty-value", "app hello \"\" world", "empty positional kept",
    ["nodes", "routes", "set", "n1", ""], run("nodes routes set", ["n1", ""]))
ids["u2234"] = case(U, 2234, "run", "empty-value", "cmd sub -f=x \"\" arg2", "empty positional and the rest kept",
    ["nodes", "routes", "set", "-o=json", "", "10.0.0.0/8"], run("nodes routes set", ["", "10.0.0.0/8"], output=["json"]))
ids["u2208"] = case(U, 2208, "run", "global", "root-local flag after a subcommand", "refused",
    ["nodes", "list", "--version"], err("unknown-flag", "nodes list", "--version"))
ids["u1964"] = case(U, 1964, "run", "interspersed", "--bool arg --text x", "flags after a positional still parsed",
    ["nodes", "delete", "--force", "n1", "--output", "json"], run("nodes delete", ["n1"], force=["true"], output=["json"]))
ids["u2315"] = case(U, 2315, "complete", "complete-flag", "myapp --par<TAB>", "flags with that prefix",
    ["nodes", "list", "--so"], comp(exact=["--sort"]))
ids["u2315b"] = case(U, 2315, "complete", "complete-flag", "myapp --<TAB>", "all flags",
    ["nodes", "list", "--"], comp(has=["--columns", "--sort", "--filter", "--list-columns", "--output", "--config", "--help"]))
ids["c10"] = case(C, 10, "run", "global", "todo --file=x add 'some todo'", "root flag before the subcommand",
    ["--config=/etc/h.yaml", "nodes", "list"], run("nodes list", config=["/etc/h.yaml"]))

with open(sys.argv[1], "w") as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
json.dump(ids, open(sys.argv[2], "w"))
print(len(cases))
