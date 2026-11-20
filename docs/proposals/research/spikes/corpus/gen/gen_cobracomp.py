import json, sys

N = "/home/kradalby/.cache/headscale-proposals/research_notes/Headscale CLI framework choice/spikes/corpus"
R = "spf13/cobra@adbc881 "
C = "completions_test.go:"
TOP = ["api", "auth", "check", "completion", "nodes", "policy", "serve", "users", "version"]
SHELLS = ["bash", "zsh", "fish", "powershell"]
COLS = ["id", "name", "owner", "ip", "version", "online", "last-seen", "expiry", "hostname"]
CC = ["service", "1-123", "11-123"]
U_SHORT = "undecided: offer -x shorts on '-<TAB>' as cobra does, or longs only (own-grammar offers a short only when typed exactly)"
U_HELP = "undecided: stop completing after -h/--help/--version (cobra), or keep going since `headscale -h nodes` is the help of nodes"

def comp(**k):
    o = {"kind": "complete"}
    o.update(k)
    return o

cases = []
def add(line, test, topic, upstream, expect, argv, want, ours=None, why=None, tree=None, note=None, f=C):
    c = {"id": "cobracomp-%03d" % (len(cases) + 1), "src": R + f + str(line) + " " + test, "lic": "Apache-2.0",
         "kind": "complete", "topic": topic, "upstream": upstream, "expect": expect}
    if tree: c["tree"] = tree
    c["argv"] = argv
    c["want"] = want
    if ours is not None:
        c["ours"], c["why"] = ours, why
    if note: c["note"] = note
    cases.append(c)
    return c["id"]

ids = {}
T = "TestCmdNameCompletionInGo"
ids[T] = [
 add(89, T, "complete-cmd", "root with children, hidden, deprecated, aliased; __complete ''", "every available command name plus cobra's own completion and help; NoFileComp",
     [""], comp(exact=TOP + ["help"], files=False), comp(exact=TOP, files=False), "D8"),
 add(108, T, "complete-cmd", "__complete s", "secondChild only", ["s"], comp(exact=["serve"], files=False)),
 add(124, T, "complete-alias", "__complete test (only aliases testAlias/testSynonym and hidden testHidden match)", "nothing: aliases are never completed, even when no name fits",
     ["users", "r"], comp(exact=[], files=False), comp(exact=["rm"], files=False), "D16",
     note="cobra completes ArgAliases only when no ValidArg fits, but never command aliases"),
]
T = "TestNoCmdNameCompletionInGo"
ids[T] = [
 add(183, T, "complete-cmd", "childCmd1 (has child childCmd2, takes args) arg1 ''", "no sub-command names once a positional is given",
     ["nodes", "bogus", ""], comp(exact=[]),
     note="cobra's directive here is Default (childCmd1 is runnable with args); our groups take no positional, so only the empty list is carried"),
 add(288, T, "global", "childCmd1 --persistent value ''", "sub-command names still completed after a persistent flag",
     ["nodes", "--config", "x", ""], comp(exact=["delete", "list", "routes", "set"], files=False)),
 add(305, T, "global", "childCmd1 -p value ''", "sub-command names still completed after a persistent short flag",
     ["nodes", "-c", "x", ""], comp(exact=["delete", "list", "routes", "set"], files=False)),
 add(216, T, "global", "TraverseChildren root: --localroot value ''", "root's sub-command names after a root flag",
     ["-c", "x", ""], comp(has=["nodes", "users", "completion"], files=False)),
 add(238, T, "global", "TraverseChildren: --localroot value childCmd1 --nonPersistent value ''", "childCmd2: flags on both sides of the group word",
     ["-c", "x", "nodes", "-o", "json", ""], comp(exact=["delete", "list", "routes", "set"], files=False),
     note="our -c/-o are globals (D3), read before the leaf like TraverseChildren; cobra's rows with a local non-persistent flag on the group have no counterpart (our groups take only -h)"),
]
T = "TestValidArgsCompletionInGo"
ids[T] = [
 add(330, T, "complete-value", "root ValidArgs one two three; ''", "all ValidArgs, NoFileComp", ["completion", ""], comp(exact=SHELLS, files=False)),
 add(347, T, "complete-value", "root ValidArgs; o", "one", ["completion", "f"], comp(exact=["fish"], files=False)),
 add(362, T, "complete-value", "root ValidArgs; one ''", "ValidArgs do not repeat; directive Default (files)",
     ["completion", "bash", ""], comp(exact=[], files=True), comp(exact=[], files=False),
     "quirk: ValidArgs cover the first argument only, then cobra falls back to files; the spec knows completion takes one argument"),
]
T = "TestValidArgsFuncSingleCmdInvalidArg"
ids[T] = [add(1370, T, "complete-value", "root MinimumNArgs(1) + ValidArgsFunction; unexpectedArg t", "nothing, NoFileComp",
              ["completion", "bash", "b"], comp(exact=[], files=False))]
T = "TestValidArgsFuncSingleCmd"
ids[T] = ids["TestValidArgsCompletionInGo"][:2]
T = "TestValidArgsFuncChildCmds"
ids[T] = [
 add(1399, T, "complete-value", "child1 ''", "one two", ["grp", "sub", ""], comp(exact=["one", "two"]), tree="pf",
     note="cobra's function returns Default; our static values are ValidArgs-like, so the directive is not carried"),
 add(1415, T, "complete-value", "child1 t", "two", ["grp", "sub", "t"], comp(exact=["two"]), tree="pf"),
 add(1430, T, "complete-value", "child1 unexpectedArg t", "nothing, NoFileComp", ["grp", "sub", "one", "t"], comp(exact=[], files=False), tree="pf"),
]
T = "TestValidArgsFuncAliases"
ids[T] = [
 add(1499, T, "complete-alias", "son '' (alias of child)", "child's args: one two", ["grp", "s", ""], comp(exact=["one", "two"]), tree="pf"),
 add(1515, T, "complete-alias", "daughter t", "two", ["grp", "s", "t"], comp(exact=["two"]), tree="pf"),
 add(1530, T, "complete-alias", "son unexpectedArg t", "nothing, NoFileComp", ["grp", "s", "one", "t"], comp(exact=[], files=False), tree="pf"),
]
T = "TestFlagNameCompletionInGo"
ids[T] = [
 add(510, T, "complete-flag", "root -f int, persistent -s bool; ''", "flag names not shown without a '-'", ["nodes", "list", ""], comp(exact=[], files=False)),
 add(527, T, "complete-flag", "root -", "every long and short: --first -f --help -h --second -s",
     ["-"], comp(exact=["--help", "-h", "--version", "--output", "-o", "--config", "-c"], files=False),
     comp(exact=["--help", "--version", "--output", "--config"], files=False), U_SHORT),
 add(547, T, "complete-flag", "root --f", "--first", ["--c"], comp(exact=["--config"], files=False)),
 add(562, T, "complete-flag", "childCmd - (root has local --first, persistent --second)", "inherited persistent and own flags with shorts; not the root's local flag",
     ["nodes", "list", "-"], comp(exact=["--columns", "--sort", "--filter", "--list-columns", "--output", "-o", "--config", "-c", "--help", "-h"], files=False),
     comp(exact=["--columns", "--sort", "--filter", "--list-columns", "--output", "--config", "--help"], files=False), U_SHORT),
]
T = "TestFlagNameCompletionRepeat"
ids[T] = [
 add(723, T, "complete-flag", "--first 1 --", "a given flag is not offered again unless it is a slice/array",
     ["nodes", "list", "--sort", "id", "--"], comp(exact=["--columns", "--filter", "--list-columns", "--output", "--config", "--help"], files=False),
     note="cobra's rule matches D15"),
 add(745, T, "complete-flag", "--first 1 --second=false --", "a bool given as =false is not offered again",
     ["nodes", "list", "--sort", "id", "--list-columns=false", "--"], comp(exact=["--columns", "--filter", "--output", "--config", "--help"], files=False)),
 add(767, T, "complete-flag", "--slice 1 --slice=2 --array val --bslice true --multi val --", "repeatable flags are offered again",
     ["nodes", "list", "--filter", "id", "--filter=ip", "--"], comp(exact=["--columns", "--sort", "--filter", "--list-columns", "--output", "--config", "--help"], files=False)),
 add(793, T, "complete-flag", "-l 1 -l=2 -a val -", "a flag given by its short is tracked like its long",
     ["nodes", "set", "1", "-e", "1h", "-"], comp(has=["--name"], **{"not": ["--expiry", "-e"]}),
     note="cobra's row has only slice/array flags; carried with -e (not repeatable) so the same rule drops it"),
 add(825, T, "complete-flag", "-l 1 -l=2 -a val -a", "-a offered again only because it is an array",
     ["nodes", "set", "1", "-e", "1h", "-e"], comp(exact=[], files=False),
     note="same rule, -e not repeatable: nothing"),
]
T = "TestFlagFileExtFilterCompletionInGo"
ids[T] = [
 add(1103, T, "complete-value", "--yaml= (MarkFlagFilename yaml yml)", "the flag is found from --x=; extensions + FilterFileExt",
     ["nodes", "list", "--sort="], comp(exact=COLS, files=False), note="carried: the four spellings find the flag; the FilterFileExt directive is OUT"),
 add(1117, T, "complete-value", "-y ''", "the flag is found from its short", ["nodes", "list", "-o", ""], comp(exact=["json"], files=False)),
 add(1131, T, "complete-value", "-y=", "the flag is found from -x=", ["nodes", "list", "-o="], comp(exact=["json"], files=False)),
]
T = "TestFlagCompletionInGo"
ids[T] = [
 add(1651, T, "complete-value", "--introot '' (func gives 1 2 10)", "all values", ["nodes", "list", "--sort", ""], comp(exact=COLS, files=False),
     note="cobra's directive is the function's own; NoFileComp is ours for a value list"),
 add(1668, T, "complete-value", "--introot 1", "1 10", ["nodes", "list", "--sort", "i"], comp(exact=["id", "ip"], files=False)),
]
T = "TestFlagCompletionWithNotInterspersedArgs"
ids[T] = [
 add(1843, T, "complete-flag", "child --", "child's own flags only: --bool --help --string", ["completion", "--"], comp(exact=["--help"], files=False),
     note="completion takes neither -o nor -c, nor the root's --version"),
 add(1860, T, "complete-dashdash", "child -- -", "no flags after --; positional completion instead", ["completion", "--", "-"], comp(exact=[])),
 add(1876, T, "complete-dashdash", "child --bool -- -", "no flags after -- with a flag before it", ["policy", "set", "--dry-run", "--", "-"], comp(exact=[], files=True)),
 add(1927, T, "complete-dashdash", "child -- ''", "positionals still completed after --", ["completion", "--", ""], comp(exact=SHELLS, files=False)),
 add(1943, T, "complete-dashdash", "child -- --string '' (--string has a value func)", "positional completion: --string after -- is an argument, not a flag wanting a value",
     ["pick", "--", "--short3", ""], comp(exact=CC, files=False), tree="cc"),
 add(1959, T, "complete-dashdash", "child2 -- a (ValidArgs arg1 arg2)", "ValidArgs after --", ["completion", "--", "b"], comp(exact=["bash"], files=False),
     note="cobra's expected list is unfiltered (arg1 arg2 for 'a'), the shell filters; carried with the prefix filter both sides apply"),
 add(1975, T, "complete-dashdash", "child -- --validarg ''", "--validarg after -- is an argument", ["pick", "--", "--short", ""], comp(exact=CC, files=False), tree="cc"),
 add(2028, T, "complete-dashdash", "child -- --validarg --toComp=ab", "the word under the cursor after -- goes to the args function, not to a flag's value",
     ["nodes", "list", "--", "--sort=i"], comp(exact=[], files=False)),
]
T = "TestFlagCompletionForPersistentFlagsCalledFromSubCmd"
ids[T] = [add(2097, T, "complete-value", "root persistent --string with values; child --string ''", "the inherited flag's values",
              ["nodes", "list", "--output", ""], comp(exact=["json"], files=False))]
T = "TestArgAliasesCompletionInGo"
ids[T] = [
 add(2333, T, "complete-alias", "ValidArgs one two three, ArgAliases un deux trois; ''", "ValidArgs only, no aliases",
     ["nodes", "routes", ""], comp(exact=["set"], files=False), note="carried by analogy: cobra applies this to ArgAliases; D16 takes the rule for command aliases"),
 add(2350, T, "complete-alias", "t", "two three; no alias while a ValidArg fits", ["nodes", "l"], comp(exact=["list"], files=False)),
 add(2366, T, "complete-alias", "tr", "trois: alias offered once no ValidArg fits", ["nodes", "routes", "ap"], comp(exact=["approve"], files=False)),
]
T = "TestCompleteHelp"
ids[T] = [ids["TestCmdNameCompletionInGo"][0],
 add(2418, T, "help", "help ''", "root's command names under help", ["help", ""], comp(has=["nodes", "users", "completion"]), comp(exact=[], files=False), "D8"),
 add(2436, T, "help", "help child1 ''", "child1's sub-commands", ["help", "nodes", ""], comp(exact=["delete", "list", "routes", "set"]), comp(exact=[], files=False), "D8"),
]
T = "TestCompleteCompletion"
ids[T] = [ids["TestValidArgsCompletionInGo"][0],
 add(2679, T, "complete-value", "completion <shell> ''", "nothing, NoFileComp", ["completion", "zsh", ""], comp(exact=[], files=False),
     note="cobra has one sub-command per shell; carried as the word after completion's only argument"),
]
T = "TestMultipleShorthandFlagCompletion"
ids[T] = [
 add(2709, T, "short", "bools -s -d, string -f (works), ValidArgs foo bar; -s ''", "ValidArgs", ["pick", "-s", ""], comp(exact=CC, files=False), tree="cc"),
 add(2725, T, "short-group", "-sd ''", "ValidArgs after grouped bools", ["pick", "-sd", ""], comp(exact=CC, files=False), comp(exact=[], files=False), "D11", tree="cc"),
 add(2741, T, "short-group", "-sdf ''", "the value of the last short in a group: works", ["pick", "-sdf", ""], comp(exact=["works"], files=False), comp(exact=[], files=False), "D11", tree="cc"),
 add(2756, T, "short-group", "-sdf=", "works", ["pick", "-sdf="], comp(exact=["works"], files=False), comp(exact=[], files=False), "D11", tree="cc"),
 add(2771, T, "short-group", "-sdf=abc ''", "ValidArgs after a group with its value", ["pick", "-sdf=abc", ""], comp(exact=CC, files=False), comp(exact=[], files=False), "D11", tree="cc"),
]
T = "TestCompletionCobraFlags"
cf = {
 1: add(3426, T, "complete-flag", "root (Version set) -", "--help -h --version -v", ["-"], comp(has=["--help", "-h", "--version"]),
        comp(has=["--help", "--version"], **{"not": ["-h"]}), U_SHORT),
 2: add(3437, T, "help", "--help ''", "nothing after --help", ["--help", ""], comp(exact=[], files=False), comp(has=["nodes"], files=False), U_HELP),
 3: add(3444, T, "help", "-h ''", "nothing after -h", ["-h", ""], comp(exact=[], files=False), comp(has=["nodes"], files=False), U_HELP),
 4: add(3451, T, "help", "--version ''", "nothing after --version", ["--version", ""], comp(exact=[], files=False), comp(has=["nodes"], files=False), U_HELP),
 6: add(3465, T, "help", "child --help '' (child has args)", "nothing even with other completions", ["completion", "--help", ""], comp(exact=[], files=False), comp(exact=SHELLS, files=False), U_HELP),
 7: add(3472, T, "help", "child -h ''", "nothing", ["completion", "-h", ""], comp(exact=[], files=False), comp(exact=SHELLS, files=False), U_HELP),
 10: add(3493, T, "help", "child -v -", "nothing, not even flags", ["completion", "-h", "-"], comp(exact=[], files=False), comp(exact=["--help"], files=False), U_HELP),
}
T = "TestArgsNotDetectedAsFlagsCompletionInGo"
an = [
 add(3607, T, "dash-value", "root func gives service 1-123 11-123; ''", "all three", ["pick", ""], comp(exact=CC, files=False), tree="cc"),
 add(3612, T, "dash-value", "service ''", "all three", ["pick", "service", ""], comp(exact=CC, files=False), tree="cc"),
 add(3617, T, "dash-value", "1-123 service ''", "all three: 1-123 is not a flag (#1816)", ["pick", "1-123", "service", ""], comp(exact=CC, files=False), tree="cc"),
 add(3622, T, "dash-value", "service 11-123 ''", "all three", ["pick", "service", "11-123", ""], comp(exact=CC, files=False), tree="cc"),
 add(3627, T, "dash-value", "service 1-123 ''", "all three", ["pick", "service", "1-123", ""], comp(exact=CC, files=False), tree="cc"),
]
T = "TestCustomDefaultShellCompDirective"
cd = [
 add(4039, T, "complete-directive", "root persistent --string (no func), SetDefaultShellCompDirective(NoFileComp); --string ''", "NoFileComp",
     ["--config", ""], comp(exact=[], files=False), note="Headscale's answerer behaves as if NoFileComp were the default"),
 add(4044, T, "complete-directive", "child1 inherits the custom default; child1 --string ''", "NoFileComp", ["nodes", "list", "--config", ""], comp(exact=[], files=False)),
 add(4049, T, "complete-directive", "child2 resets to Default; child2 --string ''", "Default: the shell offers files for a value flag with nothing to complete",
     ["nodes", "set", "1", "--name", ""], comp(exact=[], files=True), comp(exact=[], files=False),
     "undecided: a value flag with no values (--name, and -c which takes a path): cobra's default offers files, own-grammar offers nothing"),
]

with open(N + "/cases/cobracomp.jsonl", "w") as f:
    for c in cases:
        f.write(json.dumps(c) + "\n")

# inventory: one row per test function / table row
inv = []
def row(src, name, verdict, reason="", i=()):
    inv.append("\t".join([src, name, verdict, reason, ",".join(i)]))

def L(t):  # line of the func
    return LINES[t]

LINES = {}
for fname in ["completions_test.go", "bash_completions_test.go", "bash_completionsV2_test.go", "fish_completions_test.go",
              "zsh_completions_test.go", "powershell_completions_test.go", "active_help_test.go"]:
    for n, l in enumerate(open(N + "/../src/cobra/" + fname), 1):
        if l.startswith("func Test"):
            LINES[l[5:l.index("(")]] = "%s:%d" % (fname, n)

DESC = "other: descriptions"
out = {
 "TestValidArgsAndCmdCompletionInGo": "other: command with both sub-commands and positionals (our groups never run)",
 "TestValidArgsFuncAndCmdCompletionInGo": "other: command with both sub-commands and positionals (our groups never run)",
 "TestFlagNameCompletionInGoWithDesc": DESC,
 "TestRequiredFlagNameCompletionInGo": "layer-validation",
 "TestFlagDirFilterCompletionInGo": "other: file-filter directives (FilterDirs)",
 "TestValidArgsFuncCmdContext": "lifecycle",
 "TestValidArgsFuncInBashScript": "script-internals",
 "TestNoValidArgsFuncInBashScript": "script-internals",
 "TestCompleteCmdInBashScript": "script-internals",
 "TestCompleteNoDesCmdInZshScript": "script-internals",
 "TestCompleteCmdInZshScript": "script-internals",
 "TestValidArgsFuncChildCmdsWithDesc": DESC,
 "TestFlagCompletionWorksRootCommandAddedAfterFlags": "api-only",
 "TestFlagCompletionConcurrentRegistration": "api-only",
 "TestFlagCompletionInGoWithDesc": DESC,
 "TestValidArgsNotValidArgsFunc": "api-only",
 "TestDefaultCompletionCmd": "script-internals",
 "TestCompleteWithDisableFlagParsing": "other: DisableFlagParsing",
 "TestCompleteWithRootAndLegacyArgs": "layer-validation",
 "TestCompletionFuncCompatibility": "api-only",
 "TestFixedCompletions": "api-only",
 "TestFixedCompletionsWithCompletionHelpers": "api-only",
 "TestInitDefaultCompletionCmd": "api-only",
 "TestCompletionDoesNotMutateOsArgs": "api-only",
 "TestBashCompletions": "script-internals",
 "TestBashCompletionHiddenFlag": "script-internals",
 "TestBashCompletionDeprecatedFlag": "deprecated",
 "TestBashCompletionTraverseChildren": "script-internals",
 "TestBashCompletionNoActiveHelp": "active-help",
 "TestBashCompletionV2WithActiveHelp": "active-help",
 "TestCompleteNoDesCmdInFishScript": "script-internals",
 "TestCompleteCmdInFishScript": "script-internals",
 "TestProgWithDash": "script-internals",
 "TestProgWithColon": "script-internals",
 "TestFishCompletionNoActiveHelp": "active-help",
 "TestGenFishCompletionFile": "api-only",
 "TestFailGenFishCompletionFile": "api-only",
 "TestZshCompletionWithActiveHelp": "active-help",
 "TestPwshCompletionNoActiveHelp": "active-help",
 "TestActiveHelpAlone": "active-help", "TestActiveHelpWithComps": "active-help", "TestMultiActiveHelp": "active-help",
 "TestActiveHelpForFlag": "active-help", "TestConfigActiveHelp": "active-help", "TestDisableActiveHelp": "active-help",
}
tables = {
 "TestCompletionForGroupedFlags": (3090, 5, "layer-validation"),
 "TestCompletionForOneRequiredGroupFlags": (3190, 5, "layer-validation"),
 "TestCompletionForMutuallyExclusiveFlags": (3288, 4, "layer-validation"),
 "TestGetFlagCompletion": (3677, 5, "api-only"),
 "TestGetEnvConfig": (3748, 5, "env"),
 "TestDisableDescriptions": (3853, 5, "env"),
}
for t, loc in LINES.items():
    if t in ids:
        row(loc, t, "IN", "", ids[t])
    elif t in out:
        row(loc, t, "OUT", out[t])
    elif t in tables:
        start, n, why = tables[t]
        for k in range(n):
            row(loc, "%s row %d" % (t, k + 1), "OUT", why)
    elif t == "TestCompletionCobraFlags":
        for k in range(1, 19):
            if k in cf:
                row(loc, "%s row %d" % (t, k), "IN", "", [cf[k]])
            elif k in (5, 8, 9):
                row(loc, "%s row %d" % (t, k), "OUT", "other: -v/--version on a sub-command (only our root has --version, no -v)")
            elif k in (11, 12, 13, 14, 15, 16):
                row(loc, "%s row %d" % (t, k), "OUT", "other: program-defined -h/-v replacing cobra's own")
            else:
                row(loc, "%s row %d" % (t, k), "OUT", "other: DisableFlagParsing")
    elif t == "TestArgsNotDetectedAsFlagsCompletionInGo":
        for k, i in enumerate(an):
            row(loc, "%s row %d" % (t, k + 1), "IN", "", [i])
    elif t == "TestCustomDefaultShellCompDirective":
        for k, i in enumerate(cd):
            row(loc, "%s row %d" % (t, k + 1), "IN", "", [i])
    else:
        sys.exit("unclassified " + t)

with open(N + "/inventory/cobracomp.tsv", "w") as f:
    f.write("src\tname\tverdict\treason\tids\n")
    f.write("\n".join(inv) + "\n")
print(len(cases), "cases", len(inv), "rows")
