#!/usr/bin/env python3
"""Writes cases/{pflag,goflag,cobracmd}.jsonl and inventory/{...}.tsv.

The cases are typed in here once, as data, so the JSON stays valid; the
corpus itself is the .jsonl output. Run: python3 -I gen_mine.py <corpus dir>
"""
import json, os, sys, subprocess, re

out = sys.argv[1]
PF = "spf13/pflag@44b0d47"
GO = "golang/go@go1.27.3 src/flag"
CB = "spf13/cobra@adbc881"


def run(path, args=None, **flags):
    o = {"kind": "run", "path": path}
    if args:
        o["args"] = args
    if flags:
        o["flags"] = {k.replace("_", "-"): v if isinstance(v, list) else [v] for k, v in flags.items()}
    return o


def err(kind, path, word=""):
    o = {"kind": kind, "path": path}
    if word:
        o["word"] = word
    return o


def help_(path):
    return {"kind": "help", "path": path}


cases = {"pflag": [], "goflag": [], "cobracmd": []}
inv = {"pflag": [], "goflag": [], "cobracmd": []}


def case(src_key, n, src, lic, topic, upstream, expect, argv, want, tree=None, ours=None, why=None, note=None):
    c = {"id": f"{src_key}-{n:03d}", "src": src, "lic": lic, "kind": "run", "topic": topic,
         "upstream": upstream, "expect": expect}
    if tree:
        c["tree"] = tree
    c["argv"] = argv
    c["want"] = want
    if ours:
        c["ours"] = ours
        c["why"] = why
    if note:
        c["note"] = note
    cases[src_key].append(c)
    return c["id"]


def row(src_key, src, name, verdict, reason="", ids=()):
    inv[src_key].append((src, name, verdict, reason, ",".join(ids)))


# ---------------------------------------------------------------- pflag
k, L = "pflag", "BSD-3-Clause"
f = lambda line, test: f"{PF} {test.split(':')[0] if ':' in test else 'flag_test.go'}:{line} {test.split(':')[-1]}"
D11 = "D11 (best effort: a parser may accept or refuse)"
ids = [
    case(k, 1, f"{PF} flag_test.go:236 testParse", L, "bool", "--bool", "bool true", ["run", "--bool"], run("run", bool="true"), tree="pf"),
    case(k, 2, f"{PF} flag_test.go:237 testParse", L, "bool", "--bool2=true", "true", ["run", "--bool=true"], run("run", bool="true"), tree="pf"),
    case(k, 3, f"{PF} flag_test.go:238 testParse", L, "bool", "--bool3=false", "false, and the flag counts as given", ["run", "--bool=false"], run("run", bool="false"), tree="pf"),
    case(k, 4, f"{PF} flag_test.go:244 testParse", L, "space", "--uint 24", "long flag, value in the next word", ["run", "--string", "24"], run("run", string="24"), tree="pf"),
    case(k, 5, f"{PF} flag_test.go:249 testParse", L, "eq", "--string=hello", "hello", ["run", "--string=hello"], run("run", string="hello"), tree="pf"),
    case(k, 6, f"{PF} flag_test.go:240 testParse", L, "dash-value", "--int8=-8", "a value after = may start with -", ["run", "--string=-8"], run("run", string="-8"), tree="pf"),
    case(k, 7, f"{PF} flag_test.go:257 testParse", L, "interspersed", "flags then one-extra-argument", "one positional left", ["run", "--bool", "one-extra-argument"], run("run", ["one-extra-argument"], bool="true"), tree="pf"),
    case(k, 8, f"{PF} flag_test.go:388 testParse", L, "unknown-flag", "--unknown", "unknown flag: --unknown", ["run", "--unknown"], err("unknown-flag", "run", "--unknown"), tree="pf"),
    case(k, 9, f"{PF} flag_test.go:397 testParse", L, "bool", "--bool=abcdefg", "invalid argument … must be true or false", ["run", "--bool=abcdefg"], err("bad-value", "run", "--bool"), tree="pf"),
    case(k, 10, f"{PF} flag_test.go:406 testParse", L, "missing-value", "--int (last word)", "flag needs an argument: --int", ["run", "--string"], err("missing-value", "run", "--string"), tree="pf"),
]
row(k, "flag_test.go:207", "testParse (via TestParse, TestFlagSetParse): bool/string/unknown/missing parts", "IN", "", ids)
row(k, "flag_test.go:207", "testParse: int/uint/float/ip/mask/duration parts", "OUT", "typed-value")
row(k, "flag_test.go:230", "testParse: optional-int NoOptDefVal parts", "OUT", "optional-value")
row(k, "flag_test.go:769", "TestParse", "IN", "", ids)
row(k, "flag_test.go:837", "TestFlagSetParse", "IN", "", ids)
ids = [
    case(k, 11, f"{PF} flag_test.go:430 testParseAll", L, "short-group", "-ab (two bool shorts)", "both true", ["run", "-bv"], run("run", bool="true", verbose="true"), tree="pf",
         ours=err("unknown-flag", "run", "-bv"), why=D11),
    case(k, 12, f"{PF} flag_test.go:431 testParseAll", L, "short-group", "-cs=xx (bool short, then value short with =)", "c true, s=xx", ["run", "-bs=xx"], run("run", bool="true", string="xx"), tree="pf",
         ours=err("unknown-flag", "run", "-bs"), why=D11),
    case(k, 13, f"{PF} flag_test.go:433 testParseAll", L, "short-eq", "-d=true (bool short with =value)", "true", ["run", "-b=true"], run("run", bool="true"), tree="pf"),
    case(k, 14, f"{PF} flag_test.go:435 testParseAll", L, "short", "-y ee", "y=ee", ["run", "-s", "ee"], run("run", string="ee"), tree="pf"),
    case(k, 15, f"{PF} flag_test.go:433 testParseAll", L, "short-eq", "-d=true, carried to false", "short bool takes =false too", ["run", "-b=false"], run("run", bool="false"), tree="pf"),
]
row(k, "flag_test.go:416", "testParseAll (via TestParseAll)", "IN", "", ids)
row(k, "flag_test.go:434", "testParseAll: -x NoOptDefVal on a string", "OUT", "optional-value")
row(k, "flag_test.go:811", "TestParseAll", "IN", "", ids)
for ln, name in [(816, "TestIgnoreUnknownFlags"), (821, "TestIgnoreUnknownFlagsBackwardsCompat"), (826, "TestIgnoreUnknownFlagsAndPassToArgs"),
                 (831, "TestIgnoreUnknownFlagsAndPassToArgsBackwardsCompat"), (1657, "TestPassUnknownFlagToArgsWithNonInterspersed")]:
    row(k, f"flag_test.go:{ln}", name, "OUT", "other: unknown-flag allowlist/passthrough (not in the grammar)")
ids = [
    case(k, 16, f"{PF} flag_test.go:668 TestShorthand", L, "short-group", "-ab extra -cs hello -z=something -d=true -- --i-look-like-a-flag",
         "a b c d true, s=hello, z=something, args [extra --i-look-like-a-flag], ArgsLenAtDash 1",
         ["run", "-bv", "extra", "-s", "hello", "-f=something", "--", "--i-look-like-a-flag"],
         run("run", ["extra", "--i-look-like-a-flag"], bool="true", verbose="true", string="hello", file="something"), tree="pf",
         ours=err("unknown-flag", "run", "-bv"), why=D11, note="the whole line minus -d=true (a second -b is D15 for everyone; 013 has it); 017-020 split it"),
    case(k, 17, f"{PF} flag_test.go:668 TestShorthand", L, "interspersed", "-b extra -s hello (positional between flags)", "args [extra]", ["run", "-b", "extra", "-s", "hello"],
         run("run", ["extra"], bool="true", string="hello"), tree="pf"),
    case(k, 18, f"{PF} flag_test.go:671 TestShorthand", L, "short-group", "-cs hello (group ends in a value flag, value in next word)", "c true, s=hello", ["run", "-bs", "hello"],
         run("run", bool="true", string="hello"), tree="pf", ours=err("unknown-flag", "run", "-bs"), why=D11),
    case(k, 19, f"{PF} flag_test.go:673 TestShorthand", L, "short-eq", "-z=something", "z=something", ["run", "-f=something"], run("run", file="something"), tree="pf"),
    case(k, 20, f"{PF} flag_test.go:675 TestShorthand", L, "dash-dash", "-- --i-look-like-a-flag", "after --, a flag-looking word is a positional", ["run", "-b", "--", "--i-look-like-a-flag"],
         run("run", ["--i-look-like-a-flag"], bool="true"), tree="pf"),
    case(k, 21, f"{PF} flag_test.go:714 TestShorthand", L, "unknown-flag", "-ukn", "unknown shorthand flag: 'u' in -ukn", ["run", "-ukn"], err("unknown-flag", "run", "-u"), tree="pf",
         ours=err("unknown-flag", "run", "-ukn"), why=D11 + ": with no grouping the whole word is the unknown flag"),
    case(k, 22, f"{PF} flag_test.go:723 TestShorthand", L, "missing-value", "-as (s needs a value, nothing follows)", "flag needs an argument: 's' in -s", ["run", "-bs"],
         err("missing-value", "run", "-s"), tree="pf", ours=err("unknown-flag", "run", "-bs"), why=D11),
]
row(k, "flag_test.go:655", "TestShorthand", "IN", "", ids)
row(k, "flag_test.go:733", "TestShorthandLookup", "OUT", "api-only")
row(k, "flag_test.go:841", "TestParseRepeated", "OUT", "api-only")
ids = [case(k, 23, f"{PF} flag_test.go:888 TestChangedHelper", L, "bool", "--changed --settrue --setfalse=false", "all three Changed (given), even =false; the untouched one not; ArgsLenAtDash -1",
            ["run", "--bool", "--verbose=false"], run("run", bool="true", verbose="false"), tree="pf")]
row(k, "flag_test.go:881", "TestChangedHelper", "IN", "", ids)
for ln, name in [(956, "TestWordSepNormalizedNames"), (994, "TestCustomNormalizedNames"), (1018, "TestNormalizationFuncShouldChangeFlagName"),
                 (1043, "TestNormalizationSharedFlags"), (1076, "TestNormalizationSetFlags"), (1444, "TestMultipleNormalizeFlagNameInvocations")]:
    row(k, f"flag_test.go:{ln}", name, "OUT", "normalisation")
ids = [
    case(k, 24, f"{PF} flag_test.go:1129 TestUserDefined", L, "repeat", "--v=1 -v2 -v 3 on a repeatable value", "three values in order", ["run", "--filter=1", "--filter", "2", "--filter", "3"],
         run("run", filter=["1", "2", "3"]), tree="pf", note="the only repeatable flag here is --filter (D6); it has no short, so -v2 is carried by 025"),
    case(k, 25, f"{PF} flag_test.go:1129 TestUserDefined", L, "short-attached", "-v2", "attached short value", ["run", "-s2"], run("run", string="2"), tree="pf",
         ours=err("unknown-flag", "run", "-s2"), why=D11),
]
row(k, "flag_test.go:1124", "TestUserDefined", "IN", "", ids)
row(k, "flag_test.go:1141", "TestSetOutput", "IN", "", ["pflag-008"])
row(k, "flag_test.go:1157", "TestOutput", "OUT", "api-only")
ids = [case(k, 26, f"{PF} flag_test.go:1174 TestChangingArgs", L, "global", "cmd --before subcmd ; subcmd --after args (two parses, the caller dispatches)",
            "before true, cmd subcmd, after true, args [args]", ["-c", "/x", "nodes", "delete", "--force", "12"],
            run("nodes delete", ["12"], config="/x", force="true"))]
row(k, "flag_test.go:1170", "TestChangingArgs", "IN", "", ids)
ids = [case(k, 27, f"{PF} flag_test.go:1210 TestHelp", L, "help", "--help with no help flag defined", "ErrHelp", ["run", "--help"], help_("run"), tree="pf")]
row(k, "flag_test.go:1191", "TestHelp", "IN", "", ids)
ids = [case(k, 28, f"{PF} flag_test.go:1238 TestNoInterspersed", L, "interspersed", "SetInterspersed(false): --true break --false", "args [break --false]: stop at the first positional",
            ["run", "--bool", "break", "--verbose"], run("run", ["break", "--verbose"], bool="true"), tree="pf",
            ours=run("run", ["break"], bool="true", verbose="true"), why="DECISIONS facts: flags and positionals mix in any order (pflag's default too)")]
row(k, "flag_test.go:1233", "TestNoInterspersed", "IN", "", ids)
ids = [case(k, 29, f"{PF} flag_test.go:1256 TestTermination", L, "dash-dash", "-- ls -l (l is a bool short)", "bool false, args [ls -l], ArgsLenAtDash 0",
            ["run", "--", "ls", "-b"], run("run", ["ls", "-b"]), tree="pf")]
row(k, "flag_test.go:1248", "TestTermination", "IN", "", ids)
ids = [case(k, 30, f"{PF} flag_test.go:122 TestNoArgument", L, "tree", "empty argv", "no error", ["run"], run("run"), tree="pf")]
row(k, "flag_test.go:122", "TestNoArgument", "IN", "", ids)
row(k, "flag_test.go:128", "TestUsage", "IN", "", ["pflag-008"])
for ln, name, why in [(43, "TestEverything", "api-only"), (144, "TestAddFlagSet", "api-only"), (161, "TestAnnotation", "api-only"), (197, "TestName", "api-only"),
                      (1292, "TestDeprecatedFlagInDocs", "deprecated"), (1304, "TestUnHiddenDeprecatedFlagInDocs", "deprecated"),
                      (1325, "TestDeprecatedFlagShorthandInDocs", "deprecated"), (1363, "TestDeprecatedFlagUsage", "deprecated"),
                      (1380, "TestDeprecatedFlagShorthandUsage", "deprecated"), (1398, "TestDeprecatedFlagUsageNormalized", "deprecated"),
                      (1416, "TestDeprecatedFlagUsageAlias", "deprecated"), (1456, "TestHiddenFlagInUsage", "deprecated"), (1470, "TestHiddenFlagUsage", "deprecated"),
                      (1537, "TestPrintDefaults", "help-format"), (1585, "TestCustomIsBoolFlagDefaultIsZeroValue", "help-format"),
                      (1599, "TestPrintDefaultsCustomIsBoolFlagOmitsDefault", "help-format"), (1615, "TestVisitAllFlagOrder", "api-only"),
                      (1637, "TestVisitFlagOrder", "api-only"), (1745, "TestNewFlagSetDefaultUsage", "help-format"), (1763, "TestFlagSetInitDefaultUsage", "help-format")]:
    row(k, f"flag_test.go:{ln}", name, "OUT", why)
row(k, "flag_test.go:777", "TestInvalidArgumentMessages/bool", "IN", "", ["pflag-009"])
for t in ["int", "uint", "float64", "duration"]:
    row(k, "flag_test.go:777", f"TestInvalidArgumentMessages/{t}", "OUT", "typed-value")
# bool_test.go
B = lambda ln, t: f"{PF} bool_test.go:{ln} {t}"
ids = {
    "TestExplicitTrue": case(k, 31, B(69, "TestExplicitTrue"), L, "bool", "--tristate=true", "true", ["run", "--bool=true"], run("run", bool="true"), tree="pf"),
    "TestImplicitTrue": case(k, 32, B(81, "TestImplicitTrue"), L, "bool", "--tristate", "true", ["run", "--bool"], run("run", bool="true"), tree="pf"),
    "TestShortFlag": case(k, 33, B(93, "TestShortFlag"), L, "bool", "-t", "true", ["run", "-b"], run("run", bool="true"), tree="pf"),
    "TestShortFlagExtraArgument": case(k, 34, B(106, "TestShortFlagExtraArgument"), L, "bool", "-t maybe", "a bool never takes the next word: maybe is a positional",
                                       ["run", "-b", "maybe"], run("run", ["maybe"], bool="true"), tree="pf"),
    "TestExplicitFalse": case(k, 35, B(134, "TestExplicitFalse"), L, "bool", "--tristate=false", "false", ["run", "--bool=false"], run("run", bool="false"), tree="pf"),
    "TestImplicitFalse": case(k, 36, B(146, "TestImplicitFalse"), L, "bool", "no flag", "not given", ["run", "x"], run("run", ["x"]), tree="pf"),
    "TestInvalidValue": case(k, 37, B(188, "TestInvalidValue"), L, "bool", "--tristate=invalid", "error", ["run", "--bool=invalid"], err("bad-value", "run", "--bool"), tree="pf"),
    "TestLongBoolTrueTakesNoNextWord": case(k, 38, B(106, "TestShortFlagExtraArgument"), L, "bool", "-t maybe, carried to the long form", "--bool true does not eat true",
                                            ["run", "--bool", "true"], run("run", ["true"], bool="true"), tree="pf",
                                            note="pflag reads `--bool true` as bool + positional `true` (no test pins the long form; same rule as -t maybe in pflag's parseLongArg)"),
}
for ln, name in [(66, "TestExplicitTrue"), (78, "TestImplicitTrue"), (90, "TestShortFlag"), (102, "TestShortFlagExtraArgument"), (131, "TestExplicitFalse"),
                 (143, "TestImplicitFalse"), (183, "TestInvalidValue")]:
    row(k, f"bool_test.go:{ln}", name, "IN", "", [ids[name]] + (["pflag-038"] if name == "TestShortFlagExtraArgument" else []))
row(k, "bool_test.go:155", "TestCustomIsBoolFlagGetsNoOptDefaultAutomatically", "IN", "", [ids["TestImplicitTrue"]])
row(k, "bool_test.go:169", "TestCustomIsBoolFlagShortFormGetsNoOptDefaultAutomatically", "IN", "", [ids["TestShortFlag"]])
row(k, "bool_test.go:119", "TestExplicitMaybe", "OUT", "typed-value")
row(k, "bool_test.go:194", "TestBoolP", "IN", "", [ids["TestImplicitTrue"]])
# string_slice_test.go / string_array_test.go
S = lambda f_, ln, t: f"{PF} {f_}:{ln} {t}"
i39 = case(k, 39, S("string_slice_test.go", 64, "TestSS"), L, "verbatim", "--ss=one,two,4,3", "[one two 4 3] (the split is the slice type's)", ["run", "--list=one,two,4,3"],
           run("run", list="one,two,4,3"), tree="pf", note="the parser hands the word over verbatim; splitting on commas is the layer's in Headscale (D6)")
i40 = case(k, 40, S("string_slice_test.go", 149, "TestSSCalledTwice"), L, "repeat", "--ss=one,two --ss=three", "appended: [one two three]",
           ["run", "--list=one,two", "--list=three"], run("run", list=["one,two", "three"]), tree="pf",
           ours=err("flag-repeated", "run", "--list"), why="D6/D15: a repeated list flag is an error")
i41 = case(k, 41, S("string_slice_test.go", 45, "TestEmptySSValue"), L, "empty-value", "--ss=", "an empty list (len 0)", ["run", "--list="], run("run", list=""), tree="pf",
           note="parser level both deliver \"\"; pflag's slice type turns it into an empty list, the kit's layer (strings.Split) into [\"\"]: a layer question, see edge-corpus.md")
i42 = case(k, 42, S("string_array_test.go", 44, "TestEmptySAValue"), L, "empty-value", "--sa= (StringArray, the repeatable type)", "an empty array (len 0): the empty value is dropped",
           ["run", "--filter="], {"kind": "run", "path": "run", "flags": {"filter": []}}, tree="pf",
           ours=run("run", filter=""), why="undecided: is `--filter=` an empty filter, a no-op or an error? (layer question; the parser delivers \"\")")
i43 = case(k, 43, S("string_array_test.go", 127, "TestSACalledTwice"), L, "repeat", "--sa=one --sa=two", "[one two]", ["run", "--filter=one", "--filter=two"],
           run("run", filter=["one", "two"]), tree="pf")
i44 = case(k, 44, S("string_array_test.go", 167, "TestSAWithSpecialChar"), L, "verbatim", "--sa=one,two --sa='\"three\"' --sa='\"four,five\",six' --sa='seven eight'",
           "each value verbatim: commas, quotes and spaces kept", ["run", "--filter=one,two", "--filter=\"three\"", "--filter=\"four,five\",six", "--filter=seven eight"],
           run("run", filter=["one,two", "\"three\"", "\"four,five\",six", "seven eight"]), tree="pf")
i45 = case(k, 45, S("string_array_test.go", 229, "TestSAWithSquareBrackets"), L, "verbatim", "--sa=][]-[ --sa=[a-z] --sa=[a-z]+", "verbatim",
           ["run", "--filter=][]-[", "--filter=[a-z]", "--filter=[a-z]+"], run("run", filter=["][]-[", "[a-z]", "[a-z]+"]), tree="pf")
for ln, name, verdict, reason, i in [
    (25, "TestEmptySS", "OUT", "api-only", None), (42, "TestEmptySSValue", "IN", "", i41), (59, "TestSS", "IN", "", i39), (86, "TestSSDefault", "OUT", "api-only", None),
    (113, "TestSSWithDefault", "OUT", "api-only", None), (140, "TestSSCalledTwice", "IN", "", i40),
    (178, "TestSSWithComma", "OUT", "other: list-split (CSV quoting inside a list item; the split is Headscale's layer, D6)", None),
    (217, "TestSSWithSquareBrackets", "OUT", "other: list-split (CSV quoting inside a list item; the split is Headscale's layer, D6)", None),
    (255, "TestSSAsSliceValue", "OUT", "api-only", None), (278, "TestSSAsSliceValueAppend", "OUT", "api-only", None)]:
    row(k, f"string_slice_test.go:{ln}", name, verdict, reason, [i] if i else [])
for ln, name, verdict, reason, i in [
    (24, "TestEmptySA", "OUT", "api-only", None), (41, "TestEmptySAValue", "IN", "", i42), (58, "TestSADefault", "OUT", "api-only", None),
    (85, "TestSAWithDefault", "OUT", "api-only", None), (118, "TestSACalledTwice", "IN", "", i43), (156, "TestSAWithSpecialChar", "IN", "", i44),
    (196, "TestSAAsSliceValue", "OUT", "api-only", None), (219, "TestSAWithSquareBrackets", "IN", "", i45)]:
    row(k, f"string_array_test.go:{ln}", name, verdict, reason, [i] if i else [])
# errors_test.go: error types (D4: code can inspect which flag)
for ln, name in [(8, "TestNotExistError"), (22, "TestValueRequiredError"), (40, "TestInvalidValueError"), (59, "TestInvalidSyntaxError")]:
    row(k, f"errors_test.go:{ln}", name, "OUT", "api-only")
# every other pflag test file: typed values, help or the Go-flag bridge
pfdir = os.path.join(out, "..", "src", "pflag")
done = {"flag_test.go", "bool_test.go", "string_slice_test.go", "string_array_test.go", "errors_test.go"}
for fn in sorted(os.listdir(pfdir)):
    if not fn.endswith("_test.go") or fn in done:
        continue
    reason = {"printusage_test.go": "help-format", "golangflag_test.go": "api-only", "example_test.go": "api-only", "export_test.go": "api-only",
              "text_test.go": "typed-value", "func_test.go": "typed-value", "func_go1.21_test.go": "typed-value",
              "bool_func_test.go": "typed-value", "bool_func_go1.21_test.go": "typed-value"}.get(fn, "typed-value")
    for n, l in enumerate(open(os.path.join(pfdir, fn)), 1):
        m = re.match(r"func (Test\w+|Example\w*)\(", l)
        if m:
            row(k, f"{fn}:{n}", m.group(1), "OUT", reason)

# ---------------------------------------------------------------- Go flag
k, L = "goflag", "BSD-3-Clause"
G = lambda ln, t: f"{GO} flag_test.go:{ln} {t}"
i1 = case(k, 1, G(246, "testParse"), L, "long", "-bool -bool2=true --int 22 -string hello … extra", "one dash and two dashes both name a long flag",
          ["run", "-string", "hello"], run("run", string="hello"), tree="pf", ours=err("unknown-flag", "run", "-string"),
          why="D11 (kit X02): one dash takes one letter; stdlib flag style is not the grammar")
i2 = case(k, 2, G(248, "testParse"), L, "space", "--int 22", "double-dash long, value in the next word", ["run", "--string", "22"], run("run", string="22"), tree="pf")
i3 = case(k, 3, G(255, "testParse"), L, "interspersed", "flags then extra", "extra is the one positional", ["run", "--bool", "extra"], run("run", ["extra"], bool="true"), tree="pf")
row(k, "flag_test.go:230", "TestParse (testParse)", "IN", "", [i1, i2, i3])
row(k, "flag_test.go:235", "TestFlagSetParse (testParse)", "IN", "", [i1, i2, i3])
row(k, "flag_test.go:230", "testParse typed parts", "OUT", "typed-value")
i4 = case(k, 4, G(257, "TestUserDefined"), L, "repeat", "-v 1 -v 2 -v=3 on a repeatable Value", "[1 2 3]", ["run", "--filter", "1", "--filter", "2", "--filter=3"],
          run("run", filter=["1", "2", "3"]), tree="pf")
row(k, "flag_test.go:251", "TestUserDefined", "IN", "", [i4])
i5 = case(k, 5, G(349, "TestUserDefinedBool"), L, "interspersed", "-b -b -b -b=true -b=false -b barg -b", "stops at barg: the last -b is a positional (flag stops at the first non-flag)",
          ["run", "-b", "barg", "-v"], run("run", ["barg", "-v"], bool="true"), tree="pf",
          ours=run("run", ["barg"], bool="true", verbose="true"), why="DECISIONS facts: flags and positionals mix in any order")
row(k, "flag_test.go:342", "TestUserDefinedBool", "IN", "", [i5])
i6 = case(k, 6, G(441, "TestHelp"), L, "help", "-help (no help flag defined)", "ErrHelp", ["run", "-help"], help_("run"), tree="pf",
          ours=err("unknown-flag", "run", "-help"), why="D8/D11: only -h and --help; one dash takes one letter")
i7 = case(k, 7, G(684, "TestExitCode"), L, "unknown-flag", "-undefined", "exit 2, flag provided but not defined", ["run", "--undefined"], err("unknown-flag", "run", "--undefined"), tree="pf",
          note="carried with two dashes; the exit code is the layer's (001: 1)")
row(k, "flag_test.go:423", "TestHelp", "IN", "", [i6])
row(k, "flag_test.go:660", "TestExitCode", "IN", "", [i6, i7])
i8 = case(k, 8, f"{GO} flag.go:1090 parseOne", L, "unknown-flag", "---x", "bad flag syntax", ["run", "---bool"], err("unknown-flag", "run", "---bool"), tree="pf",
          note="from the code, no test pins it")
i9 = case(k, 9, f"{GO} flag.go:1090 parseOne", L, "unknown-flag", "--=x", "bad flag syntax", ["run", "--=x"], err("unknown-flag", "run", "--=x"), tree="pf",
          note="from the code, no test pins it")
i10 = case(k, 10, f"{GO} flag.go:67 package doc", L, "dash-value", "- alone", "\"-\" is a non-flag argument", ["run", "-"], run("run", ["-"]), tree="pf")
i11 = case(k, 11, f"{GO} flag.go:1086 parseOne", L, "dash-dash", "--", "terminates the flags; not kept", ["run", "--", "x"], run("run", ["x"]), tree="pf")
i12 = case(k, 12, f"{GO} flag.go:67 package doc (-flag=x) + https://github.com/spf13/cobra/issues/2358", L, "long", "-description=foo (stdlib style one-dash long)",
           "flag: description=foo. pflag reads it as -d with the value escription=foo", ["auth", "keys", "create", "alice", "-description=foo"],
           run("auth keys create", ["alice"], description="foo"), ours=err("unknown-flag", "auth keys create", "-description=foo"),
           why="D11 (kit X02): one dash takes one letter", note="the trap for a pflag-based parser: a free-text short silently takes the rest of the word")
row(k, "flag.go (code) + cobra#2358", i12, "IN", "", [i12])
for i in [i8, i9, i10, i11]:
    row(k, "flag.go (code)", i, "IN", "", [i])
for ln, name, why in [(31, "TestEverything", "api-only"), (109, "TestGet", "api-only"), (153, "TestUsage", "help-format"), (269, "TestUserDefinedFunc", "typed-value"),
                      (312, "TestUserDefinedForCommandLine", "api-only"), (364, "TestUserDefinedBoolUsage", "help-format"), (389, "TestSetOutput", "api-only"),
                      (402, "TestChangingArgs", "IN"), (519, "TestPrintDefaults", "help-format"), (546, "TestIntFlagOverflow", "typed-value"),
                      (562, "TestUsageOutput", "help-format"), (575, "TestGetters", "api-only"), (608, "TestParseError", "typed-value"),
                      (632, "TestRangeError", "typed-value"), (740, "TestInvalidFlags", "api-only"), (772, "TestRedefinedFlags", "api-only"),
                      (806, "TestUserDefinedBoolFunc", "typed-value"), (849, "TestDefineAfterSet", "api-only")]:
    if why == "IN":
        row(k, f"flag_test.go:{ln}", name, "IN", "", ["pflag-026"])
    else:
        row(k, f"flag_test.go:{ln}", name, "OUT", why)
row(k, "flag_test.go:608", "TestParseError/bool", "IN", "", ["pflag-009"])

# ---------------------------------------------------------------- cobra command tree
k, L = "cobracmd", "Apache-2.0"
C = lambda ln, t, f_="command_test.go": f"{CB} {f_}:{ln} {t}"
G10 = "D10: a group never runs; alone it is help"
T = {}
T["TestSingleCommand"] = [case(k, 1, C(99, "TestSingleCommand"), L, "tree", "runnable root with ExactArgs(2) and children a, b: `one two`", "root runs with [one two]",
                               ["one", "two"], run("", ["one", "two"]), ours=err("unknown-command", "", "one"), why=G10)]
T["TestChildCommand"] = [case(k, 2, C(124, "TestChildCommand"), L, "tree", "child1 one two", "child1 runs with [one two]", ["nodes", "routes", "set", "one", "two"],
                              run("nodes routes set", ["one", "two"]))]
T["TestCallCommandWithoutSubcommands"] = [case(k, 3, C(140, "TestCallCommandWithoutSubcommands"), L, "tree", "runnable root, no args", "root runs", [], run(""),
                                               ours=help_(""), why=G10)]
T["TestRootExecuteUnknownCommand"] = [case(k, 4, C(150, "TestRootExecuteUnknownCommand"), L, "unknown-cmd", "unknown", "unknown command \"unknown\" for \"root\"", ["unknown"],
                                           err("unknown-command", "", "unknown"))]
T["TestSubcommandExecuteC"] = [case(k, 5, C(164, "TestSubcommandExecuteC"), L, "tree", "child", "child runs", ["serve"], run("serve"))]
T["TestCommandAlias"] = [case(k, 6, C(294, "TestCommandAlias"), L, "alias", "tell times one two (tell: alias of the group echo)", "times runs with [one two]",
                              ["nodes", "routes", "approve", "one", "two"], run("nodes routes set", ["one", "two"]),
                              note="001 has aliases on leaves only, so the alias is carried to the leaf level")]
T["TestEnablePrefixMatching"] = [case(k, 7, C(318, "TestEnablePrefixMatching"), L, "abbrev", "EnablePrefixMatching: a one two", "aCmd runs", ["serv"], run("serve"),
                                      ours=err("unknown-command", "", "serv"), why="no abbreviations (DECISIONS facts: 001 never guesses); cobra's default is off too")]
T["TestAliasPrefixMatching"] = [case(k, 8, C(352, "TestAliasPrefixMatching"), L, "abbrev", "EnablePrefixMatching: sa times one two (prefix of alias say)", "times runs",
                                     ["nodes", "routes", "appr", "12", "r"], run("nodes routes set", ["12", "r"]),
                                     ours=err("unknown-command", "nodes routes", "appr"), why="no abbreviations (DECISIONS facts)")]
T["TestChildSameName"] = [case(k, 9, C(448, "TestChildSameName"), L, "tree", "root foo, child foo: foo one two", "the child runs", ["grp", "grp", "one"], run("grp grp", ["one"]), tree="pf",
                               note="carried: a child named like its parent group")]
T["TestGrandChildSameName"] = [case(k, 10, C(477, "TestGrandChildSameName"), L, "tree", "bar foo one two (grandchild foo, root foo)", "grandchild runs",
                                    ["grp", "grp", "grp"], run("grp grp", ["grp"]), tree="pf", note="a positional equal to both names stays a positional")]
T["TestFlagLong"] = [case(k, 11, C(505, "TestFlagLong"), L, "dash-dash", "--intf=7 --sf=abc one -- two", "sf=abc, args [one two], ArgsLenAtDash 1",
                          ["run", "--string=abc", "one", "--", "two"], run("run", ["one", "two"], string="abc"), tree="pf")]
T["TestFlagShort"] = [case(k, 12, C(542, "TestFlagShort"), L, "short-attached", "-i 7 -sabc one two", "i=7, s=abc, args [one two]", ["run", "-f", "7", "-sabc", "one", "two"],
                           run("run", ["one", "two"], file="7", string="abc"), tree="pf", ours=err("unknown-flag", "run", "-sabc"), why=D11)]
T["TestChildFlag"] = [case(k, 13, C(571, "TestChildFlag"), L, "short-attached", "child -i7", "i=7", ["auth", "keys", "create", "alice", "-e24h"],
                           run("auth keys create", ["alice"], expiry="24h"), ours=err("unknown-flag", "auth keys create", "-e24h"), why=D11)]
T["TestChildFlagWithParentLocalFlag"] = [case(k, 14, C(593, "TestChildFlagWithParentLocalFlag"), L, "unknown-flag", "child -i7 -sabc (s is a local flag of root)",
                                              "unknown shorthand: a parent's local flag is not the child's", ["nodes", "list", "--version"], err("unknown-flag", "nodes list", "--version"),
                                              note="carried: --version is the root's local flag")]
T["TestFlagBeforeCommand"] = [
    case(k, 15, C(624, "TestFlagBeforeCommand"), L, "global", "-i7 child (i is the child's flag)", "accepted: Find steps over it, the child parses it",
         ["-e", "24h", "api", "keys", "create"], run("api keys create", expiry="24h"),
         ours=err("unknown-flag", "", "-e"), why="undecided: may a leaf's own flag come before the subcommand? 001 promises it only for -c/-o (D3); cobra's own Traverse mode refuses it (cobracmd-033)"),
    case(k, 16, C(631, "TestFlagBeforeCommand"), L, "global", "--intf=8 child", "accepted", ["--expiry=24h", "api", "keys", "create"], run("api keys create", expiry="24h"),
         ours=err("unknown-flag", "", "--expiry"), why="undecided: as cobracmd-015"),
]
T["TestStripFlags"] = [
    case(k, 17, C(656, "TestStripFlags"), L, "verbatim", "[-s foo --str bar] -> no command words (the values are not commands)", "values of value flags are never command words",
         ["-c", "nodes", "nodes", "list"], run("nodes list", config="nodes")),
    case(k, 18, C(672, "TestStripFlags"), L, "global", "[-i=10 echo] -> [echo]", "short = value before the command", ["-c=/x", "nodes", "list"], run("nodes list", config="/x")),
    case(k, 19, C(676, "TestStripFlags"), L, "global", "[--int=100 echo] -> [echo]", "long = value before the command", ["--config=/x", "nodes", "list"], run("nodes list", config="/x")),
]
T["TestEmptyInputs"] = [case(k, 20, C(773, "TestEmptyInputs"), L, "empty-value", "\"\" -i7 \"\"", "no error, i=7 (the empty words are positionals)",
                             ["nodes", "routes", "set", "", "-o", "json", ""], run("nodes routes set", ["", ""], output="json"),
                             note="the test asserts no error and the flag only; the args are carried as positionals")]
T["TestPersistentFlagsOnChild"] = [case(k, 21, C(828, "TestPersistentFlagsOnChild"), L, "global", "child -c7 -p8 one two (p: root persistent)", "both set, args [one two]",
                                        ["nodes", "routes", "set", "-c", "/x", "-o", "json", "12", "r"], run("nodes routes set", ["12", "r"], config="/x", output="json"))]
T["TestPersistentFlagsOnSameCommand"] = [case(k, 22, C(749, "TestPersistentFlagsOnSameCommand"), L, "global", "runnable root: -i7 one two", "root runs with [one two], i=7",
                                              ["-c", "/x", "one", "two"], run("", ["one", "two"], config="/x"), ours=err("unknown-command", "", "one"), why=G10)]
T["TestHelpCommandExecuted"] = [case(k, 23, C(945, "TestHelpCommandExecuted"), L, "help", "help", "root help", ["help"], help_(""), ours=err("unknown-command", "", "help"), why="D8: no help command")]
T["TestHelpCommandExecutedOnChild"] = [case(k, 24, C(958, "TestHelpCommandExecutedOnChild"), L, "help", "help child", "child help", ["help", "nodes"], help_("nodes"),
                                            ours=err("unknown-command", "", "help"), why="D8")]
T["TestHelpFlagExecuted"] = [case(k, 25, C(1067, "TestHelpFlagExecuted"), L, "help", "--help", "root help", ["--help"], help_(""))]
T["TestHelpFlagExecutedOnChild"] = [case(k, 26, C(1080, "TestHelpFlagExecutedOnChild"), L, "help", "child --help", "child help", ["nodes", "list", "--help"], help_("nodes list"))]
T["TestHelpExecutedOnNonRunnableChild"] = [case(k, 27, C(1121, "TestHelpExecutedOnNonRunnableChild"), L, "help", "child (not runnable)", "child help", ["nodes"], help_("nodes"))]
T["TestVersionFlagExecuted"] = [case(k, 28, C(1171, "TestVersionFlagExecuted"), L, "help", "--version arg1", "version printed, arg ignored", ["--version", "arg1"], {"kind": "version"},
                                     ours=err("unknown-command", "", "arg1"), why="undecided: does --version win over a stray word? (D7 names only `headscale --version`)")]
T["TestVersionFlagExecutedOnSubcommand"] = [case(k, 29, C(1304, "TestVersionFlagExecutedOnSubcommand"), L, "help", "--version sub", "root version printed",
                                                 ["--version", "nodes", "list"], {"kind": "version"}, ours=err("unknown-flag", "nodes list", "--version"),
                                                 why="undecided: --version before a subcommand (D7 names only `headscale --version`)")]
T["TestVersionFlagOnlyAddedToRoot"] = [case(k, 30, C(1328, "TestVersionFlagOnlyAddedToRoot"), L, "unknown-flag", "sub --version", "unknown flag: --version",
                                            ["nodes", "list", "--version"], err("unknown-flag", "nodes list", "--version"))]
T["TestShorthandVersionFlagExecuted"] = [case(k, 31, C(1235, "TestShorthandVersionFlagExecuted"), L, "short", "-v arg1 (v: version shorthand)", "version printed",
                                              ["-v"], {"kind": "version"}, ours=err("unknown-flag", "", "-v"), why="D7: --version has no short form")]
T["TestCaseInsensitive"] = [
    case(k, 32, C(1490, "TestCaseInsensitive"), L, "tree", "CHILD (EnableCaseInsensitive off, the default)", "unknown command", ["NODES", "list"], err("unknown-command", "", "NODES")),
    case(k, 33, C(1530, "TestCaseInsensitive"), L, "alias", "alternative alias (case off)", "unknown command for a wrong-case alias", ["nodes", "LS"], err("unknown-command", "nodes", "LS")),
]
T["TestTraverseWithParentFlags"] = [case(k, 34, C(2330, "TestTraverseWithParentFlags"), L, "global", "TraverseChildren: -b --str ok child --int", "child found, parent flags read",
                                         ["-o", "json", "--config", "ok", "nodes", "list", "--list-columns"], run("nodes list", config="ok", output="json", list_columns="true"))]
T["TestTraverseNoParentFlags"] = [case(k, 35, C(2351, "TestTraverseNoParentFlags"), L, "tree", "child", "child", ["check", "config"], run("check config"))]
T["TestTraverseWithBadParentFlags"] = [case(k, 36, C(2371, "TestTraverseWithBadParentFlags"), L, "global", "TraverseChildren: --str ok child (str is the child's)",
                                            "unknown flag: --str", ["--expiry", "24h", "api", "keys", "create"], err("unknown-flag", "", "--expiry"))]
T["TestTraverseWithBadChildFlag"] = [case(k, 37, C(2392, "TestTraverseWithBadChildFlag"), L, "unknown-flag", "child --str (str: the root's local flag)",
                                          "Traverse leaves it to the child, which refuses it", ["nodes", "list", "--version"], err("unknown-flag", "nodes list", "--version"))]
T["TestTraverseWithTwoSubcommands"] = [case(k, 38, C(2411, "TestTraverseWithTwoSubcommands"), L, "tree", "sub subsub", "subsub", ["auth", "keys", "create", "a"], run("auth keys create", ["a"]))]
T["TestCalledAs"] = [
    case(k, 39, C(2481, "TestCalledAs"), L, "alias", "find/full-alias: that", "child2, called as that", ["nodes", "rm", "12"], run("nodes delete", ["12"])),
    case(k, 40, C(2482, "TestCalledAs"), L, "abbrev", "find/part-no-prefix: thi", "no command (prefix matching off)", ["nodes", "routes", "appr"], err("unknown-command", "nodes routes", "appr")),
]
T["TestFind"] = [
    case(k, 41, C(2810, "TestFind"), L, "tree", "child child", "child, arg [child]", ["users", "delete", "users"], run("users delete", ["users"])),
    case(k, 42, C(2818, "TestFind"), L, "global", "-f child child (f: root persistent string)", "child; -f's value is the word child", ["-c", "nodes", "nodes", "list"], run("nodes list", config="nodes")),
    case(k, 43, C(2822, "TestFind"), L, "global", "child -f child", "child, -f=child", ["nodes", "list", "-c", "nodes"], run("nodes list", config="nodes")),
    case(k, 44, C(2834, "TestFind"), L, "missing-value", "child -b (last word)", "child found; parse then fails: flag needs an argument", ["nodes", "list", "-c"], err("missing-value", "nodes list", "-c")),
    case(k, 45, C(2838, "TestFind"), L, "dash-value", "-b -f child child (b and f strings)", "found args [-b -f child]: -b takes -f as its value, child is a positional of child",
         ["-c", "-o", "nodes", "list"], run("nodes list", config="-o"), note="D20: the word after a value flag is its value"),
    case(k, 46, C(2842, "TestFind"), L, "global", "-f child -b something child", "child", ["-c", "nodes", "-o", "json", "nodes", "list"], run("nodes list", config="nodes", output="json")),
    case(k, 47, C(2846, "TestFind"), L, "missing-value", "-f child child -b", "child; -b lacks its value", ["-c", "nodes", "nodes", "list", "-o"], err("missing-value", "nodes list", "-o")),
    case(k, 48, C(2850, "TestFind"), L, "short-eq", "-f=child -b=something child", "child", ["-c=nodes", "-o=json", "nodes", "list"], run("nodes list", config="nodes", output="json")),
    case(k, 49, C(2854, "TestFind"), L, "global", "--foo child --bar something child", "child", ["--config", "nodes", "--output", "json", "nodes", "list"],
         run("nodes list", config="nodes", output="json")),
]
uk = [
    (2886, ["--config", "x", "--bogus", "nodes", "list", "--list-columns"], ""),
    (2887, ["--config", "x", "nodes", "list", "--bogus", "--list-columns"], "nodes list"),
    (2888, ["--config", "x", "nodes", "list", "--list-columns", "--bogus"], "nodes list"),
    (2889, ["--bogus", "--config=x", "nodes", "list", "--list-columns"], ""),
    (2890, ["--config=x", "--bogus", "nodes", "list", "--list-columns"], ""),
    (2891, ["--config=x", "nodes", "list", "--bogus", "--list-columns"], "nodes list"),
    (2892, ["--config=x", "nodes", "list", "--list-columns", "--bogus"], "nodes list"),
    (2893, ["--bogus", "--config=x", "nodes", "list", "--list-columns=true"], ""),
    (2894, ["--config=x", "--bogus", "nodes", "list", "--list-columns=true"], ""),
    (2895, ["--config=x", "nodes", "list", "--bogus", "--list-columns=true"], "nodes list"),
    (2896, ["--config=x", "nodes", "list", "--list-columns=true", "--bogus"], "nodes list"),
]
T["TestUnknownFlagShouldReturnSameErrorRegardlessOfArgPosition"] = [
    case(k, 50 + i, C(ln, "TestUnknownFlagShouldReturnSameErrorRegardlessOfArgPosition"), L, "unknown-flag", " ".join(a).replace("config", "namespace").replace("--bogus", "--unknown"),
         "unknown flag: --unknown, wherever it is", a, err("unknown-flag", p, "--bogus")) for i, (ln, a, p) in enumerate(uk)]
T["TestUnknownFlagShouldReturnSameErrorRegardlessOfArgPosition"].append(
    case(k, 61, C(2885, "TestUnknownFlagShouldReturnSameErrorRegardlessOfArgPosition (FIXME row)"), L, "unknown-flag", "--unknown --namespace foo child --bar",
         "intended: unknown flag; cobra today: unknown command \"foo\" (commented out as FIXME)", ["--bogus", "--config", "x", "nodes", "list", "--list-columns"],
         err("unknown-flag", "", "--bogus"), note="a known cobra bug kept as a commented-out row"))
T["TestNoRootRunCommandExecutedWithoutVersionSet"] = [case(k, 62, C(2728, "TestNoRootRunCommandExecutedWithoutVersionSet"), L, "help", "non-runnable root, no args", "root help", [], help_(""))]
T["TestHelpflagCommandExecutedWithoutVersionSet"] = [case(k, 63, C(2782, "TestHelpflagCommandExecutedWithoutVersionSet"), L, "help", "--help on root", "root help", ["-h"], help_(""))]
# args_test.go
A = lambda ln, t: C(ln, t, "args_test.go")
T["args:TestRootTakesNoArgs"] = [case(k, 64, A(494, "TestRootTakesNoArgs"), L, "unknown-cmd", "illegal args (root with children)", "unknown command \"illegal\" for \"root\"",
                                      ["illegal", "args"], err("unknown-command", "", "illegal"))]
T["args:TestChildTakesNoArgs"] = [case(k, 65, A(519, "TestChildTakesNoArgs"), L, "unknown-cmd", "child illegal args (leaf with NoArgs)", "unknown command \"illegal\" for \"root child\"",
                                       ["nodes", "list", "illegal", "args"], err("unknown-command", "nodes list", "illegal"),
                                       ours=err("arg-count", "nodes list"), why="quirk: a leaf with too many args is a count error, not an unknown command (R32, kit E20)")]
T["args:TestChildTakesArgs"] = [case(k, 66, A(532, "TestChildTakesArgs"), L, "tree", "child legal args", "accepted", ["nodes", "routes", "set", "legal", "args"], run("nodes routes set", ["legal", "args"]))]
T["args:TestRootTakesArgs"] = [case(k, 67, A(506, "TestRootTakesArgs"), L, "tree", "root ArbitraryArgs with children: legal args", "root runs with [legal args]",
                                    ["legal", "args"], run("", ["legal", "args"]), ours=err("unknown-command", "", "legal"), why=G10)]
T["args:TestLegacyArgsRootAcceptsArgs"] = [case(k, 68, A(555, "TestLegacyArgsRootAcceptsArgs"), L, "tree", "root without children, Args nil: somearg", "accepted",
                                                ["somearg"], run("", ["somearg"]), ours=err("unknown-command", "", "somearg"), why=G10)]
T["args:TestLegacyArgsSubcmdAcceptsArgs"] = [case(k, 69, A(565, "TestLegacyArgsSubcmdAcceptsArgs"), L, "tree", "child (has a grandchild and Run) somearg", "child runs with [somearg]",
                                                  ["nodes", "somearg"], run("nodes", ["somearg"]), ours=err("unknown-command", "nodes", "somearg"), why=G10)]

src = open(os.path.join(out, "..", "src", "cobra", "command_test.go")).read().splitlines()
outmap = {
    "TestExecuteContext": "lifecycle", "TestExecuteContextC": "lifecycle", "TestExecute_NoContext": "lifecycle", "TestRootUnknownCommandSilenced": "help-format",
    "TestPlugin": "help-format", "TestPluginWithSubCommands": "help-format", "TestFlagInvalidInput": "typed-value",
    "TestDisableFlagParsing": "other: DisableFlagParsing (no pass-through commands in 001)", "TestChildFlagShadowsParentPersistentFlag": "api-only",
    "TestRequiredFlags": "layer-validation", "TestPersistentRequiredFlags": "layer-validation", "TestPersistentRequiredFlagsWithDisableFlagParsing": "layer-validation",
    "TestInitHelpFlagMergesFlags": "api-only", "TestHelpCommandExecutedOnChildWithFlagThatShadowsParentFlag": "help-format",
    "TestSetHelpCommand": "help-format", "TestSetHelpTemplate": "help-format", "TestHelpFlagInHelp": "help-format", "TestFlagsInUsage": "help-format",
    "TestSetUsageTemplate": "help-format", "TestVersionFlagExecutedDiplayName": "help-format", "TestVersionFlagExecutedWithNoName": "help-format",
    "TestShortAndLongVersionFlagInHelp": "help-format", "TestLongVersionFlagOnlyInHelpWhenShortPredefined": "help-format",
    "TestVersionTemplate": "help-format", "TestShorthandVersionTemplate": "help-format", "TestRootErrPrefixExecutedOnSubcommand": "help-format",
    "TestRootAndSubErrPrefix": "help-format", "TestShorthandVersionFlagExecutedOnSubcommand": "IN:cobracmd-031",
    "TestShortVersionFlagOnlyAddedToRoot": "IN:cobracmd-030", "TestVersionFlagOnlyExistsIfVersionNonEmpty": "lifecycle",
    "TestShorthandVersionFlagOnlyExistsIfVersionNonEmpty": "lifecycle", "TestShorthandVersionFlagOnlyAddedIfShorthandNotDefined": "lifecycle",
    "TestShorthandVersionFlagOnlyAddedIfVersionNotDefined": "lifecycle", "TestUsageIsNotPrintedTwice": "help-format", "TestVisitParents": "api-only",
    "TestSuggestions": "suggestions", "TestRemoveCommand": "api-only", "TestReplaceCommandWithRemove": "api-only", "TestDeprecatedCommand": "deprecated",
    "TestHooks": "lifecycle", "TestPersistentHooks": "lifecycle", "TestGlobalNormFuncPropagation": "normalisation", "TestNormPassedOnLocal": "normalisation",
    "TestNormPassedOnInherited": "normalisation", "TestConsistentNormalizedName": "normalisation", "TestFlagOnPflagCommandLine": "api-only",
    "TestHiddenCommandExecutes": "deprecated", "TestHiddenCommandIsHidden": "help-format", "TestCommandsAreSorted": "help-format",
    "TestEnableCommandSortingIsDisabled": "help-format", "TestUsageWithGroup": "help-format", "TestUsageHelpGroup": "help-format",
    "TestUsageCompletionGroup": "help-format", "TestUngroupedCommand": "help-format", "TestAddGroup": "help-format", "TestWrongGroupFirstLevel": "help-format",
    "TestWrongGroupNestedLevel": "help-format", "TestWrongGroupForHelp": "help-format", "TestWrongGroupForCompletion": "help-format",
    "TestSetOutput": "lifecycle", "TestSetOut": "lifecycle", "TestSetErr": "lifecycle", "TestSetIn": "lifecycle", "TestUsageStringRedirected": "help-format",
    "TestCommandPrintRedirection": "lifecycle", "TestFlagErrorFunc": "help-format", "TestFlagErrorFuncHelp": "help-format", "TestSortedFlags": "api-only",
    "TestMergeCommandLineToFlags": "api-only", "TestUseDeprecatedFlags": "deprecated", "TestUpdateName": "api-only",
    "TestFParseErrWhitelistBackwardCompatibility": "other: unknown-flag allowlist/passthrough (not in the grammar)",
    "TestFParseErrWhitelistSameCommand": "other: unknown-flag allowlist/passthrough (not in the grammar)",
    "TestFParseErrWhitelistParentCommand": "other: unknown-flag allowlist/passthrough (not in the grammar)",
    "TestFParseErrWhitelistChildCommand": "other: unknown-flag allowlist/passthrough (not in the grammar)",
    "TestFParseErrWhitelistSiblingCommand": "other: unknown-flag allowlist/passthrough (not in the grammar)",
    "TestSetContext": "lifecycle", "TestSetContextPreRun": "lifecycle", "TestSetContextPreRunOverwrite": "lifecycle", "TestSetContextPersistentPreRun": "lifecycle",
    "TestNoRootRunCommandExecutedWithVersionSet": "IN:cobracmd-062", "TestHelpCommandExecutedWithVersionSet": "IN:cobracmd-023",
    "TestHelpCommandExecutedWithoutVersionSet": "IN:cobracmd-023", "TestHelpflagCommandExecutedWithVersionSet": "IN:cobracmd-063",
    "TestHelpFuncExecuted": "IN:cobracmd-024", "TestCaseSensitivityBackwardCompatibility": "IN:cobracmd-032",
}
for n, l in enumerate(src, 1):
    m = re.match(r"func (Test\w+)\(", l)
    if not m:
        continue
    name = m.group(1)
    if name in T:
        row(k, f"command_test.go:{n}", name, "IN", "", [c for c in T[name]])
    elif outmap.get(name, "").startswith("IN:"):
        row(k, f"command_test.go:{n}", name, "IN", "", [outmap[name][3:]])
    elif name in outmap:
        row(k, f"command_test.go:{n}", name, "OUT", outmap[name])
    else:
        row(k, f"command_test.go:{n}", name, "OUT", "UNCLASSIFIED")
src = open(os.path.join(out, "..", "src", "cobra", "args_test.go")).read().splitlines()
for n, l in enumerate(src, 1):
    m = re.match(r"func (Test\w+)\(", l)
    if not m:
        continue
    name = m.group(1)
    if "args:" + name in T:
        row(k, f"args_test.go:{n}", name, "IN", "", T["args:" + name])
    else:
        row(k, f"args_test.go:{n}", name, "OUT", "layer-validation")
for n in [23]:
    pass
fg = open(os.path.join(out, "..", "src", "cobra", "flag_groups_test.go")).read()
for i in range(fg.count("desc:")):
    row(k, "flag_groups_test.go:22", f"TestValidateFlagGroups row {i + 1}", "OUT", "layer-validation")
for ln, name, why in [(33, "TestAddTemplateFunctions", "help-format"), (49, "TestLevenshteinDistance", "suggestions"), (121, "TestStringInSlice", "api-only"),
                      (185, "TestRpad", "help-format"), (245, "TestDeadcodeElimination", "other: binary size")]:
    row(k, f"cobra_test.go:{ln}", name, "OUT", why)

os.makedirs(os.path.join(out, "cases"), exist_ok=True)
os.makedirs(os.path.join(out, "inventory"), exist_ok=True)
for key in cases:
    with open(os.path.join(out, "cases", key + ".jsonl"), "w") as fh:
        for c in cases[key]:
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    with open(os.path.join(out, "inventory", key + ".tsv"), "w") as fh:
        fh.write("src\tname\tverdict\treason\tids\n")
        for r in inv[key]:
            fh.write("\t".join(r) + "\n")
    print(key, len(cases[key]), "cases,", len(inv[key]), "inventory rows,", sum(1 for r in inv[key] if r[2] == "IN"), "IN")
