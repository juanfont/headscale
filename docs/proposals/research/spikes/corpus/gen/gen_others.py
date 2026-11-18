#!/usr/bin/env python3
"""Generate cases/others.jsonl and inventory/others.tsv for the corpus."""
import json, os, sys

NOTES = "/home/kradalby/.cache/headscale-proposals/research_notes/Headscale CLI framework choice/spikes/corpus"

KONG = "alecthomas/kong@v1.17.0"
URF = "urfave/cli@v3.14.0"
FF = "peterbourgon/ff@d04e563"
SERP = "coder/serpent@v0.15.0"
TS = "tailscale/tailscale@f3bc40b67"
GLIBC = "bminor/glibc@04e750e7"
UL = "util-linux/util-linux@d6abbba"
POSIX = "POSIX.1-2024 XBD 12 https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap12.html"
LIC = {KONG: "MIT", URF: "MIT", FF: "Apache-2.0", SERP: "CC0-1.0", TS: "BSD-3-Clause",
       GLIBC: "LGPL-2.1-or-later (re-expressed, no text copied)",
       UL: "GPL-2.0-or-later (re-expressed, no text copied)",
       POSIX: "IEEE/The Open Group copyright (guideline cited, not copied)"}

PROBE = "verified by running the scratch probe (kong/urfave/ff on a pf-like tree)"

cases = []
inv = []


def run(path, args=None, flags=None):
    o = {"kind": "run", "path": path}
    if args:
        o["args"] = args
    if flags:
        o["flags"] = flags
    return o


def err(kind, path, word=""):
    o = {"kind": kind, "path": path}
    if word:
        o["word"] = word
    return o


def comp(has=None, not_=None, exact=None, files=None, nospace=None):
    o = {"kind": "complete"}
    if has is not None:
        o["has"] = has
    if not_ is not None:
        o["not"] = not_
    if exact is not None:
        o["exact"] = exact
    if files is not None:
        o["files"] = files
    if nospace is not None:
        o["nospace"] = nospace
    return o


T = {"true": ["true"]}


def case(repo, loc, kind, topic, upstream, expect, argv, want, tree=None, ours=None, why=None, note=None, row=None):
    cid = "others-%03d" % (len(cases) + 1)
    c = {"id": cid, "src": f"{repo} {loc}", "lic": LIC[repo], "kind": kind, "topic": topic,
         "upstream": upstream, "expect": expect}
    if tree:
        c["tree"] = tree
    c["argv"] = argv
    c["want"] = want
    if ours is not None:
        c["ours"] = ours
        c["why"] = why
    elif why:
        c["note"] = (note + "; " if note else "") + why
        note = None
    if note:
        c["note"] = note
    cases.append(c)
    name = loc.split(" ", 1)[1] if " " in loc else loc
    if row:
        name += " / " + row
    inv.append((f"{repo} {loc.split(' ')[0]}", name, "IN", "", cid))
    return cid


def R(*a, **k):
    return case(*a[:2], "run", *a[2:], **k)


def C(*a, **k):
    return case(*a[:2], "complete", *a[2:], **k)


def out(repo, loc, name, reason):
    inv.append((f"{repo} {loc}", name, "OUT", reason, ""))


def ref(repo, loc, name, ids):
    inv.append((f"{repo} {loc}", name, "IN", "", ",".join(ids)))


D11 = "D11: -x=v is promised; grouped shorts and attached values are best effort, own-grammar refuses them"
D15 = "D15"
D20 = "D20"
D19 = "D19"
D9 = "D9"
NOABBR = "no abbreviations (DECISIONS facts)"
MIX = "DECISIONS facts: flags and positionals mix in any order"
SINGLE = "quirk: stdlib-flag style single-dash long names; in the grammar one dash is a one-letter short"
SWALLOW = "quirk: a long bool swallows a following true/false word (ff flag_set.go:330); pflag, kong, urfave leave it a positional"
PASS = "other: passthrough/raw-args mode"
COLS = ["id", "name", "owner", "ip", "version", "online", "last-seen", "expiry", "hostname"]
ROOTKIDS = ["serve", "version", "check", "completion", "nodes", "users", "auth", "api", "policy"]

# ---------------------------------------------------------------- kong
K = "kong_test.go"
k_pos = R(KONG, f"{K}:33 TestPositionalArguments", "tree", "user create 10 Alec Thomas", "nested command, three positionals",
          ["nodes", "routes", "set", "10", "r"], run("nodes routes set", ["10", "r"]))
out(KONG, f"{K}:33", "TestPositionalArguments / Missing", "layer-validation")
out(KONG, f"{K}:53", "TestRemainderReturnsUnparsedArgs", "api-only")
out(KONG, f"{K}:72", "TestBranchingArgument", "struct-tags")
out(KONG, f"{K}:109", "TestResetWithDefaults", "api-only")
out(KONG, f"{K}:123", "TestFlagSlice", "typed-value")
out(KONG, f"{K}:133", "TestFlagSliceWithSeparator", "other: backslash-escaped list separator")
k_argslice = R(KONG, f"{K}:143 TestArgSlice", "interspersed", "1 2 3 --flag (arg slice + bool)", "positionals then a flag",
               ["run", "1", "2", "3", "--bool"], run("run", ["1", "2", "3"], {"bool": T["true"]}), tree="pf")
out(KONG, f"{K}:155", "TestArgSliceWithSeparator", "typed-value")
for n, l in [("TestUnsupportedFieldErrors", 167), ("TestMatchingArgField", 175), ("TestCantMixPositionalAndBranches", 186)]:
    out(KONG, f"{K}:{l}", n, "struct-tags")
k_prop = R(KONG, f"{K}:196 TestPropagatedFlags", "global", "command-1 command-2 --flag-2 --flag-1=moo",
           "a parent's flag after the nested subcommand", ["nodes", "routes", "set", "n", "r", "--config=moo"],
           run("nodes routes set", ["n", "r"], {"config": ["moo"]}))
for n, l, r in [("TestRequiredFlag", 212, "layer-validation"), ("TestOptionalArg", 222, "layer-validation"),
                ("TestOptionalArgWithDefault", 232, "struct-tags"), ("TestArgWithDefaultIsOptional", 243, "struct-tags"),
                ("TestRequiredArg", 254, "layer-validation"), ("TestInvalidRequiredAfterOptional", 264, "layer-validation"),
                ("TestOptionalStructArg", 274, "struct-tags"), ("TestMixedRequiredArgs", 303, "layer-validation"),
                ("TestInvalidDefaultErrors", 325, "struct-tags"), ("TestCommandMissingTagIsInvalid", 334, "struct-tags"),
                ("TestDuplicateFlag", 342, "api-only"), ("TestDuplicateFlagOnPeerCommandIsOkay", 353, "api-only"),
                ("TestTraceErrorPartiallySucceeds", 366, "api-only")]:
    out(KONG, f"{K}:{l}", n, r)
k_force = R(KONG, f"{K}:391 TestNegatableFlag", "bool", "cmd --flag", "flag true",
            ["nodes", "delete", "n", "--force"], run("nodes delete", ["n"], {"force": T["true"]}), row="boolean flag")
k_forcef = R(KONG, f"{K}:391 TestNegatableFlag", "bool", "cmd --flag=false", "flag false",
             ["nodes", "delete", "n", "--force=false"], run("nodes delete", ["n"], {"force": ["false"]}), row="inverted boolean flag")
k_neg = R(KONG, f"{K}:391 TestNegatableFlag", "negation", "cmd --no-flag (negatable tag)", "flag false",
          ["nodes", "delete", "n", "--no-force"], run("nodes delete", ["n"], {"force": ["false"]}),
          ours=err("unknown-flag", "nodes delete", "--no-force"), why=D9, row="negated boolean flag")
R(KONG, f"{K}:391 TestNegatableFlag", "negation", "cmd --no-flag=false", "flag true (negation of false)",
  ["nodes", "delete", "n", "--no-force=false"], run("nodes delete", ["n"], {"force": T["true"]}),
  ours=err("unknown-flag", "nodes delete", "--no-force"), why=D9, row="inverted negated boolean flag")
for r in ["no flag", "custom boolean flag", "custom inverted boolean flag", "custom negated boolean flag",
          "inverted custom negated boolean flag"]:
    out(KONG, f"{K}:391", "TestNegatableFlag / " + r, "struct-tags")
for n, l, r in [("TestNegatableFlagWithBoolMapper", 475, "struct-tags"), ("TestNegatableFlagWithBoolMapperValue", 517, "struct-tags"),
                ("TestDuplicateNegatableLong", 590, "api-only"), ("TestDuplicateNegatableFlagsInSubcommands", 606, "api-only"),
                ("TestExistingNoFlag", 619, "other: tree has no flag named no-*"), ("TestInvalidNegatedNonBool", 634, "api-only"),
                ("TestHooks", 677, "lifecycle"), ("TestGlobalHooks", 708, "lifecycle")]:
    out(KONG, f"{K}:{l}", n, r)
R(KONG, f"{K}:767 TestShort", "short-attached", "-b -shello", "bool true, string hello",
  ["run", "-b", "-shello"], run("run", None, {"bool": T["true"], "string": ["hello"]}), tree="pf",
  ours=err("unknown-flag", "run", "-shello"), why=D11)
out(KONG, f"{K}:779", "TestAlias", "struct-tags")
k_short = R(KONG, f"{K}:789 TestSingleCharAliasIsShortFlag", "short", "-n hello", "string hello",
            ["api", "keys", "create", "-u", "hello"], run("api keys create", None, {"user": ["hello"]}))
k_last = R(KONG, f"{K}:799 TestDuplicateFlagChoosesLast", "repeat", "--flag=1 --flag=2", "last wins: 2",
           ["nodes", "list", "--sort=id", "--sort=name"], run("nodes list", None, {"sort": ["name"]}),
           ours=err("flag-repeated", "nodes list", "--sort"), why=D15)
k_acc = R(KONG, f"{K}:809 TestDuplicateSliceAccumulates", "strings", "--flag=1,2 --flag=3,4 ([]int)", "[1 2 3 4]",
          ["nodes", "list", "--filter=id,name", "--filter=ip,owner"], run("nodes list", None, {"filter": ["id,name", "ip,owner"]}),
          note="kong splits each value on commas; the layer keeps the raw values in order and splits later")
for n, l, r in [("TestMapFlag", 820, "typed-value"), ("TestMapFlagWithSliceValue", 829, "typed-value"),
                ("TestMapFlagWithUnmappableValueType", 838, "typed-value"), ("TestMapFlagWithUnmappableKeyType", 846, "typed-value"),
                ("TestEmbeddedStruct", 858, "struct-tags"), ("TestSliceWithDisabledSeparator", 870, "typed-value"),
                ("TestMultilineMessage", 879, "help-format"), ("TestRun", 930, "lifecycle"),
                ("TestRunnableNodeDoesNotRequireSubcommand", 963, "lifecycle"), ("TestPassesThroughOriginalCommandError", 997, "lifecycle"),
                ("TestInterpolationIntoModel", 1008, "help-format"), ("TestEmptyInterpolationFallback", 1038, "help-format"),
                ("TestIssue244", 1053, "struct-tags"), ("TestPositionalArgWithEnv", 1064, "env"), ("TestErrorMissingArgs", 1080, "layer-validation"),
                ("TestBoolOverride", 1092, "struct-tags"), ("TestAnonymousPrefix", 1103, "struct-tags"), ("TestEmbedInterface", 1126, "struct-tags"),
                ("TestExcludedField", 1139, "struct-tags"), ("TestExcludeEmbeddedField", 1152, "struct-tags"), ("TestUnnamedFieldEmbeds", 1189, "struct-tags"),
                ("TestHooksCalledForDefault", 1205, "lifecycle"), ("TestEnum", 1217, "layer-validation"), ("TestEnumMeaningfulOrder", 1225, "layer-validation"),
                ("TestParentBindings", 1252, "api-only"), ("TestDefaultValueIsHyphen", 1259, "struct-tags"), ("TestDefaultEnumValidated", 1269, "layer-validation"),
                ("TestEnvarEnumValidated", 1278, "env")]:
    out(KONG, f"{K}:{l}", n, r)
for n, l in [("TestXor", 1289), ("TestAnd", 1304), ("TestXorChild", 1319), ("TestAndChild", 1336), ("TestMultiXor", 1353),
             ("TestMultiAnd", 1369), ("TestXorAnd", 1390), ("TestOverLappingXorAnd", 1410), ("TestXorRequired", 1420),
             ("TestAndRequired", 1440), ("TestXorRequiredMany", 1460), ("TestAndRequiredMany", 1479)]:
    out(KONG, f"{K}:{l}", n, "layer-validation")
for n, l in [("TestLastWins", 1494), ("TestLastWinsInterleavedSequences", 1526), ("TestLastWinsLoserRevertsToDefault", 1548),
             ("TestLastWinsLoserRevertsToEnv", 1572), ("TestLastWinsLoserRevertsToResolver", 1584), ("TestLastWinsRequired", 1601),
             ("TestLastWinsIsScopedToCommand", 1617), ("TestPrefixLastWins", 1630), ("TestLastWinsNegatable", 1647),
             ("TestLastWinsEnumLoserRevertsToDefault", 1665), ("TestLastWinsHooks", 1676)]:
    out(KONG, f"{K}:{l}", n, "struct-tags")
for n, l, r in [("TestEnumSequence", 1689, "layer-validation"), ("TestIssue40EnumAcrossCommands", 1699, "layer-validation"),
                ("TestIssue179", 1723, "struct-tags"), ("TestIssue153", 1740, "struct-tags"), ("TestEnumArg", 1759, "layer-validation")]:
    out(KONG, f"{K}:{l}", n, r)
for n, l in [("TestDefaultCommand", 1773), ("TestMultipleDefaultCommands", 1784), ("TestDefaultCommandWithSubCommand", 1793),
             ("TestDefaultCommandWithAllowedSubCommand", 1803), ("TestDefaultCommandWithArgument", 1815),
             ("TestDefaultCommandWithAllowedArgument", 1825), ("TestDefaultCommandWithBranchingArgument", 1839),
             ("TestDefaultCommandWithAllowedBranchingArgument", 1851), ("TestDefaultCommandPrecedence", 1867)]:
    out(KONG, f"{K}:{l}", n, "struct-tags")
for r in ["RejectsDefaultFlagBeforeSibling", "DefaultCommandWithoutName", "DefaultFlagBeforeNamedDefault", "NamedDefaultCommand", "NamedSiblingCommand"]:
    out(KONG, f"{K}:1897", "TestDefaultCommandFlagsBeforeSiblingCommand / " + r, "struct-tags")
k_mid = R(KONG, f"{K}:1897 TestDefaultCommandFlagsBeforeSiblingCommand", "global", "group --parent=p --verbose clear",
          "flags of the parent and the root before the subcommand", ["nodes", "--config=p", "list"],
          run("nodes list", None, {"config": ["p"]}), row="ParentAndInheritedFlagsBeforeSibling")
k_dash = R(KONG, f"{K}:1976 TestLoneHpyhen", "dash-value", "- (optional arg)", "arg is \"-\"",
           ["check", "config", "-"], run("check config", ["-"]))
k_dashv = R(KONG, f"{K}:1976 TestLoneHpyhen", "dash-value", "--flag -", "flag is \"-\"",
            ["nodes", "set", "n", "--name", "-"], run("nodes set", ["n"], {"name": ["-"]}))
for n, l, r in [("TestPlugins", 1992, "struct-tags"), ("TestValidateApp", 2027, "layer-validation"), ("TestValidateCmd", 2034, "layer-validation"),
                ("TestValidateFlag", 2043, "layer-validation"), ("TestValidateArg", 2052, "layer-validation"),
                ("TestExtendedValidateFlag", 2065, "layer-validation"), ("TestValidateEmbed", 2080, "layer-validation"),
                ("TestValidateEmbedOnCommand", 2089, "layer-validation"), ("TestValidatePlugin", 2107, "layer-validation"),
                ("TestValidateNestedEmbed", 2124, "layer-validation"), ("TestExtendedValidateEmbed", 2141, "layer-validation"),
                ("TestPointers", 2150, "struct-tags"), ("TestDynamicCommands", 2181, "api-only"), ("TestDuplicateShortflags", 2216, "api-only"),
                ("TestDuplicateAliases", 2225, "api-only"), ("TestSubCommandAliases", 2234, "api-only")]:
    out(KONG, f"{K}:{l}", n, r)
ref(KONG, f"{K}:2248", "TestSubCommandSingleCharAliases", [k_short])
for n, l, r in [("TestDuplicateAliasLong", 2265, "api-only"), ("TestDuplicateNestedShortFlags", 2274, "api-only"),
                ("TestHydratePointerCommandsAndEmbeds", 2285, "struct-tags"), ("TestIgnoreRegex", 2320, "struct-tags"),
                ("TestIgnoreRegexEmpty", 2342, "struct-tags"), ("TestOptionReturnsErr", 2356, "api-only"),
                ("TestEnumValidation", 2368, "layer-validation")]:
    out(KONG, f"{K}:{l}", n, r)
for n, l in [("TestPassthroughArgs", 2437), ("TestPassthroughPartial", 2491), ("TestPassthroughAll", 2505), ("TestPassthroughCmd", 2520),
             ("TestPassthroughCmdOnlyArgs", 2576), ("TestPassthroughCmdOnlyStringArgs", 2587)]:
    out(KONG, f"{K}:{l}", n, PASS)
for n, l, r in [("TestHelpShouldStillWork", 2597, "help-format"), ("TestVersionFlagShouldStillWork", 2619, "lifecycle"),
                ("TestSliceDecoderHelpfulErrorMsg", 2642, "typed-value"), ("TestMapDecoderHelpfulErrorMsg", 2692, "typed-value"),
                ("TestDuplicateName", 2742, "api-only"), ("TestDuplicateChildName", 2751, "api-only"), ("TestChildNameCanBeDuplicated", 2763, "api-only"),
                ("TestCumulativeArgumentLast", 2774, "struct-tags"), ("TestCumulativeArgumentNotLast", 2783, "struct-tags")]:
    out(KONG, f"{K}:{l}", n, r)
k_sp = R(KONG, f"{K}:2792 TestStringPointer", "space", "--foo wtf", "foo is wtf",
         ["nodes", "set", "n", "--name", "wtf"], run("nodes set", ["n"], {"name": ["wtf"]}))
out(KONG, f"{K}:2806", "TestStringPointerNoValue", "api-only")
out(KONG, f"{K}:2819", "TestStringPointerDefault", "struct-tags")
out(KONG, f"{K}:2833", "TestStringPointerAliasNoValue", "api-only")
k_eq = R(KONG, f"{K}:2847 TestStringPointerAlias", "eq", "--f=value", "f is value",
         ["nodes", "set", "n", "--name=value"], run("nodes set", ["n"], {"name": ["value"]}))
k_empty = R(KONG, f"{K}:2862 TestStringPointerEmptyValue", "empty-value", "--f \"\"", "set, empty",
            ["nodes", "set", "n", "--name", ""], run("nodes set", ["n"], {"name": [""]}))
k_emptyeq = R(KONG, f"{K}:2862 TestStringPointerEmptyValue", "empty-value", "--g=", "set, empty",
              ["nodes", "set", "n", "--name="], run("nodes set", ["n"], {"name": [""]}))
for n, l, r in [("TestIntPtr", 2879, "typed-value"), ("TestBoolPtr", 2895, "api-only"), ("TestBoolPtrFalse", 2909, "api-only"),
                ("TestBoolPtrNegated", 2923, "struct-tags"), ("TestNilNegatableBoolPtr", 2937, "struct-tags"), ("TestBoolPtrNil", 2950, "api-only"),
                ("TestUnsupportedPtr", 2963, "struct-tags"), ("TestEnumPtr", 2981, "layer-validation"), ("TestEnumPtrOmitted", 2995, "layer-validation"),
                ("TestEnumPtrOmittedNoDefault", 3009, "layer-validation"), ("TestIntEnum", 3022, "typed-value"),
                ("TestRecursiveVariableExpansion", 3032, "help-format"), ("TestAfterRun", 3064, "lifecycle"), ("TestProviderMethods", 3091, "lifecycle"),
                ("TestEmbeddedCallbacks", 3141, "lifecycle"), ("TestApplyCalledOnce", 3180, "lifecycle"),
                ("TestPromotedEmbeddedAfterApplyCalledOnce", 3205, "lifecycle"), ("TestPromotedUnexportedEmbeddedAfterApplyCalledOnce", 3232, "lifecycle"),
                ("TestAfterApplyFiresForEnvOnlyFlag", 3259, "env"), ("TestCustomTypeNoEllipsis", 3271, "help-format"),
                ("TestPrefixXorIssue343", 3286, "layer-validation"), ("TestIssue483EmptyRootNodeNoRun", 3306, "lifecycle"),
                ("TestProviderWithoutError", 3329, "lifecycle")]:
    out(KONG, f"{K}:{l}", n, r)
R(KONG, f"{K}:3339 TestParseHyphenParameter", "dash-value", "-f -foo (WithHyphenPrefixedParameters)", "flag is -foo",
  ["run", "-f", "-foo"], run("run", None, {"file": ["-foo"]}), tree="pf", row="ShortFlag")
R(KONG, f"{K}:3339 TestParseHyphenParameter", "dash-value", "--flag -foo (WithHyphenPrefixedParameters)", "flag is -foo",
  ["run", "--file", "-foo"], run("run", None, {"file": ["-foo"]}), tree="pf", row="LongFlag")
R(KONG, f"{K}:3339 TestParseHyphenParameter", "dash-value", "--flag -oo where -o is a flag (WithHyphenPrefixedParameters)",
  "flag is -oo", ["run", "--file", "-oo"], run("run", None, {"file": ["-oo"]}), tree="pf", row="ParamMatchesFlag")
out(KONG, f"{K}:3339", "TestParseHyphenParameter / NegativeNumber", "typed-value")
M = "mapper_test.go"
R(KONG, f"{M}:833 TestValuesThatLookLikeFlags", "dash-value", "--slice -foo (default options)",
  "error: expected value but got a flag (scanner.go:166; context.go:928 suggests --x=\"-foo\")",
  ["nodes", "set", "n", "--name", "-foo"], err("missing-value", "nodes set", "--name"),
  ours=run("nodes set", ["n"], {"name": ["-foo"]}), why=D20,
  note="kong refuses any dash-led word as a separate value unless WithHyphenPrefixedParameters; kong's error is closest to missing-value")
R(KONG, f"{M}:833 TestValuesThatLookLikeFlags", "dash-value", "--slice=-foo --slice=-bar", "[-foo -bar]",
  ["nodes", "list", "--filter=-id", "--filter=-name"], run("nodes list", None, {"filter": ["-id", "-name"]}))
R(KONG, "context.go:928 (scanner.go:166)", "dash-dash", "--string -- x (default options)",
  "error: expected string value but got \"--\"", ["run", "--file", "--", "x"], err("missing-value", "run", "--file"), tree="pf",
  ours=run("run", ["x"], {"file": ["--"]}), why=D20, note=PROBE + "; urfave, ff, GNU getopt and POSIX G10 give the value \"--\"")
R(KONG, "context.go:552 short flag tail", "short-eq", "-s=xxx", "string is \"=xxx\" (the tail after the short letter)",
  ["run", "-s=xxx"], run("run", None, {"string": ["=xxx"]}), tree="pf",
  ours=run("run", None, {"string": ["xxx"]}), why=D11, note=PROBE + "; ff agrees with kong, urfave and pflag give xxx")
for n, l in [("TestValueMapper", 20), ("TestTextUnmarshaler", 45), ("TestJSONUnmarshaler", 69), ("TestNamedMapper", 79),
             ("TestTimeMapper", 106), ("TestDurationMapper", 119), ("TestDurationMapperJSONResolver", 129), ("TestSplitEscaped", 141),
             ("TestJoinEscaped", 147), ("TestMapWithNamedTypes", 153), ("TestMapWithMultipleValues", 167), ("TestMapWithDifferentSeparator", 177),
             ("TestMapWithNoSeparator", 187), ("TestURLMapper", 199), ("TestMapperValue", 257), ("TestFileContentFlag", 267),
             ("TestNamedFileContentFlag", 280), ("TestNamedSliceTypesDontHaveEllipsis", 294), ("TestCounter", 308), ("TestNumbers", 347),
             ("TestJSONLargeNumber", 435), ("TestFileMapper", 483), ("TestFileContentMapper", 502), ("TestFileContentMapperRejectsNonByteSlice", 523),
             ("TestPathMapperUsingStringPointer", 545), ("TestPathMapperWithDefaultUsingStringPointer", 590), ("TestExistingFileMapper", 627),
             ("TestExistingFileMapperSlice", 647), ("TestExistingFileMapperDefaultMissing", 661), ("TestExistingFileMapperDefaultMissingCmds", 679),
             ("TestExistingDirMapper", 706), ("TestExistingDirMapperDefaultMissing", 726), ("TestExistingDirMapperDefaultMissingCmds", 744),
             ("TestMapperPlaceHolder", 770), ("TestMapperVarsContributor", 801), ("TestDecode", 866), ("TestFileMapperWithDefaultNonExistentFile", 879)]:
    out(KONG, f"{M}:{l}", n, "typed-value")
R(KONG, f"{M}:211 TestSliceConsumesRemainingPositionalArgs", "dash-dash", "-- ls -lart", "positionals ls -lart",
  ["run", "--", "ls", "-lart"], run("run", ["ls", "-lart"]), tree="pf")
out(KONG, f"{M}:221", "TestPassthroughStopsParsing", PASS)
# other kong files: one OUT row per test function
for f, rs in [("help_test.go", "help-format"), ("helpwrap1.18_test.go", "help-format"), ("helpwrap1.19_test.go", "help-format"),
              ("config_test.go", "config-file"), ("defaults_test.go", "api-only"), ("global_test.go", "api-only"),
              ("interpolate_test.go", "help-format"), ("mapper_linux_test.go", "typed-value"), ("mapper_windows_test.go", "typed-value"),
              ("model_test.go", "help-format"), ("options_test.go", "api-only"), ("resolver_test.go", "env"),
              ("scanner_test.go", "api-only"), ("signature_test.go", "struct-tags"), ("tag_test.go", "struct-tags"), ("util_test.go", "lifecycle")]:
    out(KONG, f, "(all test functions)", rs)

# ---------------------------------------------------------------- urfave
U = "command_test.go"
R(URF, f"{U}:160 TestCommandFlagParsing", "unknown-flag", "test-cmd -break blah blah", "flag provided but not defined: -break",
  ["nodes", "list", "-break"], err("unknown-flag", "nodes list", "-break"), row="row 1")
for r in ["row 2 SkipFlagParsing", "row 3 SkipFlagParsing", "row 4 SkipFlagParsing"]:
    out(URF, f"{U}:160", "TestCommandFlagParsing / " + r, PASS)
out(URF, f"{U}:160", "TestCommandFlagParsing / row 5 blah -h", "help-format")
P = f"{U}:203 TestParseAndRunShortOpts"
X = "others"
u = {}
u[1] = R(URF, P, "short", "-a (bool abc)", "abc true", ["test", "-a"], run("test", None, {"aflag": T["true"]}), tree=X, row="-a")
u[2] = R(URF, P, "short", "-c arg1 arg2", "cde true, args arg1 arg2", ["test", "-k", "arg1", "arg2"],
         run("test", ["arg1", "arg2"], {"kflag": T["true"]}), tree=X, row="-c arg1 arg2")
u[3] = R(URF, P, "short", "-f", "fgh true", ["test", "-g"], run("test", None, {"gflag": T["true"]}), tree=X, row="-f")
for row, w, fl in [("-ac --fgh", ["-ak", "--gflag"], {"aflag": T["true"], "kflag": T["true"], "gflag": T["true"]}),
                   ("-af", ["-ag"], {"aflag": T["true"], "gflag": T["true"]}),
                   ("-cf", ["-kg"], {"kflag": T["true"], "gflag": T["true"]}),
                   ("-acf", ["-akg"], {"aflag": T["true"], "kflag": T["true"], "gflag": T["true"]})]:
    u[row] = R(URF, P, "short-group", row + " (UseShortOptionHandling)", "grouped bools all true", ["test"] + w,
               run("test", None, fl), tree=X, ours=err("unknown-flag", "test", w[0]), why=D11, row=row)
R(URF, P, "unknown-flag", "--acf", "flag provided but not defined: -acf (no grouping after --)", ["test", "--akg"],
  err("unknown-flag", "test", "--akg"), tree=X, row="--acf")
R(URF, P, "unknown-flag", "-invalid", "flag provided but not defined: -invalid", ["test", "-invalid"],
  err("unknown-flag", "test", "-invalid"), tree=X, row="-invalid")
u10 = R(URF, P, "short-group", "-acf -invalid", "error names -invalid", ["test", "-akg", "-invalid"],
        err("unknown-flag", "test", "-invalid"), tree=X, ours=err("unknown-flag", "test", "-akg"), why=D11, row="-acf -invalid")
R(URF, P, "unknown-flag", "--invalid", "flag provided but not defined: -invalid", ["test", "--invalid"],
  err("unknown-flag", "test", "--invalid"), tree=X, row="--invalid")
u12 = R(URF, P, "short-group", "-acf --invalid", "error names --invalid", ["test", "-akg", "--invalid"],
        err("unknown-flag", "test", "--invalid"), tree=X, ours=err("unknown-flag", "test", "-akg"), why=D11, row="-acf --invalid")
ref(URF, f"{U}:203", "TestParseAndRunShortOpts / -acf arg1 -invalid", [u10])
ref(URF, f"{U}:203", "TestParseAndRunShortOpts / -acf arg1 --invalid", [u12])
R(URF, P, "short-group", "-acfi not-arg arg1 -invalid", "i takes not-arg; error names -invalid",
  ["test", "-akgi", "not-arg", "arg1", "-invalid"], err("unknown-flag", "test", "-invalid"), tree=X,
  ours=err("unknown-flag", "test", "-akgi"), why=D11, row="-acfi not-arg arg1 -invalid")
u_i = R(URF, P, "short", "-i ivalue", "ijk ivalue", ["test", "-i", "ivalue"], run("test", None, {"ijk": ["ivalue"]}), tree=X, row="-i ivalue")
R(URF, P, "interspersed", "-i ivalue arg1", "ijk ivalue, args arg1", ["test", "-i", "ivalue", "arg1"],
  run("test", ["arg1"], {"ijk": ["ivalue"]}), tree=X, row="-i ivalue arg1")
u_miss = R(URF, P, "missing-value", "-i", "flag needs an argument: -i", ["test", "-i"], err("missing-value", "test", "-i"), tree=X, row="-i")
R(URF, P, "short-attached", "-ia", "flag needs an argument: i (a value flag must end the group; never -i=a as pflag/kong/ff read it)",
  ["test", "-ia"], err("missing-value", "test", "-i"), tree=X, ours=err("unknown-flag", "test", "-ia"), why=D11, row="-ia")
R(URF, P, "short-attached", "-ia ivalue", "flag needs an argument: i", ["test", "-ia", "ivalue"], err("missing-value", "test", "-i"),
  tree=X, ours=err("unknown-flag", "test", "-ia"), why=D11, row="-ia ivalue")
R(URF, P, "short-group", "-aic", "flag needs an argument: i", ["test", "-aik"], err("missing-value", "test", "-i"), tree=X,
  ours=err("unknown-flag", "test", "-aik"), why=D11, row="-aic")
u_ai = R(URF, P, "short-group", "-ai ivalue", "abc true, ijk ivalue", ["test", "-ai", "ivalue"],
         run("test", None, {"aflag": T["true"], "ijk": ["ivalue"]}), tree=X, ours=err("unknown-flag", "test", "-ai"), why=D11, row="-ai ivalue")
for n, l, r in [("TestCommand_Run_DoesNotOverwriteErrorFromBefore", 279, "lifecycle"), ("TestCommand_Run_BeforeSavesMetadata", 297, "lifecycle"),
                ("TestCommand_Run_BeforeReturnNewContext", 331, "lifecycle"), ("TestCommand_Run_BeforeReturnNewContextSubcommand", 392, "lifecycle"),
                ("TestCommand_Run_FlagActionContext", 442, "lifecycle"), ("TestCommand_OnUsageError_hasCommandContext", 497, "lifecycle"),
                ("TestCommand_OnUsageError_WithWrongFlagValue", 512, "typed-value"), ("TestCommand_OnUsageError_WithSubcommand", 528, "typed-value"),
                ("TestCommand_Run_SubcommandsCanUseErrWriter", 549, "lifecycle"), ("TestCommandSkipFlagParsing", 570, PASS),
                ("TestCommand_Run_CustomShellCompleteAcceptsMalformedFlags", 603, "api-only"), ("TestCommand_CanAddVFlagOnSubCommands", 646, "api-only"),
                ("TestCommand_VisibleSubcCommands", 666, "help-format"), ("TestCommand_VisibleFlagCategories", 692, "help-format"),
                ("TestCommand_RunSubcommandWithDefault", 744, "other: default command"), ("TestCommand_Run", 774, "lifecycle"),
                ("TestCommand_Command", 803, "api-only"), ("TestCommand_RunDefaultCommand", 840, "other: default command"),
                ("TestCommand_RunDefaultCommandWithSubCommand", 931, "other: default command"),
                ("TestCommand_RunDefaultCommandWithFlags", 997, "other: default command"), ("TestCommand_FlagsFromExtPackage", 1051, "api-only"),
                ("TestCommand_Setup_defaultsReader", 1105, "api-only"), ("TestCommand_Setup_defaultsWriter", 1111, "api-only")]:
    out(URF, f"{U}:{l}", n, r)
R(URF, f"{U}:1117 TestCommand_CommandWithFlagBeforeTerminator", "dash-dash", "cmd --option my-option my-arg -- --notARealFlag",
  "option my-option, args my-arg --notARealFlag", ["run", "--file", "x", "a", "--", "--notaflag"],
  run("run", ["a", "--notaflag"], {"file": ["x"]}), tree="pf")
R(URF, f"{U}:1144 TestCommand_CommandWithDash", "dash-value", "cmd my-arg -", "args my-arg -", ["run", "a", "-"], run("run", ["a", "-"]), tree="pf")
B = f"{U}:1165 TestCommand_BareDash"
R(URF, B, "dash-value", "cmd - foo bar", "args - foo bar", ["run", "-", "foo", "bar"], run("run", ["-", "foo", "bar"]), tree="pf",
  row="arguments after a bare dash are kept")
R(URF, B, "dash-value", "cmd - --option my-option foo", "option set, args - foo", ["run", "-", "--file", "x", "foo"],
  run("run", ["-", "foo"], {"file": ["x"]}), tree="pf", row="flags after a bare dash still parse")
R(URF, B, "dash-dash", "cmd - -- --option leftover", "args - --option leftover", ["run", "-", "--", "--file", "leftover"],
  run("run", ["-", "--file", "leftover"]), tree="pf", row="terminator after a bare dash still stops flag parsing")
R(URF, B, "verbatim", "cmd \" - \" foo", "args \" - \" foo unchanged", ["run", " - ", "foo"], run("run", [" - ", "foo"]), tree="pf",
  row="a bare dash with surrounding whitespace")
R(URF, B, "unknown-flag", "cmd - --undefined", "flag provided but not defined", ["run", "-", "--undefined"],
  err("unknown-flag", "run", "--undefined"), tree="pf", row="an undefined flag after a bare dash is an error")
R(URF, f"{U}:1237 TestCommand_PositionalArgsKeepWhitespace", "verbatim", "prog \"  padded  \" \"\\ttabbed\\t\"", "kept byte for byte",
  ["run", "  padded  ", "\ttabbed\t"], run("run", ["  padded  ", "\ttabbed\t"]), tree="pf")
W = f"{U}:1253 TestCommand_FlagValuesKeepWhitespace"
ref(URF, f"{U}:1253", "TestCommand_FlagValuesKeepWhitespace / empty", [k_empty, k_emptyeq])
R(URF, W, "verbatim", "--text \" hello \" operand", "value \" hello \"", ["run", "--file", " hello ", "operand"],
  run("run", ["operand"], {"file": [" hello "]}), tree="pf", row="spaces")
R(URF, W, "verbatim", "--text=\\t operand", "value \"\\t\"", ["run", "--file=\t", "operand"], run("run", ["operand"], {"file": ["\t"]}),
  tree="pf", row="tab only")
R(URF, W, "verbatim", "--text \"line\\n\" operand", "value \"line\\n\"", ["run", "--file", "line\n", "operand"],
  run("run", ["operand"], {"file": ["line\n"]}), tree="pf", row="newline")
R(URF, W, "verbatim", "--text=\"space\\u00a0\" operand", "value kept", ["run", "--file=space\u00a0", "operand"],
  run("run", ["operand"], {"file": ["space\u00a0"]}), tree="pf", row="unicode space")
R(URF, W, "eq", "--text=\"a=b \" operand", "value \"a=b \" (split at the first =)", ["run", "--file=a=b ", "operand"],
  run("run", ["operand"], {"file": ["a=b "]}), tree="pf", row="embedded equals")
R(URF, W, "short", "-t \" hello \" operand", "value \" hello \"", ["run", "-f", " hello ", "operand"],
  run("run", ["operand"], {"file": [" hello "]}), tree="pf", row="alias")
R(URF, W, "short-eq", "-t=\" hello \" operand", "value \" hello \"", ["run", "-f= hello ", "operand"],
  run("run", ["operand"], {"file": [" hello "]}), tree="pf", row="alias equals=true")
R(URF, W, "verbatim", "\"\\t --text\" \" hello \" operand", "read as --text (the flag word is trimmed before it is classified)",
  ["run", "\t --file", " hello ", "operand"], run("run", ["operand"], {"file": [" hello "]}), tree="pf",
  ours=run("run", ["\t --file", " hello ", "operand"]), why="quirk: urfave trims whitespace before deciding a word is a flag",
  row="leading flag whitespace")
out(URF, f"{U}:1253", "TestCommand_FlagValuesKeepWhitespace / trim enabled", "other: TrimSpace value option")
out(URF, f"{U}:1253", "TestCommand_FlagValuesKeepWhitespace / map kind", "typed-value")
out(URF, f"{U}:1310", "TestCommand_SingleRuneUnicodeFlag", "other: non-ASCII flag name (tree has none)")
E = f"{U}:1331 TestCommand_EqualsFlagValueValidation"
R(URF, E, "bool", "--value=true", "accepted", ["nodes", "delete", "n", "--force=true"], run("nodes delete", ["n"], {"force": T["true"]}),
  row="bool/whitespace=\"\"")
R(URF, E, "bool", "--value=\"true \"", "error, action not run", ["nodes", "delete", "n", "--force=true "], err("bad-value", "nodes delete", "--force"),
  row="bool/whitespace=\" \"")
R(URF, E, "bool", "--value=\"true\\t\"", "error, action not run", ["nodes", "delete", "n", "--force=true\t"], err("bad-value", "nodes delete", "--force"),
  row="bool/whitespace=\"\\t\"")
out(URF, f"{U}:1331", "TestCommand_EqualsFlagValueValidation / int rows", "typed-value")
R(URF, f"{U}:1359 TestCommand_CommandWithNoFlagBeforeTerminator", "dash-dash", "cmd my-arg -- notAFlagAtAll", "args my-arg notAFlagAtAll",
  ["run", "a", "--", "b"], run("run", ["a", "b"]), tree="pf")
out(URF, f"{U}:1381", "TestCommand_SkipFlagParsing", PASS)
out(URF, f"{U}:1400", "TestCommand_VisibleCommands", "help-format")
u_on = R(URF, f"{U}:1446 TestCommand_UseShortOptionHandling", "short-group", "-on expectedName (o bool, n string)",
         "one true, name expectedName", ["test", "-as", "expectedName"], run("test", None, {"aflag": T["true"], "str": ["expectedName"]}),
         tree=X, ours=err("unknown-flag", "test", "-as"), why=D11)
BI = f"{U}:1471 TestCommand_UseShortOptionHandlingBoolWithInverse"
u_ab = R(URF, BI, "short", "-c -v", "both true", ["test", "-a", "-b"], run("test", None, {"aflag": T["true"], "bflag": T["true"]}), tree=X, row="-c -v")
u_grp = R(URF, BI, "short-group", "-cv", "both true", ["test", "-ab"], run("test", None, {"aflag": T["true"], "bflag": T["true"]}), tree=X,
          ours=err("unknown-flag", "test", "-ab"), why=D11, row="-cv")
R(URF, BI, "short-group", "-vc", "both true", ["test", "-ba"], run("test", None, {"aflag": T["true"], "bflag": T["true"]}), tree=X,
  ours=err("unknown-flag", "test", "-ba"), why=D11, row="-vc")
ref(URF, f"{U}:1492", "TestCommand_UseShortOptionHandling_missing_value", [u_miss])
out(URF, f"{U}:1503", "TestCommand_UseShortOptionHandlingMultiByteLastFlag", "other: non-ASCII flag name (tree has none)")
ref(URF, f"{U}:1537", "TestCommand_UseShortOptionHandlingCommand", [u_on])
ref(URF, f"{U}:1567", "TestCommand_UseShortOptionHandlingCommand_missing_value", [u_miss])
ref(URF, f"{U}:1585", "TestCommand_UseShortOptionHandlingSubCommand", [u_on])
R(URF, f"{U}:1621 TestCommand_UseShortOptionHandlingSubCommand_missing_value", "missing-value", "cmd sub -n", "flag needs an argument: -n",
  ["nodes", "set", "n", "-e"], err("missing-value", "nodes set", "-e"))
u_local = R(URF, f"{U}:1640 TestCommand_UseShortOptionHandlingLocalFlagNotInherited", "unknown-flag",
            "app sub -d (d is a Local flag of app)", "flag provided but not defined: -d", ["nodes", "list", "--version"],
            err("unknown-flag", "nodes list", "--version"), row="-d", note="--version is the root's own flag, not global (D7)")
for r in ["-xd", "-dx", "-sd"]:
    ref(URF, f"{U}:1640", "TestCommand_UseShortOptionHandlingLocalFlagNotInherited / " + r, [u_local, u_grp])
ref(URF, f"{U}:1640", "TestCommand_UseShortOptionHandlingLocalFlagNotInherited / -xy", [u_grp])
R(URF, f"{U}:1690 TestCommand_UseShortOptionAfterSliceFlag", "short-group", "-e foo -on expectedName", "env [foo], one, name",
  ["test", "-x", "foo", "-as", "expectedName"], run("test", None, {"xxx": ["foo"], "aflag": T["true"], "str": ["expectedName"]}), tree=X,
  ours=err("unknown-flag", "test", "-as"), why=D11)
R(URF, f"{U}:1721 TestCommand_UseShortOptionWithArg", "short-group", "short -som hello /path/to/root", "s o bools, m hello, root arg",
  ["test", "-abs", "hello", "/path/to/root"], run("test", ["/path/to/root"], {"aflag": T["true"], "bflag": T["true"], "str": ["hello"]}),
  tree=X, ours=err("unknown-flag", "test", "-abs"), why=D11)
out(URF, f"{U}:1748", "TestCommand_Float64Flag", "typed-value")
u_sd = R(URF, f"{U}:1765 TestCommand_ParseSliceFlags", "long", "cmd -p 22 -p 80 -ip 8.8.8.8 -ip 8.8.4.4", "single-dash long names accumulate",
         ["nodes", "list", "-filter", "id", "-filter", "name"], run("nodes list", None, {"filter": ["id", "name"]}),
         ours=err("unknown-flag", "nodes list", "-filter"), why=SINGLE)
ref(URF, f"{U}:1793", "TestCommand_ParseSliceFlagsWithMissingValue", [u_sd])
for n, l, r in [("TestCommand_DefaultStdin", 1821, "api-only"), ("TestCommand_DefaultStdout", 1828, "api-only"), ("TestCommand_SetStdin", 1835, "api-only"),
                ("TestCommand_SetStdin_Subcommand", 1852, "api-only"), ("TestCommand_SetStdout", 1879, "api-only"), ("TestCommand_BeforeFunc", 1892, "lifecycle"),
                ("TestCommand_BeforeFuncPersistentFlag", 1962, "lifecycle"), ("TestCommand_BeforeAfterFuncShellCompletion", 1999, "lifecycle"),
                ("TestCommand_AfterFunc", 2051, "lifecycle"), ("TestCommand_AfterNotCalledOnSubcommandHelp", 2118, "lifecycle"),
                ("TestCommand_AfterStillCalledOnNormalSubcommand", 2140, "lifecycle"), ("TestCommandNoHelpFlag", 2162, "help-format"),
                ("TestRequiredFlagCommandRunBehavior", 2177, "layer-validation"), ("TestCommand_IncorrectUsageOnRequiredFlagsViaRun", 2318, "layer-validation"),
                ("TestCommand_IncorrectUsageOnMutuallyExclusiveFlagsViaRun", 2366, "layer-validation"),
                ("TestCommand_IncorrectUsageOnSubcommandWithFailingShowCommandHelp", 2424, "help-format"), ("TestCommandHelpPrinter", 2495, "help-format"),
                ("TestCommand_VersionPrinter", 2513, "lifecycle")]:
    out(URF, f"{U}:{l}", n, r)
u_nf = R(URF, f"{U}:2530 TestCommand_CommandNotFound", "unknown-cmd", "command foo (only bar exists)", "CommandNotFound called, nothing runs",
         ["foo"], err("unknown-command", "", "foo"))
out(URF, f"{U}:2556", "TestCommand_OrderOfOperations", "lifecycle")
H = f"{U}:2715 TestCommand_HelpFlagTakesPrecedenceOverParseErrors"
R(URF, H, "help", "command --help --undefined", "help shown, no error", ["--help", "--undefined"], err("help", ""),
  ours=err("unknown-flag", "", "--undefined"), why=D19, row="root command with --help and bad flag")
R(URF, H, "help", "command -h --undefined", "help shown, no error", ["-h", "--undefined"], err("help", ""),
  ours=err("unknown-flag", "", "--undefined"), why=D19, row="root command with -h and bad flag")
R(URF, H, "help", "command foo --help --undefined", "help of foo, no error", ["nodes", "list", "--help", "--undefined"], err("help", "nodes list"),
  ours=err("unknown-flag", "nodes list", "--undefined"), why=D19, row="subcommand with --help and bad flag",
  note="urfave: help wins only when it comes before the bad flag; probe: run x --unknown -h is an error")
R(URF, H, "unknown-flag", "command foo --undefined", "Incorrect Usage", ["nodes", "list", "--undefined"], err("unknown-flag", "nodes list", "--undefined"),
  row="subcommand with bad flag")
for n, l, r in [("TestFlagActionOrder", 2813, "lifecycle"), ("TestCommand_Run_CommandWithSubcommandHasHelpTopic", 2861, "help-format"),
                ("TestCommand_Run_SubcommandFullPath", 2906, "help-format"), ("TestCommand_Run_Help", 2929, "help-format"),
                ("TestCommand_Run_Version", 2995, "lifecycle"), ("TestCommand_Run_CustomFlagCanUseVersionAlias", 3020, "api-only"),
                ("TestCommand_Run_Categories", 3045, "help-format"), ("TestCommand_VisibleCategories", 3093, "help-format"),
                ("TestCommand_Run_SubcommandDoesNotOverwriteErrorFromBefore", 3191, "lifecycle"),
                ("TestCommand_OnUsageError_WithWrongFlagValue_ForSubcommand", 3212, "typed-value"), ("TestCustomFlagsUnused", 3307, "api-only"),
                ("TestCustomFlagsUsed", 3317, "api-only"), ("TestVersionFlagWorksWhenAliasYieldedToUserFlag", 3329, "api-only"),
                ("TestDropClashingAliases", 3353, "api-only"), ("TestCustomHelpVersionFlags", 3375, "api-only"),
                ("TestHandleExitCoder_Default", 3393, "lifecycle"), ("TestHandleExitCoder_Custom", 3401, "lifecycle")]:
    out(URF, f"{U}:{l}", n, r)
# TestShellCompletionForIncompleteFlags: carried below as tailscale's free-text value case
for n, l, r in [("TestWhenExitSubCommandWithCodeThenCommandQuitUnexpectedly", 3459, "lifecycle"), ("TestSetupInitializesBothWriters", 3513, "api-only"),
                ("TestSetupInitializesOnlyNilWriters", 3522, "api-only"), ("TestSubcommandInheritsRootWriters", 3537, "api-only"),
                ("TestFlagAction", 3560, "lifecycle")]:
    out(URF, f"{U}:{l}", n, r)
u_acc = R(URF, f"{U}:3880 TestLocalSliceFlagAccumulation", "strings", "sub -p /a -p /b -p /c", "three values",
          ["nodes", "list", "--filter", "id", "--filter", "name", "--filter", "ip"], run("nodes list", None, {"filter": ["id", "name", "ip"]}))
ref(URF, f"{U}:3913", "TestLocalFlagError", [u_local])
PF = f"{U}:3941 TestPersistentFlag"
R(URF, PF, "global", "app --p hello cmd ... subcmd ... (persistent flags at every level)", "persistent flags read at any level",
  ["-c", "hello", "nodes", "-o", "json", "list"], run("nodes list", None, {"config": ["hello"], "output": ["json"]}), row="levels")
R(URF, PF, "repeat", "app --persistentCommandFlag hello ... subcmd --persistentCommandFlag bar", "last wins: bar",
  ["-c", "hello", "nodes", "list", "-c", "bar"], run("nodes list", None, {"config": ["bar"]}),
  ours=err("flag-repeated", "nodes list", "--config"), why=D15, row="repeat across levels")
for n, l, r in [("TestPersistentFlagIsSet", 4054, "api-only"), ("TestDuplicatePersistentFlagUsesEnvSource", 4088, "env"),
                ("TestPersistentFlagCommandLineOverridesSourceInSubcommand", 4130, "env"), ("TestPersistentFlagSourceResetKeepsSliceSeparator", 4206, "env"),
                ("TestRequiredFlagDelayed", 4229, "layer-validation"), ("TestRequiredPersistentFlag", 4299, "layer-validation")]:
    out(URF, f"{U}:{l}", n, r)
FD = f"{U}:4325 TestFlagDuplicates"
R(URF, FD, "strings", "--sflag hello --isflag 1 --isflag 2 ... (each once, slice twice)", "accepted",
  ["nodes", "list", "--sort", "id", "--filter", "id", "--filter", "name"], run("nodes list", None, {"sort": ["id"], "filter": ["id", "name"]}),
  row="all args present once")
ref(URF, f"{U}:4325", "TestFlagDuplicates / duplicate non slice flag(duplicatable)", [k_last])
R(URF, FD, "repeat", "--sflag hello ... --sflag trip (OnlyOnce)", "error", ["nodes", "set", "n", "--name", "a", "--name", "b"],
  err("flag-repeated", "nodes set", "--name"), row="duplicate non slice flag(non duplicatable)")
R(URF, FD, "repeat", "--fsflag 2.0 --fsflag 3.0 (OnlyOnce slice)", "error", ["auth", "keys", "create", "o", "--tags", "tag:ci", "--tags", "tag:prod"],
  err("flag-repeated", "auth keys create", "--tags"), row="duplicate slice flag(non duplicatable)", note="D6: a repeated list flag is an error")
R(URF, FD, "repeat", "--bifflag --bifflag (OnlyOnce)", "error", ["nodes", "delete", "n", "--force", "--force"],
  err("flag-repeated", "nodes delete", "--force"), row="duplicate bool inverse flag(non duplicatable)")
for n, l in [("TestDuplicateFlagNamesAreRejected", 4394), ("TestDuplicateFlagNamesInSubcommandAreRejected", 4456), ("TestDuplicateFlagNamesSkipExtFlags", 4492),
             ("TestUserDefinedHelpFlagOverridesBuiltin", 4514), ("TestHelpFlagWorksWhenAliasYieldedToUserFlag", 4543), ("TestHelpFlagNameTakenByUserFlag", 4601)]:
    out(URF, f"{U}:{l}", n, "api-only")
SH = f"{U}:4667 TestShorthandCommand"
R(URF, SH, "abbrev", "foo cthd (PrefixMatchCommands; cthdisd)", "unique prefix runs cthdisd", ["nodes", "li"], run("nodes list"),
  ours=err("unknown-command", "nodes", "li"), why=NOABBR, row="cthd")
R(URF, SH, "alias", "foo cth (alias of cthdisd)", "alias runs cthdisd", ["nodes", "ls"], run("nodes list"), row="cth")
for r in ["cthe", "cthert", "cthet"]:
    out(URF, f"{U}:4667", "TestShorthandCommand / " + r, "other: PrefixMatchCommands tie-breaking (no abbreviations, see cthd row)")
for n, l, r in [("TestCommand_Int", 4726, "typed-value"), ("TestCommand_Uint", 4749, "typed-value"), ("TestCommand_Float64", 4772, "typed-value"),
                ("TestCommand_Duration", 4796, "typed-value"), ("TestCommand_Timestamp", 4820, "typed-value"), ("TestCommand_String", 4857, "api-only"),
                ("TestCommand_Bool", 4883, "api-only"), ("TestCommand_Value", 4906, "api-only"), ("TestCommand_Value_InvalidFlagAccessHandler", 4963, "api-only"),
                ("TestCommand_Args", 4991, "api-only"), ("TestCommand_IsSet", 5007, "api-only"), ("TestCommand_IsSet_fromEnv", 5049, "env"),
                ("TestCommand_NumFlags", 5097, "api-only"), ("TestCommand_Set", 5140, "api-only"), ("TestCommand_Set_ReplacesSourceValue", 5157, "api-only"),
                ("TestCommand_Set_InvalidFlagAccessHandler", 5177, "api-only"), ("TestCommand_lookupFlag", 5191, "api-only"),
                ("TestCommandAttributeAccessing", 5221, "api-only"), ("TestCheckRequiredFlags", 5283, "layer-validation"),
                ("TestCheckRequiredFlagsWithOnUsageError", 5447, "layer-validation"), ("TestCommand_ParentCommand_Set", 5462, "api-only")]:
    out(URF, f"{U}:{l}", n, r)
ref(URF, f"{U}:5477", "TestCommandStringDashOption / double dash separate value", [k_dashv])
R(URF, f"{U}:5477 TestCommandStringDashOption", "long", "foo -bar - test (single-dash long name)", "bar is \"-\"",
  ["nodes", "set", "n", "-name", "-"], run("nodes set", ["n"], {"name": ["-"]}), ours=err("unknown-flag", "nodes set", "-name"), why=SINGLE,
  row="single dash separate value")
for n, l, r in [("TestCommandReadArgsFromStdIn", 5522, "other: args from stdin"), ("TestZeroValueCommand", 5688, "api-only"),
                ("TestCommandInvalidName", 5693, "api-only"), ("TestCommandCategories", 5708, "help-format"),
                ("TestCommandSliceFlagSeparator", 5736, "other: configurable list separator"), ("TestCommandSliceFlagSeparatorFromEnvVar", 5751, "env"),
                ("TestCommandMapKeyValueFlagSeparator", 5769, "typed-value")]:
    out(URF, f"{U}:{l}", n, r)
ST = f"{U}:5790 TestStringFlagTerminator"
R(URF, ST, "dash-dash", "test --flag x -- test a1 a2 a3", "flag x, args after --", ["run", "--file", "x", "--", "a1", "a2", "a3"],
  run("run", ["a1", "a2", "a3"], {"file": ["x"]}), tree="pf", row="flag and args after terminator")
R(URF, ST, "dash-dash", "test --flag -- x (row commented out upstream: it wanted an error)",
  "code gives flag \"--\", args [x] (" + PROBE + ")", ["run", "--file", "--", "x"], run("run", ["x"], {"file": ["--"]}), tree="pf",
  row="missing flag value due to terminator (commented out)")
R(URF, ST, "dash-dash", "test --flag x --", "flag x, no args", ["run", "--file", "x", "--"], run("run", None, {"file": ["x"]}), tree="pf",
  row="terminator with no trailing args")
ref(URF, f"{U}:5790", "TestStringFlagTerminator / no terminator, only flag", [k_sp])
R(URF, ST, "dash-dash", "test -- x --flag=value", "args x --flag=value", ["run", "--", "x", "--file=value"], run("run", ["x", "--file=value"]),
  tree="pf", row="flag defined after --")
R(URF, ST, "interspersed", "test --flag value x", "flag value, args x", ["run", "--file", "value", "x"], run("run", ["x"], {"file": ["value"]}),
  tree="pf", row="flag and without --")
BT = f"{U}:5874 TestBoolFlagTerminator"
R(URF, BT, "dash-dash", "test --flag -- x", "bool true, args x", ["run", "--bool", "--", "x"], run("run", ["x"], {"bool": T["true"]}), tree="pf",
  row="bool flag omitted value defaults to true")
R(URF, BT, "dash-dash", "test --flag=false -- x", "bool false, args x", ["run", "--bool=false", "--", "x"], run("run", ["x"], {"bool": ["false"]}),
  tree="pf", row="bool flag explicitly set to false")
R(URF, BT, "dash-dash", "test -- x --flag=true", "bool unset, args x --flag=true", ["run", "--", "x", "--bool=true"], run("run", ["x", "--bool=true"]),
  tree="pf", row="bool flag defined after --")
R(URF, BT, "bool", "test --flag=true x", "bool true, args x", ["run", "--bool=true", "x"], run("run", ["x"], {"bool": T["true"]}), tree="pf",
  row="bool flag and without --")
SS = f"{U}:5952 TestSliceStringFlagParsing"
ref(URF, f"{U}:5952", "TestSliceStringFlagParsing / single value without delimiter", [u_acc])
u_comma = R(URF, SS, "strings", "--flag x,y", "split on comma: [x y]", ["auth", "keys", "create", "o", "--tags", "tag:ci,tag:prod"],
            run("auth keys create", ["o"], {"tags": ["tag:ci,tag:prod"]}), row="multiple values with comma",
            note="one argument, comma separated (D6, POSIX G8); the layer splits")
R(URF, SS, "strings", "--flag x:y", "unsplit: [x:y]", ["auth", "keys", "create", "o", "--tags", "tag:ci"],
  run("auth keys create", ["o"], {"tags": ["tag:ci"]}), row="without delimiter specified, value remains unsplit")
for n, l, r in [("TestJSONExportCommand", 6037, "help-format"), ("TestCommand_ExclusiveFlags", 6606, "layer-validation"),
                ("TestCommand_ExclusiveFlagsWithOnUsageError", 6632, "layer-validation"), ("TestCommand_ExclusiveFlagsWithAfter", 6662, "layer-validation"),
                ("TestCommand_ParallelRun", 6697, "api-only"), ("TestCommand_ExclusiveFlagsPersistent", 6725, "layer-validation")]:
    out(URF, f"{U}:{l}", n, r)
EP = f"{U}:6823 TestEmptyPositionalArgs"
R(URF, EP, "empty-value", "app hello \"\" world", "args hello \"\" world", ["run", "hello", "", "world"], run("run", ["hello", "", "world"]),
  tree="pf", row="empty arg between values")
R(URF, EP, "empty-value", "app \"\" hello", "args \"\" hello", ["run", "", "hello"], run("run", ["", "hello"]), tree="pf", row="empty arg at start")
R(URF, EP, "verbatim", "app hello \"  \" world", "whitespace kept", ["run", "hello", "  ", "world"], run("run", ["hello", "  ", "world"]),
  tree="pf", row="whitespace-only arg")
EA = f"{U}:6866 TestEmptyPositionalArgsAfterFlag"
R(URF, EA, "empty-value", "app -f=something \"\" arg2 arg3", "f something, args \"\" arg2 arg3", ["run", "-f=something", "", "arg2", "arg3"],
  run("run", ["", "arg2", "arg3"], {"file": ["something"]}), tree="pf", row="empty arg after equals-form flag")
R(URF, EA, "empty-value", "app -f something \"\" arg2", "f something, args \"\" arg2", ["run", "-f", "something", "", "arg2"],
  run("run", ["", "arg2"], {"file": ["something"]}), tree="pf", row="empty arg after space-form flag")
ref(URF, f"{U}:6911", "TestFlagEqualsEmptyValue / --flag= sets empty string", [k_emptyeq])
u_eqpos = R(URF, f"{U}:6911 TestFlagEqualsEmptyValue", "empty-value", "app --name= positional", "name \"\", args positional",
            ["run", "--file=", "positional"], run("run", ["positional"], {"file": [""]}), tree="pf", row="--flag= does not consume next positional arg")
R(URF, f"{U}:6956 TestCommand_NoDefaultCmdArgMatchingFlag", "verbatim", "rootCommand --flag flagvalue flag", "args [flag]",
  ["run", "--file", "flagvalue", "file"], run("run", ["file"], {"file": ["flagvalue"]}), tree="pf")
for n, l in [("TestDefaultCommandWithSubcommandFlags", 6983), ("TestDefaultCommandWithShortFlag", 7026), ("TestDefaultCommandWithShortFlagHandling", 7057)]:
    out(URF, f"{U}:{l}", n, "other: default command")
for n, l, r in [("TestCommand_Path", 7088, "api-only"), ("TestCommand_Walk", 7105, "api-only"), ("TestCommand_Walk_ShortCircuit", 7124, "api-only"),
                ("TestCommand_Walk_Hidden", 7147, "api-only"), ("TestCommand_Walk_NilFn", 7166, "api-only"),
                ("TestCommand_ArgValidator_RunsBeforeAction", 7171, "layer-validation"), ("TestCommand_ArgValidator_ErrorShortCircuitsAction", 7193, "layer-validation"),
                ("TestCommand_ArgValidator_InheritsFromParent", 7212, "layer-validation"), ("TestCommand_ArgValidator_SubcommandOverride", 7234, "layer-validation"),
                ("TestCommand_ArgValidator_RunsBeforeBefore", 7262, "layer-validation"), ("TestRunWithNoOsArgs", 7290, "lifecycle"),
                ("TestCommand_Deprecated", 7317, "deprecated"), ("TestCommand_DeprecatedStillRuns", 7433, "deprecated")]:
    out(URF, f"{U}:{l}", n, r)
R(URF, "command_parse.go:163 (bool flag, empty value)", "bool", "--bool= ", "true: an empty =value on a bool reads as true",
  ["nodes", "delete", "n", "--force="], run("nodes delete", ["n"], {"force": T["true"]}),
  ours=err("bad-value", "nodes delete", "--force"), why="quirk: urfave reads --bool= as --bool", note=PROBE)
R(URF, "command_parse.go:136 (dash word not followed by a letter)", "dash-value", "-10 11 (also args_test.go:200 row \"set ival uival\")",
  "-10 and everything after it are positionals: flag parsing stops silently", ["run", "-10", "--bool"], run("run", ["-10", "--bool"]), tree="pf",
  ours=err("unknown-flag", "run", "-10"), why="quirk: urfave ends flag parsing at a word like -10 or -+; pflag/kong/ff/getopt report an unknown flag, -- is the way",
  note=PROBE)
SN = "command_stop_on_nth_arg_test.go"
R(URF, f"{SN}:11 TestCommand_StopOnNthArg", "interspersed", "cmd --flag value arg1 --bool arg2 (StopOnNthArg nil)", "flag, bool, args arg1 arg2",
  ["run", "--file", "value", "arg1", "--bool", "arg2"], run("run", ["arg1", "arg2"], {"file": ["value"], "bool": T["true"]}), tree="pf",
  row="nil StopOnNthArg - normal parsing")
out(URF, f"{SN}:11", "TestCommand_StopOnNthArg / other rows", "other: opt-in stop after N positionals")
out(URF, f"{SN}:122", "TestCommand_StopOnNthArg_WithSubcommands", "other: opt-in stop after N positionals")
out(URF, f"{SN}:236", "TestCommand_StopOnNthArg_EdgeCases", "other: opt-in stop after N positionals")
A = "args_test.go"
for n, l, r in [("TestArgNotSet", 13, "api-only"), ("TestArgsMaxNotSet", 22, "api-only"), ("TestArgsMinGtMax", 35, "layer-validation"),
                ("TestArgsFloatTypes", 50, "typed-value"), ("TestArgsIntTypes", 77, "typed-value"), ("TestArgsFloatSliceTypes", 103, "typed-value"),
                ("TestArgsIntSliceTypes", 126, "typed-value"), ("TestArgsUintTypes", 151, "typed-value"), ("TestArgsUintSliceTypes", 175, "typed-value"),
                ("TestArgumentsRootCommand", 200, "typed-value"), ("TestArgumentsInvalidType", 301, "typed-value"), ("TestArgumentsSubcommand", 326, "typed-value"),
                ("TestArgUsage", 420, "help-format"), ("TestArgsUsage", 453, "help-format"), ("TestArgsConsumedByNamedArguments", 518, "api-only"),
                ("TestSingleOptionalArg", 542, "layer-validation"), ("TestSingleRequiredArg", 587, "layer-validation"),
                ("TestMissingRequiredArgDoesNotMutateValue", 644, "layer-validation"), ("TestChainedRequiredArgs", 670, "layer-validation"),
                ("TestRequiredArgAfterOptionalArg", 689, "layer-validation"), ("TestRequiredArgAfterMultiValueArgUsesRequiredErrorHandling", 701, "layer-validation"),
                ("TestCheckRequiredArgumentsSkipsHelpAndCompletionCommands", 721, "layer-validation"), ("TestRequiredArgWithOnUsageError", 747, "layer-validation"),
                ("TestUnboundedArgs", 761, "api-only")]:
    out(URF, f"{A}:{l}", n, r)
FB = "flag_bool_with_inverse_test.go"
ref(URF, f"{FB}:74", "TestBoolWithInverseBasic / --no-env", [k_neg])
ref(URF, f"{FB}:74", "TestBoolWithInverseBasic / --env", [k_force])
out(URF, f"{FB}:74", "TestBoolWithInverseBasic / (none)", "api-only")
R(URF, f"{FB}:74 TestBoolWithInverseBasic", "negation", "--env --no-env", "error: cannot set both flags",
  ["nodes", "delete", "n", "--force", "--no-force"], err("flag-repeated", "nodes delete", "--force"),
  ours=err("unknown-flag", "nodes delete", "--no-force"), why=D9, row="--env --no-env", note="urfave's own error; flag-repeated is the nearest kind")
out(URF, f"{FB}:109", "TestBoolWithInverseAction", "lifecycle")
ref(URF, f"{FB}:155", "TestBoolWithInverseAlias", [k_neg])
out(URF, f"{FB}:191", "TestBoolWithInverseEnvVars", "env")
ref(URF, f"{FB}:255", "TestBoolWithInverseWithPrefix", [k_neg])
for n, l, r in [("TestBoolWithInverseRequired", 295, "layer-validation"), ("TestBoolWithInverseNames", 327, "api-only"),
                ("TestBoolWithInverseDefaultText", 342, "help-format"), ("TestBoolWithInverseString", 348, "help-format"),
                ("TestBoolWithInverseDestination", 446, "api-only"), ("TestBoolWithInverseFlag_SatisfiesRequiredFlagInterface", 542, "api-only"),
                ("TestBoolWithInverseFlag_SatisfiesVisibleFlagInterface", 548, "api-only"),
                ("TestBoolWithInverseFlagStringNoPanicWithNoTabStringer", 558, "help-format"), ("TestBoolWithInverseFlagCount", 577, "api-only")]:
    out(URF, f"{FB}:{l}", n, r)
FT = "flag_test.go"
R(URF, f"{FT}:1870 TestParseShortOptionBoolError", "short-group", "run -vd=notabool", "error parsing bool",
  ["test", "-ab=notabool"], err("bad-value", "test", "--bflag"), tree=X, ours=err("unknown-flag", "test", "-ab"), why=D11)
ref(URF, f"{FT}:1893", "TestParseMultiString", [k_short])
ref(URF, f"{FT}:1952", "TestParseMultiStringSlice", [u_acc])
ref(URF, f"{FT}:2378", "TestParseMultiBool", [k_force])
ref(URF, f"{FT}:2391", "TestParseBoolShortOptionHandle", [u_grp])
ref(URF, f"{FT}:2483", "TestParseMultiBoolT", [k_forcef])
R(URF, f"{FT}:2496 TestStringSliceFlagApply_LocalPreservesRepeatedValues", "strings", "--values a,b,c --values d --values e",
  "[a b c d e]", ["nodes", "list", "--filter", "id,name,ip", "--filter", "owner", "--filter", "online"],
  run("nodes list", None, {"filter": ["id,name,ip", "owner", "online"]}))
ref(URF, f"{FT}:3313", "TestSliceShortOptionHandle", [u_grp])
out(URF, FT, "(all other test functions: help output, env, typed values, Apply/ValueFromCommand getters)", "typed-value")
UC = "completion_test.go"
for n, l, r in [("TestCompletionHelp", 17, "help-format"), ("TestCompletionDisable", 64, "api-only"), ("TestCompletionEnable", 71, "api-only"),
                ("TestCompletionEnableDiffCommandName", 90, "script-internals"), ("TestCompletionShell", 104, "script-internals"),
                ("TestCompletionSubcommandOrder", 122, "script-internals"), ("TestCompletionBashNoShebang", 147, "script-internals"),
                ("TestCompletionBashAppendsSpace", 168, "script-internals"), ("TestCompletionBashGreedyColonParsing", 189, "script-internals"),
                ("TestCompletionFishFormat", 216, "script-internals"), ("TestCompletionFishOmitsPositionalTokenFromDynamicCompletion", 246, "script-internals"),
                ("TestCompletionBashOmitsPositionalTokenFromDynamicCompletion", 265, "script-internals")]:
    out(URF, f"{UC}:{l}", n, r)
CS = f"{UC}:284 TestCompletionSubcommand"
C(URF, CS, "complete-cmd", "foo bar <TAB>", "lists the subcommand xyz", ["nodes", ""], comp(has=["list", "delete", "set", "routes"]),
  row="subcommand general completion")
c_dash = C(URF, CS, "complete-flag", "foo bar -<TAB>", "lists flag l1 (primary names only, help.go:226)", ["nodes", "set", "n", "-"],
           comp(has=["--name", "--expiry"], not_=["-e"]), row="subcommand flag completion",
           note="urfave prints each flag's first name; a one-letter first name gets one dash; aliases are never offered")
c_dd = C(URF, CS, "complete-flag", "foo bar --<TAB> / foo bar xyz --<TAB>", "--l1 / --help", ["nodes", "list", "--"],
         comp(has=["--columns", "--help"]), row="subcommand double dash shows long flags")
C(URF, CS, "complete-flag", "foo bar xyz <TAB>", "no flags on an empty word", ["nodes", "list", ""], comp(not_=["--columns", "--help", "-o"]),
  row="sub sub command general completion")
ref(URF, f"{UC}:284", "TestCompletionSubcommand / sub sub command flag completion", [c_dash])
ref(URF, f"{UC}:284", "TestCompletionSubcommand / sub sub command double dash shows flags", [c_dd])
C(URF, CS, "complete-dashdash", "foo bar xyz -- sargs <TAB>", "no flags, action does not run", ["nodes", "set", "--", "n", ""],
  comp(not_=["--name", "--expiry"]), row="sub sub command no completion extra args")
c_li = C(URF, CS, "complete-flag", "foo bar --l<TAB>", "--l1", ["nodes", "list", "--li"], comp(exact=["--list-columns"]),
         row="subcommand partial double dash flag completion")
C(URF, CS, "complete-flag", "foo bar xyz --he<TAB>", "--help", ["nodes", "list", "--he"], comp(exact=["--help"]),
  row="sub sub command partial double dash flag completion")
CD = f"{UC}:438 TestCompletionAfterDoubleDashNeverRunsAction"
c_rootdd = C(URF, CD, "complete-dashdash", "foo -- somearg <TAB>", "nothing past --, no action", ["--", "x", ""], comp(exact=[]),
             row="root command past double dash")
ref(URF, f"{UC}:438", "TestCompletionAfterDoubleDashNeverRunsAction / root command past double dash multiple words", [c_rootdd])
C(URF, CD, "complete-dashdash", "foo sub -- somearg <TAB>", "nothing past --, no action", ["policy", "set", "--", "x", ""], comp(exact=[]),
  row="subcommand past double dash")
out(URF, f"{UC}:493", "TestCompletionAfterDoubleDashDoesNotLeakToNextRun", "other: state across runs in one process")
for n, l, r in [("TestCompletionSubcommandCustomShellComplete", 529, "api-only"), ("TestCompletionRunsBeforeChain", 556, "lifecycle"),
                ("TestCompletionReturnsBeforeError", 587, "lifecycle"), ("TestCompletionInvalidShell", 608, "script-internals"),
                ("TestCompletionShellRenderError", 618, "script-internals"), ("TestCompletionShellWriteError", 656, "script-internals")]:
    out(URF, f"{UC}:{l}", n, r)
PR = "completion_partial_regression_test.go"
PP = f"{PR}:33 TestPartialFlagCompletionAfterPositionalArgument"
C(URF, PP, "complete-flag", "app --pa<TAB>", "own flags", ["--ver"], comp(exact=["--version"]), row="app/*")
C(URF, PP, "complete-flag", "app sub value --pa<TAB>", "own and parent flags after a positional", ["nodes", "set", "n", "--co"],
  comp(exact=["--config"]), row="sub/*")
C(URF, PP, "complete-flag", "app sub nested first second --pa<TAB>", "own, parent and grandparent flags", ["nodes", "routes", "set", "n", "r", "--co"],
  comp(exact=["--config"]), row="nested/*")
c_pdd = C(URF, f"{PR}:68 TestPartialFlagCompletionAfterDoubleDash", "complete-dashdash", "app sub -- --pa<TAB>", "no output past --",
          ["nodes", "list", "--", "--co"], comp(exact=[]))
out(URF, f"{PR}:89", "TestPartialFlagCustomCompletionArgs", "api-only")
out(URF, f"{PR}:109", "TestPartialFlagCompletionDisabled", "api-only")
for f, r in [("cli_test.go", "api-only"), ("dce_test.go", "api-only"), ("errors_test.go", "lifecycle"), ("examples_test.go", "help-format"),
             ("examples_template_test.go", "help-format"), ("fish_test.go", "script-internals"), ("fish_template_test.go", "script-internals"),
             ("flag_float_slice_test.go", "typed-value"), ("flag_float_test.go", "typed-value"), ("flag_int_slice_test.go", "typed-value"),
             ("flag_int_test.go", "typed-value"), ("flag_mutex_test.go", "layer-validation"), ("flag_number_slice_test.go", "typed-value"),
             ("flag_schema_type_test.go", "api-only"), ("flag_text_test.go", "typed-value"), ("flag_uint_slice_test.go", "typed-value"),
             ("flag_uint_test.go", "typed-value"), ("flag_validation_test.go", "layer-validation"), ("help_notemplate_test.go", "help-format"),
             ("help_output_test.go", "help-format"), ("help_test.go", "help-format"), ("helpers_test.go", "api-only"), ("sort_test.go", "api-only"),
             ("suggestions_test.go", "suggestions"), ("value_source_test.go", "env")]:
    out(URF, f, "(all test functions; not in the assigned files)", r)

# ---------------------------------------------------------------- ff
FS = "flag_set_test.go"
out(FF, f"{FS}:19", "TestFlagSet_Basics", "api-only")
out(FF, f"{FS}:40", "TestFlagSet_Bool / add bool flag", "api-only")
FBo = f"{FS}:40 TestFlagSet_Bool"
ref(FF, f"{FS}:40", "TestFlagSet_Bool / --xflag", [k_force])
R(FF, FBo, "bool", "--xflag=true", "x true", ["nodes", "delete", "n", "--force=true"], run("nodes delete", ["n"], {"force": T["true"]}), row="--xflag=true")
f_sw = R(FF, FBo, "bool", "--xflag true", "x true, the word true is taken as the value", ["run", "--bool", "true"], run("run", None, {"bool": T["true"]}),
         tree="pf", ours=run("run", ["true"], {"bool": T["true"]}), why=SWALLOW, row="--xflag true")
f_beq = R(FF, FBo, "short-eq", "-x=true", "ErrUnknownFlag: = read as a grouped short", ["run", "-b=true"], err("unknown-flag", "run", "-="),
          tree="pf", ours=run("run", None, {"bool": T["true"]}), why=D11, row="-x=true", note="urfave accepts -b=true (probe); kong refuses like ff")
R(FF, FBo, "short", "-x", "x true", ["run", "-b"], run("run", None, {"bool": T["true"]}), tree="pf", row="-x")
R(FF, FBo, "bool", "-x false", "x true; false is a positional", ["run", "-b", "false"], run("run", ["false"], {"bool": T["true"]}), tree="pf", row="-x false")
ref(FF, f"{FS}:40", "TestFlagSet_Bool / -y", [k_force])
ref(FF, f"{FS}:40", "TestFlagSet_Bool / --yflag=false", [k_forcef])
R(FF, FBo, "bool", "--yflag false (default true)", "y false", ["run", "--bool", "false"], run("run", None, {"bool": ["false"]}), tree="pf",
  ours=run("run", ["false"], {"bool": T["true"]}), why=SWALLOW, row="--yflag false")
out(FF, f"{FS}:40", "TestFlagSet_Bool / --yflag false -y", "layer-validation")
ref(FF, f"{FS}:40", "TestFlagSet_Bool / -y=false", [f_beq])
f_h = R(FF, FBo, "help", "-h", "ErrHelp", ["run", "-h"], err("help", "run"), tree="pf", row="-h")
ref(FF, f"{FS}:40", "TestFlagSet_Bool / --help", [f_h])
R(FF, FBo, "help", "--xflag -h", "ErrHelp", ["run", "--bool", "-h"], err("help", "run"), tree="pf", row="--xflag -h")
ref(FF, f"{FS}:40", "TestFlagSet_Bool / -y --help", [f_h])
SB = f"{FS}:115 TestStdFlags_Bool"
f_std = R(FF, SB, "long", "-xflag (stdlib flag set)", "x true", ["nodes", "delete", "n", "-force"], run("nodes delete", ["n"], {"force": T["true"]}),
          ours=err("unknown-flag", "nodes delete", "-force"), why=SINGLE, row="-xflag")
R(FF, SB, "long", "-xflag=true (stdlib flag set)", "x true", ["nodes", "delete", "n", "-force=true"], run("nodes delete", ["n"], {"force": T["true"]}),
  ours=err("unknown-flag", "nodes delete", "-force"), why=SINGLE, row="-xflag=true")
for r in ["-xflag true", "--xflag true", "-y false", "--y false", "--y false -y"]:
    ref(FF, f"{FS}:115", "TestStdFlags_Bool / " + r, [f_sw, f_std])
for r in ["--xflag=true", "-y", "-y=false", "--y=false", "-h", "--help", "-xflag -h", "--y=false --help"]:
    ref(FF, f"{FS}:115", "TestStdFlags_Bool / " + r, [f_std, f_h])
for n, l, r in [("TestFlagSet_HelpFlag", 167, "api-only"), ("TestFlagSet_GetFlag", 193, "api-only"), ("TestFlagSet_NoDefault", 217, "help-format"),
                ("TestFlagSet_NoPlaceholder", 233, "help-format"), ("TestFlagSet_Get", 249, "api-only"), ("TestFlagSet_invalid", 271, "api-only"),
                ("TestFlagSet_structs", 313, "struct-tags"), ("TestFlagSet_StructIgnoreReset", 486, "struct-tags"), ("TestFlagSet_StructEmbedded", 546, "struct-tags"),
                ("TestFlagSet_Std", 591, "api-only"), ("TestStructFieldCustomDefault", 614, "struct-tags"), ("TestFlagSet_Func", 656, "typed-value"),
                ("TestFlagSet_duplicates", 751, "env")]:
    out(FF, f"{FS}:{l}", n, r)
PT = "parse_test.go"
for r in ["empty", "args", "file only", "env only", "file args", "env args", "file env", "file env args", "file repeats", "priority repeats",
          "WithEnvVars", "WithEnvVars prefix", "WithEnvVars no prefix", "WithEnvVarSplit", "env default comma behavior",
          "env var split comma whitespace", "env var split escaping", "env var split escaping multichar", "env var provided but empty"]:
    out(FF, f"{PT}:18", "TestParse / " + r, "typed-value" if r in ("empty", "args") else ("config-file" if "file" in r else "env"))
ref(FF, f"{PT}:18", "TestParse / repeated args", [k_last, u_acc])
PF2 = f"{PT}:149 TestParse_FlagSet"
R(FF, PF2, "eq", "--str=foo --int 123 --bflag -d 13m", "str foo, bflag true (int, dur typed)", ["test", "--str=foo", "--bflag"],
  run("test", None, {"str": ["foo"], "bflag": T["true"]}), tree=X, row="long args")
ref(FF, f"{PT}:149", "TestParse_FlagSet / -b only", [k_force])
ref(FF, f"{PT}:149", "TestParse_FlagSet / --str abc", [k_sp])
ref(FF, f"{PT}:149", "TestParse_FlagSet / -s xxx", [k_short])
R(FF, PF2, "short-eq", "-s=xxx", "str \"=xxx\"", ["test", "-s=xxx"], run("test", None, {"str": ["=xxx"]}), tree=X,
  ours=run("test", None, {"str": ["xxx"]}), why=D11, row="-s=xxx")
R(FF, PF2, "short-attached", "-str=xxx", "str \"tr=xxx\" (attached value after -s)", ["test", "-str=xxx"], run("test", None, {"str": ["tr=xxx"]}),
  tree=X, ours=err("unknown-flag", "test", "-str"), why=D11, row="-str=xxx", note="urfave reads -str=xxx as the long name str (probe)")
R(FF, PF2, "dash-value", "-s -b", "str \"-b\"", ["test", "-s", "-b"], run("test", None, {"str": ["-b"]}), tree=X, row="-s -b",
  note="kong refuses (probe)")
R(FF, PF2, "short", "-a -b -c", "all three true", ["test", "-a", "-b", "-k"], run("test", None, {"aflag": T["true"], "bflag": T["true"], "kflag": T["true"]}),
  tree=X, row="-a -b -c")
R(FF, PF2, "short-group", "-ab -c", "all three true", ["test", "-ab", "-k"], run("test", None, {"aflag": T["true"], "bflag": T["true"], "kflag": T["true"]}),
  tree=X, ours=err("unknown-flag", "test", "-ab"), why=D11, row="-ab -c")
R(FF, PF2, "short-group", "-ab -sfoo -bc", "a b c true, s foo (b given twice)", ["test", "-ab", "-sfoo", "-bk"], err("flag-repeated", "test", "--bflag"),
  tree=X, ours=err("unknown-flag", "test", "-ab"), why=D11, row="-ab -sfoo -bc", note="ff accepts the repeat; D15 makes it flag-repeated")
R(FF, PF2, "short-group", "-absfoo -c", "a b c true, s foo", ["test", "-absfoo", "-k"],
  run("test", None, {"aflag": T["true"], "bflag": T["true"], "kflag": T["true"], "str": ["foo"]}), tree=X,
  ours=err("unknown-flag", "test", "-absfoo"), why=D11, row="-absfoo -c")
R(FF, PF2, "short-group", "-acs foo -b", "a b c true, s foo", ["test", "-aks", "foo", "-b"],
  run("test", None, {"aflag": T["true"], "bflag": T["true"], "kflag": T["true"], "str": ["foo"]}), tree=X,
  ours=err("unknown-flag", "test", "-aks"), why=D11, row="-acs foo -b")
f_stop = R(FF, PF2, "interspersed", "-a true -b false -c true", "a true; parsing stops at the first positional: args true -b false -c true",
           ["test", "-a", "true", "-b", "false", "-k", "true"], run("test", ["true", "-b", "false", "-k", "true"], {"aflag": T["true"]}), tree=X,
           ours=run("test", ["true", "false", "true"], {"aflag": T["true"], "bflag": T["true"], "kflag": T["true"]}), why=MIX, row="-a true -b false -c true")
R(FF, PF2, "help", "--str foo -h", "ErrHelp", ["test", "--str", "foo", "-h"], err("help", "test"), tree=X, row="--str foo -h")
ref(FF, f"{PT}:149", "TestParse_FlagSet / --str foo --help -b", [f_h])
out(FF, f"{PT}:149", "TestParse_FlagSet / -s foo -f 1.23", "typed-value")
ref(FF, f"{PT}:149", "TestParse_FlagSet / -a true -b true", [f_stop])
R(FF, PF2, "bool", "--aflag true --cflag true", "a c true, no args (long bools take the true words)", ["test", "--aflag", "true", "--kflag", "true"],
  run("test", None, {"aflag": T["true"], "kflag": T["true"]}), tree=X,
  ours=run("test", ["true", "true"], {"aflag": T["true"], "kflag": T["true"]}), why=SWALLOW, row="--aflag true --cflag true")
R(FF, PF2, "bool", "-a --bflag=false", "a true, b false", ["test", "-a", "--bflag=false"], run("test", None, {"aflag": T["true"], "bflag": ["false"]}),
  tree=X, row="-a --bflag=false")
R(FF, PF2, "bool", "-a false", "a true, args false", ["test", "-a", "false"], run("test", ["false"], {"aflag": T["true"]}), tree=X, row="-a false")
SA = f"{PT}:280 TestParse_StdFlagSetAdapter"
out(FF, f"{PT}:280", "TestParse_StdFlagSetAdapter / -singledash space values", "typed-value")
R(FF, SA, "bool", "-a true -b true (stdlib flag set: single dash is long, bools take true words)", "a b true",
  ["test", "-a", "true", "-b", "true"], run("test", None, {"aflag": T["true"], "bflag": T["true"]}), tree=X,
  ours=run("test", ["true", "true"], {"aflag": T["true"], "bflag": T["true"]}), why=SWALLOW, row="-singledash space values bool")
out(FF, f"{PT}:280", "TestParse_StdFlagSetAdapter / --doubledash space values bool", "other: one-letter long names (tree has none)")
R(FF, SA, "short-eq", "-a -b=false (stdlib flag set)", "a true, b false", ["test", "-a", "-b=false"], run("test", None, {"aflag": T["true"], "bflag": ["false"]}),
  tree=X, row="bool default true set false")
ref(FF, f"{PT}:280", "TestParse_StdFlagSetAdapter / bool default true set false with spaces", [f_sw])
out(FF, f"{PT}:321", "TestParse_PlainParser", "config-file")
out(FF, f"{PT}:378", "TestParse_types", "typed-value")
out(FF, f"{PT}:411", "TestParse_stdfs", "config-file")
CT = "command_test.go"
ref(FF, f"{CT}:14", "TestCommandNoFlags / -h, --help", [f_h])
out(FF, f"{CT}:14", "TestCommandNoFlags / no args (ErrNoExec)", "other: root without exec errors; D10 makes the root alone help")
R(FF, f"{CT}:38 TestCommandReset", "global", "--verbose foo -b \"hello world\"", "root flag, subcommand, its bool, a positional with a space",
  ["--config", "x", "nodes", "delete", "--force", "hello world"], run("nodes delete", ["hello world"], {"config": ["x"], "force": T["true"]}),
  row="first run")
out(FF, f"{CT}:38", "TestCommandReset / later runs", "lifecycle")
out(FF, "example_test.go", "(examples)", "help-format")
out(FF, "ffval/value_test.go", "(all test functions)", "typed-value")
out(FF, "ffval/collections_test.go", "(all test functions)", "typed-value")
R(FF, "flag_set.go:327 parseLongFlag", "empty-value", "--str= foo", "an empty =value counts as no value: str takes the next word, foo",
  ["run", "--file=", "x"], run("run", None, {"file": ["x"]}), tree="pf", ours=run("run", ["x"], {"file": [""]}),
  why="quirk: ff cannot tell --x= from --x (urfave, kong, pflag give the empty value)", note=PROBE + "; --file= alone is ff's missing value")
R(FF, "flag_set.go:200 parse loop", "dash-value", "- x", "a lone - is skipped: args [x]", ["run", "-", "x"], run("run", ["x"]), tree="pf",
  ours=run("run", ["-", "x"]), why="quirk: ff drops a lone - (kong, urfave, POSIX G13 keep it as an operand)", note=PROBE)

# ---------------------------------------------------------------- tailscale ffcomplete
TL = "cmd/tailscale/cli/ffcomplete/internal/complete_test.go:31 TestComplete"
t_us = C(TS, TL, "complete-cmd", "deb", "[debug]", ["us"], comp(exact=["users"]), row="deb")
ref(TS, "cmd/tailscale/cli/ffcomplete/internal/complete_test.go:31", "TestComplete / deb+descs", [t_us])
C(TS, TL, "complete-flag", "-", "--root-bool --root-str -v (one-letter names get one dash)", ["-"], comp(has=["--version", "--config"]), row="-")
C(TS, TL, "complete-flag", "--", "--root-bool --root-str --v", ["--"], comp(has=["--version", "--config"]), row="--")
C(TS, TL, "complete-flag", "-r", "-root-bool -root-str (single-dash long, stdlib flag)", ["-ver"], comp(has=["-version"]),
  ours=comp(exact=[]), why=SINGLE, row="-r")
C(TS, TL, "complete-flag", "--r", "--root-bool --root-str", ["--ver"], comp(exact=["--version"]), row="--r")
C(TS, TL, "complete-flag", "--root-str=s --r", "--root-bool: omits a flag already set", ["nodes", "list", "--columns=id", "--"],
  comp(has=["--sort"], not_=["--columns"]), row="--root-str=s --r",
  note="undecided: hide flags already given (D15 makes a second one an error); serpent does it too")
C(TS, TL, "complete-dashdash", "-- --root", "no flags after -- (test checks only the directive)", ["nodes", "list", "--", "--so"],
  comp(not_=["--sort"]), row="-- --root")
t_ddv = C(TS, TL, "complete-dashdash", "--root-str -- --r", "-- is the value of --root-str, flags still offered: --root-bool",
          ["nodes", "list", "--columns", "--", "--s"], comp(has=["--sort"]), row="--root-str -- --r")
ref(TS, "cmd/tailscale/cli/ffcomplete/internal/complete_test.go:31", "TestComplete / --root-str -- --root", [t_ddv])
C(TS, TL, "complete-dashdash", "--root-str -- -- --r", "second -- ends flags: nothing", ["nodes", "list", "--columns", "--", "--", "--s"],
  comp(not_=["--sort"]), row="--root-str -- -- --r")
C(TS, TL, "complete-value", "--root-bool=", "[true false]", ["nodes", "delete", "n", "--force="], comp(exact=["true", "false"]),
  row="--root-bool=", note="undecided: offer true/false after --bool= (D9 accepts both)")
C(TS, TL, "complete-value", "--root-bool=t", "[true]", ["nodes", "delete", "n", "--force=t"], comp(exact=["true"]), row="--root-bool=t")
C(TS, TL, "complete-value", "--root-bool=T", "[TRUE] (case of the typed prefix kept)", ["nodes", "delete", "n", "--force=T"], comp(exact=["TRUE"]),
  row="--root-bool=T")
ref(TS, "cmd/tailscale/cli/ffcomplete/internal/complete_test.go:31", "TestComplete / debug --de", [c_li])
C(TS, TL, "complete-value", "debug --enum=", "[alpha beta charlie], NoFileComp", ["nodes", "list", "--sort="], comp(exact=COLS, files=False),
  row="debug --enum=")
C(TS, TL, "complete-value", "debug --enum=al", "[alpha], NoFileComp", ["nodes", "list", "--sort=o"], comp(exact=["online", "owner"], files=False),
  row="debug --enum=al")
t_free = C(TS, TL, "complete-value", "debug --level <TAB> (flag without completer)", "nothing, directive Default (shell may offer files)",
           ["nodes", "set", "n", "--name", ""], comp(files=True), row="debug --level \"\"",
           note="undecided: free-text flag value: files (ffcomplete, cobra default) or nothing")
ref(URF, f"{U}:3414", "TestShellCompletionForIncompleteFlags", [t_free])
t_sp = C(TS, TL, "complete-value", "debug --enum b", "[beta], NoFileComp", ["nodes", "list", "--sort", "ho"], comp(exact=["hostname"], files=False),
         row="debug --enum b")
ref(TS, "cmd/tailscale/cli/ffcomplete/internal/complete_test.go:31", "TestComplete / debug --enum al", [t_sp])
out(TS, "cmd/tailscale/cli/ffcomplete/internal/complete_test.go:31", "TestComplete / ping \"\" +flags, +flags+descs",
    "other: option listing flags on an empty word")
C(TS, TL, "complete-value", "ping <TAB> (Args completer)", "[jupiter neptune venus], NoFileComp", ["completion", ""],
  comp(exact=["bash", "zsh", "fish", "powershell"], files=False), row="ping \"\"")
C(TS, TL, "complete-value", "ping j", "[jupiter], NoFileComp", ["completion", "f"], comp(exact=["fish"], files=False), row="ping j")

# ---------------------------------------------------------------- serpent
SC = "command_test.go"
SCT = f"{SC}:183 TestCommand"
s_ok = R(SERP, SCT, "tree", "toupper hello", "HELLO", ["nodes", "delete", "hello"], run("nodes delete", ["hello"]), row="SimpleOK")
R(SERP, SCT, "alias", "up hello", "alias runs toupper", ["nodes", "rm", "hello"], run("nodes delete", ["hello"]), row="Alias")
out(SERP, f"{SC}:183", "TestCommand / BadArgs", "layer-validation")
ref(SERP, f"{SC}:183", "TestCommand / NoSubcommand", [u_nf])
s_unk = R(SERP, SCT, "unknown-flag", "toupper --unknown", "error", ["nodes", "delete", "--unknown"], err("unknown-flag", "nodes delete", "--unknown"),
          row="UnknownFlags", note="the unknown flag is reported before the missing argument")
R(SERP, SCT, "global", "--verbose toupper hello", "root flag before the subcommand", ["--config", "x", "nodes", "delete", "hello"],
  run("nodes delete", ["hello"], {"config": ["x"]}), row="Verbose")
R(SERP, SCT, "eq", "--verbose=true toupper hello", "root flag with = before the subcommand", ["--config=x", "nodes", "delete", "hello"],
  run("nodes delete", ["hello"], {"config": ["x"]}), row="Verbose=")
R(SERP, SCT, "verbatim", "--prefix \"conv: \" toupper hello", "value with a space", ["--config", "conv: ", "nodes", "delete", "hello"],
  run("nodes delete", ["hello"], {"config": ["conv: "]}), row="PrefixSpace")
s_any = R(SERP, SCT, "global", "toupper --prefix \"conv: \" hello --verbose", "root flags anywhere after the subcommand",
          ["nodes", "delete", "--config", "conv: ", "hello", "--force"], run("nodes delete", ["hello"], {"config": ["conv: "], "force": T["true"]}),
          row="GlobalFlagsAnywhere")
ref(SERP, f"{SC}:183", "TestCommand / LowerVerbose", [s_any])
out(SERP, f"{SC}:183", "TestCommand / ParsedFlags", "api-only")
R(SERP, SCT, "unknown-cmd", "root level level toupper ...", "error: no such child", ["nodes", "nodes", "list"], err("unknown-command", "nodes", "nodes"),
  row="NoDeepChild")
for r in ["RequiredFlagsMissing", "RequiredFlagsMissingWithHelp", "RequiredFlagsMissingBool", "RequiredFlagsMissingString",
          "RequiredFlagsInvalid", "RequiredFlagsOK"]:
    out(SERP, f"{SC}:183", "TestCommand / " + r, "layer-validation")
out(SERP, f"{SC}:183", "TestCommand / DeprecatedCommand", "deprecated")
ref(SERP, f"{SC}:402", "TestCommand_DeepNest", [k_pos])
out(SERP, f"{SC}:428", "TestCommand_FlagOverride", "other: child flag shadows a parent flag (tree construction)")
out(SERP, f"{SC}:464", "TestCommand_MiddlewareOrder", "lifecycle")
out(SERP, f"{SC}:497", "TestCommand_RawArgs", PASS)
out(SERP, f"{SC}:562", "TestCommand_RootRaw", PASS)
R(SERP, f"{SC}:580 TestCommand_HyphenHyphen", "dash-dash", "-- --verbose --friendly", "args --verbose --friendly, verbose unset",
  ["run", "--", "--bool", "--verbose"], run("run", ["--bool", "--verbose"]), tree="pf")
out(SERP, f"{SC}:608", "TestCommand_ContextCancels", "lifecycle")
R(SERP, f"{SC}:629 TestCommand_Help", "help", "--help", "help handler runs, not the handler", ["--help"], err("help", ""), row="DefaultHandler/Long")
R(SERP, f"{SC}:629 TestCommand_Help", "help", "-h", "help handler runs", ["-h"], err("help", ""), row="Short")
ref(SERP, f"{SC}:677", "TestCommand_SliceFlags", [u_acc])
R(SERP, f"{SC}:706 TestCommand_EmptySlice", "empty-value", "--arr \"\"", "resets the list to empty", ["nodes", "list", "--filter", ""],
  run("nodes list", None, {"filter": [""]}), note="the layer keeps the raw empty value; what an empty list value means is the layer's call")
for n, l, r in [("TestCommand_DefaultsOverride", 751, "env"), ("TestCommand_OptionsWithSharedValue", 853, "api-only"),
                ("TestOptionSet_DefaultAndDefaultFn", 928, "api-only"), ("TestCommand_DefaultFn", 946, "api-only")]:
    out(SERP, f"{SC}:{l}", n, r)
SCC = "completion_test.go:16 TestCompletion"
C(SERP, SCC, "complete-cmd", "<TAB> at root", "all subcommands", [""], comp(exact=ROOTKIDS, files=False), row="SubcommandList")
C(SERP, SCC, "complete-cmd", "f<TAB>", "all subcommands: the shell filters by prefix", ["n"], comp(exact=ROOTKIDS),
  ours=comp(exact=["nodes"]), why="quirk: serpent (and urfave, help.go:185) leave prefix filtering to the shell; cobra's __complete filters in the binary",
  row="SubcommandNoPartial")
C(SERP, SCC, "complete-cmd", "required-flag<TAB>", "[required-flag]", ["nodes"], comp(exact=["nodes"]), row="SubcommandComplete")
ref(SERP, "completion_test.go:16", "TestCompletion / ListFlags", [c_dash])
C(SERP, SCC, "complete-flag", "altfile -<TAB>", "--extra (plus the arg completer's words)", ["policy", "set", "-"], comp(has=["--dry-run"]),
  row="ListFlagsAfterArg")
C(SERP, SCC, "complete-flag", "required-flag --req-bool --req-string \"foo bar\" --req-array asdf --req-array qwerty -<TAB>",
  "only flags not yet given (arrays stay)", ["auth", "keys", "create", "o", "--reusable", "--description", "foo bar", "-"],
  comp(has=["--tags", "--expiry"], not_=["--reusable", "--description"]), row="FlagExhaustive",
  note="undecided: hide flags already given (D15)")
C(SERP, SCC, "complete-flag", "required-flag -b -s \"foo bar\" -a asdf -<TAB>", "flags given by short name are hidden too",
  ["auth", "keys", "create", "o", "-d", "foo bar", "-e", "1d", "-"], comp(has=["--tags"], not_=["--description", "--expiry"]), row="FlagShorthand",
  note="undecided: hide flags already given (D15)")
C(SERP, SCC, "complete-flag", "--verbose -<TAB> (root)", "[--prefix]: the given bool is hidden and does not eat -", ["--version", "-"],
  comp(has=["--config"], not_=["--version"]), row="NoOptDefValueFlag", note="undecided: hide flags already given (D15)")
C(SERP, SCC, "complete-value", "required-flag --req-enum <TAB>", "[foo bar qux]", ["nodes", "list", "--sort", ""], comp(exact=COLS), row="EnumOK")
C(SERP, SCC, "complete-value", "required-flag --req-enum --req-enum=<TAB>", "--req-enum=foo ... (cursor word read as a new --x= flag)",
  ["nodes", "list", "--sort", "--sort="], comp(has=["id", "name"]), ours=comp(exact=[]), why=D20, row="EnumEqualsOK",
  note="serpent prints --x=v, cobra's protocol returns v and the script re-adds --x=; carried as v")
s_q = C(SERP, SCC, "complete-value", "required-flag --req-enum=\"<TAB>", "--req-enum=foo ... (leading quote dropped)", ["nodes", "list", "--sort=\""],
        comp(has=["id", "name"]), row="EnumEqualsBeginQuotesOK", note="undecided: strip an opening quote in --x=\"<Tab>; carried without the --x= prefix")
C(SERP, SCC, "complete-list", "required-flag --req-enum-array <TAB>", "[foo bar qux]", ["nodes", "list", "--filter", ""], comp(has=["id", "hostname"]),
  row="EnumArrayOK")
C(SERP, SCC, "complete-list", "required-flag --req-enum-array=<TAB>", "--req-enum-array=foo ...", ["nodes", "list", "--filter="],
  comp(has=["id", "hostname"]), row="EnumArrayEqualsOK", note="carried without the --x= prefix (protocol)")
ref(SERP, "completion_test.go:16", "TestCompletion / EnumArrayEqualsBeginQuotesOK", [s_q])
s_file = C(SERP, "completion_test.go:163 TestFileCompletion", "complete-file", "file /tmp/dir<TAB>", "the binary lists directory entries itself",
           ["policy", "set", "/tmp/"], comp(files=True), row="DirOK", note="in cobra's protocol the shell lists files; carried as files=true")
for r in ["EmptyDirOK", "CurDirOK", "PrevDirOK", "RootOK"]:
    ref(SERP, "completion_test.go:163", "TestFileCompletion / " + r, [s_file])
out(SERP, "completion_test.go:238", "TestCompletionInstall", "script-internals")
ref(SERP, "option_test.go:13", "TestOptionSet_ParseFlags / SimpleString", [k_sp, k_short])
ref(SERP, "option_test.go:13", "TestOptionSet_ParseFlags / StringArray", [u_acc])
ref(SERP, "option_test.go:13", "TestOptionSet_ParseFlags / ExtraFlags", [s_unk])
out(SERP, "option_test.go:13", "TestOptionSet_ParseFlags / RegexValid, RegexInvalid", "typed-value")
for n, l, r in [("TestOptionSet_ParseEnv", 113, "env"), ("TestOptionSet_JsonMarshal", 255, "api-only"), ("TestOptionSet_DefaultFn", 316, "api-only"),
                ("TestOptionSet_DefaultFnRace", 365, "api-only")]:
    out(SERP, f"option_test.go:{l}", n, r)
out(SERP, "env_test.go:10", "TestFilterNamePrefix", "env")
out(SERP, "values_test.go", "TestDuration, TestDurationOf", "typed-value")
out(SERP, "yaml_test.go", "TestOptionSet_YAML*", "config-file")

# ---------------------------------------------------------------- glibc
g_miss = R(GLIBC, "posix/bug-getopt1.c:63 do_test", "missing-value", "optstring \"+:a:b\", argv -a", "':' (a needs an argument, silent)",
           ["run", "-f"], err("missing-value", "run", "-f"), tree="pf", row="-a")
R(GLIBC, "posix/bug-getopt1.c:63 do_test", "missing-value", "\"+:a:b\", -b -a", "'b' then ':'", ["run", "-b", "-f"], err("missing-value", "run", "-f"),
  tree="pf", row="-b -a")
R(GLIBC, "posix/bug-getopt2.c:60 do_test", "unknown-flag", "\"+a\", -+", "'?' with a message", ["run", "-+"], err("unknown-flag", "run", "-+"), tree="pf",
  note="urfave would stop flag parsing at -+ and keep it as a positional (command_parse.go:136)")
g3 = R(GLIBC, "posix/bug-getopt3.c:67 do_test", "short-group", "\"ab:W;\", -a;", "'a' then '?' for ;", ["run", "-b;"], err("unknown-flag", "run", "-;"),
       tree="pf", ours=err("unknown-flag", "run", "-b;"), why=D11, row="-a;")
ref(GLIBC, "posix/bug-getopt3.c:67", "do_test / -a:", [g3])
g_ab = R(GLIBC, "posix/bug-getopt4.c:66 do_test", "abbrev", "long alpha, --a", "'a' (unique abbreviation)", ["run", "--bo"],
         run("run", None, {"bool": T["true"]}), tree="pf", ours=err("unknown-flag", "run", "--bo"), why=NOABBR, row="--a")
out(GLIBC, "posix/bug-getopt4.c:66", "do_test / -W a", "other: GNU -W foo means --foo")
ref(GLIBC, "posix/bug-getopt5.c:61", "do_test / --a (two longs, same val)", [g_ab])
out(GLIBC, "posix/bug-getopt5.c:61", "do_test / -W a", "other: GNU -W foo means --foo")
g_amb = R(GLIBC, "posix/tst-getopt_long1.c:30 do_test", "abbrev", "one two one-one four onto, --on", "'?': ambiguous, lists the candidates",
          ["nodes", "list", "--co", "x"], err("unknown-flag", "nodes list", "--co"), note="--co would fit --columns and --config")
GC = "posix/tst-getopt-cancel.c:160"
R(GLIBC, f"{GC} tests_short", "short-group", "\"+ab:c\", -ac -b x", "no errors", ["run", "-bv", "-f", "x"],
  run("run", None, {"bool": T["true"], "verbose": T["true"], "file": ["x"]}), tree="pf", ours=err("unknown-flag", "run", "-bv"), why=D11, row="no errors")
R(GLIBC, f"{GC} tests_short", "unknown-flag", "-d", "error message", ["run", "-d"], err("unknown-flag", "run", "-d"), tree="pf", row="invalid option")
ref(GLIBC, GC, "tests_short / missing argument", [g_miss])
GL = "posix/tst-getopt-cancel.c:172"
R(GLIBC, f"{GL} tests_long", "long", "-a --charlie --bravo=x", "no errors", ["run", "-b", "--verbose", "--file=x"],
  run("run", None, {"bool": T["true"], "verbose": T["true"], "file": ["x"]}), tree="pf", row="no errors (long)")
R(GLIBC, f"{GL} tests_long", "unknown-flag", "-a --charlie --dingo", "error", ["run", "-b", "--verbose", "--dingo"], err("unknown-flag", "run", "--dingo"),
  tree="pf", row="invalid option (long)")
R(GLIBC, f"{GL} tests_long", "bool", "-a --charlie=dingo (no_argument)", "error: option takes no argument", ["run", "--verbose=dingo"],
  err("bad-value", "run", "--verbose"), tree="pf", row="unwanted argument")
R(GLIBC, f"{GL} tests_long", "bool", "--charlie=true for a no_argument option (same rule as the unwanted-argument row)",
  "error: getopt_long refuses any =value on a no_argument option", ["run", "--verbose=true"], err("bad-value", "run", "--verbose"), tree="pf",
  ours=run("run", None, {"verbose": T["true"]}), why=D9, row="unwanted argument (generalised)",
  note="not a separate upstream row: the unwanted-argument row's rule applied to the value true")
R(GLIBC, f"{GL} tests_long", "missing-value", "-a --charlie --bravo", "error: requires an argument", ["run", "-b", "--verbose", "--file"],
  err("missing-value", "run", "--file"), tree="pf", row="missing argument (long)")
ref(GLIBC, GL, "tests_long / ambiguous options", [g_amb])
for r in ["no errors (long W)", "missing argument (W itself)", "missing argument (W longopt)", "unwanted argument (W longopt)", "ambiguous options (W)"]:
    out(GLIBC, GL, "tests_long / " + r, "other: GNU -W foo means --foo")

# ---------------------------------------------------------------- util-linux getopt(1)
UB = "tests/ts/getopt/basic (expected/getopt/basic)"
R(UL, UB, "interspersed", "-o ab:c:: --long a-long,b-long:,c-long:: -- -a -b 1 -c2 --a-long --b-long 3 --c-long foo bar",
  "a, b 1, c 2, a, b 3, c (none); remaining foo bar", ["run", "-b", "-f", "1", "--verbose", "--string", "3", "foo", "bar"],
  run("run", ["foo", "bar"], {"bool": T["true"], "file": ["1"], "verbose": T["true"], "string": ["3"]}), tree="pf",
  note="optional-value -c and the repeats of a/b are left out (OUT optional-value, D15)")
UO = "tests/ts/getopt/options"
for st in ["alternative_option_clash", "alternative_option_long", "alternative_option_short"]:
    out(UL, UO, st, "other: getopt(1) --alternative mode (single-dash long names with abbreviation)")
out(UL, UO, "invalid_getopt_option", "other: getopt(1) own options and output quoting")
ul_m = R(UL, f"{UO} invocation_model_one", "dash-value", "abc:d::e::f::g: ARG0 -b ARG1 -d -eOPTIONAL1 -f NOT_OPTIONAL ARG2 -a -c -ISREQUIRED ARG3",
         "-c takes -ISREQUIRED as its argument; operands permuted to the end", ["run", "ARG0", "-b", "ARG1", "-s", "-ISREQUIRED", "ARG2"],
         run("run", ["ARG0", "ARG1", "ARG2"], {"bool": T["true"], "string": ["-ISREQUIRED"]}), tree="pf",
         note="optional-value -d -e -f left out")
ref(UL, UO, "invocation_model_three_as_one", [ul_m])
out(UL, UO, "invocation_model_two_as_one", "other: getopt(1) own options and output quoting")
out(UL, UO, "invocation_without_parameters", "other: getopt(1) own options and output quoting")
ref(UL, UO, "long_option_ambiguous_1", [g_amb])
R(UL, f"{UO} longopts", "abbrev", "-l long1,secondlong:,thirdlong::,abbreviation: -- --long1 EXTRA1 --thirdlong=ARGUMENT --secondlong=ARG --abbr ABBRARG -a",
  "--abbr expands to --abbreviation; EXTRA1 is an operand", ["run", "--bool", "EXTRA1", "--string=ARG", "--fi", "ABBRARG", "-v"],
  run("run", ["EXTRA1"], {"bool": T["true"], "string": ["ARG"], "file": ["ABBRARG"], "verbose": T["true"]}), tree="pf",
  ours=err("unknown-flag", "run", "--fi"), why=NOABBR)
for st in ["name_option_long", "name_option_short", "quiet_option_long", "quiet_option_short", "quiet_output_option_long",
           "quiet_output_option_short", "test_for_enhanced_getopt", "unquoted_option_bash", "unquoted_option_tcsh", "weird_quoting_bash",
           "weird_quoting_tcsh", "no-arguments", "compatible", "sh", "csh"]:
    out(UL, UO, st, "other: getopt(1) own options and output quoting")
out(UL, UO, "same_long_short_options", "other: one-letter long names (tree has none)")
R(UL, f"{UO} unknown_options", "unknown-flag", "-o a -l long -- -b --long --whatever -a", "errors for -b and --whatever, exit 1",
  ["run", "-x", "--bool", "--whatever", "-v"], err("unknown-flag", "run", "-x"), tree="pf", note="getopt reports every error; the first is carried")
ul_p = R(UL, f"{UO} posix_correctly", "interspersed", "-o +ab:c:: ... -- -a ... foo bar xyxxy --a-long (also POSIXLY_CORRECT)",
         "first operand ends the options: --a-long is an operand", ["run", "-b", "foo", "--verbose"], run("run", ["foo", "--verbose"], {"bool": T["true"]}),
         tree="pf", ours=run("run", ["foo"], {"bool": T["true"], "verbose": T["true"]}), why=MIX)
ref(UL, UO, "non-option / + mode", [ul_p])
R(UL, f"{UO} non-option", "interspersed", "-o a:b: -- -a x y -b z w (default GNU permute)", "-a x -b z -- y w", ["run", "-s", "x", "y", "-f", "z", "w"],
  run("run", ["y", "w"], {"string": ["x"], "file": ["z"]}), tree="pf", row="default mode")
out(UL, UO, "non-option / - mode (return in order)", "other: getopt(1) in-order mode")

# ---------------------------------------------------------------- POSIX
R(POSIX, "12.2 Guideline 3", "long", "single-letter options only; -name is not one option", "-n... is read as options n, a, m, e (unknown here)",
  ["nodes", "set", "n", "-name", "x"], err("unknown-flag", "nodes set", "-name"))
R(POSIX, "12.2 Guideline 5", "short-group", "options without arguments, then at most one with an argument, grouped", "-bvs alpha: b, v, s=alpha",
  ["run", "-bvs", "alpha"], run("run", None, {"bool": T["true"], "verbose": T["true"], "string": ["alpha"]}), tree="pf",
  ours=err("unknown-flag", "run", "-bvs"), why=D11)
R(POSIX, "12.1 item 2 / Guideline 6", "short-attached", "implementations shall also accept option and option-argument in one string", "-salpha: s=alpha",
  ["run", "-salpha"], run("run", None, {"string": ["alpha"]}), tree="pf", ours=err("unknown-flag", "run", "-salpha"), why=D11)
out(POSIX, "12.2 Guideline 7", "option-arguments should not be optional", "optional-value")
ref(POSIX, "12.2 Guideline 8", "multiple option-arguments as one comma-separated argument", [u_comma])
R(POSIX, "12.2 Guideline 9", "interspersed", "all options should precede operands", "a -b: -b is an operand",
  ["run", "a", "-b"], run("run", ["a", "-b"]), tree="pf", ours=run("run", ["a"], {"bool": T["true"]}), why=MIX)
R(POSIX, "12.2 Guideline 10", "dash-dash", "the first -- that is not an option-argument ends the options", "-f -- x: f=\"--\", operand x",
  ["run", "-f", "--", "x"], run("run", ["x"], {"file": ["--"]}), tree="pf")
R(POSIX, "12.2 Guideline 10", "dash-dash", "operands after --, even if they begin with -", "-- -b x: operands -b x",
  ["run", "--", "-b", "x"], run("run", ["-b", "x"]), tree="pf")
R(POSIX, "12.2 Guideline 11", "repeat", "a repeated option with arguments is read in order", "-f a -f b: both, in order",
  ["run", "-f", "a", "-f", "b"], run("run", None, {"file": ["a", "b"]}), tree="pf", ours=err("flag-repeated", "run", "--file"), why=D15)
ref(POSIX, "12.2 Guideline 13", "- as an operand means stdin/stdout", [k_dash])
ref(POSIX, "12.2 Guideline 14", "an argument that fits an option is an option (so -s -b gives s the value only because -s needs one)", [ul_m])

# ---------------------------------------------------------------- write
with open(os.path.join(NOTES, "cases", "others.jsonl"), "w") as f:
    for c in cases:
        f.write(json.dumps(c, ensure_ascii=False) + "\n")
os.makedirs(os.path.join(NOTES, "inventory"), exist_ok=True)
with open(os.path.join(NOTES, "inventory", "others.tsv"), "w") as f:
    f.write("src\tname\tverdict\treason\tids\n")
    for r in inv:
        f.write("\t".join(x.replace("\t", " ").replace("\n", " ") for x in r) + "\n")
print(len(cases), "cases", len(inv), "inventory rows")
