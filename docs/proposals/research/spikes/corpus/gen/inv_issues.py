import json, sys
ids = json.load(open(sys.argv[1]))
B = {"pflag": "https://github.com/spf13/pflag/issues/", "cobra": "https://github.com/spf13/cobra/issues/",
     "kong": "https://github.com/alecthomas/kong/issues/", "urfave": "https://github.com/urfave/cli/issues/"}
SI, PL = "script-internals", "other: platform"
rows = {
"pflag": """541 Parse empty shorthand flag values|IN|p541
511 parse explicit short flag values (NoOptDefVal)|OUT|optional-value
499 empty StringArray value as empty slice|OUT|typed-value
475 reject single-dash long flag names|IN|c2358
421 bool flags parent/child order|IN|c2251
417 StringP parses next flag as value|IN|p417
410 footgun-proofing --bool false|IN|p288
406 asterisk as string value|OUT|other: shell glob expansion
372 abbreviated long args|IN|p372
328 same flag name on several commands|OUT|api-only
314 shorthand understands parameter without space|IN|c2358
311 cannot pass arguments that begin with -|IN|p311,c124
307 StringSlice truncates on newline|IN|p307
303 Bool after StringArray parsed into array|IN|p417
288 boolean --test false|IN|p288
277 optional stop on first argument|OUT|other: opt-in non-interspersed mode
265 bool vs boolSlice|OUT|typed-value
214 bool flags with only NoOptDefVal|IN|p214
173 panic: unknown flag followed by empty arg|IN|p173
154 args after bool flag|IN|p154
117 error if flag provided multiple times|IN|p72
72 error if same flag given twice|IN|p72
60 Go flag short values|OUT|other: Go flag compatibility
33 mixed named and positional parsing (PR)|OUT|other: no argv in issue (links rkt)
32 mixed named and positional broken|OUT|other: no argv in issue (links rkt)
21 bool= with shortnames|IN|p21
20 --flag arg|IN|c1114
12 short form -p=value|IN|p12
5 -- termination|IN|p5
4 force stop at terminator|IN|p5
1 flag terminator|IN|p5
370 double quote in string slice|OUT|typed-value
81 comma in string slice|OUT|typed-value
439 FlagSet.Parse keeps old args|OUT|api-only
146 single dash long options|IN|p146
329 traditional single-dash flags|IN|p146""",
"cobra": """2528 TraverseChildren runs subcommand after --|IN|c2528
2518 lone dash positional in command discovery|IN|c2518,c2518b
2512 unknown flag swallows following flag|IN|c2512
2360 unknown-flag errors stable|IN|c2512
2535 inherit parent local flags before subcommand|IN|c2311
2311 missing subcommand with parent flags|IN|c2311
2559 completion after --|IN|c2559,c2559b
2565 one-letter long flag completion|OUT|other: one-letter long names not in our specs
2527 completion parses flags twice|OUT|api-only
2358 single-hyphen long flag mistreated|IN|c2358
2295 '- h' read as flag|IN|c2295
2290 root local flag before subcommand|OUT|other: opt-in TraverseChildren
2251 bool flags parent/child order|IN|c2251
2243 ValidArgsFunction on '-'|OUT|api-only
2210 multi-value flag detection in completion|OUT|typed-value
2188 grouped shorts before command names|IN|u2254
2144 @ in completed value|OUT|script-internals
2132 embedded struct flags|OUT|struct-tags
2100 ArgsLenAtDash for single dash|OUT|api-only
2092 leaf flag accepted before the leaf|IN|c2092
2038 local flags on root|OUT|other: runnable root (tree shape)
2007 ignore unknown hyphen flags|OUT|other: unknown-flag pass-through
1998 flags passed to ValidArgsFunction|OUT|api-only
1985 option to forbid --flag <space> arg|OUT|other: opt-in mode
1931 flag found inside another flag's argument|IN|c1931
1913 flag value matches subcommand name|IN|c1913
1834 persistent flag value equals subcommand|IN|c1913
1777 flag value misparsed as subcommand|IN|c1777
1895 args after --: split helper|OUT|api-only
1877 ArgsLenAtDash in completion|OUT|api-only
1821 bool default true toggle|OUT|api-only
1816 completion: dash as 2nd char seen as flag|IN|c1816,c1816b
1817 completion: dash as 2nd char (PR)|IN|c1816
1797 unknown flag before unknown command|IN|c1797
1733 '- + 7' positional read as flag|IN|c2295
1714 zsh r<tab> file completion|OUT|script-internals
1606 bool flag false vs =false|IN|p288
1594 Go 1.18 test env unknown flag|OUT|other: go test build env
1562 completion for programs without subcommands|OUT|other: root-only program (tree shape)
1542 flag completion after -- with DisableFlagParsing|IN|c2559
1502 zsh completion without space|OUT|script-internals
1491 completion of two positionals (question)|OUT|api-only
1480 NoArgs and --all true|IN|p288
1472 flags recognised as value of other flags|IN|p417
1462 integer flags like -6|OUT|typed-value
1449 duplicate flag names persistent/local|OUT|other: spec construction
1445 double quotes in help|OUT|help-format
1437 flag completion registry regression|OUT|api-only
1409 inconsistent errors for bad subcommand + flag|IN|c2512
1398 two commands share one flag variable|OUT|api-only
1170 complete subcommands after local flag|IN|c1170
1172 bash: subcommands after local non-persistent flag|OUT|other: no root-local value flags in our tree
1127 <space><tab> runs the handler|OUT|script-internals
1114 argument with space|IN|c1114
1011 extra positional ignored|OUT|layer-validation
997 subcommand after positional|OUT|other: tree shape (groups take no positionals)
981 subcommand handling meta issue|OUT|other: no single argv
909 empty argument swallows next flag|IN|c909
760 em/en dash|IN|c760
722 local flags with same name|OUT|api-only
683 no flag parsing after subcommand|OUT|other: DisableFlagParsing
618 Traverse with grouped shorts|IN|u2254
615 bool flag before command|IN|c615
433 hyphen arguments that are not flags|IN|p311
415 --flag=<tab> doubled|IN|c415
368 -org read as -o rg|IN|c2358
124 negative numbers as arguments|IN|c124,p311
66 stripFlags robustness (PR)|OUT|other: no argv
63 unknown commands -h --help|IN|c63
44 global pflag.CommandLine flags|OUT|api-only
17 flags after -- reported|IN|p5
10 commands and flags in any order|IN|c10
2 wrap command line arguments|IN|c2
26 prefix matching replaced by aliases|IN|c26
1852 aliases not tab-completed|IN|c1852
578 bash alias of the program|OUT|script-internals
1786 completion for --help/--version|IN|c1786
572 extra space after single flag|OUT|script-internals
2385 comma-separated completion|IN|c2385
2433 MarkFlagAppendEqual|OUT|optional-value
2476 flags mixed into filter directive|OUT|other: FilterFileExt/FilterDirs unused
1257 completion with grouped shorts|IN|c1257
1629 completion of attached short value|IN|c1629
1307 completion and interspersed=false|OUT|other: opt-in non-interspersed mode
1061 required flags hide optional ones|OUT|layer-validation
926 bool flag order misleading error|OUT|help-format
1424 choose between repeated flags|IN|p72
2186 completion must use stdout|OUT|lifecycle
2129 zsh file completion despite NoFileComp|OUT|script-internals
1076 subcommands hidden by ValidArgs|OUT|other: group with positionals (tree shape)
2376 bash splits on colons|OUT|script-internals
1929 PowerShell drops @arg|OUT|other: platform
1740 whitespace in candidates, bash|OUT|script-internals
1303 fish: line starting with space|OUT|script-internals
1214 fish: unbalanced quote|OUT|script-internals
868 bash: duplicated flags with =|OUT|script-internals
1269 empty alias breaks bash script|OUT|script-internals
1334 bash: redirection on the line|OUT|script-internals
2465 bash: required flag as --flag value|OUT|script-internals
2513 directive line when stderr is stdout|OUT|lifecycle
1189 zsh prefers flags over nouns|OUT|script-internals
1211 zsh ignores NoSpace|OUT|script-internals
1802 case-insensitive command names|IN|c1802""",
"kong": """679 default command flags before sibling|OUT|other: default commands
660 -- protects flags but not command matching|IN|c2528
662 missing value with hyphen-prefixed params|IN|k662
637 single-char alias leaks between siblings|OUT|other: spec construction
611 command validated before flags|OUT|lifecycle
589 single-letter alias as short|OUT|struct-tags
570 short flags keep the equal sign|IN|p12
478 negative positional|IN|p311
166 negative number as argument|IN|p311
315 negative value with -a=|IN|k315
463 passthrough passes a flag|OUT|struct-tags
441 error if flag given twice|IN|k441
433 quotes and sep in []string|OUT|typed-value
290 values starting with -|IN|k290
175 multi-char short tag|OUT|api-only
170 negatable flag value|IN|k170
152 quoted argument as one value|IN|c1114
102 slice flag with several words|IN|k102
80 -x inside an arg slice|IN|p5
70 single dash as argument|IN|c2518
51 positionals before command|OUT|other: tree shape""",
"urfave": """2544 DefaultCommand name leaks into args|OUT|other: default commands
2439 inverse bool in combined shorts|OUT|other: inverse bool flags (D9) inside groups (D11)
2433 single-rune Unicode flags|OUT|other: non-ASCII short names
2418 bare - drops following args|IN|u2418,c2518
2315 completion for -- and --prefix|IN|u2315,u2315b
2293 --flag= rejected|IN|u2293
2292 empty positional ends parse|IN|u2292
2257 spurious empty string before flag name|OUT|api-only
2254 combined shorts do not consume value|IN|u2254
2248 --XXX<TAB> no completions|IN|u2315
2234 empty argument drops rest|IN|u2234
2229 -v alias clashes with version flag|OUT|other: spec construction
2223 --value1= swallows next arg|IN|u2223
2208 root-local flags after subcommand|IN|u2208
1993 completion after -- runs action|IN|c2559
1964 bool arg breaks other flags|IN|u1964
1932 completion ignores --|IN|c2559
1875 completion suggests aliases|IN|u1875
1822 custom completion panics on partial flag|OUT|api-only
1500 string slice parsed twice with short handling|OUT|typed-value
1447 -- missing from Args|IN|p5
1424 args reordered after --|IN|p5
1114 naked -- strange behaviour|IN|p5
1152 flag-like args to slice flags|IN|p417
740 bool --flag false|IN|p288
645 negative numbers as arguments|IN|p311
596 bare double dash|IN|p5
324 single dash reorders args|IN|u2418,c2518
56 -- terminator broken|IN|p5
1215 unique-substring command names|IN|u1215""",
}
out = ["src\tname\tverdict\treason\tids"]
for repo, block in rows.items():
    for line in block.splitlines():
        head, verdict, x = line.split("|")
        num, name = head.split(" ", 1)
        if verdict == "IN":
            out.append("\t".join([B[repo] + num, name, "IN", "", ",".join(ids[k] for k in x.split(","))]))
        else:
            out.append("\t".join([B[repo] + num, name, "OUT", x, ""]))
open(sys.argv[2], "w").write("\n".join(out) + "\n")
ins = [r for r in out[1:] if "\tIN\t" in r]
print(len(out) - 1, "rows", len(ins), "IN")
from collections import Counter
print(Counter(r.split("\t")[3] for r in out[1:] if "\tOUT\t" in r).most_common())
