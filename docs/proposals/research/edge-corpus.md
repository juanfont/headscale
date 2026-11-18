# Edge corpus: what the existing parsers know, run against our own

Date: 2026-11-17. The maintainer asked two things before choosing an own parser: "what about all the
information and knowledge grandfathered into the other ones?" and "can we get edge cases from the
ones we need?". This note answers both by measurement: every upstream test case and bug report
about the decided grammar, carried onto our tree, run through own-grammar, own-pflag and the cobra
adapter.

## Verdict

1. **Upstream knows a lot, little of it is about our grammar.** 1,628 upstream test functions,
   table rows and issues were classified; 550 are about the grammar Headscale decided (34 %), 1,078
   are not. Of what cobra and pflag know specifically: pflag's tests 33 of 210 (16 %), cobra's
   command/args tests 53 of 210 (25 %), cobra's completion tests 32 of 117 (27 %). The rest is typed
   values, Go API, validation, help text, env, deprecation: things Headscale's layer does itself or
   does not do.
1. **The 45-line parser has no gap the corpus can find.** 360 parse cases: own-grammar matches the
   source on 251, matches a Headscale decision (or a recorded quirk) on 106, and differs from both
   on 3, all three undecided questions, none a bug. pflag's own test suite (45 cases) and pflag's
   tracker (24 issues) found nothing; the 10 pflag-test cases own-grammar differs on are all D11
   (grouped shorts, `-sVALUE`), which the maintainer made best effort.
1. **The 110-line Tab answerer had three real bugs** (12 of 125 completion cases): it offers a flag
   already given, it completes flag values after `--`, and a bare positional `o` opens `-o`'s values.
   Fix: +19/−4 lines in `Complete`, tried in `spikes/corpus/own-grammar-fix`; kit v2 still 155 MUST
   (zsh skipped: not installed in this shell), `-race -count=3` ok; the copy then fails only 8
   cases, all undecided.
1. **pflag under our dispatcher buys nothing on this corpus and brings two traps.** own-grammar and
   own-pflag differ on 7 of 485 cases: 4 are D11 best-effort forms pflag accepts, 1 is a worse error
   word, and 2 are pflag defects: `-e=` gives the value `=` (pflag #541, open) and
   `-description=foo` silently stores `escription=foo` (own-pflag's 13-line pre-scan skips words
   with `=`; cobra-based Headscale today does the same). Without the pre-scan (D11 relaxed allows
   dropping it) pflag fails 19 cases own-grammar passes, 14 of them pflag defects, mostly one-dash
   long words read as a short plus a value (`-output json` → `-o utput`).
1. **What a corpus cannot carry is the shell side**, and it stays upstream by D23: cobra's tracker
   has 227 shell-specific titles, urfave's 95. The one that hits us (bash splits on `:` in
   `tag:ci`, cobra #2376) is a script/shell matter, for the D21 real-shell job.

Recommendation from the evidence: the 45 lines are enough for parsing; the answerer needs the three
fixes and this corpus as its test; pflag's history adds no case we pass because of it.

## 1. The corpus

Files, all in `spikes/corpus/`:

| Path                           | What                                                                                                                                                                       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `corpus.jsonl`                 | **the corpus**: 485 cases, one JSON object per line (= `cat cases/*.jsonl`)                                                                                                |
| `cases/<src>.jsonl`            | the same, per miner: `pflag` (45), `goflag` (12), `cobracmd` (69), `cobracomp` (67), `issues` (66), `others` (226)                                                         |
| `inventory/<src>.tsv`          | every upstream test function / table row / issue looked at: IN with corpus ids, or OUT with a reason (1,628 rows)                                                          |
| `main.go`, `trees*.go`, `kit/` | the driver; `kit/` is a copy of kit v2 plus `export.go` (77 lines: build small trees, run one argv)                                                                        |
| `own-grammar-fix/`             | own-grammar with the three answerer fixes                                                                                                                                  |
| `own-pflag-nowa/`              | own-pflag without the 13-line `-ojson` pre-scan (what D11 relaxed allows)                                                                                                  |
| `results.tsv`, `results.md`    | one row per case × adapter; `summary.py` turns it into the numbers below                                                                                                   |
| `gen/`                         | the generators that wrote `cases/` and `inventory/`, as run (`python3 -I gen/gen_mine.py <corpus dir>` for pflag/goflag/cobracmd; the others carry their scratchpad paths) |

Run (from the worktree): `nix develop -c bash -c 'cd …/spikes/corpus && go run . -tsv results.tsv -md results.md corpus.jsonl'`.

Format of a case (driver refuses unknown fields):

```json
{"id":"pflag-034","src":"spf13/pflag@44b0d47 bool_test.go:106 TestShortFlagExtraArgument","lic":"BSD-3-Clause",
 "kind":"run","topic":"bool","upstream":"-t maybe","expect":"a bool never takes the next word: maybe is a positional",
 "tree":"pf","argv":["run","-b","maybe"],"want":{"kind":"run","path":"run","args":["maybe"],"flags":{"bool":["true"]}}}
```

`want` is the source's behaviour carried onto our tree, through Headscale's layer (`Exec` refuses
repeats, bad bools, counts). `ours` + `why` appear where Headscale decided otherwise (97 cases:
`D11`, `D9`, …), where the source behaviour is a quirk (17), or where it is open (16). Completion
cases use `has`/`not`/`exact`/`files`/`nospace` against the `__complete` answer. Trees: the kit's,
`pf` (one leaf with bool, string, list shorts), `cc` (cobra's grouped-short completion tests),
`others` (urfave/ff short tables).

Sources: spf13/pflag @44b0d47 (tests and 544 issue/PR titles), Go `flag` (go1.27.3), spf13/cobra
@adbc881 (`command_test`, `args_test`, `flag_groups_test`, `cobra_test`, `completions_test` and the
per-shell tests; 2,535 issue/PR titles), alecthomas/kong v1.17.0 (tests; 595 titles), urfave/cli
v3.14.0 (tests; 2,398 titles), peterbourgon/ff @d04e563, Tailscale `ffcomplete`, coder/serpent
v0.15.0, glibc `posix/bug-getopt1–5`, `tst-getopt_long1`, `tst-getopt-cancel`, util-linux
`tests/ts/getopt`, POSIX XBD 12.1/12.2.

### What was left out, and why (1,078 rows)

| Reason                                                                     | Rows | Why it is not knowledge we lose                                                                                                                                                                                                                          |
| -------------------------------------------------------------------------- | ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| typed-value (int, IP, duration, map, count…)                               | 221  | the parser hands strings to the layer; time and numbers are the layer's (001)                                                                                                                                                                            |
| api-only (Go getters, setters, ordering)                                   | 189  | no argv behaviour                                                                                                                                                                                                                                        |
| layer-validation (required, groups, counts, enums)                         | 171  | the layer's checks (D4, R32)                                                                                                                                                                                                                             |
| help-format                                                                | 89   | help, docs, man are generated by our code (D12–D14)                                                                                                                                                                                                      |
| struct-tags (kong/urfave reflection)                                       | 73   | specs are data, not tags                                                                                                                                                                                                                                 |
| lifecycle (hooks, context, output writers)                                 | 69   | the builder's job                                                                                                                                                                                                                                        |
| script-internals (generated script text)                                   | 45   | D23: cobra writes the scripts, fixes go upstream                                                                                                                                                                                                         |
| env, config-file                                                           | 46   | no env or config binding (DECISIONS facts)                                                                                                                                                                                                               |
| deprecated/hidden, normalisation, active-help, suggestions, optional-value | 45   | not in 001 (suggestions are D5, ours)                                                                                                                                                                                                                    |
| other                                                                      | 130  | opt-in modes (passthrough, DisableFlagParsing, non-interspersed, TraverseChildren, prefix matching), getopt(1)'s own options and quoting, GNU `-W`, default commands, runnable groups, CSV quoting inside list items, unknown-flag passthrough, platform |

Per source: pflag tests IN 33 / OUT 177; Go flag 13 / 18; cobra command+args+groups 53 / 157;
cobra completion 32 / 85; issues opened 107 / 83 (pflag 24/12, cobra 47/56, kong 13/8, urfave
23/7, from 6,072 titles screened); other suites 313 / 558.

## 2. Run it

485 cases (360 run, 125 complete). Verdict per adapter: `up` = the source's behaviour, `ours` =
Headscale's decision (or quirk/open choice recorded in `why`), `neither`.

| Source                  | own-grammar        | own-pflag      | own-pflag-nowa | cobra adapter | own-grammar-fix   |
| ----------------------- | ------------------ | -------------- | -------------- | ------------- | ----------------- |
| pflag tests (45)        | 35 / 10 / 0        | 36 / 9 / 0     | 42 / 3 / 0     | 42 / 3 / 0    | 35 / 10 / 0       |
| Go flag (12)            | 8 / 4 / 0          | 8 / 3 / 1      | 8 / 1 / 3      | 6 / 1 / 5     | 8 / 4 / 0         |
| cobra command/args (69) | 51 / 18 / 0        | 51 / 18 / 0    | 53 / 16 / 0    | 52 / 13 / 4   | 51 / 18 / 0       |
| cobra completion (67)   | 42 / 19 / 6        | 43 / 18 / 6    | 44 / 17 / 6    | 53 / 8 / 6    | 49 / 18 / 0       |
| issues (66)             | 47 / 15 / 4        | 46 / 15 / 5    | 47 / 12 / 7    | 47 / 11 / 8   | 48 / 15 / 3       |
| other suites (226)      | 152 / 64 / 10      | 154 / 61 / 11  | 171 / 32 / 23  | 174 / 30 / 22 | 157 / 64 / 5      |
| **all (485)**           | **335 / 130 / 20** | 338 / 124 / 23 | 365 / 81 / 39  | 374 / 66 / 45 | **348 / 129 / 8** |

(up / ours / neither.) "up" being higher for pflag and cobra is mostly D11: they accept grouped
shorts, which the source expects and Headscale allows (best effort).

### Classification of own-grammar's 150 non-`up` cases

| Class                                | Cases | Detail                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------ | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Maintainer decided otherwise         | 97    | D11 50 (grouped shorts, `-sVALUE`, one-dash long words), no abbreviations 7, D9 7 (`--no-x`, `--bool true`), D10 6 (groups never run), D8 6 (no `help` command), flags/positionals mix 5 (Go flag, POSIX `+`), D20 5 (kong refuses a dash-led value), D15 3, D19 3 (help wins over errors upstream), D6 2, D7 1, D16 1, D3 1      |
| Upstream quirk nobody wants          | 17    | ff: `--bool true` swallows `true` (4), `--x=` same as `--x`, drops a lone `-`; urfave: `--bool=` is true, `-10` silently ends flags, whitespace trimming; cobra: too many args says "unknown command"; stdlib one-dash longs (5); cobra falls back to files after the last argument; serpent leaves prefix filtering to the shell |
| Undecided, own-grammar made a choice | 16    | leaf flag before the subcommand (2), `--version` with other words (2), shorts on `-<TAB>` (3), completion after `-h/--version` (6), value flag with no value list (1), `-1` (1), `--filter=` (1) — see open questions                                                                                                             |
| Real gap                             | 12    | answerer only; the three bugs below                                                                                                                                                                                                                                                                                               |
| Undecided, no choice recorded        | 8     | `--force=<TAB>` → `true false` (3, Tailscale), free-text value offers files (1, ffcomplete and cobra), `--sort="<TAB>` (1, serpent), `- h` as a positional (cobra #2295), the word named by `-- nodes list` (cobra #2528, kong #660), em-dash `—-help` (cobra #760, declined there)                                               |

No case found a bug in `parse` or `walk`.

### Real gaps and their fixes (all in `Complete`)

| Gap                                                                                                                                                             | Cases | Source                                                                               | Fix in `own-grammar-fix`                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| A flag already given is offered again (`nodes list --sort id --<TAB>` offers `--sort`); D15 makes it an error                                                   | 8     | cobra `completions_test.go` (flag-already-used tests), Tailscale ffcomplete, serpent | parse the words, skip given flags except `--filter`; globals before the subcommand count (+7 lines) |
| Flag values are completed after `--` (`nodes list -- --sort=i<TAB>` → `id ip`), and the N21 check took a `--` that is a flag's value (D20) for the end of flags | 3     | cobra `completions_test.go`, Tailscale ffcomplete                                    | one `dd` computed by stepping over values, guarding all three branches (+7, 3 changed)              |
| A bare positional equal to a short letter opens that flag's values (`nodes delete o <TAB>` → `json`)                                                            | 1     | cobra #1816                                                                          | `byTyped` requires a leading `-` (+3)                                                               |

Total +19 / −4 lines; `parse` untouched. Upstream cobra has all three right; the cobra adapter
passes them.

### own-grammar versus own-pflag: what pflag's history is worth here

|                                           | own-grammar | own-pflag (with pre-scan)                                                | own-pflag-nowa (D11 relaxed)                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------- | ----------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cases where it differs from own-grammar   | —           | 7                                                                        | 55                                                                                                                                                                                                                                                                                                                                |
| …accepting a D11 best-effort form         | —           | 4 (`-bs=xx`, `-str=xxx`, `-ab=notabool`, completion of `-sdf=abc`)       | 35                                                                                                                                                                                                                                                                                                                                |
| …pflag defect                             | —           | 2: `-e=` → `=` (pflag #541, open); `-description=foo` → `escription=foo` | 14: the same two, plus 12 one-dash long words read as a short with the rest of the word as value or group (`-output json` → `-o utput`, `-invalid` → `-i nvalid`, `-string hello` → `-s tring`); 5 of the 14 store a wrong value silently, the rest end in an argument-count error or an unknown flag that names the wrong letter |
| …worse error word                         | —           | 1: `-force=true` is reported as `-f`                                     | in the 14                                                                                                                                                                                                                                                                                                                         |
| …upstream disagreement, not a defect      | —           | 0                                                                        | 5 (urfave's own reading of `-ia`, `-aik`, `-10`)                                                                                                                                                                                                                                                                                  |
| Cases own-grammar fails that pflag passes | —           | 0                                                                        | 0                                                                                                                                                                                                                                                                                                                                 |
| Lines                                     | 45 parser   | 13 pre-scan + pflag                                                      | pflag                                                                                                                                                                                                                                                                                                                             |

So on 485 cases taken from pflag's own tests and tracker, plus cobra's, kong's, urfave's, ff's,
getopt's: pflag fixes nothing own-grammar gets wrong, and adds two silent-value defects. In
Headscale terms the silent ones are free-text shorts (`-d/--description`); most others end in an
argument-count error because the rest of the word becomes a positional.

The cobra adapter's 45 `neither` include upstream bugs still present in cobra v1.10.2+7 (verified
by running it): pflag #541; cobra #2358 (`-output`); cobra #2092 (a leaf's flag before the leaf is
accepted); cobra's own FIXME row in `TestUnknownFlagShouldReturnSameErrorRegardlessOfArgPosition`
(`--unknown --namespace foo child` → "unknown command foo"); after `--` completion still offers
commands (cobra #2559); `nodes - list` still dispatches (cobra #2518).

Upstream disagreements the corpus records (from `others`; each is a decided or open point for us):
dash-led value after a value flag — taken by pflag, urfave, ff, getopt, POSIX, ours (D20), refused
by kong; `-s=xxx` — `xxx` for pflag, urfave, ours, `=xxx` for kong and ff; flags after positionals
— yes for pflag, kong, urfave, serpent, GNU, ours, no for ff, POSIX, Go flag; `--x=` — empty for
pflag, kong, urfave, next word for ff; help with a bad flag — help wins in cobra, urfave, ff, error
wins in ours (D19).

## 3. Completion pass

Cobra's `completions_test.go` (4,129 lines, 117 functions/rows inventoried): 32 IN, 85 OUT
(layer-validation 16, api-only 15, script-internals 13, active-help 11, env 10, descriptions,
FilterDirs, DisableFlagParsing, program-defined `-h/-v`). Carried: 67 cases. Plus 58 completion
cases from issues, Tailscale ffcomplete, serpent and urfave.

own-grammar on cobra's 67: 42 as cobra, 19 Headscale's choice, 6 wrong (two of the three bugs);
after the fixes 49 / 18 / 0.

Where Headscale's answerer differs from cobra by choice: D8 (no `help` command, 3), D11 (grouped
shorts, 4), D16 (1); open: cobra lists `-x` shorts on `-<TAB>` (we list longs and a short only when
typed), cobra stops completing after `-h/--help/--version` (we continue, useful because `headscale -h nodes` is the help of nodes), cobra's default directive offers files for a value flag with no
list (we offer nothing; right for `--name`, wrong for `-c <path>`).

One correction to the record: cobra never completes *command* aliases (its "only when nothing else
fits" rule is for ArgAliases of ValidArgs). The comment "aliases only when no name fits, as cobra"
in own-grammar's `Complete` misstates the source; D16 stands on its own.

## 4. Can the cases be our tests? Licence and form

| Source                         | Licence                                   | If its *code* were copied                             |
| ------------------------------ | ----------------------------------------- | ----------------------------------------------------- |
| Go `flag`                      | BSD-3-Clause                              | keep copyright, conditions, disclaimer                |
| spf13/pflag                    | BSD-3-Clause (Alex Ogier, The Go Authors) | same                                                  |
| spf13/cobra                    | Apache-2.0, no NOTICE file                | licence text, kept headers, changed files marked (§4) |
| alecthomas/kong, urfave/cli v3 | MIT                                       | copyright + permission notice                         |
| peterbourgon/ff                | Apache-2.0                                | as cobra                                              |
| coder/serpent                  | CC0-1.0                                   | nothing                                               |
| Tailscale ffcomplete           | BSD-3-Clause                              | as pflag                                              |
| glibc, util-linux tests        | LGPL-2.1 / GPL-2.0                        | do not copy; facts only                               |
| issue text                     | its author's                              | do not paste prose; cite the URL                      |

Two forms:

1. **Argv and expected outcome, re-expressed in our format** (what `corpus.jsonl` is). "A bool
   short followed by `maybe` leaves `maybe` a positional" is a fact about behaviour, carried onto
   another tree in our notation. Behaviour is not what copyright protects; test code, names,
   comments and issue prose are. Re-expressed rows need no notice from any source above. Keep the
   `src` column anyway: it is attribution in the plain sense, costs nothing, and drives the yearly
   review. (Ordinary reading for test vectors; not legal advice.)
1. **Copied test code.** BSD/MIT: allowed with the notice kept. Apache-2.0: allowed in a BSD-3
   project with the licence text in the tree, the header kept and changes marked. LGPL/GPL: no.
   It also buys nothing: the tests drive upstream APIs (`FlagSet.Parse`, `executeCommand`) and
   would be rewritten against our parser anyway.

Clean way: form 1 only. One table test in the parser package reading `{src, argv, want, why}`
rows (the JSON as is, or a generated Go table), no upstream code or comments, no NOTICE, one line
in the test file: "Rows re-express behaviour recorded in the tests and trackers named in `src`."

### Keeping it alive

- The table test is the corpus. A row whose `why` names a decision documents that decision; a
  reversed decision shows which rows move. Our own bug reports become rows with `src` = the
  Headscale issue.
- Once a year (or at a cobra/pflag release, whichever is rarer): `git log`/`git diff` of upstream
  test files since the last recorded revision, and `gh search issues` with the queries in
  `inventory/issues.tsv` for pflag and cobra (labels `area/flags-args`, `area/shell-completion`).
  Measured pace over the last 12 months: pflag 33 non-merge commits touching tests, 16 of them in
  the four in-scope files, about one about our grammar (ad27a40, custom IsBoolFlag); cobra 2, none
  about our grammar. New IN items become rows; OUT items an inventory line with a reason.
- Cost: an afternoon a year; the test is a data file plus a ~40-line runner.

## 5. Honest summary

- **Size of the knowledge.** Of everything inventoried, a third is about the narrow grammar. For
  pflag alone it is one in six test functions; pflag's tests are mostly about its 20+ value types.
  For cobra it is one in four, the rest being help, hooks, validation, groups and completion
  plumbing (descriptions, ActiveHelp, file filters).
- **What own-grammar already had.** Every parse case the corpus could carry over, except where
  Headscale decided otherwise. The parser was designed from the decisions, and the decisions were
  made with pflag/cobra behaviour in view; the corpus confirms rather than corrects them.
- **What it was missing.** Three Tab answerer bugs (+19/−4). They are the kind of thing cobra
  learnt from users (cobra #1816; the completion tests for given flags and `--`), so the
  maintainer's worry is right for the answerer, and this corpus is how that knowledge is taken.
- **What a corpus cannot carry.**
    - Users finding bugs for us: 6,072 titles across four trackers are years of reports; after a
      switch, Headscale's users are the only reporters, and parser reports would go to Headscale.
    - Shell and platform behaviour: cobra's tracker has 227 shell-specific titles (bash 3 on macOS,
      `COMP_WORDBREAKS` splitting on `:` and `=`, zsh ignoring NoSpace, fish quoting, PowerShell
      dropping `@` args, redirections on the line). D23 keeps the scripts upstream, so that
      knowledge stays with cobra as long as Headscale imports its generators; D21's real-shell job is
      the guard for the part the binary answers.
    - Future upstream fixes: pflag is active (33 test commits last year); a fix there would not reach
      an own parser. On this grammar the last year had about one relevant change.
- **Keep pflag under our dispatcher?** The evidence does not support it: zero cases where pflag is
  right and own-grammar wrong, two silent-value defects where it is the other way, and the
  pre-scan that guards one of them does not guard the other. **Are the 45 lines enough?** For
  parsing, on this corpus, yes. The part that needs care is the answerer, and the corpus now
  covers it.

## Open questions for the maintainer

1. **Shorts on `-<TAB>`.** (a) Longs only, a short when typed exactly (now; cobra lists both; 0
   lines). (b) List `-x` too, as cobra (≈2 lines; longer lists).
1. **Tab after `-h`, `--help`, `--version`.** (a) Keep completing: `headscale -h no<TAB>` →
   `nodes`, which gives the help of nodes (now). (b) Stop, as cobra (≈3 lines).
1. **Value flag with no value list (`--name`, `-c`).** (a) Offer nothing (now; right for free
   text, wrong for `-c <path>`). (b) Offer files when the spec marks the flag as a path (a
   `complete:"file"` on flags, ≈3 lines plus the spec field), nothing otherwise.
1. **A leaf's own flag before the subcommand** (`headscale -e 24h api keys create`). (a) Refuse
   (now; cobra's Traverse mode does too; D3 promises only `-c`/`-o`). (b) Accept, as cobra's
   default Find (≈10 lines in `walk`, and a value word can then hide a command word).
1. **`--version` with other words** (`--version nodes list`, `--version x`). (a) Usage error (now).
   (b) Version wins, as cobra (≈3 lines).
1. **`--filter=` and `--tags=` (empty value).** The parser delivers `""`; pflag turns it into an
   empty list. (a) The layer refuses an empty list value (≈2 lines in the layer). (b) Empty means
   "none" (clear tags), as pflag; must be stated per flag in 001.
1. **`--force=<TAB>` → `true false`** (Tailscale does). (a) Nothing (now). (b) Offer both (≈3
   lines); D9 makes `--force=false` legal, so it is a discoverability gain only.
1. **Corpus upkeep.** (a) Yearly review as above (an afternoon a year). (b) Only our own bug
   reports feed it (no cost; loses upstream learning, which measured about one relevant change in
   the last year).
