# Differential testing and fuzzing of the own parser

Date: 2026-11-17. Question: if Headscale writes its own parser (`spikes/own-grammar`), what do
the parsers that thousands of programs use (spf13/pflag, cobra's command walk, Go's `flag`)
know that it does not? Method: run millions of generated command lines through the own parser
and through them, look at every difference, and fuzz the own parser for crashes and broken
invariants.

Everything is in `spikes/diff/` (own module; adapters and kits untouched). Go 1.27.3 from the
worktree's `nix develop`, 24 cores.

## Verdict

1. **Run (parsing): 2,000,000 lines, 19 causes, 1 bug in own-grammar** (B1, 2 lines to fix).
   Every other difference is decided by a D-number, is pflag/cobra behaviour nobody would want,
   is an adapter artefact, or sits in the kit's layer. **Two causes are undecided.**
1. **Tab: 1,000,000 partial lines, 15 causes, 3 bugs in own-grammar's answerer** (B2, B4, B5;
   ~15 lines). **Four causes are undecided**, all small policy choices.
1. **pflag knows almost nothing the own grammar lacks.** Against a plain pflag FlagSet the only
   differences are D11 (`-ojson`, groups), pflag's own `-o=` quirk, and error spelling. Not one
   line where pflag reads a correct line correctly and own-grammar does not.
1. **Cobra's knowledge is mostly its command walk, and it is the part to avoid**: 38 % of lines
   differ only because of cobra (help winning over errors, D19; leaf flags before the command,
   D3; a walk that skips `-`, `""` and flag-like words, or eats the word after an unknown flag).
   Its one useful piece of knowledge is in Tab: do not offer a flag that is already given (B4).
1. **Fuzzing (Go native, 6 min per target, 6 workers):** no panic, no hang, no growth, fully
   deterministic in 43 M (Run) + 16 M (leaf properties) executions on the delivered parser. The
   Tab property ("never offer a word Run refuses") fails within 1 s on the delivered answerer
   (B2, B5); a group property finds B1 from the seed corpus. The fixed copy passes all three
   targets: 37 M + 11.6 M + 26.8 M executions, 6 min each.

What a clean result means: on the kit's 12-leaf tree and this generator, the own grammar agrees
with pflag everywhere the decisions do not say otherwise. It says nothing about shells (the
referee's pty harness covers those), platforms, the real ~60-command tree, the help/doc layer, or
inputs the generator never builds (it is biased towards near-valid lines; see "Limits").

## 1. Method

| File (`spikes/diff/`)                    | What                                                                                                                                                                                    |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kit/`                                   | copy of kit-v2 plus `probe.go`: one hook in `Exec` that records the raw `Call` before the layer's checks, `Probe`/`ProbeComplete`, and a shared read-only tree (`kit.Shared`) for speed |
| `gen.go`                                 | the generator                                                                                                                                                                           |
| `oracles.go`                             | two flag readers with no dispatcher: a plain pflag `FlagSet` and Go's `flag`                                                                                                            |
| `diff.go`                                | outcome probes, the shrinker, the word-class abstraction for unexplained leftovers                                                                                                      |
| `classify.go`                            | the taxonomy: an ordered list of causes for Run and for Tab, each a predicate on the shrunk line and both outcomes                                                                      |
| `ownfix/`                                | own-grammar's adapter with the fixes of section 4 (marked `fix B1`…`B5`)                                                                                                                |
| `cmd/diffrun`                            | the runner; `cmd/probe` prints every adapter's answer for given lines                                                                                                                   |
| `fuzz_test.go`                           | the fuzz targets (section 6); `findings/` the failing inputs                                                                                                                            |
| `final.sh`, `merge.py`, `results/final/` | the runs behind this note and their merged tables (`summary.md`)                                                                                                                        |

**Generator.** Vocabulary read off the kit's tree: every command name and alias per level, wrong
words (`node`, `NODES`, `nodés`, `help`, `preauthkeys`, a name at the wrong level, with NUL,
with spaces), every flag long and short, `--x=v`, `--x v`, `-x=v`, attached `-xv`, bools bare,
`=true`, `=false`, `=`, `=maybe`/`1`/`TRUE`/`t`/`yes`, a bool followed by a separate
`true`/`false`, missing values, repeats, unknown and misspelled flags (`--forc`, `---force`,
`--no-force`, `-output`, `--o`, `--h`, `-help`, `--=`, `-=`, `-ñ`), values from plain (`12`,
`id,name`, `tag:ci,tag:prod`, `-last-seen`) to hostile (`""`, `-`, `--`, `-h`, `--help`,
`=`, `,`, `:`, spaces, quotes, `$HOME`, Unicode, zero-width space, emoji, tab, newline, NUL,
invalid UTF-8, 5,000-byte words), and command names as values. 7 of 8 lines are structured:
pick a command, write its path (sometimes an alias, sometimes a wrong word), its positionals
(count ±1), 0–4 flags (its own, the globals, sometimes another command's or an unknown one),
insert each flag anywhere after the path (globals and 1 in 10 others also before it), sometimes
repeat one, sometimes insert `--`, then 0–2 mutations (replace, delete, duplicate, swap, insert
`-h`/`--help`/`-`/`--`/`--version`/unknown flag, append `=`/`,`/NUL/`\xff`, truncate). 1 in 8
lines is random words (0–12) from the whole vocabulary and random bytes. Tab lines cut a
generated line at a random word and a random prefix of that word.

**Comparison.** Each line runs through own-grammar, own-pflag (same dispatcher, pflag reads the
flags) and cobra (cobra + pflag), and, for lines that start with a leaf's path, through a plain
pflag `FlagSet` and Go's `flag` (only lines where every flag precedes the first positional,
since `flag` stops there). An outcome is the kit's graded string: `run <path> [args] flags`,
`help <path>`, `version`, or a usage error `<kind> [<path>] "<word>"` (word normalised to the
long name). Pairs: grammar~pflag, grammar~cobra, pflag~cobra, grammar~plainpflag,
grammar~stdflag. Severity per differing line: *semantic* (both accept, different result),
*acceptance* (one accepts, one refuses), *report* (both refuse, differently).

**Shrinking and buckets.** Each differing line is shrunk (drop a word, drop a pair, replace a
word by `x`/`12`/`-`/`--`/a shorter or printable form) while the difference keeps the same pair
of outcome kinds (Run) or the same set of words only one side offers (Tab). The shrunk line goes
through the ordered cause list; the first cause that fits names the bucket. A line no cause
fits would land in a `?` bucket keyed by its word classes; **in the final runs no line was left
unexplained** (0 `?` buckets in all four runs). Every own pair is shrunk and classified in full;
pairs with cobra in a 5 % sample (counts with "≈" are sample × 20).

**Cost.** 2 M Run lines with shrinking: 2 m 14 s. 1 M Tab lines: ~2 min in 8 chunks of 125 k,
because cobra keeps ~5.8 KiB per Tab call in its package-level flag-completion map (115 MB
after 20 k calls, `TestCobraTabHeap`; a 1 M run was OOM-killed at 10 GB). A CLI process
answers one Tab and exits, so this matters only to harnesses and long-lived programs.

## 2. Volumes and the three-way picture

Run, 2,000,000 lines (seed 7), delivered own-grammar:

| Three-way (grammar, own-pflag, cobra) | Lines     | Share  |
| ------------------------------------- | --------- | ------ |
| all agree                             | 1,165,897 | 58.3 % |
| cobra alone differs                   | 760,413   | 38.0 % |
| own-pflag alone differs               | 33,192    | 1.7 %  |
| all three differ                      | 31,535    | 1.6 %  |
| grammar alone differs                 | 8,963     | 0.4 %  |

| Pair                                 | Compared  | Differ  | semantic | acceptance | report  |
| ------------------------------------ | --------- | ------- | -------- | ---------- | ------- |
| grammar~pflag                        | 2,000,000 | 73,690  | 100      | 2,763      | 70,827  |
| grammar~plainpflag (leaf lines)      | 543,136   | 67,477  | 44       | 11,735     | 55,698  |
| grammar~stdflag (ordered leaf lines) | 324,524   | 5,371   | 0        | 2,734      | 2,637   |
| grammar~cobra                        | 2,000,000 | 800,911 | 2,069    | 328,601    | 470,241 |
| pflag~cobra                          | 2,000,000 | 825,140 | 1,980    | 326,672    | 496,488 |

Tab, 1,000,000 lines: all agree 651,139; cobra alone differs 347,849; grammar alone 510;
own-pflag alone 128; all three 374. grammar~pflag differ 1,012; grammar~cobra 348,733.

Reading: the flag reader is not where cobra's behaviour comes from. own-pflag (pflag inside the
own dispatcher) and own-grammar differ on 3.7 % of lines, all explained below; own-pflag and
cobra (same pflag, cobra's walk) differ on 41 %. "Cobra's knowledge" in these lines is its
command walk and its help handling, not pflag.

## 3. The bucket table

Classes: **decided** (a decision says so), **unwanted** (pflag/cobra behaviour nobody would
want; why given), **harness** (an adapter's own code, not the parser under test), **layer**
(the kit's `Exec`, i.e. 001's builder), **report** (both refuse; only which word the error
names differs), **bug** (own-grammar), **undecided** (a question, section 7).

### Run (delivered own-grammar; lines in each pair, ≈ for cobra pairs)

| #   | Cause                                                                                                                                                      | Class                                                                                      | g~pflag | g~plain | g~std | g~cobra ≈ | pflag~cobra ≈ | Smallest line                                                                          |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------- | ------- | ----- | --------- | ------------- | -------------------------------------------------------------------------------------- |
| R1  | Attached value or grouped shorts (`-ojson`, `-hc`, `-c-`, `-output` = `-o utput`): own refuses, pflag reads a value or a group                             | decided D11                                                                                | 35,196  | 36,189  |       | 177,780   | 188,600       | `nodes list -oj` → own unknown flag, pflag `-o j`                                      |
| R2  | `-h` with a mistake: own reports the error, cobra shows help                                                                                               | decided D19                                                                                |         |         |       | 191,420   | 197,340       | `x -h`, `- -h` → own unknown command, cobra help                                       |
| R3  | Cobra takes a leaf's own flags before or between command words                                                                                             | decided D3                                                                                 |         |         |       | 4,800     | 5,020         | `--sort x nodes list` → own unknown flag, cobra runs with sort=x                       |
| R4  | pflag reads `-o=` as `-o` with value `=`, and `-h=` as `-h` plus unknown shorthand `=`                                                                     | unwanted: a user typing `-o=` means empty, as `--output=` does                             | 5,688   | 2,030   |       | 38,380    | 31,920        | `-o= version` → own output `""`, pflag/cobra output `"="` (semantic)                   |
| R5  | Cobra's command search skips `-`, `""` and flag-like words                                                                                                 | unwanted: `nodes - list` runs `list` with positional `-`; `"" nodes` reports under `nodes` |         |         |       | 44,520    | 45,100        | `- api` → own unknown command `-` at root, cobra at `api`                              |
| R6  | Cobra's command search takes the word after an unknown flag as its value                                                                                   | unwanted: `nodes --version routes -h` shows help for `nodes`                               |         |         |       | 200       | 240           | `--version api keys -h`                                                                |
| R7  | Cobra's command search reads an inherited flag's value as a command word                                                                                   | unwanted                                                                                   |         |         |       |           | 20            | `--version api --config keys --config --help` → cobra help for `api keys`              |
| R8  | Same wrong word, spelled differently: pflag names one letter of a group (`-12` → `-1`, `-last-se` → `-l`) or prints a byte as a rune (`-\xc3`, `-ñ` → `Ã`) | report (the rune one is unwanted: pflag's message shows a character the user never typed)  | 5,273   | 29,258  |       | 47,140    | 56,900        | `-ñ` → own `ñ`, pflag `Ã`                                                              |
| R9  | Two mistakes on the line, each side names a different one first                                                                                            | report                                                                                     |         |         |       | 38,800    | 42,640        | `"" -,`                                                                                |
| R10 | Cobra adapter does not map pflag's `InvalidSyntaxError` (`--=`, `---x`)                                                                                    | harness                                                                                    |         |         |       | 95,840    | 92,920        | `---`                                                                                  |
| R11 | Cobra adapter: unknown flags at a group go to its args (for D5), so the command is named instead of the flag                                               | harness                                                                                    |         |         |       | 67,740    | 63,620        | `--name= x`                                                                            |
| R12 | Cobra adapter: `--help=`/`--help=x` make cobra print "flag declared as non-bool. Please correct your code" to **stdout**                                   | harness (cobra reads help back through `Value.String`)                                     |         |         |       | 23,440    | 23,400        | `-h=x`                                                                                 |
| R13 | own-pflag's pre-scan refuses a later single-dash word before pflag reaches an earlier mistake                                                              | harness                                                                                    | 23,139  |         |       |           |               | `--force -last-se`                                                                     |
| R14 | own-pflag's pre-scan skips words with `=`: `-oname=` reaches pflag as `-o` with value `name=`                                                              | harness (a hole in its D11 workaround)                                                     | 4,394   |         |       |           |               | `-cname=` → own unknown flag, own-pflag runs with config `name=`                       |
| R15 | `--help=1` / `-h=T` runs the command: `Exec` looks for the text `true` before it parses the bool                                                           | layer (L1)                                                                                 |         |         |       | 2,700     | 3,360         | `nodes list -h=1` runs; plain pflag too; cobra shows help                              |
| R16 | `Exec` lets `-h` win over a root-only flag on a group                                                                                                      | layer (L2): D19 says the error wins                                                        |         |         |       | 520       | 640           | `api --version -h` → help; cobra unknown flag                                          |
| R17 | Own drops flags read before a group word when the line ends at a group                                                                                     | **bug B1**                                                                                 |         |         |       | 2,780     | 2,900         | `--version nodes` → own help, cobra unknown flag `--version`                           |
| R18 | `--` before the command is complete: own says unknown command `--`; cobra drops it and reads on                                                            | **undecided** (Q1)                                                                         |         |         |       | 65,040    | 66,700        | `--` → own unknown command, cobra help; `nodes -- list` → cobra unknown command `list` |
| R19 | Go's `flag`: `--h` is `-h`, `-help` is `--help` (one namespace)                                                                                            | **undecided** (referee Q4)                                                                 |         |         | 5,371 |           |               | `serve --c` → own unknown flag, `flag` missing value for `-c`                          |

Semantic differences (both accept, different result) come only from R4 (`-o=`), R15 (`-h=1`),
R6 and R7. Every acceptance difference is R1–R4, R12, R14–R18.

### Tab (delivered own-grammar)

| #   | Cause                                                                                                                                                              | Class                                               | g~pflag | g~cobra ≈                | pflag~cobra ≈ | Smallest line                                                       |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------- | ------- | ------------------------ | ------------- | ------------------------------------------------------------------- |
| T1  | A refused word earlier on the line: cobra offers files (its parse error returns the Default directive) or skips the word; own completes from the last good command | **undecided** (Q2)                                  |         | 168,380                  | 169,160       | `-1 <Tab>` → own root commands, cobra files                         |
| T2  | A flag value with no value list (`--config <Tab>`, `--name <Tab>`): cobra offers files, own nothing                                                                | **undecided** (Q3)                                  |         | 65,080                   | 65,620        | `-c=<Tab>`                                                          |
| T3  | Attached/grouped shorts earlier on the line: the two complete from different places                                                                                | decided D11                                         |         | 32,260                   | 32,980        | `-hc <Tab>`                                                         |
| T4  | Cobra offers nothing once `-h`/`--help`/`--version` is on the line                                                                                                 | **undecided** (Q4)                                  |         | 20,860                   | 19,820        | `-h <Tab>`                                                          |
| T5  | Cobra also lists short forms (`-c -h -o`) for a lone `-`                                                                                                           | **undecided** (Q4)                                  |         | 12,680 (+ mixed rows)    | 13,320        | `api -<Tab>` → own `--help`, cobra `--help -h`                      |
| T6  | Cobra adapter: `-c`/`-o` are hidden persistent flags on root and groups                                                                                            | harness                                             |         | 13,820 (+ mixed)         | 13,740        | `--<Tab>` at root                                                   |
| T7  | pflag's `-x=` quirk earlier on the line                                                                                                                            | unwanted (as R4)                                    | 12      | 7,020                    | 5,720         | `-d= <Tab>`                                                         |
| T8  | Cobra completes subcommands after `--` at a group, which its own Run then refuses                                                                                  | unwanted: Tab offers a line Run rejects             |         | 4,460                    | 4,400         | `nodes -- de<Tab>` → `delete`; `nodes -- delete` is unknown command |
| T9  | Malformed flag under the cursor (`--=`, `-=`): cobra completes as if empty                                                                                         | unwanted                                            |         | 4,120                    | 4,240         | `-=<Tab>`                                                           |
| T10 | Cobra's Tab path reads a flag-like value of a value flag as flags; its Run reads it as the value (D20)                                                             | unwanted: Tab and Run disagree (cobra #2243 family) |         | 1,160                    | 1,060         | `-o -last-se api <Tab>` → cobra "api does not support flag e"       |
| T11 | Own reads the previous word as a flag without parsing: a flag-like value (`-c -o <Tab>`), a word after `--`, an empty word, a bare letter or `---x`                | **bug B2 (+ B5)**                                   | 1,000   | 2,540                    | 2,400         | `-c -o <Tab>` → own `json`; `nodes ls '' <Tab>` → own column names  |
| T12 | Own offers flags already on the line; cobra leaves them out                                                                                                        | **bug B4** (D15: each flag once)                    |         | 4,820 (incl. mixed rows) | 4,700         | `serve -h --<Tab>` → own offers `--help` again                      |
| T13 | Cobra adapter's `#2243` workaround does not reach the root's persistent `-o`                                                                                       | harness                                             |         | 520                      | 540           | `-o -<Tab>`                                                         |
| T14 | Cobra adapter hides `--filter` once given (its Value type is not a slice); D6 lets it repeat                                                                       | harness                                             |         | 160                      | 60            | `nodes ls --filter= --<Tab>`                                        |
| T15 | Cobra adapter completes a positional's values as a comma list                                                                                                      | harness                                             |         | 40                       | 40            | `completion a,<Tab>` → `a,bash`                                     |

"Mixed rows": a shrunk line can carry two causes (`-<Tab>` at the root differs by T5 and T6 at
once); those rows are counted under each cause they name.

### Headline

|                        | Run                       | Tab                   |
| ---------------------- | ------------------------- | --------------------- |
| Causes                 | 19                        | 15                    |
| decided                | 3 (D3, D11, D19)          | 1 (D11)               |
| unwanted (pflag/cobra) | 4 (+ the rune half of R8) | 4                     |
| harness (adapters)     | 5                         | 4                     |
| layer (kit `Exec`)     | 2                         | 0                     |
| report only            | 2                         | 0                     |
| **bug in own-grammar** | **1**                     | **2 buckets, 3 bugs** |
| **undecided**          | **2**                     | **4**                 |

## 4. Bugs and fixes (own-grammar), tried in `spikes/diff/ownfix`

| Bug | What                                                                                                                                                                                                                                                                                | Found by                                                                                              | Fix                                                                                                              |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| B1  | `walk` returns only the last level's flags when the line ends at a group: `--version nodes` and `-h nodes --version` lose flags; `--version nodes` shows help instead of "unknown flag" (cobra)                                                                                     | differential (R17), FuzzRun group property (seed corpus, 0 s)                                         | at the group, parse every root flag read on the way down: `vals, _, _ := parse(root.Flags, pre, false)` (+2, −1) |
| B2  | `Complete` decides "the previous word wants a value" with `byTyped(rest[n-1])` instead of parsing: a value that looks like a flag (`-c -o <Tab>` offers `json`, though D20 makes `-o` the value of `-c`), a word after `--` (`policy set -- --output <Tab>`), and `--x=` after `--` | differential (T11), FuzzTab (1 s)                                                                     | parse the words; complete a value only on a `MissingValue` error for the last word (+9, −4)                      |
| B4  | Tab offers flags already given; D15 then refuses the line                                                                                                                                                                                                                           | differential (T12)                                                                                    | collect the flags given (root flags on the way down too) and skip them, except `Strings` (`--filter`) (+5)       |
| B5  | `byTyped` trims any number of dashes and matches an empty short: `---tags=<Tab>` completes values that `parse` then refuses; `''` and a bare `o` are taken for `-o`/`--columns`                                                                                                     | FuzzTab (< 1 s; `-c o <Tab>` offers `json`, `auth keys create ---tags=<Tab>` offers `---tags=tag:ci`) | exact match: `typed == "--"+f.Name \|\| f.Short != "" && typed == "-"+f.Short` (1 changed)                       |

Total: 23 lines added or changed, 10 removed in `adapter.go` (comments included). Kit v2 on the
fixed copy: same as delivered (154/155 MUST, the one skip is a shell not on `PATH`; STRETCH 11/12).

After the fixes (same seeds):

- Run: R17 (B1) disappears from grammar~cobra (2,780 → 0). It stays on pairs with own-pflag,
  which shares the dispatcher and was not fixed. R16 (layer) grows 520 → 680, because B1 used
  to hide some of those lines.
- Tab: T11 (B2/B5) and T12 (B4) disappear from grammar~cobra (≈ 7,360 → 0) and appear on
  grammar~pflag instead (own-pflag still has them). Remaining grammar~cobra buckets: the
  undecided, decided, unwanted and harness ones above.

Layer findings (not the parser; 001's builder should not copy them):

- L1: `Exec` treats help as given only when a value is the literal `true`, then accepts
  `strconv.ParseBool`'s set for every bool, so `nodes list -h=1` runs the command. Fix in the
  builder: parse the bool first, then decide help.
- L2: `Exec` checks help before "flag not on this command", so `api --version -h` shows help
  where D19 wants the error.
- Both rest on Q5 (which bool spellings D9 accepts).

## 5. Where own-pflag and cobra differ (cobra's walk vs pflag)

All of pflag~cobra's buckets except R13/R14 (own-pflag's workaround) are cobra's: R2 (help
before errors), R3 (leaf flags anywhere: cobra's `Find` strips flag-like words and parses the
whole line with the leaf's flag set), R5–R7 (`stripFlags` guesses which flags take values; it
does not know `-` is a positional, nor flags defined only on an ancestor), R11 and R12 (adapter
code around cobra), and in Tab T1, T4, T5, T8–T10. pflag itself adds only R4 and R8. In other
words, the "knowledge" an own parser would forgo by not using cobra is mostly behaviour the
decisions (D3, D19) already refuse, plus four cobra walk quirks nobody would want, plus three
Tab conventions worth taking (B4 adopted; Q2–Q4 open).

## 6. Fuzzing

`fuzz_test.go`, Go native fuzzing. `FUZZ_OWN=delivered` selects the delivered parser, the default is `ownfix`. argv is the fuzz string split on NUL (a real argv word cannot
hold NUL; NUL inside words is covered by the generator). Seed corpus: 300 generator lines per
target plus a few hand lines. Every call is timed (> 1 s fails).

| Target   | Properties                                                                                                                                                                                                                                                                                                                                              |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FuzzRun  | no panic, no hang; outcome and Call identical on a second run; outcome ≤ 6 × input + 1 KiB; the Call survives a round trip through its canonical line (`path --name=value… -- args`); appending `--` to a line that reached a leaf changes nothing; at a group, moving the flags behind the command words changes nothing                               |
| FuzzLeaf | for a random leaf: a string flag's value comes back byte for byte in all four spellings (`--x v`, `--x=v`, `-s v`, `-s=v`), whatever it looks like (D20); after `--` every word is a positional, byte for byte, and no flag is set; two random placements of the same flags (both spellings, repeats included) among the positionals give the same Call |
| FuzzTab  | no panic, no hang, deterministic, ≤ 64 candidates; no candidate that Run then refuses as an unknown flag or command because of that candidate (`--x=` candidates checked with the prefix the scripts put back)                                                                                                                                          |

| Run       | Target                                 | Time         | Executions | Result                                                                           |
| --------- | -------------------------------------- | ------------ | ---------- | -------------------------------------------------------------------------------- |
| delivered | FuzzRun (without the group property)   | 6 min        | 43.1 M     | pass                                                                             |
| delivered | FuzzRun (with the group property)      | —            | —          | fails on seed 19 of the corpus: B1 (`-c 24h --version users --help`)             |
| delivered | FuzzLeaf                               | 6 min        | 15.7 M     | pass                                                                             |
| delivered | FuzzTab                                | < 1 s, twice | —          | fails: B2 (`nodes list '' -<Tab>` offers `-id`), B5 (`-c o <Tab>` offers `json`) |
| fixed     | FuzzRun (with the group property)      | 6 min        | 37.0 M     | pass                                                                             |
| fixed     | FuzzLeaf                               | 6 min        | 11.6 M     | pass                                                                             |
| fixed     | FuzzTab (failing inputs kept as seeds) | 6 min        | 26.8 M     | pass                                                                             |

No panic and no hang was ever seen, on either copy. Properties that held on the delivered parser
in every run: determinism, bounded output, round trip, `--` at the end of a leaf line, values
byte for byte, `--` makes positionals, flag order among positionals. The `--` property at a
group does not hold by design today (`nodes` is help, `nodes --` unknown command: Q1), so the
target checks it only for leaf lines.

## 7. What Headscale would keep

| Piece                                                                                                                                                 | Lines                                                                                     | CI time                                                                   | Would have caught                                                                                                                                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The three fuzz targets as tests, with a checked-in seed corpus (`testdata/fuzz/…`: the generator's lines plus the four failing inputs in `findings/`) | ~200 (targets) + a ~60-line seed generator, or the seeds as files                         | `go test` replays the corpus in < 1 s; optional nightly `-fuzz` 3 × 5 min | B1 (seed corpus), B2 and B5 (first second of fuzzing); not B4 (no property says "do not offer a given flag" — add one: +5 lines)                                            |
| Differential test against a plain pflag `FlagSet` on leaf lines, test-only (pflag is in go.mod today)                                                 | generator ~220 + oracle ~70 + an allow-list of the expected causes (R1, R4, R8) ~60 ≈ 350 | 100 k lines ≈ 5 s                                                         | none of the four bugs (they are in dispatch and Tab, which pflag does not do); it guards the flag reader against future drift, e.g. a value that stops coming back verbatim |
| Differential against cobra                                                                                                                            | —                                                                                         | —                                                                         | not worth keeping: 38 % of lines differ by design or by cobra quirks; the allow-list would be most of `classify.go` (~360 lines) and would encode cobra's walk              |
| Shell-level Tab (D21, referee's pty harness)                                                                                                          | (referee)                                                                                 | < 2 min                                                                   | the protocol and script bugs no in-process test sees                                                                                                                        |

Recommendation if the own parser is chosen: keep the fuzz targets and the corpus (cheapest,
caught three of four bugs, guards the D20/`--`/byte-for-byte promises), add the B4 property,
and skip the standing differential tests. Re-run `spikes/diff` once against the real tree when
the specs exist; it is a one-off cost of minutes.

## 8. Limits

- 12 leaves, 3 levels, 13 flags. The real tree has ~60 commands; collisions (a value equal to a
  command name, a short meaning one thing everywhere) grow with it. Re-run on the real tree.
- The generator decides what is tested. It is biased to near-valid lines; it never builds lines
  longer than ~20 words except by random noise; it has no knowledge of what users really type.
- Outcomes are compared through the kit's layer, so a layer bug looks the same in every adapter
  that hands help to the layer (L1 shows in own-grammar, own-pflag and plain pflag alike).
- The classifier is code too: a cause predicate can be too wide. Every bucket's smallest line
  and eight samples were read by hand (`results/final/*.json`), and the fixes were confirmed by
  the bucket going away, not by the classifier saying so.
- In-process only: shells, terminals, escaping and the completion scripts are out of scope here.
- Cobra pairs are sampled (5 %) for classification; their totals are exact, bucket sizes ≈.

## Open questions for the maintainer

1. **`--` before the command is complete** (R18; ~3 % of generated lines). (a) Keep: `--`
   where a command word is expected is an unknown command `--`; `headscale nodes --` is an
   error, not help. 0 lines; the fuzz property "`--` at the end changes nothing" stays
   leaf-only. (b) Ignore a `--` that stands before the leaf (cobra: `nodes --` is help); then
   `nodes -- list` must still say what cobra does not (unknown command `list`, or run `list`?),
   so (b) needs one more decision. ~3 lines.
1. **Tab after a refused word** (T1, the largest Tab bucket). (a) Offer nothing: Tab after a
   mistake cannot lead to a valid line. 1 line (`return nil, NoFileComp` on a parse error).
   (b) Keep completing from the last good command (own today); helps when the mistake is a typo
   the user will fix, costs nothing. Cobra's third option (files) is wrong in both views.
1. **Flag values with no value list** (T2: `--config <Tab>`). (a) Offer files when the spec
   marks the field as a path (`complete:"file"` on a flag, as positionals already have): a spec
   tag and ~3 lines. (b) Offer nothing (own today) and let the shell's fallback do nothing.
1. **Tab conventions from cobra** (T4, T5). (a) Take them: nothing after `-h`/`--help`/
   `--version`; list `-c -h -o` too when the word is a lone `-`. ~6 lines, and the D21 shell
   list grows by two lines. (b) Keep own: long names only, completion continues after `-h`.
   0 lines; arguably clearer lists.
1. **Which bool spellings does D9 accept?** The kit's layer uses `strconv.ParseBool`, so
   `--force=1`, `=t`, `=T`, `=TRUE`, `=True` (and the false forms) are accepted by every
   adapter, and L1 hides inside that. (a) Only `true`/`false`, as D9 is written: one comparison
   in the builder; `--force=1` becomes a bad value. (b) `ParseBool`'s set, documented: 0 lines,
   and fix L1 by parsing before deciding help (1 line).
1. **`-output`, `--o`, `--h`, `-help`** (R19; referee question 4, still open). Go's `flag`
   accepts all four; pflag reads `-output` as `-o utput`; own refuses all. (a) Refuse (own
   today), D11 extended: 0 lines. (b) Accept the `flag`-package spellings: a second lookup per
   word, ~5 lines, and two spellings to document and test.
