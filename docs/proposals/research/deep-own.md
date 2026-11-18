# Deep research: "our own parser" (no framework)

Date: 2026-11-17. Candidate name: `own`. Probe: `spikes/probe-own/` (module `probe-own`, Go 1.27.3,
pflag v1.1.0). Sources cloned under `spikes/src/` (cobra adbc881 = v1.10.2+7, pflag 44b0d47 =
v1.1.0+7, tailscale f3bc40b67, coder/serpent v0.15.0).

## Verdict (Phase A)

Owning the parser is cheap; owning completion is the real cost, and it is the same for all three
variants. Measured in the probe: dispatcher 46 lines, own grammar parser 91 lines (incl. typed
errors), pflag glue 64 lines, `__complete` answerer 111 lines, cobra's four scripts 1,011 lines
copied verbatim. Both parsers pass all 45 contract cases of the probe table; stdlib `flag` cannot
(no interspersed flags, untyped errors, no short/long pairs).

Carry into the spike: **variant 2 (own grammar) first, variant 1 (pflag) as the close second**,
both with cobra's scripts copied verbatim from cobra HEAD and patched where they break us. The
decisions (D6, D9, D11) make Headscale's grammar *smaller* than pflag's, so with pflag we pay to
switch things off (`-ojson`, grouped shorts, `-h=true`, invisible repeated bools); with our own
grammar we only write what is decided. Variant 3 (stdlib `flag`) is out.

Two surprises that matter for every candidate that uses cobra's scripts (cobra, own, and anyone
copying them): (1) cobra's **fish script breaks on a single NoSpace completion that starts with
`-`** (`string split` without `--`, unchanged since 2021): `headscale nodes list --sort -l<Tab>`
and `--columns=id,na<Tab>` print a fish error instead of completing. (2) cobra's **bash script
escapes commas**: `--columns id,na<Tab>` becomes `id\,name` (bash `printf %q`, cobra ≥ v1.9).
Both reproduced in real shells, see "Completion".

______________________________________________________________________

## 1. Parsing, item by item

Probe: `spikes/probe-own/parse_test.go` runs every argv through `Dispatch` with both parsers
(`OwnParse`, `PflagParse`) and asserts one expected rendering. 45 asserted cases pass on both; 13
edge cases are printed side by side. Run: `go test -v -run TestParsers .` in the probe.

Dispatcher design (shared by all variants, `dispatch.go`): walk group levels reading only the
root's flags (`-c`, `-o`, `-h`) in "stop at first positional" mode; the next word must be a child
name or alias, else `UnknownCommandError{Path, Word}`. At the leaf, the flag tokens read before the
leaf are handed to the leaf's parser again together with the rest, so a leaf without `--output`
refuses `-o` (D3) and repeats stay visible. A group with nothing after it returns the group node
(D10: our help).

| Contract item / decision                                                 | Own grammar (v2)                                                       | pflag + dispatcher (v1)                                                                                                                          | stdlib `flag` (v3)                                                                                                                 |
| ------------------------------------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------- |
| Command at a path, aliases, group vs leaf, from data                     | our code (dispatcher 46 lines)                                         | same dispatcher                                                                                                                                  | same dispatcher                                                                                                                    |
| bool / string / repeatable string                                        | our code                                                               | native (`BoolP`, a 4-line `Value` that records every `Set`)                                                                                      | native, but long and short are two flags                                                                                           |
| `--flag=value`, `--flag value`                                           | our code                                                               | native                                                                                                                                           | native (also `-flag value`: looser)                                                                                                |
| `-o json`, `-o=json` (D11)                                               | our code                                                               | native                                                                                                                                           | native                                                                                                                             |
| `-ojson` refused (D11)                                                   | refused by not writing it; 3 lines give it its own error               | **accepted natively; refusing needs an argv pre-scan (WA, ~6 lines)**, no setting                                                                | refused (`flag provided but not defined: -ojson`)                                                                                  |
| "given" and "given twice"                                                | native (every value recorded)                                          | strings: our `Value`; bools: last value only, repeat invisible                                                                                   | `Visit`; repeats invisible unless own `Value`                                                                                      |
| Flags interspersed with positionals                                      | our code                                                               | native (`SetInterspersed(true)`, default)                                                                                                        | **no**: stops at first positional (`12 --force` → args `["12","--force"]`); emulation by re-calling `Parse` loses `--` information |
| `--` ends flags, rest positional                                         | our code                                                               | native (`ArgsLenAtDash`)                                                                                                                         | native                                                                                                                             |
| Values starting with `-` (`--sort -last-seen`, `--name -h`, `--name --`) | taken verbatim                                                         | taken verbatim                                                                                                                                   | taken verbatim                                                                                                                     |
| `-` alone, `""` as positionals                                           | yes                                                                    | yes                                                                                                                                              | yes                                                                                                                                |
| No abbreviations (`--forc`)                                              | yes                                                                    | yes                                                                                                                                              | yes                                                                                                                                |
| Typed errors with flag and path (D4)                                     | native: `UnknownCommand/UnknownFlag/MissingValue/BadValue{Path, Flag}` | `pflag.NotExistError`, `ValueRequiredError`, `InvalidValueError`, `InvalidSyntaxError` with getters (since v1.0.7, 2025-07-16; mapping 25 lines) | **no**: `*errors.errorString`, text says `-forc` even when `--forc` was typed; prints usage to `Output()` unless discarded         |
| Global flags before/after subcommand (D3)                                | dispatcher                                                             | dispatcher                                                                                                                                       | dispatcher (but leaf parse still not interspersed)                                                                                 |
| Bool `--force=true/false` (D9)                                           | 6 lines (`strconv.ParseBool`)                                          | native                                                                                                                                           | native                                                                                                                             |
| `--version` on root (D7)                                                 | one root flag                                                          | one root flag                                                                                                                                    | one root flag                                                                                                                      |
| No `help` command (D8), help on group (D10)                              | nothing to switch off                                                  | nothing to switch off                                                                                                                            | nothing to switch off                                                                                                              |
| Exit code, `os.Exit`, printing                                           | none of it exists                                                      | `ContinueOnError` + `SetOutput(io.Discard)`; `ExitOnError` paths never reached                                                                   | same; must discard output                                                                                                          |
| Package-level state                                                      | none                                                                   | none (`NewFlagSet` per call; `CommandLine` untouched)                                                                                            | none if `NewFlagSet`                                                                                                               |

Edge cases (printed, `-v`):

| argv                                   | own                       | pflag v1.1.0                                                                                         |
| -------------------------------------- | ------------------------- | ---------------------------------------------------------------------------------------------------- |
| `version -ojson`                       | unknown-flag `-ojson`     | accepted, output=json                                                                                |
| `nodes delete 12 -hf` (grouped shorts) | bad-value `-h="f"`        | unknown-flag `-f` (grouping supported)                                                               |
| `nodes delete -ø`                      | unknown-flag `-ø`         | unknown-flag **`-Ã`**: pflag slices the shorthand by byte; error field is mojibake                   |
| `nodes delete 12 -h=true`              | bad-value                 | accepted                                                                                             |
| `nodes delete 12 --force --force`      | `["true","true"]`         | `["true"]` (repeat invisible)                                                                        |
| `nodes delete ---force`                | unknown-flag `---force`   | unknown-flag (`InvalidSyntaxError`)                                                                  |
| `nodes delete -5`                      | unknown-flag `-5`         | unknown-flag `-5`                                                                                    |
| `nodes --force delete 12`              | unknown-flag at `[nodes]` | same (only globals before the leaf; cobra today accepts because `--force` is a root persistent flag) |
| `-- nodes list`                        | unknown-command `"--"`    | same                                                                                                 |
| `--force=`                             | bad-value `""`            | bad-value `""`                                                                                       |
| Unicode values (`--name tést -o jsön`) | verbatim                  | verbatim                                                                                             |

What the strict grammar does not do unless added, and the cost (own variant):

| Habit                           | Status                                                   | Cost to add                            |
| ------------------------------- | -------------------------------------------------------- | -------------------------------------- |
| `-ojson`                        | refused (D11 target)                                     | 2 lines to accept                      |
| `-o=json`                       | supported (D11)                                          | 3 lines (in)                           |
| grouped shorts `-hf`            | refused: only `-h` is a bool short, nothing to group     | ~8 lines                               |
| `--force=false`                 | supported (D9)                                           | 6 lines (in)                           |
| bool then a word `--force 12`   | correct by construction (bools never take the next word) | 0                                      |
| `-` alone                       | positional                                               | 0                                      |
| negative numbers as positionals | `-5` is an unknown flag (same as pflag); `-- -5` works   | ~3 lines; no numeric positionals exist |
| Unicode short flag              | decoded as a rune so the error shows `-ø`                | 2 lines (in)                           |
| empty argv element `""`         | positional, or a flag value                              | 0                                      |
| abbreviations                   | refused                                                  | not wanted                             |

Probe line counts (non-blank, non-comment): `parse.go` 91 (55 of it the parser function, rest
error types), `pflagparse.go` 64, `dispatch.go` 46, `complete.go` 111, `tree.go` 103 (test tree,
not product code), `parse_test.go` 118, `complete_test.go` ~45.

## 2. Completion (D1, D2): the real cost

The answerer (`complete.go`, 111 lines) speaks cobra's `__complete` protocol: lines
`word\tdescription`, then `:<directive>` (bits: 1 error, 2 no space, 4 no file completion, 8
filter extension, 16 dirs, 32 keep order). It walks the same tree, reads no config and no network,
and handles: command words with descriptions, flags per command, values per flag (`json` for
`-o`, column names), `--flag=val` (answers the bare value, the scripts re-add the prefix), comma
lists (`id,na` → `id,name` with NoSpace), `+`/`-` prefixes, files (directive 0), fixed words
(`completion f` → `fish`). `complete_test.go` asserts 19 cases. Keeping the names `__complete` and
`__completeNoDesc` means scripts users saved from today's cobra build keep working.

Real shells (pty driver `spikes/probe-own/shelltest/ptytab.py` + `run.sh`, bash 5.3 with
bash-completion 2.17, fish 4.9.3, with cobra's unpatched scripts; zsh 5.9 is covered in Phase B):

| Line + Tab                   | bash (cobra v2 script)                      | fish (cobra HEAD script)                                          |
| ---------------------------- | ------------------------------------------- | ----------------------------------------------------------------- |
| `headscale no`               | `nodes `                                    | `nodes `                                                          |
| `headscale -c x no`          | `-c x nodes `                               | `-c x nodes `                                                     |
| `nodes list --columns id,na` | **`id\,name`** (comma escaped, still works) | `id,name`                                                         |
| `nodes list --columns=id,na` | `--columns=id\,name`                        | **fish error: `string split: --columns=id,name: unknown option`** |
| `nodes list --sort -l`       | `-last-seen`                                | **fish error: `string split: -last-seen: unknown option`**        |
| `nodes list --filter na`     | `name` (no space)                           | `name`                                                            |
| `nodes list -o `             | `json `                                     | `json `                                                           |
| `policy set pol`             | `policy.` (files)                           | `policy.` (files)                                                 |
| `nodes rm --f`               | `--force `                                  | `--force `                                                        |

The fish failure is in cobra's own template (`fish_completions.go` line 223, `set -l split (string split --max 1 \t $__%[1]s_comp_results[1])`, last touched c2e21bd 2021-05-03): a single NoSpace
completion that begins with `-` is read as an option by `string split`. Any cobra program that
completes `--flag=<value>` with NoSpace on fish hits it; no cobra issue found
(`gh search issues --repo spf13/cobra "fish string split"`: none). Fix is `string split --max 1 -- \t …`. The bash comma escaping comes from 09d5664 (2025-01-23, "whitespace escape logic",
in v1.9.0): bash's `printf %q` escapes `,` (brace expansion). Both affect today's Headscale on
cobra v1.10.2 as soon as it completes comma lists.

Where scripts can come from:

| Source                                                          | Lines we hold                                                     | Licence                            | Currency                                                                                                                                                                               | Notes                                                                                                                 |
| --------------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Copy cobra HEAD verbatim (probe `cobrascripts/`)                | 1,011 template + 43 shim; bash 439, zsh 224, fish 251, pwsh 285   | Apache-2.0                         | we re-sync by diff                                                                                                                                                                     | can patch the two bugs above today                                                                                    |
| Import cobra only for `GenBashCompletionV2` etc.                | ~10                                                               | Apache-2.0 (already shipped today) | cobra releases: last v1.10.2 2025-12-03; fish quoting fix 61968e8 (2025-12-10) and bash perf 10d4b48 still unreleased after 11 months                                                  | keeps a cobra import in the adapter; no way to patch                                                                  |
| `tailscale.com/tempfork/spf13/cobra` (module already in go.mod) | ~10                                                               | Apache-2.0                         | **frozen at 2024-02-29** (82394deb); only gzip blobs regenerated for Go 1.27 (faa10dd); lacks 09d5664, 4ba5566 (bash nounset), 61968e8 (fish quoting), 5a138f1 (pwsh constrained mode) | not a public API of tailscale.com; can vanish in any bump                                                             |
| Own thin scripts, go-task style                                 | ~80 per shell + ~540 lines of shell smoke harness (go-task #2897) | ours (go-task's are MIT)           | ours                                                                                                                                                                                   | no bash descriptions; go-task passes args as an array (no `eval`, unlike cobra)                                       |
| coder/serpent style minimal scripts                             | 7–15 per shell                                                    | CC0                                | ours                                                                                                                                                                                   | no descriptions, no NoSpace, no file directive; bash `COMP_WORDS` slicing breaks on `=`/`:` (`--filter=owner=tag:ci`) |
| carapace-spec                                                   | —                                                                 | MIT                                | —                                                                                                                                                                                      | needs cobra + carapace or a user-installed carapace binary; not parser-independent                                    |

Licence (copy): Apache-2.0 §4 asks for (a) a copy of the licence to recipients, (b) a notice in
modified files, (c) kept copyright/attribution notices; (d) NOTICE only if upstream has one, and
cobra has none (`ls NOTICE*` in cobra: none). So: keep the Apache header on the copied file(s),
put cobra's `LICENSE.txt` next to them (Tailscale does both in `tempfork/spf13/cobra`), mark any
patched line. Mixing Apache-2.0 files into a BSD-3-Clause tree is fine; the files stay Apache.
Note that Headscale already redistributes Apache-2.0 cobra code in every binary today, and
`.goreleaser.yml` ships only Headscale's own `LICENSE`, so third-party notices are an existing gap,
not a new one.

What the copy saves over importing cobra for scripts only: the cobra import (87 KB of symbols,
the module stays in go.sum anyway through tailscale.com and huma), and dependence on cobra's
release cadence. It costs 1,054 lines held in tree and a re-sync job. Given (1) and (2) above, and
cobra's 11-month release gap, the copy is the better trade for a project that must not wait.

Upkeep we would inherit (cobra commits to the script files, 2023-11-17 → 2026-11-17):

| File                        | Commits | Of those, user-visible fixes for bash/zsh/fish                                                                                                   |
| --------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bash_completionsV2.go`     | 4       | 09d5664 whitespace escaping (+56/−19), 4ba5566 nounset (1 line), 10d4b48 perf (2 lines, unreleased); 41b26ec is the ActiveHelp feature (+63/−12) |
| `zsh_completions.go`        | 0       | —                                                                                                                                                |
| `fish_completions.go`       | 1       | 61968e8 quote args (2 lines, unreleased)                                                                                                         |
| `powershell_completions.go` | 2       | 5a138f1 constrained mode (+30/−5); 6b5f577 lint                                                                                                  |

So about one or two small script changes a year for the three required shells (2021–2022 had
~30, when bash v2 was new; it has settled). Re-sync is a `diff` of four template strings. The work
that does not shrink is testing: cobra itself does not test the scripts in CI; maintainers use a
separate harness (marckhouzam/cobra-completion-testing, UNVERIFIED current state). We would need
our own per-shell smoke test (go-task added one: ~540 lines incl. wrappers, CI job on Ubuntu and
macOS).

PowerShell (D2 stretch): the copied script works with our answerer by protocol; not tested (no
pwsh in probe). 285 lines more to hold, or drop it.

## 3. Errors (D4)

Own grammar: four typed errors with `Path` and the flag as typed (`parse.go`). pflag v1.1.0:
`NotExistError` (`GetSpecifiedName`, `GetSpecifiedShortnames`), `ValueRequiredError`,
`InvalidValueError` (`GetFlag`, `GetValue`, `Unwrap`), `InvalidSyntaxError`; present since v1.0.7
(8d77158, 2025-04-21) — Headscale's current v1.0.10 has them. v1.1.0 (tag 2026-10-29, GitHub
release 2026-11-06) adds friendly text for typed `Set` errors (#269), `UnknownFlagsHandling`, and
stops printing usage to a hard-coded `os.Stderr` (b595556). The path comes from our dispatcher in
both variants. stdlib `flag`: strings only.

## 4. Staying out of the way

Nothing to switch off in variants 2 and 3: there is no help, no `help` command, no
`--version`, no completion command, no suggestions, no env binding, no sorting, no `os.Exit`
unless written. pflag: `ContinueOnError`, `SetOutput(io.Discard)`, `Usage = func(){}`; its
`CommandLine` global is never touched; `-h` returns `ErrHelp` only if `help` is undefined (we define
it). pflag features we must not trip: grouped shorts, attached short values (`-ojson`, D11),
`NoOptDefVal`, deprecation warnings (printed to `Output()`), `SetNormalizeFunc`.

## 5. Global flags before and after (D3)

Done in the dispatcher (above). `-o json check config` and `check config -o json` both end in
unknown-flag `-o` at `[check config]` in the probe. Leaf flags before the leaf
(`nodes --force delete 12`) are refused; cobra accepts some such forms today through persistent
flags. Not a decision item; recorded as a behaviour change.

## 6. Risk

There is no upstream to die and none to fix bugs.

| Part                                             | Lines (own code)                              | Who                                                                                                                                                        |
| ------------------------------------------------ | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dispatcher (walk, aliases, globals, group help)  | ~50                                           | Headscale                                                                                                                                                  |
| Parser: own grammar / pflag glue                 | ~90 / ~65                                     | Headscale (pflag: spf13 org; 69 of the last-3-year commits by one maintainer, Tomas Aschan; 146 open issues+PRs; 2 releases in 2025–26 after a 2-year gap) |
| `__complete` answerer                            | ~110                                          | Headscale                                                                                                                                                  |
| Scripts                                          | ~1,050 copied (or ~10 with a cobra import)    | cobra upstream + our re-sync                                                                                                                               |
| Tests: argv table, completion table, shell smoke | ~120 + ~50 + ~150–500                         | Headscale                                                                                                                                                  |
| **Total in tree**                                | **~300 own + ~1,050 copied + ~300–700 tests** |                                                                                                                                                            |

Owner in practice: whoever owns `cmd/headscale/cli` (today one maintainer). The parser and
dispatcher are small enough to read in one sitting and fully table-tested; the scripts are not:
nobody on the project reads fish or PowerShell daily.

Worst realistic bugs:

- **Tab breaks in a user's shell.** Shown above: fish prints an error on Tab for `--sort -l`. A
  script error is visible on every Tab and survives until the user regenerates the script
  (nixpkgs regenerates at build time; dotfile users do not). Headscale already had this class:
  #839/#1012 (update notice inside the bash script), and Tailscale #12669 (log line inside the
  fish script, open and unanswered since 2024-07). Guard: the `__complete` path writes only the
  protocol to stdout; a CI job sources each script and completes a few lines per shell.
- **A flag read wrong in a destructive command.** The bad cases are a bool that swallows a word,
  a value flag that swallows the target, or `--force=false` read as true. Bools never take the
  next word in either parser; a value flag that takes the target leaves no target, and the
  argument count check (builder step 1) refuses before any call; `--force=false` is a table case.
  The prompt names the resolved target unless `--force` is given. So a parser bug turns into a
  usage error far more often than into a wrong delete — but only as long as the table cases exist;
  the safety is in the tests, not in a library's user base.
- **Drift from users' habits.** pflag syntax is what users have today; the own grammar is a strict
  subset (no grouped shorts, no `-ojson` per D11, no leaf flags before the leaf). Each is a
  changelog line.

Way out: the adapter is one file; moving from own to cobra/pflag later is the same size as any
other swap. Nothing outside the adapter would import our parser.

## 7. Evidence from others

| Project                 | What they did                                                                                                                                                                                                                                                                         | What it cost / what they said                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tailscale `tailscale`   | ffcli + `cmd/tailscale/cli/ffcomplete` (complete.go 160, internal/complete.go 271, tests 224) + cobra scripts copied into `tempfork/spf13/cobra` (82394deb, 2024-02-29, "approach is lifted from cobra", Fixes #3793)                                                                 | Scripts never re-synced in 2.7 years (only gzip regenerated, faa10dd 2026-08-21). ActiveHelp stripped. Glue uses package-level maps (`CompleteCmds`, `CompleteFlags`) and stdlib split rules (flags only before positionals). Three completion issues open with no maintainer reply: #12669 (fish, log line in script), #13446 (bash install path), #14952 (zsh `Tailscale` vs `tailscale`). Works, but nobody owns it. |
| Coder                   | cobra/viper → own `bigcli`/`clibase` on pflag (coder/coder#6347, 2023-03: "non-janky long-help formatting, doc generation, and YAML support"), extracted as coder/serpent (2024-03)                                                                                                   | Completion was dropped in the move: serpent#3 "coder completion sub-command no longer available" (2023-04-05), "This was intentionally lost during the clibase refactor", closed 2024-08-01 when serpent got its own minimal scripts (~16 months without completion). No move back to cobra.                                                                                                                            |
| go-task                 | pflag + own dispatcher; hand-written per-shell scripts (≈40 commits to `completion/` in 3 years, mostly zsh/fish fixes) → go-task/task#2897 (2026-09-28): one `task __complete` engine speaking cobra's protocol, thin scripts per shell, Go protocol tests + shell smoke tests in CI | "It's painful to maintain 4 (or more) different completion scripts, and it's also difficult to test them." Engine ~480 lines + 657 test lines + ~540 lines shell harness. No follow-up fixes or issues in the 7 weeks since.                                                                                                                                                                                            |
| micasa                  | kong → cobra (micasa-dev/micasa#785, 2026-03)                                                                                                                                                                                                                                         | replaced 170 lines of hand-written bash/zsh/fish scripts with cobra's                                                                                                                                                                                                                                                                                                                                                   |
| OpenTofu                | mitchellh/cli era                                                                                                                                                                                                                                                                     | hand-made help "tedious ... error prone" (RFC 20260807); completion via posener/complete, which they call unmaintained                                                                                                                                                                                                                                                                                                  |
| Temporal CLI            | commands.yaml → generated cobra code                                                                                                                                                                                                                                                  | stays on cobra; commands-as-data does not need leaving cobra                                                                                                                                                                                                                                                                                                                                                            |
| Go command, age, Nebula | stdlib `flag`                                                                                                                                                                                                                                                                         | single-dash, no interspersed flags, no completion; fine for their grammar, not for Headscale's                                                                                                                                                                                                                                                                                                                          |

No project found that went back from its own layer to a framework. The recorded pain is always
completion scripts (Coder lost completion, go-task rewrote theirs, Tailscale's copy is frozen,
micasa left hand-written scripts), never the parser.

## 8. Migration (from cobra v1.10.2)

- Users: pflag variant keeps today's syntax byte for byte except what decisions remove; own
  grammar additionally refuses grouped shorts and `-h=true`, and reports leaf flags placed before
  the leaf. Error wording is ours in all variants (D4).
- nixpkgs: `headscale completion bash|zsh|fish` keeps its name and output shape (cobra's scripts,
  same `__complete` command), so `installShellCompletion` keeps working; old saved scripts keep
  working because the protocol and command name are unchanged.
- Integration tests (128 calls): parsing is pflag-equivalent for every form they use (`--flag value`,
  `-o json`, `--output json`, interspersed); they change for the command renames of 001, not for
  the parser.

## Requirement table

| Requirement                                          | Own grammar                          | pflag variant                             | stdlib variant                                |
| ---------------------------------------------------- | ------------------------------------ | ----------------------------------------- | --------------------------------------------- |
| R01–R06 tree, aliases, hyphen names, same leaf names | our code (dispatcher ~50)            | our code                                  | our code                                      |
| R08–R09 old/reserved names unknown                   | native (not in tree)                 | native                                    | native                                        |
| R11–R13 raw positionals incl. `-`, `*`, `""`         | our code                             | native                                    | native                                        |
| R15 long forms                                       | our code                             | native                                    | native                                        |
| R16/D11 `-o json`, `-o=json`; `-ojson` refused       | our code (refusal free)              | native; refusal = WA ~6                   | native                                        |
| R17–R19 per-command flags, short letters             | our code                             | native                                    | two flags per short/long                      |
| R20 interspersed                                     | our code                             | native                                    | **no** (our re-parse loop, lossy around `--`) |
| R21–R22 values with `-`, `=`, `:`                    | our code                             | native                                    | native                                        |
| R23–R24 given / given empty                          | our code                             | native + 4-line `Value`                   | `Visit`                                       |
| R25/D9 bool forms                                    | our code (6)                         | native                                    | native                                        |
| R27/D6 repeat visible                                | our code                             | strings via `Value`; bools not            | own `Value`                                   |
| R31/D4 typed unknown-flag                            | our code                             | native (typed since v1.0.7) + 25-line map | **no** (strings)                              |
| R36–R38 no printing, no exit                         | native                               | setting                                   | setting                                       |
| R49/G26 no global state, parallel                    | native                               | native                                    | native                                        |
| R59/D1/D2 scripts                                    | copied cobra (1,011) or import       | same                                      | same                                          |
| R60 values per flag, comma lists                     | our code (answerer 111)              | same                                      | same                                          |
| R61 no server on Tab                                 | our code                             | same                                      | same                                          |
| R62 runtime callbacks later                          | our code (a func field per flag/arg) | same                                      | same                                          |
| G05 `--`                                             | our code                             | native                                    | native                                        |
| G20 no abbreviations                                 | native                               | native                                    | native                                        |

## Three strongest reasons for

1. The grammar Headscale decided (D3, D6, D9, D11, no abbreviations, `--`) is ~55 lines; every
   decision is a line we write rather than a default we fight. Typed errors with the path are free.
1. No framework semantics leak into tests: help, errors, exit codes, completion protocol are all
   ours or a documented protocol; the adapter is the whole framework.
1. Completion scripts can be fixed the day a bug is found (two real bugs found here, one unfixed
   in cobra since 2021, one fix sitting unreleased for 11 months).

## Three strongest reasons against

1. **Completion is a product we would own**: ~110 lines of answerer, ~1,050 lines of copied shell
   in four languages, and a shell smoke test in CI. Tailscale's copy shows the default outcome:
   frozen, issues unanswered.
1. The safety of `nodes delete --force` rests on our table tests, not on a parser used by
   thousands of programs. Every new syntax habit (grouped shorts, `-ojson`) is a decision and a
   test.
1. Bus factor: today one maintainer owns `cmd/headscale/cli`. pflag has the same problem upstream
   (one active maintainer) but at least has other users who report bugs.

## Open questions for the maintainer

1. **Where do the completion scripts live?**
   (a) Copy cobra's templates verbatim into the tree with cobra's licence, patch the fish
   `string split --` and decide on the bash comma escape; cost: ~1,050 lines held, a yearly
   re-sync diff, a CI shell smoke job. (b) Import cobra in the adapter only for
   `GenBashCompletionV2/GenZshCompletion/GenFishCompletion`; cost: ~10 lines, but fixes wait for
   cobra releases (none for 11 months) and we cannot patch the fish bug.
1. **pflag under our dispatcher, or our grammar?**
   (a) pflag: today's syntax for free, 25 lines of error mapping, but a WA pre-scan to refuse
   `-ojson` and invisible bool repeats. (b) Own grammar: ~55 lines, exactly the decisions, no
   dependency; cost: every edge is ours to test (the probe table has 58 rows).
1. **Is a shell smoke test in CI acceptable?** (a) Yes: bash, zsh, fish in the nix dev shell,
   ~150–500 lines of harness, catches script regressions like the fish one above. (b) No: protocol
   tests in Go only (cobra's own approach); cost: script bugs reach users first.
1. **PowerShell (D2 stretch).** (a) Ship cobra's script untested (285 lines more). (b) Drop it;
   cost: none for Linux/macOS/FreeBSD users.

______________________________________________________________________

# Phase B: the adapter spike

Two adapters, same dispatcher, same `__complete` answerer, same copied scripts; they differ only
in `parse`:

- `spikes/own-grammar/` — our parser for the decided grammar. No dependency.
- `spikes/own-pflag/` — pflag v1.1.0 reads the flags under our dispatcher.

Both: `adapter.go` (the adapter), `scripts/` (cobra's templates, Apache-2.0, `LICENSE.txt` next to
them, one marked line patched), `cmd/headscale` (binary for shell tests), `RESULT.md`. Shell check:
`spikes/own-grammar/shellcheck.sh` (non-interactive bash + fish) and the pty driver
`spikes/probe-own/shelltest/` (interactive bash, zsh, fish).

## Numbers

|                                        | own-grammar                      | own-pflag                    |
| -------------------------------------- | -------------------------------- | ---------------------------- |
| MUST                                   | **112/112**                      | **112/112**                  |
| STRETCH                                | 4/4 (C18–C20, PowerShell syntax) | 4/4                          |
| OBSERVE                                | 13 recorded, identical rows      | 13 recorded, identical rows  |
| `-race -count=3`                       | ok (1.6 s)                       | ok (1.6 s)                   |
| Suite / `go test -count=1` wall        | 173–337 ms / 0.8 s               | 152–223 ms / ~0.8 s          |
| Adapter lines (non-blank, non-comment) | 228                              | 254                          |
| Workaround lines (`// WA`)             | 0                                | 16                           |
| Modules added to go.sum                | 0 (no go.sum)                    | 1 (`github.com/spf13/pflag`) |
| Copied script templates + shim         | 1,011 + 43                       | same                         |
| Script bytes bash / zsh / fish / pwsh  | 16,300 / 7,856 / 10,082 / 10,904 | same                         |

Where the 228 lines go (own-grammar): parser 45, dispatcher (`walk`, `child`, `at`) 40,
completion (`Complete`, `byTyped`, `values`, `Serve`) 110, the three interface methods 20, the
rest imports and types.

Workarounds in own-pflag, all declared:

1. **`-ojson` refusal (13 lines).** pflag reads `-ojson` as `-o json` and `-ho json` as
   `-h -o json` and has no setting to stop it. D11 wants an unknown-flag error, so the adapter
   walks argv before pflag, stepping over the values of value flags (it must know which flags take
   a value, i.e. it re-tokenizes), and refuses an attached short value or a short group. Without it,
   F05 runs `nodes list` with output=json and F28 prints help (probe edge rows).
1. **Global flags handed to the leaf (3 lines).** The dispatcher reads `-c`/`-o` before the
   subcommand and re-feeds those tokens to the leaf's FlagSet (D3). In the grammar variant the
   same three lines exist, but there is no framework to work around, so they are not marked.

argv handled before the parser sees it: own-grammar none (the parser is ours; the dispatcher
calls it per level). own-pflag: the WA pre-scan above, and the dispatcher's split of argv into
levels, which every "no framework" variant has by definition.

Not a workaround but worth naming: pflag's bool repeat is invisible with `BoolP`. The adapter
registers every flag, bools included, with one 4-line `Value` that records each `Set`, and sets
`NoOptDefVal = "true"` for bools. That is plain pflag API and makes B05 (`--force --force`) and
B04 (`--force=maybe`) reach the kit's own checks, same as the grammar variant.

## OBSERVE rows (both adapters)

| ID      | argv                                  | Outcome                     | Other behaviour costs                                                                           |
| ------- | ------------------------------------- | --------------------------- | ----------------------------------------------------------------------------------------------- |
| H14/H15 | `nodes list --bogus -h`, `-h --bogus` | unknown-flag `bogus`        | help-wins would need a pre-scan for `-h` (WA-like, ~5 lines) and is wrong for `--name -h`       |
| H16/H17 | `nodes --help list`, `-h nodes list`  | help for `nodes list`       | group help instead: stop the walk on a group-level `-h` (2 lines)                               |
| V04     | `nodes list --version`                | unknown-flag                | accept: add `version` to every leaf (1 line)                                                    |
| F05     | `nodes list -ojson`                   | unknown-flag `-ojson`       | grammar: accepting costs 2 lines; pflag: refusing costs the 13-line WA, accepting costs nothing |
| F26     | `nodes set 12 --name -e`              | runs, name=`-e`             | treating `-e` as a flag would break R21                                                         |
| F27     | `nodes list --sort --filter x`        | arg-count (sort=`--filter`) | refusing a value that looks like a known flag: 3 lines, breaks `--name --`                      |
| F28     | `nodes list -ho json`                 | unknown-flag `-ho`          | grammar: grouping costs ~8 lines; pflag: native, refusal is in the WA                           |
| B04     | `--force=maybe`                       | bad-value (kit)             | —                                                                                               |
| B05     | `--force --force`                     | flag-repeated (kit)         | last-wins: drop repeats for bools (1 line)                                                      |
| G11     | `-c /a nodes list -c /b`              | flag-repeated `config`      | last-wins for globals: 2 lines                                                                  |
| E21     | `--bogus nodes list`                  | unknown-flag at root        | —                                                                                               |

## Completion through real shells

How the script calls the binary: cobra's protocol, `headscale __complete <words…> <cur>` (and
`__completeNoDesc`), lines `word\tdesc` then `:<directive>`. `Adapter.Complete` and the binary's
`Serve` call the same `Complete` function; `Files` is "directive lacks NoFileComp".

Non-interactive (`own-grammar/shellcheck.sh`; bash 5.3 interactive build + bash-completion 2.17,
`COMP_*` set by hand; fish 4.9.3 `complete -C`). Both binaries give identical output.

| Line + Tab                   | bash `COMPREPLY`                                                                                                                                                         | fish `complete -C`                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `headscale no`               | `nodes`                                                                                                                                                                  | `nodes`                                                                                                                |
| `nodes list --columns `      | 9 column names                                                                                                                                                           | 9 column names                                                                                                         |
| `nodes list --columns id,na` | `id\,name`                                                                                                                                                               | `id,name` (+ `id,name.`, cobra's NoSpace trick)                                                                        |
| `nodes list -o `             | `json`                                                                                                                                                                   | `json`                                                                                                                 |
| `policy set `                | empty: directive 0 makes the script hand over to readline's filename completion (`compopt -o default`), which only exists inside a real Tab; the pty run shows the files | `policy.hujson policy.json`                                                                                            |
| `nodes routes ap`            | `approve`                                                                                                                                                                | `approve`                                                                                                              |
| `nodes list --sort -la`      | `-last-seen`                                                                                                                                                             | `-last-seen`                                                                                                           |
| `nodes list --columns=id,na` | `id\,name`                                                                                                                                                               | `--columns=id,name` (works only because of our one-line patch; cobra's script prints `string split: … unknown option`) |

zsh has no entry into its completion system without a terminal; the pty driver
(`probe-own/shelltest/run.sh`, zsh 5.9 with `bindkey -e`) covers it, see the next table.

Interactive, real Tab in a pty (own-grammar binary on the kit's tree; edited line shown in
brackets, so a trailing space is visible). zsh drops the auto-inserted space when the driver types
the next character, so zsh rows show no trailing space even where one was added.

| Line + Tab                                              | bash 5.3             | zsh 5.9             | fish 4.9.3                         |
| ------------------------------------------------------- | -------------------- | ------------------- | ---------------------------------- |
| `headscale no`                                          | `nodes `             | `nodes`             | `nodes `                           |
| `headscale -c x no`                                     | `-c x nodes `        | `-c x nodes`        | `-c x nodes `                      |
| `nodes list --columns id,na`                            | `id\,name`           | `id,name`           | `id,name`                          |
| `nodes list --columns=id,na`                            | `--columns=id\,name` | `--columns=id,name` | `--columns=id,name` (patched line) |
| `nodes list --sort -l`                                  | `-last-seen `        | `-last-seen`        | `-last-seen `                      |
| `nodes list --filter na`                                | `name` (no space)    | `name`              | `name`                             |
| `nodes list --columns +ho`                              | `+hostname `         | `+hostname`         | `+hostname `                       |
| `nodes routes ap`                                       | `approve `           | `approve`           | `approve `                         |
| `nodes list -o `                                        | `json `              | `json`              | `json `                            |
| `policy set pol` (files `policy.json`, `policy.hujson`) | `policy.`            | `policy.`           | `policy.`                          |
| `nodes rm --f`                                          | `--force `           | `--force`           | `--force `                         |
| `completion f`                                          | `fish `              | `fish`              | `fish `                            |

All three shells complete every line; the only defect left is bash's escaped comma.

## Completion scripts: source, licence, upkeep

Copied from cobra commit adbc881 (v1.10.2 + 7, includes the unreleased fish quoting fix
61968e8), the four `gen*Comp` functions verbatim, plus a 43-line shim for the constants they use.
Licence Apache-2.0: header kept, cobra's `LICENSE.txt` beside the file, the one changed line
marked `# Headscale:` (Apache §4(b)). No NOTICE file upstream. To keep current: diff cobra's
four template files on each cobra release (about one or two relevant changes a year since 2023),
decide on each, re-run the shell checks. Alternatives considered: importing cobra only for the
scripts (10 lines, but no patching and cobra's 11-month release gap), and
`tailscale.com/tempfork/spf13/cobra` (zero new modules since Headscale already requires
tailscale.com, but frozen at cobra of 2024-02 and missing four fixes, among them the fish quoting
one; not a public API).

## What surprised me

- Both adapters passed every MUST on the first run; the kit's hard cases (D3 globals on both
  sides, D6 repeats, D9 bools, `--` and `-`, help anywhere) are all dispatcher-shaped, and a
  dispatcher of our own is where they are cheapest.
- The decided grammar is smaller than pflag's. With pflag the extra lines are spent switching
  pflag off (`-ojson`, grouping), and that switch-off is a second tokenizer in front of pflag,
  which is exactly what owning the parser would have been.
- The scripts are the risk, again: the fish bug in cobra's own template, and bash escaping `,`
  in comma lists (`id\,name`; works, looks wrong, same for today's cobra-based Headscale).

## What was ugly

- `values()` treats every flag with values as a comma list with `+`/`-` items because the kit's
  `Flag` does not say which flags are lists; in Headscale the field type (`[]string`) would.
- The NoSpace choice is a guess for the same reason (`--columns id<Tab>` adds a space).
- `-c <Tab>` offers nothing: the kit's `Flag` has no "file" marker.
- In bash, completing inside a comma list shows the escaped comma.

## Did Phase B change the Phase A verdict?

It sharpened it. Both variants are equal on behaviour (identical 130 rows); the grammar variant is
26 lines shorter, has no `// WA`, no dependency, and does what D11 says without a pre-scan. pflag's
remaining argument is "today's syntax, used by thousands of programs", but the decisions already
leave today's syntax (D11, D6, D9 are stricter than pflag), so that argument is mostly spent.
Recommendation for the "no framework" option: **own grammar + our dispatcher + cobra's scripts
copied verbatim with marked patches + a shell smoke job in CI**. Against the framework candidates
the honest comparison is not parser lines but who keeps ~1,050 lines of shell working.

## Five years of this adapter: what would worry me

Not the parser: 45 lines, every decided form in a table, and a parse bug shows up as a usage
error long before it deletes the wrong node, because the argument count and the named prompt
stand behind it. What worries me is the shell side. Four script languages that nobody on the
project writes, copied from a project whose own CI does not run them, will drift from cobra and
from new shell and bash-completion releases. The day a fish or zsh release breaks Tab, it breaks in every user's shell
until they regenerate the script, and nobody will notice unless a CI job sources each script in a
real shell on every change and every bump of the dev shell. If that job exists and someone reads
cobra's script diffs once a release, this is a small, quiet component; if it does not, it becomes
Tailscale's `tempfork`: frozen, with completion issues that nobody answers.

## Conformance table (own-grammar; own-pflag's 130 rows are identical)

MUST 112/112 pass (0 skipped) · STRETCH 4/4 · OBSERVE 13 recorded · suite 173ms

| ID           | Class   | From        | Input                                                                                              | Want                                                                             | Got                                                                              | Result |
| ------------ | ------- | ----------- | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ------ |
| T01          | MUST    | R01         | `headscale nodes routes set 12 10.0.0.0/8`                                                         | `run nodes routes set ["12" "10.0.0.0/8"]`                                       | `run nodes routes set ["12" "10.0.0.0/8"]`                                       | PASS   |
| T02          | MUST    | R06         | `headscale nodes routes approve 12 10.0.0.0/8`                                                     | `run nodes routes set ["12" "10.0.0.0/8"]`                                       | `run nodes routes set ["12" "10.0.0.0/8"]`                                       | PASS   |
| T03          | MUST    | R06         | `headscale nodes rm 12`                                                                            | `run nodes delete ["12"]`                                                        | `run nodes delete ["12"]`                                                        | PASS   |
| T04          | MUST    | R06         | `headscale nodes ls`                                                                               | `run nodes list []`                                                              | `run nodes list []`                                                              | PASS   |
| T05          | MUST    | R05         | `headscale users rm alice`                                                                         | `run users delete ["alice"]`                                                     | `run users delete ["alice"]`                                                     | PASS   |
| T06          | MUST    | R06         | `headscale auth keys approve x`                                                                    | `unknown-command [auth keys] "approve"`                                          | `unknown-command [auth keys] "approve"`                                          | PASS   |
| T07          | MUST    | R01         | `headscale auth keys create alice`                                                                 | `run auth keys create ["alice"]`                                                 | `run auth keys create ["alice"]`                                                 | PASS   |
| T08          | MUST    | R01         | `headscale api keys create`                                                                        | `run api keys create []`                                                         | `run api keys create []`                                                         | PASS   |
| T09          | MUST    | R04         | `headscale check config`                                                                           | `run check config []`                                                            | `run check config []`                                                            | PASS   |
| T10          | MUST    | R04         | `headscale check config /etc/hs.yaml`                                                              | `run check config ["/etc/hs.yaml"]`                                              | `run check config ["/etc/hs.yaml"]`                                              | PASS   |
| T11          | MUST    | R67         | `headscale serve`                                                                                  | `run serve []`                                                                   | `run serve []`                                                                   | PASS   |
| T12          | MUST    | R52 D10     | `headscale`                                                                                        | `help`                                                                           | `help`                                                                           | PASS   |
| T13          | MUST    | R03 D10     | `headscale nodes`                                                                                  | `help nodes`                                                                     | `help nodes`                                                                     | PASS   |
| T14          | MUST    | R03 D10     | `headscale nodes routes`                                                                           | `help nodes routes`                                                              | `help nodes routes`                                                              | PASS   |
| T15          | MUST    | D10         | `headscale check`                                                                                  | `help check`                                                                     | `help check`                                                                     | PASS   |
| H01          | MUST    | R53         | `headscale -h`                                                                                     | `help`                                                                           | `help`                                                                           | PASS   |
| H02          | MUST    | R53         | `headscale --help`                                                                                 | `help`                                                                           | `help`                                                                           | PASS   |
| H03          | MUST    | R53         | `headscale nodes -h`                                                                               | `help nodes`                                                                     | `help nodes`                                                                     | PASS   |
| H04          | MUST    | R53         | `headscale nodes routes --help`                                                                    | `help nodes routes`                                                              | `help nodes routes`                                                              | PASS   |
| H05          | MUST    | R53         | `headscale nodes routes set -h`                                                                    | `help nodes routes set`                                                          | `help nodes routes set`                                                          | PASS   |
| H06          | MUST    | R53         | `headscale nodes delete --help`                                                                    | `help nodes delete`                                                              | `help nodes delete`                                                              | PASS   |
| H07          | MUST    | R53         | `headscale nodes delete 12 -h`                                                                     | `help nodes delete`                                                              | `help nodes delete`                                                              | PASS   |
| H08          | MUST    | R53         | `headscale nodes rm --help`                                                                        | `help nodes delete`                                                              | `help nodes delete`                                                              | PASS   |
| H09          | MUST    | R53         | `headscale nodes routes approve -h`                                                                | `help nodes routes set`                                                          | `help nodes routes set`                                                          | PASS   |
| H10          | MUST    | R53         | `headscale auth keys create alice --tags tag:a -h`                                                 | `help auth keys create`                                                          | `help auth keys create`                                                          | PASS   |
| H11          | MUST    | D8          | `headscale help`                                                                                   | `unknown-command [] "help"`                                                      | `unknown-command [] "help"`                                                      | PASS   |
| H12          | MUST    | D8          | `headscale help nodes`                                                                             | `unknown-command [] "help"`                                                      | `unknown-command [] "help"`                                                      | PASS   |
| H13          | MUST    | D8          | `headscale nodes help`                                                                             | `unknown-command [nodes] "help"`                                                 | `unknown-command [nodes] "help"`                                                 | PASS   |
| H14          | OBSERVE | R53         | `headscale nodes list --bogus -h`                                                                  |                                                                                  | `unknown-flag [nodes list] "bogus"`                                              | SEEN   |
| H15          | OBSERVE | R53         | `headscale nodes list -h --bogus`                                                                  |                                                                                  | `unknown-flag [nodes list] "bogus"`                                              | SEEN   |
| H16          | OBSERVE | R53         | `headscale nodes --help list`                                                                      |                                                                                  | `help nodes list`                                                                | SEEN   |
| H17          | OBSERVE | R53         | `headscale -h nodes list`                                                                          |                                                                                  | `help nodes list`                                                                | SEEN   |
| V01          | MUST    | D7          | `headscale --version`                                                                              | `version`                                                                        | `version`                                                                        | PASS   |
| V02          | MUST    | D7          | `headscale version`                                                                                | `run version []`                                                                 | `run version []`                                                                 | PASS   |
| V03          | MUST    | R19         | `headscale version -o json`                                                                        | `run version [] output=["json"]`                                                 | `run version [] output=["json"]`                                                 | PASS   |
| V04          | OBSERVE | D7          | `headscale nodes list --version`                                                                   |                                                                                  | `unknown-flag [nodes list] "version"`                                            | SEEN   |
| F01          | MUST    | R15         | `headscale auth keys create alice --expiry 24h`                                                    | `run auth keys create ["alice"] expiry=["24h"]`                                  | `run auth keys create ["alice"] expiry=["24h"]`                                  | PASS   |
| F02          | MUST    | R15         | `headscale auth keys create alice --expiry=24h`                                                    | `run auth keys create ["alice"] expiry=["24h"]`                                  | `run auth keys create ["alice"] expiry=["24h"]`                                  | PASS   |
| F03          | MUST    | R16 D11     | `headscale nodes list -o json`                                                                     | `run nodes list [] output=["json"]`                                              | `run nodes list [] output=["json"]`                                              | PASS   |
| F04          | MUST    | R16 D11     | `headscale nodes list -o=json`                                                                     | `run nodes list [] output=["json"]`                                              | `run nodes list [] output=["json"]`                                              | PASS   |
| F05          | OBSERVE | R16 D11     | `headscale nodes list -ojson`                                                                      |                                                                                  | `unknown-flag [nodes list] "ojson"`                                              | SEEN   |
| F06          | MUST    | R17         | `headscale auth keys create alice -e 24h`                                                          | `run auth keys create ["alice"] expiry=["24h"]`                                  | `run auth keys create ["alice"] expiry=["24h"]`                                  | PASS   |
| F07          | MUST    | R20         | `headscale nodes delete --force 12`                                                                | `run nodes delete ["12"] force=["true"]`                                         | `run nodes delete ["12"] force=["true"]`                                         | PASS   |
| F08          | MUST    | R20         | `headscale nodes delete 12 --force`                                                                | `run nodes delete ["12"] force=["true"]`                                         | `run nodes delete ["12"] force=["true"]`                                         | PASS   |
| F09          | MUST    | R20         | `headscale nodes routes set 12 -o json 10.0.0.0/8`                                                 | `run nodes routes set ["12" "10.0.0.0/8"] output=["json"]`                       | `run nodes routes set ["12" "10.0.0.0/8"] output=["json"]`                       | PASS   |
| F10          | MUST    | R20 R25     | `headscale auth keys create --reusable alice -e 1h --tags tag:ci`                                  | `run auth keys create ["alice"] expiry=["1h"] reusable=["true"] tags=["tag:ci"]` | `run auth keys create ["alice"] expiry=["1h"] reusable=["true"] tags=["tag:ci"]` | PASS   |
| F11          | MUST    | R23         | `headscale nodes set 12 --name ''`                                                                 | `run nodes set ["12"] name=[""]`                                                 | `run nodes set ["12"] name=[""]`                                                 | PASS   |
| F12          | MUST    | R23         | `headscale nodes set 12 --name=`                                                                   | `run nodes set ["12"] name=[""]`                                                 | `run nodes set ["12"] name=[""]`                                                 | PASS   |
| F13          | MUST    | R24         | `headscale nodes set 12 -e 1d`                                                                     | `run nodes set ["12"] expiry=["1d"]`                                             | `run nodes set ["12"] expiry=["1d"]`                                             | PASS   |
| F14          | MUST    | R21         | `headscale nodes list --sort -last-seen`                                                           | `run nodes list [] sort=["-last-seen"]`                                          | `run nodes list [] sort=["-last-seen"]`                                          | PASS   |
| F15          | MUST    | R21         | `headscale nodes list --sort=-last-seen`                                                           | `run nodes list [] sort=["-last-seen"]`                                          | `run nodes list [] sort=["-last-seen"]`                                          | PASS   |
| F16          | MUST    | R21         | `headscale nodes list --columns -ip`                                                               | `run nodes list [] columns=["-ip"]`                                              | `run nodes list [] columns=["-ip"]`                                              | PASS   |
| F17          | MUST    | R21         | `headscale nodes list --columns -ip,+hostname`                                                     | `run nodes list [] columns=["-ip,+hostname"]`                                    | `run nodes list [] columns=["-ip,+hostname"]`                                    | PASS   |
| F18          | MUST    | R22         | `headscale nodes list --filter=owner=tag:ci`                                                       | `run nodes list [] filter=["owner=tag:ci"]`                                      | `run nodes list [] filter=["owner=tag:ci"]`                                      | PASS   |
| F19          | MUST    | R22 R27     | `headscale nodes list --filter name:web,online=true --filter 'last-seen>30d' '--filter=expiry<7d'` | `run nodes list [] filter=["name:web,online=true" "last-seen>30d" "expiry<7d"]`  | `run nodes list [] filter=["name:web,online=true" "last-seen>30d" "expiry<7d"]`  | PASS   |
| F20          | MUST    | R12         | `headscale policy set -`                                                                           | `run policy set ["-"]`                                                           | `run policy set ["-"]`                                                           | PASS   |
| F21          | MUST    | R12         | `headscale nodes delete 'hskey-auth-ab12cd-***'`                                                   | `run nodes delete ["hskey-auth-ab12cd-***"]`                                     | `run nodes delete ["hskey-auth-ab12cd-***"]`                                     | PASS   |
| F22          | MUST    | R26         | `headscale nodes routes set 12 ''`                                                                 | `run nodes routes set ["12" ""]`                                                 | `run nodes routes set ["12" ""]`                                                 | PASS   |
| F23          | MUST    | G05         | `headscale users delete -- --with-nodes`                                                           | `run users delete ["--with-nodes"]`                                              | `run users delete ["--with-nodes"]`                                              | PASS   |
| F24          | MUST    | G05         | `headscale users delete --force -- -alice`                                                         | `run users delete ["-alice"] force=["true"]`                                     | `run users delete ["-alice"] force=["true"]`                                     | PASS   |
| F25          | MUST    | R46         | `headscale api keys create -u alice --expiry 90d`                                                  | `run api keys create [] expiry=["90d"] user=["alice"]`                           | `run api keys create [] expiry=["90d"] user=["alice"]`                           | PASS   |
| F26          | OBSERVE | R21         | `headscale nodes set 12 --name -e`                                                                 |                                                                                  | `run nodes set ["12"] name=["-e"]`                                               | SEEN   |
| F27          | OBSERVE | R21         | `headscale nodes list --sort --filter x`                                                           |                                                                                  | `arg-count [nodes list] "takes no arguments, got 1"`                             | SEEN   |
| F28          | OBSERVE | G21         | `headscale nodes list -ho json`                                                                    |                                                                                  | `unknown-flag [nodes list] "ho"`                                                 | SEEN   |
| B01          | MUST    | D9          | `headscale nodes delete 12 --force=true`                                                           | `run nodes delete ["12"] force=["true"]`                                         | `run nodes delete ["12"] force=["true"]`                                         | PASS   |
| B02          | MUST    | D9          | `headscale nodes delete 12 --force=false`                                                          | `run nodes delete ["12"] force=["false"]`                                        | `run nodes delete ["12"] force=["false"]`                                        | PASS   |
| B03          | MUST    | D9          | `headscale nodes delete 12 --no-force`                                                             | `unknown-flag [nodes delete] "no-force"`                                         | `unknown-flag [nodes delete] "no-force"`                                         | PASS   |
| B04          | OBSERVE | D9          | `headscale nodes delete 12 --force=maybe`                                                          |                                                                                  | `bad-value [nodes delete] "force"`                                               | SEEN   |
| B05          | OBSERVE | D6          | `headscale nodes delete 12 --force --force`                                                        |                                                                                  | `flag-repeated [nodes delete] "force"`                                           | SEEN   |
| G01          | MUST    | D3          | `headscale -c /etc/hs.yaml nodes list`                                                             | `run nodes list [] config=["/etc/hs.yaml"]`                                      | `run nodes list [] config=["/etc/hs.yaml"]`                                      | PASS   |
| G02          | MUST    | D3          | `headscale nodes list -c /etc/hs.yaml`                                                             | `run nodes list [] config=["/etc/hs.yaml"]`                                      | `run nodes list [] config=["/etc/hs.yaml"]`                                      | PASS   |
| G03          | MUST    | D3          | `headscale -o json nodes list`                                                                     | `run nodes list [] output=["json"]`                                              | `run nodes list [] output=["json"]`                                              | PASS   |
| G04          | MUST    | D3          | `headscale --config=/x nodes routes set 12 10.0.0.0/8`                                             | `run nodes routes set ["12" "10.0.0.0/8"] config=["/x"]`                         | `run nodes routes set ["12" "10.0.0.0/8"] config=["/x"]`                         | PASS   |
| G05          | MUST    | D3 R20      | `headscale nodes delete 12 -c /x`                                                                  | `run nodes delete ["12"] config=["/x"]`                                          | `run nodes delete ["12"] config=["/x"]`                                          | PASS   |
| G06          | MUST    | D3          | `headscale -o json -c /x version`                                                                  | `run version [] config=["/x"] output=["json"]`                                   | `run version [] config=["/x"] output=["json"]`                                   | PASS   |
| G07          | MUST    | D3 R19      | `headscale check config -o json`                                                                   | `unknown-flag [check config] "output"`                                           | `unknown-flag [check config] "output"`                                           | PASS   |
| G08          | MUST    | D3 R19      | `headscale -o json check config`                                                                   | `unknown-flag [check config] "output"`                                           | `unknown-flag [check config] "output"`                                           | PASS   |
| G09          | MUST    | R19         | `headscale completion bash -c /x`                                                                  | `unknown-flag [completion] "config"`                                             | `unknown-flag [completion] "config"`                                             | PASS   |
| G10          | MUST    | R19         | `headscale serve -o json`                                                                          | `unknown-flag [serve] "output"`                                                  | `unknown-flag [serve] "output"`                                                  | PASS   |
| G11          | OBSERVE | D3 D6       | `headscale -c /a nodes list -c /b`                                                                 |                                                                                  | `flag-repeated [nodes list] "config"`                                            | SEEN   |
| L01          | MUST    | D6          | `headscale auth keys create alice --tags tag:a,tag:b`                                              | `run auth keys create ["alice"] tags=["tag:a,tag:b"]`                            | `run auth keys create ["alice"] tags=["tag:a,tag:b"]`                            | PASS   |
| L02          | MUST    | D6          | `headscale auth keys create alice --tags tag:a --tags tag:b`                                       | `flag-repeated [auth keys create] "tags"`                                        | `flag-repeated [auth keys create] "tags"`                                        | PASS   |
| L03          | MUST    | D6          | `headscale nodes list -o json -o json`                                                             | `flag-repeated [nodes list] "output"`                                            | `flag-repeated [nodes list] "output"`                                            | PASS   |
| E01          | MUST    | D4 D5       | `headscale nodez`                                                                                  | `unknown-command [] "nodez"`                                                     | `unknown-command [] "nodez"`                                                     | PASS   |
| E02          | MUST    | D4 D5       | `headscale nodes lst`                                                                              | `unknown-command [nodes] "lst"`                                                  | `unknown-command [nodes] "lst"`                                                  | PASS   |
| E03          | MUST    | D4 D5       | `headscale nodes routes aprove 12 10.0.0.0/8`                                                      | `unknown-command [nodes routes] "aprove"`                                        | `unknown-command [nodes routes] "aprove"`                                        | PASS   |
| E04          | MUST    | D4 D5       | `headscale auth keyz create alice`                                                                 | `unknown-command [auth] "keyz"`                                                  | `unknown-command [auth] "keyz"`                                                  | PASS   |
| E05          | MUST    | D4 D3       | `headscale -c /x nodez`                                                                            | `unknown-command [] "nodez"`                                                     | `unknown-command [] "nodez"`                                                     | PASS   |
| E06          | MUST    | D5 R08      | `headscale preauthkeys list`                                                                       | `unknown-command [] "preauthkeys"`                                               | `unknown-command [] "preauthkeys"`                                               | PASS   |
| E07          | MUST    | D5 R08      | `headscale node ls`                                                                                | `unknown-command [] "node"`                                                      | `unknown-command [] "node"`                                                      | PASS   |
| E08          | MUST    | R09         | `headscale nodes authorize 12`                                                                     | `unknown-command [nodes] "authorize"`                                            | `unknown-command [nodes] "authorize"`                                            | PASS   |
| E09          | MUST    | D4          | `headscale nodes list --bogus`                                                                     | `unknown-flag [nodes list] "bogus"`                                              | `unknown-flag [nodes list] "bogus"`                                              | PASS   |
| E10          | MUST    | R18         | `headscale nodes list --force`                                                                     | `unknown-flag [nodes list] "force"`                                              | `unknown-flag [nodes list] "force"`                                              | PASS   |
| E11          | MUST    | R17         | `headscale auth keys create alice -r`                                                              | `unknown-flag [auth keys create] "r"`                                            | `unknown-flag [auth keys create] "r"`                                            | PASS   |
| E12          | MUST    | G20         | `headscale auth keys create alice --exp 1h`                                                        | `unknown-flag [auth keys create] "exp"`                                          | `unknown-flag [auth keys create] "exp"`                                          | PASS   |
| E13          | MUST    | D4          | `headscale nodes list --sort`                                                                      | `missing-value [nodes list] "sort"`                                              | `missing-value [nodes list] "sort"`                                              | PASS   |
| E14          | MUST    | D4          | `headscale auth keys create alice -e`                                                              | `missing-value [auth keys create] "expiry"`                                      | `missing-value [auth keys create] "expiry"`                                      | PASS   |
| E15          | MUST    | D4          | `headscale nodes list -o`                                                                          | `missing-value [nodes list] "output"`                                            | `missing-value [nodes list] "output"`                                            | PASS   |
| E16          | MUST    | R32         | `headscale nodes delete 12 13`                                                                     | `arg-count [nodes delete] "needs 1 argument, got 2"`                             | `arg-count [nodes delete] "needs 1 argument, got 2"`                             | PASS   |
| E17          | MUST    | R32         | `headscale nodes delete`                                                                           | `arg-count [nodes delete] "needs 1 argument, got 0"`                             | `arg-count [nodes delete] "needs 1 argument, got 0"`                             | PASS   |
| E18          | MUST    | R32         | `headscale nodes routes set 12`                                                                    | `arg-count [nodes routes set] "needs 2 arguments, got 1"`                        | `arg-count [nodes routes set] "needs 2 arguments, got 1"`                        | PASS   |
| E19          | MUST    | R32         | `headscale check config a b`                                                                       | `arg-count [check config] "takes at most 1 argument, got 2"`                     | `arg-count [check config] "takes at most 1 argument, got 2"`                     | PASS   |
| E20          | MUST    | R32         | `headscale nodes list extra`                                                                       | `arg-count [nodes list] "takes no arguments, got 1"`                             | `arg-count [nodes list] "takes no arguments, got 1"`                             | PASS   |
| E21          | OBSERVE | D4          | `headscale --bogus nodes list`                                                                     |                                                                                  | `unknown-flag [] "bogus"`                                                        | SEEN   |
| C01          | MUST    | D1 D8       | `headscale ''<TAB>`                                                                                | `has serve version check completion nodes users auth api policy; not help`       | `api auth check completion nodes policy serve users version`                     | PASS   |
| C02          | MUST    | D1          | `headscale no<TAB>`                                                                                | `has nodes; not users`                                                           | `nodes`                                                                          | PASS   |
| C03          | MUST    | D1          | `headscale nodes ''<TAB>`                                                                          | `has list delete set routes; not help`                                           | `delete list routes set`                                                         | PASS   |
| C04          | MUST    | D1          | `headscale nodes routes ''<TAB>`                                                                   | `has set`                                                                        | `set`                                                                            | PASS   |
| C05          | MUST    | D1 R06      | `headscale nodes routes ap<TAB>`                                                                   | `has approve`                                                                    | `approve`                                                                        | PASS   |
| C06          | MUST    | D1          | `headscale auth keys c<TAB>`                                                                       | `has create`                                                                     | `create`                                                                         | PASS   |
| C07          | MUST    | D1 D3       | `headscale -c /x nodes l<TAB>`                                                                     | `has list`                                                                       | `list`                                                                           | PASS   |
| C08          | MUST    | D1 R60      | `headscale nodes list --<TAB>`                                                                     | `has --columns --sort --filter --list-columns --output --config; not --force`    | `--columns --config --filter --help --list-columns --output --sort`              | PASS   |
| C09          | MUST    | D1 R18      | `headscale users delete alice --<TAB>`                                                             | `has --force --with-nodes; not --columns`                                        | `--config --force --help --output --with-nodes`                                  | PASS   |
| C10          | MUST    | D1          | `headscale auth keys create alice --<TAB>`                                                         | `has --tags --expiry --reusable --description; not --force --columns`            | `--config --description --expiry --help --output --reusable --tags`              | PASS   |
| C11          | MUST    | D1 R60      | `headscale nodes list -o ''<TAB>`                                                                  | `has json`                                                                       | `json`                                                                           | PASS   |
| C12          | MUST    | D1 R60      | `headscale nodes list --columns ''<TAB>`                                                           | `has id name owner last-seen`                                                    | `expiry hostname id ip last-seen name online owner version`                      | PASS   |
| C13          | MUST    | D1 R60      | `headscale nodes list --sort la<TAB>`                                                              | `has last-seen; not id`                                                          | `last-seen`                                                                      | PASS   |
| C14          | MUST    | D1 R60      | `headscale nodes list --filter ow<TAB>`                                                            | `has owner`                                                                      | `owner`                                                                          | PASS   |
| C15          | MUST    | D1 R59      | `headscale completion ''<TAB>`                                                                     | `has bash zsh fish`                                                              | `bash fish powershell zsh`                                                       | PASS   |
| C16          | MUST    | D1          | `headscale policy set ''<TAB>`                                                                     | `+files`                                                                         | ` +files`                                                                        | PASS   |
| C17          | MUST    | D1          | `headscale check config ''<TAB>`                                                                   | `+files`                                                                         | ` +files`                                                                        | PASS   |
| C18          | STRETCH | R60         | `headscale nodes list --columns id,na<TAB>`                                                        | `has id,name`                                                                    | `id,name`                                                                        | PASS   |
| C19          | STRETCH | R60         | `headscale nodes list --columns +ho<TAB>`                                                          | `has +hostname`                                                                  | `+hostname`                                                                      | PASS   |
| C20          | STRETCH | R60         | `headscale nodes list --sort -la<TAB>`                                                             | `has -last-seen`                                                                 | `-last-seen`                                                                     | PASS   |
| S-bash       | MUST    | D1 D2 R59   | `Script(bash)`                                                                                     | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-zsh        | MUST    | D1 D2 R59   | `Script(zsh)`                                                                                      | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-fish       | MUST    | D1 D2 R59   | `Script(fish)`                                                                                     | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-powershell | STRETCH | D1 D2 R59   | `Script(powershell)`                                                                               | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| I01          | MUST    | R49 R56 G26 | `every case twice, in parallel, fresh tree each`                                                   | `same outcome both times, no panic`                                              | `ok`                                                                             | PASS   |
