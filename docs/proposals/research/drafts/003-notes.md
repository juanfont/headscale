# Notes on the draft of 003-cmdline.md

Draft: `drafts/003-cmdline.md`. These notes say where each part came from, where the writer had to choose, what in `rules.md` did not fit the code, and where the 001 draft now disagrees with 003. Questions for the maintainer are in section 2, each with two alternatives and the cost.

## 0. What was run, and what was added to this folder

- Every example in 003 was run. The example program `prog` is in `spikes/final/prog/` (on `spikes/final/cmdline` through a `replace`): `main.go` is the code shown in 003; `main_test.go` holds the test shown in 003 and `TestProbe`, whose output (`probe.txt`) fills the `Parse` and Tab tables; `probe2_test.go` holds the extra rows; `console.txt` is every `console` block, run again on the built binary. A script checked that every Go block in 003 is a substring of these files.
- A new measurement: a value that holds `=`, completed in the `--x=` form. zsh offers nothing and fish offers `--filter=name=name=web`; bash and PowerShell are right. Program, lines and table in `spikes/probe-eq/` (`RESULT.md`). It is in 003 under "Known faults in the scripts". Not reported upstream.
- The completion protocol was read from cobra v1.10.2 in the Go module cache (`~/go/pkg/mod/github.com/spf13/cobra@v1.10.2`), the version in Headscale's `go.mod`, not from `spikes/src/cobra` (that is `adbc881`, seven commits later).
- `uvx mdformat` with the repository's plugins and `.mdformat.toml` is a no-op on the draft. All 181 links were checked: every `#anchor` resolves in 003, every `001-cli.md#…` anchor resolves in `drafts/001-cli.md`, and every `research/…` path exists in this folder. The `research/` links assume this folder is copied as it is into `docs/proposals/research/` (D36).
- Library tests, `go vet` and the example's tests pass in `nix develop` (Go 1.27.3).

## 1. Where each part came from

| Part of 003                        | Sources                                                                                                                                                                                     |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Intro, Words used here             | D31; the terms of `rules.md` ("How to read the rules"); the form of 001 and 002                                                                                                             |
| What the library is, Who does what | `library-design.md` §1; `rules.md` §12 (E1–E8); the package comment of `parse.go`                                                                                                           |
| The command tree, A valid tree     | the types in `parse.go`; `check.go`; `rules.md` §11 (K1–K6); `TestCheck`, `TestContract`; the `Check` messages from `TestProbe`                                                             |
| Reading a command line             | `rules.md` §1–7; `parse.go`; `TestParse`, `TestOrder`; every table row from `TestProbe`                                                                                                     |
| Several mistakes on one line       | `rules.md` §8; D35, D19; the kit's `Exec` in `spikes/final/kit-v3/kit.go` (the order of checks, `pos < at`); kit v3 rows E21–E26, P01–P12, H14, H23 from `headscale/RESULT.md`              |
| Tab completion                     | `rules.md` §9; `complete.go`; `TestComplete`; the table from `TestProbe` and `probe2_test.go`                                                                                               |
| The completion protocol            | cobra v1.10.2 source (`completions.go`, `active_help.go`, the four generators); `rules.md` §10; `referee.md` §1 and §4; `spikes/final/headscale/shell/out/`; `spikes/probe-eq/`             |
| Using the library                  | `spikes/final/prog/`; `library-design.md` §2                                                                                                                                                |
| Tests                              | `rules.md` §0; `cmdline_test.go`; `edge-corpus.md` §1, §2, §4; counts computed from `spikes/corpus/corpus.jsonl`; `differential.md` §6–7; `spikes/final/diff/fuzz_test.go`; `referee.md` §1 |
| Limits, platforms, compatibility   | `rules.md` "What the specification needs from elsewhere"; `referee.md` "could not measure"; DECISIONS call 2; `library-design.md` §5; the bash script's source for bash 3                   |
| Why Headscale has its own parser   | the report; `discovery.md`; `referee.md` §2–5; `edge-corpus.md`; `differential.md`; `library-design.md`; `deep-own.md`; INTERVIEW (the three concerns, quoted)                              |
| Decision log                       | DECISIONS D1–D38 and facts; INTERVIEW for the rejected options and "against the recommendation"                                                                                             |
| Open points                        | `rules.md` "Rules that are still open"; `library-design.md` open questions; sections 2 and 3 below                                                                                          |
| Rule index                         | generated from the "Held by" column of `rules.md`, all 109 rules                                                                                                                            |

## 2. Where the writer chose: questions for the maintainer

1. **Where the D35 positions live.** 003 holds the full table (repeat at the second occurrence, bad value at the flag word, not-alone at the second word, count at the end of the line, the order inside one word) as "Headscale's rule, which a caller following D35 needs". It is Headscale's policy, not the library's. (a) Keep it in 003, and 001's "Errors on the command line" points to `003-cmdline.md#several-mistakes-on-one-line`: one place, but 003 then states Headscale rules. (b) Move the table to 001 and keep only the mechanism (X5, M5, `At`) in 003: 003 stays generic, and 001 grows by one table.

1. **D11 against the library's tests.** D11 says no test fixes `-ojson` either way; `TestParse` P19–P21 pin the refusal, and 003 specifies it (a complete spec must). (a) Keep: the library refuses, Headscale's promise stays "either". (b) Drop the rows and leave the words unspecified in 003: D11 holds literally, and 003 is no longer complete for those words. In 003's open points.

1. **The example program.** 003 uses an invented program `prog` (`items list`, `items delete`, `check`, `completion`) so that it names no Headscale command. Headscale examples appear only where the evidence is Headscale's (the D35 rows, the script faults), marked as such. (a) Keep. (b) Use Headscale's tree throughout, marked as examples: closer to 001, but 003 then reads as Headscale's document.

1. **The example Completer reads a file named on the line.** `itemIDs` picks a file from `-c` to show why a Completer gets the line (call 1). For Headscale, D1 forbids config reads at Tab time. (a) Keep: the example is about any program. (b) Change it to a Completer that depends on another flag's value without any I/O: no conflict with D1, but a weaker example of the reason.

1. **Rule IDs.** 003 keeps the IDs of `rules.md` (L1 … E8) so that every test name still points to a rule. (a) Keep. (b) Renumber by 003's sections: easier to read, and every test comment and kit row reference changes.

1. **Headscale tests in the rule index.** The "Held by" column names kit rows and `sh:` lines on Headscale's tree. (a) Keep them, marked as a caller's tests: the full trace from rule to test. (b) List only the library's own tests: 003 stays generic, and about 40 rules (those held only by kit rows, such as X1–X4, R2–R8, E4–E6) then show no test.

1. **The layout of `research/`.** The links assume this folder is copied unchanged. (a) Copy it unchanged (with `spikes/src/` and binaries left out, as `.gitignore` does): links hold. (b) A curated layout: every `research/…` link in 003 (and 001) changes.

1. **Which calls go in 003's "Calls not confirmed" table.** It lists the library's calls and also two of 001's (Q4 `-h` before the subcommand, Q6 file positionals), because the library makes them possible. (a) Keep. (b) Leave 001's calls to 001: no duplicate, but the maintainer reads two lists.

1. **The real-shell job on a cobra bump** (in 003's open points). (a) Run it on every pull request that changes `go.mod`. (b) Run it only when the CLI changes, by hand on a cobra bump.

1. **Report the cobra script faults upstream** (in 003's open points): fish `string split --`, bash colon and comma, and the new `=` fault. (a) File now. (b) Wait.

1. **Two `Check` gaps** (in 003's open points): a `Help` with a newline passes `Check` and breaks the protocol; a command named `__complete` passes `Check` and is hidden by `Serve`. (a) Add both (two lines and two `TestCheck` rows). (b) Leave them.

1. **The import path in the repository** (in 003's open points). (a) Top level of the module, `github.com/juanfont/headscale/cmdline`. (b) Under `cmd/headscale/cli/`.

1. **The corpus as a library test** (in 003's open points). (a) Split each row into a library expectation and a layer expectation now (one pass over 485 rows). (b) Keep it in Headscale's tests until the library moves.

## 3. Rules in `rules.md` that did not fit the code, or that 003 had to state otherwise

- **M5 is wrong for one case.** "Nothing after the refused word is read" fails for W2: a flag typed before the leaf that the leaf does not declare is refused only when the leaf word is read, so the words between it and the leaf word, and the leaf word itself, were read; `Match.Command` and `Path` are the leaf's (`TestOrder` O5: `-c a -o j -c b policy check` gives `[policy check]`, `config=a@0`, error at 2). 003 states the exception.
- **K1's wording is too narrow.** `Check` also refuses one child whose alias equals its own name (second K1 row of `TestCheck`); "a word that names two children" does not cover it. 003 says "appears twice among the children of one group".
- **L11 and K4 pull apart.** `Parse` matches a non-ASCII short (`-ø`, P13); `Check` refuses it, and the library's own test tree fails `Check` (asserted in `TestCheck`). Consistent, but a reader of either rule alone is surprised. 003 states both in one place.
- **E3's guard can pass silently.** `TestStdlibOnly` calls `t.Skip` when `go list` fails, so a CI without the `go` binary on `PATH` passes it.
- **Stale test comments.** `cmdline_test.go` says "rules.md groups A–G", "group H", "group I" for what are now L–C, T and S.
- **FuzzParse is weaker than M2/M5.** Its error property exempts `UnknownFlag` from "every flag before the error"; no path in `parse.go` needs the exemption.
- **S6 and `Check`.** S6 covers candidates; a `Help` text with `\n` reaches the protocol through T12 and is not refused anywhere (see question 11).
- **R6 and R7 have no home in 001.** "An empty item in a list (`a,,b`) is a bad value" and "an empty `-o` is a bad value" are Headscale layer rules (call 2), held by kit L09–L12, but 001's "Lists as input" states only the empty list. 003 mentions them only in the D35 position table.
- **S10 is incomplete.** It misses the `=` fault (section 0). 003's fault table adds it.
- **E7 and E8** are not modelled in the kit (as `rules.md` says); 003 points to 001 for them.

## 4. Where the 001 draft now disagrees with 003

- **Help texts on Tab.** 001 "Shell completion": "where the shell shows such text, as zsh and fish do". Measured: bash (cobra's V2 script with descriptions) and PowerShell show them too when several candidates are listed (`spikes/final/headscale/shell/out/pty-bash.txt`, `nodes `). Suggested: "bash, zsh, fish and PowerShell show it when they list several candidates".
- **`-ojson` and tests.** 001 "How flags are written": "no test fixes either". The library's own tests fix the refusal (question 2). Suggested: "Headscale's tests fix neither; the parser refuses them (003)".
- **The order of mistakes.** 001 "Errors on the command line" states only "the first one, left to right" and "a wrong count never hides `--help`". The positions and the order inside one word are in 003 only (question 1). Suggested: a link to `003-cmdline.md#several-mistakes-on-one-line`.
- **"Only one package of Headscale imports the parser."** 001 "Our layer, not the framework's". The prototype's `main` imports `cmdline` (for `Serve`) and `script`. Either `command` exposes one entry function that calls `Serve` first, or the sentence needs "and `main`".
- **Tab on a group's flags.** 001 "Shell completion" says a lone `-` lists long names. 003 (T6, call 2) adds that at a group only the group's own flags are listed: `headscale nodes -<Tab>` gives `--help`, not `--config`, though `-c` can be typed there. 001 does not contradict it, but a reader will expect `--config`.
- **The scripts' size.** 001 and D23 say "about 10 lines"; `script` is 20 non-blank lines (the call is about 10). Harmless.
- **The decision log row of 001** ("uses only Go's standard library") needs "(the scripts sub-package imports cobra)", as the body already says.
- **001 does not link to 003's parts.** 001 links `003-cmdline.md` as a file. Useful anchors now exist: `#several-mistakes-on-one-line`, `#tab-completion`, `#the-completion-protocol`, `#known-faults-in-the-scripts`.
- **The `=` fault and Headscale.** Headscale's `--filter` Completer offers column names only, so `--filter=name=w<Tab>` offers nothing today and does not hit the zsh and fish fault. It would, if values after the operator are completed later.

## 5. Round two (answers from the coordinator)

- Q1: the D35 position table left 003. "Several mistakes on one line" keeps the mechanism (X1, X5, X8, `Given.At`, `Match.ArgAt`, `Error.At`) and links to `001-cli.md#errors-on-the-command-line`. In the rule index, X2–X4, X6 and X7 point to 001.
- Q2: D11 is said once, under L11: the library refuses, its tests hold it, Headscale promises neither form. Out of "Not decided"; the `-vv` row left the calls table.
- Q4: one sentence under "Complete from the line": a program may forbid I/O at Tab time, as Headscale does (D1).
- Q7: `research/` links point to `research/README.md` for the folder; no link goes to `spikes/v2/shell/path*`, `spikes/corpus/results.tsv`, `spikes/diff/results/` or `spikes/v2/modcheck/`.
- Q9: the shell job runs on every pull request that changes `go.mod` or the CLI (stated under "Real shells" and "Cobra versions"; in the calls table).
- Q11: K7 (no child of the root named `__complete` or `__completeNoDesc`; allowed below the root) and K8 (no line break, `\n` or `\r`, in a command's or a flag's `Help`), numbered as in the fixed prototype (`check.go`, `TestCheck` K7 and K8 rows; tests pass). In the calls table.
- Q13: the corpus section states the target form (each row carries the library's expectation; a caller's expectation lives with the caller); the split is implementation work.
- X2, X3, X4, K3 and K4 moved to the calls table. "A Completer that calls a server" is a line under Limits.
- Still open in 003: the name, the import path, reporting the script faults upstream.
- `rules.md` was not yet changed when this round ended: the rule index has K7 and K8 from the prototype's tests; M5, K1, L11/K4 and S10 in 003 already follow section 3. Re-generate the index if `rules.md` renames or adds rules.
- Style pass: removed the second statement of W4 and of "no variadic positionals" from "Commands and flags", S9 from "The hidden entry point" (it stays under "The scripts"), and the K1–K8 overlap in the calls table.
