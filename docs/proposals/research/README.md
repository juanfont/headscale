# Headscale CLI framework choice: research record

Work done on 2026-11-17 for juanfont/headscale#3375 (`docs/proposals/001-cli.md`).
Question: is cobra still the right CLI framework, what requirements were missing, and which
tool is best. Result: a parser of Headscale's own, written as a small library (decision D24),
specified in `docs/proposals/003-cmdline.md` (decision D31).

This folder is a local git repository. Upstream clones (`spikes/src/`) and built binaries are
not in it; they can be made again.

## Read in this order

| File           | What it holds                                                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `INTERVIEW.md` | Every question put to the maintainer, both alternatives, his answer in his own words                                                     |
| `DECISIONS.md` | D1–D40 as rules; facts fixed without a question; calls made by the assistant                                                             |
| `report.md`    | The report of round 2. It is out of date: written before D11 was relaxed and before D23–D40. `003-cmdline.md` replaces it as the summary |
| `rules.md`     | Every rule of the consolidated library and layer, each tied to a test                                                                    |
| `drafts/`      | The change table for `001-cli.md` and the writer's notes for `003-cmdline.md`                                                            |

## The research, by round

| Round  | File                                                                                     | What it holds                                                                                     |
| ------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Briefs | `BRIEF.md`, `DEEP-BRIEF.md`, `PHASE-B.md`                                                | What the researchers were asked                                                                   |
| 1      | `requirements.md`                                                                        | 70 requirements from 001, the adapter contract, 27 gaps, 13 contradictions                        |
| 1      | `current-usage.md`                                                                       | What Headscale uses from cobra today; who depends on the syntax; PR #2647                         |
| 1      | `screen-cobra-urfave.md`, `screen-kong-goarg.md`, `screen-ff-command-mitchellh-gocmd.md` | First-pass screening of the listed projects                                                       |
| 1      | `discovery.md`                                                                           | About 35 other projects; what well-known Go CLIs use; who moved and why                           |
| side   | `man-pages.md`                                                                           | Man page layout, generator and shipping (D12–D14)                                                 |
| 2      | `spike-kit.md`                                                                           | The shared test kit: interface, cases, choices                                                    |
| 2      | `deep-cobra.md`, `deep-urfave.md`, `deep-kong.md`, `deep-creachadair.md`, `deep-own.md`  | One champion per finalist: desk research and an adapter against the kit                           |
| 2      | `referee.md`                                                                             | The independent check: real shells, kit v2, uniform numbers, fairness, cobra script bugs, ranking |
| 3      | `edge-corpus.md`                                                                         | 1,628 upstream tests and bug reports screened; 485 cases; what the own parser got wrong           |
| 3      | `differential.md`                                                                        | 3 million generated lines against pflag and cobra; fuzzing; the bugs found                        |
| 3      | `library-design.md`                                                                      | The parser as a reusable library: edge, API, proof, prior art, where it lives                     |
| 4      | `rules.md`                                                                               | The consolidated build and the complete rule list                                                 |

## The code and data

| Path                                                                        | What it is                                                                                    |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `spikes/kit`, `spikes/kit-v2`                                               | The test kit: 112 and 155 MUST cases                                                          |
| `spikes/cobra`, `urfave`, `kong`, `creachadair`, `own-grammar`, `own-pflag` | The six adapters as delivered, each with `RESULT.md`                                          |
| `spikes/v2`                                                                 | The referee's copies with fixes, and the real-shell harness (`spikes/v2/shell`)               |
| `spikes/corpus/corpus.jsonl`                                                | 485 upstream edge cases, each with its source; `inventory/` has all 1,628 rows with IN or OUT |
| `spikes/diff`                                                               | Differential harness and three fuzz targets                                                   |
| `spikes/lib`, `lib-headscale`, `lib-toy`                                    | The library prototype, its Headscale adapter, a second consumer                               |
| `spikes/final`                                                              | The consolidated build with every decision and every fix                                      |
| `spikes/probe-*`                                                            | Small proof programs from the desk research                                                   |

## What the copy in the pull request leaves out

The copy under `docs/proposals/research/` has all notes and all code. It leaves out only what can
be made again or what is already in the pull request:

| Left out                                                                                  | Why                                                                                                    |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `spikes/src/`                                                                             | Upstream clones; fetch them again                                                                      |
| Built binaries, and the links to them under `spikes/v2/shell/path*/`                      | Build them again with the scripts in `spikes/v2/shell/`                                                |
| `spikes/v2/modcheck/`                                                                     | `go.mod` and `go.sum` only, made by `go get` to measure module weight; the numbers are in `referee.md` |
| `spikes/corpus/results.tsv`, `spikes/diff/results/smoke.md`                               | Test output; run the tests again                                                                       |
| `drafts/001-cli.md`, `drafts/001-cli.orig.md`, `drafts/001.diff`, `drafts/003-cmdline.md` | They are `docs/proposals/001-cli.md` and `003-cmdline.md` and the git history                          |

Some notes name paths under `/home/kradalby/`. Those are the paths of the machine the work ran
on.

## What must not be lost when this folder goes

- The decisions and their rejected alternatives: they belong in the decision logs of 001 and 003.
- The corpus, the fuzz seeds and the Tab lines of the shell test: they are the tests of the library.
- The bugs found upstream (cobra's fish and bash scripts, pflag #541 and others): listed in the
  report and in `referee.md` section 4; none is reported upstream.
