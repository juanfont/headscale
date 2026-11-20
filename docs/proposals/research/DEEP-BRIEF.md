# Deep research brief (round 2)

Read `BRIEF.md` (context, evidence rules, house rules), `requirements.md` (R01–R70, the adapter
contract, gaps, contradictions), `DECISIONS.md` (the maintainer's answers; they are requirements
now) and the screening notes for your candidate in this folder. `current-usage.md` and
`discovery.md` have the migration surface and what other projects did.

Finalists: spf13/cobra (+pflag), urfave/cli v3, alecthomas/kong, creachadair/command (+flax),
and "our own parser" (no framework). Each has its own researcher. You own one.

Your job has two phases.

**Phase A (now): desk research with probes.** Answer the questions below for your candidate with
primary evidence. Where a claim is about behaviour, prove it with a small throwaway Go program in
`spikes/probe-<candidate>/` (its own module; run go inside `nix develop -c` from
`/home/kradalby/worktrees/headscale/cli-restructure-proposal`, with `cd` to your module inside the
command). Reading the source of the framework is expected: clone it under `spikes/src/` if that
helps.

**Phase B (later, by a second message): the adapter spike.** A shared test kit is being built
at `spikes/kit`. You will be told when it is ready. Then you write one adapter for your candidate
and run the kit's conformance suite. Do not start Phase B before that message.

## Questions for every candidate

1. **Parsing, exactly.** Go through "2. The adapter contract" in `requirements.md` and every
   decision in `DECISIONS.md` item by item: native, possible with a setting, possible with
   code of ours (how much), or not possible. Give the proof.
1. **Completion (D1, D2).** How does the binary answer at Tab time? Which shells? What does the
   user see: descriptions, no trailing space where needed, file completion, values per flag,
   comma lists (`--columns id,na<Tab>`)? What is ours to write, in lines? PowerShell is a stretch.
1. **Errors (D4).** What does a parse failure give us: a typed error with fields, or a string?
   Can we get the unknown word and the path so far without parsing the message text?
1. **Staying out of the way.** Can everything automatic be switched off or replaced: help
   output, the `help` command, `--version`, a `completion` command, suggestions, usage printed on
   error, `os.Exit`, environment binding, sorting, global state? What can not?
1. **Global flags before and after the subcommand (D3)**, while a command without `--output`
   still refuses `-o`.
1. **Risk.** Who maintains it, how many people can release, how releases and breaking changes
   went in the last three years, security history, the Go version floor, the dependencies. If
   it was abandoned tomorrow: how many lines would we own in a fork, or how hard is the way out
   given that only one adapter file imports it?
1. **Evidence from others.** Projects that use it at scale, moved to it or left it, with the
   reasons they gave (link the PR, issue or RFC). Open bugs that would hit us.
1. **Migration.** From today's cobra CLI to this candidate, behind the adapter: what changes for
   a user who types the same commands (flag syntax, error text aside), for nixpkgs (which runs
   `headscale completion bash|fish|zsh` at build time), and for the 128 `headscale` calls in the
   integration tests.

## Output

Notes at `deep-<candidate>.md` in this folder: the answers, a table "requirement → native /
setting / our code (lines) / no", the three strongest reasons for and against, the risks, and
"Open questions for the maintainer" (two alternatives each, with cost). Be hard on your own
candidate: the reader wants to know what will hurt in two years. Final message back: 10 lines at
most.
