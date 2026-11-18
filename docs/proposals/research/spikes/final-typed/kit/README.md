# spike/kit: the shared kit for the CLI framework bake-off

You write one adapter: a type that turns the kit's tree into your framework's
commands, parses argv with it, answers Tab, and writes completion scripts. The
kit does everything else and grades you. Standard library only.

| File          | What                                                                                                                                                                                              |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kit.go`      | The framework-free command layer: `Spec`, `Tree`, `Exec`, `UsageError`, the `Adapter` interface                                                                                                   |
| `specs.go`    | The tree: 12 leaves from 001 (`nodes list/delete/set`, `nodes routes set`, `users delete`, `auth keys create`, `api keys create`, `policy set`, `check config`, `version`, `completion`, `serve`) |
| `suite.go`    | The conformance cases and `Conformance`                                                                                                                                                           |
| `kit_test.go` | A null adapter (fails all) and a replay adapter (proves the expectations are reachable)                                                                                                           |

## The interface

```go
type Adapter interface {
    Run(ctx context.Context, t *Tree, argv []string, std Stdio) error
    Complete(ctx context.Context, t *Tree, argv []string) (Completion, error)
    Script(t *Tree, shell string, w io.Writer) error
}
```

Read `t.Commands` and nothing else. Each `Command` has `Path` (root is empty),
`Aliases`, `Leaf` (false = group), `Flags` and `Args`. Each `Flag` has `Name`,
`Short`, `Kind` (`Bool`, `String`, `Strings`), `Global` and `Values` (Tab
candidates). Each `Arg` has `Name`, `Optional`, `Values` and `File`.

**Run.** Parse `argv` (no program name). When the framework reaches a command,
call `t.Exec(ctx, std, Call{Path, Flags, Args})` exactly once and return its
error unchanged. When the framework refuses argv, return a `*kit.UsageError`
and call nothing.

- `Path`: the command reached, names or aliases (the kit resolves aliases).
- `Flags`: only flags that were **given**, by long name, with **every value in
  the order given**. A bool is `"true"` or `"false"` (`--force` → `"true"`,
  `--force=false` → `"false"`). Do not drop repeats and do not fill defaults:
  the kit refuses repeats itself (D6) and `--name ""` must arrive as `[""]`.
- `Args`: positionals in order, `--` removed, `-` kept.
- Help: on `-h`/`--help` anywhere, call `Exec` with that command's path and
  `Flags{"help": {"true"}}`. A group or the root with nothing after it: call
  `Exec` with its path and no flags (D10). `--version` on the root: `Exec` with
  `Flags{"version": {"true"}}`.
- Global flags (`-o`, `-c`; `Global: true`) may come before or after the
  subcommand (D3). They are listed on the root and on each leaf that takes
  them. Hand them to `Exec` with the leaf's flags; if the leaf does not take
  one, refuse it yourself or let `Exec` refuse it. `check config -o json`
  must end in `unknown-flag`, not run.
- An unknown word under a group: return `UsageError{UnknownCommand, pathSoFar, word}`,
  or pass it to `Exec` as `Args` of the group and the kit returns the same error.
- Usage error kinds you map framework errors to: `UnknownCommand`,
  `UnknownFlag`, `MissingValue`, `FlagRepeated`, `BadValue`. `Word` is the bad
  command word, or the flag as typed (`--exp`, `-r`). `Path` is where parsing
  stopped. The kit writes every error sentence (D4) and the "Did you mean"
  (D5), so give it these fields, not text.
- The framework writes nothing to `std`, never reads `std.In`, never calls
  `os.Exit`, and keeps no package-level state. Arg counts and value parsing
  are the kit's (R32): do not reject extra positionals.

**Complete.** `argv` is the words after the program name; the last one is
the word under the cursor (`""` for a new word). Return the candidates (a
`"\t"` and what follows is ignored) and `Files: true` when the shell should
offer files. This must be the same code the script reaches when it calls the
binary at Tab time (D1), driven in-process. It must not run a command
(`Exec`), read config or touch the network. Say in your notes how the script
calls the binary (`headscale __complete …` or whatever your framework uses).

**Script.** Write the script for `bash`, `zsh`, `fish` (required) and
`powershell` (stretch, D2). It must name `headscale`.

## Running

```
spikes/<name>/go.mod:   module spike/<name>
                        require spike/kit v0.0.0
                        replace spike/kit => ../kit
```

```go
func TestConformance(t *testing.T) {
    kit.Conformance(t, "<name>", myAdapter{}, "conformance.md")
}
```

```sh
cd /home/kradalby/worktrees/headscale/cli-restructure-proposal
nix shell nixpkgs#zsh nixpkgs#powershell -c nix develop -c bash -c \
  'cd "<notes folder>/spikes/<name>" && go test -count=1 ./...'
```

`nix shell` puts zsh and pwsh on `PATH`; without them those script rows are
SKIP, not FAIL. Add `CGO_ENABLED=1 go test -race` once: the suite runs every
case twice, all in parallel, with a fresh `Tree` and context each time.

`conformance.md` gets one row per case: ID, class, the requirement or
decision it comes from, argv, wanted and actual outcome, PASS / FAIL / SKIP /
SEEN. MUST failures fail the test; STRETCH and OBSERVE never do. Paste the
table into your notes.

## Classes

- **MUST**: decided by 001 or DECISIONS.md. A failure counts against you.
- **OBSERVE**: not decided. The row records what your framework does. Say in
  your notes what it would cost to get the other behaviour.
- **STRETCH**: wanted, not required.

For `-ojson` (F05, OBSERVE, D11): say what it costs to **refuse** it with
your framework, as well as whether it is accepted.

## What counts as cheating

- **Declared and counted:** any code that looks at or rewrites `argv` before
  the framework parses it (finding `-h`, splitting `-o=json`, moving global
  flags, inserting `--`). Mark every such line `// WA` and explain the block
  once above it. Same for code that re-parses what the framework already
  parsed, or post-processes its errors by matching message text.
- **Not allowed:** matching case IDs or specific argv strings from the suite;
  reaching into framework internals with `reflect` or `unsafe`; a hand-written
  parser inside a framework adapter that does the framework's job.
- Writing your own small `flag.Value` or error-mapping code is normal adapter
  work, not a workaround.

## Numbers every adapter reports

| Number                                  | How                                                                                                |
| --------------------------------------- | -------------------------------------------------------------------------------------------------- |
| MUST / STRETCH passed, OBSERVE recorded | first line of `conformance.md`                                                                     |
| Adapter lines                           | non-blank, non-comment lines of the adapter, tests excluded: `grep -cvE '^\s*(//.*)?$' adapter.go` |
| Workaround lines                        | `grep -c '// WA' adapter.go`                                                                       |
| Modules added                           | `cut -d' ' -f1 go.sum \| sort -u \| wc -l` (the kit adds none)                                     |
| Suite time                              | the `suite` figure on the first line, and `go test -count=1` wall time                             |
| Script bytes per shell                  | `wc -c` of each script                                                                             |

## v4 (`spikes/final-typed`)

Kit v4 is kit v3 with three functions added in `export.go`, and with D49 (`--output` takes only
`json`): rows E22, H20, P06 and P11 use `json` where they used `a` and `b`, rows J01–J13 are new,
and `Exec` refuses a `-o` that is not `json`.

- `Done(ctx, std, outcome)` is `Exec` for a layer that has done the builder's steps itself. It
  records and prints the outcome and checks nothing. The layer on the typed library uses it:
  repeats, bool words, lists and the argument count are the library's there, and `Exec` would
  hide any of them that the library missed.
- `Raw(ctx, call)` hands the differential harness the line as it was read, as `Exec` does.
- `Sh(line)` is the suite's line splitter.

`Exec` and the kit's own specs stay for the adapters of the other parsers. The typed layer has the
same tree as typed specs; its `TestTwin` holds the two together.
