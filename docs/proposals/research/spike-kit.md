# Spike kit: shared test kit for the CLI framework bake-off

Date: 2026-11-17. Code: `spikes/kit` (module `spike/kit`, Go 1.27.3, standard library only).
Adapter guide: `spikes/kit/README.md`.

## What the kit is

| Part                                                                                                          | File          | Size (lines) |
| ------------------------------------------------------------------------------------------------------------- | ------------- | ------------ |
| Command layer: `Spec[In]`, `Tree` (flat description), `Exec` (the builder, cut down), `UsageError`, `Adapter` | `kit.go`      | ~440         |
| The tree: 12 leaves, 9 groups from 001                                                                        | `specs.go`    | 80           |
| Conformance suite, Markdown table, `Conformance(t, name, adapter, mdPath)`                                    | `suite.go`    | ~520         |
| Null adapter, replay adapter, `Exec` unit checks                                                              | `kit_test.go` | ~125         |

Verified: `go vet` clean; `go test` passes; `CGO_ENABLED=1 go test -race -count=3` passes; with
`nix shell nixpkgs#zsh nixpkgs#powershell` all four script syntax checks run (bash, fish are on
PATH already; zsh, pwsh are not). The null adapter fails every MUST except I01. The replay adapter
(answers each case with its own expected outcome through `Exec`) passes 112/112 MUST and 4/4
STRETCH, which shows that every expected outcome can be reached through `Exec`. A
toy sibling module with `replace spike/kit => …` builds and writes its table.

## The interface as written

```go
type Adapter interface {
    Run(ctx context.Context, t *Tree, argv []string, std Stdio) error
    Complete(ctx context.Context, t *Tree, argv []string) (Completion, error)
    Script(t *Tree, shell string, w io.Writer) error
}

type Command struct { Path, Aliases []string; Leaf bool; Flags []Flag; Args []Arg }
type Flag    struct { Name, Short string; Kind Kind; Global bool; Values []string } // Kind: Bool, String, Strings
type Arg     struct { Name string; Optional bool; Values []string; File bool }
type Call    struct { Path []string; Flags map[string][]string; Args []string }
type UsageError struct { Kind ErrKind; Path []string; Word string }
  // UnknownCommand, UnknownFlag, MissingValue, FlagRepeated, BadValue; ArgCount (kit only)
type Completion struct { Words []string; Files bool }

func (t *Tree) Exec(ctx context.Context, std Stdio, c Call) error
```

The adapter reads `Tree.Commands`, builds its framework tree, parses, and calls `Exec` once
from the framework's action. `Exec` owns everything 001 gives our layer: flag-belongs-to-command
(so a global `-o` on `check config` is refused here, D3), repeats (D6), bool values (D9), help
and `--version` dispatch, group-alone-is-help (D10), argument count (R32), filling the input
struct, calling `Run`. Every `Run` only records its filled input.

How the suite sees a framework's behaviour without trusting the adapter's word:

- The context carries a per-run recorder. `Exec` refuses a context without it, so the framework
  (or adapter) must pass the caller's context through.
- `Exec` writes one line to the `Stdio.Out` it is given; the suite checks stdout is exactly that
  line and stderr is empty. A framework that prints help, usage or errors itself fails.
- Stdin is a reader holding `"y\n"`; it must be unread after the run.
- Every case runs twice, all cases in parallel, a fresh `Tree` each time. Different outcomes or
  a panic fail I01.

"Was this flag given": two layers. At the adapter boundary a flag is in `Call.Flags` only when
given, with every value (so `--name ""` is `{"name": [""]}`). In the input struct an optional
flag is a `*string` field: nil when not given, `&""` for `--name ""`. `TestExec` checks both.

## Cases by class

MUST 112 (91 run, 17 completion, 3 scripts, 1 isolation), STRETCH 4, OBSERVE 13.

| Group                     | MUST                                                                                                                                                                                                                                                                                                                                                                                                      | STRETCH                                                              | OBSERVE                                                                                  |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Tree, aliases, groups (T) | T01–T15: 3-level leaves, `approve`/`rm`/`ls`, alias only where declared, `headscale`, `nodes`, `nodes routes`, `check` alone = help (D10)                                                                                                                                                                                                                                                                 |                                                                      |                                                                                          |
| Help (H)                  | H01–H13: `-h`/`--help` at root, group, 3-level leaf, through an alias, with no target (beats arg count), after args; `help`, `help nodes`, `nodes help` = unknown command (D8)                                                                                                                                                                                                                            |                                                                      | H14–H17: `-h` with an unknown flag before/after it, `nodes --help list`, `-h nodes list` |
| Version (V)               | V01 `--version` (D7), V02 `version`, V03 `version -o json`                                                                                                                                                                                                                                                                                                                                                |                                                                      | V04 `nodes list --version`                                                               |
| Flag syntax (F)           | F01–F04, F06–F25: `--f v`, `--f=v`, `-o json`, `-o=json` (D11), `-e`, flags before/after/between positionals, `--name ''`, `--name=`, not-given stays absent, `--sort -last-seen`, `--sort=-last-seen`, `--columns -ip`, `-ip,+hostname`, `--filter=owner=tag:ci`, three `--filter` in order, `policy set -`, `***` in a positional, `''` positional, `--` then `--with-nodes`, `--force -- -alice`, `-u` |                                                                      | F05 `-ojson` (D11), F26 `--name -e`, F27 `--sort --filter x`, F28 `-ho json`             |
| Bool forms (B, D9)        | B01 `--force=true`, B02 `--force=false`, B03 `--no-force` = unknown flag                                                                                                                                                                                                                                                                                                                                  |                                                                      | B04 `--force=maybe`, B05 `--force --force`                                               |
| Globals (G, D3)           | G01–G10: `-c`/`-o`/`--config=` before and after the subcommand, after leaf positionals, both before one leaf; `-o` on `check config` before or after = unknown flag; `-c` on `completion`, `-o` on `serve` = unknown flag                                                                                                                                                                                 |                                                                      | G11 `-c /a nodes list -c /b`                                                             |
| Lists (L, D6)             | L01 `--tags a,b` verbatim, L02 `--tags` twice = repeated, L03 `-o` twice = repeated                                                                                                                                                                                                                                                                                                                       |                                                                      |                                                                                          |
| Usage errors (E, D4/D5)   | E01–E20: unknown command at root, level 1, level 2, after `-c`; old names `preauthkeys`, `node`; reserved `nodes authorize`; unknown long flag, `--force` where it does not exist, unknown short `-r`, abbreviation `--exp`; missing value at end of argv for long, short, global; arg count (too many, none, one of two, at most, none allowed): framework must not decide                               |                                                                      | E21 `--bogus nodes list` (which path?)                                                   |
| Completion (C, D1)        | C01–C17: commands at each level, prefix, alias `approve`, after `-c /x`, flag names per leaf (and absence of foreign ones), values for `-o`, `--columns`, `--sort`, `--filter`, `completion <shell>`, files for `policy set` and `check config`; no command runs on any completion                                                                                                                        | C18 `id,na`→`id,name`, C19 `+ho`→`+hostname`, C20 `-la`→`-last-seen` |                                                                                          |
| Scripts (S, D1/D2)        | bash, zsh, fish: non-empty, names `headscale`, `<shell> -n` passes (SKIP when the shell is missing)                                                                                                                                                                                                                                                                                                       | powershell: parsed by pwsh's parser                                  |                                                                                          |
| Isolation                 | I01: every case same outcome twice, in parallel, no panic                                                                                                                                                                                                                                                                                                                                                 |                                                                      |                                                                                          |

D9–D11 arrived mid-work and are folded in: `--force=true/false` MUST, `--no-force` MUST
unknown, group alone = help MUST, `-o=json` MUST, `-ojson` OBSERVE with a README request to
report the cost of refusing it. D12 (man pages) has no effect on the kit.

## Choices the maintainer did not make

1. **Optional flags are `*string` fields** (nil = not given). 001's field table has no such
   type (C5). Alternative: a given-bit in `Ctx`.
1. **Spec has `Output` and `Config` bools** to say who gets `-o`/`-c` (C6). 001 has no field.
1. **`Use` holds the full path** (`"nodes routes set <node> <routes>"`), groups are implied;
   001 nests groups as objects. Flat is shorter and changes nothing an adapter sees.
1. **A `complete:"file"` / `complete:"a b c"` struct tag** gives positional Tab values. 001 has
   no tag for it. Help text tags are dropped: adapters must not need them.
1. **Every flag except `--filter` may be given once**, bools and `-c` included. D6 says so for
   list flags; the task said so for `-o`; the kit applies it to all. `--force --force` and
   `-c` before and after stay OBSERVE because they hit this choice.
1. **The kit, not the framework, refuses** flags not on the command, repeats, bad bools and
   wrong arg counts. An adapter may refuse earlier with the same `UsageError`; both pass.
   This keeps frameworks with persistent flags (cobra, urfave) and per-level flags (stdlib
   style) on equal terms.
1. **`-h` wins over every kit check** (R53 extended to kit refusals). When the framework errors
   before it sees `-h`, that is OBSERVE (H14–H17).
1. **A group given extra words** may be handed to `Exec` as args; the kit turns the first into
   `unknown-command`. So "unknown command" does not depend on how the framework treats groups.
1. **A global flag on a group** (`headscale -c x nodes`) is ignored by the kit; outcome is help.
1. **Alias completion is MUST** (C05 `nodes routes ap` → `approve`). R60 had "aliases?".
1. **Completion after a global flag is MUST** (C07), from D1 + D3.
1. **`--filter` value completion is plain column names** (MUST); operator-aware completion is
   not tested.
1. **File completion is checked only where wanted**; offering files elsewhere is not penalised.
1. **Script check is syntax only** plus "names headscale". No case drives the script through a
   shell to the binary; adapters must state the entry point (`__complete` or other).
1. **`arg-count` wording for zero-arg commands** is `takes no arguments, got N` (001 shows none).
1. **Error sentences in `UsageError.Error()` are placeholders.** The kit does not implement
   "Did you mean" (D5) or the old-name table; the suite only checks the adapter hands over kind,
   path and word. Unknown-flag words are normalised (`--exp=1` → `exp`, `-o` → `output`) before
   comparing, so frameworks need not agree on dashes.
1. **Exit codes are not tested**: `main` maps errors to 1; adapters never exit.
1. **Completion candidates may carry `\t description`**; the suite strips it.
1. **Unknown shell for `Script`** is not tested.

## Open questions for the maintainer

1. **Repeat rule beyond list flags.** `--force --force`, `-c a nodes list -c b`. (a) Every
   non-`--filter` flag once, as the kit does now: one rule, strict; costs a custom value type in
   pflag-style frameworks, which default to last-wins. (b) Only list flags and `-o` are strict,
   others last-wins: matches pflag habits; costs two rules to document and test.
1. **A value that looks like a flag** (`--name -e`, `--sort --filter x`). (a) Always a value
   (pflag today): `--sort -last-seen` works the same way; a forgotten value silently eats the
   next flag. (b) A known flag name is never a value → `missing-value`: safer; costs an adapter
   check in most frameworks and breaks the symmetry with `-last-seen`.
1. **`-h` together with an error** (`nodes list --bogus -h`). (a) Help wins (R53 read widely):
   friendly; some frameworks stop at the first error, so adapter code. (b) First error wins:
   no adapter code; help hides behind a typo.
1. **`--version` below the root** (`nodes list --version`). (a) Unknown flag: one place, matches
   D7's wording. (b) Accepted anywhere (persistent): free in cobra; a second meaning to test.
1. **Aliases in Tab results.** (a) Offer `ls`, `rm`, `approve` (kit MUST now): every valid word
   completes. (b) Names only: shorter lists; `approve` users get nothing on `ap<TAB>`.
1. **Spec fields for `--output` and `--config`** (C6). (a) Explicit bools as in the kit:
   one line per spec. (b) Derived (`!Local` → output, plus a list of exceptions): no field;
   costs exceptions for `version`, `debug health`, `check`.
1. **Optional flag type** (C5). (a) `*string` / `*time.Time` fields: plain Go, nil = not given.
   (b) `command.Opt[T]` with `Given bool`: reads better in `Run`; one more kit type.
1. **End-to-end completion test.** (a) Syntax check only (kit now): cheap, no TTY. (b) Drive
   each script in its shell against a built binary: proves D1 for real; slower, needs bash, zsh,
   fish in CI.
