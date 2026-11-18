# Deep research: urfave/cli v3 (Phase A)

Date of work: 2026-11-17. Version under test: `github.com/urfave/cli/v3` **v3.14.0** (2026-10-02, latest
tag). Source read at the v3.14.0 tag and at `main` (d5c06cb, 2026-11-10; 163 commits not yet released).
Clone: `spikes/src/urfave-cli`. Probes: `spikes/probe-urfave/` (`main.go` argv table, `probe2_test.go`
hooks + `-race` parallel test, `cmd/hs` real binary, `bash-harness.sh` drives the real bash completion
function with bash-interactive 5.3 + bash-completion 2.17; fish 4.9.3 driven with `complete -C`).
Run: `nix develop -c bash -c 'cd spikes/probe-urfave && go run . && CGO_ENABLED=1 go test -race -v .'`.
zsh and pwsh were **not executed** (not installed); their behaviour below is from reading the scripts.

## Verdict in one paragraph

urfave/cli v3 parses everything Headscale needs (it refuses `-ojson`, which D11 now asks for), and every
automatic behaviour can be switched off, with one package-global write (`cli.HelpFlag = nil`). It is weak
exactly where D1 and D4 put weight. **Completion** is a thin hook plus four basic scripts: the binary does
answer at Tab time, but the script does not send the word under the cursor unless it starts with `-`, there
are no directives (no-space, no-file), `token:description` breaks on any value that contains `:`, bash falls
back to filenames everywhere, and fish never completes filenames. Per-flag values cost us ~40 lines, but
comma lists, `--flag=<Tab>` and values starting with `-` cannot be done without replacing the scripts.
**Errors** are `fmt.Errorf` strings with no `%w` and no types. The flag word is only available by parsing
the message text, and that text changes inside v3.x minors. OpenTofu, the one big adopter, kept
posener/complete for completion and parses error text too. Against: velocity is high and a v4 rewrite is
planned. For: zero dependencies and an active fix stream.

______________________________________________________________________

## 1. Parsing, exactly (adapter contract + decisions)

### How the v3 parser works

v3 no longer uses the standard library's `flag`: removed in v3.1.0 ("Remove dependency on golang flag library",
[#2074](https://github.com/urfave/cli/pull/2074)). The parser is one hand-written loop,
`(*Command).parseFlags` in [`command_parse.go`](https://github.com/urfave/cli/blob/v3.14.0/command_parse.go)
(~300 lines). It runs **once per command level**. It walks the words and collects positionals. When a
positional matches a subcommand name, it hands the rest of the words to that subcommand
(`cmd.Command(firstArg) != nil`). Flags known at a level = the command's own flags + ancestors' flags
that are not `Local` (persistent is the **default**: `Local: false`).

Rules read from the source and confirmed by the probe (`main.go` sections A–H):

| Input                                                              | v3.14.0 behaviour                                                                                                                                                                                                                                                                   | Probe  |
| ------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| `--flag v`, `--flag=v`                                             | both work                                                                                                                                                                                                                                                                           | B      |
| `-o json`, `-o=json`                                               | work                                                                                                                                                                                                                                                                                | B      |
| `-ojson`, `-e90d`                                                  | **error** `flag provided but not defined: -ojson`, with or without `UseShortOptionHandling`. Grouping treats every rune as a flag name; no "rest is the value" rule                                                                                                                 | B      |
| value starting with `-` (`--sort -last-seen`, `--columns -ip,-os`) | taken as the value: a non-bool flag always eats the next word                                                                                                                                                                                                                       | B      |
| `--name ""` vs not given                                           | `IsSet()=true, ""` vs `IsSet()=false`                                                                                                                                                                                                                                               | B      |
| `--name=`                                                          | `IsSet()=true, ""`                                                                                                                                                                                                                                                                  | B      |
| `--filter=owner=tag:ci`, `'last-seen>30d'`                         | verbatim (split on first `=` only)                                                                                                                                                                                                                                                  | B      |
| `StringFlag` given twice                                           | last wins silently; `Count()` = 2. `OnlyOnce: true` → error `invalid value "b" for flag -sort: can't duplicate this flag`                                                                                                                                                           | B      |
| `StringSliceFlag` repeated                                         | accumulates in order, **but also splits on `,`** unless `DisableSliceFlagSeparator` is set **on the parsing command**. In v3.14.0 the setting is **not inherited** from root (fixed on main 2026-10-11, unreleased): `--filter name:web,online=true` became two values in the probe | B      |
| flags after / between positionals                                  | yes (v3 default); `StopOnNthArg` restores v2's stop-at-first-arg                                                                                                                                                                                                                    | B      |
| `--`                                                               | ends flags; rest positional (`nodes delete -- -x` → `["-x"]`)                                                                                                                                                                                                                       | C      |
| `-` alone                                                          | positional                                                                                                                                                                                                                                                                          | C      |
| `""` positional                                                    | kept (`routes set 12 ""` → `["12",""]`)                                                                                                                                                                                                                                             | C      |
| `-5 --force` (dash + non-letter)                                   | **silently stops flag parsing for the rest of the line**: args `["-5","--force"]`, force not set. On main this changes again (#2474, unreleased)                                                                                                                                    | C      |
| `" --force"` (leading space)                                       | **parsed as the flag** `--force` (`strings.TrimSpace` before the classification)                                                                                                                                                                                                    | C      |
| bool `--force`                                                     | true; does **not** eat a following `false` (that becomes a positional)                                                                                                                                                                                                              | C      |
| bool `--force=false` / `=true`                                     | works; `--force=maybe` → `invalid value "maybe" for flag -force: parse error`                                                                                                                                                                                                       | C      |
| bool `--force=`                                                    | v3.14.0: **true**; main (unreleased): error ("reject explicit empty boolean flag values")                                                                                                                                                                                           | source |
| abbreviations `--exp`                                              | rejected (no prefix matching for flags). `PrefixMatchCommands` is off by default                                                                                                                                                                                                    | B      |
| `--no-x`                                                           | only with `BoolWithInverseFlag`; plain `BoolFlag` has none                                                                                                                                                                                                                          | source |
| env vars                                                           | none unless a flag has `Sources`; nothing binds by convention                                                                                                                                                                                                                       | source |
| arg count                                                          | none unless `Command.Arguments` or `ArgValidator` is set                                                                                                                                                                                                                            | source |
| `-h` / `--help` anywhere                                           | with our own flag: visible as set in the leaf; but a parse error **before** it wins (`list --bogus --help` → unknown flag). Same as cobra                                                                                                                                           | F      |
| `--sort x --sort --help`                                           | `--help` eaten as the value of `--sort` (same as pflag)                                                                                                                                                                                                                             | probe2 |

### Contract items and decisions

| #         | Requirement                                                                     | urfave v3.14.0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Proof / cost                                                                             |
| --------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| C1        | Command at a path, name, aliases, group vs leaf, built at runtime               | **native**: `&cli.Command{Name, Aliases, Commands, Action}` literals; a loop over specs                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | A: 3 levels, `rm`/`ls`/`approve` aliases, hyphen names, same leaf name under two parents |
| C2        | Flags per leaf: bool, string (`""`, `-x`, `=:<>,`), repeatable string           | **native** (`BoolFlag`, `StringFlag`, `StringSliceFlag`). Repeatable needs `DisableSliceFlagSeparator` **on every command** (not inherited in 3.14.0); or a 30-line own `Flag` type (the interface is 7 methods)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | B                                                                                        |
| C3        | Values + "given" bit + args in order, interspersed, `-`, `--`, no typing        | **native** (`Flag.IsSet()`, `Count()`, `Get()`, `cmd.Args()`). Exceptions: `-5` stops parsing; leading-space word becomes a flag                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | B, C                                                                                     |
| C4        | One callback, ctx, streams, error back without print/exit                       | **setting**: `Action` per leaf, `Writer`/`ErrWriter`/`Reader` on root (inherited since v3.9.1), `ExitErrHandler: noop` on root (else `HandleExitCoder` → `OsExiter` = `os.Exit` for `ExitCoder` errors)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | probe never exited; `-race` parallel pass                                                |
| C5        | Help to us; typed parse errors                                                  | help: **setting + 1 global write** (see §4). Errors: **no**: strings only (§3). Our classifier on message text: ~25 lines, breaks when wording changes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | F, D                                                                                     |
| C6        | Completion scripts with per-flag values, files, comma lists                     | **partial** (§2). Per-flag values ~40 lines on top; comma lists / `--x=<Tab>` / `-`-prefixed values / no-space / per-arg file completion: **not possible with the shipped scripts**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | bash + fish runs                                                                         |
| C7        | Fresh tree per run, no package state, parallel                                  | **native with care**: fresh tree per run required. Reusing one tree leaks `IsSet` into the next run (H: second run sees `sort` set to `""`; fixed on main "parse flags from scratch when a command is run again", unreleased). Parallel fresh trees pass `-race` with `cli.HelpFlag = nil` set once in `init`                                                                                                                                                                                                                                                                                                                                                                                     | H, `TestParallel`                                                                        |
| D1        | Binary answers at Tab                                                           | **native, weaker protocol**: the script appends `--generate-shell-completion`; `ShellComplete(ctx, cmd)` runs on the deepest command matched                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | §2                                                                                       |
| D2        | bash, zsh, fish (+pwsh)                                                         | **native**: four embedded scripts                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | §2                                                                                       |
| D3        | `-c`/`-o` before and after the subcommand; leaf without `--output` refuses `-o` | **setting + our code (~10 lines)**. Persistent flag on root: `-c x nodes list`, `nodes list -c x`, `nodes -c x list` all work, **and** `check config -o json` parses, so our layer refuses using `IsSet`. Alternative: `Local` on root + local `-o` on server leaves: `check config -o json` → native unknown flag, but `-o json check config` still parses at root (needs the same check) and `nodes -c x list` errors. Either way we cannot tell whether the user typed `-o` or `--output` for our error text without scanning argv                                                                                                                                                             | E, E2                                                                                    |
| D4        | Inspectable errors                                                              | **no**: see §3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | D                                                                                        |
| D5        | Our "did you mean" + old-name table                                             | **our code (~15 lines)**: unknown words land in the group's own `Action` as `cmd.Args()` (A: `node ls` → root Action args `["node","ls"]`). When an unknown flag follows the unknown word, `OnUsageError` on that group gets `cmd.Args()=["frob"]` (probe2), so "unknown command" can win                                                                                                                                                                                                                                                                                                                                                                                                         | A, probe2                                                                                |
| D6        | Comma lists; only `--filter` repeats; repeated list flag errors                 | **our code (~5 lines)**: `Count() > 1` → our error. (`OnlyOnce` exists but its text is fixed)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | B                                                                                        |
| D7        | `--version` prints the line only                                                | **our code (~5 lines)**: own `BoolFlag{Name:"version", Local:true}` on root; built-in disabled by `HideVersion` or empty `Version`. `nodes list --version` → unknown flag (Local)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | F                                                                                        |
| D8        | No `help` command                                                               | **setting**: `HideHelp: true` removes the command and the flag; `help` then reaches our Action as a positional                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | A                                                                                        |
| fixed     | exit 1 on usage error                                                           | ours: the error comes back from `Run`; we pick the code. The one built-in exit-3 path (`No help topic for 'x'`) is only reached through the default help action, which we replace                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | source `help.go`                                                                         |
| fixed     | no abbreviations                                                                | native                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | B                                                                                        |
| fixed     | `--` POSIX                                                                      | native                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | C                                                                                        |
| fixed     | mixed flags and positionals                                                     | native                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | B                                                                                        |
| R16 / D11 | `-ojson`, `-e24h`                                                               | **native refusal**, which D11 (decided after Phase A started) makes the target: `unknown flag`. Accepting it would need a ~30-line argv pre-pass                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | B                                                                                        |
| R21       | values starting with `-`                                                        | native                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | B                                                                                        |
| R23/R24   | `""` vs not given; set bit per flag                                             | native                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | B                                                                                        |
| R31       | unknown flag → error                                                            | native, text `flag provided but not defined: -force` (**one dash even for `--force`**)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | D                                                                                        |
| R32/R33   | no framework arg counting / required flags                                      | native (don't set `Arguments`/`Required`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | source                                                                                   |
| R36/R38   | all output to our writers, no print on error                                    | **setting on every command**: `OnUsageError` is **not inherited**. Without it on the leaf, `nodes list --force` writes `Incorrect Usage: …` to ErrWriter (B/D rows show it). The adapter's loop sets it per command (1 line)                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | D, probe2                                                                                |
| R49       | build twice, no "already registered"                                            | native (fresh literals); duplicate flag names on one command now **fail `Run`** with an error (v3.14.0 #2396)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | source                                                                                   |
| R51–R53   | help ours, root no-arg, group without leaf                                      | setting: root/group `Action` receives control; `HideHelp`; `cli.HelpFlag = nil` (else **any** flag named `help` on a command triggers the framework's help printer: probe F printed urfave's template for `--help nodes` until this was set)                                                                                                                                                                                                                                                                                                                                                                                                                                                      | F, probe2                                                                                |
| R56       | in-process, parallel                                                            | native with fresh tree; `Reader` injectable; no TTY abstraction (ours)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `TestParallel`                                                                           |
| R59       | `completion <shell>`                                                            | native hidden command; renamable (`ConfigureShellCompletionCommand`). The script renderers are **unexported**, so our own `completion` spec (for help/reference from specs) must either run the hidden urfave command into a buffer or copy the 4 scripts (MIT, ~250 lines)                                                                                                                                                                                                                                                                                                                                                                                                                       | probe2                                                                                   |
| R61       | Tab never calls the server                                                      | native: completion mode returns before `Action`. **`Before` hooks still run in completion mode** (`runBefore` precedes `runCompletion`); we use none                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | source `command_run.go`                                                                  |
| R63       | no env binding                                                                  | native                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | source                                                                                   |
| G26       | no package state                                                                | 1 global write (`HelpFlag`). Other mutable globals exist but are untouched: `OsExiter`, `ErrWriter`, `HelpPrinter`, `HelpPrinterCustom`, `VersionPrinter`, `ShowRootCommandHelp`, `ShowCommandHelp`, `ShowSubcommandHelp`, `HelpFlag`, `VersionFlag`, `GenerateShellCompletionFlag`, `FlagStringer`, `FlagNamePrefixer`, `FlagEnvHinter`, `FlagFileHinter`, `SuggestFlag`, `SuggestCommand`, the three help templates, `DefaultInverseBoolPrefix`. v3.14.0 `DefaultCompleteWithFlags` at the root reads **`os.Args`**, not the args given to `Run` ([#2486](https://github.com/urfave/cli/issues/2486), fixed on main, unreleased): in-process completion tests of the root are wrong until v3.15 | source                                                                                   |

## 2. Completion (D1, D2): what the scripts really do

**Mechanism.** `EnableShellCompletion: true` on root does two things. It adds a hidden `completion {bash,zsh,fish,pwsh}` command, and it makes `Run` treat a **last** argument `--generate-shell-completion`
as a completion request ([`help.go` checkShellCompleteFlag](https://github.com/urfave/cli/blob/v3.14.0/help.go)).
The marker is stripped and parsing runs in "completion mode". Unknown flags, value-less flags and incomplete
groups are kept as positionals instead of raising errors. Then `ShellComplete(ctx, cmd)` of the deepest
matched command runs. That function **prints lines** `token` or `token:description` to `Root().Writer`.
There is no return value, no directive and no per-flag hook (`Flag` has only `TakesFile`, which the dynamic
scripts ignore; the static `ToFishCompletion` generator uses it). The upstream request for per-flag
completion, [#1905](https://github.com/urfave/cli/issues/1905), was closed unimplemented on 2026-09-27 in a
stale sweep.

**What `ShellComplete` sees** (probe G2): `cmd.Args()` = the leftover words. A trailing value-less flag is
kept (`list --sort <Tab>` → `["--sort"]`), so value completion is possible. But a flag whose value was
already typed has consumed it: `--sort -la<Tab>` → `[]`, `--sort = <Tab>` → `[]`, `--columns id,na<Tab>` →
`[]`. The partial word is lost unless we re-scan the raw argv ourselves.

**What the scripts send and do** (read + bash/fish runs; table from `bash-harness.sh` and `fish complete -C`):

| Line + Tab                                   | bash (stock script + our 40-line value completer)                                                                                           | fish                                                              | cobra (for comparison, from its scripts/protocol)                               |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `hs nodes `                                  | `list delete`; 2nd Tab shows `list -- list nodes`                                                                                           | with descriptions                                                 | same, descriptions from `Short`                                                 |
| `hs nodes list --`                           | flag names (persistent included since 3.14.0)                                                                                               | with descriptions                                                 | same                                                                            |
| `hs nodes list --sort `                      | `id name owner last-seen`                                                                                                                   | same                                                              | same via `RegisterFlagCompletionFunc`                                           |
| `hs nodes list --sort la`                    | `last-seen` (shell filters; app never sees `la`)                                                                                            | same                                                              | app sees `la`                                                                   |
| `hs nodes list --sort -la`                   | **nothing**                                                                                                                                 | **nothing**                                                       | handled (`-la` sent as toComplete)                                              |
| `hs nodes list --sort=`                      | **nothing**: bash splits `=` into its own word and sends `--sort =`; parser takes `=` as the value                                          | **nothing**                                                       | handled (`--flag=` prefix special-cased in bash v2 script and `completions.go`) |
| `hs nodes list --columns id,`                | **nothing**, then readline falls back to **filenames** (`complete -o default`)                                                              | nothing                                                           | app sees `id,` and can answer `id,name …` with NoSpace                          |
| `hs check config `                           | empty reply → bash default = **filenames** (wanted)                                                                                         | **nothing**: script registers `complete -f` (files never offered) | `ShellCompDirectiveDefault` → files                                             |
| `hs nodes delete `                           | empty → **filenames** (unwanted)                                                                                                            | nothing                                                           | `NoFileComp` directive                                                          |
| value with `:` (`tag:ci`, `owner=tag:ci`)    | bash/fish/pwsh split each line at the **first `:`**, so `tag:ci` becomes token `tag`, description `ci`; zsh `_describe` needs `\:` escaping | same                                                              | `value\tdescription` (tab), no conflict                                         |
| no trailing space (`id,`, `--filter owner=`) | not possible (no `compopt -o nospace`)                                                                                                      | n/a                                                               | `ShellCompDirectiveNoSpace`                                                     |

Script specifics (v3.14.0 `autocomplete/`):

- **bash**: sends `words_before_cursor` + current word only if it starts with `-`. Runs it via `eval`, as
  cobra does. Needs the bash-completion package (`_comp_initialize`/`_get_comp_words_by_ref`), as cobra's
  v2 script does. Filters with `compgen -W` and registers `complete -o bashdefault -o default`.
  Descriptions are shown on the second Tab (since v3.9.0).
- **zsh** (not run): uses `words[-1]` (the **last word of the line**, not the word under the cursor), so
  completing mid-line is wrong. `_describe 'values' opts` on `token:desc`; empty output → `_files`.
- **fish**: sends the current token only if it starts with `-`. `complete -c X -f`, so never files.
  Fish sorts candidates itself.
- **pwsh** (not run): `Invoke-Expression "<line> --generate-shell-completion"`, splits on the first `:`.

**What is ours, in lines.**

- (a) Stay on urfave's scripts: one `ShellComplete` set on every command. It looks at the last word of
  `cmd.Args()`, finds the flag in the lineage and prints our value list; otherwise it defers to
  `cli.DefaultCompleteWithFlags`. **~40 lines** (`cmd/hs/main.go` is 30). It fits their model. We give
  up comma lists, `--flag=<Tab>`, values starting with `-` (bad for `--sort -<col>`, R21/R60), choosing
  files per argument, and values containing `:` (blocks R62's live tag/user names later).
- (b) Replace the scripts and keep urfave for parsing only. Vendor cobra's four scripts (Apache-2.0)
  and answer cobra's `__complete` protocol ourselves before `Run` (Tailscale's `ffcomplete` pattern:
  ~200 lines Go + ~900 lines of copied script). urfave then contributes nothing to completion, and the
  `__complete` handler must find the leaf and the flag before the cursor itself, which is a second
  small parser over our spec tree.
- (c) Write our own scripts against urfave's `--generate-shell-completion`: we would own three shells'
  scripts, worse than (b).

Honest comparison: cobra's `__complete` sends every word including the current one (an empty `''` when the
cursor is after a space), reads `value\tdescription`, and ends with `:<directive>` bits (Error, NoSpace,
NoFileComp, FilterFileExt, FilterDirs, KeepOrder), plus ActiveHelp
([completions.go](https://github.com/spf13/cobra/blob/v1.10.2/completions.go), `bash_completionsV2.go`
L57–80 handles `--flag=`). urfave's protocol is a subset that loses the current word, has no directives,
and uses a separator (`:`) that real values contain. The bash-completion maintainer said so on
2026-08-07: "IME, spf13/cobra is much better regarding shell completions than urfave/cli". He pointed to
lefthook, whose completions "regressed significantly" when it moved to urfave
([scop/bash-completion#1718](https://github.com/scop/bash-completion/issues/1718),
[evilmartians/lefthook#1230](https://github.com/evilmartians/lefthook/pull/1230)). After merging the
experimental CLI, OpenTofu shipped a completion regression and kept posener/complete
([opentofu#4658](https://github.com/opentofu/opentofu/issues/4658)).

**nixpkgs**: `headscale completion bash|fish|zsh` keeps working under (a), (b) or (c). Installed files change
content, not path.

## 3. Errors (D4)

Every parse error is a `fmt.Errorf` string without `%w` (`errors.Unwrap` → nil in probe D):

| Situation                | Text (v3.14.0)                                                                                                                                                                                                                                                                                                                                                      | Where the word is                                                                                                                                    |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| unknown flag             | `flag provided but not defined: -force` (single dash for `--force` too; whole group for `-ojson`)                                                                                                                                                                                                                                                                   | after the prefix; urfave itself recovers it by `strings.TrimPrefix` ([`flagFromError`](https://github.com/urfave/cli/blob/v3.14.0/command_parse.go)) |
| missing value            | `flag needs an argument: --sort` (as typed)                                                                                                                                                                                                                                                                                                                         | after the prefix                                                                                                                                     |
| bad value                | `invalid value "maybe" for flag -force: parse error` (`%v` of the inner error)                                                                                                                                                                                                                                                                                      | quoted                                                                                                                                               |
| repeated `OnlyOnce`      | `invalid value "b" for flag -sort: can't duplicate this flag`                                                                                                                                                                                                                                                                                                       | quoted                                                                                                                                               |
| unknown command          | **no error at all**: the word reaches the parent's `Action` as a positional. Only the default help action turns it into `Exit("No help topic for 'x'", 3)` or calls `CommandNotFound(ctx, cmd, word)`. `CommandNotFound` is not inherited and is never reached when the parent has an `Action` ([discussion #2522](https://github.com/urfave/cli/discussions/2522)) | `cmd.Args().First()` in our Action                                                                                                                   |
| required flag/arg, mutex | private types `errRequiredFlags`, `errRequiredArguments`, `mutuallyExclusiveGroup` (unexported fields); unused by us                                                                                                                                                                                                                                                | —                                                                                                                                                    |

Hooks: `OnUsageError(ctx, cmd, err, isSubcommand) error` gets the command where parsing failed (path =
`cmd.FullName()`/`Lineage()`), the error string, and `cmd.Args()` = positionals seen so far. It must be set
**on every command** (not inherited; probe D shows leaf errors bypassing a root-only hook).
`ExitErrHandler(ctx, cmd, err)` is looked up on the root only; set it to a no-op to stop `os.Exit`.
`InvalidFlagAccessHandler(ctx, cmd, name)` only fires when *our code* reads an undefined flag name; it is not
a parse hook. So: **path yes, typed reason no.** Getting the flag word means matching three message prefixes.
Those strings already changed inside v3: main (unreleased) rewrites the missing-value text for short groups
to `flag needs an argument: -e`. A golden test per prefix is needed to catch drift. The v4 plan promises
`*cli.Error` with `Kind` and fields ([discussion #2446](https://github.com/urfave/cli/discussions/2446), draft
[#2447](https://github.com/urfave/cli/pull/2447), idle since 2026-09-28): typed errors arrive only with
another major version.

## 4. Staying out of the way

| Automatic thing            | Off / replaced by                                                                                                                 | Residue                                                                                  |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| help flag + `help` command | `HideHelp: true` (inherited) + `cli.HelpFlag = nil` (global)                                                                      | without the global, any flag named `help` re-enables the template printer on its command |
| help output                | not needed once disabled; else `HelpPrinter` (global func) / templates (globals)                                                  | OpenTofu mutates these globals                                                           |
| `--version`                | `HideVersion` or empty `Version`                                                                                                  | —                                                                                        |
| `completion` command       | `EnableShellCompletion: false` removes both the command and Tab support; can rename/reshape via `ConfigureShellCompletionCommand` | cannot keep `--generate-shell-completion` without the command; renderers unexported      |
| suggestions                | off by default (`Suggest`, `SuggestCommandFunc`, `PrefixMatchCommands`)                                                           | —                                                                                        |
| usage printed on error     | `OnUsageError` on **every** command                                                                                               | —                                                                                        |
| `os.Exit`                  | `ExitErrHandler` no-op on root                                                                                                    | `ShowAppHelpAndExit` etc. only if we call them                                           |
| env binding                | none unless `Sources`                                                                                                             | —                                                                                        |
| sorting                    | categories sorted for help only; completion lists in `Commands` order                                                             | —                                                                                        |
| deprecation warnings       | only if `Deprecated` set (writes to ErrWriter)                                                                                    | —                                                                                        |
| `Before`/`After`           | unused                                                                                                                            | `Before` runs even in completion mode                                                    |
| global state               | see C7/G26 rows                                                                                                                   | —                                                                                        |

## 5. D3 (global flags before/after) — see the D3 row; both layouts were probed (E, E2). Recommended: persistent

`-c`/`-o` on root (cobra-like placement, works on every level) + our `IsSet` refusal on leaves without
output (~10 lines). The refusal message cannot know if `-o` or `--output` was typed unless we scan argv.

## 6. Risk

**Maintainers and releases.** Releases from 2025-11-17 to 2026-11-17: v3.6.1 → v3.14.0, 11 tags. The
v3.14.0 tag was cut by Eng Zer Jun (Juneezee); every earlier v3.5–v3.13 tag by `dearchap` (Naveen
Gogineni). In the last 12 months 87 PRs were merged by dearchap and 81 by Eng Zer Jun; others merged 8
(`git log --first-parent`). Effective release-capable people: **2** (meatballhat/Dan Buch released
v3.3–v3.4 in 2025, not active since). The release process is manual, signed tags
([discussion #2446](https://github.com/urfave/cli/discussions/2446)). On 2026-09-27 a maintainer
(coilysiren) closed every issue untouched since 2025 "to reduce maintainer burden while we coordinate a
roll-over of who is doing the primary work day to day"
([#1905 close comment](https://github.com/urfave/cli/issues/1905)). A hand-over is in progress, not a
settled team. 49 open issues+PRs. A contributor's team-membership request
([#2505](https://github.com/urfave/cli/issues/2505)) is unanswered.

**Churn inside v3.** v3 took 2 years of alpha/beta (alpha2 2023-01 → beta1 2024-11 → v3.1.0 2025-03; there
is **no v3.0.0 tag**). CONTRIBUTING claims strict semver, and `godoc-current.txt` tooling guards the API
surface. Yet:

- **API break in a minor**: v3.2.0 changed `IntFlag` from int64 to int, announced as "Breaking change"
  ([v3.2.0](https://github.com/urfave/cli/releases/tag/v3.2.0)).

- **Behaviour changes on our surface since v3.1.0** (release notes, `spikes/probe-urfave/urfave-releases.md`):

    - 3.1.0: own parser replaces `flag`.
    - 3.6.1: empty value after `=`.
    - 3.7.0: arg after short option.
    - 3.8.0: `--flag=""` accepted; empty positionals.
    - 3.9.1: subcommands inherit Reader/Writer, bash script colon parsing and spacing.
    - 3.10.0: help vs parse-error precedence.
    - 3.12.0: whitespace preserved in positionals and `=` values; completion after positionals.
    - 3.14.0: duplicate flag names now fail `Run`; args after a bare `-`; persistent flags in completion.
    - main, unreleased: empty bool value rejected, digit flags, `StopOnNthArg` ordering, slice-separator
      inheritance, tree re-run reset, root completion reads Run args, new error text.

    That is about **15 changes touching parsing, completion or error text in 13 releases**. Most are fixes,
    but each can move a golden test.

- **Regressions** are fixed fast (v3.6.2 help-subcommand regression [#2271](https://github.com/urfave/cli/issues/2271)
  opened 2026-02 → fixed in v3.7.0 11 days later). Nothing yanked.

- **Go floor**: v3.14.0 `go 1.22`; main raised to **`go 1.26`** on 2026-10-21, so the next minor raises it.
  No issue for Headscale (1.27.3).

- **v4**: a "clean slate" rewrite is planned ([#2192](https://github.com/urfave/cli/issues/2192),
  [discussion #2446](https://github.com/urfave/cli/discussions/2446)). The draft is idle. If it ships, v3
  goes the way of v2 (frozen at v2.27.7 in 2025-06).

**Security**: no GitHub advisories for `urfave/cli/v3` or `/v2` (GraphQL `securityVulnerabilities`, 0 results).

**Dependencies**: zero non-std packages in the build (`go list -deps` → only `github.com/urfave/cli/v3`);
`testify` is test-only, yaml indirect. Size: a stripped hello-world is 3.79 MB versus 2.93 MB for stdlib
`flag`+`text/template`, so **~0.86 MB** (the probe's `size/` dir). Its own CI limit was raised to 2.3 MB on
main.

**Way out.** Only the adapter imports it. The parser is ~300 lines and the completion glue ~100, so a fork
of what we use is ~1,500 lines with flag types. Leaving costs one adapter rewrite plus the error-text
classifier.

## 7. Evidence from others

**OpenTofu** (the case the brief asked for):

- RFC ([20260807-use-urfave-instead-of-cobra.md](https://github.com/opentofu/opentofu/blob/main/rfc/20260807-use-urfave-instead-of-cobra.md),
  PR [#4445](https://github.com/opentofu/opentofu/pull/4445), merged 2026-08-12). The deciding reason is
  pflag's POSIX parsing of `-json` as `-j -s -o -n`; urfave keeps Go-style single-dash long flags. **Does
  not apply** to Headscale, which already uses pflag syntax and whose 001 relies on `-o`/`--output` pairs.
- Their architecture **does apply**: an own `arguments.CommandLine` metadata layer (like our specs), walked
  to build urfave structs ("If we ever need to migrate the cli package again, the churn to the codebase is
  minimal").
- Implementation: [#4419](https://github.com/opentofu/opentofu/pull/4419) (+2130/−1066, merged
  2026-07-31). v1.13 ships it behind `TOFU_EXPERIMENTAL_CLI_ENABLED` (v1.13.9 `main.go` switches on it). On
  `main` the legacy path is gone (`cmd/tofu/` has no `legacy_main.go`), so urfave is the only path for
  1.14. They are still pinned at **v3.10.1** (go.mod on main) and have filed no issues or PRs upstream
  (searched `author:cam72cam`).
- Workarounds visible in [`cmd/tofu/command_main.go`](https://github.com/opentofu/opentofu/blob/main/cmd/tofu/command_main.go):
    1. Mutate the globals `cli.HelpPrinter` and the three help templates to inject their own help.
    1. **Run the urfave tree twice**: a throwaway tree with `HideHelp` and stub Actions finds which
       subcommand is meant, "Ideally, we would be able to inject args … but that's not possible in the
       current urfave version".
    1. Unknown command handled in the root `Action` with their own did-you-mean, then `os.Exit(1)`.
    1. `OnUsageError` on every command, turning `err.Error()` into a diagnostic.
    1. Completion **not** urfave's: kept posener/complete on `COMP_LINE`. The reasons were bash-completion's
       shipped `complete -C` fallback and that "making sure the switchover was done correctly was beyond the
       scope"; the bash-completion thread adds urfave's missing functionality.
    1. A completion regression shipped in 1.13 ([#4658](https://github.com/opentofu/opentofu/issues/4658)).
    - Applies to Headscale: points 1–4 are the same seams we would use (we avoid 1 with
      `HelpFlag = nil`); 5 says urfave's completion was not good enough for them either.

**lefthook** moved to urfave v3 in 2.0.0 ([#1155](https://github.com/evilmartians/lefthook/pull/1155),
2025-10-01). Completions "regressed significantly due to change of the CLI library"; a partial restore in
[#1230](https://github.com/evilmartians/lefthook/pull/1230) says completions "continue to be worse than
they were in 1.x (lack of context)".

**Gitea** v2 → v3 (2025-06, [#34510](https://github.com/go-gitea/gitea/pull/34510)) is a large user.
**wharflab/tally** left v3 for cobra (2026-04, [#588](https://github.com/wharflab/tally/pull/588)), to
embed as a Docker CLI plugin. (Both from `discovery.md`.)

**Open bugs that would hit us** (v3.14.0, all fixed on main but unreleased as of today): root completion
reads `os.Args` ([#2486](https://github.com/urfave/cli/issues/2486)); slice separator not inherited; tree
re-run state leak. Open: `Hidden` not recursive ([#2372](https://github.com/urfave/cli/issues/2372),
irrelevant to us), unknown flags cannot be collected ([#2240](https://github.com/urfave/cli/issues/2240),
v4). Not reported anywhere I found: the leading-space positional parsed as a flag, and `-5` silently
disabling flag parsing.

## 8. Migration from today's cobra CLI

- **Same commands typed by users**: unchanged for `--x v`, `--x=v`, `-o json`, `-o=json`, interspersed
  flags, `--`, `--force=false`. **Changes**:
    - `-ojson`/`-e24h` stop working (D11 wants exactly that; it goes in the changelog).
    - A positional like `-5` no longer errors; it switches off flag parsing for the rest of the line.
    - `--force=` means true (pflag: error).
    - `-o` placement and `help`/`--version` behave as we wire them.
    - Error text is ours (D4), so it only changes where our classifier misses a new urfave message.
- **nixpkgs** (`headscale completion bash|fish|zsh` at build time): works. The script content changes and
  completion quality drops unless we take option (b).
- **128 integration calls**: the headscale invocations found use spaced or `=` forms (`--user x`,
  `-o json`, `--expiration 24h`, `--flag=v`). No attached short values were found (grep of `integration/`
  and `nix/`), so no call should need changing for parsing reasons.

______________________________________________________________________

## Requirement table

| Requirement                                                  | Native                                | Setting                                                       | Our code (lines)                               | No                                  |
| ------------------------------------------------------------ | ------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------- |
| R01–R06 tree, 3 levels, aliases, hyphen names, runtime build | ✔                                     |                                                               |                                                |                                     |
| R08/R09 removed/reserved names unknown                       |                                       |                                                               | 15 (group/root Action → unknown-command error) |                                     |
| R11–R13 raw positionals                                      | ✔ (except `-5`, leading-space quirks) |                                                               |                                                |                                     |
| R15 long forms                                               | ✔                                     |                                                               |                                                |                                     |
| R16 / D11 `-ojson` refused                                   | ✔                                     |                                                               |                                                |                                     |
| R17 short letters                                            | ✔ (`Aliases: ["o"]`)                  |                                                               | tree test is ours                              |                                     |
| R18/R19 per-command flags                                    | ✔                                     | `Local`                                                       | 10 (D3 refusal)                                |                                     |
| R20 interspersed                                             | ✔                                     |                                                               |                                                |                                     |
| R21 `-`-prefixed values                                      | ✔                                     |                                                               |                                                |                                     |
| R22 verbatim `=:<>,`                                         | ✔                                     | `DisableSliceFlagSeparator` per command                       |                                                |                                     |
| R23/R24 given bit                                            | ✔                                     |                                                               |                                                |                                     |
| R25 bools                                                    | ✔                                     |                                                               |                                                |                                     |
| R27 / D6 repeat `--filter`, others error                     | ✔ accumulate                          | per-command separator off                                     | 5 (`Count()>1`)                                |                                     |
| R28–R30 strings to our parsers                               | ✔                                     |                                                               |                                                |                                     |
| R31 unknown flag error                                       | ✔ (string)                            |                                                               |                                                |                                     |
| R32/R33 no arg count / required                              | ✔                                     |                                                               |                                                |                                     |
| R36–R38 streams, no print, no exit                           |                                       | Writer/ErrWriter, `OnUsageError` ×every cmd, `ExitErrHandler` | 3                                              |                                     |
| R41 builder flags                                            | ✔                                     |                                                               |                                                |                                     |
| R49 cheap repeatable build                                   | ✔ fresh tree                          |                                                               |                                                | reuse leaks state (3.14.0)          |
| R51–R53 help ours, root/group                                |                                       | `HideHelp`, `HelpFlag=nil`                                    | 10                                             |                                     |
| R56 in-process parallel                                      | ✔                                     |                                                               |                                                |                                     |
| R59 `completion <shell>`                                     | ✔ hidden cmd                          | rename                                                        | copy scripts or buffer-run if our spec owns it |                                     |
| R60 values per flag                                          |                                       |                                                               | 40                                             |                                     |
| R60 comma-aware `--columns id,na`                            |                                       |                                                               | ~200 + vendored scripts (option b)             | ✘ with stock scripts                |
| R61 no server on Tab                                         | ✔                                     |                                                               |                                                |                                     |
| R62 live values later                                        |                                       |                                                               | in the same `ShellComplete`                    | values with `:` break stock scripts |
| R63 no env binding                                           | ✔                                     |                                                               |                                                |                                     |
| D1 binary answers                                            | ✔ (weaker protocol)                   |                                                               |                                                |                                     |
| D2 bash/zsh/fish/pwsh                                        | ✔ scripts                             |                                                               |                                                |                                     |
| D3                                                           |                                       | persistent                                                    | 10                                             |                                     |
| D4 typed errors                                              |                                       |                                                               | ~25 text classifier + golden tests             | ✘ types                             |
| D5 did-you-mean + hint table                                 |                                       |                                                               | 15 + table                                     |                                     |
| D7 `--version`                                               |                                       | `HideVersion`                                                 | 5                                              |                                     |
| D8 no `help`                                                 |                                       | `HideHelp`                                                    |                                                |                                     |

Adapter estimate on urfave: ~250 lines with option (a) completion; ~450 lines + ~900 copied script lines with
option (b).

## Three strongest reasons for

1. **Nothing it insists on owning.** Help, version, suggestions, env, exit, arg counting, required flags
   are all off or unused; the tree is plain struct literals; zero runtime dependencies; parallel
   in-process runs pass `-race`.
1. **Active fixing.** 11 releases in 12 months; bugs reported against v3 get fixed in days to weeks.
1. **Parsing matches nearly all of 001**: interspersed flags, `""` vs unset, `-`-prefixed values,
   verbatim `=` values, `--`, persistent flags for D3.

## Three strongest reasons against

1. **Completion is the weak point D1 cares most about.** The current word is not sent and there are no
   directives. `:` breaks values, bash falls back to files everywhere, fish never shows files. Real
   comma-list completion means replacing the scripts, at which point urfave adds nothing. Two outside
   projects (lefthook, OpenTofu) report regressions or avoided it.
1. **D4 is not met**: string errors without wrapping, plus wording that changes in minors. We would parse
   message text and keep golden tests to catch drift. Typed errors are promised only for a v4 rewrite.
1. **Behaviour churn and a team in transition.** About 15 parse/completion/error behaviour changes in 13
   minors, one declared API break in a minor, a Go-floor jump in the next minor, a planned v4, and a
   maintainer "roll-over" under way with 2 people cutting releases.

## Risks (two-year view)

- v4 ships and v3 freezes like v2 did: a second adapter rewrite. Bounded by the one-file rule.
- Each minor bump can change parse edge cases or error text: needs a pinned version and a conformance suite
  run on every bump (the kit from Phase B would be that suite).
- Completion stays basic; R62 (live names, tags with `:`) pushes us to own scripts anyway.
- The release-cut bus factor is 2.

## Open questions for the maintainer

1. **Completion quality bar for D1** (decides whether urfave's completion is used at all).
    - (a) Accept urfave's scripts + our ~40-line value completer. Cost: no comma lists, no `--x=<Tab>`, no
      `--sort -<Tab>`, files offered after every argument in bash and never in fish, tag values with `:`
      unusable later.
    - (b) Vendor cobra's four scripts and answer `__complete` ourselves (Tailscale pattern). Cost: ~200 lines
      Go + ~900 lines copied script to re-sync by hand; urfave then gives only parsing.
1. (Settled by D11: `-ojson` is refused, which urfave does natively.)
1. **D4 with a string-error framework.**
    - (a) Classify by message prefix, with one golden test per urfave message. Cost: ~25 lines + a test that
      fails on every wording change in a bump.
    - (b) Ask upstream for exported error types in v3 (a PR from us). Cost: our time, and they have said that
      typed errors are a v4 item.
1. **Version policy if urfave is chosen.**
    - (a) Pin and bump deliberately, running the conformance kit each time. Cost: a review per minor
      (roughly monthly).
    - (b) Track latest via the daily bump tool. Cost: parse or error-text changes can land unnoticed if the
      kit misses an edge case.

______________________________________________________________________

# Phase B: the adapter spike

Code: `spikes/urfave/adapter.go` (the only file importing urfave), `adapter_test.go`, result
`spikes/urfave/RESULT.md`, real-shell driver `spikes/urfave/shells.sh` with output in
`spikes/urfave/shells-output.txt`, and the binary `spikes/urfave/cmd/headscale`. urfave/cli **v3.14.0**.
Run with zsh 5.9.1 and pwsh 7.6.5 on PATH: **MUST 112/112, STRETCH 0/4, OBSERVE 13**. Suite time 22 ms;
`go test -count=1` takes 0.025 s for the test binary and ~2.6 s including nix startup.
`CGO_ENABLED=1 go test -race -count=3` passes.

## How the adapter works

- One urfave `Command` per kit command. Each one gets the same `Action`: read the parsed flags along the
  lineage, then call `t.Exec` once. Each one gets the same `OnUsageError`, set per command because it is
  not inherited. Each one gets the same `ShellComplete`.
- Flags use an own ~20-line `kflag` type (the urfave `Flag` interface + `IsBoolFlag` + `IsLocal`). It
  records every value in order, so the kit sees repeats, `""`, and raw bool spellings (`=maybe` reaches
  the kit as is).
- `-o`/`-c` on the root are persistent (`Local: false`) and on leaves local. `check config -o json`
  parses, and the kit refuses it (G07/G08 pass).
- Unknown words under a group arrive as `Args` of the group's `Action`, and the kit raises
  `UnknownCommand`. When an unknown flag follows the unknown word (`nodes frob --force`),
  `OnUsageError` passes the word on, so the command error wins.
- Root settings: `HideHelp`, `HideVersion`, `EnableShellCompletion`, and the built-in script command
  renamed to `__urfave_completion` because the spec tree owns `completion`. `ErrWriter = io.Discard`,
  `Reader` empty, `ExitErrHandler` a no-op.

## Numbers

| Number                                 | Value                                                                                                                                                                                                                                     |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MUST / STRETCH / OBSERVE               | 112/112 · 0/4 · 13                                                                                                                                                                                                                        |
| Adapter lines (non-blank, non-comment) | 181                                                                                                                                                                                                                                       |
| `// WA` lines                          | 11                                                                                                                                                                                                                                        |
| argv handled before the framework      | `Run`: **none**. `Complete`: drops the current word unless it starts with `-` and appends `--generate-shell-completion` (5 lines). This is exactly what urfave's bash script sends, reproduced so the kit drives the same path in-process |
| Modules added to go.sum                | 3 (`urfave/cli/v3`; `stretchr/testify` and `go.yaml.in/yaml/v3` appear only through urfave's go.mod and are not compiled in)                                                                                                              |
| Script bytes                           | bash 3076 · zsh 882 · fish 1232 · powershell 719                                                                                                                                                                                          |
| `-ojson` (D11, F05)                    | **refused natively**: `flag provided but not defined: -ojson` → `unknown-flag "ojson"`. Cost to refuse: 0 lines                                                                                                                           |

Workarounds, named:

1. **`cli.HelpFlag = nil`** (1 `// WA` line, in `init`). Any flag named `help` makes urfave print its
   template instead of calling the Action, even with `HideHelp`. The package global is the only switch.
1. **Error text matching** (10 `// WA` lines). The three parse-error prefixes (`flag provided but not defined: `, `flag needs an argument: `, `… for flag X:`) map to `UnknownFlag`, `MissingValue` and
   `BadValue` (D4).
1. Not `// WA` by the kit's definition, but framework-fighting:
    - Renaming the built-in completion command so it does not shadow the spec leaf (1 line).
    - `Script` runs that hidden command into a buffer, because the script renderers are unexported (3 lines).
    - `Complete` emulates the shell side of urfave's scripts: keep candidates with the current word as
      prefix, and `Files` when the answer is empty (bash `complete -o default`, zsh `_files`) (~8 lines).

## OBSERVE rows, and the cost of the other behaviour

| ID                                 | urfave did                                                         | Other behaviour costs                                                                                      |
| ---------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| H14 `nodes list --bogus -h`        | `unknown-flag bogus` (parsing stops at the bad flag)               | help needs an argv scan for `-h`/`--help` before Run: ~5 `// WA` lines, and the scan must skip flag values |
| H15 `nodes list -h --bogus`        | `help nodes list` (`OnUsageError` sees `-h` already set)           | 0                                                                                                          |
| H16 `nodes --help list`            | `help nodes list` (group's flag collected along the lineage)       | group help: 3 lines                                                                                        |
| H17 `-h nodes list`                | `help nodes list`                                                  | same                                                                                                       |
| V04 `nodes list --version`         | `unknown-flag version` (root-local)                                | make it persistent: 1 line                                                                                 |
| F05 `nodes list -ojson`            | `unknown-flag ojson`                                               | accepting it: ~30-line argv pre-pass                                                                       |
| F26 `nodes set 12 --name -e`       | `name=["-e"]` (a string flag always eats the next word)            | refusing a dash value: per-flag check, ~5 lines                                                            |
| F27 `nodes list --sort --filter x` | `sort=["--filter"]`, then arg-count error for `x`                  | same as F26                                                                                                |
| F28 `nodes list -ho json`          | `unknown-flag ho`                                                  | `UseShortOptionHandling: true` would give `-h -o json` = help                                              |
| B04 `--force=maybe`                | `bad-value force` (from the kit, since `kflag` keeps the raw text) | —                                                                                                          |
| B05 `--force --force`              | `flag-repeated force` (kit)                                        | —                                                                                                          |
| G11 `-c /a nodes list -c /b`       | `flag-repeated config` (root value + leaf value both reported)     | "last wins": 2 lines                                                                                       |
| E21 `--bogus nodes list`           | `unknown-flag [] bogus` (root path)                                | —                                                                                                          |

STRETCH failures: C18 `--columns id,na`, C19 `--columns +ho` and C20 `--sort -la`, all as Phase A
predicted. The script does not send `id,na`/`+ho`, and `-la` is consumed as the value of `--sort`, so
the completer never learns the prefix. S-powershell: urfave's pwsh script takes the program name from
its own file name (`$MyInvocation.MyCommand.Name` minus `.ps1`), so it never contains `headscale`. It
must be saved as `headscale.ps1`, and `headscale completion powershell | Invoke-Expression` does not
work. Both kept failing on purpose.

## Real shells (step 3)

How the script calls the binary: `headscale <words before the cursor> [current word if it starts with -] --generate-shell-completion`. Answers are one `token[:description]` per line.

| Line + Tab                       | bash                             | zsh                                                              | fish                        |
| -------------------------------- | -------------------------------- | ---------------------------------------------------------------- | --------------------------- |
| `headscale no`                   | `nodes`                          | all root commands handed to `_describe`, which filters → `nodes` | `nodes`                     |
| `nodes list --columns `          | 9 columns                        | 9 columns                                                        | 9 columns                   |
| `nodes list -o `                 | `json`                           | `json`                                                           | `json`                      |
| `policy set `                    | empty → **files** (`-o default`) | `_files`                                                         | **nothing** (`complete -f`) |
| `nodes list --sort la`           | `last-seen`                      | list → `_describe` filters                                       | `last-seen`                 |
| `nodes list --sort=`             | empty → files                    | `_files`                                                         | nothing                     |
| `nodes list --columns id,`       | empty → files                    | list, prefix `id,` matches nothing → **nothing, no files**       | nothing                     |
| `nodes delete `                  | empty → **files** (unwanted)     | `_files` (unwanted)                                              | nothing                     |
| `nodes list --filter owner=tag:` | empty → files                    | list → nothing                                                   | nothing                     |

- bash ran as a non-interactive bash-interactive 5.3 with bash-completion 2.17 sourced, with
  `COMP_WORDS`/`COMP_CWORD`/`COMP_LINE`/`COMP_POINT` set by hand. It splits on `=` and `:` the way
  readline does.
- zsh ran without a terminal: the generated script was sourced, `words`/`CURRENT` were set, and
  `compdef`, `_describe` and `_files` were stubbed to print what they receive. So the zsh column shows
  what the script hands to zsh, not zsh's final menu.
- fish: `complete -C`. pwsh: not driven.

Kit fairness note: C16/C17 (`+files`) pass because the adapter reports `Files` for any empty answer, which
is what bash and zsh do. Fish does the opposite (never files), and the kit has no case that forbids files
(e.g. `nodes delete ''`). The kit therefore rates urfave's file handling better than a fish user sees it.

## Completion scripts: where from, licence, upkeep

The scripts are urfave's own embedded `autocomplete/{bash_autocomplete,zsh_autocomplete,fish_autocomplete, powershell_autocomplete.ps1}` (MIT), rendered by its hidden command. Nothing to keep current by hand. In
exchange there is no control: a urfave bump changes the scripts (v3.9.0 refactored bash, v3.9.1 fixed
colon parsing and spacing, main has another bash perf change). We cannot add directives or send the
current word without replacing them, and replacing them (cobra's scripts or `tailscale.com/tempfork/spf13/cobra`,
Apache-2.0, plus our `__complete`) leaves urfave doing only the parsing.

## What surprised me

- **Parsing is better than Phase A feared.** Every MUST passed on the first run, including D3 placement,
  D9 bool forms, D10 group help, `--` and `""`. D11 turned the `-ojson` gap into a native pass.
- `OnUsageError` and `CommandNotFound` are per command, not inherited. Easy in a loop, easy to miss by hand.
- The help flag trap: `HideHelp: true` is not enough; a flag *named* `help` still triggers the framework.
- The PowerShell script never names the program.

## What was ugly

- Error kinds come from string prefixes (10 lines), and one of those strings already changes on `main`
  (unreleased short-group wording).
- A package-global write to switch off help.
- Getting script text means running a hidden command, because the renderers are unexported.
- `Complete` has to mimic the bash script's request shape and the shell's filtering to be testable
  in-process. The binary never sees the current word, so the code under test is half Go, half shell.

## Did Phase B change the Phase A verdict?

Partly. As a **parser** urfave is fine for Headscale: 181 lines, 112/112, no argv rewriting in `Run`.
As a **completion** framework the verdict stands or gets worse. The real-shell runs show three shells
behaving three different ways on files, none of them able to do comma lists, and pwsh not usable with
`source`-style loading. **D4** stays unmet (text matching). If D1 quality matters, the completion half
gets replaced, and then urfave competes as "a parser" with pflag. pflag is already in Headscale's tree,
keeps today's syntax exactly, and has typed errors (`NotExistError`, `ValueRequiredError`,
`InvalidValueError`).

## Five years with this adapter

What would worry me is everything outside the 181 lines. Text: three error-message prefixes that upstream
treats as free text, plus a help-flag hack that the maintainers themselves list for removal in v4
([#2192](https://github.com/urfave/cli/issues/2192)). Completion: scripts we do not own and that change
with every other minor. Parser behaviour: it moves monthly, e.g. `--force=` flips from true to an error
and `-5` handling changes on main right now. All of it sits on a project in a maintainer hand-over with
a v4 "clean slate" rewrite planned. In five years I expect at least one forced adapter rewrite (v4), and a
dozen bumps where the conformance kit is the only thing between a quiet change in parse or error text and
users. The kit would have to become a permanent CI test of the adapter, and it would need more cases than
today, because urfave's behaviour changes land at edges the kit does not cover yet (leading-space words,
`-5`, `--force=`).

## Phase B table (RESULT.md)

MUST 112/112 pass (0 skipped) · STRETCH 0/4 · OBSERVE 13 recorded · suite 22ms

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
| H15          | OBSERVE | R53         | `headscale nodes list -h --bogus`                                                                  |                                                                                  | `help nodes list`                                                                | SEEN   |
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
| C03          | MUST    | D1          | `headscale nodes ''<TAB>`                                                                          | `has list delete set routes; not help`                                           | `delete list ls rm routes set`                                                   | PASS   |
| C04          | MUST    | D1          | `headscale nodes routes ''<TAB>`                                                                   | `has set`                                                                        | `approve set`                                                                    | PASS   |
| C05          | MUST    | D1 R06      | `headscale nodes routes ap<TAB>`                                                                   | `has approve`                                                                    | `approve`                                                                        | PASS   |
| C06          | MUST    | D1          | `headscale auth keys c<TAB>`                                                                       | `has create`                                                                     | `create`                                                                         | PASS   |
| C07          | MUST    | D1 D3       | `headscale -c /x nodes l<TAB>`                                                                     | `has list`                                                                       | `list ls`                                                                        | PASS   |
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
| C18          | STRETCH | R60         | `headscale nodes list --columns id,na<TAB>`                                                        | `has id,name`                                                                    | ` +files (does not match)`                                                       | FAIL   |
| C19          | STRETCH | R60         | `headscale nodes list --columns +ho<TAB>`                                                          | `has +hostname`                                                                  | ` +files (does not match)`                                                       | FAIL   |
| C20          | STRETCH | R60         | `headscale nodes list --sort -la<TAB>`                                                             | `has -last-seen`                                                                 | ` +files (does not match)`                                                       | FAIL   |
| S-bash       | MUST    | D1 D2 R59   | `Script(bash)`                                                                                     | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-zsh        | MUST    | D1 D2 R59   | `Script(zsh)`                                                                                      | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-fish       | MUST    | D1 D2 R59   | `Script(fish)`                                                                                     | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-powershell | STRETCH | D1 D2 R59   | `Script(powershell)`                                                                               | `non-empty, names headscale, syntax check passes`                                | `719 bytes, does not name headscale`                                             | FAIL   |
| I01          | MUST    | R49 R56 G26 | `every case twice, in parallel, fresh tree each`                                                   | `same outcome both times, no panic`                                              | `ok`                                                                             | PASS   |
