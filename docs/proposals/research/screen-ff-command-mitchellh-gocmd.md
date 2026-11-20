# Screen: peterbourgon/ff, creachadair/command(+flax), mitchellh/cli (hashicorp/cli), devfacet/gocmd

Date of work: 2026-11-17. Probes below were run by me (scratch module, ff v4.0.0-beta.1, command v0.2.13) unless a URL is given. Repos were cloned at HEAD on 2026-11-17.

## Verdicts

| Project                    | Verdict                                                                                                                                                   | Deciding facts                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| peterbourgon/ff v4         | go to deep research (with caveat: still beta)                                                                                                             | Only tagged v4 is `v4.0.0-beta.1` (2025-08-02), no GitHub release; maintainer still commits (Oct 2026). Short+long flags, `-ab`, `--x=y`, repeated flags native. No completion, no flags after positionals. Same family as Tailscale's ffcli v3.                                                                                                                        |
| peterbourgon/ff v3 / ffcli | weak, keep as reserve                                                                                                                                     | Last release v3.4.0 on 2023-07-20. Stdlib `flag` only (single-dash long flags, no grouped shorts). Only value: it is what `tailscale` uses, and Tailscale's `ffcomplete` exists for it. Completion code is welded to `ffcli.Command`.                                                                                                                                   |
| creachadair/command + flax | go to deep research                                                                                                                                       | Most alive of the group (58 commits since 2025-11-17, release 2026-11-02). Runtime tree from data: yes. Already in go.mod. Flags after positionals work. No completion, no aliases, no grouped shorts; single maintainer, v0.x. We tried it once (#2647), stopped without a stated reason.                                                                              |
| mitchellh/cli              | disqualified: archived 2024-07-22, no commit since; successor is hashicorp/cli (row below), so the 24-month knockout is not met on the successor          | Last tag v1.1.5.                                                                                                                                                                                                                                                                                                                                                        |
| hashicorp/cli (successor)  | weak, keep as reserve                                                                                                                                     | Alive but maintenance-only (6 commits since 2025-11-17, none functional in the list I read). Does not parse flags (each command brings its own `flag.FlagSet`). Dynamic completion via posener/complete, bash/zsh/fish only, installs by editing shell rc files. Heavy deps (sprig, crypto). Used by Terraform, Vault, Nomad; Consul and Packer still on mitchellh/cli. |
| devfacet/gocmd             | disqualified: knockout "no release and no meaningful commit for 24 months, and no maintained successor" and knockout "cannot be driven from runtime data" | Last commit and last release 2023-04-04 (about 43 months ago). Struct tags only.                                                                                                                                                                                                                                                                                        |

## 1. peterbourgon/ff

### Takeaway

v4 is the live line but is still a beta tag after more than 3 years of alpha/beta; v3 is frozen since July 2023. Tailscale's own CLI is on v3 `ffcli` and has its own dynamic completion, which sits on ffcli types and cannot be dropped onto v4 as is.

### Screen card

- Module `github.com/peterbourgon/ff/v4` (and `.../v3`, `ffcli` sub-package); licence Apache-2.0 [repo](https://github.com/peterbourgon/ff); v4 go.mod floor `go 1.21.0`, requires `pelletier/go-toml/v2` and `gopkg.in/yaml.v2` ([go.mod](https://github.com/peterbourgon/ff/blob/main/go.mod)); those serve `fftoml`/`ffyaml` and are only compiled if imported (inference). Core use would add 0 extra modules to the build graph beyond stdlib (inference; UNVERIFIED with `go list -deps`).
- Releases: v3.4.0 2023-07-20 is the newest GitHub release; v4 tags are `v4.0.0-alpha.2..4` and `v4.0.0-beta.1` (commit 012e827, dated 2025-08-02) and there are no GitHub releases for v4 ([releases](https://github.com/peterbourgon/ff/releases), [tags](https://github.com/peterbourgon/ff/tags)). README says "This README describes the pre-release version v4 of ff" ([README](https://github.com/peterbourgon/ff#note)). So: not out of beta as of today.
- Health: 2 commits since 2025-11-17 (2026-10-19 Peter Bourgon "ffval: fix lint issue"; 2026-10-26 external contributor "ffenv: report scanner errors"). Before that the last real work was July-Aug 2025 (#148-#155). One maintainer. 10 open issues, 4 open PRs; PR #139 (a `--long=` fix) open since 2025-01 with no merge, #156 (dep bump) open since 2025-08 ([pulls](https://github.com/peterbourgon/ff/pulls)). Alive, slow.
- Model: declarative `ff.Command` struct (fields Name, Usage, ShortHelp, LongHelp, Flags, Subcommands, Exec) plus its own `ff.FlagSet` that wraps nothing from stdlib but accepts `flag.Value` ([command.go](https://github.com/peterbourgon/ff/blob/main/command.go)). Plain data; a tree can be built at runtime from our specs. Yes.
- Nesting: arbitrary depth via `Subcommands`. Aliases: no field. Hidden/deprecated commands: no field (UNVERIFIED for flag-level hiding).
- Flag syntax (probed, v4.0.0-beta.1 FlagSet with parent flag set):

| Input                                                 | Result                                                                                                                                                                                     |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `sub --output=json x`                                 | works                                                                                                                                                                                      |
| `sub -o json x`                                       | works                                                                                                                                                                                      |
| `--output json sub x` (parent flag before subcommand) | works                                                                                                                                                                                      |
| `sub -ab x` (grouped shorts)                          | works, both set                                                                                                                                                                            |
| `sub x --output json` (flag after positional)         | NOT parsed; `x --output json` all become args. Open issue [#124](https://github.com/peterbourgon/ff/issues/124) since 2023-10; maintainer's objection is ambiguity of `foo --bar baz quux` |
| `sub -r 1 -r 2 x` (repeated)                          | works with `StringSet`/`StringList`                                                                                                                                                        |
| `sub -- -a x`                                         | works, `-a x` are args                                                                                                                                                                     |
| `sub x -- -a`                                         | `--` kept literally in args                                                                                                                                                                |

Also: bool forms, custom `flag.Value`, enum flag, env vars (`ff.WithEnvVarPrefix`), config files (plain, JSON, YAML, TOML) are native ([README](https://github.com/peterbourgon/ff#usage)). Required and mutually exclusive flags: none seen. Standalone `-` as positional is an open PR ([#159](https://github.com/peterbourgon/ff/pull/159)).

- Positional args: only `Exec(ctx, args []string)`; no counts or types. We validate ourselves.
- Completion: none in ff v4. Issue [#132](https://github.com/peterbourgon/ff/issues/132) (Tailscale's request to upstream theirs, 2024-03) got "I'm basically on board, show me a strawman PR" from the maintainer on 2024-04-04; nothing landed. Third-party add-on `climax` (generator) in [#158](https://github.com/peterbourgon/ff/issues/158), not completion.
- Help: `ffhelp` package renders help; you call it yourself, so it is fully replaceable. "Did you mean": none seen (UNVERIFIED).
- Testability: `cmd.ParseAndRun(ctx, args)`; stdout is whatever our code uses, so in-process is trivial. Context is passed to Exec.
- Notable users: Tailscale CLI (v3 `ffcli`) ([tailscale go.mod](https://github.com/tailscale/tailscale/blob/main/go.mod) line `github.com/peterbourgon/ff/v3 v3.4.0`, verified at HEAD 2026-11-17).
- Pain points: [#124](https://github.com/peterbourgon/ff/issues/124) flags after positionals; [#157](https://github.com/peterbourgon/ff/issues/157) no persistent pre-run; stalled PRs.

### Tailscale and ffcli / ffcomplete (checked in a clone of tailscale/tailscale HEAD, 2026-11-17)

- Path `cmd/tailscale/cli/ffcomplete/`: `ffcomplete.go` 60 lines, `complete.go` 160, `scripts.go` 85, `internal/complete.go` 271 (plus tests and `_omit` stubs for the `ts_omit_completion` build tag). About 600 lines non-test. The shell scripts are extracted from cobra into `tempfork/spf13/cobra` (253 lines Go plus `comp.bash/.zsh/.fish/.ps1`, Apache-2.0 per its `LICENSE.txt`) ([dir](https://github.com/tailscale/tailscale/tree/main/cmd/tailscale/cli/ffcomplete)).
- How it works: `Inject(root *ffcli.Command, ...)` adds `completion bash|zsh|fish|powershell` and a hidden `completion __complete -- <args>` subcommand. Shell scripts call `$0 completion __complete`, which walks the ffcli tree and prints candidates plus a cobra `ShellCompDirective` on the last line. Same protocol as cobra's `__complete`.
- Dynamic: yes. `ffcomplete.Flag(fs, name, fn)` and `ffcomplete.Args(cmd, fn)` register Go callbacks; used for `--exit-node` in `set.go`, args of `ping`, `nc`, `switch`. All four shells ship.
- Reuse: licence is Tailscale BSD-3-Clause for the Go files (SPDX header) and Apache-2.0 for the cobra script fork, so copying fits a BSD-3 project with attribution. But it imports `ffcli.Command` and `flag.FlagSet`, so we would need to port the 271-line tree walker to our own tree (small, since we hold our own specs). Merged upstream into Tailscale as PR [#11336](https://github.com/tailscale/tailscale/pull/11336) (2024-04-17).
- Move to ff v4 or elsewhere: no issue or PR found. `gh search issues "ff v4"` in tailscale/tailscale returned nothing; HEAD still on ff/v3 v3.4.0 (77 Go files import ff). UNVERIFIED beyond that (private roadmap cannot be seen).

### Inferences

- Headscale users type `tailscale` and `headscale` side by side; ff v3/v4 syntax matches stdlib-style single-dash/double-dash acceptance that `tailscale` has, but v4's short flags and `-ab` are a difference from `tailscale`.
- If we pick ff v4, we write: completion (port of ffcomplete), aliases, flags-after-positional workaround (or live with it), required/exclusive flag checks.

### Gaps

- Dependency count via `go list -deps`, hidden-flag support and "did you mean" in ff v4 not checked.

## 2. creachadair/command (+ creachadair/flax)

### Takeaway

Small (command.go 442 lines, help.go 428), actively developed by one person, plain data tree, flags after positionals work. No completion and no aliases; the one trial in Headscale did not do completion either.

### Screen card

- Module `github.com/creachadair/command` v0.2.13 (tag commit 2026-11-02); flax `github.com/creachadair/flax` v0.1.0 (2026-08-31). Licence text is 3-clause BSD with "All Rights Reserved" line (GitHub shows NOASSERTION, but the text is BSD-3) ([LICENSE](https://github.com/creachadair/command/blob/main/LICENSE)). Go floor: command `go 1.26.0`, flax `go 1.23`; Headscale is on 1.27.3, fine.
- Deps: command requires `google/go-cmp` (tests) and `creachadair/mds`; flax none ([go.mod](https://github.com/creachadair/command/blob/main/go.mod)). My probe resolved only `mds` besides command itself. Headscale go.mod has command v0.2.12, flax v0.1.0, mds v0.31.0 already.
- Health: command 58 commits since 2025-11-17, all by M. J. Fromberger; flax 15. 0 open issues each, 8 stars / 0 stars. v0.x only, no GitHub releases, tags only. v0.2.3 retracted for "Bug in flag parsing on nested subcommands". One maintainer. [repo](https://github.com/creachadair/command)
- Model: `command.C` plain struct (Name, Usage, Help, Flags flag.FlagSet, SetFlags, Init, Run, Commands, Unlisted, CustomFlags), stdlib `flag` underneath; `flax` binds struct fields to flags via tags (`flag:"name,usage"`) and is optional ([flax README](https://github.com/creachadair/flax)). Runtime tree from our data: yes, `SetFlags` is a closure.
- Nesting: arbitrary via `Commands`. Aliases: none (PR #2647 emulated them as duplicate commands via `createCommandAlias`). Hidden: `Unlisted`. Deprecated: none.
- Flag syntax (probed, stdlib `flag` rules):

| Input                                    | Result                                                                                               |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `sub -o=json x` / `--o=json` / `-o json` | work (single or double dash both accepted)                                                           |
| `sub -ab x`                              | ERROR `flag provided but not defined: -ab` (no grouped shorts)                                       |
| `sub x -o json` (flag after positional)  | works (default "merge flags": `MergeFlags(true)`)                                                    |
| `sub x -- -a`                            | BUG-like: `-a` after `--` was still taken as a flag (a=true, args=[x --]). `sub -- -a x` is correct. |
| `-r 1 -r 2` repeated                     | works with a custom `flag.Value` we write; flax supports lists via TextUnmarshaler or flag.Value     |
| `-a=false`                               | works; bool needs `=` form to set false                                                              |
| Parent flags                             | merged from later in the args; ancestor flag shadows child of same name                              |

Single-letter `-o` and long `--output` need two registrations, no `-o`/`--output` pairing. flax types: bool, float64, int, int64, string, `time.Duration`, TextUnmarshaler. Required/exclusive flags: none. Env binding: none.

- Positional args: `Env.Args []string`; `command.Adapt` wraps `func(*Env, s1, s2 string, rest ...string)` with arg-count checks. Typing/validation ours.
- Completion: none. No completion code in the repo (grep). So everything is ours; the Tailscale `ffcomplete` approach (hidden `__complete` + cobra scripts) is portable by hand.
- Help: built in (`HelpInfo`, `printLongHelp`, "Did you mean" via `findCandidates`); `-h` triggers built-in output, so replacing it means intercepting before `Run` or using `CustomFlags` (UNVERIFIED how clean).
- Testability: `command.Run(env, args)` returns error, `Env.Log` writer for diagnostics, context via `Env.SetContext`. Primary output is whatever our `Run` writes.
- Notable users: Tailscale repos with `creachadair/command` in go.mod: setec, squibble, go-cache-plugin, tailsql, tskagent (go.mod search hits; direct/indirect UNVERIFIED); NOT `tailscale/tailscale` itself (its go.mod has only mds, msync, taskgroup). The author works at Tailscale (per brief). Also the author's own tools.
- Pain points: no completion; single maintainer; `--` after positional (above).

### Headscale #2647 (read with `gh`)

- "cmd/headscale: migrate CLI from Cobra to command", opened by kradalby 2025-06-17, closed 2025-06-23 with the single comment "abandon for now". 43 files, +4038/-2603. Body: "This is currently just some playing around, lets see how it turns out." No reason recorded in the thread.
- The diff: replaced cobra tree with `command.C` + `flax.MustBind`; rewrote output/table code; changed `--identifier` to `--node`; aliases written as extra commands (`createCommandAlias`, `createSubcommandAlias`); the `completion` special case was deleted and no replacement appeared in the diff (grep for "complet" shows only that removal), so the PR lost shell completion. ([PR](https://github.com/juanfont/headscale/pull/2647))
- Inference: the reasons it could not have shipped include lost completion and bundled UX changes; the thread does not say which stopped it.

### Gaps

- Real reason for closing #2647 (only the maintainer knows). Whether `Run` can be given our own help renderer.

## 3. mitchellh/cli and hashicorp/cli

### Takeaway

mitchellh/cli is archived (2024-07-22). The fork `hashicorp/cli` (created 2023-11-20) is the live successor and powers Terraform, Vault, Nomad. It is a dispatcher, not a flag parser.

### Screen card

- mitchellh/cli: MPL-2.0, last tag v1.1.5, archived true, last commit 2024-07-22 (README banner "This project is archived") ([repo](https://github.com/mitchellh/cli)).
- hashicorp/cli: module `github.com/hashicorp/cli` v1.1.7 (tag, 2026-09-29), MPL-2.0 (MPL is file-level copyleft; compatible with shipping inside a BSD-3 binary but not a plain BSD dep; flag for maintainer), `go 1.23`. 6 commits since 2025-11-17 (James Rasell; mostly CI/compliance/docs), 0 open issues ([repo](https://github.com/hashicorp/cli)).
- Deps: direct `Masterminds/sprig/v3`, `armon/go-radix`, `bgentry/speakeasy`, `fatih/color`, `mattn/go-isatty`, `posener/complete`; 15 indirect incl. `golang.org/x/crypto`. Heaviest of the four ([go.mod](https://github.com/hashicorp/cli/blob/main/go.mod)).
- Model: interface `Command{Help() string; Run(args []string) int; Synopsis() string}`; `CLI.Commands map[string]CommandFactory` keyed by space-separated names (`"nodes routes approve"`). Runtime tree: yes.
- Nesting: yes, by key prefix (radix tree); hidden via `HiddenCommands`; aliases: register the same factory under another key; deprecated: none.
- Flags: CLI core only recognises `-h/--help`, `-v/--version` and autocomplete flags; each command parses its own args (usually stdlib `flag`), so syntax is stdlib `flag` (no grouped shorts, no `--` special handling, flags after positionals stop parsing). Global flags: none inherited (UNVERIFIED but implied by design: `AutocompleteGlobalFlags` only for completion). I did not probe it.
- Completion: dynamic via `posener/complete`; bash, zsh, fish; installed by `-autocomplete-install` which edits the user's rc file (README: "supports bash, zsh and fish"); no PowerShell. Our spec data would need mapping to `complete.Command`.
- Help: `HelpFunc` replaceable. Did-you-mean: yes (UNVERIFIED in code).
- Testability: `CLI.HelpWriter`, `ErrorWriter`, `Args`, `command_mock.go`; `Run` returns an exit code.
- Users: Terraform, Vault, Nomad on `hashicorp/cli v1.1.7`; Consul and Packer still on `mitchellh/cli v1.1.5` (default-branch go.mod of each repo, 2026-11-17).

### Gaps

- Flag behaviour and completion install flow not probed; posener/complete maintenance state not checked.

## 4. devfacet/gocmd

- Module `github.com/devfacet/gocmd/v3`, MIT, `go 1.17`, v3.1.3 on 2023-04-04, one open issue, 67 stars; no commit since 2023-04-04 ([repo](https://github.com/devfacet/gocmd)).
- Model: struct tags (`command:"echo" short:"h" long:"help" required:"true"`) on an anonymous struct, handlers via `gocmd.HandleFlag("Math.Sqrt", fn)`. Reflection over a struct type fixed at compile time: cannot be fed from our `Spec` data without generating struct types at runtime, so each command would be declared twice.
- No completion in the README feature list. Nested commands exist. Not probed further.
- Knockouts hit: 24 months without commit or release (about 43 months) with no successor; runtime-data knockout.

## Open questions for the maintainer

1. Stay inside stdlib-`flag` behaviour (no grouped shorts, single-dash long flags accepted) or require GNU-style flags?
    - Option A: accept stdlib quirks (`creachadair/command`): matches `tailscale` side by side, we lose `-ab`; cost is we explain it in docs and the `--` after positional oddity must be fixed or worked around.
    - Option B: require short+long pairs and grouped shorts (ff v4 or cobra): friendlier to scripts; cost is beta dependency (ff v4) or staying on cobra.
1. How much beta risk for ff v4?
    - Option A: take ff v4 beta.1 (matches Tailscale lineage, 1 maintainer, no flags after positionals).
    - Option B: take command v0.2.x (already in go.mod, single maintainer, flags after positionals work). Both leave completion to us.
1. Completion: port Tailscale's `ffcomplete` approach (about 600 lines plus Apache-2.0 cobra scripts, dynamic, 4 shells) or keep cobra just for completion generation?
    - Option A: port: framework-free, we own it; cost about 600 lines and tests.
    - Option B: keep cobra's completion engine: zero new code; cost is staying on cobra.
