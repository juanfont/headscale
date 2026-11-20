# Screen: alecthomas/kong and alexflint/go-arg (struct-tag frameworks)

Date: 2026-11-17. Source checkouts at `~/.cache/tmp/scr/{kong,go-arg,exp}` (scratch; `exp/main.go` is the runtime-tree experiment). "Tested" = I ran it with Go 1.27.1.

## Screen card: kong

### Takeaway

Healthy, one active maintainer plus contributors, MIT, zero non-test deps. A runtime-built 3-level tree works (tested) but only by synthesising Go struct types with `reflect.StructOf`; kong has no API to add nested nodes from data. Own help can be fully off or replaced; the parsed model is public. Completion is third-party only. Verdict: go to deep research.

### Cited Findings

- Module `github.com/alecthomas/kong`, latest tag v1.17.0 (2026-10-30), prior v1.16.1 (2026-08-09), v1.16.0 (2026-07-15), v1.15.0 (2026-04-02), v1.13.0 (2025-11-13) — `git tag` in clone of [repo](https://github.com/alecthomas/kong). GitHub "releases" list is empty; tags only.
- Licence MIT; go.mod floor `go 1.20` — [repo](https://github.com/alecthomas/kong), [go.mod](https://github.com/alecthomas/kong/blob/master/go.mod).
- Health: 44 commits since 2025-11-17 (10 renovate, rest Alec Thomas, Andrew Chen, JinHyuk Sung, Abhinav Gupta, others); all-time contributors alecthomas 273, renovate 46, gak 14, abhinav 13, mitar 11; last push 2026-11-02; 35 open issues, 32 open PRs; not archived, no successor statement — `gh api repos/alecthomas/kong[/commits,/contributors]`. Effectively one lead maintainer (bus factor 1, with a few regular contributors).
- Footprint: `go list -deps .` shows only the module itself plus stdlib; go.mod lists assert/repr/gotextdiff, which are test-only. Zero runtime deps — tested.
- Model: struct tags + reflection. `kong.New(&grammar, opts...)` / `kong.Parse`; nested struct fields with `cmd:""` are commands, `arg:""` positional, other fields flags. Bind/DI: `Bind`, `BindTo`, `BindToProvider`, hooks `BeforeResolve/BeforeApply/AfterApply`, `Run()` methods — [options.go](https://github.com/alecthomas/kong/blob/master/options.go), [hooks.go](https://github.com/alecthomas/kong/blob/master/hooks.go).
- Runtime tree, the deciding question:
    - `kong.DynamicCommand(name, help, group, cmd any, tags...)` adds one command **directly under the root** from a pointer to a struct (or a func type with `Run`). README documents it in one sentence — [options.go L100](https://github.com/alecthomas/kong/blob/master/options.go), [kong.go L142](https://github.com/alecthomas/kong/blob/master/kong.go), [test](https://github.com/alecthomas/kong/blob/master/kong_test.go).
    - `kong.Embed(&struct)` splices an embedded struct's children and flags into the root; `kong.Plugins` embeds structs in an interface-typed field — [README](https://github.com/alecthomas/kong#plugins).
    - Both take a Go struct value; nesting below the first level needs struct fields with `cmd` tags. Nothing takes (name, children, flags) as data.
    - Tested: a 3-level tree `nodes routes set` (alias `approve`) built at runtime by `reflect.StructOf` with tags `cmd:""`, `aliases:"approve"`, args and `-e` flag nested, parsed `nodes routes approve n1 10.0.0.0/8 -e 24h` correctly into the leaf struct, and `Context.Command()` gave `nodes routes set <node> <routes>`. Flag after positionals worked.
    - So the adapter would, for each spec, build a mirror struct type (translate our `arg:`/`flag:`/`short:`/`help:` tags to kong's `arg:""`/`name:`/`short:`/`help:`) and nest them with `StructOf`. Doable in one adapter file, but it is reflection that writes reflection, and `reflect.StructOf` has limits (no methods, so `Run`/hooks must go through bindings or func-typed commands; field names must be exported and unique). Our entity types (`v0.Node`) would need a kong `Mapper` or a string mirror field. Not tested: custom mapper for entity types, large-tree cost.
    - Not tested but visible in source: `Kong.Model` and `Node`/`Flag`/`Value` are exported, so hand-building a model without structs looks possible, unsupported. UNVERIFIED.
- Help: `kong.NoDefaultHelp()` removes `-h/--help` (tested: `--help` then errors "unknown flag --help"); `kong.Help(HelpPrinter)` replaces the printer; `ConfigureHelp`, `ValueFormatter`, `ShortUsageOnError`/`UsageOnError` — [options.go](https://github.com/alecthomas/kong/blob/master/options.go). Suggestions: "did you mean X?" exists — [context.go L1324](https://github.com/alecthomas/kong/blob/master/context.go).
- Read-back for a spec-vs-model test: public `Application{*Node, HelpFlag}`; `Node` has Name, Help, Detail, Hidden, Flags, Positional, Children, Aliases, Tag; `Flag` has Xor, And, Envs, Aliases, Short, Hidden, Negated; `Value` carries Target — [model.go](https://github.com/alecthomas/kong/blob/master/model.go). Tested: walked the runtime tree and printed names, flag and positional counts.
- Tags (from tag.go): `required`, `optional`, `default`, `enum`, `env` (+`envprefix`), `sep`, `xor`, `and` (+`xorprefix`), `hidden`, `negatable`, `aliases`, `short`, `placeholder`, `passthrough`, `prefix`, `embed`. Enum needs required or a default. `Resolvers(...)` for config sources; `LoadConfig` — [tag.go](https://github.com/alecthomas/kong/blob/master/tag.go), [resolver.go](https://github.com/alecthomas/kong/blob/master/resolver.go).
- Custom types: `TypeMapper`, `KindMapper`, `NamedMapper`, `Mapper` interface and `MapperFunc`; built-in `time.Time` and `time.Duration` mappers; slices split on `sep` (default comma) and repeat — [mapper.go](https://github.com/alecthomas/kong/blob/master/mapper.go). We can replace the duration/time mappers with our own.
- Flag syntax: tested `--x=v`, `-e v`, flags after positionals. Other forms (grouped short flags, `--`, `--no-x` via `negatable`) from tags/README, not run. Global flags: flags on the root are inherited by subcommands (README). UNVERIFIED by me beyond reading.
- Positional args: typed, `arg:""` required by default unless `optional`; slices take rest; cannot mix positionals and child commands on one node ("can't mix positional arguments and branching arguments", [build.go](https://github.com/alecthomas/kong/blob/master/build.go)). Validation via `Validate()` methods (`Validatable`).
- Testability: `kong.Writers(stdout, stderr)`, `kong.Exit(func(int))`, `k.Parse(args)` returns error instead of exiting; `kctx.Run(binds...)` — [options.go](https://github.com/alecthomas/kong/blob/master/options.go); stdin is not injected by kong (ours to pass via binding).
- Completion: **none in core**. [issue #43 "Shell completions"](https://github.com/alecthomas/kong/issues/43) open since 2019-12-03. Third parties:
    - [willabides/kongplete](https://github.com/willabides/kongplete): bash/zsh/fish via posener/complete; last push 2024-07-15, 42 stars (stale; used by syncthing, see below).
    - [jotaen/kong-completion](https://github.com/jotaen/kong-completion): fork of kongplete; bash, zsh, fish; completion derived from kong tags with custom predictors (dynamic, answered by the app at TAB time); last push 2026-10-14, 41 stars. No powershell.
    - [miekg/king](https://github.com/miekg/king): generates static zsh/bash/fish completions and man pages from a `*kong.Node`; `completion:""` tag runs a shell command or names a bash action; last push 2026-09-24, 19 stars, author says zsh is the focus. Not dynamic in-process.
    - carapace (1490 stars, active) is multi-shell incl. powershell, cobra-centred; a kong adapter: UNVERIFIED, not found.
    - Nothing merged into kong itself that I found.
- Users: syncthing uses kong v1.16.1 and `willabides/kongplete v0.4.0` in go.mod (also `urfave/cli v1.22.17` still) — [syncthing go.mod](https://github.com/syncthing/syncthing/blob/main/go.mod). Kong first took over the main command in [PR #7330](https://github.com/syncthing/syncthing/pull/7330) (2021 era; merged). [PR #9166](https://github.com/syncthing/syncthing/pull/9166) (merged 2023-12-11) "Mostly replace urfave/cli" with kong for `syncthing cli`; author notes help text and error format changed, and `syncthing cli config` stayed on urfave/cli because it builds commands dynamically from struct reflection, bridged with kong's `passthrough:""`. [PR #9226](https://github.com/syncthing/syncthing/pull/9226) (merged 2024-01-04) added completion via kongplete and needed a declared CLI struct for it. So "syncthing moved to kong" is true for the main and `cli` commands but incomplete, and the one dynamic part is the one they did not move. No retrospective write-up found. Other well-known kong users (e.g. from the README's list): not verified here.

### Inferences

- Because kong's unit is a Go struct, our tree of specs becomes a generated tree of types. It works (tested) but the adapter is the reflection-heavy part, and kong's model, help and hooks all see our mirror structs, not our specs. Since help/docs come from specs this matters little; the spec-vs-model test is easy because `Node` is public.
- Dynamic completion (node names from the server) is only offered by kong-completion; it is a 41-star single-author fork, so we may end up owning completion code. Our own `__complete` handler fed from the specs plus a small script generator is the likely fallback; the framework choice does not buy us completion.
- The syncthing story is evidence that kong's static-struct model resists runtime-built command sets.

### Gaps

- Exact stderr/exit behaviour for bad input and whether error text can be fully replaced (we can wrap `Parse` errors; not read in detail).
- Whether an entity-typed field (`v0.Node`) can be supplied via mapper cleanly when the mirror struct is generated.
- Kong global flags inheritance and `--` handling: not run.
- Kong open issues/PR response times not sampled (35 issues, 32 PRs open; last 6 closed PRs sampled by API were old 2018 ones because of sort; no conclusion).

## Screen card: go-arg

### Takeaway

Small, alive, BSD-2-Clause, two runtime deps. Struct nesting is the only way to declare subcommands, no public model, hard-coded `-h/--help`, no completion, no xor, no enum. Verdict: weak, keep as reserve (leaning disqualify for our design; not a formal knockout).

### Cited Findings

- Module `github.com/alexflint/go-arg`, latest v1.6.1 (release 2025-12-23; tag date 2025-11-24), v1.6.0 (2025-07-12), v1.5.1 (2024-06-28), v1.5.0 (2024-05-12), previous v1.4.3 in 2022 — `gh api repos/alexflint/go-arg/releases`. Licence BSD-2-Clause (compatible with BSD-3-Clause); `go 1.18` — [go.mod](https://github.com/alexflint/go-arg/blob/master/go.mod).
- Health: 17 commits since 2025-11-17 (Alex Flint 7 across two names, Carlos Ruiz 4, others); last push 2026-11-14; contributors alexflint 342, hhromic 12, walle 9; 43 open issues-and-PRs, 16 open PRs. One maintainer. Releases are sparse (about 1 to 3 per year).
- Footprint: `alexflint/go-scalar` only at runtime — tested via `go list -deps`; testify and yaml are test-only.
- Model: struct tags + reflection; `arg.MustParse(&args)` / `arg.NewParser(Config, dests...)`; subcommands are pointer-to-struct fields tagged `arg:"subcommand:name"`; a struct holding subcommands cannot hold positionals — [README](https://github.com/alexflint/go-arg#subcommands). `NewParser` accepts several dests; `Config` has Program, IgnoreEnv, IgnoreDefault, StrictSubcommands, EnvPrefix, DefaultEnvName, AllHaveEnv, Exit, Out — [parse.go L123](https://github.com/alexflint/go-arg/blob/master/parse.go).
- Runtime tree: only by building nested struct types with `reflect.StructOf` and passing them in; no DynamicCommand/Embed/plugin equivalent. Not tested (kong test shows the technique works with tag-based reflection; go-arg's reflection should accept it, UNVERIFIED).
- Help: `-h`/`--help` hard-coded in the parser (returns `ErrHelp` from `Parser.Parse`, prints through `WriteHelp*` only if we call them) — [parse.go L561, L716](https://github.com/alexflint/go-arg/blob/master/parse.go). We can intercept `ErrHelp` ourselves, but cannot turn the flag off. Version via `Versioned` interface. No "did you mean" found by grep.
- Model read-back: none exported (`Parser.cmd` is private); only `Subcommand()` and `SubcommandNames()` — [subcommand.go](https://github.com/alexflint/go-arg/blob/master/subcommand.go). A test against our specs could only use rendered help text.
- Features by grep: subcommand aliases and `hidden` exist; `required`, `positional`, `env`, `placeholder`; `encoding.TextUnmarshaler` for custom types; slices; no `xor`/`and`, no `enum`/choices, no `negatable`, no short-flag grouping docs found (grep of README and source) — [README](https://github.com/alexflint/go-arg).
- Completion: none. [Issue #186 "Completion support"](https://github.com/alexflint/go-arg/issues/186) open since 2022-07-02, 21 comments. No third-party library found in a quick search (not exhaustive).
- Users: not checked in depth; no well-known large CLI identified. UNVERIFIED.

### Inferences

- Missing public model plus hard-coded help makes spec-vs-framework tests and our own help layer awkward; no enum/xor means we validate anyway (we do already in the builder).
- Nothing it offers beats kong for this design; it is a smaller kong without the model, hooks or mappers.

### Gaps

- Real-world user list, grouped short flags, `--` handling, flags-after-positional: not tested.
- Whether `StrictSubcommands` or dest ordering affects a runtime 3-level tree: not tested.

## Verdicts

| Project | Verdict                   | Deciding facts                                                                                                                                                                                                                                                                                                                         |
| ------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| kong    | **go to deep research**   | Runtime 3-level tree works via `reflect.StructOf` (tested); `NoDefaultHelp`+`Help()` replace help; public `Node`/`Flag` model for spec tests; mappers for time/duration; xor/and/enum/env/aliases in tags; zero runtime deps, active 2026 releases. Cost: completion third-party only, tree is mirror structs, single lead maintainer. |
| go-arg  | **weak, keep as reserve** | No public model, hard-coded `-h/--help`, no xor/enum, no completion (open issue since 2022), one maintainer with 1 to 3 releases a year. Not a knockout, but no advantage over kong for specs.                                                                                                                                         |

Answer to the main question: a struct-tag framework fits as "the input struct is the grammar" for leaves, but the tree of specs must be turned into generated struct types. Kong tolerates that; go-arg tolerates it worse. The framework does not give us completion either way.

## Open questions for the maintainer

1. Accept reflection-generated mirror structs in the adapter (kong), or require a framework with a data-driven builder (cobra, creachadair/command)?
    - Accept: lowest parse code, input structs nearly kong-native (`help`, `short` tags already match); cost is `reflect.StructOf` machinery and no methods on generated types.
    - Require data-driven: the adapter stays plain code; cost is we keep cobra-like imperative registration and kong's parse niceties are lost.
1. Shell completion: depend on `jotaen/kong-completion` (dynamic, bash/zsh/fish, 41 stars, active Oct 2026), or write our own completion handler from the specs?
    - Depend: less code; cost is a tiny single-author dependency, no powershell, and its predictors hook into kong's Node, not our specs.
    - Own: full control incl. powershell and server-fetched names; cost is writing and testing script generators for each shell (cobra supplies this today).
