# Deep research: alecthomas/kong (Phase A)

Date 2026-11-17. Kong v1.17.0 (tag 2026-10-30, commit af6c651). Source clones: `spikes/src/{kong,kong-completion,kongplete,complete,king}`.
Probes: `spikes/probe-kong/` (module `probekong`, kong v1.17.0, Go 1.27.3 in `nix develop`); all under
`/home/kradalby/worktrees/headscale/cli-restructure-proposal/`. "Proven" = output of `go test -v` in that module;
"source" = read in the v1.17.0 clone.

- `mirror.go` (197 non-blank, non-comment lines): approach (a), the adapter sketch: specs → `reflect.StructOf`
  mirror types → kong → `Result{Leaf, Flags (every occurrence), Args}` or a typed `ParseErr{Kind, Word, Path, Flags}`.
- `mirror_test.go`: 70 command lines from the contract and D1–D8; parallel run (200 goroutines, `-race` clean);
  env; writers; kong's raw error shape.
- `more_test.go`: missing values with/without kong's hyphen option, leaf identity by custom tag, approach (b)
  (kong on the real 001 input struct), grafting hand-built nodes, `DynamicCommand`, build twice, benchmark,
  kong's own help flag with a non-exiting `Exit`.

## Verdict in one paragraph

Kong can be the parser behind 001's adapter, but only one way is honest. It does that by generating mirror
struct types with `reflect.StructOf` and reading kong's public `Context.Path`. Kong then gives us its tokenizer
and tree walk, and nothing more. Kong's selling points are all switched off or unusable: the struct-tag grammar on
our own types, `Run`/hooks/DI, help, env/config resolvers and "did you mean". Three of kong's defaults break our
contract and must be replaced in the adapter: a short flag with `=` (`-o=json` gives `=json`), values that start
with `-`, and a flag at the end of the line. Kong has no typed unknown-flag or unknown-command error. Completion
gives nothing that meets D1/D2, so it is our code whatever we pick. The fit is real but thin: about 200 adapter
lines buy a tokenizer that an own parser would write in about the same space.

______________________________________________________________________

## 1. Is the fit real or forced? (a) mirror types vs (b) the real input struct

### (a) Mirror structs from the specs: works, honest

- Per spec node one `reflect.StructOf` type. Flag fields `F0..`, positional fields `A0..`, child-command fields
  `C0..`. The tags are generated: `name:"…"`, `short:"…"`, `cmd:""`, `aliases:"…"`, `arg:"" optional:""`. No help text in
  tags (help is ours), so nothing to escape. Proven: 3-level tree, hyphenated names (`oauth-clients`,
  `extra-records`), the same leaf name under several parents, aliases `ls`/`rm`/`approve`, all parsed
  (`mirror_test.go` TestContract rows 1–6).
- Leaf identity: kong keeps unknown tag keys. A generated `hsid:"5"` reads back as `ctx.Selected().Tag.Get("hsid")`.
  Proven (TestCustomTag → `hsid="5"`, `Path()="nodes routes set (approve)"`).
- `reflect.StructOf` limits:
    - No methods, so no kong `Run()`, `Validate()`, `Help()` or hooks on our nodes. We need none of them: the builder
      runs everything, and the spec→leaf mapping comes from the tag.
    - Exported, unique field names: generated, so this does not bite.
    - Embedded fields: none are used.
    - Type cache: reflect caches `StructOf` types forever. The same tree gives the same types, so the cache stays
      bounded.
    - None of these limits bit in the probes.
- Upgrade exposure:
    - (1) The tag grammar, stable since v0.
    - (2) `Context.Path` and `Path.Remainder()`. Both are public; `Remainder` was added in v1.10.0 (#472,
      2025-03-07).
    - (3) `ParseError.Context`, public.
    - (4) The token types in a custom mapper (`kong.ShortFlagTailToken`), public.
    - Two of these rest on *behaviour*, not on a contract: "the first word of the last path element's remainder is
      the word that failed", and "a Validate-stage error with no validating tags means the selected node has
      children". A conformance test pins both; a kong upgrade that changes trace order would fail that test, not
      production.
- Cost: build plus parse of a 63-leaf tree takes **2.0 ms, 1.58 MB, 20.8k allocs** per run (BenchmarkBuildAndParse,
  i9-13900K). That is fine for one CLI run and for a TAB answer. Building twice in one process: no error
  (TestBuildTwice).

### (b) Kong on the spec's real input struct: works by accident, then fights 001. Forced.

Proven in TestRealStruct, with 001's `routesSetIn` shape:

- Kong reads `arg:"node"` as its own `arg` marker. It ignores the value; the name comes from the field name.
  `flag:"display-name"` is ignored, the flag becomes `--name` from the field name, and `--display-name` is
  "unknown flag".
- Kong makes the positional args required: `n1` alone gives "missing positional arguments <routes>". That runs
  before our count check, so R32 breaks.
- Kong parses `time.Time` as RFC3339: `-e 90d` fails with "parsing time "90d""; R28 breaks. `[]netip.Prefix` is
  split and parsed by kong: "netip.ParsePrefix(…)"; R26 (our splitter, our error words) breaks. `v0.Node` fails at
  `kong.New` ("positional branch must have at least one child positional") until a `TypeMapper` is registered.
- To get 001's behaviour back, the spec struct would need kong tags: `optional:""`, `name:"…"`, `sep:"none"`,
  `type:"…"`. That is two tag vocabularies on one struct, with collisions on `arg`, `short`, `help`, and on any key
  we add later that kong also owns (`default`, `env`, `hidden`, `required`, `enum`, `name`, `sep`, `type`,
  `placeholder`). The rule "a spec has no framework type in it" (001 L2136) is kept in letter, because tags are
  strings, and broken in spirit: a kong release that changes a tag's default changes our parse. An `env:"…"` tag
  added by mistake would bind an env var (R63).
- (b) also does not solve the tree. `kong.DynamicCommand` adds only at the root (proven, TestDynamic), and `Embed`
  and `Plugins` splice at the root too, so depth needs `StructOf` parents anyway.

### Other ways to compose the tree

| Way                                                                                          | Result                                                                           | Judgement                                                                                                                                                                                                                                             |
| -------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DynamicCommand` / `Embed` / `Plugins`                                                       | Root level only, each takes a struct (source `options.go` L76–L112; TestDynamic) | Needs `StructOf` below the root anyway                                                                                                                                                                                                                |
| Graft hand-built `kong.Node`s (`New` one sub-app, re-parent its `Node` into another `Model`) | Parses (TestGraft)                                                               | A trick: it mutates exported fields that `build()` owns. `Tag` has an unexported `items` map, so a node cannot be built from zero. It relies on undocumented invariants (`lastWinsPeers` is computed from the model at `Trace`). Will break silently. |
| One kong parser per leaf behind our dispatcher                                               | Possible                                                                         | Our dispatcher must find the leaf first. With `-c x` before the subcommand (D3), that means our own tokenizer for root flags: half an own parser, and kong then parses one level. No gain.                                                            |
| **(a) `StructOf` mirror**                                                                    | Works (all probes)                                                               | **The honest one.**                                                                                                                                                                                                                                   |

______________________________________________________________________

## 2. Parsing, item by item

"Setting" = a kong option or a tag the adapter generates. "Ours" = code in the adapter or our layer.

| Contract / decision                                                   | Kong                        | How (proof)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------------------------------------------------- | --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1 register a command at a path, aliases, group vs leaf               | setting                     | StructOf + `cmd`/`aliases` tags. Group = node with children (TestContract)                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| C1 hidden                                                             | setting                     | `hidden:""` tag (source). Not needed if `__complete` is caught before kong                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| C2 bool flag                                                          | native                      | `--force`, `--force=true`, `--force=false` OK; `--no-force` unknown (G06 (a))                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| C2 string flag, may be `""`, may start with `-`, may hold `= : < > ,` | **ours, ~20 lines**         | Kong's default refuses `--sort -last-seen` ("expected string value but got "-last-seen" (short flag)"). `WithHyphenPrefixedParameters(true)` fixes that but makes `--name` at end of line silently `""` **and marks it given**, so `nodes set 12 --name` would reset the name. Our `NamedMapper("hsraw")` pops the next word whatever it is, errors at EOL with our typed `*MissingValue`, and strips the `=` of `-o=json`. Proven (TestMissingValue, TestContract R21/R22/missing-value rows)                                    |
| C2 repeatable string (`--filter`, debug `-r`)                         | setting + ours              | `[]string` field. The same mapper appends one value per occurrence (kong's slice decoder would comma-split, and its element parse refuses `-x`). Proven: `--filter "last-seen>30d" --filter name:web,online=true` → 2 values in order                                                                                                                                                                                                                                                                                             |
| C3 value per flag **and whether it was given**                        | native (Path)               | Each occurrence is one `Path{Flag}` entry. `--name ""` and `--name=` → given, `""`; `nodes set 12` → absent. Proven                                                                                                                                                                                                                                                                                                                                                                                                               |
| C3 positionals as `[]string`, in order, interspersed                  | setting + ours              | One optional string slot per spec arg plus an `Extra []string`. `routes set 12 --force 10.0.0.0/8` OK. **Limit**: an `[]string` positional is consumed once, so `nodes delete 12 13 --force 14` gives "unexpected argument 14" and not a list we can count (proven). Fix: K extra single slots (bounded), or count leftover words ourselves on that error (~15 lines that re-tokenize)                                                                                                                                            |
| C3 `-` as positional; `--`                                            | native                      | `policy set -` → `["-"]`; `nodes delete -- -x` → `["-x"]`; `--force -- --force` → arg `--force`. Proven                                                                                                                                                                                                                                                                                                                                                                                                                           |
| C3 no arg-count check, no type conversion                             | setting                     | All slots `optional`, all values strings: kong never counts. Proven `nodes delete 12 13 14` → 3 args to us                                                                                                                                                                                                                                                                                                                                                                                                                        |
| C4 one callback, error returned, no print, no `os.Exit`               | native                      | We do not use `Run`. `Parse` returns `(ctx, err)`, and we dispatch on the `hsid` tag. Nothing written to `Writers` (proven, TestNothingWritten). `Exit` set to a panic in probes: never hit                                                                                                                                                                                                                                                                                                                                       |
| C5 help hand-off (`-h` anywhere, bare root, group without leaf)       | setting + ours              | `NoDefaultHelp()` plus our own root bool `--help/-h`. The flag is inherited by every node. Leaf: `nodes delete --help` → leaf, help=true, args empty → our help before count. Group or root: kong returns ParseError "expected one of …", but `ParseError.Context.Path` still holds `help=true`, so our layer prints group help. Bare `headscale` → no-leaf error, path `[]` → root help. Proven. Kong's own help flag with a returning `Exit` keeps parsing and errors afterwards (TestKongHelpFlagExitReturns), so don't use it |
| C5 typed parse errors                                                 | **ours, ~40 lines**         | See §4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| C6 completion                                                         | **no**                      | See §3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| C7 fresh tree, no package state, parallel                             | native                      | No mutable package vars (source grep). But the **model is mutated during parse** (`Value.Set`, `Node.Active`, `Flag.Negated`), so it must be one `*kong.Kong` per run. 200 parallel fresh parses race-clean under `CGO_ENABLED=1 go test -race`                                                                                                                                                                                                                                                                                   |
| R12 `hskey-auth-ab12cd-***`, IPs, CIDR lists                          | native                      | Proven                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| R16 `-o json` / `-ojson` / `-o=json`                                  | native / native / **ours**  | Kong gives `=json` for `-o=json`. Upstream calls this GNU getopt behaviour and closed #570 (2026-01-11) without a fix. Fixed in our mapper (1 line). Proven                                                                                                                                                                                                                                                                                                                                                                       |
| R17 short letters                                                     | native                      | Unknown short → unknown flag. One meaning per letter is our tree test                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| R18 per-command flags                                                 | native                      | `nodes list --force` → unknown flag                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| R20 interspersed                                                      | native for one slot per arg | see C3 limit                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| R27/D6 repeated flag                                                  | native count                | `--tags a --tags b` → 2 occurrences visible (value of the first is lost: kong keeps the last). Our layer errors on count > 1 except `--filter`. `-o json -o json` same. Kong's open #441 asks for this in core, not done                                                                                                                                                                                                                                                                                                          |
| R28 time values raw                                                   | setting                     | Strings only; `-e 90d`, `-e 1d12h` reach us verbatim                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| R31 unknown flag → error                                              | native                      | yes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| R41 flags that are not fields                                         | native                      | Mirror flags come from data, not fields                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| R46 our reflection, not kong tags on spec structs                     | ours                        | Only under (a)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| R47 only the adapter imports kong                                     | native                      | Kong has zero non-std deps (`go list -deps` → only `github.com/alecthomas/kong`)                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| R49 build twice                                                       | native                      | Proven                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| R63/G22 no env binding                                                | native                      | No `env` tags and no `DefaultEnvars` mean no env read. `HEADSCALE_FORCE=1` ignored (TestNoEnv). Only `os.LookupEnv` sites are env tags (`model.go` L399, `context.go` L1370). `COLUMNS` is read for kong's help width only                                                                                                                                                                                                                                                                                                        |
| R67/G17 context, signals                                              | native                      | Kong installs no signal handler (grep). Context is ours, passed past kong                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| R34 stdin                                                             | native                      | Kong reads `os.Stdin` only in the `filecontent`/`file` mappers (unused)                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| D3 `-c`/`-o` before and after the subcommand                          | setting + ours (~5 lines)   | Declare on the root: kong accepts them at any depth (parent flags are in scope, `model.go` `AllFlags`). Proven `-c x nodes list`, `nodes list -c x`, `-o json nodes list`. Kong also accepts `check extra-records f -o json` (proven), so **our layer refuses `-o`** when the spec has no output, from the Path entry. Declaring `-o` per leaf instead makes `headscale -o json nodes list` fail at the root                                                                                                                      |
| D5 unknown command → our matcher + old-name table                     | ours                        | `ParseErr{Kind:unknown-command, Word:"node", Path:[]}`, `configtest` → `Word:"configtest"`, `auth keys approve` → `Word:"approve", Path:[auth keys]`. Proven                                                                                                                                                                                                                                                                                                                                                                      |
| D7 `--version`                                                        | setting + ours              | Our root bool flag. `headscale --version` is a no-leaf ParseError with `version=true` in the Path → our layer prints. Don't use `kong.VersionFlag` (it calls `Exit`; open regression #680 in v1.16.0 prints on any env value)                                                                                                                                                                                                                                                                                                     |
| D8 no `help` command                                                  | native                      | Kong never adds one; `help` → unknown command (proven)                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Exit code 1                                                           | ours                        | Kong's `ParseError.ExitCode()` is **80** for usage errors (`exit.go`). Irrelevant: we never call `FatalIfErrorf`, our `main` maps to 1                                                                                                                                                                                                                                                                                                                                                                                            |
| No abbreviations (G20)                                                | native                      | `--exp` → unknown flag (proven)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Grouped shorts (G21)                                                  | native                      | `-e90d` attached OK. `-fo json` → unknown `-f` (we have no bool shorts but `-h`)                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

## 3. Completion (D1, D2)

Kong core has none. [#43](https://github.com/alecthomas/kong/issues/43) has been open since 2019-12-03. The
maintainer wrote "I would love it, but just haven't had the time" (2019-12-03) and pointed to kongplete
(2020-02-19); nothing since.

| Option                                                                      | Answers at TAB from the binary (D1)                | Shells                                                                                                                                              | What the user sees                                                                   | State                                                                                                                                                                                 | Fits?                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jotaen/kong-completion](https://github.com/jotaen/kong-completion) v0.0.15 | yes, via `COMP_LINE` (bash `complete -C` protocol) | bash, zsh **via `bashcompinit`**, fish (one `complete -f -a` line); no PowerShell ([#10](https://github.com/jotaen/kong-completion/issues/10) open) | Words only, no descriptions. Fish `-f` turns off file completion. Predictors per tag | 41 stars, one author, active (last push 2026-10-14); built on **posener/complete v1.2.3**; v2 upgrade open ([#4](https://github.com/jotaen/kong-completion/issues/4))                 | **No.** Its `completion` command prints prose unless `-c`, auto-detects the login shell, and bakes `os.Executable()` into the script (`completion.go`, `shells.go`). That breaks nixpkgs' `headscale completion bash` at build time unless wrapped. Reads process env, so it cannot be injected in tests |
| [willabides/kongplete](https://github.com/willabides/kongplete)             | yes (same protocol)                                | bash, zsh (bashcompinit), fish                                                                                                                      | same                                                                                 | Last commit 2023-11-15, `go.mod` pins kong v0.8.1; syncthing still uses it                                                                                                            | No (stale)                                                                                                                                                                                                                                                                                               |
| [miekg/king](https://github.com/miekg/king)                                 | **no**: static scripts from a `kong.Node`          | zsh first; bash "can probably be done a lot better"; fish "generally unfinished" (README)                                                           | zsh descriptions                                                                     | 19 stars, no tags                                                                                                                                                                     | No (fails D1)                                                                                                                                                                                                                                                                                            |
| posener/complete itself                                                     | `COMP_LINE`                                        | bash; zsh through bash emulation; fish                                                                                                              | Words only                                                                           | v1 branch last commit 2020-12-07, last v1 tag v1.2.3 2019-10-24; v2.1.0 2023-07-19; master last commit 2025-03-05 (README). 29 open issues, PowerShell request #151 (2023) unanswered | Unmaintained in effect: the OpenTofu RFC says so (discovery.md)                                                                                                                                                                                                                                          |
| **Our own `__complete`**                                                    | yes                                                | bash, zsh, fish, PowerShell from cobra's scripts                                                                                                    | Descriptions, no-space directive, file completion, per-flag values, comma lists      | ours                                                                                                                                                                                  | **Yes**, and it needs nothing from kong                                                                                                                                                                                                                                                                  |

What our own costs. This is Tailscale's ffcomplete pattern, see screen-ff-command-mitchellh-gocmd.md:

- Scripts: copy cobra v1.10.2's templates (`bash_completionsV2.go` 484 lines, `zsh_completions.go` 308,
  `fish_completions.go` 292, `powershell_completions.go` 350, mostly script text; Apache-2.0, so we keep its LICENSE
  or NOTICE next to the copy). Tailscale did this in `tempfork/spf13/cobra` (253 lines of Go plus 4 script files).
- Answerer: `headscale __complete <words…>` walks **our spec tree**. It finds the node, decides whether the word
  before the cursor is a value-taking flag, and offers children, aliases, flags, per-flag values (`-o` → `json`,
  columns per list spec), comma-aware prefixes (`--columns id,na` → `id,name`), and a file directive for file
  positionals. It ends with cobra's `:<directive>` line. Estimate: 200–300 lines plus about 200 lines of tests.
  Tailscale's equivalent `ffcomplete/internal/complete.go` is 271 lines.
- Risk: medium-low.
    - Cobra's `__complete` protocol and directives have been stable since cobra 1.2 (2021).
    - We re-sync script fixes from cobra by hand.
    - Bash `COMP_WORDBREAKS` (`=`, `:`) around `--filter owner=tag:ci` is handled by cobra's v2 script
      (`__ltrim_colon_completions`).
- Compatibility bonus: completion scripts installed by today's cobra build call `headscale __complete`, and keep
  working after the upgrade if we speak the same protocol. kong-completion's `COMP_LINE` protocol would break
  hand-installed scripts until users reinstall them (nixpkgs regenerates at build, so it is not hit).
- **Kong's model is not needed for this.** We could use `kong.Trace` on the partial line to find the cursor node,
  which saves perhaps 30 lines of word-walking. But the values (columns, `json`, files) come from the specs anyway.
  This is a point for the "own parser" candidate: completion is our code with or without a framework, and kong
  contributes nothing to it.

## 4. Errors (D4)

- What comes back: `*kong.ParseError{error, Context *Context, exitCode}`. `Context` is public, with `Path`,
  `Args`, `Selected()`, `Command()`, and `Path[i].Remainder()` (source `error.go`, `context.go` L14–L90).

- The cause underneath:

    | Failure            | Cause type                                               | Can we `errors.As` it? |
    | ------------------ | -------------------------------------------------------- | ---------------------- |
    | Unknown flag       | `*kong.unknownFlagError`                                 | no, unexported         |
    | Unknown command    | `fmt.Errorf("unexpected argument %s[, did you mean …]")` | no, a string           |
    | Missing value      | `*expectedError`                                         | no, unexported         |
    | Group without leaf | `"expected one of …"`                                    | no, a string           |

    Proven (TestKongErrorShape: `unwrap=*errors.errorString` and `*kong.unknownFlagError`).

- How we get the kind without reading the message (proven, `classify` in `mirror.go`):

    - Path so far = the `Command` entries in `ParseError.Context.Path`.
    - Offending word = `Remainder()[0]` of the last path element.
    - Kind = word starts with `-` → unknown flag, else unknown command.
    - A trace with no error but a selected node with children (or none) → group/root without leaf.
    - Missing value → our mapper's own `*MissingValue`, which survives kong's `%w` wrap (`model.go` L368), so
      `errors.As` works.
    - Results: `node ls` → (unknown-command, `node`, `[]`); `nodes lst` → (`lst`, `[nodes]`);
      `nodes list --force` → (unknown-flag, `--force`, `[nodes list]`); `nodes set 12 -e` → (missing-value,
      `--expiry`).
    - Edges: a short cluster gives the whole word (`-fo`, not `-f`). On a trace error, flag **values** in the Path
      are not applied yet, but presence is: `--help`/`--version` still win.

- Independent confirmation: Buildkite CLI (moved to kong 2025) writes in its `main.go`: "Kong does not expose a
  typed unknown-command error", and falls back to `strings.HasPrefix(err.Error(), "unexpected argument ")`
  ([main.go](https://github.com/buildkite/cli/blob/main/main.go), `commandTelemetry`).

- "Did you mean": kong builds it into the error string (`findPotentialCandidates`, `context.go` L1309). There is no
  option to turn it off. Kong never prints it unless we call `FatalIfErrorf`; we never print kong's message, so
  our matcher is the only one the user sees. Note that kong's matcher accepts prefix or Levenshtein ≤ 2, including
  `--help` for `--exp`.

## 5. Staying out of the way

| Automatic thing       | Off / replaced?                                                      | How                                                                                                                 |
| --------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Help flag and printer | off                                                                  | `NoDefaultHelp()`; our root `-h/--help` bool. (`Help(printer)` exists, but kong's help flag calls `Exit` mid-parse) |
| `help` command        | never existed                                                        | —                                                                                                                   |
| `--version`           | not added unless `VersionFlag` is used                               | own bool                                                                                                            |
| `completion` command  | none in core                                                         | —                                                                                                                   |
| Suggestions           | in error text only, never printed by kong                            | ignore message                                                                                                      |
| Usage on error        | off by default (`UsageOnError` opt-in, and only via `FatalIfErrorf`) | —                                                                                                                   |
| `os.Exit`             | only from `FatalIfErrorf`, help/version flags, `Kong.Exit` default   | `kong.Exit(panic)` as a tripwire; never fired                                                                       |
| Writers               | `kong.Writers`; nothing written in the probes                        | —                                                                                                                   |
| Name                  | `kong.New` reads `os.Args[0]` (`kong.go` L118)                       | `kong.Name("headscale")`                                                                                            |
| Env binding           | only by `env` tags or `DefaultEnvars`                                | neither generated                                                                                                   |
| Config resolvers      | none by default                                                      | —                                                                                                                   |
| Sorting               | none; struct field order                                             | help is ours anyway                                                                                                 |
| `kong.Bind`/DI        | unused                                                               | —                                                                                                                   |
| Package state         | none mutable; the model is mutated per parse                         | one `Kong` per run; parallel proven                                                                                 |

## 6. Risk

- **People.**
    - Alec Thomas, sole merger: every PR sampled, #562–#679, `merged_by=alecthomas`.
    - Last 12 months: 44 commits, 1 committed by him directly, the rest squash-merged by him (`%cn`=GitHub).
      Authors are a long tail (Andrew Chen 4, Abhinav Gupta 2, …) plus renovate.
    - Reviews come in bursts: 9 PRs merged on 2026-08-24, several waited 4–6 weeks.
    - Bus factor 1 for releases.
- **His other work**: chroma (5.1k stars), participle, voluptuous, kong-yaml/kong-toml, hermit (Cash App), 181
  public repos.
- **Kingpin precedent**: the README now says "CONTRIBUTIONS ONLY … I no longer use Kingpin personally (I now use
  kong)" ([kingpin](https://github.com/alecthomas/kingpin)). The last release is v2.4.0 (2023-11-16). Big users
  forked or stayed frozen: Teleport runs `gravitational/kingpin` and natscli `choria-io/fisk`; Prometheus and Alloy
  stay on v2.4.0 (discovery.md). Kong is his current daily tool, but if he moves on, the kingpin path (no
  successor maintainer named) is the precedent.
- **Release pace**: 25 tags since v0.9.0 (2024-03-08); v1.0.0 on 2024-08-21; v1.13.0 2025-11-13, v1.14.0
  2026-02-07, v1.15.0 2026-04-02, v1.16.0 2026-07-15, v1.16.1 2026-08-09, v1.17.0 2026-10-30. Tags only, no GitHub
  release notes. **Release hygiene**: v1.14.0 was tagged on a commit that is on no branch
  ([#594](https://github.com/alecthomas/kong/issues/594), open).
- **Breaking changes inside v1.x**:
    - v1.2.0 `fix!: Include -- in passthrough args` (#436).
    - v1.5.0 regression "all args became passthrough", fixed in v1.5.1.
    - v1.8.0 env-as-resolver, reverted in v1.8.1.
    - v1.16.0 single-char aliases became short flags (#605), and a VersionFlag/env regression
      ([#680](https://github.com/alecthomas/kong/issues/680), open).
    - v1.17.0 rejects default-command flags before a sibling (#679).
    - None of these hit the subset we use (no passthrough, env, default commands, VersionFlag). But kong changes
      trace behaviour in minor releases, so the conformance suite must run on every bump.
- **Security**: no GitHub advisories (`security-advisories` → 0). One dependency CVE fix in 2022 (yaml, test-only).
- **Go floor**: `go 1.20`. **Deps**: zero at runtime; assert, repr and gotextdiff are test-only.
- **Binary size**: kong calls `MethodByName`/`Type.Method(i)` with non-constant names (`callbacks.go` L122–142,
  `context.go` L981), which turns off the linker's method dead-code elimination
  ([#547](https://github.com/alecthomas/kong/issues/547)). **Not a cost for Headscale**: the binary already has
  `<ReflectMethod>` through gorm (`go build -ldflags=-dumpdep ./cmd/headscale` → `gorm.io/gorm/schema.ParseWithSpecialTableName <ReflectMethod>`).
- **If abandoned**: kong is 5,152 non-blank, non-comment non-test lines. A fork would carry them all, though we
  use only the scanner, trace and model, maybe 1,500 of them. The way out is cheaper: replace one adapter file
  (~200 lines) with another framework's or our own.
- **Open bugs that would hit us**: none of the 33 open issues touch the parts we use, except #441 (no "given
  twice" error; we handle it) and #365 (`Value.Set` cannot tell default from explicit; we read the Path, not
  `Value.Set`).

## 7. Evidence from others

- **Syncthing** (kong v1.16.1, kongplete v0.4.0, urfave/cli v1.22.17 still in [go.mod](https://github.com/syncthing/syncthing/blob/main/go.mod)).
    - [PR #9166](https://github.com/syncthing/syncthing/pull/9166) (2023-12-11) moved `syncthing cli` to kong
      except `cli config`, "because it uses some magic to dynamically build commands from struct reflects". That
      magic is [`AudriusButkevicius/recli`](https://github.com/AudriusButkevicius/recli), which turns the config
      struct into urfave `cli.Command`s.
    - Kong's side is `Config configCommand \`cmd:"" passthrough:""\``with`Args []string \`arg:"" default:"-h"\``. Its `Run`builds a urfave`cli.App\` at runtime and even overrides urfave's **global** help templates "to mimic
      the kong output format"
      ([config.go](https://github.com/syncthing/syncthing/blob/main/cmd/syncthing/cli/config.go)).
    - Reading: kong has no data-driven builder, so a runtime-built tree was cheaper to keep on urfave than to port
      to kong. That is exactly our use case. They did not try `StructOf`; we did, and it works. The lesson is "kong
      gives nothing for data-driven trees", not "it cannot".
    - Completion came later via kongplete ([#9226](https://github.com/syncthing/syncthing/pull/9226), 2024-01-04).
      It needed "a CLI structure for syncthing/cli … for kongplete to be able to parse", and it is bash-protocol only.
- **Buildkite CLI**: cobra → kong ([#549](https://github.com/buildkite/cli/pull/549), 2025-09-26). Now on kong
  v1.17.0, with no cobra and **no shell completion** in the tree (tree search). It classifies errors by message
  prefix (§4).
- **gum** (charmbracelet): kong v1.15.0 + `mango-kong` for man pages. Its completion is its own generator
  (king's README says king was copied from gum).
- **micasa** left kong for cobra (2026-03-17, [#785](https://github.com/micasa-dev/micasa/pull/785)): cobra's
  completion replaced 170 lines of hand-written scripts, and in-process tests got faster (discovery.md). Kong
  users write their own completion; that matches our finding.

## 8. Migration (cobra today → kong behind the adapter)

- **A user typing the same commands**: with the `hsraw` mapper, the syntax tested matches pflag:
    - `--f v`, `--f=v`, `-o json`, `-ojson`, `-o=json`, values starting with `-`, `--x=false`, `--`, `-` as an arg,
      interspersed flags.
    - Unknown flags, a missing value and `--no-x` are errors.
    - Without that mapper, three habits break silently or loudly: `-o=json`, `--sort -last-seen`, and `--name` at
      the end of the line.
    - Error text is ours either way (D4).
- **nixpkgs**: `postInstall` runs `installShellCompletion --cmd headscale --bash <($out/bin/headscale completion bash) --fish … --zsh …`
  (`nix eval --inputs-from . nixpkgs#headscale.postInstall`). With our own `completion <shell>` printing a script
  to stdout, nothing changes. With kong-completion as shipped, it breaks (prose output without `-c`, absolute path
  baked in).
- **The 128 integration-test calls**: no syntax difference was found that they depend on. The one to watch is
  `generate private-key --output json` (C11), which is our layer's `-o` refusal, not kong's.

______________________________________________________________________

## Summary table: requirement → kong

| Requirement                                                         | Native        | Setting                    | Our code (lines)                                           | No                                 |
| ------------------------------------------------------------------- | ------------- | -------------------------- | ---------------------------------------------------------- | ---------------------------------- |
| Runtime 3-level tree from specs (R01, R02, C1)                      |               | `StructOf` + tags          | ~60 (type generator)                                       |                                    |
| Aliases, hyphen names, same leaf names (R04–R06)                    | ✓             |                            |                                                            |                                    |
| Leaf identity → spec                                                |               | custom tag `hsid`          | ~5                                                         |                                    |
| Bool flag, `=true/false` (R25, G06)                                 | ✓             |                            |                                                            |                                    |
| String flag: `""`, leading `-`, EOL error, `-o=json` (R16, R21–R23) |               | `NamedMapper`              | ~20                                                        |                                    |
| Repeatable `--filter`, `-r` (R27)                                   |               | `[]string` + mapper        | (in the 20)                                                |                                    |
| "Given" and "given twice" (R24, D6)                                 | ✓ (`Path`)    |                            | ~15 (collect)                                              |                                    |
| Interspersed positionals, any count (R20, R32)                      | partial       | slots                      | 0–15 (K slots, or recount on error)                        |                                    |
| `-`, `--` (R12, G05)                                                | ✓             |                            |                                                            |                                    |
| No arg-count/type checks of its own (R11, R28, R32)                 |               | `optional`, strings        |                                                            |                                    |
| Typed errors: kind, word, path (D4, D5)                             |               |                            | ~40 (classify by trace)                                    | typed causes: no                   |
| Help hand-off: leaf, group, bare root (R51–R53)                     |               | `NoDefaultHelp` + own flag | ~10                                                        |                                    |
| `-c`/`-o` before and after, refuse `-o` (D3, R19)                   | ✓ (inherited) |                            | ~5 (refusal)                                               |                                    |
| `--version` (D7), no `help` cmd (D8)                                | ✓             | own flag                   | ~3                                                         |                                    |
| No env, no exit, no writes, no stdin (R36–R38, R63)                 | ✓             | `Exit`, `Name`             |                                                            |                                    |
| Fresh tree per run, parallel (R49, R56)                             | ✓             |                            |                                                            |                                    |
| Completion bash/zsh/fish, `__complete` (D1, D2, R59–R62)            |               |                            | 200–300 + ~1,100 lines of copied cobra script + ~200 tests | **no (kong gives nothing usable)** |
| PowerShell                                                          |               |                            | from cobra's script                                        | no                                 |

Adapter total for parsing: about 200 lines (`mirror.go`, measured 197) plus the completion layer, which is the
same for every candidate that lacks it.

## Three strongest reasons for

1. **The tokenizer is good and proven against 70 of our command lines**: interspersed flags, attached short values,
   `--`, `-`, aliases, the inherited global flags for D3, and no abbreviations. Zero dependencies, `go 1.20` floor.
1. **Nothing leaks**: kong prints nothing, exits nothing, reads no env and no stdin, has no global state, and runs
   200 parallel parses race-clean. The public `Context.Path` gives "given", "given empty" and "given twice" exactly.
1. **The public model** (`Application`/`Node`/`Flag`/`Tag`) makes a spec-vs-model test trivial, and the `StructOf`
   route keeps all framework vocabulary inside one generated file.

## Three strongest reasons against

1. **We disable everything kong is for.** Its value is the struct-tag grammar on your own types plus `Run`/DI/help.
   Under 001 we use none of it and must *generate types* to feed it. Reflection that writes reflection, to drive a
   tokenizer that an own parser would be about the same size as.
1. **Three defaults fight our contract, and the errors are untyped.** `-o=json` → `=json` (upstream won't change
   it, #570). Hyphen values are either refused, or accepted with silent `""` at end of line. A `[]string`
   positional stops at the first flag. Unknown flag and unknown command come only as strings or unexported types,
   so our classification reads trace behaviour (Buildkite reads message text).
1. **Completion is a hole that kong's ecosystem fills badly**: posener/complete v1 (last tag 2019), zsh through
   bash emulation, no descriptions, scripts that bake in a path. We write completion ourselves, and then kong's
   model adds nothing to it. One maintainer merges everything, in bursts, with behaviour changes in minor releases
   and the kingpin precedent behind him.

## Risks in two years

- A kong minor release changes trace order, aliases or short-flag handling (it did in v1.2, v1.5, v1.16, v1.17).
  The conformance suite catches it at bump time; renovate bumps must not auto-merge.
- Alec moves on, as with kingpin. The impact is low because one ~200-line file is the exit, but a security or
  correctness fix would then be ours to fork.
- The `StructOf` adapter is the one place reviewers won't follow easily. Every contributor who touches flags must
  understand generated types. Mitigation: the adapter's own table test.
- Completion scripts copied from cobra drift from cobra's fixes. This is not kong-specific, but kong forces it.

## Open questions for the maintainer

1. **Kong's tokenizer behind generated mirror types, or an own tokenizer of the same size?**
    - Kong via `StructOf`: ~200 adapter lines; tested syntax already pflag-equivalent; costs a dependency with one
      merger, reflection-generated types, and errors classified from trace behaviour.
    - Own parser: about the same line count, with typed errors and positionals collected natively; costs owning
      every tokenizer edge case (attached shorts, `--`, `=`) and its tests.
1. **Positional overflow with interleaved flags (`nodes delete 12 13 --force 14`)**:
    - K extra single slots (e.g. 8): exact count up to K, then kong's "unexpected argument". Costs a bound nobody
      will hit.
    - Recount leftover words from the trace on that error: always exact. Costs ~15 lines that re-tokenize, i.e.
      duplicate parsing.
1. **Completion protocol**:
    - Cobra's `__complete` + cobra's scripts (Apache-2.0 copy, Tailscale's route): 4 shells with descriptions, and
      already-installed scripts keep working. Costs 200–300 Go lines, ~1,100 lines of vendored script and manual
      re-syncs.
    - kong-completion: least code. Costs: no descriptions, zsh via bashcompinit, no PowerShell, unmaintained
      posener/complete underneath, a wrapper to keep nixpkgs' `completion <shell>` contract, and broken old
      installed scripts.
1. **`-o=json`**:
    - Keep pflag's reading (our mapper strips `=`): scripts keep working. Costs one line that departs from GNU
      getopt.
    - Take kong's GNU reading: `=json` reaches our layer as an unknown format. Costs a break for any script using
      `-o=json`, which pflag accepts today and R16 requires (001 L3385 names it as a form that must work).

Not checked: man pages via `mango-kong` (G23; not wanted). Kong's size inside the 80 MB headscale binary was not
measured; it has no deps, and DCE is already off through gorm, so it should be small. carapace-spec's kong
generator was not checked; it needs carapace-bin on the user's machine, which fails D1's "binary answers".

______________________________________________________________________

# Phase B: the adapter spike

Code in `spikes/kong/` in this folder (module `spike/kong`, kit untouched).

| File                    | What                                                       |
| ----------------------- | ---------------------------------------------------------- |
| `adapter.go`            | The adapter                                                |
| `adapter_test.go`       | Runs `kit.Conformance`; writes `RESULT.md`                 |
| `cmd/headscale/main.go` | A spike binary: `__complete` and `completion <shell>` only |

Run from the worktree:

- `nix shell nixpkgs#zsh nixpkgs#powershell -c nix develop -c …go test -count=1`
- `CGO_ENABLED=1 go test -race -count=3`

Both are green.

## Which way, and why

The Phase A way (a), generated mirror structs, unchanged. It is the only way that keeps 001's specs free of kong
tags, and it uses only kong's public API:

- tags;
- `NamedMapper`;
- `Context.Path` / `Path.Remainder()`;
- `ParseError.Context`;
- `Tag.Get`;
- `kong.Trace`.

`reflect` is used only to *build* the struct types (`reflect.StructOf`) and to append to our own `[]string`
targets. It never reads kong's internals. Way (b) fights R28/R32 and puts two tag vocabularies on one struct.
Grafting nodes and per-leaf parsers are a trick and half an own parser, respectively (§1).

What the adapter does:

- **Tree.** One struct per `t.Commands` entry. Flags an ancestor already declares are left out: kong refuses
  duplicates and gives children every flag of their parents. That is how `-c`/`-o` work before and after the
  subcommand (D3). `Exec` refuses them where the leaf has none (G07–G10).
- **Leaf identity.** A tag `hs:"<index>"` on each command field.
- **Values.** Every flag is a `[]string` filled by our `valueMapper`, one element per occurrence:
    - repeats arrive for D6;
    - `--name ""` arrives as `[""]`;
    - a value may start with `-`;
    - end of line is a typed `missingValue`;
    - `-o=json` drops the `=`;
    - `-ojson` is refused as a typed `attachedValue` (D11 target);
    - a bool takes `--x` or `--x=v`, and `Exec` judges `v` (D9).
- **Positionals.** One optional string slot per `Arg`, plus `Extra []string`. Kong never counts; the kit does
  (R32).
- **Run.** Success → `Exec(path, flags, args)`. On `ParseError`, the typed mapper errors map directly to
  `MissingValue` / `UnknownFlag`. A finished trace → `Exec(path, flags)` (group, root, `--help`, `--version`).
  Otherwise the first word of `Remainder()` of the last path element → `UnknownFlag` or `UnknownCommand`.
- **Complete.** `kong.Trace` (trace only, no validate) on the words before the cursor. If its error is our
  `missingValue`, the cursor is a flag value → that flag's `Values`, comma- and `+`/`-`-aware. Otherwise the kit
  command at the traced path gives flags (cursor starts with `-`), children and aliases (group), or the next
  `Arg`'s values/files. Kong's tokenizer decides where the cursor is, so completion and parsing cannot disagree on
  flag arity or `--`.
- **Script.** `tailscale.com/tempfork/spf13/cobra` (`ScriptBash/Zsh/Fish/Powershell(w, "headscale", "__complete", "headscale")`).
  These are cobra's scripts, Apache-2.0, gzipped and embedded by Tailscale, with activeHelp removed. Headscale
  already requires `tailscale.com`. The scripts call `headscale __complete <words…>` and read cobra's
  `:<directive>` line: 4 (no file completion), or 0 (files, for `policy set`/`check config`). `Answer()` writes
  that format.

## Results

`RESULT.md`: **MUST 112/112 · STRETCH 4/4 (C18–C20 comma lists, PowerShell script) · OBSERVE 13 recorded**.
Suite 281 ms plain (359 ms under `-race`); `go test -count=1` wall about 1 s.

| Number                                                | Value                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Adapter lines (`grep -cvE '^\s*(//.*)?$' adapter.go`) | **231**. Parse side ~165, completion ~57 (`Complete` 43 + `listValues` 14), scripts and `Answer` ~15                                                                                                                                                                                                                                                        |
| Workaround lines (`// WA`)                            | **7** in `adapter.go` (error classification) + **2** in `cmd/headscale/main.go` (`__complete` dispatch)                                                                                                                                                                                                                                                     |
| Argv handled before kong                              | **Only `__complete` in `main`** (2 lines, as cobra itself does in `ExecuteC`; a hidden kong command can't do it, because kong would parse `-c /x` in `__complete -c /x nodes l` as our flag). Nothing in `Run` looks at or rewrites argv. `-o=json`, `-ojson` and hyphen values are handled *inside* kong's parse by our mapper, on the token kong hands it |
| Modules in the spike's go.sum                         | **5**: `alecthomas/kong`, its test-only `alecthomas/assert/v2`, `alecthomas/repr`, `hexops/gotextdiff`, and `tailscale.com`. In Headscale: +4 (kong and its 3 test-only modules; `tailscale.com` is already there). Zero new modules in the binary's build list except kong                                                                                 |
| Script bytes                                          | bash 10,020 · zsh 7,307 · fish 10,470 · powershell 10,486                                                                                                                                                                                                                                                                                                   |
| `-ojson` (D11)                                        | Kong **accepts** it natively (attached short value, GNU style). Refusing costs **2 lines** in our mapper (the `attachedValue` case), with no argv scan. It also refuses `-e24h`, which is the same rule everywhere                                                                                                                                          |

Workarounds, named (lines that work *around* kong rather than use it):

1. **Error classification, 7 `// WA` lines.** Kong has no typed unknown-flag/unknown-command error. We read the
   word that stopped the trace from `Path.Remainder()` and tell the two apart by a leading `-`. We infer "group
   without command" from "ParseError whose trace finished".
1. **`valueMapper`, 18 lines.** Arguably normal mapper work, but it exists because three kong defaults break the
   contract: `-o=json` → `=json`; `-x` values refused or EOL → `""`; values kept per occurrence.
1. **Skipping inherited flags in `nodeType`, 4 lines.** Kong refuses a flag that a parent already declares, while
   the kit lists globals on both.
1. **`Extra` slot, 3 lines.** Kong cannot collect interspersed positionals into one list.
1. **The generator itself, `nodeType`, 35 lines.** Not a workaround in the kit's sense, but it is the price of
   kong's struct model.

## OBSERVE rows, and the cost of the other behaviour

| ID  | Input                             | Kong adapter did                                                                       | Other behaviour and its cost                                                                                                                                            |
| --- | --------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| H14 | `nodes list --bogus -h`           | `unknown-flag "bogus"`                                                                 | Help wins: needs an argv pre-scan for `-h`/`--help` before kong (~3 WA lines), since kong's trace stops at the first bad token                                          |
| H15 | `nodes list -h --bogus`           | `unknown-flag "bogus"`                                                                 | Same; kong does not stop at `-h` (our help is a plain bool)                                                                                                             |
| H16 | `nodes --help list`               | `help nodes list`                                                                      | — (flags anywhere)                                                                                                                                                      |
| H17 | `-h nodes list`                   | `help nodes list`                                                                      | —                                                                                                                                                                       |
| V04 | `nodes list --version`            | `unknown-flag "version"` (kong accepts the inherited root flag; `Exec` refuses it)     | To accept it: kit decision, no adapter cost                                                                                                                             |
| F05 | `nodes list -ojson`               | `unknown-flag "ojson"` (adapter word `-ojson`, kit-normalised; our choice, D11 target) | To accept: delete 2 lines                                                                                                                                               |
| F26 | `nodes set 12 --name -e`          | `name=["-e"]` (pflag-like: next word is the value)                                     | `missing-value`: ~5 mapper lines refusing a word that is a known flag. That makes `--sort -last-seen`-style values ambiguous only if a column is ever named like a flag |
| F27 | `nodes list --sort --filter x`    | `sort=["--filter"]`, then arg-count (`x` is extra)                                     | Same as F26                                                                                                                                                             |
| F28 | `nodes list -ho json`             | `help nodes list` (`-h` bool in a cluster, then `-o json`)                             | —                                                                                                                                                                       |
| B04 | `nodes delete 12 --force=maybe`   | `bad-value "force"` (from `Exec`; our mapper passes the word through)                  | —                                                                                                                                                                       |
| B05 | `nodes delete 12 --force --force` | `flag-repeated "force"` (from `Exec`)                                                  | Allow: kit decision                                                                                                                                                     |
| G11 | `-c /a nodes list -c /b`          | `flag-repeated "config"` (one flag value across levels, both occurrences kept)         | Last-wins: kit decision; adapter unchanged                                                                                                                              |
| E21 | `--bogus nodes list`              | `unknown-flag [] "bogus"`                                                              | —                                                                                                                                                                       |

## Real shells (step 3)

Spike binary on `PATH` as `headscale`, scripts from `headscale completion <shell>`. Scratch under
`~/.cache/tmp/kongdeep/`; the pty driver for zsh is `zdriver/ztab.py`.

| Line (cursor at end)                   | bash (`__start_headscale`, COMP\_\* set)                             | zsh (pty, `compinit`, real Tab) | fish (`complete -C`) | pwsh (`TabExpansion2`)         |
| -------------------------------------- | -------------------------------------------------------------------- | ------------------------------- | -------------------- | ------------------------------ |
| `headscale no`                         | `nodes`                                                              | inserted `nodes`                | `nodes`              | `nodes`                        |
| `headscale nodes list --columns `      | 9 columns                                                            | 9 columns listed                | 9 columns            | —                              |
| `headscale nodes list --columns id,na` | `id,name`                                                            | inserted `id,name`              | `id,name`            | `` id`,name `` (pwsh escaping) |
| `headscale nodes list -o `             | `json`                                                               | inserted `json`                 | `json`               | `json`                         |
| `headscale policy set `                | empty `COMPREPLY`, directive 0 → bash's `-o default` file completion | files listed                    | files listed         | files                          |
| `headscale nodes routes ap`            | `approve`                                                            | —                               | —                    | —                              |
| `headscale -c /x nodes l`              | `list ls`                                                            | `list ls`                       | `list ls`            | —                              |

The bash script (Tailscale's copy of cobra's v2) needs bash-completion's `_get_comp_words_by_ref`. Without the
bash-completion package, every Tab fails with "command not found". That is the same dependency as the cobra script
Headscale ships today. `compopt` warnings appear only because the function was called outside a real completion.

## Completion scripts: source, licence, upkeep

- Source: `tailscale.com/tempfork/spf13/cobra` at the version Headscale's go.mod already pins
  (`v1.105.0-pre.0.20261028221719-f7c1b8e52600`). Cobra's scripts, Apache-2.0 (`LICENSE.txt` in that directory);
  Tailscale removed activeHelp.
- To keep current: nothing in our tree. Script fixes arrive when Tailscale re-syncs its tempfork and we bump
  `tailscale.com`, which we do anyway.
- Risks:
    - Tailscale may change or remove the package. It is an internal tempfork, not an API promise. The fallback is
      copying the four files (Apache-2.0, ~38 KB) into our tree.
    - The protocol (`__complete`, `:<directive>`) is cobra's. Scripts already installed by today's cobra-built
      Headscale keep working.
- Kong contributes nothing to the scripts. It contributes the cursor position via `kong.Trace`.

## What surprised me

- **112/112 MUST** on the first run of the full adapter. Most of the credit goes to the kit, which owns
  repeats, bools, arg counts and the `-o` refusal, and to our mapper. Kong's part is the tokenizer and tree walk,
  which proved solid.
- `kong.Trace` plus our typed `missingValue` gives completion "the word before the cursor is a flag that wants a
  value" for free, with no completion-side tokenizer.
- Tailscale's tempfork made the four-shell scripts a one-line import, and all four worked through real shells,
  PowerShell included.
- One kong quirk shows in G11: a root flag given at two levels accumulates into one value. That is good for the
  kit's D6 check, and different from cobra.

## What was ugly

- `reflect.StructOf` to generate types whose only reader is kong. A reviewer must think in generated struct tags
  to follow the adapter.
- Error kinds come from trace behaviour (first word of the remainder, a leading `-`), not from types. A kong
  change in how trace records progress silently changes our error kinds, though the conformance suite would catch
  it.
- "ParseError with a finished trace = group without command" holds only while we generate no validating tags.
  That is an implicit invariant.
- Positionals interleaved after the overflow slot (`nodes delete 12 13 --force 14`) still give "unknown command
  14", not an arg-count error. The suite has no such case.

## Did Phase B change the Phase A verdict?

It moved it up a notch and did not reverse it.

- Moved up: the fit is real. Every MUST passes with 231 lines, 9 declared workaround lines, and no argv rewriting
  in `Run`.
- Not reversed: the shape is unchanged. Kong is used only as a tokenizer and tree walker behind generated types.
  Its typed-error gap is papered over by trace reading. Completion is ours (borrowed scripts plus ~57 lines). An
  own parser would need about the same lines without the reflection layer and the dependency.

## Five years of this adapter: what would worry me

The adapter rests on three things kong does not promise:

- that the first remaining word after the last traced element is the one that failed;
- that a ParseError with a finished trace can only mean "no command" while we add no validating tags;
- that kong will keep handing a custom mapper the raw `ShortFlagTailToken`.

Kong changed trace behaviour in minor releases four times since v1.0 (passthrough, aliases-as-shorts,
default-command flags). One person merges and tags everything, sometimes after weeks of silence. His previous
parser ended as "contributions only" with no successor maintainer. So every kong bump has to go through the full
conformance suite by hand-review, never auto-merge.

The `StructOf` generator is code nobody will want to touch: the first contributor who needs a new flag kind
(an int, or a hidden flag) will have to learn kong's tag grammar *and* reflect's struct building to add three
lines.

None of this is dangerous, because the exit is one 231-line file and the kit proves a replacement. But it is
five years of paying a dependency for the part of parsing that is cheapest to own.

## Conformance table (`spikes/kong/RESULT.md`)

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
| F28          | OBSERVE | G21         | `headscale nodes list -ho json`                                                                    |                                                                                  | `help nodes list`                                                                | SEEN   |
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
| C18          | STRETCH | R60         | `headscale nodes list --columns id,na<TAB>`                                                        | `has id,name`                                                                    | `id,name`                                                                        | PASS   |
| C19          | STRETCH | R60         | `headscale nodes list --columns +ho<TAB>`                                                          | `has +hostname`                                                                  | `+hostname`                                                                      | PASS   |
| C20          | STRETCH | R60         | `headscale nodes list --sort -la<TAB>`                                                             | `has -last-seen`                                                                 | `-last-seen`                                                                     | PASS   |
| S-bash       | MUST    | D1 D2 R59   | `Script(bash)`                                                                                     | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-zsh        | MUST    | D1 D2 R59   | `Script(zsh)`                                                                                      | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-fish       | MUST    | D1 D2 R59   | `Script(fish)`                                                                                     | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| S-powershell | STRETCH | D1 D2 R59   | `Script(powershell)`                                                                               | `non-empty, names headscale, syntax check passes`                                | `syntax ok`                                                                      | PASS   |
| I01          | MUST    | R49 R56 G26 | `every case twice, in parallel, fresh tree each`                                                   | `same outcome both times, no panic`                                              | `ok`                                                                             | PASS   |
