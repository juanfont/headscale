# Deep research: creachadair/command (+ creachadair/flax)

Date: 2026-11-17. Phase A (desk research + probes), then Phase B (adapter + kit) at the end of
this file. **Phase B softened the Phase A verdict.** The adapter passes 112/112 MUST and 4/4
STRETCH, with 289 lines (completion included), of which 31 code lines are declared workarounds.
See "Phase B".

Sources: clones of `github.com/creachadair/command` at a1f4198 (2026-11-05, tag v0.2.13 = 530f376,
2026-11-02) and `github.com/creachadair/flax` at 90a1b15 (v0.1.0, 2026-08-31) under `spikes/src/`.
Probe: `spikes/probe-creachadair/main.go` (command v0.2.13, flax v0.1.0, go1.27.3 via `nix develop`),
modes `runnable-groups`, `plain-groups`, `reuse`, `flax`, `patched`. Every "probe:" row below is output
of that program. Line refs are to v0.2.13 files (`command.go`, `utils.go`, `help.go`).

## Verdict (short)

Liking it is not enough. The library gives us a ~250-line dispatcher and stdlib `flag` parsing. It gives
nothing for completion, aliases or typed errors, and its parsing differs from today's pflag in ways a
user sees: no `-ojson`, an unknown flag after a positional silently becomes a positional, `--`
does not end flags once a positional came first, and root flags are taken from after `--`. We can
patch every one of these in the adapter (about 60–80 lines beyond a plain adapter). By then most of
the parsing semantics are ours, and the library saves maybe 50–100 lines against "our own parser". It is
a fair finalist only if upstream takes three small changes (aliases, strict `--`, typed parse errors).
Otherwise "our own parser" gives the same result with one dependency fewer.

## 1. Parsing, exactly

### How it works (source)

- `command.Run(env, args)` (`command.go:390–442`). For each level it calls `SetFlags` once per `C` value
  (guarded by `isFlagSet`, `help.go:150–155`). Unless `CustomFlags` is set, it parses with
  `parseFlagsInternal` (`command.go:172–191`), runs `Init`, then looks up `env.Args[0]` with
  `FindSubcommand` (name match only, `command.go:307–314`) and recurses.
- With `MergeFlags(true)` (the default: `skipMerge` false), `splitFlags` (`utils.go:91–147`) scans the
  **whole** rest of argv for flags of the current level. Words that look like flags but are not in this
  level's set are treated as free words and handed down. It then calls stdlib `fs.Parse(flags ++ free)`.
  Effects:
    - flags may sit anywhere after their command, also after the leaf (D3 works, R20 works);
    - an ancestor flag "shadows" a child flag of the same name (doc on `MergeFlags`, `command.go:122–125`);
    - at the leaf, stdlib `Parse` stops at the first positional, so **any unknown flag-shaped word after
      a positional stays in `Args`** with no error.
- `--` (`utils.go:106–117`, commit 9964d3a, 2026-05-13): `--` stops scanning **only if it is the first
  free word at that level**. Otherwise it is kept as a free word and scanning goes on.
- `-h`/`-help`/`--help` not defined by us → stdlib returns `flag.ErrHelp` → the library prints long help
  to `env.Log` and returns `ErrRequestHelp` (`command.go:184–185`).
- `Flags flag.FlagSet` is a **field of `C`** and `SetFlags` runs once per `C`. A tree keeps parse state.

### The `--` question (`sub x -- -a`): by design, tested, not a setting

Probe: `t x -- -a` → `args=["x" "--"]`, `-a` set to true. Cause: `splitFlags` at the leaf sees `x` (free),
then `--` with `len(free) != 0` → append `--` to free and **continue** scanning, so `-a` is matched as a
flag. Then `Parse(["-a","x","--"])` stops at `x` and leaves `--` in `Args`.

The author tests this on purpose: `parse_test.go:171`
`{"twoMergedFlagsStopC", true, "one two -C 3 -- x --A=1 -B 2 y", "x y", noError}`: `--A=1` and
`-B 2` after the `--` are taken by the ancestors. The design is that `--` is a "stop" **for the level
at which it is the first free word**. It exists to stop ancestors from taking a child's flag
(`parse_test.go:183–188`, "poached"). It does not mean "end of all flags" (POSIX). For a CLI with flags
on the root (D3) this means **a root flag is taken from anywhere, even after `--`**:

| Input                        | Result (probe)                                              |
| ---------------------------- | ----------------------------------------------------------- |
| `nodes delete 12 -- --force` | `force=true`, `args=["12","--"]`                            |
| `nodes get -- -o`            | error `missing value for flag "-o"` (root took `-o`)        |
| `nodes delete -- -h`         | help=true (root took `-h`)                                  |
| `nodes get -- -x`            | `args=["-x"]` (correct: `--` is the leaf's first free word) |
| `nodes get 12 -- y`          | `args=["12","--","y"]` (`--` leaks into args)               |

Verdict: by design. It is a bug for a POSIX reader, and there is no setting for it. Fix in the adapter:
split argv at the first `--` before calling `command.Run`, and append the tail to the leaf args
(probe `patched`: all four rows above then come out right, ~10 lines). Remaining edge: `--name --`
(value `--`) becomes a split. pflag takes `--` as the value there.

### Stdlib `flag` syntax vs today's pflag (probe, `runnable-groups`)

| Form                                                          | pflag today                                                       | command v0.2.13                                                         | Note                                                                                                    |
| ------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `-o json`, `-o=json`, `--output json`, `--output=json`        | ok                                                                | ok                                                                      |                                                                                                         |
| `-ojson` (attached short value)                               | ok                                                                | **error** `flag provided but not defined: -ojson`                       | R16 lost. Fix: argv rewrite in adapter, ~15 lines, possible because R17 makes short letters tree-unique |
| `auth keys create alice -e24h`                                | ok                                                                | **silent**: `args=["alice","-e24h"]`, expiry not set                    | our arg-count check then says "takes 1 argument, got 2": wrong message                                  |
| `-output json`                                                | `-o` with value `utput` (pflag reads it as short `-o` + attached) | **accepted** as `--output`                                              | a second spelling                                                                                       |
| `--o json`                                                    | `unknown flag: --o`                                               | **accepted** as `-o`                                                    | a second spelling                                                                                       |
| `---output`                                                   | error                                                             | error `bad flag syntax`                                                 |                                                                                                         |
| `-ab` (grouped bools)                                         | ok                                                                | error `-ab` not defined                                                 | only `-h` is a bool short in 001, so grouping is moot (G21)                                             |
| `--force` / `--force=false` / `--force true 12`               | true / false / `true` is a positional                             | same                                                                    |                                                                                                         |
| `--force=yes`                                                 | error                                                             | error `invalid boolean value "yes"`                                     |                                                                                                         |
| `--sort -last-seen`, `--columns -ip,-os`                      | ok                                                                | ok                                                                      | value taken without a dash check (stdlib takes the next word)                                           |
| `--name ""`, `--name=`                                        | given, `""`                                                       | given, `""`                                                             | R23 ok                                                                                                  |
| `--name` at end                                               | error                                                             | error `missing value for flag "--name"`                                 |                                                                                                         |
| `--filter=owner=tag:ci --filter 'last-seen>30d'`              | ok                                                                | ok, accumulates (our `flag.Value`)                                      |                                                                                                         |
| `policy set -`                                                | ok                                                                | `args=["-"]`                                                            | R12 ok                                                                                                  |
| `hskey-auth-ab12cd-***`                                       | ok                                                                | ok                                                                      |                                                                                                         |
| unknown flag before positional (`nodes list --bogus`)         | `unknown flag: --bogus`                                           | error `flag provided but not defined: -bogus` (spelling lost: `-bogus`) |                                                                                                         |
| unknown flag **after** positional (`nodes delete 12 --bogus`) | `unknown flag: --bogus`                                           | **no error**, `args=["12","--bogus"]`                                   | fix: after the `--` split, any flag-shaped word left in args = unknown flag (~5 lines, probe `patched`) |
| flag abbreviation `--exp`                                     | no                                                                | no                                                                      |                                                                                                         |

**Short + long for one flag:** two registrations (`fs.Var(v,"output",…)`, `fs.Var(v,"o",…)`) that share
one `flag.Value`. stdlib has no pairing. "Given": `env.IsFlagSet(name)` checks one name only, so use our
own `Value` that records each `Set`. "Given twice": `-o json --output yaml` → our value saw
`["json","yaml"]` (probe), so D6's "repeated list flag is an error" is a count check in our `Value`.
Stdlib alone would silently keep the last one.

**"One way to write it":** yes, it is a problem. Every flag has two spellings (`-output` / `--output`,
`-o` / `--o`), and stdlib strips the dashes before we see the flag, so our layer cannot tell which one
was typed. To refuse them we would have to pre-scan argv against our flag table (~10 lines). That is
our own tokenizer again. If not refused, the help and docs show one spelling and the parser accepts
two. This matches `tailscale` (ffcli v3, also stdlib `flag`), which accepts both.

### Interspersed flags and flags before the subcommand (D3)

- `-c x nodes list`, `nodes list -c x`, `-o json nodes list`, `nodes -o json list`: all parse when
  `-c`/`-o` are registered on the root (probe). This is native.
- **A leaf cannot refuse `-o` by itself.** With merge, the root takes `-o` from anywhere
  (`check config -o json` → root `output=["json"]`, leaf runs). If `-o` is registered only on leaves,
  `headscale -o json nodes list` fails at the root (`-o` not defined). So D3 needs `-o` on the root, and
  the refusal is adapter code: if the root's output value was set and the leaf spec has no output →
  our "unknown flag" error (~5 lines). The same applies to `--version` (D7): register it on the root and
  refuse it below the root.
- `CustomFlags: true` plus `Init` lets a level parse its own words: the author does this himself to stop
  the poaching (`ffstools/ffs/internal/cmdstorage/cmdstorage.go:116–121`:
  `CustomFlags: true, Init: env.MergeFlags(false).ParseFlags()`).
- **How much of the library is left if we parse ourselves:** with `CustomFlags` on every level, `Run`
  does: call `SetFlags`, call `Init`, `FindSubcommand(env.Args[0])`, recurse, call `Run`, recover panics,
  cancel the context. That is about 40 lines of `command.go:390–442`. Flags before the subcommand
  (`headscale -c x nodes list`) would then need our root `Init` to strip them, or `Args[0]` is `-c` and
  dispatch fails. At that point the library is a name lookup. "Our own parser" plus a 30-line walk over
  the spec tree does the same.

### Adapter contract, item by item

| #   | Contract item                                                 | command v0.2.13                                                                                                               | Ours (lines)                                                                                                                      | Proof                            |
| --- | ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| 1   | command at a path, from runtime data                          | native: `[]*command.C` literal tree                                                                                           | ~40 to convert specs                                                                                                              | probe `build()`                  |
| 1   | aliases                                                       | **no** (no field; `FindSubcommand` matches `Name` only)                                                                       | ~6: copy the `C`, rename, `Unlisted` (probe `nodes ls --sort id` → `nodes list`)                                                  | `command.go:307`                 |
| 1   | group = no run                                                | possible, but a group with no `Run` prints its own help/"not understood" text                                                 | ~10: give every group our `Run` (gets `Args=[unknownword,…]`)                                                                     | probe `nodes frob`               |
| 1   | hidden                                                        | native `Unlisted` (only matters for the library's help, which we do not use)                                                  | 0                                                                                                                                 |                                  |
| 2   | bool / string / repeatable string, long + short               | via `flag.Value`; short+long = two registrations                                                                              | ~35 for two `Value` types that record each `Set`                                                                                  | probe                            |
| 3   | value + "given" per flag                                      | `IsFlagSet` per name only                                                                                                     | in the `Value` above                                                                                                              | probe                            |
| 3   | positionals in order, interspersed                            | native (merge)                                                                                                                |                                                                                                                                   | probe                            |
| 3   | unknown flag after positional is an error                     | **no**: silent positional                                                                                                     | ~5                                                                                                                                | probe `patched`                  |
| 3   | `-` positional                                                | native                                                                                                                        |                                                                                                                                   | probe                            |
| 3   | `--` ends flags                                               | **no** (by design, tested)                                                                                                    | ~10 argv split                                                                                                                    | probe `patched`                  |
| 3   | no arg count, no type conversion                              | native (`Run` gets `env.Args`; `Adapt` is opt-in)                                                                             |                                                                                                                                   |                                  |
| 4   | one callback, context, error returned, no print, no `os.Exit` | native with `Run` (not `RunOrFail`); `SetContext(ctx)`                                                                        | streams are in our `Ctx`                                                                                                          | `command.go:92,390`              |
| 4   | panics                                                        | forced: `Run` recovers them into `PanicError` (`command.go:391–396`)                                                          | none possible                                                                                                                     |                                  |
| 5   | help to us (`-h` anywhere, no-arg root, group)                | define `h`/`help` on the root: they are then taken from anywhere (also after `--`)                                            | ~10                                                                                                                               | probe `nodes delete 12 -h`       |
| 5   | typed parse errors                                            | **no**: plain `errors.errorString` from stdlib `flag` or `splitFlags`                                                         | ~30: path from a `SetFlags` hook (probe `patched` gives `["headscale","nodes","delete"]`), flag name by matching the message text | probe                            |
| 6   | completion                                                    | **none**                                                                                                                      | all of it; see §2                                                                                                                 | grep: no completion code in repo |
| 7   | fresh tree per run, no package state, parallel tests          | no package state, but **a reused tree leaks flag values** (probe `reuse`: 2nd run `nodes delete 13` still has `force=[true]`) | build the tree per run (cheap)                                                                                                    | probe `reuse`                    |

### DECISIONS and fixed facts

| Item                                                     | Status                                                                                                                                 | Ours (lines)                         |
| -------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| D1 binary answers at Tab                                 | none in library                                                                                                                        | ~200–250 + tests (§2)                |
| D2 bash, zsh, fish (+pwsh)                               | none in library; scripts from cobra via Tailscale                                                                                      | ~30 wiring                           |
| D3 `-c`/`-o` before or after; leaf refuses `-o`          | accept: native; refuse: ours                                                                                                           | ~5                                   |
| D4 inspectable errors                                    | no                                                                                                                                     | ~30 (message matching) or own parser |
| D5 own "did you mean" + hint table                       | library has `findCandidates` (`help.go:319`, `mstr.Similarity ≥ 0.75`) but only writes text; we route unknown words to our group `Run` | matcher is ours in any case          |
| D6 comma only, `--filter` repeats, repeated list = error | our `Value` counts                                                                                                                     | in the `Value`                       |
| D7 `headscale --version`                                 | root bool flag + refuse below root                                                                                                     | ~5                                   |
| D8 no `help` command                                     | native (no `HelpCommand` unless added); `headscale help` → root `Run(["help"])`                                                        | 0                                    |
| exit 1 on usage error                                    | ours (`RunOrFail` would exit 2; not used)                                                                                              | 0                                    |
| no abbreviations                                         | native                                                                                                                                 | 0                                    |
| `--` ends flags                                          | no                                                                                                                                     | ~10                                  |
| flags/positionals any order                              | yes, except unknown flags after positionals                                                                                            | ~5                                   |
| no env binding                                           | native (flax has `default=$VAR`, but we do not use flax)                                                                               | 0                                    |

**flax is of no use to the main CLI.** Its tag is `flag:"name[,default=V],usage"` (`flax.go:363`). There
are no short names. 001's tags (`flag:"expiry" short:"e" help:"…"`) fail `flax.Check`:
`field "Expiry": invalid flag tag format "expiry"` (probe `flax`). Our own reflection registers the
flags. The adapter would import `command` only.

## 2. Completion (D1, D2)

- Nothing in the library: no hook, no `__complete`, no script (grep over the repo; no issue ever asked).
  The answerer cannot use `command.Run` to find "where am I" either, because `Run` runs commands. So it
  walks our spec tree with our own tokenizer. The cost is **the same as for "our own parser"**: zero
  help from this framework.
- Scripts: `tailscale.com/tempfork/spf13/cobra` is an importable package (not `internal/`) in a module
  Headscale already requires (`go.mod:86`). It exports `ScriptBash/ScriptZsh/ScriptFish/ScriptPowershell(w, name, compCmd, nameForVar)` and the `ShellCompDirective` constants. The scripts are embedded and
  gzipped: bash 333, zsh 198, fish 248, ps1 259 lines. The whole package is Apache-2.0 (cobra's
  `LICENSE.txt` in the directory; `comp.go` has no header of its own; corrected in Phase B)
  (`tailscale.com@v1.98.3/tempfork/spf13/cobra/comp.go`). Tailscale's `ffcomplete` uses exactly this
  (`cmd/tailscale/cli/ffcomplete/scripts.go`). So PowerShell is free.
- What the user sees: cobra's protocol. Our answerer prints `value\tdescription` lines and a last line
  `:<directive>`. That gives descriptions (zsh, fish, and bash v2 when there are several), `NoSpace` for
  `--columns id,` and `--flag=`, file completion (default directive) for `check …` and `policy set`, and a
  value list per flag. Comma lists: we answer `id,name`, `id,namespace` for `--columns id,na`, with
  `NoSpace`.
- Ours, in lines: hidden entry point (`completion __complete -- words…`, or `__complete`) ~20;
  `completion <shell>` spec ~25; answerer (tokenize words, find node/leaf, flag needs a value?,
  candidates from spec: subcommands, aliases or not, flags of leaf + globals, values per flag, columns
  per list command, comma prefix) ~150–200; tests ~150. Tailscale's generic version is 271 lines
  (`ffcomplete/internal/complete.go`) plus ~300 glue lines.
- Risk of importing `tempfork`: it is not a supported API. Tailscale can move or drop it. The fallback is
  to copy four script files (~1040 lines of shell, Apache-2.0 NOTICE).

## 3. Errors (D4)

- `command.Run` returns, for a parse failure, the **stdlib `flag` error unchanged**
  (`flag provided but not defined: -%s`, `flag needs an argument: -%s`, `invalid boolean value %q for -%s: …`, `bad flag syntax: %s`; Go `src/flag/flag.go:1115–1136`) or a `splitFlags` error
  (`missing value for flag %q`, `utils.go:144`). All are `*errors.errorString`, with no `Env` and no
  path. The stdlib text drops the dash count (`--bogus` → `-bogus`).
- `command.UsageError{Env *Env; Message string}` exists, but **the library never returns it itself**.
  Only `env.Usagef` (user code) makes one (`command.go:328–332`).
- Unknown command: if the parent has no `Run`, the library writes `Error: nodes command "frob" not understood. Did you mean …?` to `env.Log` and returns the sentinel `ErrRequestHelp` (no word, no path)
  (`command.go:429–436`). If the parent has our `Run`, we get `Args=["frob",…]` and write our own
  error (probe).
- `Init` errors are wrapped with `%w` (`command.go:413`), so `errors.As` works on our own typed errors.
- Getting word + path without parsing text: path yes (from a `SetFlags` wrapper, probe `patched`). Flag
  word: only from the message text, or from our own pre-scan of argv.

## 4. Staying out of the way

| Automatic thing                                                    | Off?   | How                                                                                                              |
| ------------------------------------------------------------------ | ------ | ---------------------------------------------------------------------------------------------------------------- |
| help output on `-h`/`--help`                                       | yes    | define `h`/`help` flags ourselves (otherwise `flag.ErrHelp` → `printLongHelp` to `env.Log`)                      |
| help on a group without a leaf, short help on a node without `Run` | yes    | give every node a `Run`                                                                                          |
| `help` command                                                     | yes    | opt-in `command.HelpCommand(topics)`                                                                             |
| `--version` / `version`                                            | yes    | opt-in `command.VersionCommand()` (it writes to `os.Stdout` and returns `ErrRequestHelp` on success: do not use) |
| `completion`                                                       | n/a    | none exists                                                                                                      |
| suggestions                                                        | yes    | only on the paths above                                                                                          |
| usage printed on error, `os.Exit`, `log.Printf`                    | yes    | only in `RunOrFail`; use `Run`                                                                                   |
| env binding                                                        | yes    | none in `command`; flax only with `default=$VAR`                                                                 |
| sorting                                                            | yes    | none; slice order kept                                                                                           |
| global state                                                       | yes    | none in the package (only the `ErrRequestHelp` var). State lives in `C` values, so build a fresh tree per run    |
| panic recovery                                                     | **no** | `Run` always recovers panics into `PanicError`                                                                   |
| context cancel                                                     | **no** | `Run` always calls `env.Cancel(err)` when it returns (harmless)                                                  |
| ancestor flag shadowing, `--` rule                                 | **no** | only `MergeFlags(false)` (breaks interspersed) or `CustomFlags`                                                  |

## 5. Global flags before and after (D3)

See §1. Accepting them is native. Refusing `-o` on a leaf is ~5 lines, because the root owns `-o` for the
whole line. Side effect: a root flag also wins after `--` unless we split argv first.

## 6. Risk

- **People:** M. J. Fromberger, 210 of 211 commits. One outside PR merged: Dave Anderson (Tailscale),
  #5 "Fix Run with multiple levels of subcommands" (2025-01-27). Repo is owned by a user account, so only
  he can release. 8 stars, 2 forks. **No issue has ever been filed** on command (#1–#6 are all PRs, 5 his
  own) or flax (#1–#3 PRs, 2 dependabot) (`gh api repos/creachadair/{command,flax}/issues?state=all`).

- **Cadence:** 115 commits since 2023-11-17, every month but a few. 14 tags in 2026 alone (v0.2.1 …
  v0.2.13). No GitHub releases, tags only. No 1.0, and none announced.

- **API breaks, last two years:** none in exported signatures. I diffed `go doc -all` of v0.1.13
  (2024-03), v0.1.19, v0.2.0, v0.2.6 against v0.2.13: only doc text changed. The last renames were in
  2023 (`Execute`→`Run` 2021, `ErrUsage`→`ErrRequestHelp` and `Run` signature 2023-05, `MergeFlags`
  helper removed 2023-08). **Behaviour changed often in 2026**:

    - v0.2.3 retracted for "Bug in flag parsing on nested subcommands" (`go.mod`), fixed in v0.2.4;
    - `--` semantics changed (9964d3a, May 2026);
    - `ErrRequestHelp` from `Init` fixed (v0.2.7);
    - suggestions added (v0.2.9);
    - help includes flags under `CustomFlags` (v0.2.13).

    Parsing behaviour is where it moves. Our conformance tests would catch a change at bump time.

- **Security:** OSV has no entries for command, flax or mds (api.osv.dev, 2026-11-17). Small attack
  surface (no I/O, no network).

- **Go floor:** command v0.2.13 `go 1.26.0`. It follows Go closely: 1.24 (2025-08) → 1.25 (2025-12) → 1.26.0
  (2026-08). That fits AGENTS.md rule 3 today. A future bump could force Headscale's `go` directive
  ahead of nixpkgs.

- **Dependencies:** `creachadair/mds` (help/utils use `mstr`, `slice`, `value`), plus `go-cmp` in go.mod
  for tests. Both are already in Headscale's graph. flax: none.

- **Users of size:** none outside the author's circle. Tailscale's five repos list it as a **direct**
  dependency (first require block, no `// indirect`): setec v0.2.0, squibble v0.2.11, go-cache-plugin
  v0.2.6, tailsql v0.2.2, tskagent v0.2.11. Their CLIs are small: setec 9 named commands / 685 lines;
  go-cache-plugin 9 / 835; squibble 3 / 222; tailsql and tskagent one command each (83–241 lines). None
  has completion or aliases. `tailscale/tailscale` itself does not use it. Code search also shows
  Tailscale's private `corp` repo and `tailscale/mjftools` importing it for internal tools (not read).
  The largest public user is the author's `ffstools/ffs` (61 named commands, ~5100 lines, no completion),
  then `keyfish` `kf` (23). Third party: `publicsuffix/list` `psltool` (5 commands),
  `danderson/dbus`. pkg.go.dev "imported by" lists ~70 packages, nearly all `creachadair/*`, Tailscale,
  or forks of `go-cache-plugin`/headscale.

- **Size if forked / way out:** non-test code 975 lines (command.go 211, utils.go 209, help.go 320,
  version.go 146, adapt.go 89, counted without comments and blanks). The path we would execute is
  `Run`/`Env`/`C` (~211) plus `splitFlags`/`isBoolFlag`/`joinArgs` (~45), so **~250 lines** + stdlib
  `flag`. Only the adapter imports it, so the way out is one file: cheap.

- **Fair number for "our own parser":** to match what this library gives us we would write a spec-tree
  walk (~25–40 lines) plus a tokenizer (long/short, `=`/separate value, bool, attached short value,
  interspersed, `--`), ~150–200 lines. The creachadair adapter, plain plus patches, is ~185–210 lines,
  because the patches replace the tokenizer. **Net saving from the library: ~0–60 lines**, in exchange for
  stdlib-`flag` semantics and a dependency.

## 7. Evidence from others

- No project moved **to** it from cobra that I could find. No project left it with a stated reason.
  Headscale #2647 is the only migration attempt on record (§8 below).
- The author works around his own flag poaching with `CustomFlags` + `MergeFlags(false)` in `ffs storage`
  (above).
- Open bugs that would hit us: none filed (no tracker activity). The behaviours in §1 are by design and
  have tests, so they are not bugs upstream would see as such without an argument.
- Upstream scope: README "basic subcommand dispatch for Go command-line programs… based on the way the
  'go' command-line tool works"; package doc "plumbing for command dispatch". The go command has no
  completion, no aliases and no GNU flags. **No record of accepting or refusing** aliases, completion
  hooks or GNU-style flags: nobody asked (0 issues). Grep of the commit log for alias/complet/gnu/posix/
  pflag: nothing. He reverted "short help for --help" (478df19, 2024-09) and changed `--` semantics on
  his own. He accepted an outside fix from a Tailscale colleague.

## 8. Migration

- **User typing the same commands** (error text aside):

    - lost: `-ojson`/`-e24h` (attached short value) unless we rewrite argv;
    - new: `-output`, `--o` accepted;
    - unknown flags after a positional need our patch, or they become positionals;
    - `--` needs our split;
    - flags before the subcommand keep working (root flags);
    - `--force=false` same; no abbreviations either way.

    Integration tests and docs use no attached short values (grep of `integration/`, `docs/`, `nix/`).

- **nixpkgs** (`headscale completion bash|fish|zsh` at build time): we write `completion` as a `Local`
  spec that prints the tempfork scripts. The same command name works, and it needs no config and no
  server. The scripts change (cobra v2-style via Tailscale's fork, calling our `__complete`). Any
  framework but cobra has this cost.

- **128 integration calls:** only the 001 renames change them. Everything they use (`--flag value`,
  `--flag=value`, `-o json`, `-c`, `--force`) parses the same.

### Why #2647 stopped, read again with the spec in mind

The record says only "abandon for now" (2025-06-23). From the diff (`gh pr diff 2647`, command v0.1.22,
flax v0.0.5):

| Problem in #2647                                                                                                                                                                                                                                    | With 001's spec + one adapter                                                     |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| framework swap mixed with renames, new table layer, proto and `grpcv1.go` changes, resolver rewrite                                                                                                                                                 | **gone**: the spec separates them; the adapter is one file                        |
| **every short flag was silently missing.** 20 flax tags like `flag:"config,c,Config file path"`: flax reads `c,Config file path` as the usage, so `-c`, `-o`, `-u`, `-i`, `-e`, … never existed (probe `flax`: `flag provided but not defined: -c`) | **gone**: our reflection registers both names                                     |
| package-global flag structs (`globalArgs`) bound into every command's flag set; tests set globals                                                                                                                                                   | **gone**: fresh tree per run, values in our `Value`s                              |
| `--output`/`--force` bound to every command                                                                                                                                                                                                         | **gone**: adapter adds them per spec and refuses the rest                         |
| 28 aliases as `Unlisted` copies (`createCommandAlias`)                                                                                                                                                                                              | **mostly gone**: 3 aliases, ~6 lines, still copies unless upstream adds `Aliases` |
| library help text and `RunOrFail` (exit 2, `log` output)                                                                                                                                                                                            | **gone**: our help, our exit codes                                                |
| **no shell completion at all**                                                                                                                                                                                                                      | **stays**: ~200–250 lines of ours plus scripts                                    |
| stdlib syntax: no `-ojson`, unknown flag after positional, `--` rule                                                                                                                                                                                | **stays**: adapter patches ~30–40 lines, or upstream changes                      |

## Requirement table

N = native, S = setting, O = our code (lines), X = not possible.

| Req                                         | Status                                             | Lines            |
| ------------------------------------------- | -------------------------------------------------- | ---------------- |
| R01 3-level tree                            | N                                                  |                  |
| R02 tree from specs                         | N                                                  | ~40              |
| R03 groups not runnable                     | O (group `Run` = ours)                             | ~10              |
| R04 hyphen names / R05 same leaf name twice | N                                                  |                  |
| R06 aliases                                 | O (copies)                                         | ~6               |
| R08/R09 removed/reserved names unknown      | N (not in tree → our group `Run`)                  |                  |
| R10 order                                   | N                                                  |                  |
| R11–R13 raw positionals                     | N                                                  |                  |
| R12 `-` and odd positionals                 | N; `-x` needs `--` (works only as first free word) | ~10 split        |
| R15 `--flag value` / `=`                    | N                                                  |                  |
| R16 `-o json`, `-o=json`                    | N; **`-ojson` X**                                  | ~15 rewrite      |
| R17 short letters                           | N (two registrations); uniqueness test ours        |                  |
| R18 flags per command                       | N                                                  |                  |
| R19 / D3 globals where allowed              | N accept, O refuse                                 | ~5               |
| R20 interspersed                            | N (merge); unknown flag after positional O         | ~5               |
| R21 values starting `-`                     | N                                                  |                  |
| R22 verbatim values                         | N                                                  |                  |
| R23/R24 empty + given                       | O (`Value` with set record)                        | ~35 shared       |
| R25 bool / G06 `=false`                     | N                                                  |                  |
| R27 / D6 repeat and repeat-error            | O (`Value`)                                        | in ~35           |
| R31 unknown flag error                      | partial N; after positional O                      | ~5               |
| R36/R38 streams, no print/exit              | N with `Run` + `env.Log`                           |                  |
| R41 builder-added flags                     | N (`SetFlags` closure)                             |                  |
| R47 one importer                            | N                                                  |                  |
| R48 one callback                            | N                                                  |                  |
| R49/R56 build twice, parallel               | N if fresh tree (reuse leaks)                      |                  |
| R51–R53 help ours, `-h` anywhere            | O                                                  | ~10              |
| R59–R62 completion                          | X in library; O                                    | ~200–250 + tests |
| R63 no env                                  | N                                                  |                  |
| R67 context, no signals                     | N (`SetContext`)                                   |                  |
| R68 `debug create-node -r a -r b`           | O (`Value`)                                        |                  |
| D4 typed errors                             | X; O by message match                              | ~30              |
| D5 did-you-mean                             | O (ours anyway)                                    |                  |
| D7 `--version`                              | O                                                  | ~5               |
| D8 no `help`                                | N                                                  |                  |
| `--` POSIX                                  | X (by design); O                                   | ~10              |

Adapter total on the native path: **~185–210 lines** + completion ~200–250 + tests.

## Three strongest reasons for

1. Already in go.mod and used by three Headscale tools. The maintainer knows the style and the author.
   The code we would execute is ~250 readable lines, and the way out is one adapter file.
1. It stays out of the way: plain data tree, no package state, `Run` returns errors, no `os.Exit`, no env
   binding, help/version/help-command all opt-in, context injectable.
1. Interspersed flags and flags before the subcommand are native (D3 accept side, R20). The syntax
   matches `tailscale`'s stdlib-flag habits (`-flag` and `--flag`).

## Three strongest reasons against

1. Its parsing is stdlib `flag` with a merge pass, and that differs from pflag where users see it:

    - no `-ojson`;
    - a typo'd flag after a positional silently becomes a positional;
    - `--` does not end flags after a positional;
    - root flags are taken past `--`;
    - two spellings for every flag.

    Each one can be patched, but the patches make the semantics ours and the library a lookup table.

1. It provides none of the two things the framework is wanted for beyond parsing: no completion, no
   typed errors, no aliases. All three are our code, the same as with "our own parser".

1. Bus factor 1, v0.x, an issue tracker nobody has used, no large outside user. Parsing behaviour
   changed several times in 2026 (retracted v0.2.3, `--` rework). We would be the largest user by a
   wide margin.

## What we would ask upstream (if we pick it)

1. `C.Aliases []string`, matched by `FindSubcommand` (~10 lines upstream).
1. A strict `--` mode: `--` anywhere ends flag scanning for every level and is removed from `Args`
   (an `Env` setting, so the current tested behaviour stays the default).
1. Typed parse errors: `FlagError{Env, Name, Err}` (unknown/missing/invalid) and
   `UnknownCommandError{Env, Name, Candidates}` returned instead of logging + `ErrRequestHelp`.
1. Optional: report flag-shaped words after a positional at a leaf as unknown flags (setting).

Not worth asking: GNU attached short values/grouping (outside the stdlib-flag model the README states)
and completion (the go command has none). Ask in person: he has never had to refuse anything in public.

## Open questions for the maintainer

1. **If command: native parsing with patches, or `CustomFlags` + our tokenizer?**
    - (a) Native + patches (~185–210 lines adapter): least code. Users get stdlib syntax (`-output`
      accepted, `-ojson` only with a rewrite). Each library bump needs the conformance suite.
    - (b) Our tokenizer, library only dispatches: our syntax exactly. Cost: same as "our own parser" plus
      a dependency that then does almost nothing. If (b), drop the library.
1. **Ask upstream first, or patch in the adapter?**
    - (a) Ask for aliases, strict `--` and typed errors before deciding. Cost: wait time and his scope
      call. The design stays clean if he says yes.
    - (b) Patch in the adapter now (~30–40 lines). Cost: we depend on his message texts and his `--`
      rule staying the same. Tests catch drift.
1. **Completion scripts: import `tailscale.com/tempfork/spf13/cobra`, or copy them?** (same for every
   non-cobra candidate)
    - (a) Import: zero copied lines, bash/zsh/fish/pwsh. Cost: a non-API package of a dependency;
      Tailscale may move it.
    - (b) Copy four scripts (~1040 lines shell, Apache-2.0 notice). Cost: we own updates to the scripts.
1. **Attached short values (`-ojson`, `-e24h`).**
    - (a) Keep them: argv rewrite (~15 lines, valid because R17 makes letters tree-unique; debug tools
      excepted). Cost: one more pre-pass and its tests.
    - (b) Drop them and add a changelog line. No test or doc uses them today. Cost: scripts that use
      them break, and `-e24h` after a positional gives an arg-count error instead of a clear one.
1. **Is liking the author's style a tiebreaker?** If yes, the honest form is "our own parser written in
   the creachadair style" or "command after upstream says yes to (2)". If no, command loses to our own
   parser on equal lines and one dependency fewer.

______________________________________________________________________

# Phase B: the adapter spike

Code: `spikes/creachadair/` (module `spike/creachadair`, `replace spike/kit => ../kit`).

| File                            | What                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| `adapter.go`                    | the adapter, the only importer of `creachadair/command`                                          |
| `adapter_test.go`               | `kit.Conformance`                                                                                |
| `cmd/headscale/main.go`         | a test binary for the shell check (`completion <shell>`, `__complete …`)                         |
| `shelltest.sh`, `shelltest.out` | completion through bash, fish and zsh, no terminal                                               |
| `ptytab.py`                     | copy of probe-own's pty driver, with `TERM` settable; tried for zsh, not used in the end (below) |
| `RESULT.md`                     | the kit's table                                                                                  |

## How the adapter works (native path, with patches)

- **Tree.** Every `kit.Command` becomes a `command.C`. Every node, groups and root included, gets the
  same `Run`, which calls `Exec`. So the library's own help and "not understood" paths are never
  reached: an unknown word under a group arrives as `env.Args[0]`, and the kit returns
  `unknown-command`.

- **Aliases** are second `command.C` nodes (`Unlisted`) that share `SetFlags`/`Run`; a group alias
  also shares the child slice. There is no alias field.

- **Flags.** One `flag.Value` records every `Set`. It is registered under the long name and the
  letter, gives "given", "given twice" and `""`, and leaves bool parsing to `Exec`, so
  `--force=maybe` is a typed `bad-value`.

- **Root flags.** `-h`, `--version`, `-o` and `-c` are registered on the root only. `MergeFlags(true)`
  lets the root take them anywhere on the line, which is D3 and "`-h` anywhere". A leaf that lacks
  `-o` is refused by `Exec`.

- **Fresh state per call.** `command.C` keeps its `FlagSet` and calls `SetFlags` only once (Phase A
  `reuse` probe), so `Run` and `Complete` build a new tree every time. That is cheap.

- **Library still doing real work:**

    - dispatch by name, three levels;
    - the merge pass (interspersed flags, globals before or after);
    - stdlib `flag` for `--x v`, `--x=v`, `-o=json`, bools, values that start with `-`;
    - context threading.

    **I did not parse flags myself.** Completion also reuses the library: it runs the same tree on the
    words before the cursor and reads where it stopped. A `missing value for flag "--sort"` error is
    how it learns that the cursor is on a flag value.

## Numbers

| Number                                     | Value                                                                                                                                                               |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MUST                                       | **112/112** (0 skipped, zsh and pwsh on PATH)                                                                                                                       |
| STRETCH                                    | **4/4** (comma list `id,na`→`id,name`, `+ho`, `-la`, PowerShell script)                                                                                             |
| OBSERVE                                    | 13 recorded (below)                                                                                                                                                 |
| Race                                       | `CGO_ENABLED=1 go test -race -count=3`: ok (1.57 s)                                                                                                                 |
| Suite time                                 | 182 ms suite figure; `go test -count=1` wall 0.36 s                                                                                                                 |
| Adapter lines (`grep -cvE '^\s*(//.*)?$'`) | **289**, of which completion is ~114: `Complete`, value/prefix helpers, `__complete` printer, `Script`                                                              |
| Workaround lines (`grep -c '// WA'`)       | 35, i.e. **31 code lines** + 4 explanation comments                                                                                                                 |
| Modules in go.sum                          | 4: `creachadair/command`, `creachadair/mds`, `google/go-cmp` (go.mod hash only), `tailscale.com`. **New to Headscale: 0**, all four are in Headscale's go.sum today |
| Script bytes                               | bash 10020, zsh 7307, fish 10470, powershell 10486                                                                                                                  |

### Workarounds, named (all marked `// WA`)

| #   | Workaround                                                                                                                                                            | Code lines | Why                                                                                                        | MUST lost without it (ablation run)                                                                                                   |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | split argv at the first `--` before `command.Run`, append the tail to the args                                                                                        | 3          | `--` after a positional does not stop flag parsing (by design, Phase A)                                    | F23, F24. They pass natively but fail here, because #3 then refuses the literal `--with-nodes` and `-alice`. #1 and #3 come as a pair |
| 2   | map parse errors to `UsageError` by **message prefix**: `flag provided but not defined: `, `bad flag syntax: `, `missing value for flag `, `flag needs an argument: ` | 7          | the library returns plain strings with no `Env`                                                            | E09, E10, E13, E14, E15 and completion C11–C14 (10 MUST)                                                                              |
| 3   | after parsing, a flag-shaped word left in a leaf's `Args` = `unknown-flag`                                                                                            | 5          | stdlib stops at the first positional, so `alice -r` becomes two positionals                                | B03, E11, E12 (reported as arg-count)                                                                                                 |
| 4   | for a root-level `missing value`, walk the command words of argv to find the path                                                                                     | 13         | a root flag with no value fails in the root's pass, before any child is reached                            | E15 (path `[]` instead of `nodes list`)                                                                                               |
| 5   | `argv[0] == "__complete"` taken before the library                                                                                                                    | 3          | as a hidden command node, the root's merge pass would take `-o`/`-c`/`-h` out of the words being completed | none in the kit (the kit calls `Complete` directly), but needed by the real binary                                                    |

All workarounds off: **99/112 MUST**, 0/4 STRETCH.

**Argv handled before the framework sees it:** #1 (split at `--`) and #5 (`__complete`). #4 re-reads
argv, but only on the error path. #2 and #3 post-process the library's output. Nothing moves global
flags, splits `-o=json` or finds `-h`: the library does those.

**Not marked WA but there because of the library:**

- alias nodes as copies (~8 lines with the group fix-up);
- not registering root-named flags on leaves, because the root shadows them (2 lines);
- a fresh tree per call.

## OBSERVE cases

| ID      | Input                          | What it did                                                                                                                      | Cost of the other behaviour                                                                                         |
| ------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| H14     | `nodes list --bogus -h`        | `unknown-flag`                                                                                                                   | help-wins: ~2 lines (the root's `help` value is already set when the leaf fails; check it before mapping the error) |
| H15     | `nodes list -h --bogus`        | `unknown-flag`                                                                                                                   | same 2 lines                                                                                                        |
| H16     | `nodes --help list`            | help for `nodes list` (the root took `--help`, dispatch went on)                                                                 | to give `nodes` help instead we would need to know where `-h` sat: argv scan, ~5 WA lines                           |
| H17     | `-h nodes list`                | help for `nodes list`                                                                                                            | same                                                                                                                |
| V04     | `nodes list --version`         | `unknown-flag` (root took it; `Exec` refuses it on a leaf)                                                                       | to accept it: drop it from `Call.Flags` below the root, 1 line                                                      |
| **F05** | `nodes list -ojson`            | **`unknown-flag "ojson"`**: refused natively, the D11 target, **cost 0**. Accepting it would cost an argv rewrite (~15 WA lines) | —                                                                                                                   |
| F26     | `nodes set 12 --name -e`       | `name=["-e"]` (a value, like pflag)                                                                                              | missing-value instead: check the value against the flag table, ~5 lines                                             |
| F27     | `nodes list --sort --filter x` | `--filter` became the value of `--sort`, then arg-count                                                                          | same as F26                                                                                                         |
| F28     | `nodes list -ho json`          | `unknown-flag "ho"` (no grouping)                                                                                                | grouping: argv rewrite, ~15 WA lines                                                                                |
| B04     | `--force=maybe`                | `bad-value` (the kit parses the bool)                                                                                            | —                                                                                                                   |
| B05     | `--force --force`              | `flag-repeated`                                                                                                                  | last-wins: drop repeats for bools, 2 lines                                                                          |
| G11     | `-c /a nodes list -c /b`       | `flag-repeated` (both reach the root's value)                                                                                    | —                                                                                                                   |
| E21     | `--bogus nodes list`           | `unknown-flag` at path `[]` (the root's pass fails first)                                                                        | report it at `nodes list`: the #4 walk for this kind too, 1 line                                                    |

## Completion through real shells (`shelltest.sh` → `shelltest.out`)

The binary is `cmd/headscale` built from the adapter and the kit's tree. The script calls
`headscale __complete <words…>`. The answer is cobra's protocol: one candidate per line, then
`:<directive>`. Directive 4 is no file completion; directive 0 is the shell default (files).

| Line                                        | bash (`__start_headscale`, bash-completion 2.17, `bashInteractive`)                                            | fish (`complete -C`) | zsh                                     |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------- | --------------------------------------- |
| `headscale no<Tab>`                         | `nodes`                                                                                                        | `nodes`              | `nodes`                                 |
| `headscale nodes list --columns <Tab>`      | 9 columns                                                                                                      | 9 columns            | 9 columns                               |
| `headscale nodes list -o <Tab>`             | `json`                                                                                                         | `json`               | `json`                                  |
| `headscale policy set <Tab>`                | empty `COMPREPLY`; directive 0 leaves it to `complete -o default`, which a non-interactive harness cannot show | file names from cwd  | `_arguments '*:filename:_files'` called |
| `headscale nodes list --columns id,na<Tab>` | `id,name`                                                                                                      | `id,name`            | `id,name`                               |
| `headscale nodes routes ap<Tab>`            | `approve`                                                                                                      | `approve`            | `approve`                               |
| `headscale -c /x nodes l<Tab>`              | `list ls`                                                                                                      | `list ls`            | `list ls`                               |

- **zsh:** a pty run of an interactive zsh did not complete (the Tab was inserted literally, also
  with `TERM=xterm`; I did not dig further). Instead the script's own `_headscale` function was
  called with `words`/`CURRENT` set and zsh's `_describe`/`_arguments` replaced by stubs that print
  what they get. That proves the script → binary → answer path, not zsh's menu display.
- **No `NoSpace`:** after `id,name` bash and zsh add a space. Adding `NoSpace` for comma-list flags
  is 2 lines; I left it out.

### Where the scripts come from

`tailscale.com/tempfork/spf13/cobra` at the version Headscale pins
(`v1.105.0-pre.0.20261028221719-f7c1b8e52600`). It is cobra's four scripts (activeHelp removed),
gzipped and embedded, under **Apache-2.0** (cobra's `LICENSE.txt` in that directory). Tailscale uses
it for its own `ffcomplete`.

What we keep current:

- nothing, while Tailscale keeps the package;
- if it moves, the four scripts (~1040 lines of shell) are copied into Headscale with the Apache
  notice;
- the `__complete` protocol (`value[\tdesc]` lines plus `:<int>`) is ours to keep in step with the
  scripts.

The library itself contributes nothing to completion except the parse state.

## What surprised me

- **The library does more useful work than I priced in Phase A.**
    - Completion reuses its parse (path, positional count, "flag before the cursor needs a value").
    - The adapter is 289 lines with completion, against my estimate of ~185–210 without it.
    - Workarounds are 31 code lines, against an estimate of 60–80.
- **`-ojson` is refused for free.** Phase A counted it as a loss; under D11 it is the target.
- **Two workarounds depend on each other.** The "flag-shaped leftover = unknown flag" check (#3) is
  only right because `--` is split off first (#1). Without #1, F23 and F24 (which the library gets
  right natively) break.
- **Ten MUST rows (E09–E15, C11–C14) rest on four stdlib/library message prefixes.** It works, but
  the typed-error requirement (D4) is met by string matching.
- **The kit does not test the case that motivated the `--` split.** `nodes delete 12 -- --force`
  (root/leaf flag taken past `--` after a positional) is not in the suite. F23/F24 have `--` right
  after the leaf, where the library is already correct. A case like `nodes routes set 12 -- -o`
  (want args `["12","-o"]`; without the split the root takes `-o` → missing-value) would separate
  frameworks. Suggest adding it to the kit for every candidate.

## What was ugly

- Error kinds from message text: `missing value for flag %q` is the library's,
  `flag provided but not defined: -%s` is Go's. The stdlib text also drops the dashes the user typed:
  `--bogus` becomes `-bogus`. The kit normalises it, but our error sentence would have to guess.
- The path walk (#4), only to name the command when a root flag has no value at the end of the line.
- Aliases are copies of nodes. A group alias would also need its children copied in.
- `__complete` has to be intercepted before the library, because the library's design (the root
  takes its flags from the whole line) would eat the words being completed.
- `-output` and `--o` are still accepted as second spellings; the kit does not test them. Refusing
  them needs an argv scan (~10 WA lines).

## Did Phase B change the Phase A verdict?

Partly. Phase A said "liking it is not enough; our own parser gives the same with one dependency
fewer". Phase B shows the library carries real weight: dispatch, interspersed and global flags,
stdlib value syntax, and the completion state. It reaches 112/112 MUST with ~31 lines of declared
workarounds. So it is a **viable finalist on its own**, not only after upstream changes. The Phase A
objections that remain are smaller but real:

- D4 is met by matching message text;
- `--` and "unknown flag after a positional" need the paired patches;
- `-output`/`--o` are second spellings;
- one maintainer, and parsing behaviour moved in 2026.

The upstream asks (aliases, strict `--`, typed parse errors) would delete workarounds #1–#4 (about 28
of the 31 lines) and the alias copies. The comparison with "our own parser" now comes down to a
dependency whose message texts and `--` rule we rely on, against ~150–200 lines of tokenizer we
would own.

## Five years of maintaining this adapter: what would worry me

The adapter's correctness rests on things the library does not promise:

- the exact text of four error messages, two from Go's `flag` and two from `splitFlags`;
- the rule that `--` stops a level only when it is its first free word (changed once already, May
  2026);
- ancestor flags shadowing child flags;
- `SetFlags` running once per `C` value.

Any of these can change in a v0.2.x patch release from a single maintainer with no issue tracker
traffic, and the failure mode is quiet: an unknown flag becomes an untyped error, or a `--` stops
working. Only the conformance suite would notice, so it has to run on every bump of
`creachadair/command`. The scripts come from a `tempfork` directory of another project that may
disappear in any `tailscale.com` bump. Headscale's own `go` directive is tied to his, and he follows
Go releases closely. None of this is hard to fix, because the adapter is one file and the way out
(our own tokenizer under the same tree code) is ~150–200 lines. The worry is drift we do not see,
not a dead end.

## Conformance table

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
