# Requirements a CLI framework must meet for Headscale (from 001)

Source: `docs/proposals/001-cli.md` in `/home/kradalby/worktrees/headscale/cli-restructure-proposal`
(3582 lines, read in full on 2026-11-17, commit fef27c697). "L123" = line in 001. Today's code:
`cmd/headscale/cli/*.go` (cobra v1.10.2 + pflag v1.0.10 + viper).

Columns in the matrix:

- **Need**: H = hard (001 states it, or a stated test depends on it), N = nice to have.
- **Who**: P = framework must **provide** it; B = framework must **not block** it (Headscale's
  `command` layer does it); P/B = framework must provide the hook, our layer does the work.
- **Test**: a concrete check for the spike. "→" means "must result in".

The framework's job per 001 is narrow (L2132–2139): read the command line into a tree of
commands, flags and args, and write completion scripts. Everything else is our layer.

______________________________________________________________________

## 1. Requirements matrix

### Command tree, names, aliases

| ID  | Requirement                                                                                                                                                                                                                                                                                                     | 001                                                              | Need | Who | Test                                                                                                                                                                                                |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---- | --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R01 | Nested command tree, depth 3 below root (`nodes routes set`, `auth keys create`, `api oauth-clients delete`).                                                                                                                                                                                                   | Command tree, L95–178                                            | H    | P   | `headscale api oauth-clients delete c9f2 --force` dispatches to the leaf `api/oauth-clients/delete` with args `["c9f2"]`.                                                                           |
| R02 | Tree built at runtime from our spec data (one adapter loop over the specs), not declared in the framework's own way per command.                                                                                                                                                                                | Our layer, L2137; Design decisions L3104                         | H    | P   | Adapter builds the full tree from a `[]Spec` slice with no per-command framework code; adding a spec adds a command.                                                                                |
| R03 | Group nodes (`nodes`, `auth`, `api`, `check`, `generate`, `debug`, `nodes routes`, …) are not runnable; every leaf is.                                                                                                                                                                                          | L93                                                              | H    | P   | `headscale nodes routes` (no leaf) does not call any leaf `Run`; it reaches our help/handler (see G15).                                                                                             |
| R04 | Names with hyphens: `update-client`, `oauth-clients`, `derp-map`, `extra-records`, `private-key`, `nixos-options`, `cli-reference`, `create-node`.                                                                                                                                                              | L95–178                                                          | H    | P   | `headscale check extra-records r.json` dispatches to `check/extra-records`.                                                                                                                         |
| R05 | Same leaf name under different parents (`list`, `get`, `set`, `delete`, `create`, `keys` under `auth` and `api`, `approve` under `auth` and alias under `nodes routes`).                                                                                                                                        | L120–170, L206                                                   | H    | P   | `auth keys list` and `api keys list` reach two different specs.                                                                                                                                     |
| R06 | Command aliases, per command: `ls`→every `list`, `rm`→every `delete`, `approve`→`nodes routes set` only. No group aliases.                                                                                                                                                                                      | Aliases, L196–206; Validation L2130                              | H    | P   | `headscale nodes rm 12` = `nodes delete 12`; `headscale nodes routes approve 12 10.0.0.0/8` = `routes set`; `headscale node ls` → unknown command; `headscale auth keys approve` → unknown command. |
| R07 | Aliases must be listable by our help ("(alias: approve)") and reference.                                                                                                                                                                                                                                        | L2159, L2271                                                     | H    | B   | Help and reference read aliases from the spec, not from the framework.                                                                                                                              |
| R08 | Removed names must not resolve: `configtest`, `dumpConfig`, `health`, `mockoidc` (top-level), `preauthkeys`, `apikeys`, `oauth-clients` (top-level), `nodes register/rename/backfillips/list-routes/approve-routes/tag`, `users rename/destroy`, `policy check`, `generate` alias `gen`, all old group aliases. | Commands that go away L208–220; changelog L2429–2469, L2543–2562 | H    | P   | Each old form exits 1 with an error on stderr; none runs. (Error wording: G11/G12.)                                                                                                                 |
| R09 | Reserved, unbuilt names stay unknown: `nodes authorize`, `nodes deauthorize`, `--preauthorized`, `--ignore-ssh-sessions`.                                                                                                                                                                                       | Reserved names L3127–3144                                        | H    | P   | `headscale nodes authorize 12` → unknown command, exit 1.                                                                                                                                           |
| R10 | Sibling ordering for help is our tree order (local, server, debug sections), not alphabetical.                                                                                                                                                                                                                  | Help on three levels L2233–2256                                  | H    | B   | Our root help prints `serve`, `version`, `check …` first, regardless of framework sort.                                                                                                             |

### Verbs, targets, resolvers

| ID  | Requirement                                                                                                                                                                                                | 001                                                      | Need | Who | Test                                                                                                                           |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ---- | --- | ------------------------------------------------------------------------------------------------------------------------------ |
| R11 | Positional args reach our layer as raw strings, in order; the framework does no typing or lookup. Resolvers (ID/IP/name/hostname/email/prefix) run in our builder after the client exists.                 | Targets and resolvers L269–349; builder steps L2081–2087 | H    | B   | `headscale nodes set 100.64.0.1 --name x` → args `["100.64.0.1"]`.                                                             |
| R12 | A positional may look like an IP, an email, a key (`hskey-auth-ab12cd-***`, containing `*`), a CIDR list, `tag:ci,tag:build`, `exit`, `-` (stdin). None may be treated as a flag or glob by the framework. | L276–278, L310, L1372, L1745–1750                        | H    | P   | `headscale policy set -` → args `["-"]`; `headscale auth keys get 'hskey-auth-ab12cd-***'` → args `["hskey-auth-ab12cd-***"]`. |
| R13 | Second positional (`auth register <auth-id> <user>`, `routes set <node> <routes>`, `tags set <node> <tags>`) and flag values (`--user`) also go through resolvers. Framework sees only strings.            | L314                                                     | H    | B   | `headscale auth register hskey-authreq-x alice` → args `["hskey-authreq-x","alice"]`.                                          |
| R14 | One target per command; no variadic bulk targets now, but "can be added without a break".                                                                                                                  | L316, L3120                                              | N    | B   | Adding a `<node>...` arg later needs only a spec change.                                                                       |

### Flags

| ID  | Requirement                                                                                                                                                                                                                                             | 001                                                                                                                                                                | Need | Who | Test                                                                                                                                                                                                                |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R15 | Long flags `--flag value` and `--flag=value`.                                                                                                                                                                                                           | Our layer L2139                                                                                                                                                    | H    | P   | `--expiry 24h` and `--expiry=24h` give the same value.                                                                                                                                                              |
| R16 | Short flags `-o json`, `-ojson`, `-o=json` all work (today `-o=json` is mis-detected by an arg scan).                                                                                                                                                   | Short flags L375–388; Impl. notes L3385                                                                                                                            | H    | P   | All three set output=`json`.                                                                                                                                                                                        |
| R17 | Short letters allowed: only `-o`, `-c`, `-h`, `-e`, `-d`, `-u`. Every other flag long only. One meaning per letter across the tree (debug tools exempt).                                                                                                | L377–388; Validation L2128                                                                                                                                         | H    | P/B | `headscale auth keys create alice -r` → unknown flag; our tree test fails on a letter with two meanings.                                                                                                            |
| R18 | Flags are per command. `--force` exists only on commands that can prompt; on others it is an unknown flag.                                                                                                                                              | `--force` L365–373; changelog L2527, L2538                                                                                                                         | H    | P   | `headscale nodes list --force` → error, exit 1; `headscale nodes delete 12 --force` → force=true.                                                                                                                   |
| R19 | "Global" flags: `--output/-o` on every server command, `debug health`, `version`; `--config/-c` on every command that reads the config; `--help/-h` on every command. Not on `serve` (`--output`), `completion`, `check`, `generate`, debug test tools. | Global flags L353–363; L180                                                                                                                                        | H    | P   | `headscale check config -o json` → unknown flag; `headscale version -o json` OK. Placement before the subcommand: G03.                                                                                              |
| R20 | Flags may come after positionals and between them (interspersed).                                                                                                                                                                                       | L520 `nodes delete 12 --force`; L1927 `xargs -n1 headscale nodes delete --force` (flag before arg); L2972 `auth keys create "$owner" --reusable --expiry 24h "$@"` | H    | P   | `nodes delete --force 12` and `nodes delete 12 --force` both → force, args `["12"]`.                                                                                                                                |
| R21 | Flag values that begin with `-` are values, not flags: `--sort -last-seen`, `--columns -ip`, `--columns -ip,-os`.                                                                                                                                       | `--sort` L971, L973; `--columns` L805                                                                                                                              | H    | P   | `headscale nodes list --sort -last-seen` → sort=`-last-seen`; `--columns -ip` → columns=`-ip`.                                                                                                                      |
| R22 | Flag values with `=`, `:`, `<`, `>`, `,` are kept verbatim: `--filter owner=tag:ci`, `--filter=owner=alice`, `--filter 'last-seen>30d'`, `--filter name:web,online=true`.                                                                               | `--filter` L869–961                                                                                                                                                | H    | P   | `--filter=owner=tag:ci` → filter=`owner=tag:ci`.                                                                                                                                                                    |
| R23 | Empty string value is accepted and distinguishable from "flag not given": `--name ""` resets the node name; `--picture-url ""` clears; `users set --name ""` is an error; `set` with no flag is an error.                                               | L1297, L1309, L1431, L1436, L1438, L396                                                                                                                            | H    | P   | `nodes set 12 --name ""` → name set=true, value=`""`; `nodes set 12` → name set=false.                                                                                                                              |
| R24 | "Was this flag given" is visible to our layer for every flag (also for `--columns` + `--all`, `--columns` + `-o json`).                                                                                                                                 | L817, L1603                                                                                                                                                        | H    | P   | Adapter can ask "set?" per flag, independent of the default value.                                                                                                                                                  |
| R25 | Bool flags: `--reusable`, `--ephemeral`, `--force`, `--all`, `--with-nodes`, `--dry-run`, `--running`, `--list-columns`, `--bypass-server-and-access-database-directly`. Present means true.                                                            | Tree L100–178; L1775                                                                                                                                               | H    | P   | `--dry-run` → true; absent → false. `=false` form: G06.                                                                                                                                                             |
| R26 | List values: one comma-separated string per value; our layer splits and parses (routes, tags, scopes, columns). Empty list (`""`) is an error with its own word, from our layer.                                                                        | Lists as input L400–412                                                                                                                                            | H    | B   | `routes set 12 ""` → our error `the route list is empty.` (not a framework error). Framework must pass `""` through as a positional.                                                                                |
| R27 | Repeated flag for `--filter` (and per the struct comment, `--tags`): values accumulate in order.                                                                                                                                                        | L879; L2039                                                                                                                                                        | H    | P   | `--filter name:web --filter online=true` → `["name:web","online=true"]`. Which other flags repeat: G07.                                                                                                             |
| R28 | Time values (`--expiry`, filter times) are parsed by our one parser (timestamps, dates, `30m`, `90d`, `2w`, `1d12h`, `now`, `never`). The framework must not parse them as Go durations.                                                                | Time values L414–443; L2046                                                                                                                                        | H    | B   | `-e 90d` reaches our parser as the string `90d`; no framework error.                                                                                                                                                |
| R29 | Defaults that depend on the command and on "now" (auth key 1h, API key 90d) are applied by our layer, not shown as a computed timestamp in help.                                                                                                        | L434, L1584, L1667                                                                                                                                                 | H    | B   | `auth keys create alice` with no `-e` → our builder fills 1h.                                                                                                                                                       |
| R30 | `--output` takes only `json`; table is the default. Unknown value → our error `unknown output format "yaml". Use json.`                                                                                                                                 | Output L543; L2625                                                                                                                                                 | H    | B   | `-o yaml` reaches our layer as `yaml`; our layer errors.                                                                                                                                                            |
| R31 | Unknown flag on a command → error, exit 1. Wording today is pflag's (`unknown flag: --force`).                                                                                                                                                          | Principles L79; L2538                                                                                                                                              | H    | P   | `nodes list --force` → stderr starts `Error: unknown flag: --force` if the wording is kept (G10).                                                                                                                   |
| R32 | Argument count is checked by our builder before any server call, with our exact text and the usage line. Framework must not reject or accept extra args on its own.                                                                                     | Argument count L445–463; builder step 1 L2081; L2190                                                                                                               | H    | B   | `nodes routes set 12` → stderr `` Error: `nodes routes set` needs 2 arguments, got 1. `` + usage; `nodes delete 12 13` → `needs 1 argument, got 2.`; `nodes routes list 12 13` → `takes at most 1 argument, got 2.` |
| R33 | Required input is positional; no required flags on normal commands. `set` needs at least one flag (our check).                                                                                                                                          | Positional or flag L390–398                                                                                                                                        | H    | B   | `nodes set mynode` → our error `nothing to change. Give at least one of …`. Required flags for debug tools: G16.                                                                                                    |

### Confirmation prompts, streams, exit codes, errors, secrets

| ID  | Requirement                                                                                                                                                                                                   | 001                                                              | Need | Who | Test                                                                                    |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ---- | --- | --------------------------------------------------------------------------------------- |
| R34 | Prompts read stdin; no terminal on stdin → error `confirmation needed, but there is no terminal.` exit 1. Framework must not read or close stdin, and stdin plus "is a terminal" must be injectable in tests. | Confirmation prompts L466–539; builder step 6 L2086; tests L2218 | H    | P/B | In-process: stdin=`"y\n"` + fake TTY → proceeds; stdin=pipe → error text, exit 1.       |
| R35 | Declined prompt prints `Aborted.` and exits 1.                                                                                                                                                                | L526–531                                                         | H    | B   | stdin `n` + TTY → exit 1.                                                               |
| R36 | stdout = result only; stderr = errors, prompts, notes, update hint. Every framework-originated text (parse errors, completion) must go to writers we choose.                                                  | Streams and exit codes L647–662                                  | H    | P   | Inject two buffers; nothing reaches `os.Stdout`/`os.Stderr` directly. Help stream: G13. |
| R37 | Exit 0 = done, exit 1 = not done (error, declined prompt, failed check). No other codes are stated.                                                                                                           | L653–654                                                         | H    | P/B | Framework returns an error value; our `main` maps to exit code. Usage-error code: G09.  |
| R38 | Framework must not print errors itself or call `os.Exit`; errors are plain text on stderr as `Error: <lower-case sentence>` in both output modes; stdout empty on error.                                      | Errors L664–679; L1173                                           | H    | P   | Parse error with `-o json` → stdout empty, stderr `Error: …`.                           |
| R39 | Secrets of `create` go to stdout alone; notes on stderr.                                                                                                                                                      | Secrets L681–712                                                 | H    | B   | `KEY=$(headscale auth keys create alice)` captures only the key.                        |
| R40 | Server commands print no log lines; `-o json` changes only the format (no log silencing by arg scan).                                                                                                         | L658, L662, L2617                                                | H    | B   | No framework logging on stdout/stderr.                                                  |

### Table engine flags

| ID  | Requirement                                                                                                                                                                        | 001                            | Need | Who | Test                                                                                                                                                |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | ---- | --- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| R41 | Every `ListSpec` gets `--columns`, `--list-columns`, `--filter`, `--sort` added by the builder (not declared in the input struct). The adapter must add flags that are not fields. | L180; builder L2091            | H    | P   | `headscale users list --sort -count` parses on every list command.                                                                                  |
| R42 | `--columns` grammar (`a,b` or `+a,-b`), unknown column with "Did you mean", `--columns` + `-o json` error: all ours.                                                               | `--columns` L800–823; L775–781 | H    | B   | `--columns id,nmae` → our `Did you mean "name"?`.                                                                                                   |
| R43 | `--list-columns` prints and exits without a server, before client creation and the version check.                                                                                  | `--list-columns` L825–863      | H    | B   | `nodes list --list-columns` with no server running → table, exit 0. (Builder order L2081–2089 puts client at step 3: our layer must short-circuit.) |
| R44 | `--filter`, `--sort` values reach us verbatim (R21, R22, R27).                                                                                                                     | L867–987                       | H    | P   | `--filter 'expiry<7d' --sort expiry` → `["expiry<7d"]`, `expiry`.                                                                                   |
| R45 | `--all` on key and OAuth client lists, in the input struct.                                                                                                                        | L148, L157, L162, L1603        | H    | P   | `auth keys list --all` → all=true.                                                                                                                  |

### Command spec, builder, adapter

| ID  | Requirement                                                                                                                                                                          | 001                                | Need | Who | Test                                                                                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------- | ---- | --- | ----------------------------------------------------------------------------------------- |
| R46 | Flags derived from input-struct fields (`flag:"expiry" short:"e" help:"…"`, `arg:"node"`), via our reflection, not the framework's struct tags.                                      | Input struct L2030–2053            | H    | P   | Adapter registers flags from our reflected field list; no framework tags on spec structs. |
| R47 | Nothing outside the adapter file imports the framework; `Ctx` never exposes a framework type; `Run` never reads a flag by name.                                                      | Our layer L2132–2139               | H    | P   | `go list -deps` of every package except the adapter excludes the framework module.        |
| R48 | One callback per leaf: framework hands our builder the leaf identity, parsed flags (value + set), raw args, a context, and streams; our builder runs steps 1–9 and returns an error. | What the builder does L2077–2091   | H    | P   | All leaves share one run function.                                                        |
| R49 | `command.New` validation at startup and a unit test that builds the whole tree. Building the tree must be cheap, repeatable and free of global state.                                | Validation L2120–2130; Tests L2176 | H    | P   | Build the tree twice in one process; no panic for "already registered".                   |
| R50 | Framework must not own help, docs, validation, output, time parsing, config, the API client.                                                                                         | Brief; L2132–2139                  | H    | B   | Each can be replaced or disabled.                                                         |

### Help, reference, docs, tests

| ID  | Requirement                                                                                                                                                                                          | 001                                  | Need | Who | Test                                                                                                                                  |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ---- | --- | ------------------------------------------------------------------------------------------------------------------------------------- |
| R51 | Help fully replaceable at three levels: root (full nested tree, grouped "Local / Server / Debug"), group (sub-tree + examples), leaf (Long, usage, `<node> is …` line, examples, flags).             | Help on three levels L2225–2322      | H    | P/B | `headscale`, `headscale --help`, `headscale nodes routes --help`, `headscale nodes set --help` print exactly our text (golden files). |
| R52 | `headscale` with no arguments prints the root help (same as `--help`).                                                                                                                               | L2167, L2227                         | H    | P   | `headscale` → root help. Exit code: G15.                                                                                              |
| R53 | `-h/--help` on every command, wherever it appears in the line, wins over arg-count and unknown-value checks.                                                                                         | L359                                 | H    | P   | `headscale nodes delete --help` (no target) → help, not `needs 1 argument`.                                                           |
| R54 | `generate cli-reference` prints one Markdown page from the specs; CI diffs it against `docs/ref/cli.md`. Output must be deterministic.                                                               | Reference page L2324–2338            | H    | B   | Two runs give byte-identical output.                                                                                                  |
| R55 | Tests read the specs (tree walk, short-letter uniqueness, `--force` iff `Confirm`, columns vs generated type, no command with unbounded args).                                                       | Tests that keep it honest L2174–2192 | H    | B   | Walk uses our spec tree, not framework objects.                                                                                       |
| R56 | In-process test helper runs the real tree against `servertest` over a unix socket and returns stdout, stderr, exit code; one table per group; every `Example` line is a case. Milliseconds per case. | Every command is tested L2194–2206   | H    | P   | `run(t, "nodes","list","-o","json")` → (stdout, stderr, code) with no `os.Exit`, no global state, safe under `t.Parallel()`.          |
| R57 | "This document as tests": every example, error text and changelog before/after row is a case, including the old command failing "with its hint".                                                     | L2208–2223                           | H    | P/B | `run("configtest")` → exit 1 + hint text (see C1, G11).                                                                               |
| R58 | Docker integration tests run the real binary for every command.                                                                                                                                      | L2206                                | H    | B   | No framework requirement beyond R56.                                                                                                  |

### Completion

| ID  | Requirement                                                                                                                                | 001                               | Need | Who | Test                                                                                                                     |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------- | ---- | --- | ------------------------------------------------------------------------------------------------------------------------ |
| R59 | `headscale completion <shell>` writes a completion script to stdout. Shells not named.                                                     | Tree L116; L2171; L2137           | H    | P   | `headscale completion bash \| bash -n` passes. Shell list: G01.                                                          |
| R60 | Completes commands, aliases?, flags, and column names for `--columns`, `--filter`, `--sort` (per list command, from the specs).            | Shell completion L2364–2368; L772 | H    | P   | `headscale nodes list --sort <TAB>` offers `id name owner … last-seen …`; `users list --sort <TAB>` offers user columns. |
| R61 | TAB never calls the server.                                                                                                                | L2368                             | H    | P   | Completion with no server and no config → no delay, no network.                                                          |
| R62 | Live node/user names can be added later "without changing any command": the completion mechanism must allow runtime value callbacks later. | L2368; L3121                      | N    | P   | Spike: a callback that returns names for `nodes get <TAB>` can be wired in the adapter alone.                            |

### Config, environment, version, non-API commands

| ID  | Requirement                                                                                                                                                                                                                            | 001                                                | Need | Who | Test                                                                                            |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- | ---- | --- | ----------------------------------------------------------------------------------------------- |
| R63 | `HEADSCALE_CONFIG` = `--config`. No other flag has an env var; there must be no `HEADSCALE_OUTPUT`, `HEADSCALE_FORCE`. Framework must not auto-bind env vars to flags.                                                                 | Configuration and environment L1987–2003           | H    | P/B | `HEADSCALE_FORCE=1 headscale nodes delete 12` (no TTY) → still `confirmation needed`.           |
| R64 | Config loading (koanf) is ours and per command: a server command with no config file prints no warning; `version` reads config only if present; `mockoidc` reads none; bypass needs full config. Framework needs no config/viper link. | L2003; L1886; L1911; L1777; Impl. notes L3377–3381 | H    | B   | No framework init hook is needed; no `os.Args[1]` special-casing (L3379).                       |
| R65 | CLI/server version check is a round tripper on the API client; runs in builder step 4 for non-`Local` specs.                                                                                                                           | Version check L1950–1985; L3361                    | H    | B   | No framework role.                                                                              |
| R66 | `version` (command) prints info and an update hint on stderr; `-o json` with Go field names; no update check on other commands.                                                                                                        | `version` L1870–1890                               | H    | B   | No framework `--version` behaviour that triggers anything (G08).                                |
| R67 | `serve`: long-running, no `--output`, takes `--config`; errors with multi-line hints; runs until signal. `debug mockoidc`: long-running, env-var configured, no headscale config.                                                      | Tree L100; L1911; `serve.go`                       | H    | P/B | `serve` gets a cancellable context; framework installs no signal handler of its own (G17).      |
| R68 | `debug mockoidc` and `debug create-node` keep their current flags and are exempt from the rules (short letters, tests). Today `create-node` has `-u`, `-k`, `-r`, required flags, and a repeatable/comma `--route` (`StringSliceP`).   | L1911; L2192; L388; `debug.go`                     | H    | P   | `debug create-node --name a -u alice -k K -r 10.0.0.0/8 -r 10.1.0.0/16` parses as today. (G16.) |
| R69 | Database bypass flag changes which steps run (no client, needs full config, prompts). `generate config --running` is a local command that asks the server.                                                                             | L1773–1797; L42; L1868                             | H    | B   | Builder reads the parsed flag before step 3 (flags are parsed at step 2, so possible).          |
| R70 | Platforms built today: linux, darwin, freebsd (amd64/arm64); no Windows.                                                                                                                                                               | `.goreleaser.yml` targets                          | N    | P   | Builds with `CGO_ENABLED=0` on those targets. (G19.)                                            |

______________________________________________________________________

## 2. The adapter contract

From "The command spec" (L2005–2140) plus the requirements above. In words, the one adapter file
needs a framework that lets it:

1. **Register a command at a path** (`["nodes","routes","set"]`) at runtime from our data, with:
   name, aliases (list of words), and a marker "group" (no run) or "leaf" (one run callback).
   Optional per command: hidden (only if G12/G18 answers need it).
1. **Register flags on a leaf** (not inherited unless we choose), each with: long name, optional
   one-letter short, kind. Kinds needed:
    - **bool** (present = true);
    - **string** (one value, may be `""`, may start with `-`, may contain `= : < > ,`);
    - **repeatable string** (values accumulate in order) — for `--filter`, possibly `--tags`
      (G07), and `--route` of `debug create-node`.
      Help text and defaults are ours; the framework may store them but must not need them.
1. **Parse argv** and give back, for the chosen leaf: for every flag its value(s) **and whether it
   was given**; the positional args as `[]string`, in order, with flags interspersed; `-` as a
   positional; `--` honoured (G05). No arg-count check of its own, no type conversion beyond
   bool/string.
1. **Call one function of ours** with (leaf identity, parsed flags, args, `context.Context`,
   stdin, stdout, stderr) and **return its error** to the caller without printing it and without
   `os.Exit`.
1. **Hand control to us for help**: `-h/--help` anywhere, no-arg root, a group with no leaf — we
   print. Parse errors (unknown flag, unknown command, missing flag value) come back as errors,
   ideally typed (which flag, which command, suggestions), so our layer writes the `Error:` line.
1. **Write completion scripts** for the chosen shells (G01), where the scripts know: the command
   tree, aliases, flags per leaf, and **per-flag value lists** we supply (column names per list
   command; `json` for `-o`; shell names for `completion`) plus file completion for file
   positionals (`check …`, `policy set`). Values must be comma-aware (`--columns id,na<TAB>`,
   `+`/`-` prefixes; `--filter` column before the operator) — or we accept plain-word completion
   (G02). Hook for a later runtime callback (R62).
1. **Run in-process many times**: a fresh tree per invocation, no package-level state, args/streams/
   context injected, safe in parallel tests.

**Go types of input-struct fields that must become flags** (L2043–2050 plus the tree):

| Field type                                     | Framework kind                      | Parsed by                          |
| ---------------------------------------------- | ----------------------------------- | ---------------------------------- |
| `string`                                       | string                              | — (needs "given" bit: `--name ""`) |
| `bool`                                         | bool                                | framework                          |
| a number (none in the tree today)              | string or int                       | ours or framework                  |
| `time.Time`, `time.Duration` (`--expiry`)      | string                              | our time parser                    |
| `[]string`, `[]netip.Prefix` (`--tags`)        | string (comma) or repeatable string | our splitter                       |
| an entity `v0.User` (`api keys create --user`) | string                              | our resolver                       |
| `command.Owner` (positional only today)        | —                                   | our resolver                       |

Flags added by the builder, not fields: `--output/-o` (string), `--config/-c` (string),
`--force` (bool, iff `Confirm`), `--columns`, `--sort` (string), `--filter` (repeatable),
`--list-columns` (bool), `--help/-h`.

Positionals: always strings to the framework; typing, resolving and counting are ours.

______________________________________________________________________

## 3. Gaps: what 001 does not state (each is an open question)

Format: what 001 says today → why the framework choice depends on it → two answers and cost.

**G01. Which shells get completion.**
001: `completion <shell>` (L116), "Cobra … writes the shell completion scripts" (L2137). No list.
Why: frameworks differ in which shells they generate for, and the "second thing would be new code"
(L2139). (a) bash, zsh, fish: covers Linux/macOS admins; every candidate must do three.
(b) also powershell: only useful with Windows (G19); narrows candidates or means writing a script.

**G02. "Static" completion: baked into the script, or answered by the binary?**
001: "Completion is static: commands, flags, and the column names" (L2366); "TAB never calls the
server" (L2368). Why: cobra-style completion calls the binary (`headscale __complete …`) on every
TAB; a framework with script-only completion embeds lists. (a) Binary answers (hidden completion
entry point, our specs, no config/no network): column lists stay exact per command, live names later
(R62) are trivial; cost: a hidden command/entry point in the tree and the "no network" rule must be
enforced on that path. (b) Lists baked into generated scripts: no binary call on TAB; cost: the
script is stale when the binary changes, comma-list completion (`id,na<TAB>`) is hard in pure shell,
and R62 later needs a framework change.

**G03. Global flags before the subcommand.**
001: tables say where `-o`, `-c` exist (L355–361); every example puts them after the leaf. Nothing on
`headscale -c /x nodes list` or `headscale -o json nodes list`. Why: needs inherited/persistent flag
parsing on group levels; some parsers accept flags only after the leaf. (a) Accept on any level
(today's cobra persistent flags; muscle memory, NixOS kit/scripts may use it); cost: `-o` would then be
accepted on `check …` at root level unless filtered, conflicting with R19. (b) Only after the leaf;
cost: breaks `headscale -c x …` habits silently at upgrade — must be in the changelog.

**G04. Flags after positionals: also after `--`-less trailing words?**
001 implies interspersed flags (R20) but never says it. Why: POSIX-strict parsers stop at the first
positional. (a) Interspersed everywhere (today's behaviour). (b) Strict order; cost: breaks L520,
L1927, L2972 examples. Answer (a) looks implied; confirm.

**G05. `--` handling.**
001: silent. A positional that starts with `-` (a username, a description via flag value is fine) is
otherwise impossible to pass. Why: parsers differ on whether `--` is supported and whether it is
passed through. (a) `--` ends flags, rest are positionals (POSIX). (b) No `--`; cost: a user named
`-x` cannot be a target except by ID.

**G06. Bool forms.**
001: silent on `--force=false`, `--reusable=true`, `--no-…`. Why: some parsers offer negation
(`--no-x`), some accept `=false`, some neither. (a) Accept `--x` and `--x=true|false`, no `--no-x`
(today's pflag behaviour; scripts can pass `--force=$FLAG`). (b) Only `--x`; cost: `--force=false`
becomes an error, smaller grammar to test and document.

**G07. Repeated flags versus comma lists.**
001: "Every list value is comma separated" (L402); `--filter` "may also be repeated" (L879); input
struct comment on `--tags`: `"a,b" or repeated` (L2039); the old `oauth-clients create --scope … --scope …`
form is replaced (L2885). Why: decides whether the adapter needs a repeatable kind generally or
only for `--filter`. (a) Comma only, `--filter` the one repeatable flag; cost: one special case in the
adapter and the tests. (b) Every list flag accepts both; cost: two spellings to document and test,
and a value cannot contain a comma either way.

**G08. `--version`.**
001: tree has a `version` command (L101); global flags table has no `--version` (L355–359). Why:
several frameworks add `--version` automatically, cobra adds it only if `Version` is set. (a) No
`--version`: `headscale --version` is an unknown flag, exit 1. (b) `--version` = `version` without
the update check; cost: a second spelling and a choice whether it checks GitHub.

**G09. Exit code of a usage error.**
001: "exit 1: not done: an error, a declined prompt, a failed check" (L654); no mention of 2. Why:
some frameworks exit 2 on parse errors by default. (a) Always 1 (today; what 001's tables imply).
(b) 2 for usage errors (POSIX/getopt habit, lets scripts tell typos from failures); cost: change to
L647–656 and every arg-count test.

**G10. Unknown-flag and parse-error wording.**
001: `Error: unknown flag: --force` (L2538) — this is pflag's text verbatim. Arg-count text is ours
(L451). Why: tests compare full stderr (L2217–2219); a framework change changes this text unless our
layer rewrites it, which needs typed errors. (a) Our layer owns all parse-error text (needs typed
errors or a parser wrapper); cost: adapter code. (b) Accept the framework's text and update golden
files on a switch; cost: user-visible wording drifts with the framework.

**G11. Unknown command text and "did you mean".**
001: column typos get "Did you mean" (L779). Unknown commands: nothing. The changelog drops group
aliases (`node`, `user`, L204) — exactly what a Levenshtein suggestion catches. Why: cobra suggests
built in; others don't. (a) Suggest nearest command/alias (and print the group's commands); cost:
needs framework support or our own matcher on the spec tree. (b) Plain `unknown command "node"`; cost:
every upgrading user's first typo gets no help.

**G12. Old commands: hint or plain failure?** (see C1)
001 says both: "one case per old command, for the hint that says where it went" (L2216) and "the old
one fails with its hint" (L2223), versus "no deprecated shims and no stubs that print a hint" (L2372,
L3076). Why: a hint needs either hidden stub commands (framework must support hidden commands and
arbitrary trailing args/flags on them) or a lookup table in our unknown-command error path (needs the
raw argv on a parse error). (a) Old→new table consulted only on an unknown-command/flag error; cost:
a table that is a list kept by hand (conflicts with L2145), lives one release. (b) No hint, plain
unknown command; cost: tests per old command only check exit 1; changelog carries everything.

**G13. Help stream and exit code.**
001: help is "the documentation" (L87) but the stream for help is not stated; stdout carries "the
result" (L651). Why: frameworks differ (some print usage on stderr on error, help on stdout on
request). (a) Requested help → stdout, exit 0; help shown because of a usage error → stderr, exit 1.
(b) Always stdout; cost: `headscale nodes 2>/dev/null` style scripts see help text in output.

**G14. `help` as a command.**
001: only `--help`/`-h` (L359, L2167). Cobra adds `headscale help <cmd>` automatically. Why: name
reservation and test walk. (a) No `help` command: `headscale help` → unknown command; cost: users of
`help nodes` habit get an error. (b) `help [path…]` = `--help`; cost: a non-spec command in the tree
that the "every command has a case" walk must know about.

**G15. Group invoked without a leaf.**
001: "Every leaf is a runnable command" (L93); `headscale` alone prints the tree (L2227); group alone
(`headscale nodes`) not stated. Why: some frameworks error "missing command", some print help.
(a) Print group help to stdout, exit 0. (b) Print group help to stderr, exit 1 (it did nothing);
cost: differs from root behaviour unless root also exits 1.

**G16. Debug test tools: specs or raw framework commands?**
001: they "keep their current flags, and do not follow the rules" (L1911), exempt from tests (L2192)
and from the short-letter rule (L388). Today `create-node` uses required flags (`mustMarkRequired`)
and `StringSliceP` (`debug.go`). Why: if they are specs, the adapter needs required flags and
string-slice kinds just for them; if not, a second path imports the framework (breaks R47).
(a) Specs, with their required flags turned into our "set?" checks in `Run`; cost: their flags'
behaviour changes slightly (error text). (b) Hand-written framework commands in the adapter file;
cost: the adapter grows, the help/reference generators need a second source for them.

**G17. Signals and context for `serve` and `mockoidc`.**
001: silent. `Ctx` is used as a context (`c.API.SetNodeRoutes(c, …)`, L2022). Why: some frameworks
install signal handlers or create their own context. (a) `main` makes a `signal.NotifyContext` and
passes it through the framework to our callback; framework must accept an external context.
(b) `serve` handles signals itself as today, framework context unused; cost: two cancellation paths.

**G18. Hidden and deprecated commands/flags.**
001: no hidden commands remain (`dumpConfig` goes, L220); no deprecation period (L2406). Why: if G12
= stubs, or G02 = binary-answered completion (`__complete`), hidden support is needed. (a) None
needed. (b) Hidden only, no deprecation machinery.

**G19. Windows.**
001: silent. Releases build linux, darwin, freebsd only (`.goreleaser.yml`). Why: TTY detection,
powershell completion, path handling. (a) Not supported: drop powershell from requirements.
(b) CLI-only Windows build for remote admin over `HEADSCALE_CLI_ADDRESS`; cost: TTY/colour/prompt
paths and a new release target to test.

**G20. Flag abbreviation (`--exp` for `--expiry`).**
001: silent; spirit is "never guesses" (L281, L3078). Why: some parsers allow unique prefixes.
(a) No abbreviations (pflag today). (b) Unique prefixes; cost: adding a flag later can break a script
that used a prefix.

**G21. Grouped short flags (`-fo json`).**
001: silent. All short flags except `-h` take a value, so grouping only matters as `-ojson`
(attached value). Why: some parsers forbid attached values or allow grouping. (a) Attached value
yes (`-ojson`, `-e24h`), grouping of value flags no. (b) Only `-o json` (separate word); cost: R16
loses `-ojson`, scripts using it break.

**G22. Environment variables as flag defaults.**
001: only `HEADSCALE_CONFIG` (L2001). The `HEADSCALE_CLI_*` variables are config keys, read by the
config loader. Why: some frameworks bind env vars by convention; must be off. (a) No framework env
binding; `HEADSCALE_CONFIG` handled by our config loader. (b) Framework binds `HEADSCALE_CONFIG` only;
cost: precedence rules split between two places.

**G23. Man pages.**
001: not mentioned; one Markdown reference page (L2326). Why: some frameworks generate man pages;
distro packages (`nfpms` in goreleaser) could ship them. (a) No man pages. (b) Generate `man1` from
the specs (our generator, like the reference); cost: one more generated artifact and CI diff.

**G24. Plugins / external subcommands (`headscale-foo` on PATH).**
001: silent. (a) None (the tree is closed; matches "unknown command is an error"). (b) kubectl-style
plugins; cost: unknown-command path must search PATH; conflicts with reserved names.

**G25. Binary size and dependency count.**
001: silent. The server binary already carries tailscale.com; CLI framework share is small. Why: a
reason to prefer a zero-dependency parser. (a) No budget, record numbers only. (b) A ceiling (for
example no new indirect modules); cost: may rule out larger frameworks.

**G26. How tests run a command in-process.**
001: "One helper runs a command. It runs the real command tree inside the test … returns stdout,
stderr and the exit code" (L2196). Not stated: stdin injection, fake TTY (for R34), parallel safety,
environment isolation (`HEADSCALE_*`, `NO_COLOR`). Today `rootCmd` is a package global with `init()`
registration, `cobra.OnInitialize`, and an `os.Args[1]` check (root.go; L3379). Why: frameworks with
global state (default flag sets, global init hooks) cannot run parallel cases. (a) Fresh tree per
case, `Ctx` carries stdin/stdout/stderr/env/isTTY, `t.Parallel()` allowed. (b) Shared tree, serial
cases; cost: slower suite, hidden coupling between cases.

**G27. Help flag text in the leaf flag block.**
001's sample (L2307–2311) prints `-e, --expiry string` (pflag's `FlagUsages` format, type word
`string` although the field is `time.Time`) and lists `-o` but not `-c`/`-h`. Why: if the framework's
flag formatter is reused, the format follows the framework; if ours, we choose. (a) Our formatter
(R51), with a type word from our kind table (`time`, `list`). (b) Reuse the framework's formatter;
cost: help changes on a framework switch.

______________________________________________________________________

## 4. Contradictions and weak spots in 001 that touch the framework

**C1. Old-command hints: tests require them, the changelog forbids them.** L2216 ("one case per old
command, for the hint that says where it went"), L2223 ("the old one fails with its hint") versus L2372
("no deprecated shims and no stubs that print a hint") and L3076 (decision: "No stubs or shims for old
commands"). A framework with built-in suggestions gives a weak "hint" for free; otherwise it is code.
→ G12.

**C2. Cobra's text baked into expected output.** L2538 `Error: unknown flag: --force` is pflag's
wording; L1173 "as the errors of Go and of cobra do"; L2296 `headscale nodes set <node> [flags]` is
cobra's usage convention; L2309–2311 is pflag's flag-block layout. All of these will be golden
test text (L2210), so they tie the tests to cobra although L2134–2139 says no command depends on it.
→ G10, G27.

**C3. The adapter is said to be cobra-only, and the decision log says the redesign stays on cobra.**
L2134 "The CLI is built on cobra today, and that may change"; L2137 "One file turns the tree of specs
into cobra commands"; L3262 "the redesign stays on cobra, behind the command spec". If the framework
changes, these three lines change.

**C4. L2139 under-counts what a framework switch must match.** It names two things (flag syntax,
completion scripts). Also framework-dependent: interspersed flags (R20), values starting with `-`
(R21), "was the flag given" (R23/R24), `--` (G05), bool forms (G06), unknown-command suggestions
(G11), help triggering on groups/no args (G15), `--version`/`help` auto-commands (G08, G14), and
in-process test isolation (G26).

**C5. "Given empty" is not expressible in the input struct.** The field table (L2043–2050) maps
`string` to "reads it", but `--name ""` must reset (L1297) and "a flag you do not pass leaves the field
alone" (L1293, L1434); `set` with no flag is an error (L1295). A plain `string` field cannot tell
"not given" from `""`. Needs `*string`/an `Optional[T]` kind, or a "set" bit from the framework (R24).
Same for `--expiry`: `time.Time` (L2037) cannot carry `never` (null) or the word `now` that is sent to
the server (L432, L1299).

**C6. `--output` is not derivable from the spec fields.** It is on every server command, `debug health` and `version` (L357), and absent on `check`, `generate`, `serve`, `completion` (L361). The
spec has `Local` (L2071), but `version` is local with `--output` and `check` is local without. There
is no spec field that says "takes `--output`". Same for `--config` "on every command that reads the
config" (L358) — no field says which. The adapter cannot add them correctly from L2063–2073 alone.

**C7. `Local` is static, but two commands switch on a flag.** `generate config --running` is local yet
asks the server (L42, L1868); `policy get/set --bypass-…` is a server command that does not talk to the
server and prompts only with the flag (L1777, L482). Builder step 3 (L2083) is keyed on `Local`. Not a
framework issue, but the adapter must deliver parsed flags before the builder decides (it does: step 2
precedes 3).

**C8. `ArgCount` "`...` means many" versus "no command accepts any number of arguments".** L2068 vs
L2190. Either `...` needs an upper bound or the test needs an exception. Affects whether the framework
is ever asked for variadic positionals.

**C9. "Global" means two things.** L381 marks `-o` as "global" in the short-flag table, while L357
lists the commands that have it and L361 those that do not. If the adapter registers `-o` as a
persistent/inherited flag (the cobra way), `check config -o json` parses. → G03, R19.

**C10. `--list-columns` must run before the client and version check**, but the builder order puts
the client at step 3 and does not mention `--list-columns` as an early exit (L2081–2091). Same for
`--help`, which the framework normally handles before any run callback. Our layer, but the spike should
show where the early exits live.

**C11. `generate private-key` today takes `--output json`** (`integration/cli_server_test.go`
calls `headscale generate private-key --output json`), while L361 says `generate` has no `--output`.
The integration test changes; not listed under "What else the implementation touches" (L3459–3482).

**C12. Help text for "can it prompt".** L373 "The help text of a command therefore tells you whether
it can prompt" — via `--force` appearing in the flag list. Fine with our help; would not hold if a
framework's help shows inherited flags that the command does not have.

**C13. Prompt input not in `Ctx`.** L2136: `Ctx` gives "the API client and the output streams". The
prompt reads stdin and checks for a terminal (L534–538), and tests run "without a terminal" (L2218). No
input stream or TTY switch is named. → G26.

______________________________________________________________________

## Open questions for the maintainer

Ordered by how much they move the framework choice. Each has its two answers and costs in §3.

1. **G02** Completion answered by the binary at TAB time, or lists baked into the script?
1. **G01 / G19** Shells: bash, zsh, fish only, or also powershell (and with it, Windows)?
1. **G12 / C1** Old commands: a one-release hint table in the unknown-command path, or plain failure
   (and fix L2216/L2223)?
1. **G10 / C2** Who owns parse-error wording: our layer (typed errors needed) or the framework?
1. **G03 / C9** May `-c` and `-o` come before the subcommand (`headscale -c x nodes list`)?
1. **G11** "Did you mean" for unknown commands and flags: required or not?
1. **G26 / C13** In-process tests: fresh tree per case, parallel, with stdin and TTY in `Ctx`?
1. **G16** Debug test tools as specs (lose required flags) or hand-written in the adapter?
1. **G07** Which list flags may repeat: only `--filter`, or all?
1. **G06, G08, G09, G13, G14, G15, G20, G21** Small syntax choices: `--x=false`, `--version`, exit
   code 2 for usage errors, help on stdout, `help` command, group-without-leaf behaviour, no flag
   abbreviations, `-ojson`. Each is a one-line decision but changes golden test text.
1. **C5 / C6** Spec gaps the adapter needs closed: an optional/"given" field kind, and spec fields
   for "takes `--output`" and "reads config".
1. **G23, G24, G25** Man pages, plugins, size/dependency budget: probably "none / none / record
   only"; confirm.
