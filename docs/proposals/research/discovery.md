# Discovery: Go CLI frameworks and approaches beyond the eight already covered

Date: 2026-11-17. Scope: frameworks not on the list (cobra, urfave/cli, kong, go-arg, gocmd,
mitchellh/hashicorp cli, ff, creachadair/command), layers that sit on or next to a framework,
what well-known Go CLIs use, and the "no framework" option.

Method: `gh api` against each repository (default-branch commits since 2025-11-17, latest
release or tag, licence), raw `go.mod` of each tool on its default branch as of today, merged
PR bodies for migration reasons, awesome-go "Standard CLI" section
(https://github.com/avelino/awesome-go#standard-cli), GitHub topic search
(`topic:cli-framework`, `command-line-parser`, `argument-parser`, `flags`, `subcommands`,
language Go, pushed after 2025-06). "c12m" = commits on the default branch since 2025-11-17
(capped at 100 by the query).

Headscale constraint that decides most of this (001-cli.md "Our layer, not the framework's",
lines ~2132-2139): the tree is built at runtime from `command.Spec` values; the spec carries its
own `flag:`/`short:`/`help:`/`arg:` tags read by Headscale's builder; help, docs and validation
are Headscale's. The framework must (a) accept a tree built from data, (b) parse GNU/pflag
syntax (`--flag=value`, `--flag value`, `-o json`, flags after positionals), (c) produce shell
completion with a dynamic hook.

## 1. Other frameworks (screen)

### Takeaway

Of ~35 projects checked, none is a better fit than the eight already covered. Most fall to the
24-month knockout. Survivors that can be built from runtime data: `jessevdk/go-flags` (awkward:
reflection over struct pointers), `integrii/flaggy` (imperative, zero deps, one maintainer),
`coder/serpent` (closest in spirit to Headscale's own spec layer, but CC0 and heavy deps),
`gookit/gcli`, `hedzr/cmdr` (both bring their own UI/config stacks). None is worth deep research
on its own merits; serpent is worth reading as a design reference.

### Cited Findings

Knocked out (no release and no meaningful commit for 24 months, i.e. since 2024-11-17):

| Project                                   | Last default-branch commit                         | Last release       | Link                                  |
| ----------------------------------------- | -------------------------------------------------- | ------------------ | ------------------------------------- |
| cristalhq/acmd                            | 2024-04-26                                         | v0.12.0 2024-04-26 | https://github.com/cristalhq/acmd     |
| jawher/mow.cli                            | 2021-07-25                                         | v1.2.0 2020-08-08  | https://github.com/jawher/mow.cli     |
| leaanthony/clir                           | 2024-06-10                                         | v1.7.0 2024-05-09  | https://github.com/leaanthony/clir    |
| akamensky/argparse                        | 2022-08-11                                         | v1.4.0 2022-08-09  | https://github.com/akamensky/argparse |
| teris-io/cli                              | 2021-05-09                                         | v1.0.1 2018-02-22  | https://github.com/teris-io/cli       |
| muesli/coral (dependency-free cobra fork) | 2022-03-10                                         | v1.0.0 2022-02-02  | https://github.com/muesli/coral       |
| posener/cmd                               | 2020-09-27                                         | none               | https://github.com/posener/cmd        |
| tucnak/climax                             | 2020-09-05                                         | none               | https://github.com/tucnak/climax      |
| cosiner/argv                              | 2020-04-16                                         | none               | https://github.com/cosiner/argv       |
| jaffee/commandeer                         | 2022-09-20                                         | v0.6.0 2022-09-20  | https://github.com/jaffee/commandeer  |
| octago/sflags                             | moved; repo now redirects to urfave/sflags (below) |                    | https://github.com/urfave/sflags      |

Not knocked out but dismissed for a recorded reason (one line each):

| Project                                 | State                                                              | Why not                                                                                                                                                                                                   |
| --------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| alecthomas/kingpin v2                   | 7 c12m, last release v2.4.0 2023-11-16, MIT                        | README: "CONTRIBUTIONS ONLY ... I no longer use Kingpin personally (I now use kong)". Successor is kong (covered). https://github.com/alecthomas/kingpin                                                  |
| choria-io/fisk (kingpin fork)           | v0.9.1 2026-07-06, 24 stars, MIT                                   | Fork for NATS's own needs, "will likely make some breaking changes", says it will "probably never pass 0.x.x". https://github.com/choria-io/fisk                                                          |
| google/subcommands                      | last commit 2025-09-15, last release v1.2.0 2019-09-04, Apache-2.0 | stdlib `flag` per command, flat registration; nesting means a Commander inside `Execute`; no completion. Release-dead. https://github.com/google/subcommands                                              |
| DavidGamba/go-getoptions                | v0.33.0 2025-04-15, 0 c12m, MPL-2.0, `go 1.16`                     | Builder API, nested commands, built-in completion is bash-oriented ("source sourceme.bash", options complete only after `-`). One maintainer, idle 19 months. https://github.com/DavidGamba/go-getoptions |
| mkideal/cli                             | 2 c12m, last release v0.2.5 2021-02-16                             | Struct-tag model, no release in 5 years. https://github.com/mkideal/cli                                                                                                                                   |
| urfave/sflags                           | v0.4.1 2025-04-02, 2 c12m, BSD-3                                   | Not a framework: generates flags from structs for stdlib flag / pflag / kingpin / urfave. https://github.com/urfave/sflags                                                                                |
| rwxrob/bonzai                           | 8 c12m, no releases, Apache-2.0                                    | Opinionated "batteries included" framework with its own conventions; no tags to pin. https://github.com/rwxrob/bonzai                                                                                     |
| agilira/orpheus (+ agilira/flash-flags) | created 2025-09-10, v1.6.0 2026-10-07, 34 stars, MPL-2.0           | New since 2024; tiny user base; own flag parser; adds agilira/go-errors, go-timecache. https://github.com/agilira/orpheus                                                                                 |
| jxskiss/mcli                            | v0.10.3 2026-11-07, 47 stars, MIT                                  | Struct-tag model, single maintainer. https://github.com/jxskiss/mcli                                                                                                                                      |
| napalu/goopt                            | v2.4.11 2026-06-30, 5 stars                                        | No user base. https://github.com/napalu/goopt                                                                                                                                                             |
| bobg/subcmd                             | v2.4.0 2026-01-12, 15 stars                                        | Small dispatcher on stdlib flag; no completion. https://github.com/bobg/subcmd                                                                                                                            |
| jon-codes/getopt                        | no releases, 9 stars, BSD-3                                        | POSIX getopt port only, no command tree. https://github.com/jon-codes/getopt                                                                                                                              |
| desertbit/grumble                       | interactive shell (REPL) library, not an argv parser               | https://github.com/desertbit/grumble                                                                                                                                                                      |
| GiGurra/boa, leodido/structcli          | cobra layers (struct -> cobra), see section 2                      | https://github.com/GiGurra/boa , https://github.com/leodido/structcli                                                                                                                                     |

Survivors, screen card (compressed; only fields that differ from "yes/normal" are spelled out):

|                   | jessevdk/go-flags                                                                                                            | integrii/flaggy                                                                           | coder/serpent                                                                           | gookit/gcli v3                                   | hedzr/cmdr v2                                    |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------ |
| Module / latest   | github.com/jessevdk/go-flags v1.6.1 (2024-06-15)                                                                             | github.com/integrii/flaggy v1.8.0 (2025-10-04)                                            | github.com/coder/serpent v0.15.0 (tag)                                                  | github.com/gookit/gcli/v3 v3.8.6 (2026-10-29)    | github.com/hedzr/cmdr/v2 v2.2.9 (2026-09-17)     |
| Licence           | BSD-3                                                                                                                        | Unlicense                                                                                 | CC0-1.0                                                                                 | MIT                                              | Apache-2.0                                       |
| Go floor          | UNVERIFIED                                                                                                                   | go 1.25                                                                                   | go 1.21.4                                                                               | UNVERIFIED                                       | UNVERIFIED                                       |
| Health            | 29 c12m, last 2026-10-10; no release for 29 months                                                                           | 0 c12m since v1.8.0; last commit 2025-10-04; single maintainer                            | 15 c12m, last 2026-05-01; maintained by Coder for coder/coder                           | 100+ c12m                                        | 62 c12m                                          |
| Stars             | 2693                                                                                                                         | 956                                                                                       | 22                                                                                      | 382                                              | 144                                              |
| Deps              | none beyond x/sys                                                                                                            | none                                                                                      | 15 direct incl. cdr.dev/slog/v3 rc, pion/udp, termenv, yaml; 26 indirect incl. lipgloss | gookit/cliui, color, goutil, gopty (+creack/pty) | hedzr/store, evendeep, logg, errors.v3, fsnotify |
| Model             | struct tags + reflection; `AddCommand(name, short, long, data any)`, `Group.AddOption(*Option, data)`                        | imperative builder (`NewSubcommand`, `AttachSubcommand`, `String(&v, short, long, help)`) | plain struct values: `serpent.Command{Use, Options: OptionSet{...}}`, middleware        | builder + struct binding                         | builder with its own config store                |
| From runtime data | possible but every command needs a struct pointer to reflect over; dynamic options via `AddOption`                           | yes                                                                                       | yes (commands and options are data)                                                     | yes                                              | yes                                              |
| 3-level nesting   | yes                                                                                                                          | yes ("Nested subcommands")                                                                | yes                                                                                     | yes                                              | yes                                              |
| Flag syntax       | GNU style on Unix; **on Windows defaults to `/flag` and `:` delimiter unless built with `forceposix`** (optstyle_windows.go) | `--flag`, `-flag`, `-f`, `=` or space, flags at any position, `--`                        | pflag underneath                                                                        | UNVERIFIED                                       | "POSIX-compliant" per description                |
| Completion        | in-process via `GO_FLAGS_COMPLETION` env var; ships no shell scripts                                                         | bash, zsh, fish, PowerShell, Nushell (completion.go, v1.8.0); dynamic hook UNVERIFIED     | bash, fish, zsh, PowerShell (completion/ dir)                                           | zsh, bash, pwsh incl. dynamic                    | UNVERIFIED                                       |
| Help replaceable  | yes (custom WriteHelp)                                                                                                       | custom templates                                                                          | own template (help.tpl)                                                                 | UNVERIFIED                                       | UNVERIFIED                                       |
| Notable users     | grafana/alloy (indirect)                                                                                                     | jesseduffield/lazygit                                                                     | coder/coder, coder-logstream-kube                                                       | —                                                | —                                                |

Sources: https://github.com/jessevdk/go-flags (group.go, completion.go, optstyle_windows.go),
https://github.com/integrii/flaggy (README, completion.go, go.mod),
https://github.com/coder/serpent (README, go.mod, completion/),
https://github.com/gookit/gcli (README, go.mod), https://github.com/hedzr/cmdr (go.mod),
https://github.com/jesseduffield/lazygit/blob/master/go.mod.

### Inferences

- go-flags fits Headscale's spec layer badly: it wants to reflect over its own struct tags; the
  Headscale input struct already carries Headscale tags. Bridging means `reflect.StructOf` or one
  `AddOption` per field with a data pointer; the Windows `/flag` default is a user-visible trap.
- flaggy is the cleanest "small builder, zero deps" survivor, with the widest shell list of any
  non-cobra option, but the bus factor is one and activity stopped 13 months ago; Unlicense is
  rejected by some licence policies (public-domain dedication).
- serpent is the one project whose design matches 001: commands and options as data, help and
  docs generated by the project. It is Coder's internal library made public, CC0 (Fedora and
  others do not accept CC0 for code; UNVERIFIED for Debian's current view), and drags a logging
  library at an rc version plus a UDP package. As a dependency: no. As a design reference for a
  pflag-based adapter: yes.
- gcli and cmdr own too much (UI, colour, config store); the brief counts that as cost.

### Gaps

- pkg.go.dev "imported by" counts not collected (would need scraping; not done).
- Dynamic completion hooks for flaggy and cmdr not verified in code.
- Go version floors for go-flags, gcli, cmdr not read.

## 2. Layers on top of or next to a framework

### Takeaway

Every serious completion layer in Go is either cobra-bound (carapace, fang, simplecobra, cobra's
own) or old (posener/complete). The one framework-independent pattern that works in production
is Tailscale's: vendor cobra's four completion scripts and answer cobra's `__complete` protocol
from your own parser. That pattern is the key enabler for leaving cobra while keeping
completion.

### Cited Findings

| Layer                                                             | What it gives                                                                                                                                                          | Cost                                                                                                                                                             | Health                                                              |
| ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| charmbracelet/fang (`charm.land/fang/v2`)                         | Styled help and errors, auto `--version`, hidden `man` command (mango-cobra), `completion` command, themes, silent usage on error                                      | Takes over help and errors (Headscale generates its own); adds lipgloss v2, charmbracelet/x/\*, colorprofile, ultraviolet, mango-cobra, roff (18 indirect lines) | v2.0.1 2026-03-11, 15 c12m, MIT, 1964 stars; goreleaser uses v1.0.0 |
| carapace-sh/carapace                                              | Completion engine for **cobra only**; 10 shells (bash, zsh, fish, PowerShell, Nushell, Elvish, Xonsh, Oil, Tcsh exp., Cmd exp.)                                        | cobra + pflag + carapace-shlex + yaml; replaces cobra's completion command                                                                                       | v1.18.2 2026-11-13, 100+ c12m, Apache-2.0                           |
| carapace-sh/carapace-spec                                         | YAML spec of a CLI -> completion (via carapace-bin); generators exist for kong, kingpin, urfave/cli, clap, man pages                                                   | Users must install carapace-bin; not self-contained in our binary                                                                                                | v1.10.2 2026-10-30, MIT                                             |
| carapace-sh/carapace-bridge                                       | Bridges completion from cobra, urfave/cli, kingpin, posener/complete, argcomplete, clap, etc. into carapace-bin                                                        | Same: user-side tool                                                                                                                                             | MIT, 16 stars                                                       |
| bep/simplecobra                                                   | `Commander` interface tree (Name/Init/PreRun/Run/Commands) built in one go, over cobra; "built to help rewriting Hugo's commands package"                              | Only cobra + quicktest; another interface on top of our own spec layer = redundant                                                                               | v0.8.0 2026-08-21, 8 c12m, MIT; used by gohugoio/hugo               |
| spf13/cobra-cli                                                   | Scaffolding generator                                                                                                                                                  | Not runtime; irrelevant                                                                                                                                          | last commit 2023-08-19, v1.3.0 2022-03-02 (dead)                    |
| posener/complete v1/v2                                            | Bash-protocol completion (`COMP_LINE`/`COMP_POINT`); zsh via bashcompinit; installs by editing rc files                                                                | OpenTofu RFC lists it as unmaintained and as a reason to leave mitchellh/cli                                                                                     | v2.1.0 tag 2023-07-19; master last commit 2025-03-06                |
| jotaen/kong-completion                                            | Completion for kong (bash, zsh, fish), tags `completion-enabled`, predictors                                                                                           | Built on posener/complete v1.2.3                                                                                                                                 | v0.0.15 2026-10-14, 10 c12m                                         |
| WillAbides/kongplete                                              | Same idea, older                                                                                                                                                       | posener/complete                                                                                                                                                 | last commit 2023-11-15; still used by syncthing                     |
| miekg/king                                                        | Completions + man pages generated from a `kong.Node`, no source changes; copied from gum                                                                               | Zsh first, bash "can probably be done a lot better" (README)                                                                                                     | 12 c12m, no tags                                                    |
| reeflective/flags                                                 | Generates cobra commands from structs (go-flags / sflags / kong tags), carapace completions                                                                            | Third tag dialect over our own                                                                                                                                   | v0.11.1 2025-08-01, 0 c12m, 16 stars                                |
| GiGurra/boa, leodido/structcli                                    | Struct -> cobra with env/config                                                                                                                                        | Same redundancy                                                                                                                                                  | active, \<50 stars                                                  |
| tailscale `cmd/tailscale/cli/ffcomplete` + `tempfork/spf13/cobra` | Cobra's bash/zsh/fish/ps1 scripts copied (Apache-2.0, activeHelp removed), gzipped, plus a ~6.8 KB `complete.go` that answers `__complete` for ffcli and stdlib `flag` | Own the ~200-line glue; re-sync scripts from cobra by hand                                                                                                       | Added 2024-04-17 (commit 82394de), Fixes tailscale#3793             |

Sources: https://github.com/charmbracelet/fang (README, go.mod, releases),
https://github.com/carapace-sh/carapace (README, go.mod),
https://github.com/carapace-sh/carapace-spec, https://github.com/carapace-sh/carapace-bridge,
https://github.com/bep/simplecobra, https://github.com/spf13/cobra-cli,
https://github.com/posener/complete, https://github.com/jotaen/kong-completion,
https://github.com/miekg/king, https://github.com/reeflective/flags,
https://github.com/tailscale/tailscale/tree/main/tempfork/spf13/cobra (README),
https://github.com/tailscale/tailscale/commit/82394debb7e8eb582c31fc1cc4c80869bd502a31.

### Inferences

- fang and simplecobra solve problems 001 already solves itself (help, docs, command structure);
  both would be dead weight. carapace adds shells (Nushell, Elvish) at the cost of tying
  completion harder to cobra.
- The Tailscale pattern decouples completion from the parser. Cobra's `__complete` protocol plus
  its scripts is the de-facto standard; any parser can serve it. This is the answer to 001's
  "the completion scripts would be new code": it is roughly one file plus four copied scripts,
  with a known production user in the same ecosystem (Headscale is a Tailscale control server;
  Tailscale code is BSD-3, the scripts Apache-2.0).
- Completion for kong lives on posener/complete in practice, the library OpenTofu calls
  unmaintained; that is a recorded weakness for kong (covered elsewhere).

### Gaps

- Carapace's notable library users (not carapace-bin) not counted.
- Tailscale's ffcomplete reported bugs/regrets not searched in issues.

## 3. What well-known Go CLIs use (default-branch go.mod, 2026-11-17)

### Takeaway

Cobra v1.10.2 is near-universal among large Go CLIs, including every network control plane
checked (NetBird, Netmaker, Zitadel, Cilium). The moves away from cobra that exist are to a
project's own layer on pflag (Coder, 2023) or to kong (Buildkite CLI, 2025); moves to cobra
are for consolidation (Kairos, 2026) and plugin compatibility (tally, 2026). OpenTofu tried
cobra in 2025-26 and rejected it because pflag's POSIX syntax breaks `-json`-style flags; that
reason does not apply to Headscale, which already uses pflag syntax.

### Cited Findings

| Tool                                                                                       | Framework + version                                                                     | Layered on top                                                      | Migration (last 3 years)                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| kubectl                                                                                    | cobra v1.10.2, pflag v1.0.10                                                            | heredoc                                                             | none                                                                                                                                                                                                                                                                   |
| gh (cli/cli)                                                                               | cobra v1.10.2, pflag v1.1.0                                                             | heredoc                                                             | none                                                                                                                                                                                                                                                                   |
| docker CLI (vendor.mod)                                                                    | cobra v1.10.2, pflag v1.0.10                                                            | —                                                                   | none                                                                                                                                                                                                                                                                   |
| tailscale                                                                                  | peterbourgon/ff/v3 v3.4.0 (ffcli)                                                       | own completion from vendored cobra scripts (2024-04)                | added completion 2024, no framework change                                                                                                                                                                                                                             |
| hugo                                                                                       | cobra v1.10.2                                                                           | bep/simplecobra v0.7.0                                              | cobra -> cobra+simplecobra (simplecobra "built to help rewriting Hugo's commands package")                                                                                                                                                                             |
| restic                                                                                     | cobra v1.10.2                                                                           | —                                                                   | none found                                                                                                                                                                                                                                                             |
| rclone                                                                                     | cobra v1.10.2                                                                           | —                                                                   | none found                                                                                                                                                                                                                                                             |
| age                                                                                        | stdlib flag (no framework in go.mod)                                                    | —                                                                   | —                                                                                                                                                                                                                                                                      |
| terraform                                                                                  | hashicorp/cli v1.1.7 + posener/complete v1.2.3                                          | —                                                                   | none                                                                                                                                                                                                                                                                   |
| opentofu                                                                                   | urfave/cli/v3 v3.10.1 + posener/complete v1.2.3 (still mitchellh-style path as default) | experimental CLI behind `TOFU_EXPERIMENTAL_CLI_ENABLED`             | mitchellh/cli -> cobra RFC (2025-11) -> superseded by urfave/cli RFC (merged 2026-08-12): pflag treats `-json` as `-j -s -o -n`; switching flag paradigm "not a realistic option". Also: mitchellh/cli archived, posener/complete unmaintained, zsh scripts deprecated |
| vault, nomad, openbao                                                                      | hashicorp/cli v1.1.7 + posener/complete                                                 | —                                                                   | none                                                                                                                                                                                                                                                                   |
| consul, packer                                                                             | mitchellh/cli v1.1.5 (archived)                                                         | —                                                                   | none                                                                                                                                                                                                                                                                   |
| flyctl                                                                                     | cobra v1.10.2, viper                                                                    | heredoc/v2                                                          | none                                                                                                                                                                                                                                                                   |
| chezmoi                                                                                    | cobra v1.10.2                                                                           | —                                                                   | none                                                                                                                                                                                                                                                                   |
| goreleaser                                                                                 | cobra v1.10.2                                                                           | charmbracelet/fang v1.0.0                                           | added fang                                                                                                                                                                                                                                                             |
| caddy                                                                                      | cobra v1.10.2                                                                           | —                                                                   | none (moved to cobra before the 3-year window; not re-checked)                                                                                                                                                                                                         |
| syncthing                                                                                  | kong v1.16.1 (+ urfave/cli v1 still listed)                                             | willabides/kongplete v0.4.0                                         | outside window                                                                                                                                                                                                                                                         |
| dolt                                                                                       | juju/gnuflag (2017 pseudo-version)                                                      | own command layer                                                   | none                                                                                                                                                                                                                                                                   |
| k9s                                                                                        | cobra v1.10.2                                                                           | —                                                                   | none                                                                                                                                                                                                                                                                   |
| podman                                                                                     | cobra v1.10.2                                                                           | —                                                                   | none                                                                                                                                                                                                                                                                   |
| helm                                                                                       | cobra v1.10.2                                                                           | —                                                                   | none                                                                                                                                                                                                                                                                   |
| golangci-lint                                                                              | cobra v1.10.2, viper v1.12.0                                                            | —                                                                   | none                                                                                                                                                                                                                                                                   |
| buf                                                                                        | cobra v1.10.2                                                                           | own appcmd layer (UNVERIFIED name)                                  | none                                                                                                                                                                                                                                                                   |
| go command, gopls                                                                          | stdlib `flag` + own `base.Command` / tool package                                       | —                                                                   | — (UNVERIFIED: not re-read today)                                                                                                                                                                                                                                      |
| NetBird                                                                                    | cobra v1.10.2, viper                                                                    | —                                                                   | none                                                                                                                                                                                                                                                                   |
| Nebula                                                                                     | stdlib flag                                                                             | —                                                                   | —                                                                                                                                                                                                                                                                      |
| Netmaker                                                                                   | cobra v1.10.2                                                                           | —                                                                   | none                                                                                                                                                                                                                                                                   |
| Zitadel, Cilium, etcd, LXD, cosign, trivy, grype, ko, cue, devbox, yq, zrepl, temporal CLI | cobra v1.10.2                                                                           | temporal: commands.yaml -> generated cobra code (`commands.gen.go`) | none found                                                                                                                                                                                                                                                             |
| coder/coder                                                                                | pflag v1.0.10 + own coder/serpent (cobra only indirect)                                 | —                                                                   | cobra/viper -> own `bigcli`/`clibase` (2023-03) -> extracted as coder/serpent (2024-03)                                                                                                                                                                                |
| go-task                                                                                    | pflag v1.1.0 + own dispatcher and completion                                            | —                                                                   | —                                                                                                                                                                                                                                                                      |
| gitea                                                                                      | urfave/cli/v3 v3.14.0 + urfave/cli-docs                                                 | —                                                                   | urfave v2 -> v3 (2025-06)                                                                                                                                                                                                                                              |
| lefthook                                                                                   | urfave/cli/v3 v3.14.0                                                                   | —                                                                   | not checked                                                                                                                                                                                                                                                            |
| sops, smallstep/cli                                                                        | urfave/cli v1.22.17                                                                     | —                                                                   | none                                                                                                                                                                                                                                                                   |
| k3s, rke2                                                                                  | urfave/cli/v2 (+ cobra)                                                                 | —                                                                   | none                                                                                                                                                                                                                                                                   |
| minio mc                                                                                   | minio/cli (urfave fork) + posener/complete                                              | —                                                                   | none                                                                                                                                                                                                                                                                   |
| gum                                                                                        | kong v1.15.0                                                                            | —                                                                   | —                                                                                                                                                                                                                                                                      |
| lazygit                                                                                    | integrii/flaggy v1.8.0                                                                  | —                                                                   | —                                                                                                                                                                                                                                                                      |
| teleport                                                                                   | kingpin/v2 replaced by gravitational/kingpin fork (2026-05 pseudo-version) + cobra      | —                                                                   | maintain own fork of a contributions-only library                                                                                                                                                                                                                      |
| prometheus, kopia, grafana/alloy                                                           | kingpin/v2 v2.4.0                                                                       | —                                                                   | none                                                                                                                                                                                                                                                                   |
| natscli                                                                                    | choria-io/fisk v0.9.1 (kingpin fork)                                                    | —                                                                   | kingpin -> fisk (date not checked)                                                                                                                                                                                                                                     |
| juju                                                                                       | juju/gnuflag v1.0.0                                                                     | own cmd package                                                     | —                                                                                                                                                                                                                                                                      |
| k6                                                                                         | cobra v1.4.0 (old pin)                                                                  | —                                                                   | —                                                                                                                                                                                                                                                                      |

Migrations with stated reasons:

- OpenTofu, mitchellh/cli -> cobra (planned) -> urfave/cli v3 (experimental): reasons quoted in
  section above. https://github.com/opentofu/opentofu/pull/4445 (RFC, merged 2026-08-12),
  https://github.com/opentofu/opentofu/pull/4419 (experimental urfave CLI, merged 2026-08-18),
  https://github.com/opentofu/opentofu/blob/main/rfc/20260807-use-urfave-instead-of-cobra.md .
  The RFC also notes bash-completion ships a default for tofu, and completion migration would
  break installed scripts.
- Coder, cobra/viper -> own layer: "enables non-janky long-help formatting, doc generation, and
  YAML support"; later "Verify that `cobra` is no longer imported".
  https://github.com/coder/coder/pull/6347 , https://github.com/coder/coder/pull/6491 ,
  https://github.com/coder/coder/pull/12252 (extracted to serpent, 2024-03-15).
- Buildkite CLI, cobra -> kong (incremental, Kong delegating to existing cobra commands first;
  no reason stated in the PR). https://github.com/buildkite/cli/pull/549 (2025-09-26),
  https://github.com/buildkite/cli/pull/571 .
- Kairos, urfave/cli + cobra + stdlib flag -> cobra (2026-11-03): one hand-written dispatcher
  had to compose three libraries. https://github.com/kairos-io/kairos/pull/5900
- wharflab/tally, urfave/cli v3 -> cobra + koanf/posflag (2026-04-29): to expose a cobra-based
  Docker CLI plugin "without doubling up CLI frameworks"; noted pflag defaults silently
  overriding config defaults as a migration trap. https://github.com/wharflab/tally/pull/588
- micasa, kong -> cobra (2026-03-17): built-in completion replaced 170 lines of hand-written
  bash/zsh/fish scripts; in-process tests via `cmd.OutOrStdout()` cut test time from ~10s to
  ~100ms. https://github.com/micasa-dev/micasa/pull/785
- coder-logstream-kube, cobra -> serpent (2026-02-11): native env and default fields.
  https://github.com/coder/coder-logstream-kube/pull/158
- Gitea, urfave/cli v2 -> v3 (2025-06-10), no reason beyond "migrate", added CLI tests.
  https://github.com/go-gitea/gitea/pull/34510
- Several small projects cobra -> kong in 2025-26 (scip-go, shunt, resolved, tmux-remux) and
  kingpin -> kong (maprobe, kasa_exporter, jellyfin_exporter, ashron); found via
  `gh search prs "migrate to kong"`, e.g. https://github.com/scip-code/scip-go/pull/194 ,
  https://github.com/fujiwara/maprobe/pull/99 .

### Inferences

- No large project left cobra for a different general-purpose framework in the window; the two
  notable exits went to their own layer (Coder) or kong (Buildkite). The kingpin -> kong flow is
  steady, which is evidence for kong's health, not against cobra.
- Projects that keep compatibility constraints (OpenTofu) choose by flag syntax first. For
  Headscale the existing syntax is pflag's, so syntax argues for staying on pflag whatever sits
  above it.
- Temporal CLI is the closest large analogue to 001: commands declared as data (YAML), cobra
  generated underneath, cobra not visible to command authors.

### Gaps

- Reasons for Buildkite's move not stated in PRs; an issue or blog post may exist.
- gopls / go command internals and buf's layer not re-read today.
- No search for regrets after Coder's move (issues mentioning serpent pain points not read).

## 4. The "no framework" option

### Takeaway

The realistic version is not stdlib `flag`; it is **pflag + a ~small dispatcher of our own +
Tailscale-style vendored cobra completion scripts**. pflag keeps today's syntax byte-for-byte
(cobra delegates all flag parsing to it), the dispatcher is a map walk over the spec tree that
001 already builds, and completion reuses cobra's `__complete` protocol so existing user
completion scripts keep working. stdlib `flag` alone would change user-visible syntax.

### Cited Findings

- stdlib `flag` stops at the first non-flag argument and has no short/long pairs or grouped
  shorts; pflag adds GNU syntax and interspersed flags. (Go docs: https://pkg.go.dev/flag ,
  https://pkg.go.dev/github.com/spf13/pflag) — behaviour from package docs, not re-tested.
- pflag itself: pushed 2026-11-16, BSD-3, 146 open issues+PRs, used directly by coder,
  go-task, rke2, cue (cue pins a 2026-10-29 pseudo-version).
  https://github.com/spf13/pflag , go.mod files linked in section 3.
- Projects that built their own layer: Coder (own layer on pflag, now serpent), go-task (pflag
    - own completion command: `cmd/task/complete_cmd.go`), Tailscale (ffcli/stdlib flag + vendored
      cobra scripts), dolt and juju (gnuflag + own command packages), the go command.
      https://github.com/go-task/task/tree/main/cmd/task ,
      https://github.com/tailscale/tailscale/tree/main/cmd/tailscale/cli/ffcomplete
- Sizes at Tailscale: `ffcomplete/internal/complete.go` 6797 bytes (+5918 bytes of tests);
  `tempfork/spf13/cobra` four scripts 7-10 KB each plus `comp.go` 1892 bytes and `cobra.go`
  4811 bytes. https://github.com/tailscale/tailscale/tree/main/tempfork/spf13/cobra
- Costs others met when hand-rolling: OpenTofu's mitchellh-era help text "manually created,
  formatted, and updated ... tedious ... error prone" and flag parsing "scattered"; micasa had
  170 lines of hand-written completion scripts before moving to cobra. (OpenTofu RFC above;
  https://github.com/micasa-dev/micasa/pull/785)

What Headscale would have to write (beyond what 001 already specifies):

1. Tree walk: argv -> command node, with aliases and hidden/deprecated handling.
1. One `pflag.FlagSet` per command assembled from the spec fields, plus inherited global flags
   merged in (cobra's persistent-flag logic), `--` handling, `SetInterspersed(true)`.
1. `-h/--help` and `help <cmd>` routing to Headscale's own help (already planned).
1. "Unknown command" errors with suggestions (Levenshtein; cobra has `SuggestionsMinimumDistance`).
1. `completion <shell>` emitting vendored scripts, and a hidden `__complete` command that walks
   the tree, lists subcommands/flags, calls per-arg completers (node names from the server), and
   returns cobra's directive integer.
1. Tests: argv tables (001 already plans them) and the completion protocol.

Regrets found: the hand-rolled cases that hurt (OpenTofu, micasa) were hand-written **help and
completion scripts**, both of which 001 already generates or would vendor. No source found of a
project regretting a hand-written dispatcher over pflag.

### Inferences

- In 001's design cobra is already reduced to: tree walk, pflag wiring, persistent flags,
  suggestions, and completion scripts + `__complete`. Items 1-4 are small; item 5 is the only
  real code and Tailscale shows its shape. The risk is drift from cobra's scripts (bug fixes
  must be copied by hand) and owning edge cases cobra has fixed over years (e.g. flag-value
  completion, `NoSpace`, file completion directives).
- Keeping cobra costs one dependency (cobra, pflag, mousetrap) and nothing else, since 001
  already isolates it in one file. The no-framework option buys little unless cobra's own
  behaviour (help hooks, persistent pre-runs, error printing) keeps leaking into the adapter.

### Gaps

- No measured line count for a pflag dispatcher; estimate would be speculation.
- Did not test that cobra's `__complete` scripts accept output from a non-cobra server across
  shell versions (Tailscale's production use is the only evidence).

## Ranked shortlist for deep research (beyond the eight)

1. **pflag + own dispatcher + vendored cobra completion (Tailscale pattern).** Only addition
   that could beat cobra for 001: same syntax, same completion protocol, no framework. Deep
   research: read Tailscale's ffcomplete fully, prototype the adapter file against 001's spec
   tree, measure lines, run completion on bash/zsh/fish/pwsh.
1. **coder/serpent, as a design reference only.** Closest existing match to 001's "commands as
   data, own help and docs" on pflag. Read its option/command model and completion package; do
   not adopt (CC0, heavy deps, Coder-driven roadmap).
1. **charmbracelet/fang and carapace: no.** Both overlap with or bind harder to cobra; fang
   duplicates 001's help/docs; carapace only matters if Nushell/Elvish completion is a goal.
1. **flaggy, go-flags: no.** flaggy is a single-maintainer project idle for 13 months; go-flags
   fights the spec's own tags and defaults to `/flag` on Windows.

Answer in short: no new framework deserves deep research; one new **approach** does (#1).

## Open questions for the maintainer

1. **Is Nushell/Elvish completion a goal?**
   (a) No: cobra's built-in four shells or vendored scripts suffice; zero extra deps.
   (b) Yes: carapace on cobra; binds completion to cobra harder and adds carapace-shlex + yaml.
1. **Keep cobra as a thin parser, or replace it with pflag + own dispatcher?**
   (a) Keep: one adapter file, no new code, cobra's completion edge cases fixed upstream; cost
   is a dependency whose defaults (help, error printing, usage on error) must be switched off.
   (b) Replace: one dispatcher file + vendored scripts + `__complete` server; identical syntax;
   cost is owning completion edge cases and syncing scripts by hand.
1. **Must existing installed completion scripts keep working after the CLI change?**
   (a) Yes: either stay on cobra or answer cobra's `__complete` protocol exactly (Tailscale
   pattern); rules out kong/urfave native completion.
   (b) No: release note telling users to regenerate; opens all candidates, costs user friction.
