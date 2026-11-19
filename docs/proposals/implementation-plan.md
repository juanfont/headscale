# Implementation plan

This file is for the session that drives the implementation of the three proposals: [001](001-cli.md) (the CLI), [002](002-api.md) (the API `/api/headscale/v0`) and [003](003-cmdline.md) (the parser library). It was written with the maintainer on 2026-11-19. It is a start, not an order: adopt it, check it against the code, and change it where it is wrong.

## How to use this file

1. Read this file, and then the "Implementation notes" of each proposal.
1. Do the checks in [To check before the first pull request](#to-check-before-the-first-pull-request).
1. Make the plan of the whole work with the plan tool, from [The stack](#the-stack) and [The team](#the-team). The maintainer approves it there.
1. When a part of the stack starts, fill the TODO tool with the tasks of that part, from its block in [The parts](#the-parts). Close them before the next part starts.

The plan tool holds the whole. The TODO tool holds one part at a time.

## Goal

Headscale 0.30 has the new CLI, the API v0 and its own parser library. The old cobra CLI is gone. `/api/v1` is frozen, and the changelog says that it is removed in 0.33.

The proposals are the specification, and they will be wrong in places. The CLI is the first real client of v0. The work is cut so that those places show early, when a change is cheap.

## Sources

- The proposals are on the branch `cli-restructure-proposal` (pull request #3375). That branch is never merged. The stack is built on `main`, in other worktrees, so a builder does not have the proposals in its tree. The root gives each builder the path of the proposal worktree.
- The prototype of the library is in [`research/spikes/final-typed/cmdline/`](research/spikes/final-typed/cmdline/).
- The decisions behind the library are in [`research/DECISIONS.md`](research/DECISIONS.md), [`research/typed-library.md`](research/typed-library.md) and [`research/rules-typed.md`](research/rules-typed.md).
- The recordings of the Tailscale API are in `hscontrol/testdata/tailscale_api/`, with a `README.md`.

## Decisions

| Decision                                                             | Rejected                                    | Why                                                                                                            |
| -------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| slices: one resource in each pull request, from the API to the CLI   | the whole API first                         | a fault in 002 shows in the first slice                                                                        |
| a stack of pull requests on GitHub                                   | one long branch                             | `main` moves fast, and a small pull request can be reviewed                                                    |
| every pull request passes all tests on its own                       | a stack that is green only at its top       | each one can be reviewed, and merged, by itself                                                                |
| no code joins the old CLI and the new one                            | a root that sends the old groups to cobra   | a bridge is thrown away                                                                                        |
| the new CLI is built beside the old one, and the old one leaves last | delete the old CLI first                    | the integration tests set up every tailnet with the CLI; while they are red, nothing guards the server work    |
| the build tag `newcli` selects the new CLI                           | no way to run it before the swap            | the integration tests run on the new CLI before the old one is deleted                                         |
| the library starts as a copy of the prototype                        | write it again from 003                     | the prototype passes every case of the test kit                                                                |
| one root session, and builders one after the other                   | builders side by side                       | every slice changes the OpenAPI file, the generated client, `hscontrol/app.go` and the command builder         |
| all of it is in 0.30, and 0.30 is not released before the swap       | the API in one release, the CLI in the next | 002 removes `/api/v1` three releases after v0; while the stack merges, `main` serves a v0 that is not complete |

The maintainer confirmed two more cuts on 2026-11-19: `users delete` is its own part (part 8), and what was "the rest" is three parts (9, 10, 11).

Decisions of 2026-11-19, before the first builder. Each one is also in the proposal that it changes.

| Point                                                    | Decision                                                                                                          |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| the branches of the stack                                | in `juanfont/headscale`, named `kradalby/cli-v0-NN-<name>`; each pull request has the branch below it as its base |
| #3707 and #3708                                          | the stack carries their work and does not wait for them                                                           |
| the name of the library                                  | `cmdline`                                                                                                         |
| the string reader                                        | the public package `cmdline/reader`, not `internal/reader`                                                        |
| the reserved names of `GET /me`                          | as 002 has them                                                                                                   |
| `GET /health`                                            | the reason `database_unreachable`; the node checks of today as warnings, one for each check                       |
| the packages of the new CLI                              | `cmd/headscale/newcli`, with `command` and `table` under it; the swap renames it to `cli`                         |
| `command.Owner`, the `--version` sentence, `NeedsServer` | as 001 has them                                                                                                   |
| the `api whoami` sheet                                   | one line for each part of `GET /me`; the OAuth client has its own `Client` line                                   |

## The stack

| Part | Name                       | API operations                                                | Commands                                                  |
| ---- | -------------------------- | ------------------------------------------------------------- | --------------------------------------------------------- |
| 1    | the library                | none                                                          | none                                                      |
| 2    | the empty API              | `GET /version`, `GET /me`, `GET /health`                      | none                                                      |
| 3    | the base of the CLI        | none                                                          | `version`, `api whoami`, `completion`, `debug health`     |
| 4    | users                      | `GET /users`, `GET`, `POST`, `PATCH /users/{id}`              | `users list`, `get`, `create`, `set`                      |
| 5    | nodes                      | the eight node operations, `GET /tags`                        | all of `nodes`, with `routes` and `tags`                  |
| 6    | auth keys                  | the four `/auth-keys` operations                              | `auth keys`                                               |
| 7    | API keys and OAuth clients | the four `/api-keys` and the four `/oauth-clients` operations | `api keys`, `api oauth-clients`                           |
| 8    | user delete                | `DELETE /users/{id}`                                          | `users delete`                                            |
| 9    | auth requests and debug    | the four `/auth-requests` operations, `POST /debug/nodes`     | `auth register`, `approve`, `reject`; `debug create-node` |
| 10   | policy                     | `GET /policy`, `PUT /policy`, `POST /policy/reload`           | `policy get`, `set`, `reload`                             |
| 11   | local commands             | `GET /config`                                                 | `serve`, `check`, `generate`, `debug mockoidc`            |
| 12   | the integration tests move | none                                                          | none                                                      |
| 13   | the swap                   | the marks on `/api/v1`                                        | the old CLI is deleted                                    |

Parts 1 and 2 do not need each other and can be built at the same time. No other parts can.

In a pull request, the API operations, the server work, the commands and the generated files are separate commits. A migration is its own commit.

A slice is done when every row of "This document as tests" in 001 that belongs to it has its cases, when the tests that 002 asks for its operations exist (see "Tests" in its implementation notes), and when [every test of the repository](#what-every-pull-request-passes) passes.

How the two CLIs live in one tree until the swap is in "How the old CLI leaves" in 001.

## The parts

"Read" names the sections of the proposals for the part. "Ask first" is a point that only the maintainer can settle, and that blocks the part.

### 1. The library

- **Read:** all of 003. For the work itself: "Tests", "Limits, platforms and compatibility", "Open points".
- **Build:** the package at the top of the module, next to `cmd` and `hscontrol` (decision D39), with `reader` and `script`. The prototype has the reader in `internal/reader`; it moves to `cmdline/reader`. Its own tests and both `FuzzParse` targets come with it.
- **Not here:** the corpus, `FuzzRun`, `FuzzLeaf`, `FuzzTab`, the test kit and the real-shell job. They run through Headscale's layer, which arrives in part 3. The differential test against other parsers stays in the research.
- **Done when:** the tests of the three packages pass with `-race`, and `TestStdlibOnly` holds.
- **Asked:** the name is `cmdline`. The reader is public.

### 2. The empty API

- **Read:** in 002: "Conventions", "Errors", "Authentication" with "Who am I" and "CORS", "Server", "Server operations", and all of "Implementation notes".
- **Build:** the package `hscontrol/api/headscale/v0`; the wiring in four places in `hscontrol/app.go`; the problem type and the transformer for Huma's own errors; the auth middleware with its one caller value, and the token rules; the three operations; the `Headscale-Version` header; the config key `api.cors.allowed_origins`; the OpenAPI document in the tree, with a check that fails when it is stale; the generated client in `gen/client/headscale/v0`; the guard tests; a unix socket in `hscontrol/servertest`, which has none today.
- **Done when:** `GET /me` answers for an API key, for a token and for the socket in `hscontrol/servertest`, and the guard tests fail for an operation without a scope, without error codes or without an operation ID.
- **Asked:** the names in `GET /me` hold as 002 has them, and the OpenAPI enums list the reserved values. `GET /health` has the reason `database_unreachable` and the warnings `node_name_invalid` and `node_expiry_invalid`; `policy_file_invalid` arrives with part 10.

### 3. The base of the CLI

- **Read:** in 001: "Principles", "Flags", "Output", "The table engine", "Messages and errors", "The CLI and the server", "The command spec", "Help on three levels", and "Shared building blocks" in the notes. In 002: "The CLI and the API". In 003: "Using the library".
- **Build:** the builder (`command.Spec[In, Out]`) and the shared building blocks; the four commands; the help; the test helper and the walk that fails when a command has no case; the `newcli` build tag and a CI build with it.
- **Also here, from the library's research:** the corpus, the three fuzz targets, the test kit, and the job that presses Tab in real shells. That job needs zsh and PowerShell in the nix dev shell, and they are not there today. The rows of the kit that name a command of a later part arrive with that part.
- **Done when:** `headscale api whoami` works over the socket in a test, and the real-shell job passes in CI.
- **Asked:** the new CLI is in `cmd/headscale/newcli`, with `command` and `table` under it. `command.Owner` is read by a lookup, the sentence is `Error: --version takes no other flag.`, and `NeedsServer` has no guard, all as 001 has them. The `api whoami` sheet has one line for each part of `GET /me`.

### 4. Users

- **Read:** in 002: "Lists", "Paging", "Update with PATCH", "Users", "User operations". In 001: "Targets and resolvers", and `users` in "Commands by group".
- **Server work:** the user update for display name, email and picture, with the OIDC check; `loginName`; the checks on a new user; the `409` for a write that a unique index refuses, from the commits of #3708.
- **First of its kind:** the paging helper with its signed token, on an SQL list; the walk helper next to the generated client; `Optional[T]` for `PATCH`; a resolver; a table with `--columns`, `--filter` and `--sort`.
- **Done when:** the list is walked with a page size of 2, and with a token that is forged, for another list and for other filters.
- This slice proves the base. Expect it to change parts 2 and 3.

### 5. Nodes

- **Read:** in 002: "Nodes", "Node operations", "Tags", "Tag operations", "Actions", "Expire, and key expiry that is disabled", "Where v0 differs on purpose". In 001: `nodes`.
- **Server work:** the `revision` of a node and its check inside the update of the NodeStore; the column for the creator of a node and of a credential, with its migration; the name that resets; name and expiry changed together or not at all; the reason a node refused an update; the list of tags from the policy; `lastSeen` and `connectedToControl`; `updateAvailable` with the config key `auto_update.check_versions`; the stored expiry time next to the switch for "key expiry disabled".
- **First of its kind:** paging on one snapshot of the NodeStore; `If-Match`.
- **Done when:** every node write is tested with an old `revision`, as "Tests" in 002 says.
- **Ask first:** two earlier calls in 002 that the maintainer has not confirmed: there is no `createdByUserId` field, and no call changes the owner of a node.

### 6. Auth keys

- **Read:** in 002: "Secrets", "How a credential ends", "Auth keys", "Auth key operations". In 001: `auth`.
- **Server work:** the list with revoked keys and their state; a delete that always revokes; the check of the tags against the policy.

### 7. API keys and OAuth clients

- **Read:** in 002: "API keys", "OAuth clients", and their operations. In 001: `api`.
- **Server work:** the owner of an API key at create; the soft delete for both kinds, with the hourly job for all three; the tokens of a revoked client are refused at once; the time an API key was last used; the check of a client's tags against the policy; the config key `credentials.revoked_retention`, which takes the place of `preauth_keys.revoked_retention`.

### 8. User delete

- **Read:** in 002: "Dry run", `DELETE /users/{id}`, and the first item of "Server work behind the API". In 001: "Confirmation prompts", and `users delete`.
- **Server work:** the delete of a user with its nodes and API keys in one transaction, the dry run, and the `expect` token.
- **Done when:** the tests pass on SQLite and on PostgreSQL, with a node that registers and a key that is made while the delete runs.
- **Ask first:** how the spec states the second try of the delete (an open point of 001).
- It stands after parts 5 to 7 so that its tests can read the nodes and the keys back through v0.

### 9. Auth requests and debug

- **Read:** in 002: "Auth requests", "Auth request operations", "Debug operations". In 001: `auth`, `debug`.
- **Server work:** reading one auth request.

### 10. Policy

- **Read:** in 002: "Policy", "Policy operations". In 001: `policy`, "The database bypass".
- **Server work:** failed policy tests as data; the watch on the policy file; errors with a type from the reload; the `ETag` compared under the one policy lock.

### 11. Local commands

- **Read:** in 001: `check`, `generate`, "Generated documentation", "Relation to the config pull requests".
- **Build:** `serve`, the five `check` commands, the five `generate` commands, `debug mockoidc`. The old `check` and `generate` are new code from the config stack: move their logic, do not write it again. The generated reference and man page are in the tree, and their stale check builds with the tag until the swap.

### 12. The integration tests move

- **Read:** `cmd/hi/README.md` and `integration/README.md` in full, as `AGENTS.md` says. In 001: "What else the implementation touches".
- **Build:** `Dockerfile.integration` builds with `-tags newcli`. The tests use the new commands and the new JSON. A walk fails when a command never runs in Docker.
- **Done when:** the whole integration suite passes on the new CLI, on SQLite and on PostgreSQL.

### 13. The swap

- **Read:** in 001: "How the old CLI leaves", "What else the implementation touches", "Changelog", "Commit rules for this work". In 002: "The end of the legacy API".
- **Build:** remove the tag, `cmd/headscale/cli`, pterm, and cobra as the command framework; run `go run ./cmd/vendorhash update` after `go.mod` changes. Change what must match the default binary: the NixOS test kit with its BREAKING entry, the GitHub automation, the commands that the server prints, the docs, the packaging. On `/api/v1`: `deprecated` on every operation, the `Deprecation`, `Sunset` and `Link` headers, the warning in the log, the migration guide. The changelog: the edits that 001 lists, and the removal of `/api/v1` in 0.33. The removal of `nodes backfillips` is its own commit.

## Beside the stack

These are their own pull requests. They are not parts of the stack, but the stack depends on them.

- **The Tailscale API of Headscale.** "In the Tailscale API of Headscale" in 002 lists ten differences to remove and five to keep with a test. Pull request #3707 holds that work. Three of its rows touch the same code as the stack: expire and key expiry (part 5), the tag checks (parts 6 and 7) and the soft revoke of an OAuth client (part 7). The maintainer decided that those parts carry the work: each takes the commits of its rows from the branch of #3707, and never edits that branch.
- **The legacy API before it is frozen.** "In the legacy API, before it is frozen" in 002 lists three places where `/api/v1` differs from 0.29. One small pull request, before the swap.
- **Pull request #3708** makes a write that a unique index refuses a `409`. It changes `hscontrol/db` and the errors of `/api/v1`. Part 4, which creates users, carries its commits. When one of the two pull requests merges first, a rebase drops the same commits from the stack.

## What every pull request passes

- The Go tests, and the race check (`nix build -L .#checks.x86_64-linux.gorace`).
- `hscontrol/servertest`.
- The integration tests. Until part 12 they run on the old CLI, which no part changes, so they guard the server work of every slice.
- The hooks (`prek run`), the strict docs build, and the checks for stale generated files.
- A build with `-tags newcli`, from part 3 on.

The root runs the tests itself before it calls a part done. A report of a builder is not a test.

## The team

- **The root session** owns this plan and the proposals. A slice will find things that change the API or the CLI. The root decides each one, or asks the maintainer when it is his to decide, and writes the result into 001, 002 or 003 on the proposal branch. It writes no product code. It keeps its state in the plan, the TODO list and the stack, so that a summary of its context loses nothing.
- **A builder** (Opus) builds one slice, in a worktree on top of the slice before it. One builder works at a time.
- **Reviewers** read slice N while slice N+1 is built: Claude reviewers, and Codex in two Rex panes on the right, one above the other, with `gpt-6.1-sol` and `gpt-6-astra`. Codex reviews start on 2026-11-22.
- A finding goes back to the builder of that slice. The slices above it are rebased.

**What a builder gets from the root:** the goal of the slice in a few sentences; the block of the part from this file; the path of the proposal worktree; the answers to the "Ask first" points; the [risks](#risks) that touch the slice. A builder does not edit the proposals. When the code and a proposal cannot both be right, it stops and tells the root.

**What a reviewer gets:** the diff and the sections of the proposals for the part, not the builder's summary. It compares the code with the proposal, checks the "Done when" of the part, and checks the rules of `AGENTS.md`: the migration rules, the view types, no `AsStruct()` in `hscontrol/api`.

## Risks

- **The user delete on PostgreSQL** (part 8). One transaction is not enough: the delete must lock the user first, or a node that registers during the delete is lost with the user and a key made then outlives it. 002 has the detail.
- **The `revision` check** (part 5). It must run inside the update function of the NodeStore. A check in the handler is the race again. The NodeStore is the hot path: measure the snapshot build before the sort moves into it.
- **Migrations** (part 5, and any later part that needs a column). The rules in `AGENTS.md` are strict: only at the end, explicit DDL, in a transaction.
- **Huma's package-level settings** (part 2). Three APIs run in one process, so v0 must not change them.
- **The policy `ETag`** (part 10). It is compared under the policy lock. `/api/v2` compares before the lock today.
- **The NixOS test kit** (part 13). It is a public contract. A change needs the BREAKING entry.
- **The real-shell job** (part 3). It is the only test that sees the scripts and the protocol together, and its shells are not in the dev shell yet.
- **A partial v0 on `main`.** From part 2 on, `main` serves a v0 that is not complete. No 0.30 release is cut before part 13.

## Rules of the maintainer

These come on top of `AGENTS.md` and the maintainer's own instructions.

- No push, no pull request and no comment on GitHub without his word. Text for GitHub names no person with `@`.
- A decision for him goes through the question tool: two options, the recommended one first. The examples and the comparison go in the chat text, with short labels in the dialog.
- When an option is not built yet and he asks to see it, build it before the question.
- A proposal that is wrong is corrected in the same step as the code. The proposals stay true to the code.

## To check before the first pull request

- **Where the stack branches live.** Decided: in `juanfont/headscale`. The maintainer has push access there, and `gh stack` is installed. A stack has not been pushed there yet.
- **The state of #3707 and #3708.** Checked on 2026-11-19: both are open drafts, pass their checks and can merge. See [Beside the stack](#beside-the-stack).
- **The "Ask first" points of parts 1, 2 and 3.** Asked; each part has its answers.
- **The calls that the maintainer has not confirmed.** The two tables "Calls not confirmed by the maintainer" in 003. They do not block a part.
- **The notes on the code.** "What the code does today" in 001 was checked against `main` only for the files that changed in the last rebase.
- **Whether `hscontrol/servertest` can serve v0 over a unix socket** for the test helper of part 3. Checked: it serves no socket today. Part 2 adds one.

## State

The root keeps this section true. It holds the tasks of the part that is active, because the root has no TODO tool.

| Part | Branch                        | State                                                                                        |
| ---- | ----------------------------- | -------------------------------------------------------------------------------------------- |
| 1    | `kradalby/cli-v0-01-cmdline`  | a builder works on it; brief in `~/.cache/handover/headscale-kradalby-cli-v0-01-cmdline.md`  |
| 2    | `kradalby/cli-v0-02-api-base` | a builder works on it; brief in `~/.cache/handover/headscale-kradalby-cli-v0-02-api-base.md` |
