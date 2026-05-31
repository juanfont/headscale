# AGENTS.md

Behavioural guidance for AI agents working in this repository. Reference
material for complex procedures lives next to the code — integration
testing is documented in [`cmd/hi/README.md`](cmd/hi/README.md) and
[`integration/README.md`](integration/README.md). Read those files
before running tests or writing new ones.

Headscale is an open-source implementation of the Tailscale control server
written in Go. It manages node registration, IP allocation, policy
enforcement, and DERP routing for self-hosted tailnets.

## Interaction Rules

These rules govern how you work in this repo. They are listed first
because they shape every other decision.

### Ask with comprehensive multiple-choice options

When you need to clarify intent, scope, or approach, use the
`AskUserQuestion` tool (or a numbered list fallback) and present the user
with a comprehensive set of options. Cover the likely branches explicitly
and include an "other — please describe" escape.

- Bad: _"How should I handle expired nodes?"_
- Good: _"How should expired nodes be handled? (a) Remain visible to peers
  but marked expired (current behaviour); (b) Hidden from peers entirely;
  (c) Hidden from peers but visible in admin API; (d) Other."_

This matters more than you think — open-ended questions waste a round
trip and often produce a misaligned answer.

### Read the documented procedure before running complex commands

Before invoking any `hi` command, integration test, generator, or
migration tool, read the referenced README in full —
`cmd/hi/README.md` for running tests, `integration/README.md` for
writing them. Never guess flags. If the procedure is not documented
anywhere, ask the user rather than inventing one.

### Map once, then act

Use `Glob` / `Grep` to understand file structure, then execute. Do not
re-explore the same area to "double-check" once you have a plan. Do not
re-read files you edited in this session — the harness tracks state for
you.

### Fail fast, report up

If a command fails twice with the same error, stop and report the exact
error to the user with context. Do not loop through variants or
"try one more thing". A repeated failure means your model of the problem
is wrong.

### Confirm scope for multi-file changes

Before touching more than three files, show the user which files will
change and why. Use plan mode (`ExitPlanMode`) for non-trivial work.

### Prefer editing existing files

Do not create new files unless strictly necessary. Do not generate helper
abstractions, wrapper utilities, or "just in case" configuration. Three
similar lines of code is better than a premature abstraction.

## Quick Start

```bash
# Enter the nix dev shell (Go 1.26.1, buf, golangci-lint, prek)
nix develop

# Full development workflow: fmt + lint + test + build
make dev

# Individual targets
make build           # build the headscale binary
make test            # go test ./...
make fmt             # format Go, docs, proto
make lint            # lint Go, proto
make generate        # regenerate protobuf code (after changes to proto/)
make clean           # remove build artefacts

# Direct go test invocations
go test ./...
go test -race ./...

# Integration tests — read cmd/hi/README.md first
go run ./cmd/hi doctor
go run ./cmd/hi run "TestName"
```

Go 1.26.1 minimum (per `go.mod:3`). `nix develop` pins the exact toolchain
used in CI.

## Pre-Commit with prek

`prek` installs git hooks that run the same checks as CI.

```bash
nix develop
prek install            # one-time setup
prek run                # run hooks on staged files
prek run --all-files    # run hooks on the full tree
```

Hooks cover: file hygiene (trailing whitespace, line endings, BOM),
syntax validation (JSON/YAML/TOML/XML), merge-conflict markers, private
key detection, nixpkgs-fmt, prettier, and `golangci-lint` via
`--new-from-rev=HEAD~1` (see `.pre-commit-config.yaml:59`). A manual
invocation with an `upstream/main` remote is equivalent:

```bash
golangci-lint run --new-from-rev=upstream/main --timeout=5m --fix
```

`git commit --no-verify` is acceptable only for WIP commits on feature
branches — never on `main`.

## Project Layout

```
headscale/
├── cmd/
│   ├── headscale/    # Main headscale server binary
│   └── hi/           # Integration test runner (see cmd/hi/README.md)
├── hscontrol/        # Core control plane
├── integration/      # End-to-end Docker-based tests (see integration/README.md)
├── proto/            # Protocol buffer definitions
├── gen/              # Generated code (buf output — do not edit)
├── docs/             # User and ACL reference documentation
└── packaging/        # Distribution packaging
```

### `hscontrol/` packages

- `app.go`, `handlers.go`, `grpcv1.go`, `noise.go`, `auth.go`, `oidc.go`,
  `poll.go`, `metrics.go`, `debug.go`, `tailsql.go`, `platform_config.go`
  — top-level server files
- `state/` — central coordinator (`state.go`) and the copy-on-write
  `NodeStore` (`node_store.go`). All cross-subsystem operations go
  through `State`.
- `db/` — GORM layer, migrations, schema. `node.go`, `users.go`,
  `api_key.go`, `preauth_keys.go`, `ip.go`, `policy.go`.
- `mapper/` — streaming batcher that distributes MapResponses to
  clients: `batcher.go`, `node_conn.go`, `builder.go`, `mapper.go`.
  Performance-critical.
- `policy/` — `policy/v2/` is **the** policy implementation. The
  top-level `policy.go` is thin wrappers. There is no v1 directory.
- `routes/`, `dns/`, `derp/`, `types/`, `util/`, `templates/`, `capver/`
  — routing, MagicDNS, relay, core types, helpers, client templates,
  capability versioning.
- `servertest/` — in-memory test harness for server-level tests that
  don't need Docker. Prefer this over `integration/` when possible.
- `assets/` — embedded UI assets.

### `cmd/hi/` files

`main.go`, `run.go`, `doctor.go`, `docker.go`, `cleanup.go`, `stats.go`,
`README.md`. **Read `cmd/hi/README.md` before running any `hi` command.**

## Architecture Essentials

- **`hscontrol/state/state.go`** is the central coordinator. Cross-cutting
  operations (node updates, policy evaluation, IP allocation) go through
  the `State` type, not directly to the database.
- **`NodeStore`** in `hscontrol/state/node_store.go` is a copy-on-write
  in-memory cache backed by `atomic.Pointer[Snapshot]`. Every read is a
  pointer load; writes rebuild a new snapshot and atomically swap. It is
  the hot path for `MapRequest` processing and peer visibility.
- **The map-request sync point** is
  `State.UpdateNodeFromMapRequest()` in
  `hscontrol/state/state.go:2351`. This is where Hostinfo changes,
  endpoint updates, and route advertisements land in the NodeStore.
- **Mapper subsystem** streams MapResponses via `batcher.go` and
  `node_conn.go`. Changes here affect all connected clients.
- **Node registration flow**: noise handshake (`noise.go`) → auth
  (`auth.go`) → state/DB persistence (`state/`, `db/`) → initial map
  (`mapper/`).

## Database Migration Rules

These rules are load-bearing — violating them corrupts production
databases. The `migrationsRequiringFKDisabled` map in
`hscontrol/db/db.go:962` is frozen as of 2025-07-02 (see the comment at
`db.go:989`). All new migrations must:

1. **Never reorder existing migrations.** Migration order is immutable
   once committed.
2. **Only add new migrations to the end** of the migrations array.
3. **Never disable foreign keys.** No new entries in
   `migrationsRequiringFKDisabled`.
4. **Use the migration ID format** `YYYYMMDDHHMM-short-description`
   (timestamp + descriptive suffix). Example: `202602201200-clear-tagged-node-user-id`.
5. **Never rename columns** that later migrations reference. Let
   `AutoMigrate` create a new column if needed.

## Tags-as-Identity

Headscale enforces **tags XOR user ownership**: every node is either
tagged (owned by tags) or user-owned (owned by a user namespace), never
both. This is a load-bearing architectural rule.

- **Use `node.IsTagged()`** (`hscontrol/types/node.go:221`) to determine
  ownership, not `node.UserID().Valid()`. A tagged node may still have
  `UserID` set for "created by" tracking — `IsTagged()` is authoritative.
- `IsUserOwned()` (`node.go:227`) returns `!IsTagged()`.
- Tagged nodes are presented to Tailscale as the special
  `TaggedDevices` user (`hscontrol/types/users.go`, ID `2147455555`).
- `SetTags` validation is enforced by `validateNodeOwnership()` in
  `hscontrol/state/tags.go`.
- Examples and edge cases live in `hscontrol/types/node_tags_test.go`
  and `hscontrol/grpcv1_test.go` (`TestSetTags_*`).

**Don't do this**:

```go
if node.UserID().Valid() { /* assume user-owned */ }       // WRONG
if node.UserID().Valid() && !node.IsTagged() { /* ok */ }  // correct
```

## Policy Engine

`hscontrol/policy/v2/policy.go` is the policy implementation. The
top-level `hscontrol/policy/policy.go` contains only wrapper functions
around v2. There is no v1 directory.

Key concepts an agent will encounter:

- **Autogroups**: `autogroup:self`, `autogroup:member`, `autogroup:internet`
- **Tag owners**: IP-based authorization for who can claim a tag
- **Route approvals**: auto-approval of subnet routes by policy
- **SSH policies**: SSH access control via grants
- **HuJSON** parsing for policy files

For usage examples, read `hscontrol/policy/v2/policy_test.go`. For ACL
reference documentation, see `docs/`.

## Integration Testing

**Before running any `hi` command, read `cmd/hi/README.md` in full.**
Guessing at `hi` flags leads to broken runs and stale containers.

Test-authoring patterns (`EventuallyWithT`, `IntegrationSkip`, helper
variants, scenario setup) are documented in `integration/README.md`.

Key reminders:

- Integration test functions **must** start with `IntegrationSkip(t)`.
- External calls (`client.Status`, `headscale.ListNodes`, etc.) belong
  inside `EventuallyWithT`; state-mutating commands (`tailscale set`)
  must not.
- Tests generate ~100 MB of logs per run under `control_logs/{runID}/`.
  Prune old runs if disk is tight.
- Flakes are almost always code, not infrastructure. Read `hs-*.stderr.log`
  before blaming Docker.

## Code Conventions

- **Commit messages** follow Go-style `package: imperative description`.
  Recent examples from `git log`:
  - `db: scope DestroyUser to only delete the target user's pre-auth keys`
  - `state: fix policy change race in UpdateNodeFromMapRequest`
  - `integration: fix ACL tests for address-family-specific resolve`

  Not Conventional Commits. No `feat:`/`chore:`/`docs:` prefixes.

- **Protobuf regeneration**: changes under `proto/` require
  `make generate` (which runs `buf generate`) and should land in a
  **separate commit** from the callers that use the regenerated types.
- **Formatting** is enforced by `golangci-lint` with `golines` (width 88)
  and `gofumpt`. Run `make fmt` or rely on the pre-commit hook.
- **Logging** uses `zerolog`. Prefer single-line chains
  (`log.Info().Str(...).Msg(...)`). For 4+ fields or conditional fields,
  build incrementally and **reassign** the event variable:
  `e = e.Str("k", v)`. Forgetting to reassign silently drops the field.
- **Tests**: prefer `hscontrol/servertest/` for server-level tests that
  don't need Docker — faster than full integration tests.

## Gotchas

- **Database**: SQLite for local dev, PostgreSQL for integration-heavy
  tests (`go run ./cmd/hi run "..." --postgres`). Some race conditions
  only surface on one backend.
- **NodeStore writes** rebuild a full snapshot. Measure before changing
  hot-path code.
- **`.claude/agents/` is deprecated.** Do not create new agent files
  there. Put behavioural guidance in this file and procedural guidance
  in the nearest README.
- **Do not edit `gen/`** — it is regenerated from `proto/` by
  `make generate`.
- **Proto changes + code changes should be two commits**, not one.
