# AGENTS.md

Headscale is an open-source Tailscale control server in Go. This file holds
what the code cannot tell you. Directories with their own rules carry a nested
`AGENTS.md`: `hscontrol/db/` (migrations), `integration/`, `tools/bump/`
(version pins), `.github/` (Actions lock).

## Commands

```bash
nix develop                  # pinned toolchain (Go, golangci-lint, prek)
make dev                     # fmt + lint + test + build
make test                    # CGO_ENABLED=1 go test -race ./...
make fmt                     # format Go, docs, Nix and config files
make lint                    # golangci-lint
make generate                # go generate ./... + API clients in gen/
go test ./hscontrol/state -run 'TestName$'
nix build -L .#checks.x86_64-linux.gorace   # CI race check

go run ./cmd/hi doctor       # integration tests: read cmd/hi/README.md first
go run ./cmd/hi run "TestName"
```

The dev shell exports `CGO_ENABLED=0`; `-race` needs cgo.

Read `cmd/hi/README.md` in full before any `hi` command. Never guess flags.

## Pre-commit

`prek install` once in the dev shell; hooks match CI (treefmt, mdformat,
zizmor, `golangci-lint --new-from-rev=HEAD~1`, vendor hash). Never skip them
(`--no-verify`, `SKIP=`).

## Rules that are not visible in the code

- **Tags XOR user ownership.** A node is tagged or user-owned, never both.
  `node.IsTagged()` (`hscontrol/types/node.go`) is authoritative: a tagged node
  may still have `UserID` set for "created by" tracking.

  ```go
  if node.UserID().Valid() { /* assume user-owned */ }       // WRONG
  if node.UserID().Valid() && !node.IsTagged() { /* ok */ }  // correct
  ```

  Tagged nodes appear to clients as the `TaggedDevices` user
  (`hscontrol/types/users.go`). Ownership checks live in
  `validateNodeOwnership()` (`hscontrol/state/tags.go`).

- **Cross-subsystem work goes through `State`** (`hscontrol/state/state.go`),
  not the database directly. `NodeStore` writes rebuild a full snapshot;
  measure before changing hot-path code.

- **`hscontrol/policy/v2` is the only policy implementation.**
  `hscontrol/policy/policy.go` is thin wrappers.

- **`types`, `derp`, `dns` and `policy` never import `hscontrol/config`.**

- **Read paths use views.** Response serializers read through
  `NodeView`/`UserView`/`PreAuthKeyView`/`CredentialView`. `AsStruct()` clones
  the record; use it only for DB writes and mutable working copies.
  `grep AsStruct hscontrol/api` must come back empty.

- **zerolog**: prefer single-line chains. When building an event
  incrementally, reassign it (`e = e.Str("k", v)`); otherwise the field is
  silently dropped.

## Generated files — do not edit

- `gen/`: `make client` from the OpenAPI spec.
- `hscontrol/types/config_docs_generated.go`, `nix/options.generated.nix`,
  `docs/ref/configuration-options.md`, `docs/ref/config-example.yaml`:
  `go generate ./hscontrol/types/`.
- `services.headscale.settings` options come only from
  `nix/options.generated.nix`. Never declare one in `nix/module.nix`; the
  module only sets values, below `lib.mkDefault`.

## Dependencies

- Any `go.mod`/`go.sum` change needs `go run ./cmd/vendorhash update`, or
  `nix build` breaks.
- `go.mod`'s `go` directive must not exceed the Go nixpkgs ships; nix builds
  use `GOTOOLCHAIN=local`. `go get` raises it silently.
- Full rules: `tools/bump/AGENTS.md`.

## Testing

- Prefer `hscontrol/servertest/` (in-memory) over `integration/` (Docker).
- Integration flakes are almost always code. Read `hs-*.stderr.log` before
  blaming Docker.
- Some races surface only on SQLite or only on PostgreSQL (`hi run --postgres`).

## Public contract

The NixOS test kit is consumed by other projects: the "Contract" in
`nix/README.md` (`nix/testkit.nix`, `nix/testkit-peer.nix`, the embedded DERP
region, `HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR`, the CLI commands
`hs-authkey` calls). Breaking it needs a "NixOS test kit" BREAKING entry in
`CHANGELOG.md`.

## Commits

Go style: `package: imperative description`, e.g.
`state: fix policy change race in UpdateNodeFromMapRequest`. Not Conventional
Commits.
