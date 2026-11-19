# tools/bump

`go run ./tools/bump plan` reports stale pins and changes nothing;
`go run ./tools/bump verify` exits non-zero when pins disagree. A hand-written
bump follows the same rules:

1. `modernc.org/libc` moves only to the version `modernc.org/sqlite` requires;
   `gvisor.dev/gvisor` only to the version `tailscale.com` requires. Read both
   off the owner's `go.mod` via `proxy.golang.org`, never guess. If the partner
   cannot be resolved, neither half moves. `go mod tidy` can detach the `go.mod`
   NOTE comments explaining this; check they are still attached.
2. Any `go.mod`/`go.sum` change needs `go run ./cmd/vendorhash update`.
3. `go.mod`'s `go` directive must not exceed nixpkgs' Go. `go get` raises it
   silently and local builds download a toolchain; nix builds use
   `GOTOOLCHAIN=local` and fail. `bump verify` reports it; the tool never
   edits the directive.
4. Actions: see `.github/AGENTS.md`.

Not encoded in the tool: `github.com/libdns/*` providers and
`github.com/caddyserver/certmagic` must share the `github.com/libdns/libdns`
major version. One provider instance serves both, so a provider on another
major waits until certmagic moves.

Servertest Terraform tests run the newest three `tailscale/tailscale` provider
releases from `terraformProviderVersions` (`hscontrol/servertest/apiv2_test.go`).
The list is committed, so new releases arrive as bump PRs. A test of a provider
feature calls `requireProvider` with the first release that has it.

`Dockerfile.tailscale-HEAD` and `Dockerfile.derper` build an unpinned tailscale
branch: their builder image is a floor (≥ upstream's `go` directive), and
`GOTOOLCHAIN=auto` turns an upstream bump into a slower build, not a broken one.
