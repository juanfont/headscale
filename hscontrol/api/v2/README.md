# API v2 — Headscale's v2 API

This is Headscale's v2 HTTP API, served at `/api/v2`. Some of its endpoints are
**ported from Tailscale's API** — reusing Tailscale's wire shapes — so the
Tailscale ecosystem that cannot talk to Headscale today works: the
[Terraform/OpenTofu provider], [tscli], and the official [Go client]
(`tailscale.com/client/tailscale/v2`).

It is **not** a port of the whole Tailscale API. Ported endpoints are added one
at a time, only as we need them; a headscale-native v2 endpoint may use
headscale's own conventions. The headscale-native admin API stays at `/api/v1`
(`hscontrol/api/v1`). This guide is for the endpoints **ported from Tailscale**.

[Terraform/OpenTofu provider]: https://registry.terraform.io/providers/tailscale/tailscale/latest
[tscli]: https://github.com/jaxxstorm/tscli
[Go client]: https://pkg.go.dev/tailscale.com/client/tailscale/v2

## Conventions

- Operations derived from Tailscale carry the `Tailscale compat` tag.
- The `{tailnet}` path segment must be `-` (the single Headscale tailnet);
  anything else is `404`. See `requireDefaultTailnet`.
- Errors use **Tailscale's** body (`{"message","data","status"}`), installed as
  a per-API transform (`tailscaleErrorTransformer` in `errors.go`). A future
  headscale-native v2 operation would keep Huma's RFC 9457 problem+json.
- Auth accepts the API key as **HTTP Basic** (key as username — what the SDK
  sends) or **Bearer**. See `authMiddleware`.
- Each operation declares the Tailscale scope it would require (`auth_keys`,
  `devices:core`, `devices:routes`, `policy_file`, `feature_settings`, each with
  a `:read` subset). Nothing is enforced yet — every key is all-access — pending
  OAuth tokens; see the `TODO(scopes)` in `api.go`.
- Resolve one entity by id with a typed getter (`GetNodeByID`, `GetUserByID`,
  `GetAPIKeyByID`, `GetPreAuthKeyByID`); add one to state/db if it is missing
  rather than scanning a `List`. Build responses from the view accessors
  (`NodeView`/`UserView`/`PreAuthKeyView`), never `AsStruct()`.
- Reuse upstream wire shapes, but declare the request/response structs here:
  Huma reflects these to build the OpenAPI schema, and the upstream `Key`'s
  `ExpirySeconds *time.Duration` marshals as nanoseconds, which the spec and
  every client read as seconds.

## Adding an endpoint

Worked example: the keys resource (`keys.go`) = Tailscale auth keys = Headscale
pre-auth keys.

1. **Read the Tailscale spec.** Find the operation in the [Tailscale API
   reference](https://tailscale.com/api) (OpenAPI 3.1). Note method, path,
   request/response schema, and which variant(s) Headscale supports (auth keys
   only, for keys).

2. **Capture golden samples.** Pull the request + response JSON examples from the
   spec, prune to the variant, and use them as the assertion in the contract
   test. _Acceptance: the captured request and response are recorded in the
   test._

3. **Map to Headscale.** Write the field ↔ field ↔ `state` call mapping. Record
   gaps and the decision for each (e.g. Tailscale `preauthorized` has no
   Headscale equivalent — accepted, ignored, echoed back). _Acceptance: every
   request field is consumed or deliberately ignored; every response field has a
   source._

4. **Implement the Huma operation.** Declare named request/response structs with
   validation/`default`/`example`/`doc` tags; tag the operation `Tailscale
compat`; declare its `Errors`; enforce the tailnet and scope. Map state
   errors with `mapError`. _Acceptance: `go build ./hscontrol/api/v2/` and the
   operation appears in `Spec()`._

5. **Contract test (in-process, `humatest`).** Assert the server accepts the
   golden request and returns the golden response shape, with secrets and
   timestamps neutralised. Pin the wire facts (e.g. `expirySeconds` in seconds,
   the list `{"keys":[...]}` envelope, the error `message`). See
   `hscontrol/apiv2_keys_test.go`. _Acceptance: the test is green._

6. **Roundtrip the real clients.** Add a `t.Run` subtest to `TestAPIv2`
   (`hscontrol/servertest/apiv2_test.go`) for each of the Go client, tscli, and
   OpenTofu — full create→read→list→delete against one shared server on a real
   loopback port (`servertest.WithRealListener`). tscli and tofu come from the
   nix dev shell; a missing binary fails the test. _Acceptance: `nix develop -c
go test ./hscontrol/servertest/ -run TestAPIv2` is green._

7. **Update the CLI** only if the v2 operation fully replaces a v1 one. Tailscale
   has no separate key-expire verb — its `DELETE` _is_ the revoke — so v2 maps
   `DELETE` to a soft revoke: the key stays retrievable with `invalid: true`
   until the collector reaps it (`preauth_keys.revoked_retention`), the
   equivalent of v1 `preauthkeys expire`. `headscale preauthkeys` still stays on
   v1 for now (it is the cross-user admin surface), but the verb gap that
   previously blocked migration is closed.
