# API v2: Headscale's v2 API

This is Headscale's v2 HTTP API, served at `/api/v2`. Some of its endpoints are
**ported from Tailscale's API**, reusing Tailscale's wire shapes, so the
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
- Auth accepts a credential as **HTTP Basic** (key as username, what the SDK
  sends) or **Bearer**: an admin API key (`hskey-api-…`), or an OAuth access
  token (`hskey-oauthtok-…`). See `authMiddleware`.
- Each operation declares the Tailscale scope it requires (`auth_keys`,
  `oauth_keys`, `devices:core`, `devices:routes`, `policy_file`,
  `feature_settings`, each with a `:read` subset, plus `all`/`all:read`).
  `requireScope` records it both for the middleware and in the generated
  OpenAPI, as an `x-required-scope` extension and a sentence in the operation
  description, so the scope shows up in the docs and spec. Enforcement: an
  **admin API key is all-access** (scope checks skipped); an **OAuth access
  token is scope-limited**, the middleware checks the operation's declared scope
  against the token's grant (`scope.Grants`, where a write scope subsumes its
  `:read` and `all`/`all:read` are super-scopes). The two are told apart by
  credential prefix.
- Resolve one entity by id with a typed getter (`GetNodeByID`, `GetUserByID`,
  `GetAPIKeyByID`, `GetPreAuthKeyByID`); add one to state/db if it is missing
  rather than scanning a `List`. Build responses from the view accessors
  (`NodeView`/`UserView`/`PreAuthKeyView`), never `AsStruct()`.
- Reuse upstream wire shapes, but declare the request/response structs here:
  Huma reflects these to build the OpenAPI schema, and the upstream `Key`'s
  `ExpirySeconds *time.Duration` marshals as nanoseconds, which the spec and
  every client read as seconds.

## OAuth clients & scopes

Most of the Tailscale ecosystem (the Terraform provider, `tscli`, the Go client)
accepts **either** an API key **or OAuth 2.0 client-credentials**; the Kubernetes
operator is OAuth-only. Supporting OAuth lets all of them drive Headscale.

- **OAuth clients** are not a separate resource; they are `keyType:"client"` on
  the keys endpoint, exactly as Tailscale does it. Create
  (`POST /api/v2/tailnet/-/keys` with `{"keyType":"client","scopes":[…],"tags":[…]}`)
  returns a `Key` whose `id` is the client id and whose `key` is the secret,
  **shown once**; get/list never re-expose it. The secret is
  `hskey-client-<clientID>-<secret>`, embedding the client id so the token
  endpoint derives it from the secret (Tailscale's `get-authkey` trick). See
  `keys.go` (`createOAuthClient`) and `db/oauth.go`.
- **Token endpoint** `POST /api/v2/oauth/token` (`oauth.go`) is a plain handler,
  not a Huma operation: it takes `application/x-www-form-urlencoded` and emits
  RFC 6749 OAuth2 error bodies (`{"error","error_description"}`). Credentials
  arrive in the body or HTTP Basic; optional space-delimited `scope`/`tags`
  narrow the token to a subset of the client's grant. It returns a 1-hour
  `Bearer` access token (`hskey-oauthtok-…`).
- **Scope enforcement** is the one seam in `authMiddleware`. **Tag enforcement**:
  an auth key minted by a token may only carry tags the token holds, or tags
  owned-by them via the policy `tagOwners` (`State.TagOwnedByTags` →
  `policy/v2`), so e.g. an operator token tagged `tag:k8s-operator` may mint
  `tag:k8s` keys.
- Credentials/tokens are stored like API keys: a public id/prefix plus an
  **Argon2id** hash of the secret (no JWT, no signing keys). `OAuthClient` and
  `OAuthAccessToken` live in `types/oauth.go` and `db/oauth.go`.

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
   Headscale equivalent: accepted, ignored, echoed back). _Acceptance: every
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
   OpenTofu, full create→read→list→delete against one shared server on a real
   loopback port (`servertest.WithRealListener`). tscli and tofu come from the
   nix dev shell; a missing binary fails the test. _Acceptance: `nix develop -c
go test ./hscontrol/servertest/ -run TestAPIv2` is green._

7. **Update the CLI** only if the v2 operation fully replaces a v1 one. Tailscale
   has no separate key-expire verb (its `DELETE` _is_ the revoke), so v2 maps
   `DELETE` to a soft revoke: the key stays retrievable with `invalid: true`
   until the collector reaps it (`preauth_keys.revoked_retention`), the
   equivalent of v1 `preauthkeys expire`. `headscale preauthkeys` still stays on
   v1 for now (it is the cross-user admin surface), but the verb gap that
   previously blocked migration is closed.
