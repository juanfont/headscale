# Plan: Headscale v1 API — gRPC/Protobuf → ogen OpenAPI 3.0

This is the implementation plan for converting the Headscale v1 API from a
Protobuf gRPC service with a grpc-gateway REST facade to an OpenAPI 3.0 spec
driving ogen-generated server stubs and a Go client, backed unchanged by the
`hscontrol/state` layer. It is written so coding agents can execute the
remaining work autonomously; tests are the gate.

See [CHANGES.md](./CHANGES.md) for every deliberate behaviour deviation.

## Locked decisions

- **Integer IDs** are native JSON numbers (`type: integer, format: uint64`), not protojson strings.
- **Errors** are RFC 7807 problem documents (`application/problem+json`).
- **Local CLI** talks HTTP over the existing unix socket (no API key; socket permissions are the trust boundary). Remote stays HTTPS + bearer key.
- Preserved by default: HTTP verbs/paths, camelCase JSON keys, `SCREAMING_SNAKE` enums, RFC3339 timestamps, response envelopes, operation set and state side effects.

## Package layout (v1 self-contained; v2 drops in as a sibling)

| Concern                     | Path                        | Package                          |
| --------------------------- | --------------------------- | -------------------------------- |
| Spec (source of truth)      | `openapi/v1/headscale.yaml` | —                                |
| Generated server+client     | `gen/api/v1/`               | `apiv1` (imported as `oas`)      |
| Handlers / state adapter    | `hscontrol/api/v1/`         | `apiv1`                          |
| HTTP-parity tests + harness | `hscontrol/servertest/`     | `servertest` / `servertest_test` |

v1 and v2 must not import each other or share generated types — they converge
only on `hscontrol/state`. Codegen: `go generate ./gen/api/v1/` (also run by
`make generate` via `go generate ./...`); CI freshness via
`.github/workflows/check-generated.yml`. Never hand-edit generated code; fix the
spec, never reach for `x-ogen` without recording in CHANGES.md why no spec
change works.

## Architecture

- **Routing.** chi is the top mux. The ogen server (`http.Handler`) is mounted at `/api/v1/*` in `app.go` `createRouter`; chi leaves `r.URL.Path` intact so ogen's router matches the full path. ogen owns `/api/v1` wholesale: un-migrated operations inherit `oas.UnimplementedHandler` (501) until their unit lands. Parallel endpoint agents therefore touch only their handler file + tests — never `app.go`.
- **Auth.** Spec declares `bearerAuth` (http/bearer) global security. `Server.HandleBearerAuth` → `state.ValidateAPIKey`; any failure → 401. (Unix-socket auth bypass is added in the CLI phase, when the socket serves HTTP.)
- **Errors.** `Server.NewError` (ogen's convenient-error hook for security/decoding) and `errorHandler` (`WithErrorHandler`, for plain handler errors) both route through `classify` in `hscontrol/api/v1/errors.go`: typed `*oas.ErrorStatusCode` pass through; ogen framework errors use their `Code()` (security→401, decode→400); state errors via `mapStateError` (not-found sentinels→404, `ErrPolicyUpdateIsDisabled`→400, else 500). Handlers build expected errors with `apiError`/`notFound`/`badRequest`/`mapStateError`.
- **Side effects.** Handlers replicate the exact `state.*` call sequence and `change(...)` notifications from `hscontrol/grpcv1.go` (policy reload on SetPolicy, route auto-approval on RegisterNode, change broadcasts on node mutations, etc.). The adapter holds `state *state.State`, `cfg *types.Config`, and `change func(...change.Change)` (wired to `Headscale.Change`); it does not import the parent `hscontrol` package (no import cycle).
- **Transitional gRPC.** The gRPC unix-socket and TCP servers keep running through the endpoint phase so the existing CLI works; they (and proto/gateway code) are removed in cutover.

## Operation inventory (backbone) → state mapping

All paths keep the current `google.api.http` templates. Source of truth for
behaviour: `hscontrol/grpcv1.go`.

**User** — `hscontrol/api/v1/users.go`

- `POST /api/v1/user` CreateUser → `state.CreateUser`; `change(policyChanged)`.
- `GET /api/v1/user` ListUsers(`id`,`name`,`email` query) → `ListUsersWithFilter` (by name|email|id) else `ListAllUsers`; sort by id.
- `POST /api/v1/user/{old_id}/rename/{new_name}` RenameUser → `GetUserByID`,`RenameUser`,`change(c)`,`GetUserByName`.
- `DELETE /api/v1/user/{id}` DeleteUser → `GetUserByID`,`DeleteUser`,`change`.

**PreAuthKey** — `preauthkeys.go`

- `POST /api/v1/preauthkey` CreatePreAuthKey → validate each `aclTags` (`validateTag`), optional `GetUserByID`, `CreatePreAuthKey(userID, reusable, ephemeral, &expiration, aclTags)`.
- `GET /api/v1/preauthkey` ListPreAuthKeys → `ListPreAuthKeys`; sort by id.
- `POST /api/v1/preauthkey/expire` ExpirePreAuthKey → `ExpirePreAuthKey(id)`.
- `DELETE /api/v1/preauthkey` DeletePreAuthKey(`id` query) → `DeletePreAuthKey(id)`.

**Node** — `nodes.go`

- `GET /api/v1/node` ListNodes(`user` query) → `GetUserByName`+`ListNodesByUser` | `ListNodes`; `nodesToProto` (tagged→`TaggedDevices` user; `subnetRoutes` = primary+exit routes); sort by id.
- `POST /api/v1/node/register` RegisterNode(`user`,`key` query) → `AuthIDFromString`,`GetUserByName`,`HandleNodeFromAuthPath(...,RegisterMethodCLI)`,`AutoApproveRoutes`,`change(nodeChange,routeChange)`.
- `POST /api/v1/node/backfillips` BackfillNodeIPs(`confirmed` query) → require confirmed else error; `BackfillNodeIPs`.
- `GET /api/v1/node/{node_id}` GetNode → `GetNodeByID`; not found → 404.
- `DELETE /api/v1/node/{node_id}` DeleteNode → `GetNodeByID`(404),`DeleteNode`,`change`.
- `POST /api/v1/node/{node_id}/tags` SetTags → non-empty tags else 400; `validateTag` each; `GetNodeByID`(404); `SetNodeTags`(invalid→400); `change`.
- `POST /api/v1/node/{node_id}/approve_routes` SetApprovedRoutes → parse prefixes; exit-route expansion (AllIPv4/AllIPv6 → add both); sort+compact; `SetApprovedRoutes`(invalid→400); `change`; set `subnetRoutes` = `GetNodePrimaryRoutes`.
- `POST /api/v1/node/{node_id}/expire` ExpireNode(`expiry`,`disable_expiry` query) → both set → 400; disable → `SetNodeExpiry(nil)`; else `SetNodeExpiry(&expiry)` (default now); `change`.
- `POST /api/v1/node/{node_id}/rename/{new_name}` RenameNode → `RenameNode`,`change`.
- `POST /api/v1/debug/node` DebugCreateNode → `GetUserByName`,`StringToIPPrefix`,`AuthIDFromString`,`SetAuthCacheEntry`; echo synthetic node.

**Auth** — `auth.go`

- `POST /api/v1/auth/register` AuthRegister → delegates to RegisterNode(`key`=authId,`user`).
- `POST /api/v1/auth/approve` AuthApprove → `AuthIDFromString`(400),`GetAuthCacheEntry`(404),`FinishAuth({})`.
- `POST /api/v1/auth/reject` AuthReject → `AuthIDFromString`(400),`GetAuthCacheEntry`(404),`FinishAuth({Err})`.

**ApiKey** — `apikeys.go`

- `POST /api/v1/apikey` CreateApiKey → `CreateAPIKey(&expiration)`; returns raw `apiKey` string.
- `GET /api/v1/apikey` ListApiKeys → `ListAPIKeys`; sort by id.
- `POST /api/v1/apikey/expire` ExpireApiKey → `getAPIKey` (id xor prefix; neither/both→400),`ExpireAPIKey`.
- `DELETE /api/v1/apikey/{prefix}` DeleteApiKey(`id` query) → `getAPIKey`,`DestroyAPIKey`.

**Policy** — `policy.go`

- `GET /api/v1/policy` GetPolicy → DB mode: `GetPolicy`; file mode: read `cfg.Policy.Path`.
- `PUT /api/v1/policy` SetPolicy → DB mode only (`ErrPolicyUpdateIsDisabled`→400); `ListNodes`,`SetPolicy`,`SSHPolicy(node0)`,`SetPolicyInDB`,`ReloadPolicy`,`change(cs...)`.
- `POST /api/v1/policy/check` CheckPolicy → `ListAllUsers`,`ListNodes`,`NewPolicyManager`+`SetPolicy` (no persist; invalid→400).

**Health** — `health.go` (done) — `PingDB`; ok→200, fail→500.

## Handler authoring recipe (for endpoint agents)

For each resource group, in this order, then `/commit` (Go style: `api: <imperative>`):

1. **Tests first.** Add `hscontrol/servertest/apiv1_<resource>_test.go` (package `servertest_test`). Use `srv := servertest.NewServer(t)`, `client := srv.APIClient(t, srv.CreateAPIKey(t))`, seed state via `srv.State()` / existing `servertest` helpers. Assert: success payloads (status, envelope, field values), every error path (404/400/401 with `*apiv1.ErrorStatusCode` status), and state side effects (re-read via `srv.State()`). Cover real behaviour, not just happy paths. Where the new contract intentionally differs from the old, the assertion encodes the new value **and** there is a matching CHANGES.md entry.
1. **Implement** the group's handler methods on `*apiv1.Server` in `hscontrol/api/v1/<resource>.go`, mirroring the `grpcv1.go` logic and side effects exactly. Convert between ogen types (`*XxxReq`, `XxxParams`, `*XxxOK`, `oas.User`/`oas.Node`/…) and state types. Build `oas.OptXxx` for optional fields; map state results to the response envelope. Errors: `notFound`/`badRequest`/`mapStateError`/`apiError`.
1. **CLI tests** for the group's commands belong to the CLI phase (`integration/`); reference them in the unit's acceptance.
1. **CHANGES.md**: add an entry for any deviation; if a test had to encode a non-preserved behaviour, it must correspond to an entry.
1. Run `goimports -w`, `go test ./hscontrol/servertest/ -run TestAPIv1_<Resource>`, then `make fmt`/`make lint` on touched files. Commit.

A reusable proto→ogen conversion (`oas.User` from `types.User`, etc.) should live in `hscontrol/api/v1/convert.go`; the first agent to need a converter adds it there and others reuse it. Do not duplicate.

## Work units & dependency map

```
F1 spec → F2 codegen+CI → F3 server/adapter/auth/errors → F4 harness   [DONE]
                                                              │
         ┌────────────────────────────────────────────────────┐
         E1 User   E2 PreAuthKey   E3 Node   E4 Auth   E5 ApiKey   E6 Policy   E7 Health(done)
         └────────────────────────────────────────────────────┘   (parallel; touch only own handler+tests)
F2 → C0 CLI client adapter → C1..C8 per-command (each needs its E-unit)  (parallel)
all E* + all C* → X1 flip/auth → X2 remove proto/gRPC/gateway → X3 docs+served spec → X4 reconcile
```

- **E1–E7**: each owns its handler file + `apiv1_<resource>_test.go`. Acceptance: that group's HTTP-parity tests green; behaviour matches `grpcv1.go` modulo CHANGES.md.
- **C0**: rework `cmd/headscale/cli/utils.go` dial point to build `apiv1.Client` (local HTTP-over-unix, no key; remote HTTPS+`HEADSCALE_CLI_API_KEY`+`cli.insecure`). Serve ogen over the unix socket; add socket auth-bypass. **C1–C8**: convert each `cmd/headscale/cli/*.go` off the gRPC client; gate with `integration/` CLI tests. Acceptance: no `v1.HeadscaleServiceClient` usage remains.
- **X1**: ogen is already the sole `/api/v1` handler; ensure no chi auth duplication, remove any dead gateway wiring. **X2**: delete `proto/headscale/v1`, `gen/go`, `gen/openapiv2`, `hscontrol/grpcv1.go`(+test), gRPC servers, `buf.*`; drop grpc/grpc-gateway deps (verify Noise is independent). **X3**: serve `openapi/v1/headscale.yaml` at `/swagger`; update `swagger.go` embed + `docs/`. **X4**: reconcile PLAN.md/CHANGES.md to the built state; DoD checklist green.

## Status

- [x] **F1** spec — `openapi/v1/headscale.yaml` (all 27 ops, native int64, RFC7807 `Problem`, bearerAuth). ogen generates cleanly.
- [x] **F2** codegen — `gen/api/v1/generate.go` (`go generate`), ogen tool dep in `go.mod`, CI freshness covers `openapi/**`.
- [x] **F3** server/adapter/auth/errors — `hscontrol/api/v1/{server,errors,auth,health}.go`; mounted at `/api/v1`; gateway unmounted; gRPC servers retained.
- [x] **F4** harness — `servertest.APIClient`/`CreateAPIKey`; Health parity + 401 tests green.
- [x] **E1–E7** endpoints — all 27 operations implemented in `hscontrol/api/v1/{users,apikeys,preauthkeys,nodes,auth,policy,health}.go` with HTTP-parity tests in `hscontrol/servertest/apiv1_*_test.go` (30 tests, all green).
- [x] **C0–C8** CLI migration — server serves the API over the unix socket (auth bypassed via `apiv1.WithSocketAuth`); every `cmd/headscale/cli/*.go` command runs on the generated `apiv1.Client`; no gRPC client usage remains.
- [x] **X1/X2** proto/gRPC removal — `grpcv1.go`, the TCP gRPC server + interceptor, the `.Proto()`/`RegisterMethodToV1Enum` builders, `proto/`, `gen/go/`, `gen/openapiv2/`, and `buf.gen.yaml` are deleted; `convert.go` reads the state views directly; `integration/` decodes into `apiv1` types. `grep` finds zero proto references in any `.go` file. grpc/grpc-gateway are no longer direct go.mod deps. Proto lint/format targets removed from the Makefile.
- [x] **X3** served spec — `/swagger` serves the embedded `openapi/v1/headscale.yaml` (3.0).
- [x] **X4** reconcile — this document and CHANGES.md reflect the built state.

The conversion is complete. The full `go test ./...` suite is validatable here for
everything except the Docker-based `integration/` package, which is
compile-clean (`go vet ./integration/...`) and ported to the new wire format; its
end-to-end run is gated on Docker (`go run ./cmd/hi`).

## Definition of done

Every v1 op served by ogen over the state layer; HTTP + CLI tests cover every
endpoint and pass; CLI on the generated client (no gRPC client); proto/gRPC +
gateway + generated code removed; generated code matches committed spec
(CI green); docs + `/swagger` point at the 3.0 spec; v1 self-contained, no
cross-version coupling; current behaviour preserved except deliberate,
test-matched, CHANGES.md-recorded deviations.
