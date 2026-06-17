# v1 API: behaviour changes (gRPC/grpc-gateway → ogen OpenAPI 3.0)

This file records every deliberate deviation of the new ogen-based v1 HTTP API
from the previous gRPC + grpc-gateway behaviour. Anything not listed here is
preserved: HTTP verbs and path templates, JSON property names (camelCase,
matching protojson), enum values (`SCREAMING_SNAKE`, e.g.
`REGISTER_METHOD_CLI`), RFC3339 timestamp strings, response envelopes
(`{"user": …}`, `{"nodes": […]}`, …), and the set of operations and their side
effects on the state layer.

Each entry: **what changed**, **why**, **client impact**.

## Wire format

### Integer IDs are JSON numbers, not strings

**What:** `id`, `nodeId`/`node_id`, `oldId`, `user`, and every other integer
identifier is now a JSON number (`"id": 42`). grpc-gateway emitted protojson's
int64-as-string form (`"id": "42"`).

**Why:** native integers are the idiomatic OpenAPI 3.0 / ogen representation,
type-safe end to end, and remove per-field string⇄int conversion. Headscale
identifiers are small and well within the JS safe-integer range.

**Client impact:** HTTP clients that read IDs as strings must read them as
numbers. `headscale … -o json/yaml` output changes accordingly (the CLI now
runs on the generated client).

### Error responses are RFC 7807 problem documents

**What:** errors are returned as `application/problem+json` with a body of
`{type?, title, status, detail, instance?}`. grpc-gateway returned an
`rpcStatus` envelope `{code, message, details[]}` as `application/json`, where
`code` was a gRPC status code and `details` was effectively always empty.

**Why:** RFC 7807 is the standard HTTP error shape; the gRPC `code`/`details`
fields were gRPC implementation leakage with no value over the HTTP status line.

**Client impact:** clients that parsed `{code, message}` must read
`{status, detail}` and the `application/problem+json` content type. The HTTP
status code itself is unchanged for equivalent conditions (e.g. unknown user →
404, invalid argument → 400, bad/My missing API key → 401).

## Behaviour

### Client errors return 4xx consistently

**What:** client mistakes now map to the appropriate 4xx status instead of 500.
Missing resources are `404` (e.g. `RenameUser`, `DeleteUser`, `GetNode`,
`DeleteNode`); invalid input is `400` (e.g. an unparseable route in
`SetApprovedRoutes`, a malformed registration key in `RegisterNode`, an invalid
tag in `SetTags`, an unconfirmed `BackfillNodeIPs`). Many of these gRPC handlers
returned a plain Go error, which grpc-gateway rendered as `500`.

**Why:** a missing resource or bad input is a client error, not a server error;
4xx is the correct, consistent status.

**Client impact:** clients that treated these as 500 should treat them as 400/404.

### Health on database failure

**What:** `GET /api/v1/health` returns `200 {"databaseConnectivity": true}` when
the database is reachable and `500` (problem document) when the ping fails. The
gRPC implementation returned the ping error, which grpc-gateway rendered as a
500; the `databaseConnectivity:false` body was never observable on failure.

**Why:** preserves the observable contract (200 healthy, 500 unhealthy) under
the new error shape.

**Client impact:** none beyond the problem-document error shape above.

## CLI

### Remote CLI connects to the HTTP API, not the gRPC port

**What:** with a configured `cli.address` (or `HEADSCALE_CLI_ADDRESS`), the CLI
now speaks HTTP to the headscale API URL rather than gRPC to `grpc_listen_addr`.
A bare `host:port` is assumed to be `https://host:port`. Locally (no address)
the CLI talks HTTP over the existing unix socket, unchanged in spirit — no API
key needed, filesystem permissions are the trust boundary.

**Why:** the gRPC service and its TCP listener are removed; the CLI runs on the
generated HTTP client.

**Client impact:** point `cli.address` at the headscale HTTP server (the same
URL `server_url` is reachable on) instead of the gRPC address. `cli.api_key`
and `cli.insecure` are unchanged.

### `delete`/`expire` commands print a result message

**What:** commands whose API operation has no response body (user/node/key
delete, key expire, auth approve/reject) print a small
`{"result": "..."}`-style object (or the human-readable message) instead of the
previous empty `{}`.

**Why:** the operations return no content; a result message is more useful than
an empty object.

**Client impact:** scripts parsing the empty `{}` should read the `result`
field (machine-readable output) or rely on the exit code.

### CLI database-bypass flag renamed

**What:** `--bypass-grpc-and-access-database-directly` is now
`--bypass-server-and-access-database-directly`.

**Why:** the gRPC server is gone; the flag bypasses the running server whatever
its transport, so the name no longer mentions gRPC.

**Client impact:** scripts using the old flag name must update it.

### Missing resources return a consistent `404`

**What:** renaming or expiring an unknown node, and expiring or deleting an
unknown pre-auth key, now return `404 Not Found`. Previously the node
operations surfaced as `500` and the pre-auth key operations reported success
without changing anything.

**Why:** a missing resource is a client error, not a server error, and an
expire or delete that matched no row should not report success.

**Client impact:** code that treated these as `500` or as a silent success
should handle `404`.

## Delivery note (not a shipped behaviour change)

The grpc-gateway HTTP facade is replaced wholesale at `/api/v1` by the ogen
server in the foundation commit, rather than path-by-path. During development,
endpoints whose resource group has not yet been migrated return `501` over HTTP;
all are implemented before the branch is complete. The CLI is unaffected during
this window because it still uses the gRPC servers until its own migration. No
intermediate state is released.
