# API v0 problem codes

!!! note "Generated page"

    This page is generated from the list of codes in `hscontrol/api/headscale/v0/problem.go` by
    `go run ./cmd/gen-openapi -api headscale/v0`. Edit the list there, not this page.

Every error of `/api/headscale/v0` is a problem (RFC 9457). A program reads its `code`; the
`type` of the problem leads to the heading of that code here. `details` holds the data of the
code, and is `{}` when the code has none. `object` names the resource the problem is about; for an
auth request its `id` is always `""`, as the auth ID is a secret, and `name` is the hostname of a
registration that waits.

## auth_request_kind { #auth_request_kind }

- **Status:** 409
- **Title:** The auth request is of another kind
- **When:** `register` on an SSH check, or `approve` on a registration. Nothing is answered; the request still waits. `object` is the auth request, without its ID, which is a secret.
- **`details`:**
    - `kind`: the kind the request is, `registration` or `sshCheck`

## email_taken { #email_taken }

- **Status:** 409
- **Title:** The email is taken
- **When:** The email of a local user equals the name, the email or the provider identifier of another user, without regard to case. A policy names a user by these texts. `object` is that user.
- **`details`:**
    - `email`: the email that is taken, as the request sent it

## empty_patch { #empty_patch }

- **Status:** 422
- **Title:** The patch changes nothing
- **When:** A `PATCH` with no fields.
- **`details`:** `{}`

## expiry_in_past { #expiry_in_past }

- **Status:** 422
- **Title:** The expiry is in the past
- **When:** An expiry before now. A node's expiry takes `"now"` for the server's clock; a key's must be in the future.
- **`details`:** `{}`

## expiry_required { #expiry_required }

- **Status:** 422
- **Title:** An expiry is required
- **When:** A key with no expiry.
- **`details`:** `{}`

## forbidden { #forbidden }

- **Status:** 403
- **Title:** The credential may not do this
- **When:** The token lacks a scope the operation needs, or breaks a token rule.
- **`details`:**
    - `scopes`: every scope the token lacks; `[]` when a rule refused it
    - `rule`: a short word naming the token rule that refused it; `null` when a scope is missing

## internal { #internal }

- **Status:** 500
- **Title:** The server failed
- **When:** A fault in the server. The server log has it, under the `requestId`.
- **`details`:** `{}`

## invalid_field { #invalid_field }

- **Status:** 422
- **Title:** A field or parameter is not valid
- **When:** A field or parameter is unknown, or has a value that is not allowed. `errors` names each one; a long list may be cut, and then its last entry has `location` `""` and says how many more.
- **`details`:** `{}`

## invalid_page_token { #invalid_page_token }

- **Status:** 422
- **Title:** The page token is not valid
- **When:** The page token was not made by this server, is for another list or other filters, or is from before a restart. Start again from the first page.
- **`details`:** `{}`

## invalid_request { #invalid_request }

- **Status:** 400
- **Title:** The request cannot be read
- **When:** The body is not valid JSON.
- **`details`:** `{}`

## invalid_scope { #invalid_scope }

- **Status:** 422
- **Title:** The scope does not exist
- **When:** A scope that the server does not know.
- **`details`:**
    - `scopes`: every scope of the request that the server does not know

## method_not_allowed { #method_not_allowed }

- **Status:** 405
- **Title:** The method is not allowed on this path
- **When:** The path exists, the method does not. The `Allow` header lists the methods it takes.
- **`details`:** `{}`

## name_taken { #name_taken }

- **Status:** 409
- **Title:** The name is taken
- **When:** The name belongs to another node or user; `object` is that one. The name of a local user is also taken when it equals the email or the provider identifier of another user, without regard to case.
- **`details`:**
    - `name`: the name that is taken, as the request sent it; `object` names the holder as messages do, which for a user can be its email

## not_found { #not_found }

- **Status:** 404
- **Title:** The resource does not exist
- **When:** The resource does not exist, or no longer exists; also a path that no operation has.
- **`details`:** `{}`

## owner_conflict { #owner_conflict }

- **Status:** 422
- **Title:** The owner is not one user or tags
- **When:** A key with both a user and tags, or with neither.
- **`details`:** `{}`

## policy_invalid { #policy_invalid }

- **Status:** 422
- **Title:** The policy is not valid
- **When:** The policy does not parse, does not validate against the users and nodes of the server, or fails its tests. Nothing was written; the policy in force stays.
- **`details`:**
    - `policyErrors`: one entry per problem, schema `PolicyError` (`{message, line, column}`); `line` and `column` count from 1, in bytes, and are `null` when the problem has no place in the text. A text that more than one user matches is a problem too, placed where the policy first names it
    - `policyErrorCount`: how many problems there are in all; `policyErrors` holds the first of them, up to a cap
    - `failedTests`: one entry per assertion that did not hold, schema `FailedTest` (`{kind, index, src, dst, user, want, got, line, column}`): `kind` is `acl` for `tests` and `ssh` for `sshTests`, `index` the position of the test in it from 0, `user` the login user of an `ssh` test and `null` for `acl`, `want` and `got` `accept`, `deny` or, for `ssh`, `check`, `line` and `column` where the policy text has the test
    - `failedTestCount`: how many assertions failed in all; `failedTests` holds the first of them, up to a cap
    - `testsNotRun`: how many entries of `tests` and `sshTests` were not run because the policy was refused before them; `0` when they ran, or when the text cannot be read far enough to count them

## policy_read_only { #policy_read_only }

- **Status:** 409
- **Title:** The policy is a file
- **When:** `PUT /policy` while the policy is read from a file. Edit the file; the server reloads it when it is saved. A dry run still checks the policy.
- **`details`:**
    - `path`: the policy file

## policy_source_changing { #policy_source_changing }

- **Status:** 409
- **Title:** The policy changed while it was read
- **When:** `POST /policy/reload` when the policy file, or the stored policy, changed between two reads that both worked, and the reload ran out of tries, as while something writes it. Nothing changed; the policy in force stays. Reload again.
- **`details`:** `{}`

## precondition_failed { #precondition_failed }

- **Status:** 412
- **Title:** The resource changed
- **When:** `If-Match` does not match: the resource changed since it was read, such as a node since its `revision` was read, or the policy since its `ETag` was. Nothing was written; read it again.
- **`details`:** `{}`

## registration_refused { #registration_refused }

- **Status:** 409
- **Title:** The registration cannot be made
- **When:** `register` of a machine whose registration the server refuses for what the machine sent. Nothing is made; the request still waits.
- **`details`:**
    - `reason`: `nodeKeyInUse`: another machine has the node key it sent, and no user makes it pass; `reportTooLarge`: the machine logs in again as a node the user has, and its report merged with that node's is over the limit; a register to a user with no node of this machine can pass. A client must accept a reason it does not know

## request_timeout { #request_timeout }

- **Status:** 408
- **Title:** The body did not arrive in time
- **When:** The request did not arrive in time.
- **`details`:** `{}`

## scope_requires_tags { #scope_requires_tags }

- **Status:** 422
- **Title:** The scopes need tags
- **When:** An OAuth client with a scope that makes tagged keys or nodes (`devices:core`, `auth_keys`), and no tags.
- **`details`:**
    - `scopes`: every scope of the request that needs tags

## tags_not_permitted { #tags_not_permitted }

- **Status:** 422
- **Title:** The tags are not in the policy
- **When:** Tags that are not in `tagOwners` of the policy; for `register`, tags the node asks for that its user may not give, and the request still waits.
- **`details`:**
    - `tags`: every tag of the request that the policy does not name, or that the user may not give

## tags_required { #tags_required }

- **Status:** 422
- **Title:** Tags are required
- **When:** An empty tag list where one is needed, such as the tags of a node.
- **`details`:** `{}`

## too_large { #too_large }

- **Status:** 413
- **Title:** The body is too large
- **When:** The body is over the limit of the operation.
- **`details`:** `{}`

## unauthorized { #unauthorized }

- **Status:** 401
- **Title:** The request has no valid credential
- **When:** No credential, or it is unknown, expired or revoked.
- **`details`:** `{}`

## unhealthy { #unhealthy }

- **Status:** 503
- **Title:** The server is not healthy
- **When:** A check of the server fails: `GET /health`, and any call whose credential cannot be checked because the database does not answer; also `POST /debug/nodes` when the server holds as many auth requests as it may.
- **`details`:**
    - `reasons`: one entry for each failed check, `{code, message, details}`; the codes are under [Reasons of unhealthy](#reasons)

## unsupported_media_type { #unsupported_media_type }

- **Status:** 415
- **Title:** The body is not JSON
- **When:** The body is not JSON.
- **`details`:** `{}`

## update_refused { #update_refused }

- **Status:** 409
- **Title:** The node did not start the update
- **When:** The node did not start an update of its Tailscale client.
- **`details`:**
    - `reason`: `notConnected`, `updatesNotAllowed`, `clientRefused` or `timeout`; a client must accept a reason it does not know
    - `clientError`: with `clientRefused`, the text the Tailscale client sent; `""` when it sent none

## user_changed { #user_changed }

- **Status:** 409
- **Title:** The user changed
- **When:** A delete of a user with `expect`, when a node or a key of the user came or went since the dry run. Nothing is removed; run the dry run again. `object` is the user.
- **`details`:** `{}`

## user_has_nodes { #user_has_nodes }

- **Status:** 409
- **Title:** The user still owns nodes
- **When:** A delete of a user that owns nodes, without `withNodes=true`. Nothing is removed. `object` is the user.
- **`details`:**
    - `nodes`: every node the user owns, `{id, name}`, in ID order

## user_managed_by_oidc { #user_managed_by_oidc }

- **Status:** 409
- **Title:** The identity provider owns this user
- **When:** A change to a user from OIDC, whose fields the identity provider owns. `object` is the user.
- **`details`:** `{}`

## Token rules { #rules }

The `rule` of a `forbidden` problem: what an OAuth access token may not do although its scopes allow it. An API key and the unix socket are not held by these rules. The OpenAPI document lists the rules of each operation under `x-token-rules`.

### token_cannot_approve_ssh_check { #token_cannot_approve_ssh_check }

An OAuth access token cannot approve an SSH check, whatever its scopes: the check is a person confirming who they are. It may reject one. Use an API key or the unix socket.

### token_cannot_change_user_name_or_email { #token_cannot_change_user_name_or_email }

An OAuth access token cannot change the name or the email of a user that exists, because a policy names a user by them. It can create a user, and change the display name and the picture. Use an API key.

### token_cannot_create_api_key { #token_cannot_create_api_key }

An OAuth access token cannot make an API key, whatever its scopes: an API key may do everything. Use an API key or the unix socket.

### token_cannot_create_key_for_user { #token_cannot_create_key_for_user }

An OAuth access token can make an auth key for tags only, never for a user (userId). Use an API key.

### token_cannot_register_node_to_user { #token_cannot_register_node_to_user }

An OAuth access token cannot register a node to a user, whatever its scopes. Use an API key or the unix socket.

### token_must_hold_scopes { #token_must_hold_scopes }

An OAuth access token can give a new OAuth client only scopes that its own scopes grant. GET /me lists them as authorization.scopes.

### token_must_own_tags { #token_must_own_tags }

An OAuth access token must hold, or own in the policy's tagOwners, every tag it gives: to a node, where it must also own every tag the node has now, and to an auth key or an OAuth client. GET /me lists these tags as authorization.tags. An API key may give any tag of the policy.

## Warnings of health { #warnings }

The `code` of each entry in `warnings` of `GET /health`. A client must accept one it does not know.

### node_expiry_invalid { #node_expiry_invalid }

Nodes hold a key expiry that is not valid. `details`: `count`, how many. The node object says which checks it fails.

### node_name_invalid { #node_name_invalid }

Nodes hold a name that is not valid. `details`: `count`, how many. The node object says which checks it fails.

### policy_file_invalid { #policy_file_invalid }

The policy file was refused when it was read last, at start-up or after it was saved; the last valid policy stays in force until a valid file is saved or reloaded. At start-up there is none before it: a file of zero bytes, or one that is not an object (such as `null`), is in force as no policy, which allows all, as it always was; a file of only white space stops the server; one with a NUL byte is in force as it always was. `POST /policy/reload` answers why. `details`: `{}`.

### policy_not_stored { #policy_not_stored }

The policy in force may not be the stored one, which a restart would install: a policy write failed and the stored policy could not be read to tell whether the write landed, or a read of the stored policy found another text than the one in force, byte for byte, that no other warning explains. It holds until a policy write or a reload succeeds, or a read finds the policy in force stored. `details`: `{}`.

### policy_stored_invalid { #policy_stored_invalid }

The stored policy was refused when it was read last, at start-up or by a reload, or a write of `/api/v1` or `/api/v2` stored a text that API v0 refuses: one that is not an object (such as `null`) is in force as no policy, which allows all; one with a NUL byte is in force as written; after a reload, the last valid policy stays in force. A policy write that succeeds ends it. `POST /policy/reload` answers why. `details`: `{}`.

### policy_user_ambiguous { #policy_user_ambiguous }

Texts of the policy in force, such as `alice@`, match more than one user, so each matches nobody. `details`: `count`, how many texts. A dry run of the policy in force names them.

## Reasons of unhealthy { #reasons }

The `code` of each entry in `details.reasons`. A client must accept one it does not know.

### auth_requests_full { #auth_requests_full }

The server holds as many waiting auth requests as it may.

### credential_check_busy { #credential_check_busy }

Every slot for checking an old-format credential hash stayed busy, so the credential was not checked.

### database_unreachable { #database_unreachable }

The database does not answer.
