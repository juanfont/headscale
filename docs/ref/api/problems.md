# API v0 problem codes

!!! note "Generated page"

    This page is generated from the list of codes in `hscontrol/api/headscale/v0/problem.go` by
    `go run ./cmd/gen-openapi -api headscale/v0`. Edit the list there, not this page.

Every error of `/api/headscale/v0` is a problem (RFC 9457). A program reads its `code`; the
`type` of the problem leads to the heading of that code here. `details` holds the data of the
code, and is `{}` when the code has none.

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
- **When:** A field or parameter is unknown, or has a value that is not allowed. `errors` names each one.
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

## request_timeout { #request_timeout }

- **Status:** 408
- **Title:** The body did not arrive in time
- **When:** The request did not arrive in time.
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
- **When:** A check of the server fails: `GET /health`, and any call whose credential cannot be checked because the database does not answer.
- **`details`:**
    - `reasons`: one entry for each failed check, `{code, message, details}`; the codes are under [Reasons of unhealthy](#reasons)

## unsupported_media_type { #unsupported_media_type }

- **Status:** 415
- **Title:** The body is not JSON
- **When:** The body is not JSON.
- **`details`:** `{}`

## user_managed_by_oidc { #user_managed_by_oidc }

- **Status:** 409
- **Title:** The identity provider owns this user
- **When:** A change to a user from OIDC, whose fields the identity provider owns. `object` is the user.
- **`details`:** `{}`

## Token rules { #rules }

The `rule` of a `forbidden` problem: what an OAuth access token may not do although its scopes allow it. An API key and the unix socket are not held by these rules. The OpenAPI document lists the rules of each operation under `x-token-rules`.

### token_cannot_change_user_name_or_email { #token_cannot_change_user_name_or_email }

An OAuth access token cannot change the name or the email of a user that exists, because a policy names a user by them. It can create a user, and change the display name and the picture. Use an API key.

## Reasons of unhealthy { #reasons }

The `code` of each entry in `details.reasons`. A client must accept one it does not know.

### credential_check_busy { #credential_check_busy }

Every slot for checking an old-format credential hash stayed busy, so the credential was not checked.

### database_unreachable { #database_unreachable }

The database does not answer.
