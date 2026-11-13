# Tailscale SaaS API behaviour, captured 2026-11-12

Purpose: know what Tailscale's API really does, so that Headscale can mimic it
where that is sensible. The CLI and Headscale's own API (v0) come first; a
Tailscale behaviour is copied only where it does not hurt them.

Captured against the tscap test tailnet (`kratail2tid@passkey`), with the API
key that tscap uses. Probes that needed nodes joined disposable ones
with a local `tailscaled` in userspace mode. Every node and key that a probe
made was deleted by its ID. The tailnet had 0 devices before and after. No
policy was written: every `POST /acl` carried a wrong `If-Match`. Users and
settings were only read.

Raw output, with keys redacted, is in the `probe-*.txt` files next to this one.
They are transcripts of `curl` calls, not golden files in tscap's capture
format. No test reads them yet; they are kept so that tests can be written
from them.

The decisions that were made from these captures are in
`docs/proposals/002-api.md`, "Checked against the Tailscale API". The "v0"
columns below show what that proposal says.

Columns: **Tailscale** is what was captured. **Headscale `/api/v2`** is what
the code in this tree does, where I read it; "not checked" where I did not.
**v0 (002)** is what the API proposal says today.

## 1. Expire, and "key expiry disabled"

Files: `probe-B`, `probe-C`, `probe-D`.

| Device                                  | Call                                                 | Answer | Node afterwards            |
| --------------------------------------- | ---------------------------------------------------- | ------ | -------------------------- |
| user-owned, key expiry on (the default) | `POST /device/{id}/expire`                           | 200    | `NeedsLogin` within 15 s   |
| tagged (`keyExpiryDisabled: true`)      | `POST /device/{id}/expire`                           | 200    | still `Running` after 60 s |
| user-owned, `keyExpiryDisabled: true`   | `POST /device/{id}/expire`                           | 200    | still `Running` after 30 s |
| the tagged one, after the expire        | `POST /device/{id}/key {"keyExpiryDisabled": false}` | 200    | `NeedsLogin` within 12 s   |

Facts:

- A node that joins with a tagged auth key gets `keyExpiryDisabled: true`. The
  API still shows an `expires` time (join time plus the tailnet's key duration).
- A node that is tagged later through the API (`POST /device/{id}/tags`) keeps
  `keyExpiryDisabled: false`. So "tagged" and "key expiry disabled" are two
  separate things; only joining as tagged sets the flag.
- The expire call sets `expires` to the time of the call on every device. It
  logs the node out only when key expiry is enabled.
- An expired tagged node that runs `tailscale up` with no key gets a login URL.
  On Tailscale a person can log it in again.

**Why we think this may be wrong in Tailscale:**

1. **The documentation promises something else.** Tailscale's OpenAPI text for
   the call: "Mark a device's node key as expired. This will require the device
   to re-authenticate in order to connect to the tailnet." With key expiry
   disabled the device does not have to re-authenticate.
1. **A 200 for a call that had no effect.** The caller cannot tell that nothing
   happened. An admin who expires a compromised tagged server believes it is
   cut off, and it is not.
1. **The state afterwards contradicts itself.** `GET /device/{id}` shows
   `expires` in the past, `connectedToControl: true` and
   `keyExpiryDisabled: true` at the same time.
1. **The expire fires later, from another call.** When somebody enables key
   expiry on that device days later, it is logged out at once, because the old
   expire is still stored. The cause and the effect are far apart.

**Why it may be intended:** "key expiry disabled" could simply mean "ignore
`expires`", and the expire call only writes `expires`. Then the behaviour is
consistent, and only the documentation is incomplete.

**Headscale `/api/v2` today:** one stored field, an expiry time or none.
`keyExpiryDisabled` is "no expiry". `POST .../expire` sets the expiry to now
for every node, so a tagged node is logged out at once.
`POST .../key {"keyExpiryDisabled": false}` is a no-op. Both differ from
Tailscale.

**Not decided.** Kristoffer: "I'm not confident we should not do the same as
tailscale, lets document it and investigate it so we potentially can report it
if we think it is wrong." Then: "Document it, but properly, and include why we
think it might be wrong."

## 2. Auth keys

Files: `probe-A`, `probe-E`, `probe-F`, `probe-G`, `probe-J`.

| Case                                             | Tailscale                                                                           | Headscale `/api/v2`                            | v0 (002)                                   |
| ------------------------------------------------ | ----------------------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------ |
| tag not in `tagOwners`, admin API key            | 400 "requested tags [tag:x] are invalid or not permitted"                           | refused for OAuth callers only                 | **decided:** refuse, `tags_not_permitted`  |
| tag without `tag:` prefix                        | 400, the same message                                                               | not checked                                    | `invalid_field` or `tags_not_permitted`    |
| no `expirySeconds`, or `0`                       | 90 days                                                                             | 90 days                                        | expiry required; the CLI gives the default |
| `expirySeconds` over 90 days                     | 400 "expirySeconds must be less than or equal to 7776000"                           | the same cap                                   | **decided:** no cap                        |
| negative `expirySeconds`                         | 400 "expirySeconds must be greater than or equal to 0"                              | not checked                                    | `expiry_in_past`                           |
| defaults                                         | `reusable`, `ephemeral`, `preauthorized` all `false`                                | not checked                                    | the same                                   |
| description of 51 characters                     | 200, accepted                                                                       | `maxLength: 50`, refused                       | no limit stated                            |
| empty body                                       | 400 "exactly one capability scope must be populated"                                | not checked                                    | `invalid_field`                            |
| unknown field in the body                        | ignored, 200                                                                        | not checked                                    | refused (422)                              |
| bad JSON                                         | 400 "invalid JSON in request body"                                                  | not checked                                    | `invalid_request`                          |
| `keyType: "api"`                                 | 400 "invalid key type, "api" is not supported"                                      | not checked                                    | API keys are their own resource            |
| a tagged key                                     | has a `userId`: the user whose API key made it                                      | not checked                                    | `createdBy`                                |
| `DELETE` a key (unused, or in use, or ephemeral) | 200. A soft revoke: `GET` by ID still returns it with `revoked` and `invalid: true` | the same (soft revoke, reaped after 168 h)     | one operation, a soft delete               |
| `DELETE` it again                                | 200                                                                                 | 200                                            | 204 again                                  |
| a node that joined with the deleted key          | keeps running; stays ephemeral                                                      | keeps running                                  | keeps running                              |
| a single-use key after a node used it            | `invalid: true` and `revoked` set to the time of use                                | a `used` flag                                  | state `used`                               |
| a key past its expiry                            | `invalid: true`, `revoked: null`                                                    | not checked                                    | state `expired`                            |
| the key list                                     | hides revoked, used and expired keys; entries have no `capabilities`                | hides them too                                 | lists every key, with `state`              |
| an unknown key ID                                | `GET` 404 "not found"; `DELETE` 404 "key not found"                                 | 404                                            | `not_found`                                |
| revoked keys, 15 minutes later                   | still readable by ID. How long they stay was not measured.                          | deleted after `preauth_keys.revoked_retention` | the same retention                         |

## 3. OAuth clients

File: `probe-G`.

| Case                              | Tailscale                                                                           | Headscale `/api/v2`                    | v0 (002)                 |
| --------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------- | ------------------------ |
| create with a read scope, no tags | 200; `expires: null`; has a `userId`                                                | allowed                                | allowed                  |
| a scope that needs tags, no tags  | 400 "OAuth clients with auth key write scope must specify one or more tags"         | refused                                | `scope_requires_tags`    |
| unknown scope                     | 400 `invalid scopes: ["devices:cor"]`                                               | not checked                            | `invalid_scope`          |
| no scopes                         | 400 "scopes cannot be empty, at least one scope is required for OAuth clients"      | not checked                            | `invalid_field`          |
| in the key list                   | only with `?all=true`                                                               | the same                               | its own resource         |
| `DELETE`                          | 200. A soft revoke: `GET` by ID still returns it with `revoked` and `invalid: true` | a hard delete, with its tokens         | a soft delete            |
| `DELETE` again                    | 200                                                                                 | not checked                            | 204                      |
| a token deletes its own client    | 200 `null`; the next call with that token is 401 "API token invalid" (`probe-Q`)    | tokens of a deleted client are refused | 204, then `unauthorized` |

## 4. Devices

File: `probe-J`. The `lastSeen` values are in `probe-B`.

| Case                                       | Tailscale                                                                                                                                                                                 | Headscale `/api/v2`                  | v0 (002)                                    |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------------- |
| ID in the path                             | the numeric `id` and the `nodeId` both work                                                                                                                                               | one ID                               | one ID                                      |
| `user` of a tagged device                  | the user whose key made the auth key                                                                                                                                                      | the same                             | `owner.user` is `null`; `createdBy` is open |
| rename                                     | 200                                                                                                                                                                                       | 200                                  | `PATCH`, returns the node                   |
| rename to a name another device has        | 400 `name "x" is already taken`                                                                                                                                                           | not checked                          | `name_taken`                                |
| rename to `""`                             | 200; the name goes back to the one made from the hostname                                                                                                                                 | not checked                          | the same: the name is reset                 |
| rename to `"Bad Name!"`                    | 200; the resulting name was not recorded                                                                                                                                                  | not checked                          | `invalid_field`                             |
| tags `[]` on a tagged device               | 400 "tagged nodes cannot be untagged without reauth"                                                                                                                                      | accepted as "no change"              | `tags_required`                             |
| a tag that is not in the policy            | 400 "requested tags [...] are invalid or not permitted"                                                                                                                                   | refused                              | `tags_not_permitted`                        |
| tag a user-owned device                    | 200; `user` stays; `keyExpiryDisabled` stays `false`                                                                                                                                      | 200; the expiry stays                | 200; the owner becomes the tags             |
| enable one exit prefix (`0.0.0.0/0`)       | only that one is enabled; `::/0` is not                                                                                                                                                   | not checked                          | "one exit prefix approves both"             |
| enable a route the node does not advertise | 200; it is stored as enabled                                                                                                                                                              | not checked                          | not stated                                  |
| a route that is not a prefix               | 400 `"not-a-route" is not a valid IP address or CIDR prefix`                                                                                                                              | not checked                          | `invalid_field`                             |
| routes `[]`                                | 200; clears                                                                                                                                                                               | clears                               | clears                                      |
| `authorized: false`                        | 200; the device is deauthorized, also with device approval off                                                                                                                            | refused (400)                        | reserved, not built                         |
| attributes                                 | `ip:country`, `ip:publicAddress` (`{"type": "IpAddr", "value": ...}`), `node:os`, `node:osVersion`, `node:tsAutoUpdate`, `node:tsReleaseTrack`, `node:tsStateEncrypted`, `node:tsVersion` | only `ip:publicAddress`, as a string | `attributes`, a map; today one entry        |
| `lastSeen` of a connected device           | the current time                                                                                                                                                                          | the current time                     | **decided:** the current time               |
| `updateAvailable`                          | `true` for an old client                                                                                                                                                                  | always `false`                       | no such field                               |
| unknown field in a body                    | ignored, 200                                                                                                                                                                              | ignored                              | refused (422)                               |
| `DELETE`                                   | 200                                                                                                                                                                                       | 200                                  | 204                                         |
| `GET` or `DELETE` a deleted device         | 404 "no manageable device matching this ID found"                                                                                                                                         | 404                                  | `not_found`                                 |

## 5. Policy

File: `probe-KLM`. Nothing was written.

| Case                                | Tailscale                                                                                                            | v0 (002)                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `GET /acl`                          | HuJSON by default; JSON with `Accept: application/json`; an `ETag` header                                            | JSON with the policy as a string; ETag |
| `GET /acl?details=1`                | `{acl, errors, warnings}`                                                                                            | none                                   |
| `POST /acl` with a wrong `If-Match` | 412 "precondition failed, invalid old hash"; checked before the policy is read                                       | 412 `precondition_failed`              |
| validate: a valid policy            | 200 `{}`                                                                                                             | 200 with the policy (dry run)          |
| validate: bad syntax                | **200** `{"message": "line 1, column 11: parsing value: unexpected EOF"}`                                            | 422 `policy_invalid`                   |
| validate: an unknown tag            | **200** `{"message": "src=tag not found: \"tag:nope\""}`                                                             | 422 `policy_invalid`                   |
| validate: a failing test            | **200** `{"message": "test(s) failed", "data": [{"user": "tag:server", "errors": ["... want: Accept, got: Drop"]}]}` | 422 `policy_invalid`, `failedTests`    |

Tailscale answers 200 for an invalid policy in validate, and the body says it
is invalid. A client must read the body to know. v0 uses the status.

## 6. Users and settings (read only)

File: `probe-KLM`.

- A user has `id`, `displayName`, `loginName`, `profilePicUrl`, `tailnetId`,
  `created`, `type`, `role`, `status`, `lastSeen`. There is no separate email
  and no username; `loginName` is the one name. **Decided for v0:** `name` as
  stored, plus a read-only `loginName`.
- `GET /users/{id}` for an unknown ID: 404 `{"message": "404 page not found"}`.
- `?type=bogus`: 400 `invalid type "bogus"`.

## 7. Errors and strictness

File: `probe-G`.

| Case                    | Tailscale                                                                    | v0 (002)                 |
| ----------------------- | ---------------------------------------------------------------------------- | ------------------------ |
| error body              | `{"message": "..."}`; no code                                                | a problem with a `code`  |
| no or wrong credential  | 401 "API token invalid"                                                      | `unauthorized`           |
| unknown device          | 404 "no manageable device matching this ID found"                            | `not_found`              |
| unknown query parameter | ignored, 200                                                                 | refused (422)            |
| `fields=bogus`          | 400 `"bogus" is not a valid fields parameter`                                | no `fields` parameter    |
| wrong method            | 405 `{"error": "method_not_allowed", "message": "..."}` (another body shape) | `method_not_allowed`     |
| unknown path            | 404, plain text "404 page not found"                                         | a problem                |
| another tailnet's name  | 404 `tailnet "example.invalid" not found`                                    | no tailnet in the path   |
| request ID              | header `x-tailscale-request-id`                                              | `requestId` in a problem |

## 8. Where Headscale's `/api/v2` differs from Tailscale

These are outside both proposals. `/api/v2` exists to answer as Tailscale does,
so each is a candidate for an issue.

1. `POST /device/{id}/expire` logs out a node whose key expiry is disabled.
   Tailscale does not. (See section 1; which side is right is open.)
1. `POST /device/{id}/key {"keyExpiryDisabled": false}` is a no-op. On
   Tailscale it turns key expiry on.
1. A key description is limited to 50 characters. Tailscale accepted 51.
1. `POST /device/{id}/tags` with `[]` is accepted as "no change". Tailscale
   answers 400 "tagged nodes cannot be untagged without reauth".
1. Deleting an OAuth client is a hard delete. On Tailscale it is a soft revoke,
   and the client can still be read by its ID.
1. An auth key with a tag that is not in the policy is accepted from an API
   key. Tailscale refuses it for every caller.
1. `POST /device/{id}/authorized {"authorized": false}` is refused. Tailscale
   accepts it.
1. Attributes: only `ip:publicAddress`, and as a plain string. Tailscale sends
   an object `{"type": "IpAddr", "value": ...}` and the `node:` attributes.

Not checked in Headscale: a route that is not advertised, rename to `""`.

## 9. One exit prefix

Files: `probe-N-one-exit-prefix.txt` (the node's own view only),
`probe-P-one-exit-prefix-peer-view.txt` (two nodes, with an accept-all policy),
and the two tscap captures
`hscontrol/policy/v2/testdata/routes_results/hsprobe-exit-v4-only.hujson` and
`hsprobe-exit-v6-only.hujson`.

A node that advertises both exit routes. Routes were enabled with
`POST /device/{id}/routes`.

| Enabled through the API | API reports `enabledRoutes` | The exit node's own view      | Another node receives | Usable as exit node |
| ----------------------- | --------------------------- | ----------------------------- | --------------------- | ------------------- |
| nothing                 | `[]`                        | no exit route                 | no exit route         | no                  |
| `0.0.0.0/0` only        | `["0.0.0.0/0"]`             | both routes, `ExitNodeOption` | **no exit route**     | **no**              |
| `::/0` only             | `["::/0"]`                  | `::/0` only                   | **no exit route**     | **no**              |
| both                    | both                        | both, `ExitNodeOption`        | both routes           | yes                 |

- **On Tailscale a node is an exit node for others only when both routes are
  enabled.** With one of them, other nodes receive neither route, and
  `tailscale exit-node list` does not show the node.
- The exit node's own view is misleading: with only `0.0.0.0/0` enabled it
  shows both routes and `ExitNodeOption: true`. My first probe looked only at
  that view and drew the wrong conclusion. The peer view is the one that counts.
- The Tailscale client offers a peer as an exit node only when the peer's
  allowed IPs hold both routes (`tsaddr.ContainsExitRoutes`, used for
  `ExitNodeOption` in `ipn/ipnlocal/local.go`).
- **The policy cannot approve an exit route through `autoApprovers.routes`.**
  Two tscap scenarios (`hsprobe-exit-v4-only`, `hsprobe-exit-v6-only`, full
  12-node topology) listed one exit prefix there for `tag:exit`: the admin API
  reported no approved exit route, and no node received one. The existing
  capture `routes-d6-exit-node-auto-approval` lists both prefixes there and
  shows the same. Exit nodes are auto-approved with `autoApprovers.exitNode`.
- Headscale, in `/api/v1` and in `/api/v2` (`parseRoutes`): either exit prefix
  is stored as both, the API reports both, and the node works as an exit node.
  That differs from Tailscale, where one prefix gives no exit node.

**Decided for v0:** either exit prefix approves both, and the API reports both.
The difference to Tailscale is documented in 002.

## 10. How a key ends: the soft delete, and when it is cleaned up

Kristoffer: "Investigate a path and what we need to implement to do the same
as tailscale", and: "I think all will behave in the same way, and we need to
understand how the soft delete work and when or how it is cleaned up."

### Tailscale

Captured (`probe-E`, `probe-F`, `probe-G`, `probe-J`):

| Kind         | `DELETE`              | `GET` by ID afterwards                  | In the list afterwards | `DELETE` again |
| ------------ | --------------------- | --------------------------------------- | ---------------------- | -------------- |
| auth key     | 200                   | 200, with `revoked` and `invalid: true` | no                     | 200            |
| OAuth client | 200                   | 200, with `revoked` and `invalid: true` | not checked            | 200            |
| API key      | not tested, see below |                                         |                        |                |

- Auth keys and OAuth clients behave the same: `DELETE` is a soft revoke.
- A single-use auth key is revoked by Tailscale itself when a node uses it: it
  then has `invalid: true` and a `revoked` time equal to the time of use.
  Tailscale's docs say the same: "Tailscale automatically revokes one-off keys
  after they are used."
- An expired key has `invalid: true` and `revoked: null`.
- The list shows only keys that work. Revoked, used and expired keys are not in
  it.
- A node that joined with a key is not touched when the key is revoked. Docs:
  "Revoking a key does not deauthorize nodes using the key."
- **The word.** The API method is `DELETE`. Tailscale's admin console and docs
  call the action "Revoke".
- **API keys were not tested.** The API cannot create one
  (`"api" is not supported`), and the only API keys in the test tailnet are the
  three real ones that tscap uses. I did not delete one of those.

**When Tailscale cleans up: not known.**

- Keys revoked at 18:10 UTC were still readable by ID at 20:01 UTC. That
  read was made by hand and is not in a recording.
- The docs say only: "You can find recently revoked or expired keys on the Keys
  page of the admin console." No time is given.
- To measure it, read these IDs again later: `kyBWL6oKa511CNTRL` (auth key,
  revoked 2026-11-12 18:10 UTC), `kLMGJaDJ8p11CNTRL` (auth key, 18:21),
  `kiJueGvH4521CNTRL` (OAuth client, 18:39).

### Headscale today

| Kind         | Soft revoke                                            | Clean-up         |
| ------------ | ------------------------------------------------------ | ---------------- |
| auth key     | yes: `db.RevokePreAuthKey`, used by `/api/v2` `DELETE` | a job, see below |
| OAuth client | no: `DELETE` removes the client and its tokens at once | none needed      |
| API key      | no: "expire" sets the expiry to now; delete removes it | none             |

How the soft revoke of an auth key works:

- It stores a revoke time. A repeated revoke keeps the first time and succeeds.
- The key no longer registers nodes. It can still be read by its ID through
  `/api/v2`. Both lists hide it.
- A background job runs every hour. It hard-deletes every auth key that was
  revoked longer ago than `preauth_keys.revoked_retention` (168 hours by
  default).
- **The job skips a key that a node still refers to.** Such a key stays until
  the node is deleted.
- A retention of zero or less turns the job off. Revoked keys then stay for
  ever.
- A single-use key that was used is not revoked; it has a `used` flag.
- `/api/v1` has a hard delete (`db.DestroyPreAuthKey`). It has one exception:
  an ephemeral key that a node still uses is revoked instead.
- The `credentials` table holds all three kinds and has a `revoked` column.
  `OAuthClient.Revoked` exists in the type and is never set.

### What "the same as Tailscale" needs in v0

- `DELETE /auth-keys/{id}`: call the soft revoke that exists. Answer the same
  when repeated.
- `DELETE /oauth-clients/{id}`: new. Set the revoke time, refuse the client's
  tokens from then on, keep the record readable, and let the job remove it.
- `DELETE /api-keys/{id}`: new. Set the revoke time and refuse the key.
- The job: extend it from auth keys to all three kinds. One retention setting.
- No hard delete in the API. The ephemeral exception can no longer be reached.
- v0's lists show every key with its `state`, so a revoked key is visible until
  the job removes it. That is more than Tailscale's list shows; it is what the
  CLI's `--all` needs.
  **Decided for v0:** auth keys, API keys and OAuth clients end with one
  operation, `DELETE`, a soft delete. The CLI verb is `delete`. Headscale's
  clean-up rule applies to all three kinds. A used single-use key keeps its own
  state, `used`.
