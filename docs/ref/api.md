# API

Headscale provides a [HTTP REST API](#rest-api) which may be used to integrate a [web
interface](integration/web-ui.md), [remote control Headscale](#remote-control) or provide a base for custom
integration and tooling.

The API requires a valid API key before use. To create an API key, log into your Headscale server and generate
one:

```shell
headscale api keys create
```

Copy the output of the command and save it for later. Please note that you can not retrieve an API key again. If the API
key is lost, delete the old one, and create a new one.

To list the API keys currently associated with the server:

```shell
headscale api keys list
```

and to delete an API key, which stops it working at once:

```shell
headscale api keys delete <PREFIX>
```

## REST API

- API endpoint: `/api/headscale/v0`, e.g. `https://headscale.example.com/api/headscale/v0`
- Documentation: `/api/headscale/v0/docs`, e.g. `https://headscale.example.com/api/headscale/v0/docs`, and the
  [OpenAPI document](api/headscale-v0.yaml) of this release
- Errors: every error is a problem (RFC 9457) with a stable `code`, listed under [problem codes](api/problems.md)
- Headscale Version: `/version`, e.g. `https://headscale.example.com/version`
- Authenticate using HTTP Bearer authentication by sending the [API key](#api) with the HTTP `Authorization: Bearer <API_KEY>` header.

API v0 may change in any minor release; every change is in the changelog under "API v0", and a patch release does not
break it. The legacy API at `/api/v1` is deprecated and removed in Headscale 0.33: see
[Migrate from /api/v1](#migrate-from-apiv1).

Start by [creating an API key](#api) and test it with the examples below. Read the API documentation provided by your
Headscale server at `/api/headscale/v0/docs` for details.

=== "List users"

    ```console
    curl -H "Authorization: Bearer <API_KEY>" \
        https://headscale.example.com/api/headscale/v0/users
    ```

    This is the first page. When the answer has `nextPageToken`, send it back as `?pageToken=` for the next one.

=== "Get details for user 'bob'"

    ```console
    curl -H "Authorization: Bearer <API_KEY>" \
        "https://headscale.example.com/api/headscale/v0/users?name=bob"
    ```

=== "Register a node"

    ```console
    curl -H "Authorization: Bearer <API_KEY>" \
        --json '{"userId": "<USER_ID>"}' \
        "https://headscale.example.com/api/headscale/v0/auth-requests/<AUTH_ID>/register"
    ```

## Migrate from /api/v1

The legacy API at `/api/v1` is frozen: it gets no new operation and no new field until it is removed.

| Release    | `/api/v1`                                                                        |
| ---------- | -------------------------------------------------------------------------------- |
| 0.30       | works; every operation is marked deprecated and every answer carries the headers |
| 0.31, 0.32 | the same, and fully frozen: no new operation and no new field, only fixes        |
| 0.33       | removed                                                                          |

How a client of `/api/v1` learns it:

- Its OpenAPI document, at `/api/v1/openapi.yaml`, marks every operation `deprecated`; a client generated from it
  shows the mark.
- Every answer to a path under `/api/v1`, an error or a `404` too, carries `Deprecation`
  ([RFC 9745](https://www.rfc-editor.org/rfc/rfc9745)) and a `Link` to this guide. It carries no `Sunset`
  ([RFC 8594](https://www.rfc-editor.org/rfc/rfc8594)) until 0.33 has a date. A web UI that calls it cross-origin from the browser
  reads them only when its reverse proxy exposes them; Headscale sends no CORS headers for `/api/v1`.
- The server logs one warning the first time a client calls an operation of `/api/v1` after each start, with the
  operation and the client's address.

### What changes for every client

- **Every list is paged.** Every `GET` of a collection (`/nodes`, `/users`, `/auth-keys`, `/api-keys`,
  `/oauth-clients`, `/tags`) answers one page. Follow `nextPageToken`, sent back as `pageToken`, until it is missing.
- **IDs, not names.** Every path, body and filter names a user by its ID (the `user` filters, `userId`); find the ID
  with `GET /users?name=`.
- **`name` of a node changes meaning.** In `/api/v1` `name` is the hostname and `givenName` the name; in v0 `name` is
  the name and `hostname` the hostname. Code that reads `name` still runs and shows the other value.
- **Status codes.** `/api/v1` answered `200` to every success. In v0 a `POST` that makes something answers `201`:
  `/users`, `/auth-keys`, `/api-keys`, `/oauth-clients`, `/auth-requests/{id}/register` (the node) and `/debug/nodes`
  (the auth request). `DELETE` of a node, an auth key, an API key or an OAuth client, and `approve` and `reject` of an
  auth request, answer `204` with no body. `DELETE /users/{id}` answers `200` with what was removed, or with
  `dryRun=true` what would be. Every other success is `200` with a body.
- **Errors.** Every error, a path no operation has too, is a problem (`application/problem+json`): the text is
  `detail`, and `code` is a string such as `name_taken`, listed under [problem codes](api/problems.md).
- **Values.** Enums are short words (`cli`, not `REGISTER_METHOD_CLI`); a time that is not set is `null`, never the
  year 1.
- **Keys need an expiry.** A new auth key or API key without `expiry` is refused with `expiry_required`. An OAuth
  client has no expiry.
- **Owner.** A node and an auth key have `owner`: one user, or tags (then `user` is `null`). A tagged auth key is made
  with `tags` and no `userId`. An API key's `owner` is the user recorded on it, or `null`; its `tags` is always `[]`,
  and the owner does not limit what the key may do.
- **A delete of a key revokes it.** `DELETE` of an auth key, an API key or an OAuth client refuses the credential at
  once, and the record stays readable with `state` `revoked`. Read `removal` for when the server removes it: a time,
  or `null` when it is kept for ever (`credentials.revoked_retention` is zero or less, or a node still refers to the
  auth key). `/api/v1` removed the record of a deleted key at once.
- **CORS.** v0 answers CORS itself for the origins in `api.cors.allowed_origins`. A reverse proxy that answers CORS in
  its place must allow `PATCH` and `PUT`.

### Each call

Paths are relative to `/api/v1` and `/api/headscale/v0`.

| `/api/v1`                              | API v0                                         | What changes                                                                                    |
| -------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `GET /node`                            | `GET /nodes`                                   | paged; `user` filter takes an ID; an unknown user gives `{"nodes": []}`, not `404`              |
| `GET /node/{nodeId}`                   | `GET /nodes/{id}`                              | the same object as in the list                                                                  |
| `DELETE /node/{nodeId}`                | `DELETE /nodes/{id}`                           | `204`                                                                                           |
| `POST /node/{nodeId}/expire`           | `POST /nodes/{id}/expire`, `PATCH /nodes/{id}` | now is the action, or `"expiry": "now"`; a future time, or `null` for never, is `expiry`        |
| `POST /node/{nodeId}/rename/{newName}` | `PATCH /nodes/{id}`                            | the name is in the body, as `name`                                                              |
| `POST /node/{nodeId}/tags`             | `PUT /nodes/{id}/tags`                         |                                                                                                 |
| `POST /node/{nodeId}/approve_routes`   | `PUT /nodes/{id}/routes`                       |                                                                                                 |
| `POST /node/register`                  | `POST /auth-requests/{id}/register`            | takes a user ID; `201` with the node                                                            |
| `POST /node/backfillips`               | none                                           | works until 0.33 removes `/api/v1`                                                              |
| `POST /debug/node`                     | `POST /debug/nodes`                            | takes no user; `201` with the auth request it made, not a node                                  |
| `GET /user`                            | `GET /users`, `GET /users/{id}`                | paged; filters combine; a get by ID exists                                                      |
| `POST /user`                           | `POST /users`                                  | `201`; `name` is required                                                                       |
| `POST /user/{oldId}/rename/{newName}`  | `PATCH /users/{id}`                            | also display name, email and picture                                                            |
| `DELETE /user/{id}`                    | `DELETE /users/{id}`                           | `withNodes`, `dryRun` and `expect`; `200` with what was removed, not `204`                      |
| `GET /preauthkey`                      | `GET /auth-keys`, `GET /auth-keys/{id}`        | paged; revoked keys are listed until removed; `state`; plain `prefix`                           |
| `POST /preauthkey`                     | `POST /auth-keys`                              | `userId` or `tags`; `expiry` required; `description`                                            |
| `POST /preauthkey/expire`              | `DELETE /auth-keys/{id}`                       | the ID is in the path; revokes at once; the state is `revoked`, not `expired`                   |
| `DELETE /preauthkey?id=`               | `DELETE /auth-keys/{id}`                       | the ID is in the path; revokes at once and keeps the record; see `removal`                      |
| `GET /apikey`                          | `GET /api-keys`, `GET /api-keys/{id}`          | paged; `owner`, `state`, plain `prefix`                                                         |
| `POST /apikey`                         | `POST /api-keys`                               | answers with the whole key; `userId`; `expiry` required                                         |
| `POST /apikey/expire`                  | `DELETE /api-keys/{id}`                        | by ID only; revokes at once; the state is `revoked`                                             |
| `DELETE /apikey/{prefix}`              | `DELETE /api-keys/{id}`                        | by ID only; revokes at once and keeps the record; see `removal`                                 |
| `POST /auth/register`                  | `POST /auth-requests/{id}/register`            | takes a user ID, not a username                                                                 |
| `POST /auth/approve`                   | `POST /auth-requests/{id}/approve`             | SSH checks only; a registration is `register`ed or `reject`ed (`auth_request_kind`); `204`      |
| `POST /auth/reject`                    | `POST /auth-requests/{id}/reject`              | `204`                                                                                           |
| `GET /policy`                          | `GET /policy`                                  | `mode`, `path` and an `ETag`; `updated`, `null` in file mode; no `500` when no policy is stored |
| `PUT /policy`                          | `PUT /policy`                                  | `If-Match`; `dryRun`; each error has its line and column where it has a place in the text       |
| `POST /policy/check`                   | `PUT /policy?dryRun=true`                      |                                                                                                 |
| `GET /config`                          | `GET /config`                                  | a token needs `all`, as an API key has                                                          |
| `GET /health`                          | `GET /health`                                  | `503` with reasons; `warnings`                                                                  |

### Examples

=== "Rename a node"

    ```console
    # before
    curl -X POST -H "Authorization: Bearer <API_KEY>" \
        https://headscale.example.com/api/v1/node/12/rename/web-1
    # after
    curl -X PATCH -H "Authorization: Bearer <API_KEY>" --json '{"name": "web-1"}' \
        https://headscale.example.com/api/headscale/v0/nodes/12
    ```

=== "Disable a node's key expiry"

    ```console
    # before
    curl -H "Authorization: Bearer <API_KEY>" --json '{"disableExpiry": true}' \
        "https://headscale.example.com/api/v1/node/12/expire?disableExpiry=true"
    # after
    curl -X PATCH -H "Authorization: Bearer <API_KEY>" --json '{"expiry": null}' \
        https://headscale.example.com/api/headscale/v0/nodes/12
    ```

    The "before" sends `disableExpiry` in the query and in the body because 0.29 reads only the query and some 0.30
    builds read only the body; a `/api/v1` expire that finds the field in neither expires the node now. In v0 the call
    without a body is `POST /nodes/{id}/expire`, which expires it now.

=== "Create an auth key"

    ```console
    # before
    curl -H "Authorization: Bearer <API_KEY>" \
        --json '{"user": "3", "reusable": true, "expiration": "2030-01-01T00:00:00Z"}' \
        https://headscale.example.com/api/v1/preauthkey
    # after
    curl -H "Authorization: Bearer <API_KEY>" \
        --json '{"userId": "3", "reusable": true, "expiry": "2030-01-01T00:00:00Z"}' \
        https://headscale.example.com/api/headscale/v0/auth-keys
    ```

## Join nodes with an OAuth client

Headscale also serves a subset of the Tailscale-compatible API at `/api/v2`, which
accepts **OAuth 2.0 client-credentials** in addition to API keys. The Tailscale
client can use an OAuth client secret in place of an auth key: it exchanges the
secret for an access token, mints a single-use tagged auth key and registers with
it. This works anywhere the client takes an auth key: `tailscale up`, the
container image, `tsnet` and the
[`tailscale/github-action`](https://github.com/tailscale/github-action). One
long-lived secret joins any number of nodes. A client keeps its newest 1000
access tokens and minting more ends the oldest, so give a long-lived integration
its own client.

Create an OAuth client with the `auth_keys` scope and the tags its nodes get.
Each tag must exist in the policy's `tagOwners`, or the create fails. The secret
is shown once:

```shell
headscale api oauth-clients create auth_keys --tags tag:ci
```

Scopes apply to the whole tailnet, as in Tailscale: an `auth_keys` token can read
and revoke auth keys of any tag, an `oauth_keys` token every OAuth client, and a
`devices:core:read` token reads every device, routes included with `fields=all`.
Keep the secret as safe as any credential that can revoke keys. Without
`all=true`, a token lists only the auth keys made through a token, whatever their
tags; with it, every valid auth key. An admin API key lists OAuth clients only
with `all=true`. No listing holds a
spent, expired or revoked key. Tags limit only the tags a token puts on keys, clients and devices, and
which tagged devices it may retag. Deleting an OAuth client revokes its secret
and its access tokens; auth keys, clients and nodes created with it stay until
you remove them.

Build the auth key from the secret:

1. Swap the prefix: `hskey-client-…` becomes `tskey-client-…`. The client only
   runs the exchange for `tskey-client-`; Headscale accepts both.
1. Append `?baseURL=<your Headscale URL>`.
1. Set `--advertise-tags`. Each tag must be one of the OAuth client's tags, or
   owned by one of them.

```text
tskey-client-<id>-<secret>?baseURL=https://headscale.example.com
```

!!! warning

    Without `baseURL` the client sends the secret to `https://api.tailscale.com`.

### Attributes

These are all the attributes the client understands; any other is an error.
Order does not matter and an empty value means the default.

| Attribute       | Default                     | Effect                                                                                           |
| --------------- | --------------------------- | ------------------------------------------------------------------------------------------------ |
| `baseURL`       | `https://api.tailscale.com` | Where the exchange and key creation go. Your Headscale URL, no trailing slash.                   |
| `ephemeral`     | `true`                      | Node is removed after it goes offline (`node.ephemeral.inactivity_timeout`). `false` to keep it. |
| `preauthorized` | `false`                     | Accepted, no effect: Headscale always authorizes pre-auth-key nodes.                             |

Booleans take any Go `strconv.ParseBool` value (`true`, `false`, `1`, `0`, …).

### Examples

`tailscale up`, either as the auth key or via `--client-secret` (which also takes
`file:/path/to/secret`):

```shell
tailscale up --login-server https://headscale.example.com --advertise-tags tag:ci \
  --auth-key 'tskey-client-<id>-<secret>?baseURL=https://headscale.example.com&ephemeral=false'
```

Container image:

```shell
docker run -d --name tailscale \
  -e TS_AUTHKEY='tskey-client-<id>-<secret>?baseURL=https://headscale.example.com' \
  -e TS_EXTRA_ARGS='--login-server=https://headscale.example.com --advertise-tags=tag:ci' \
  tailscale/tailscale
```

`tsnet` (`TS_CLIENT_SECRET` works too); import `tailscale.com/feature/oauthkey`:

```go
srv := &tsnet.Server{
    ControlURL:    "https://headscale.example.com",
    AuthKey:       "tskey-client-<id>-<secret>?baseURL=https://headscale.example.com",
    AdvertiseTags: []string{"tag:ci"},
}
```

GitHub Action, with the whole string stored as a repository secret:

{% raw %}

```yaml
- uses: tailscale/github-action@v4
  with:
    authkey: ${{ secrets.HEADSCALE_AUTHKEY }}
    args: --login-server=https://headscale.example.com --advertise-tags=tag:ci
```

{% endraw %}

Use `authkey` even though upstream marks it deprecated: `oauth-secret` appends its
own `?…` to the secret, which corrupts `baseURL`.

## Remote control

The `headscale` binary can control a Headscale instance from a remote machine over the HTTP API.

### Prerequisite

- A workstation to run `headscale` (any supported platform, e.g. Linux).
- The Headscale server reachable over HTTP(S).
- An [API key](#api) to authenticate with the Headscale server.

### Setup remote control

1. Download the [`headscale` binary from GitHub's release page](https://github.com/juanfont/headscale/releases). Make
   sure to use the same version as on the server.

1. Put the binary somewhere in your `PATH`, e.g. `/usr/local/bin/headscale`

1. Make `headscale` executable: `chmod +x /usr/local/bin/headscale`

1. [Create an API key](#api) on the Headscale server.

1. Provide the connection parameters for the remote Headscale server either via a minimal YAML configuration file or
   via environment variables:

    === "Minimal YAML configuration file"

        ```yaml title="config.yaml"
        cli:
            address: <HEADSCALE_URL>
            api_key: <API_KEY>
        ```

    === "Environment variables"

        ```shell
        export HEADSCALE_CLI_ADDRESS="<HEADSCALE_URL>"
        export HEADSCALE_CLI_API_KEY="<API_KEY>"
        ```

    This instructs the `headscale` binary to connect to a remote instance at `<HEADSCALE_URL>` (e.g.
    `https://headscale.example.com`), instead of connecting to the local instance. A bare host without a scheme is
    assumed to be `https`.

1. Test the connection by listing all nodes:

    ```shell
    headscale nodes list
    ```

    You should now be able to see a list of your nodes from your workstation, and you can
    now control the Headscale server from your workstation.

### Behind a proxy

The remote CLI uses the same HTTP API as everything else, so it works through the reverse proxy already in front of
Headscale with no extra setup.

### Troubleshooting

- Make sure you have the _same_ Headscale version on your server and workstation: the CLI refuses a server of
  another major or minor version.
- Verify that your TLS certificate is valid and trusted.
- If you don't have access to a trusted certificate (e.g. from Let's Encrypt), either:
    - Add your self-signed certificate to the trust store of your OS _or_
    - Disable certificate verification by either setting `cli.insecure: true` in the configuration file or by setting
      `HEADSCALE_CLI_INSECURE=1` via an environment variable. We do **not** recommend to disable certificate validation.
