Headscale implements the same policy ACLs as Tailscale.com, adapted to the self-hosted environment.

For instance, instead of referring to users when defining groups you must
use users (which are the equivalent to user/logins in Tailscale.com).

Please check https://tailscale.com/kb/1018/acls/ for further information.

When using ACL's the User borders are no longer applied. All machines
whichever the User have the ability to communicate with other hosts as
long as the ACL's permits this exchange.

## ACL Setup

To enable and configure ACLs in Headscale, you need to specify the path to your ACL policy file in the `policy.path` key in `config.yaml`.

Your ACL policy file must be formatted using [huJSON](https://github.com/tailscale/hujson).

Info on how these policies are written can be found
[here](https://tailscale.com/kb/1018/acls/).

Please reload or restart Headscale after updating the ACL file. Headscale may be reloaded either via its systemd service
(`sudo systemctl reload headscale`) or by sending a SIGHUP signal (`sudo kill -HUP $(pidof headscale)`) to the main
process. Headscale logs the result of ACL policy processing after each reload.

## Simple Examples

- [**Allow All**](https://tailscale.com/kb/1192/acl-samples#allow-all-default-acl): If you define an ACL file but completely omit the `"acls"` field from its content, Headscale will default to an "allow all" policy. This means all devices connected to your tailnet will be able to communicate freely with each other.

    ```json
    {}
    ```

- [**Deny All**](https://tailscale.com/kb/1192/acl-samples#deny-all): To prevent all communication within your tailnet, you can include an empty array for the `"acls"` field in your policy file.

    ```json
    {
      "acls": []
    }
    ```

## Complex Example

Let's build a more complex example use case for a small business (It may be the place where
ACL's are the most useful).

We have a small company with a boss, an admin, two developers and an intern.

The boss should have access to all servers but not to the user's hosts. Admin
should also have access to all hosts except that their permissions should be
limited to maintaining the hosts (for example purposes). The developers can do
anything they want on dev hosts but only watch on productions hosts. Intern
can only interact with the development servers.

There's an additional server that acts as a router, connecting the VPN users
to an internal network `10.20.0.0/16`. Developers must have access to those
internal resources.

Each user have at least a device connected to the network and we have some
servers.

- database.prod
- database.dev
- app-server1.prod
- app-server1.dev
- billing.internal
- router.internal

![ACL implementation example](../assets/images/headscale-acl-network.png)

When [registering the servers](../usage/getting-started.md#register-a-node) we
will need to add the flag `--advertise-tags=tag:<tag1>,tag:<tag2>`, and the user
that is registering the server should be allowed to do it. Since anyone can add
tags to a server they can register, the check of the tags is done on headscale
server and only valid tags are applied. A tag is valid if the user that is
registering it is allowed to do it.

Here are the ACL's to implement the same permissions as above:

```json title="acl.json"
{
  // groups are collections of users having a common scope. A user can be in multiple groups
  // groups cannot be composed of groups
  "groups": {
    "group:boss": ["boss@"],
    "group:dev": ["dev1@", "dev2@"],
    "group:admin": ["admin1@"],
    "group:intern": ["intern1@"]
  },
  // tagOwners in tailscale is an association between a TAG and the people allowed to set this TAG on a server.
  // This is documented [here](https://tailscale.com/kb/1068/acl-tags#defining-a-tag)
  // and explained [here](https://tailscale.com/blog/rbac-like-it-was-meant-to-be/)
  "tagOwners": {
    // the administrators can add servers in production
    "tag:prod-databases": ["group:admin"],
    "tag:prod-app-servers": ["group:admin"],

    // the boss can tag any server as internal
    "tag:internal": ["group:boss"],

    // dev can add servers for dev purposes as well as admins
    "tag:dev-databases": ["group:admin", "group:dev"],
    "tag:dev-app-servers": ["group:admin", "group:dev"]

    // interns cannot add servers
  },
  // hosts should be defined using its IP addresses and a subnet mask.
  // to define a single host, use a /32 mask. You cannot use DNS entries here,
  // as they're prone to be hijacked by replacing their IP addresses.
  // see https://github.com/tailscale/tailscale/issues/3800 for more information.
  "hosts": {
    "postgresql.internal": "10.20.0.2/32",
    "webservers.internal": "10.20.10.1/29"
  },
  "acls": [
    // boss have access to all servers
    {
      "action": "accept",
      "src": ["group:boss"],
      "dst": [
        "tag:prod-databases:*",
        "tag:prod-app-servers:*",
        "tag:internal:*",
        "tag:dev-databases:*",
        "tag:dev-app-servers:*"
      ]
    },

    // admin have only access to administrative ports of the servers, in tcp/22
    {
      "action": "accept",
      "src": ["group:admin"],
      "proto": "tcp",
      "dst": [
        "tag:prod-databases:22",
        "tag:prod-app-servers:22",
        "tag:internal:22",
        "tag:dev-databases:22",
        "tag:dev-app-servers:22"
      ]
    },

    // we also allow admin to ping the servers
    {
      "action": "accept",
      "src": ["group:admin"],
      "proto": "icmp",
      "dst": [
        "tag:prod-databases:*",
        "tag:prod-app-servers:*",
        "tag:internal:*",
        "tag:dev-databases:*",
        "tag:dev-app-servers:*"
      ]
    },

    // developers have access to databases servers and application servers on all ports
    // they can only view the applications servers in prod and have no access to databases servers in production
    {
      "action": "accept",
      "src": ["group:dev"],
      "dst": [
        "tag:dev-databases:*",
        "tag:dev-app-servers:*",
        "tag:prod-app-servers:80,443"
      ]
    },
    // developers have access to the internal network through the router.
    // the internal network is composed of HTTPS endpoints and Postgresql
    // database servers.
    {
      "action": "accept",
      "src": ["group:dev"],
      "dst": ["10.20.0.0/16:443,5432"]
    },

    // servers should be able to talk to database in tcp/5432. Database should not be able to initiate connections to
    // applications servers
    {
      "action": "accept",
      "src": ["tag:dev-app-servers"],
      "proto": "tcp",
      "dst": ["tag:dev-databases:5432"]
    },
    {
      "action": "accept",
      "src": ["tag:prod-app-servers"],
      "dst": ["tag:prod-databases:5432"]
    },

    // interns have access to dev-app-servers only in reading mode
    {
      "action": "accept",
      "src": ["group:intern"],
      "dst": ["tag:dev-app-servers:80,443"]
    },

    // Allow users to access their own devices using autogroup:self (see below for more details about performance impact)
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["autogroup:self:*"]
    }
  ]
}
```

## Autogroups

Headscale supports several autogroups that automatically include users, destinations, or devices with specific properties. Autogroups provide a convenient way to write ACL rules without manually listing individual users or devices.

### `autogroup:internet`

Allows access to the internet through [exit nodes](routes.md#exit-node). Can only be used in ACL destinations.

```json
{
  "action": "accept",
  "src": ["group:users"],
  "dst": ["autogroup:internet:*"]
}
```

### `autogroup:member`

Includes all [personal (untagged) devices](registration.md/#identity-model).

```json
{
  "action": "accept",
  "src": ["autogroup:member"],
  "dst": ["tag:prod-app-servers:80,443"]
}
```

### `autogroup:tagged`

Includes all devices that [have at least one tag](registration.md/#identity-model).

```json
{
  "action": "accept",
  "src": ["autogroup:tagged"],
  "dst": ["tag:monitoring:9090"]
}
```

### `autogroup:self`
**(EXPERIMENTAL)**

!!! warning "The current implementation of `autogroup:self` is inefficient"

Includes devices where the same user is authenticated on both the source and destination. Does not include tagged devices. Can only be used in ACL destinations.

```json
{
  "action": "accept",
  "src": ["autogroup:member"],
  "dst": ["autogroup:self:*"]
}
```
*Using `autogroup:self` may cause performance degradation on the Headscale coordinator server in large deployments, as filter rules must be compiled per-node rather than globally and the current implementation is not very efficient.*

If you experience performance issues, consider using more specific ACL rules or limiting the use of `autogroup:self`.
```json
{
  // The following rules allow internal users to communicate with their
  // own nodes in case autogroup:self is causing performance issues.
  { "action": "accept", "src": ["boss@"], "dst": ["boss@:*"] },
  { "action": "accept", "src": ["dev1@"], "dst": ["dev1@:*"] },
  { "action": "accept", "src": ["dev2@"], "dst": ["dev2@:*"] },
  { "action": "accept", "src": ["admin1@"], "dst": ["admin1@:*"] },
  { "action": "accept", "src": ["intern1@"], "dst": ["intern1@:*"] }
}
```

### `autogroup:nonroot`

Used in Tailscale SSH rules to allow access to any user except root. Can only be used in the `users` field of SSH rules.

```json
{
  "action": "accept",
  "src": ["autogroup:member"],
  "dst": ["autogroup:self"],
  "users": ["autogroup:nonroot"]
}
```

## Testing ACLs

Headscale provides ACL testing functionality to verify that your policy rules work as expected. You can test ACLs using embedded tests in your policy file or via the CLI.

### Embedded Tests in Policy

You can include a `tests` section in your policy file to define test cases that are automatically validated when the policy is loaded or updated. **If any embedded test fails, the policy update will be rejected**, providing regression protection when modifying ACL rules.

```json
{
  "groups": {
    "group:dev": ["dev1@", "dev2@"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:dev"],
      "dst": ["tag:dev-servers:*"]
    }
  ],
  "tests": [
    {
      "src": "dev1@",
      "accept": ["tag:dev-servers:22", "tag:dev-servers:80"]
    },
    {
      "src": "dev1@",
      "deny": ["tag:prod-servers:22"]
    },
    {
      "src": "group:dev",
      "proto": "tcp",
      "accept": ["tag:dev-servers:443"]
    }
  ]
}
```

Each test case supports the following fields:

| Field    | Description                                              |
|----------|----------------------------------------------------------|
| `src`    | Source alias to test from (user, group, tag, host, or IP) |
| `accept` | List of destinations that should be **allowed** (format: `host:port`) |
| `deny`   | List of destinations that should be **denied** (format: `host:port`) |
| `proto`  | Optional protocol filter (`tcp`, `udp`, `icmp`)          |

### CLI Testing

The `headscale policy test` command allows you to test ACL rules without modifying your policy.

#### Test Specific Access

```bash
# Test if a user can access a server on port 22
headscale policy test --src "alice@example.com" --accept "tag:server:22"

# Test with multiple destinations
headscale policy test --src "group:dev" --accept "tag:dev:22" --accept "tag:dev:80"

# Test both allowed and denied access
headscale policy test --src "alice@" --accept "10.0.0.1:80" --deny "10.0.0.2:443"

# Test with protocol filter
headscale policy test --src "tag:monitoring" --proto tcp --accept "tag:servers:9090"
```

#### Run Embedded Tests

```bash
# Run all tests defined in the current policy's tests section
headscale policy test --embedded
```

#### Test a Proposed Policy

Before applying a new policy, you can test it without affecting the running configuration:

```bash
# Test against a proposed policy file
headscale policy test --src "alice@" --accept "server:22" --policy-file new-acl.json

# Run embedded tests from a proposed policy file
headscale policy test --embedded --policy-file new-acl.json
```

#### Test from a File

You can define multiple tests in a JSON file:

```bash
headscale policy test --file tests.json
```

Where `tests.json` contains:

```json
[
  {
    "src": "alice@example.com",
    "accept": ["server1:22", "server2:80"],
    "deny": ["database:5432"]
  },
  {
    "src": "tag:ci",
    "accept": ["tag:staging:*"]
  }
]
```

#### Output Formats

By default, the CLI shows human-readable output.

For programmatic use, JSON output is available:

```bash
headscale policy test --src "alice@" --accept "server:22" --output json
```

### API Endpoint

Third-party UIs can use the gRPC/HTTP API to test ACL rules:

**Endpoint:** `POST /api/v1/policy/test`

**Request:**

```json
{
  "tests": [
    {
      "src": "alice@example.com",
      "accept": ["server1:22"],
      "deny": ["database:5432"]
    }
  ],
  "policy": ""
}
```

The optional `policy` field allows testing against a proposed policy instead of the current active policy. If empty, tests run against the current policy.

**Response:**

```json
{
  "all_passed": true,
  "results": [
    {
      "src": "alice@example.com",
      "passed": true,
      "accept_ok": ["server1:22"],
      "deny_ok": ["database:5432"]
    }
  ]
}
```
