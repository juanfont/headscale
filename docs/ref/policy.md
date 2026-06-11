# Policy

Headscale implements a large portion of Tailscale's [policy
features](https://tailscale.com/docs/features/tailnet-policy-file), most notably access control based on
[ACLs](https://tailscale.com/docs/features/access-control/acls) and
[Grants](https://tailscale.com/docs/features/access-control/grants) or [Tailscale
SSH](https://tailscale.com/docs/features/tailscale-ssh). See [limitations](#limitations) to learn about missing features
and notable implementation differences between Headscale and Tailscale.

Headscale uses the same [huJSON](https://github.com/tailscale/hujson) based file format as Tailscale. By default, no
policy is loaded which means that Headscale allows all traffic between nodes. To start using a policy file[^1], specify
its path in the `policy.path` key in the [configuration file](configuration.md).

Headscale needs to be reloaded to pick up changes to the policy file. Either reload Headscale via its systemd service
(`sudo systemctl reload headscale`) or by sending a SIGHUP signal (`sudo kill -HUP $(pidof headscale)`) to the main
process. Headscale logs the result of policy processing after each reload.

Please have a look at Tailscale's policy related documentation to learn more:

- [Tailscale policy file](https://tailscale.com/docs/features/tailnet-policy-file): A description of supported sections
  within the policy file along with links to syntax references for each section.
- [ACLs](https://tailscale.com/docs/features/access-control/acls): How to configure access control using ACLs.
- [Grants](https://tailscale.com/docs/features/access-control/grants): Introduction to Grants with links to [syntax
  reference](https://tailscale.com/docs/reference/syntax/grants),
  [examples](https://tailscale.com/docs/reference/examples/grants) and a [migration guide from ACLs to
  Grants](https://tailscale.com/docs/reference/migrate-acls-grants).

## Getting started

Headscale supports both [ACLs](https://tailscale.com/docs/features/access-control/acls) and
[Grants](https://tailscale.com/docs/features/access-control/grants) to write an access control policy. We recommend the
use of Grants since ACLs are considered legacy and will not receive new features by Tailscale.

### Allow All

If you define a policy file but completely omit the `"acls"` or `"grants"` section, Headscale will default to an [allow
all](https://tailscale.com/docs/reference/examples/acls#allow-all-default-acl) policy. This means all devices connected
to your tailnet will be able to communicate freely with each other.

```json title="policy.json"
{}
```

### Deny All

To [prevent all communication within your tailnet](https://tailscale.com/docs/reference/examples/acls#deny-all), you can
include an empty array for the `"grants"` section in your policy file.

```json title="policy.json"
{
  "grants": []
}
```

### More examples

- See our documentation on [subnet routers](routes.md#subnet-router) and [exit nodes](routes.md#exit-node) to learn how
  to restrict their use or how to automatically approve them.
- The Tailscale documentation provides a large collection of configuration examples:
    - [ACL examples](https://tailscale.com/docs/reference/examples/acls)
    - [Grants examples](https://tailscale.com/docs/reference/examples/grants)
    - [SSH configuration](https://tailscale.com/docs/features/tailscale-ssh#configure-tailscale-ssh)
    - [Define a tag](https://tailscale.com/docs/features/tags#define-a-tag)

______________________________________________________________________

## Limitations

- [Device postures](https://tailscale.com/docs/features/device-posture) and the related sections such as `postures` or
  `srcPosture` aren't supported.
- [IP sets](https://tailscale.com/docs/features/tailnet-policy-file/ip-sets) aren't supported.
- A subset of [Autogroups](#autogroups) are available.

## Autogroups

Headscale supports several [Autogroups](https://tailscale.com/docs/reference/targets-and-selectors#autogroups) that
automatically include users, destinations, or devices with specific properties. Autogroups provide a convenient way to
write policy rules without manually listing individual users or devices.

### [`autogroup:internet`](https://tailscale.com/docs/reference/targets-and-selectors#autogroupinternet)

Allows access to the internet through [exit nodes](routes.md#exit-node). Can only be used in policy destinations.

```json title="policy.json"
{
  "grants": [
    {
      "src": ["alice@"],
      "dst": ["autogroup:internet"],
      "ip": ["*"]
    }
  ]
}
```

### [`autogroup:member`](https://tailscale.com/docs/reference/targets-and-selectors#autogrouprole)

Includes all [personal (untagged) devices](registration.md/#identity-model).

```json title="policy.json"
{
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["tag:prod-app-servers"],
      "ip": ["80,443"]
    }
  ]
}
```

### [`autogroup:tagged`](https://tailscale.com/docs/reference/targets-and-selectors#autogrouptagged)

Includes all devices that [have at least one tag](registration.md/#identity-model).

```json title="policy.json"
{
  "grants": [
    {
      "src": ["autogroup:tagged"],
      "dst": ["tag:monitoring"],
      "ip": ["9090"]
    }
  ]
}
```

### [`autogroup:self`](https://tailscale.com/docs/reference/targets-and-selectors#autogroupself)

Includes devices where the same user is authenticated on both the source and destination. Does not include tagged
devices. Can only be used in policy destinations.

```json title="policy.json"
{
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["autogroup:self"],
      "ip": ["*"]
    }
  ]
}
```

!!! warning "The current implementation of `autogroup:self` is inefficient"

    Using `autogroup:self` may cause performance degradation on the Headscale coordinator server in large deployments,
    as filter rules must be compiled per-node rather than globally and the current implementation is not very efficient.

    If you experience performance issues, consider using more specific policy rules or limiting the use of
    `autogroup:self`.

    ```json title="policy.json"
    {
      "grants": [
        // The following rules allow internal users to communicate with their
        // own nodes in case autogroup:self is causing performance issues.
        {
          "src": ["boss@"],
          "dst": ["boss@"],
          "ip": "*"
        },
        {
          "src": ["dev1@"],
          "dst": ["dev1@"],
          "ip": "*"
        },
        {
          "src": ["intern1@"],
          "dst": ["intern1@"],
          "ip": "*"
        }
      ]
    }
    ```

### [`autogroup:nonroot`](https://tailscale.com/docs/reference/targets-and-selectors#other-built-in-targets)

Used in Tailscale SSH rules to allow access to any user except root. Can only be used in the `users` field of SSH rules.

```json title="policy.json"
{
  "ssh": [
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["autogroup:self"],
      "users": ["autogroup:nonroot"]
    }
  ]
}
```

### [`autogroup:danger-all`](https://tailscale.com/docs/reference/targets-and-selectors#autogroupdanger-all)

This autogroup resolves to all IP addresses (`0.0.0.0/0` and `::/0`) which also includes all IP addresses outside the
standard Tailscale IP ranges. This autogroup can only be used as source.

## Node Attributes

[Node attributes](https://tailscale.com/docs/reference/syntax/policy-file#node-attributes) allow for device-specific
configuration and attributes. At least the following node attributes are currently supported by Headscale[^2]:

- `drive:access`, `drive:share`: [Taildrive support](https://tailscale.com/docs/features/taildrive).
- `nextdns:<profile>`, `nextdns:no-device-info`: [NextDNS integration](https://tailscale.com/docs/integrations/nextdns).
  Be sure to set NextDNS as global resolver in the [configuration](configuration.md).
- `magicdns-aaaa`: Respond to AAAA queries on the local [MagicDNS](https://tailscale.com/docs/features/magicdns)
  resolver at 100.100.100.100.
- `disable-ipv4`: Selectively disable IPv4 for specfic nodes. This is may be useful to workaround [CGNat
  conflicts](https://tailscale.com/docs/reference/troubleshooting/network-configuration/cgnat-conflicts).
- `randomize-client-port`: Allocate a [random port for WireGuard
  traffic](https://tailscale.com/docs/reference/syntax/policy-file#randomizeclientport) instead of the static default
  port 41641.
- `disable-captive-portal-detection`: [Disable automatic captive portal
  detection](https://tailscale.com/docs/integrations/captive-portals#disable-captive-portal-detection).

```json title="policy.json"
{
  "nodeAttrs": [
    {
      // Enable MagicDNS AAAA records for all nodes
      "target": ["*"]
      "attr": ["magicdns-aaaa"]
    }
  ]
}
```

The `attr` field above carries key-only capabilities. A `nodeAttrs` entry may instead (or additionally) carry an `app`
field for *valued* capabilities — a capability name mapped to a list of JSON payloads, matching Tailscale's `app` field.
Headscale passes these payloads through unmodified. [App Connectors](#app-connectors) are delivered this way via the
`tailscale.com/app-connectors` capability.

## Network-wide policy options

The following options are applied for the entire tailnet. Consider [node attributes](#node-attributes) for a more
fine-grained configuration instead.

- `randomizeClientPort`: Allocate a [random port for WireGuard
  traffic](https://tailscale.com/docs/reference/syntax/policy-file#randomizeclientport) instead of the static default
  port 41641.

```json title="policy.json"
{
  // Use a random WireGuard port for the entire tailnet
  "randomizeClientPort": true
}
```

## App Connectors

Headscale supports [App Connectors](https://tailscale.com/kb/1281/app-connectors), which route traffic for specific
domains through designated connector nodes. This is useful for reaching internal applications or services that are only
reachable from certain nodes in your tailnet.

App connectors are configured exactly as they are in Tailscale: through the [`app`](#node-attributes) field of a
`nodeAttrs` entry, using the `tailscale.com/app-connectors` capability. The `target` selects which nodes receive the
configuration; a connector node must also be started with `tailscale set --advertise-connector`.

```json title="policy.json"
{
  "tagOwners": {
    "tag:connector": ["admin@"]
  },
  "nodeAttrs": [
    {
      "target": ["tag:connector"],
      "app": {
        "tailscale.com/app-connectors": [
          {
            "name": "Internal Apps",
            "connectors": ["tag:connector"],
            "domains": ["internal.example.com", "*.corp.example.com"],
            "routes": ["10.0.0.0/8"]
          }
        ]
      }
    }
  ]
}
```

### Configuration fields

The objects under `tailscale.com/app-connectors` use Tailscale's [app connector
attribute](https://tailscale.com/kb/1281/app-connectors) format. Headscale passes them through unmodified; the connector
client interprets them.

| Field | Required | Description |
|-------|----------|-------------|
| `name` | No | A human-readable name for this collection of domains. |
| `connectors` | Yes | A list of tags (e.g. `tag:connector`) or `*` that identifies which nodes serve as connectors for these domains. Evaluated by the client. |
| `domains` | Yes | Domain names to route through the connector. Supports wildcards like `*.example.com`. |
| `routes` | No | Optional IP prefixes to advertise as routes, in addition to routes discovered dynamically from DNS. |

### Auto-approving routes

App connectors work as dynamic subnet routers under the hood. When a connector resolves DNS for a configured domain, it
advertises the resulting IP addresses as subnet routes. For these routes to take effect automatically, configure
`autoApprovers` to approve routes from the connector nodes:

```json title="policy.json"
{
  "autoApprovers": {
    "routes": {
      "0.0.0.0/0": ["tag:connector"],
      "::/0": ["tag:connector"]
    }
  }
}
```

Without `autoApprovers`, each dynamically discovered route requires manual approval.

### How it works

1. Declare the app connector configuration in a `nodeAttrs` entry whose `target` selects the connector nodes.
2. Configure `autoApprovers` to auto-approve routes from your connector tags.
3. Start the connector node with `tailscale set --advertise-connector`. It receives the domain configuration via the
   `tailscale.com/app-connectors` capability.
4. When clients query DNS for a configured domain, traffic is routed through the connector node, which resolves the DNS
   and forwards traffic to the destination.

### Example: multiple connectors

```json title="policy.json"
{
  "tagOwners": {
    "tag:web-connector": ["admin@"],
    "tag:db-connector": ["admin@"]
  },
  "nodeAttrs": [
    {
      "target": ["tag:web-connector"],
      "app": {
        "tailscale.com/app-connectors": [
          {
            "name": "Web Applications",
            "connectors": ["tag:web-connector"],
            "domains": ["*.internal.example.com", "dashboard.corp.example.com"]
          }
        ]
      }
    },
    {
      "target": ["tag:db-connector"],
      "app": {
        "tailscale.com/app-connectors": [
          {
            "name": "Database Access",
            "connectors": ["tag:db-connector"],
            "domains": ["db.internal.example.com"],
            "routes": ["10.20.30.0/24"]
          }
        ]
      }
    }
  ]
}
```

[^1]: Headscale also allows to store the policy in the database. This is typically only required in case a [web
    interface](integration/web-ui.md) is used.

[^2]: Other key-only node attributes can be used as well. Find them in the client source code with `grep -E '^\s+NodeAttr\w+' tailcfg/tailcfg.go` or by using [GitHub code search (requires
    login)](https://github.com/search?q=repo%3Atailscale%2Ftailscale%20language%3Ago%20path%3Atailcfg%2Ftailcfg.go%20symbol%3A%2FNodeAttr%5Cw%2B%2F&type=code).
