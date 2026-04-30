# Policy

Headscale implements a large portion of Tailscale's [policy
features](https://tailscale.com/docs/features/tailnet-policy-file), most notably access control based on
[ACLs](https://tailscale.com/docs/features/access-control/acls) and
[Grants](https://tailscale.com/docs/features/access-control/grants) or [Tailscale
SSH](https://tailscale.com/docs/features/tailscale-ssh). See [differences between Headscale and Tailscale
policy](#differences-between-headscale-and-tailscale-policy) to learn about notable differences.

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

## Differences between Headscale and Tailscale policy

- [Device postures](https://tailscale.com/docs/features/device-posture) and the related sections such as `postures` or
  `srcPosture` are not supported.
- A subset of [Autogroups](#autogroups) are available.

## Autogroups

Headscale supports several [Autogroups](https://tailscale.com/docs/reference/targets-and-selectors#autogroups) that
automatically include users, destinations, or devices with specific properties. Autogroups provide a convenient way to
write policy rules without manually listing individual users or devices.

### `autogroup:internet`

Allows access to the internet through [exit nodes](routes.md#exit-node). Can only be used in ACL destinations.

```json title="policy.json"
{
  "action": "accept",
  "src": ["group:users"],
  "dst": ["autogroup:internet:*"]
}
```

### `autogroup:member`

Includes all [personal (untagged) devices](registration.md/#identity-model).

```json title="policy.json"
{
  "action": "accept",
  "src": ["autogroup:member"],
  "dst": ["tag:prod-app-servers:80,443"]
}
```

### `autogroup:tagged`

Includes all devices that [have at least one tag](registration.md/#identity-model).

```json title="policy.json"
{
  "action": "accept",
  "src": ["autogroup:tagged"],
  "dst": ["tag:monitoring:9090"]
}
```

### `autogroup:self`

!!! warning "The current implementation of `autogroup:self` is inefficient"

Includes devices where the same user is authenticated on both the source and destination. Does not include tagged devices. Can only be used in ACL destinations.

```json title="policy.json"
{
  "action": "accept",
  "src": ["autogroup:member"],
  "dst": ["autogroup:self:*"]
}
```

*Using `autogroup:self` may cause performance degradation on the Headscale coordinator server in large deployments, as filter rules must be compiled per-node rather than globally and the current implementation is not very efficient.*

If you experience performance issues, consider using more specific ACL rules or limiting the use of `autogroup:self`.

```json title="policy.json"
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

```json title="policy.json"
{
  "action": "accept",
  "src": ["autogroup:member"],
  "dst": ["autogroup:self"],
  "users": ["autogroup:nonroot"]
}
```

### `autogroup:danger-all`

This autogroup resolves to all IP addresses (`0.0.0.0/0` and `::/0`) which also includes all IP addresses outside the
standard Tailscale IP ranges. [This autogroup can only be used as
source](https://tailscale.com/docs/reference/targets-and-selectors#autogroupdanger-all)

[^1]: Headscale also allows to store the policy in the database. This is typically only required in case a [web
    interface](integration/web-ui.md) is used.
