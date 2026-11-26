# Tags

Headscale supports Tailscale tags. Please read [Tailscale's tag documentation](https://tailscale.com/docs/features/tags)
to learn how tags work and how to use them.

Tags can be applied during [node registration](registration.md):

- using the `--advertise-tags` flag, see [web authentication for tagged devices](registration.md#__tabbed_1_2)
- using a tagged pre authenticated key, see [how to create and use it](registration.md#__tabbed_2_2)

Administrators can manage tags with:

- Headscale CLI
- [Headscale API](api.md)

## Common operations

### Manage tags for a node

Run `headscale nodes list` to list the tags for a node.

Use the `headscale nodes tags set` command to replace the tags of a node. At least one tag is required and multiple
tags can be provided as comma separated list. The following command sets the tags `tag:server` and `tag:prod` on node
with ID 1:

```console
headscale nodes tags set 1 tag:server,tag:prod
```

### Convert from personal to tagged node

Use the `headscale nodes tags set` command to convert a personal (user-owned) node to a tagged node. It asks for
confirmation, because the user loses the node; `--force` skips the question:

```console
headscale nodes tags set <NODE_ID> <TAG>
```

The node is now owned by its tags: `headscale nodes list` shows them as its owner, and Tailscale clients see the node under
the special user `tagged-devices`.

### Convert from tagged to personal node

Tagged nodes can return to personal (user-owned) nodes by re-authenticating with:

```console
tailscale up --login-server <YOUR_HEADSCALE_URL> --advertise-tags= --force-reauth
```

Usually, a browser window with further instructions is opened. This page explains how to complete the registration on
your Headscale server and it also prints the Auth ID required to approve the node:

```console
headscale auth register <AUTH_ID> <USER>
```

All previously assigned tags get removed and the node is now owned by the user specified in the above command.
