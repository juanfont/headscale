# Registration methods

Headscale supports multiple ways to register a node. The preferred registration method depends on the identity of a node
and your use case.

## Identity model

Tailscale's identity model distinguishes between personal and tagged nodes:

- A personal node (or user-owned node) is owned by a human and typically refers to end-user devices such as laptops,
  workstations or mobile phones. End-user devices are managed by a single user.
- A tagged node (or service-based node or non-human node) provides services to the network. Common examples include web-
  and database servers. Those nodes are typically managed by a team of users. Some additional restrictions apply for
  tagged nodes, e.g. a tagged node is not allowed to [Tailscale SSH](https://tailscale.com/kb/1193/tailscale-ssh) into a
  personal node.

Headscale implements Tailscale's identity model and distinguishes between personal and tagged nodes where a personal
node is owned by a Headscale user and a tagged node is owned by a tag. Tagged devices are grouped under the special user
`tagged-devices`.

## Registration methods

There are two main ways to register new nodes, [web authentication](#web-authentication) and [registration with a pre
authenticated key](#pre-authenticated-key). Both methods can be used to register personal and tagged nodes.

### Web authentication

Web authentication is the default method to register a new node. It's interactive, where the client initiates the
registration and the Headscale administrator needs to approve the new node before it is allowed to join the network. A
node can be approved with:

- Headscale CLI (described in this documentation)
- [Headscale API](api.md)
- Or delegated to an identity provider via [OpenID Connect](oidc.md)

Web authentication relies on the presence of a Headscale user. Use the `headscale users` command to create a new user:

```console
headscale users create <USER>
```

=== "Personal devices"

    Run `tailscale up` to login your personal device:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL>
    ```

    Usually, a browser window with further instructions is opened. This page explains how to complete the registration
    on your Headscale server and it also prints the registration key required to approve the node:

    ```console
    headscale nodes register --user <USER> --key <REGISTRATION_KEY>
    ```

    Congrations, the registration of your personal node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `<USER>` as the owner of the node.

=== "Tagged devices"

    Your Headscale user needs to be authorized to register tagged devices. This authorization is specified in the
    [`tagOwners`](https://tailscale.com/kb/1337/policy-syntax#tag-owners) section of the [ACL](acls.md). A simple
    example looks like this:

    ```json title="The user alice can register nodes tagged with tag:server"
    {
      "tagOwners": {
        "tag:server": ["alice@"]
      },
      // more rules
    }
    ```

    Run `tailscale up` and provide at least one tag to login a tagged device:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --advertise-tags tag:<TAG>
    ```

    Usually, a browser window with further instructions is opened. This page explains how to complete the registration
    on your Headscale server and it also prints the registration key required to approve the node:

    ```console
    headscale nodes register --user <USER> --key <REGISTRATION_KEY>
    ```

    Headscale checks that `<USER>` is allowed to register a node with the specified tag(s) and then transfers ownership
    of the new node to the special user `tagged-devices`. The registration of a tagged node is complete and it should be
    listed as "online" in the output of `headscale nodes list`. The "User" column displays `tagged-devices` as the owner
    of the node. See the "Tags" column for the list of assigned tags.

### Pre authenticated key

Registration with a pre authenticated key (or auth key) is a non-interactive way to register a new node. The Headscale
administrator creates a preauthkey upfront and this preauthkey can then be used to register a node non-interactively.
Its best suited for automation.

=== "Personal devices"

    A personal node is always assigned to a Headscale user. Use the `headscale users` command to create a new user:

    ```console
    headscale users create <USER>
    ```

    Use the `headscale user list` command to learn its `<USER_ID>` and create a new pre authenticated key for your user:

    ```console
    headscale preauthkeys create --user <USER_ID>
    ```

    The above prints a pre authenticated key with the default settings (can be used once and is valid for one hour). Use
    this auth key to register a node non-interactively:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
    ```

    Congrations, the registration of your personal node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `<USER>` as the owner of the node.

=== "Tagged devices"

    Create a new pre authenticated key and provide at least one tag:

    ```console
    headscale preauthkeys create --tags tag:<TAG>
    ```

    The above prints a pre authenticated key with the default settings (can be used once and is valid for one hour). Use
    this auth key to register a node non-interactively. You don't need to provide the `--advertise-tags` parameter as
    the tags are automatically read from the pre authenticated key:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
    ```

    The registration of a tagged node is complete and it should be listed as "online" in the output of `headscale nodes
    list`. The "User" column displays `tagged-devices` as the owner of the node. See the "Tags" column for the list of
    assigned tags.
