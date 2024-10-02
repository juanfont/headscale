# Exit Nodes

## On the node

Register the node and make it advertise itself as an exit node:

```console
$ sudo tailscale up --login-server https://headscale.example.com --advertise-exit-node
```

If the node is already registered, it can advertise exit capabilities like this:

```console
$ sudo tailscale set --advertise-exit-node
```

To use a node as an exit node, IP forwarding must be enabled on the node. Check the official [Tailscale documentation](https://tailscale.com/kb/1019/subnets/?tab=linux#enable-ip-forwarding) for how to enable IP forwarding.

## On the control server

```console
$ # list nodes
$ headscale routes list
ID | Node   | Prefix    | Advertised | Enabled | Primary
1  |        | 0.0.0.0/0 | false      | false   | -
2  |        | ::/0      | false      | false   | -
3  | phobos | 0.0.0.0/0 | true       | false   | -
4  | phobos | ::/0      | true       | false   | -

$ # enable routes for phobos
$ headscale routes enable -r 3
$ headscale routes enable -r 4

$ # Check node list again. The routes are now enabled.
$ headscale routes list
ID | Node   | Prefix    | Advertised | Enabled | Primary
1  |        | 0.0.0.0/0 | false      | false   | -
2  |        | ::/0      | false      | false   | -
3  | phobos | 0.0.0.0/0 | true       | true    | -
4  | phobos | ::/0      | true       | true    | -
```

## On the client

The exit node can now be used with:

```console
$ sudo tailscale set --exit-node phobos
```

Check the official [Tailscale documentation](https://tailscale.com/kb/1103/exit-nodes#use-the-exit-node) for how to do it on your device.
