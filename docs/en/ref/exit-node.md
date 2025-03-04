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
$ headscale nodes list-routes
ID | Hostname           | Approved | Available       | Serving
1  | ts-head-ruqsg8     |          | 0.0.0.0/0, ::/0 |
2  | ts-unstable-fq7ob4 |          | 0.0.0.0/0, ::/0 |

# Note that for exit nodes, it is sufficient to approve either the IPv4 or IPv6 route. The other will be added automatically.
$ headscale nodes approve-routes --identifier 1 --routes 0.0.0.0/0
Node updated

$ headscale nodes list-routes
ID | Hostname           | Approved        | Available       | Serving
1  | ts-head-ruqsg8     | 0.0.0.0/0, ::/0 | 0.0.0.0/0, ::/0 | 0.0.0.0/0, ::/0
2  | ts-unstable-fq7ob4 |                 | 0.0.0.0/0, ::/0 |
```

## On the client

The exit node can now be used with:

```console
$ sudo tailscale set --exit-node phobos
```

Check the official [Tailscale documentation](https://tailscale.com/kb/1103/exit-nodes#use-the-exit-node) for how to do it on your device.
