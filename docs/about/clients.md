# Client and operating system support

We aim to support the [**last 10 releases** of the Tailscale client](https://tailscale.com/changelog#client) on all
provided operating systems and platforms. Some platforms might require additional configuration to connect with
headscale.

| OS      | Supports headscale                                                                                    |
| ------- | ----------------------------------------------------------------------------------------------------- |
| Linux   | Yes                                                                                                   |
| OpenBSD | Yes                                                                                                   |
| FreeBSD | Yes                                                                                                   |
| Windows | Yes (see [docs](../usage/connect/windows.md) and `/windows` on your headscale for more information)   |
| Android | Yes (see [docs](../usage/connect/android.md) for more information)                                    |
| macOS   | Yes (see [docs](../usage/connect/apple.md#macos) and `/apple` on your headscale for more information) |
| iOS     | Yes (see [docs](../usage/connect/apple.md#ios) and `/apple` on your headscale for more information)   |
| tvOS    | Yes (see [docs](../usage/connect/apple.md#tvos) and `/apple` on your headscale for more information)  |

## Update clients

Tailscale clients can update themselves. Set `auto_update.enabled: true` in the configuration file to turn auto-updates
on by default for nodes that have not made a local choice with `tailscale set --auto-update`.

A connected node can also be asked to update right away:

```console
headscale nodes update-client --identifier <NODE_ID>
```

The node only starts the update if auto-updates are enabled on it and its platform supports them. Otherwise the command
reports why the node refused. A node with active Tailscale SSH sessions refuses as well, unless `--force` is given. The
command returns once the update has started; the node reconnects with the new version when it is done.

The same request is available in the API as `POST /api/v2/device/<NODE_ID>/update-client` with an optional
`{"force": true}` body. It needs an API key or an OAuth token with the `devices:core` scope.
