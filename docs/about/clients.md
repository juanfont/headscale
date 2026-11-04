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

Tailscale clients can update themselves. `auto_update.enabled: true` in the configuration file turns auto-updates on
by default, but a node takes the default only while its own setting is unset. Once it has stored a value, from an
earlier default or from `tailscale set --auto-update`, it keeps it. Headscale always sends a default, so turning the
option on later does not reach nodes that joined while it was off.

A connected node can also be asked to update right away:

```console
headscale nodes update-client --identifier <NODE_ID>
```

The node must allow remote updates (`tailscale set --auto-update`) and run on a platform that can update itself. As on
Tailscale, a node that does not, is not connected, or refuses (for example, with active Tailscale SSH sessions) is
answered "not found". Headscale logs the reason a node gives. The command returns once the update has started.

The same request is available in the API as `POST /api/v2/device/<NODE_ID>/update-client`, with no body. It needs an
API key or an OAuth token with the `devices:core` scope. `GET /api/v2/device/<NODE_ID>/update-status` answers
`{"status": "updating"}` from a started update until the node runs another version, for at most 10 minutes, and
`{"status": "not-updating"}` otherwise. It needs the `devices:core:read` scope.
