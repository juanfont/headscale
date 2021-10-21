# headscale

![ci](https://github.com/juanfont/headscale/actions/workflows/test.yml/badge.svg)

An open source, self-hosted implementation of the Tailscale coordination server.

Join our [Discord](https://discord.gg/XcQxk2VHjx) server for a chat.

## Overview

Tailscale is [a modern VPN](https://tailscale.com/) built on top of [Wireguard](https://www.wireguard.com/). It [works like an overlay network](https://tailscale.com/blog/how-tailscale-works/) between the computers of your networks - using all kinds of [NAT traversal sorcery](https://tailscale.com/blog/how-nat-traversal-works/).

Everything in Tailscale is Open Source, except the GUI clients for proprietary OS (Windows and macOS/iOS), and the 'coordination/control server'.

The control server works as an exchange point of Wireguard public keys for the nodes in the Tailscale network. It also assigns the IP addresses of the clients, creates the boundaries between each user, enables sharing machines between users, and exposes the advertised routes of your nodes.

headscale implements this coordination server.

## Status

- [x] Base functionality (nodes can communicate with each other)
- [x] Node registration through the web flow
- [x] Network changes are relayed to the nodes
- [x] Namespaces support (~tailnets in Tailscale.com naming)
- [x] Routing (advertise & accept, including exit nodes)
- [x] Node registration via pre-auth keys (including reusable keys, and ephemeral node support)
- [x] JSON-formatted output
- [x] ACLs
- [x] Taildrop (File Sharing)
- [x] Support for alternative IP ranges in the tailnets (default Tailscale's 100.64.0.0/10)
- [x] DNS (passing DNS servers to nodes)
- [x] Share nodes between namespaces
- [x] MagicDNS (see `docs/`)

## Client OS support

| OS      | Supports headscale                                                                                                |
| ------- | ----------------------------------------------------------------------------------------------------------------- |
| Linux   | Yes                                                                                                               |
| OpenBSD | Yes                                                                                                               |
| macOS   | Yes (see `/apple` on your headscale for more information)                                                         |
| Windows | Yes                                                                                                               |
| Android | [You need to compile the client yourself](https://github.com/juanfont/headscale/issues/58#issuecomment-885255270) |
| iOS     | Not yet                                                                                                           |

## Roadmap 🤷

Suggestions/PRs welcomed!


## Running headscale

Please have a look at the documentation under [`docs/`](docs/).


## Disclaimer

1. We have nothing to do with Tailscale, or Tailscale Inc.
2. The purpose of writing this was to learn how Tailscale works.


## Contributors


