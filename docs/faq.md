---
hide:
  - navigation
---

# Frequently Asked Questions

## What is the design goal of headscale?

`headscale` aims to implement a self-hosted, open source alternative to the [Tailscale](https://tailscale.com/)
control server.
`headscale`'s goal is to provide self-hosters and hobbyists with an open-source
server they can use for their projects and labs.
It implements a narrow scope, a _single_ Tailnet, suitable for a personal use, or a small
open-source organisation.

## How can I contribute?

Headscale is "Open Source, acknowledged contribution", this means that any
contribution will have to be discussed with the Maintainers before being submitted.

Headscale is open to code contributions for bug fixes without discussion.

If you find mistakes in the documentation, please also submit a fix to the documentation.

## Why is 'acknowledged contribution' the chosen model?

Both maintainers have full-time jobs and families, and we want to avoid burnout. We also want to avoid frustration from contributors when their PRs are not accepted.

We are more than happy to exchange emails, or to have dedicated calls before a PR is submitted.

## When/Why is Feature X going to be implemented?

We don't know. We might be working on it. If you want to help, please send us a PR.

Please be aware that there are a number of reasons why we might not accept specific contributions:

- It is not possible to implement the feature in a way that makes sense in a self-hosted environment.
- Given that we are reverse-engineering Tailscale to satify our own curiosity, we might be interested in implementing the feature ourselves.
- You are not sending unit and integration tests with it.

## Do you support Y method of deploying Headscale?

We currently support deploying `headscale` using our binaries and the DEB packages. Both can be found in the
[GitHub releases page](https://github.com/juanfont/headscale/releases).

In addition to that, there are semi-official RPM packages by the Fedora infra team https://copr.fedorainfracloud.org/coprs/jonathanspw/headscale/

For convenience, we also build Docker images with `headscale`. But **please be aware that we don't officially support deploying `headscale` using Docker**. We have a [Discord channel](https://discord.com/channels/896711691637780480/1070619770942148618) where you can ask for Docker-specific help to the community.

## Why is my reverse proxy not working with Headscale?

We don't know. We don't use reverse proxies with `headscale` ourselves, so we don't have any experience with them. We have [community documentation](https://headscale.net/reverse-proxy/) on how to configure various reverse proxies, and a dedicated [Discord channel](https://discord.com/channels/896711691637780480/1070619818346164324) where you can ask for help to the community.

## Can I use headscale and tailscale on the same machine?

Running headscale on a machine that is also in the tailnet can cause problems with subnet routers, traffic relay nodes, and MagicDNS. It might work, but it is not supported.
