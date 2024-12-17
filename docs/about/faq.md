# Frequently Asked Questions

## What is the design goal of headscale?

Headscale aims to implement a self-hosted, open source alternative to the [Tailscale](https://tailscale.com/)
control server.
Headscale's goal is to provide self-hosters and hobbyists with an open-source
server they can use for their projects and labs.
It implements a narrow scope, a _single_ Tailnet, suitable for a personal use, or a small
open-source organisation.

## How can I contribute?

Headscale is "Open Source, acknowledged contribution", this means that any
contribution will have to be discussed with the Maintainers before being submitted.

Please see [Contributing](contributing.md) for more information.

## Why is 'acknowledged contribution' the chosen model?

Both maintainers have full-time jobs and families, and we want to avoid burnout. We also want to avoid frustration from contributors when their PRs are not accepted.

We are more than happy to exchange emails, or to have dedicated calls before a PR is submitted.

## When/Why is Feature X going to be implemented?

We don't know. We might be working on it. If you're interested in contributing, please post a feature request about it.

Please be aware that there are a number of reasons why we might not accept specific contributions:

- It is not possible to implement the feature in a way that makes sense in a self-hosted environment.
- Given that we are reverse-engineering Tailscale to satisfy our own curiosity, we might be interested in implementing the feature ourselves.
- You are not sending unit and integration tests with it.

## Do you support Y method of deploying headscale?

We currently support deploying headscale using our binaries and the DEB packages. Visit our [installation guide using
official releases](../setup/install/official.md) for more information.

In addition to that, you may use packages provided by the community or from distributions. Learn more in the
[installation guide using community packages](../setup/install/community.md).

For convenience, we also [build Docker images with headscale](../setup/install/container.md). But **please be aware that
we don't officially support deploying headscale using Docker**. On our [Discord server](https://discord.gg/c84AZQhmpx)
we have a "docker-issues" channel where you can ask for Docker-specific help to the community.

## Which database should I use?

We recommend the use of SQLite as database for headscale:

- SQLite is simple to setup and easy to use
- It scales well for all of headscale's usecases
- Development and testing happens primarily on SQLite
- PostgreSQL is still supported, but is considered to be in "maintenance mode"

The headscale project itself does not provide a tool to migrate from PostgreSQL to SQLite. Please have a look at [the
related tools documentation](../ref/integration/tools.md) for migration tooling provided by the community.

## Why is my reverse proxy not working with headscale?

We don't know. We don't use reverse proxies with headscale ourselves, so we don't have any experience with them. We have
[community documentation](../ref/integration/reverse-proxy.md) on how to configure various reverse proxies, and a
dedicated "reverse-proxy-issues" channel on our [Discord server](https://discord.gg/c84AZQhmpx) where you can ask for
help to the community.

## Can I use headscale and tailscale on the same machine?

Running headscale on a machine that is also in the tailnet can cause problems with subnet routers, traffic relay nodes, and MagicDNS. It might work, but it is not supported.
