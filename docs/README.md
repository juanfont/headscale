# headscale documentation

This page contains the official and community contributed documentation for `headscale`.

If you are having trouble with following the documentation or get unexpected results,
please ask on [Discord](https://discord.gg/c84AZQhmpx) instead of opening an Issue.

## Official documentation

### How-to

- [Running headscale on Linux](running-headscale-linux.md)
- [Control headscale remotely](remote-cli.md)
- [Using a Windows client with headscale](windows-client.md)

### References

- [Configuration](../config-example.yaml)
- [Glossary](glossary.md)
- [TLS](tls.md)

## Community documentation

Community documentation is not actively maintained by the headscale authors and is
written by community members. It is _not_ verified by `headscale` developers.

**It might be outdated and it might miss necessary steps**.

- [Running headscale in a container](running-headscale-container.md)
- [Running headscale on OpenBSD](running-headscale-openbsd.md)

## Misc

### Policy ACLs

Headscale implements the same policy ACLs as Tailscale.com, adapted to the self-hosted environment.

For instance, instead of referring to users when defining groups you must
use namespaces (which are the equivalent to user/logins in Tailscale.com).

Please check https://tailscale.com/kb/1018/acls/, and `./tests/acls/` in this repo for working examples.

When using ACL's the Namespace borders are no longer applied. All machines
whichever the Namespace have the ability to communicate with other hosts as
long as the ACL's permits this exchange.

The [ACLs](acls.md) document should help understand a fictional case of setting
up ACLs in a small company. All concepts presented in this document could be
applied outside of business oriented usage.

### Apple devices

An endpoint with information on how to connect your Apple devices (currently macOS only) is available at `/apple` on your running instance.
