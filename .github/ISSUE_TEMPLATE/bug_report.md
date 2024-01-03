---
name: "Bug report"
about: "Create a bug report to help us improve"
title: ""
labels: ["bug"]
assignees: ""
---

<!--
Before posting a bug report, discuss the behaviour you are expecting with the Discord community
to make sure that it is truly a bug.
The issue tracker is not the place to ask for support or how to set up Headscale.

Bug reports without the sufficient information will be closed.

Headscale is a multinational community across the globe. Our language is English.
All bug reports needs to be in English.
-->

## Bug description

<!-- A clear and concise description of what the bug is. Describe the expected bahavior
  and how it is currently different. If you are unsure if it is a bug, consider discussing
  it on our Discord server first. -->

## Environment

<!-- Please add relevant information about your system. For example:
- Version of headscale used
- Version of tailscale client
- OS (e.g. Linux, Mac, Cygwin, WSL, etc.) and version
- Kernel version
- The relevant config parameters you used
- Log output
-->

- OS:
- Headscale version:
- Tailscale version:

<!--
We do not support running Headscale in a container nor behind a (reverse) proxy.
If either of these are true for your environment, ask the community in Discord
instead of filing a bug report.
-->

- [ ] Headscale is behind a (reverse) proxy
- [ ] Headscale runs in a container

## To Reproduce

<!-- Steps to reproduce the behavior. -->

## Logs and attachments

<!-- Please attach files with:
- Client netmap dump (see below)
- ACL configuration
- Headscale configuration

Dump the netmap of tailscale clients:
`tailscale debug netmap > DESCRIPTIVE_NAME.json`

Please provide information describing the netmap, which client, which headscale version etc.
-->
