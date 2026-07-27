# Sealos

!!! warning "Community documentation"

    This page is maintained by the Sealos templates community and is not
    verified by headscale developers. Report deployment-specific issues in the
    [Sealos templates repository](https://github.com/labring-actions/templates/issues).
    Confirm that the template uses a supported headscale release before
    production use.

The community-maintained Sealos template deploys headscale and
[Headplane](https://github.com/tale/headplane) on Kubernetes. It configures
persistent storage, TLS-enabled endpoints, and SQLite by default. PostgreSQL is
available as a deployment option.

[![Deploy on Sealos](https://sealos.io/Deploy-on-Sealos.svg)](https://sealos.io/products/app-store/headscale)

## Deploy

1. Open the Sealos template and select **Deploy Now**.
1. Keep SQLite for the default deployment, or enable PostgreSQL to provision a
   dedicated database.
1. Wait for the headscale and Headplane containers to become ready.
1. Open the application URL. The root path redirects to Headplane at `/admin/`.

The template also creates a separate TLS endpoint for the headscale gRPC API.

## Sign in and register a node

Create a headscale API key from the headscale container:

```shell
headscale apikeys create
```

Paste the key into the Headplane sign-in page. In Headplane, create a user and
then create a pre-authentication key for that user.

Connect a node with the public application URL and the pre-authentication key:

```shell
tailscale up \
  --login-server=https://<HEADSCALE_DOMAIN> \
  --authkey=<PRE_AUTH_KEY>
```

Continue with the [getting started guide](../../usage/getting-started.md) for
the standard headscale registration workflow.

## Persistence and database

The template persists these paths:

| Path                 | Contents                                 |
| -------------------- | ---------------------------------------- |
| `/var/lib/headscale` | SQLite database, keys, and runtime state |
| `/etc/headscale`     | Headscale configuration                  |
| `/var/lib/headplane` | Headplane state                          |

When PostgreSQL is enabled, Sealos provisions a dedicated database and injects
its credentials from a Kubernetes Secret. The headscale configuration and keys
remain on persistent volumes.

## Updating

Review the template's
[deployment notes](https://github.com/labring-actions/templates/tree/kb-0.9/template/headscale)
for its currently tested headscale and Headplane versions. Before changing the
headscale image version, back up the database and persistent volumes and follow
the [upgrade guide](../upgrade.md).
