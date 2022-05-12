# Controlling `headscale` with remote CLI

## Prerequisit

- A workstation to run `headscale` (could be Linux, macOS, other supported platforms)
- A `headscale` server (version `0.13.0` or newer)
- Access to create API keys (local access to the `headscale` server)
- `headscale` _must_ be served over TLS/HTTPS
  - Remote access does _not_ support unencrypted traffic.
- Port `50443` must be open in the firewall (or port overriden by `grpc_listen_addr` option)

## Goal

This documentation has the goal of showing a user how-to set control a `headscale` instance
from a remote machine with the `headscale` command line binary.

## Create an API key

We need to create an API key to authenticate our remote `headscale` when using it from our workstation.

To create a API key, log into your `headscale` server and generate a key:

```shell
headscale apikeys create --expiration 90d
```

Copy the output of the command and save it for later. Please note that you can not retrieve a key again,
if the key is lost, expire the old one, and create a new key.

To list the keys currently assosicated with the server:

```shell
headscale apikeys list
```

and to expire a key:

```shell
headscale apikeys expire --prefix "<PREFIX>"
```

## Download and configure `headscale`

1. Download the latest [`headscale` binary from GitHub's release page](https://github.com/juanfont/headscale/releases):

2. Put the binary somewhere in your `PATH`, e.g. `/usr/local/bin/headcale`

3. Make `headscale` executable:

```shell
chmod +x /usr/local/bin/headscale
```

4. Configure the CLI through Environment Variables

```shell
export HEADSCALE_CLI_ADDRESS="<HEADSCALE ADDRESS>:<PORT>"
export HEADSCALE_CLI_API_KEY="<API KEY FROM PREVIOUS STAGE>"
```

for example:

```shell
export HEADSCALE_CLI_ADDRESS="headscale.example.com:50443"
export HEADSCALE_CLI_API_KEY="abcde12345"
```

This will tell the `headscale` binary to connect to a remote instance, instead of looking
for a local instance (which is what it does on the server).

The API key is needed to make sure that your are allowed to access the server. The key is _not_
needed when running directly on the server, as the connection is local.

5. Test the connection

Let us run the headscale command to verify that we can connect by listing our nodes:

```shell
headscale nodes list
```

You should now be able to see a list of your nodes from your workstation, and you can
now control the `headscale` server from your workstation.

## Behind a proxy

It is possible to run the gRPC remote endpoint behind a reverse proxy, like Nginx, and have it run on the _same_ port as `headscale`.

While this is _not a supported_ feature, an example on how this can be set up on
[NixOS is shown here](https://github.com/kradalby/dotfiles/blob/4489cdbb19cddfbfae82cd70448a38fde5a76711/machines/headscale.oracldn/headscale.nix#L61-L91).

## Troubleshooting

Checklist:

- Make sure you have the _same_ `headscale` version on your server and workstation
- Make sure you use version `0.13.0` or newer.
- Verify that your TLS certificate is valid and trusted
  - If you do not have access to a trusted certificate (e.g. from Let's Encrypt), add your self signed certificate to the trust store of your OS or
  - Set `HEADSCALE_CLI_INSECURE` to 0 in your environement
