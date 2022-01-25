# Controlling `headscale` with remote CLI

## Prerequisit

- A workstation to run `headscale` (could be Linux, macOS, other supported platforms)
- A `headscale` server (version `0.13.0` or newer)
- Access to create API keys (local access to the `headscale` server)
- `headscale` _must_ be served over TLS/HTTPS
  - Remote access does _not_ support unencrypted traffic.

## Goal

This documentation has the goal of showing a user how-to set control a `headscale` instance
from a remote machine with the `headscale` command line binary.

## Create an API key 

We need to create an API key to authenticate our remote `headscale` when using it from our workstation.

To create a API key, log into your `headscale` server and generate a key:

```shell
headscale apikeys create --expiration 90d
```

Copy the output of the command and save it for later. Please not that you can not retrieve a key again, 
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
export HEADSCALE_CLI_ADDRESS="<HEADSCALE ADDRESS>"
export HEADSCALE_CLI_API_KEY="<API KEY FROM PREVIOUS STAGE>"
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

## Troubleshooting

Checklist:

- Make sure you have the _same_ `headscale` version on your server and workstation
- Make sure you use version `0.13.0` or newer.
- Verify that your TLS certificate is valid 
  - If it is not valid, set the environment variable `HEADSCALE_CLI_INSECURE=true` to allow insecure certs.
