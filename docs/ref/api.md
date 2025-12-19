# API
Headscale provides a [HTTP REST API](#rest-api) and a [gRPC interface](#grpc) which may be used to integrate a [web
interface](integration/web-ui.md), [remote control Headscale](#setup-remote-control) or provide a base for custom
integration and tooling.

Both interfaces require a valid API key before use. To create an API key, log into your Headscale server and generate
one with the default expiration of 90 days:

```shell
headscale apikeys create
```

Copy the output of the command and save it for later. Please note that you can not retrieve an API key again. If the API
key is lost, expire the old one, and create a new one.

To list the API keys currently associated with the server:

```shell
headscale apikeys list
```

and to expire an API key:

```shell
headscale apikeys expire --prefix <PREFIX>
```

## REST API

- API endpoint: `/api/v1`, e.g. `https://headscale.example.com/api/v1`
- Documentation: `/swagger`, e.g. `https://headscale.example.com/swagger`
- Headscale Version: `/version`, e.g. `https://headscale.example.com/version`
- Authenticate using HTTP Bearer authentication by sending the [API key](#api) with the HTTP `Authorization: Bearer
  <API_KEY>` header.

Start by [creating an API key](#api) and test it with the examples below. Read the API documentation provided by your
Headscale server at `/swagger` for details.

=== "Get details for all users"

    ```console
    curl -H "Authorization: Bearer <API_KEY>" \
        https://headscale.example.com/api/v1/user
    ```

=== "Get details for user 'bob'"

    ```console
    curl -H "Authorization: Bearer <API_KEY>" \
        https://headscale.example.com/api/v1/user?name=bob
    ```

=== "Register a node"

    ```console
    curl -H "Authorization: Bearer <API_KEY>" \
        -d user=<USER> -d key=<KEY> \
        https://headscale.example.com/api/v1/node/register
    ```

## gRPC

The gRPC interface can be used to control a Headscale instance from a remote machine with the `headscale` binary.

### Prerequisite

- A workstation to run `headscale` (any supported platform, e.g. Linux).
- A Headscale server with gRPC enabled.
- Connections to the gRPC port (default: `50443`) are allowed.
- Remote access requires an encrypted connection via TLS.
- An [API key](#api) to authenticate with the Headscale server.

### Setup remote control

1.  Download the [`headscale` binary from GitHub's release page](https://github.com/juanfont/headscale/releases). Make
    sure to use the same version as on the server.

1.  Put the binary somewhere in your `PATH`, e.g. `/usr/local/bin/headscale`

1.  Make `headscale` executable: `chmod +x /usr/local/bin/headscale`

1.  [Create an API key](#api) on the Headscale server.

1.  Provide the connection parameters for the remote Headscale server either via a minimal YAML configuration file or
    via environment variables:

    === "Minimal YAML configuration file"

        ```yaml title="config.yaml"
        cli:
            address: <HEADSCALE_ADDRESS>:<PORT>
            api_key: <API_KEY>
        ```

    === "Environment variables"

        ```shell
        export HEADSCALE_CLI_ADDRESS="<HEADSCALE_ADDRESS>:<PORT>"
        export HEADSCALE_CLI_API_KEY="<API_KEY>"
        ```

    This instructs the `headscale` binary to connect to a remote instance at `<HEADSCALE_ADDRESS>:<PORT>`, instead of
    connecting to the local instance.

1.  Test the connection by listing all nodes:

    ```shell
    headscale nodes list
    ```

    You should now be able to see a list of your nodes from your workstation, and you can
    now control the Headscale server from your workstation.

### Behind a proxy

It's possible to run the gRPC remote endpoint behind a reverse proxy, like Nginx, and have it run on the _same_ port as Headscale.

While this is _not a supported_ feature, an example on how this can be set up on
[NixOS is shown here](https://github.com/kradalby/dotfiles/blob/4489cdbb19cddfbfae82cd70448a38fde5a76711/machines/headscale.oracldn/headscale.nix#L61-L91).

### Troubleshooting

- Make sure you have the _same_ Headscale version on your server and workstation.
- Ensure that connections to the gRPC port are allowed.
- Verify that your TLS certificate is valid and trusted.
- If you don't have access to a trusted certificate (e.g. from Let's Encrypt), either:
    - Add your self-signed certificate to the trust store of your OS _or_
    - Disable certificate verification by either setting `cli.insecure: true` in the configuration file or by setting
      `HEADSCALE_CLI_INSECURE=1` via an environment variable. We do **not** recommend to disable certificate validation.
