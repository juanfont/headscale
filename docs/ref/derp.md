# DERP

A [DERP (Designated Encrypted Relay for Packets) server](https://tailscale.com/kb/1232/derp-servers) is mainly used to
relay traffic between two nodes in case a direct connection can't be established. Headscale provides an embedded DERP
server to ensure seamless connectivity between nodes.

## Configuration

DERP related settings are configured within the `derp` section of the [configuration file](./configuration.md). The
following sections only use a few of the available settings, check the [example configuration](./configuration.md) for
all available configuration options.

### Enable embedded DERP

Headscale ships with an embedded DERP server which allows to run your own self-hosted DERP server easily. The embedded
DERP server is disabled by default and needs to be enabled. In addition, you should configure the public IPv4 and public
IPv6 address of your Headscale server for improved connection stability:

```yaml title="config.yaml" hl_lines="3-5"
derp:
  server:
    enabled: true
    ipv4: 198.51.100.1
    ipv6: 2001:db8::1
```

Keep in mind that [additional ports are needed to run a DERP server](../setup/requirements.md#ports-in-use). Besides
relaying traffic, it also uses STUN (udp/3478) to help clients discover their public IP addresses and perform NAT
traversal. [Check DERP server connectivity](#check-derp-server-connectivity) to see if everything works.

### Remove Tailscale's DERP servers

Once enabled, Headscale's embedded DERP is added to the list of free-to-use [DERP
servers](https://tailscale.com/kb/1232/derp-servers) offered by Tailscale Inc. To only use Headscale's embedded DERP
server, disable the loading of the default DERP map:

```yaml title="config.yaml" hl_lines="6"
derp:
  server:
    enabled: true
    ipv4: 198.51.100.1
    ipv6: 2001:db8::1
  urls: []
```

!!! warning "Single point of failure"

    Removing Tailscale's DERP servers means that there is now just a single DERP server available for clients. This is a
    single point of failure and could hamper connectivity.

    [Check DERP server connectivity](#check-derp-server-connectivity) with your embedded DERP server before removing
    Tailscale's DERP servers.

### Customize DERP map

The DERP map offered to clients can be customized with a [dedicated YAML-configuration
file](https://github.com/juanfont/headscale/blob/main/derp-example.yaml). This allows to modify previously loaded DERP
maps fetched via URL or to offer your own, custom DERP servers to nodes.

=== "Remove specific DERP regions"

    The free-to-use [DERP servers](https://tailscale.com/kb/1232/derp-servers) are organized into regions via a region
    ID. You can explicitly disable a specific region by setting its region ID to `null`. The following sample
    `derp.yaml` disables the New York DERP region (which has the region ID 1):

     ```yaml title="derp.yaml"
     regions:
       1: null
     ```

    Use the following configuration to serve the default DERP map (excluding New York) to nodes:

    ```yaml title="config.yaml" hl_lines="6 7"
    derp:
      server:
        enabled: false
      urls:
        - https://controlplane.tailscale.com/derpmap/default
      paths:
        - /etc/headscale/derp.yaml
    ```

=== "Provide custom DERP servers"

    The following sample `derp.yaml` references two custom regions (`custom-east` with ID 900 and `custom-west` with ID 901)
    with one custom DERP server in each region. Each DERP server offers DERP relay via HTTPS on tcp/443, support for captive
    portal checks via HTTP on tcp/80 and STUN on udp/3478. See the definitions of
    [DERPMap](https://pkg.go.dev/tailscale.com/tailcfg#DERPMap),
    [DERPRegion](https://pkg.go.dev/tailscale.com/tailcfg#DERPRegion) and
    [DERPNode](https://pkg.go.dev/tailscale.com/tailcfg#DERPNode) for all available options.

    ```yaml title="derp.yaml"
    regions:
      900:
        regionid: 900
        regioncode: custom-east
        regionname: My region (east)
        nodes:
          - name: 900a
            regionid: 900
            hostname: derp900a.example.com
            ipv4: 198.51.100.1
            ipv6: 2001:db8::1
            canport80: true
      901:
        regionid: 901
        regioncode: custom-west
        regionname: My Region (west)
        nodes:
          - name: 901a
            regionid: 901
            hostname: derp901a.example.com
            ipv4: 198.51.100.2
            ipv6: 2001:db8::2
            canport80: true
    ```

    Use the following configuration to only serve the two DERP servers from the above `derp.yaml`:

    ```yaml title="config.yaml" hl_lines="5 6"
    derp:
      server:
        enabled: false
      urls: []
      paths:
        - /etc/headscale/derp.yaml
    ```

Independent of the custom DERP map, you may choose to [enable the embedded DERP server and have it automatically added
to the custom DERP map](#enable-embedded-derp).

### Verify clients

Access to DERP serves can be restricted to nodes that are members of your Tailnet. Relay access is denied for unknown
clients.

=== "Embedded DERP"

    Client verification is enabled by default.

    ```yaml title="config.yaml" hl_lines="3"
    derp:
      server:
        verify_clients: true
    ```

=== "3rd-party DERP"

    Tailscale's `derper` provides two parameters to configure client verification:

    - Use the `-verify-client-url` parameter of the `derper` and point it towards the `/verify` endpoint of your
      Headscale server (e.g `https://headscale.example.com/verify`). The DERP server will query your Headscale instance
      as soon as a client connects with it to ask whether access should be allowed or denied. Access is allowed if
      Headscale knows about the connecting client and denied otherwise.
    - The parameter `-verify-client-url-fail-open` controls what should happen when the DERP server can't reach the
      Headscale instance. By default, it will allow access if Headscale is unreachable.

## Check DERP server connectivity

Any Tailscale client may be used to introspect the DERP map and to check for connectivity issues with DERP servers.

- Display DERP map: `tailscale debug derp-map`
- Check connectivity with the embedded DERP[^1]:`tailscale debug derp headscale`

Additional DERP related metrics and information is available via the [metrics and debug
endpoint](./debug.md#metrics-and-debug-endpoint).

[^1]:
    This assumes that the default region code of the [configuration file](./configuration.md) is used.

## Limitations

- The embedded DERP server can't be used for Tailscale's captive portal checks as it doesn't support the `/generate_204`
  endpoint via HTTP on port tcp/80.
- There are no speed or throughput optimisations, the main purpose is to assist in node connectivity.
