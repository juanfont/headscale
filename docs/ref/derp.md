# DERP

A [DERP (Designated Encrypted Relay for Packets) server](https://tailscale.com/docs/reference/derp-servers) is mainly
used to relay traffic between two nodes in case a direct connection can't be established. Headscale provides an embedded
DERP server to ensure seamless connectivity between nodes.

## Configuration

DERP related settings are configured within the `derp` section of the [configuration file](configuration.md). The
following sections only use a few of the available settings; [`derp`](configuration-options.md#derp) in the
configuration options lists all of them.

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
servers](https://tailscale.com/docs/reference/derp-servers) offered by Tailscale Inc. To only use Headscale's embedded
DERP server, disable the loading of the default DERP map:

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
file](https://github.com/juanfont/headscale/blob/main/derp-example.yaml). The file extension picks the format: `.yaml`
or `.yml`, or the JSON format Tailscale serves DERP maps in as `.json` or `.hujson`. Both JSON extensions are read as
[HuJSON](https://github.com/tailscale/hujson), so comments and trailing commas are allowed. This allows to modify previously
loaded DERP maps fetched via URL or to offer your own, custom DERP servers to nodes. A file with a key that has no field
in [DERPMap](https://pkg.go.dev/tailscale.com/tailcfg#DERPMap) fails to load. So does a region whose `regionid` differs
from its key, a node whose `regionid` differs from its region, or a region without nodes: clients count latency by
`regionid`.

A `derp.urls` or `derp.paths` source that fails to load, for example a URL that is down or a file with an error, is
logged as a warning and skipped. Headscale starts with the DERP regions from the other sources, the embedded DERP server
and the policy's `derpMap`, and refuses to start only when no region remains. A refresh with a failing source keeps the
previous DERP map. A skipped file also skips what it removes: a region it sets to `null` comes back.

=== "Remove specific DERP regions"

    The free-to-use [DERP servers](https://tailscale.com/docs/reference/derp-servers) are organized into regions via a
    region ID. You can explicitly disable a specific region by setting its region ID to `null`. The following sample
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

=== "Prefer or avoid DERP regions"

    Each client picks its home DERP region by latency. A region score multiplies the latency a client measures for a
    region before it compares regions: a score below 1 makes a region more attractive, a score above 1 less attractive.
    Regions without a score count as 1, scores of 0 or below are ignored. See
    [DERPHomeParams](https://pkg.go.dev/tailscale.com/tailcfg#DERPHomeParams).

    The following sample `derp.yaml` prefers the embedded DERP server (region ID 999) and avoids New York (region ID 1).
    The file may hold scores alone, the regions come from other sources:

    ```yaml title="derp.yaml"
    homeparams:
      regionscore:
        999: 0.5
        1: 2
    ```

    The same in a `.json` or `.hujson` file is `{"HomeParams": {"RegionScore": {"999": 0.5, "1": 2}}}`.

    A score biases the choice, it does not pin it: a client keeps its home region unless another one is clearly faster
    after scaling. Connected clients keep a score that is removed from the file until they reconnect; set it to `1`
    instead to reset it.

Independent of the custom DERP map, you may choose to [enable the embedded DERP server and have it automatically added
to the custom DERP map](#enable-embedded-derp).

### Customize the DERP map in the policy

The [policy](policy.md#network-wide-policy-options) may hold a `derpMap`, as on Tailscale. It changes the DERP map from
the configuration above, and connected nodes get the change as soon as the policy is updated. Headscale checks it like
Tailscale does:

- A region added in the policy needs a region ID from 900 to 999 and at least one node. Its `RegionID`, and the `RegionID`
  of each node, must match the ID it is listed under. A policy region replaces a configured region with the same ID,
  such as the embedded DERP server's.
- A node's `HostName` and `CertName` must not be `tailscale.com` or one of its subdomains. Tailscale also rejects the IP
  addresses of its own DERP servers; Headscale does not, as that needs Tailscale's current list of servers.
- A region set to `null` is removed. This works for any region ID.
- `OmitDefaultRegions: true` removes every region from the configuration, the embedded DERP server's included, and
  needs at least one region added in the policy.
- `HomeParams` is accepted but ignored, as on Tailscale. Set region scores in a `derp.paths` file instead.

```json title="policy.json"
{
  "derpMap": {
    "Regions": {
      "1": null,
      "900": {
        "RegionID": 900,
        "RegionCode": "custom",
        "RegionName": "My region",
        "Nodes": [{"Name": "900a", "RegionID": 900, "HostName": "derp900.example.com"}]
      }
    }
  }
}
```

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
endpoint](debug.md#metrics-and-debug-endpoint).

## Limitations

- The embedded DERP server can't be used for Tailscale's captive portal checks as it doesn't support the `/generate_204`
  endpoint via HTTP on port tcp/80.
- There are no speed or throughput optimisations, the main purpose is to assist in node connectivity.

[^1]: This assumes that the default region code of the [configuration file](configuration.md) is used.
