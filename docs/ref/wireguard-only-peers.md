# WireGuard-Only Peers

WireGuard-only peers allow Headscale to integrate external WireGuard endpoints that don't run Tailscale clients. These are statically configured peers that appear in your tailnet alongside regular Tailscale nodes.

## Use Cases

WireGuard-only peers are particularly useful for using commercial VPN providers as exit nodes, like akin to [Tailscale's Mullvad integration](https://tailscale.com/blog/mullvad-integration).

## Important Security Considerations

!!! warning "ACL Bypass"
    **WireGuard-only peers BYPASS ALL ACL POLICIES**. They are explicitly configured by administrators and do not participate in normal policy evaluation. Access control is managed solely through the `--known-nodes` parameter, which determines which regular nodes can see the peer.

Because WireGuard-only peers cannot receive dynamic map updates from Headscale, they must be configured with a static list of peers on their side. Only the nodes you specify will have this peer added to their network maps.

## Prerequisites

Before registering a WireGuard-only peer, you need:

1. The WireGuard public key of the external peer
2. The endpoint (IP address and port) where the peer can be reached
3. The routes (allowed IPs) that peer should handle
4. At least one masquerade address (see [Masquerade Addresses](#masquerade-addresses))
5. The node IDs of regular Tailscale nodes that should see this peer

## Register a WireGuard-Only Peer

### Basic Registration

Register a WireGuard-only peer using the `headscale node register-wg-only` command:

```console
$ headscale node register-wg-only \
    --name "mullvad-exit" \
    --user 1 \
    --public-key "xJsw8SNGxKwqPHgULHWY7Z2tPNBJPxKLbJ9FJxDfXr8=" \
    --known-nodes "1,2,3" \
    --allowed-ips "0.0.0.0/0,::/0" \
    --endpoints "1.2.3.4:51820" \
    --self-ipv4-masq-addr "10.64.0.100" \
    --suggest-exit-node
```

### Command Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--name` | Yes | Human-readable name for the peer |
| `--user` | Yes | User ID that owns this peer |
| `--public-key` | Yes | WireGuard public key of the external peer |
| `--known-nodes` | Yes | Comma-separated list of node IDs that can see this peer |
| `--allowed-ips` | Yes | Comma-separated list of IP prefixes the peer can route (e.g., `0.0.0.0/0,::/0` for an exit node) |
| `--endpoints` | Yes | Comma-separated list of WireGuard endpoints (e.g., `1.2.3.4:51820,[2001:db8::1]:51820`) |
| `--self-ipv4-masq-addr` | * | IPv4 address the external peer expects to see as source IP from your nodes |
| `--self-ipv6-masq-addr` | * | IPv6 address the external peer expects to see as source IP from your nodes |
| `--extra-config` | No | See [extra config](#Extra-Config) section |

\* At least one masquerade address (`--self-ipv4-masq-addr` or `--self-ipv6-masq-addr`) must be specified.

### Masquerade Addresses

Masquerade addresses are critical for WireGuard-only peers to work correctly. They specify the source IP address that the external peer expects to see from your nodes.

External WireGuard peers (like commercial VPN providers) expect traffic from specific IP addresses. Headscale nodes normally have tailnet IPs (e.g., `100.64.0.1`), but the external peer might only accept traffic from IPs it has assigned (e.g., `123.1.0.100`). The masquerade address tells Headscale to instruct your nodes to use this specific source IP when communicating with the peer.

### Extra Config

The --extra-config parameter accepts a JSON object with optional fields to configure
exit node behavior, tags, and geographic location for Tailscale/Android client integration.

Available fields:
  - exitNodeDNSResolvers: Array of DNS server addresses to use when this peer is an exit node
  - suggestExitNode: Boolean to suggest this peer as an exit node to clients
  - tags: Array of tags to apply to this peer
  - location: Geographic location object for proximity-based exit node selection

Location object fields (all fields required if location is provided):
  - country: User-friendly country name (e.g., "Sweden")
  - countryCode: ISO 3166-1 alpha-2 code in uppercase (e.g., "SE")
  - city: User-friendly city name (e.g., "Stockholm")
  - cityCode: Short code for the city in uppercase (e.g., "sto")
  - latitude: Geographic latitude in degrees (e.g., 59.3293)
  - longitude: Geographic longitude in degrees (e.g., 18.0686)
  - priority: Integer priority for "best available" selection (higher = better)

Example:
```json
{
    "exitNodeDNSResolvers": ["10.64.0.1"],
    "suggestExitNode": true,
    "location": {
        "country": "Sweden",
        "countryCode": "SE",
        "city": "Stockholm",
        "cityCode": "sto",
        "latitude": 59.3293,
        "longitude": 18.0686,
        "priority": 100
    }
}
```

#### Android Client Display

When location data is provided, the Android Tailscale client will display the
exit node with a flag emoji and formatted name: "🇸🇪 Sweden: Stockholm",
and use geographic proximity for automatic exit node selection
