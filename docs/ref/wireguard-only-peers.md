# WireGuard-Only Peers

WireGuard-only peers allow Headscale to integrate external WireGuard endpoints that don't run Tailscale clients. These are statically configured peers that appear in your tailnet alongside regular Tailscale nodes.

## Use Cases

WireGuard-only peers are particularly useful for using commercial VPN providers as exit nodes, like akin to [Tailscale's Mullvad integration](https://tailscale.com/blog/mullvad-integration).

## Important Security Considerations

!!! warning "ACL Bypass"
    **WireGuard-only peers BYPASS ALL ACL POLICIES**. They are explicitly configured by administrators and do not participate in normal policy evaluation. Access control is managed through connections - only nodes with explicit connections to a peer can see and use it.

Because WireGuard-only peers cannot receive dynamic map updates from Headscale, they must be configured with a static list of peers on their side. Only nodes you explicitly connect will have this peer added to their network maps.

## Architecture Overview

The WireGuard-only peer system uses a two-level architecture:

1. **WireGuard-only peer**: Defines the external endpoint's static properties (public key, endpoints, allowed IPs)
2. **Connections**: Define which nodes can access the peer and the per-connection masquerade addresses

This separation allows different nodes to use different masquerade addresses when communicating with the same WireGuard peer, which is essential when the external peer assigns unique IPs to each connection.

## Setup Workflow

### Step 1: Register the WireGuard-Only Peer

Register the peer with its static properties:

```console
$ headscale node register-wg-only \
    --name "mullvad-exit" \
    --user 1 \
    --public-key "xJsw8SNGxKwqPHgULHWY7Z2tPNBJPxKLbJ9FJxDfXr8=" \
    --allowed-ips "0.0.0.0/0,::/0" \
    --endpoints "1.2.3.4:51820" \
    --extra-config '{"suggestExitNode": true}'
```

#### Registration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--name` | Yes | Human-readable name for the peer |
| `--user` | Yes | User ID that owns this peer |
| `--public-key` | Yes | WireGuard public key of the external peer |
| `--allowed-ips` | Yes | Comma-separated list of IP prefixes the peer can route (e.g., `0.0.0.0/0,::/0` for an exit node) |
| `--endpoints` | Yes | Comma-separated list of WireGuard endpoints (e.g., `1.2.3.4:51820,[2001:db8::1]:51820`) |
| `--extra-config` | No | See [extra config](#extra-config) section |

### Step 2: Create Connections to Nodes

After registering the peer, create connections for each node that should access it:

```console
$ headscale node add-wg-connection \
    --node-id 1 \
    --wg-peer-id 100000001 \
    --ipv4-masq-addr "10.64.0.100"

$ headscale node add-wg-connection \
    --node-id 2 \
    --wg-peer-id 100000001 \
    --ipv4-masq-addr "10.64.0.101"
    --ipv6-masq-addr "ff02:b::11"
```

#### Connection Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--node-id` | Yes | ID of the regular Tailscale node to connect |
| `--wg-peer-id` | Yes | ID of the WireGuard-only peer (from registration output) |
| `--ipv4-masq-addr` | * | IPv4 address the external peer expects to see as source IP from this node |
| `--ipv6-masq-addr` | * | IPv6 address the external peer expects to see as source IP from this node |

\* At least one masquerade address must be specified per connection.

### Managing Connections

Remove a connection when a node should no longer access the peer:

```console
$ headscale node remove-wg-connection \
    --node-id 1 \
    --wg-peer-id 100000001
```

## Masquerade Addresses

Masquerade addresses specify the source IP address that the external peer expects to see from your nodes. They are configured per-connection, allowing each node to use a different address.

External WireGuard peers (like commercial VPN providers) expect traffic from specific IP addresses. Headscale nodes normally have tailnet IPs (e.g., `100.64.0.1`), but the external peer might only accept traffic from IPs it has assigned (e.g., `10.64.0.100`). The masquerade address tells Headscale to instruct the node to use this specific source IP when communicating with that peer.

**Example**: If you have two nodes connecting to the same Mullvad server, each would typically receive a different assigned IP from Mullvad. Node 1 might use `10.64.0.100` and Node 2 might use `10.64.0.101` as their masquerade addresses for that connection.

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
and use geographic proximity for automatic exit node suggestions.
