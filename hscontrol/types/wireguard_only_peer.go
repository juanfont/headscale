package types

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
)

const WireGuardOnlyPeerIDOffset = 100_000_000

// WireGuardOnlyPeerExtraConfig holds optional configuration for a WireGuard-only peer.
// This is stored as JSON in the database and allows configuring exit node behavior,
// tags, and location data for proximity-based exit node selection.
type WireGuardOnlyPeerExtraConfig struct {
	ExitNodeDNSResolvers []string          `json:"exitNodeDNSResolvers,omitempty"`
	SuggestExitNode      *bool             `json:"suggestExitNode,omitempty"`
	Tags                 []string          `json:"tags,omitempty"`
	Location             *tailcfg.Location `json:"location,omitempty"`
}

// WireGuardOnlyPeer represents an external WireGuard peer that does not run
// a full Tailscale client. These peers are manually configured and statically defined.
//
// IMPORTANT: WireGuard-only peers BYPASS ACL POLICIES. They are explicitly configured
// by administrators and do not participate in the normal policy evaluation flow.
// Access control is managed through the node_wg_peer_connections table, which defines
// which regular nodes can see this peer and stores per-connection masquerade addresses.
type WireGuardOnlyPeer struct {
	ID NodeID `gorm:"primary_key"`

	// Human-readable name for the peer (must be unique)
	Name string `gorm:"unique;not null"`

	UserID UserID
	User   User `gorm:"constraint:OnDelete:CASCADE;"`

	// WireGuard public key of the external peer
	PublicKey key.NodePublic `gorm:"serializer:text;not null"`

	// AllowedIPs that the WireGuard-only peer is allowed to route
	// Typically includes exit routes like 0.0.0.0/0 and ::/0
	AllowedIPs []netip.Prefix `gorm:"serializer:json;not null"`

	// WireGuard endpoints where the peer can be reached
	Endpoints []netip.AddrPort `gorm:"serializer:json;not null"`

	// Auto-allocated tailnet IP addresses for the peer
	// These are allocated using the same algorithm as regular nodes
	IPv4 *netip.Addr `gorm:"column:ipv4;serializer:text"`
	IPv6 *netip.Addr `gorm:"column:ipv6;serializer:text"`

	// Extra configuration stored as JSON (exit node settings, tags, location)
	ExtraConfig *WireGuardOnlyPeerExtraConfig `gorm:"serializer:json"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type WireGuardOnlyPeers []*WireGuardOnlyPeer

// TableName overrides the default table name used by GORM.
// Without this method, GORM would create a table named "wire_guard_only_peers"
// but we instead want "wireguard_only_peers".
func (WireGuardOnlyPeer) TableName() string {
	return "wireguard_only_peers"
}

func (p *WireGuardOnlyPeer) IPs() []netip.Addr {
	var ret []netip.Addr

	if p.IPv4 != nil {
		ret = append(ret, *p.IPv4)
	}

	if p.IPv6 != nil {
		ret = append(ret, *p.IPv6)
	}

	return ret
}

// Prefixes returns the IP addresses as /32 or /128 prefixes
func (p *WireGuardOnlyPeer) Prefixes() []netip.Prefix {
	var addrs []netip.Prefix
	for _, ip := range p.IPs() {
		prefix := netip.PrefixFrom(ip, ip.BitLen())
		addrs = append(addrs, prefix)
	}
	return addrs
}

// Proto converts the WireGuardOnlyPeer to protobuf representation
func (p *WireGuardOnlyPeer) Proto() *v1.WireGuardOnlyPeer {
	peer := &v1.WireGuardOnlyPeer{
		Id:         uint64(p.ID),
		Name:       p.Name,
		User:       p.User.Proto(),
		PublicKey:  p.PublicKey.String(),
		AllowedIps: prefixesToString(p.AllowedIPs),
		Endpoints:  addrPortsToString(p.Endpoints),
		CreatedAt:  timestamppb.New(p.CreatedAt),
		UpdatedAt:  timestamppb.New(p.UpdatedAt),
	}

	if p.IPv4 != nil {
		peer.Ipv4 = p.IPv4.String()
	}

	if p.IPv6 != nil {
		peer.Ipv6 = p.IPv6.String()
	}

	if p.ExtraConfig != nil {
		extraConfigJSON, _ := json.Marshal(p.ExtraConfig)
		peer.ExtraConfig = string(extraConfigJSON)
	}

	return peer
}

// ToTailcfgNode converts a WireGuardOnlyPeer to a tailcfg.Node for inclusion
// in network maps sent to regular Tailscale clients. The connection parameter
// provides the per-node masquerade addresses for this specific node-to-peer relationship.
func (p *WireGuardOnlyPeer) ToTailcfgNode(connection *WireGuardConnection) (*tailcfg.Node, error) {
	addresses := p.Prefixes()

	node := &tailcfg.Node{
		ID:       tailcfg.NodeID(p.ID),
		StableID: tailcfg.StableNodeID(fmt.Sprintf("wg-only-%d", p.ID)),
		Name:     p.Name,

		User: tailcfg.UserID(p.UserID),

		Key: p.PublicKey,

		Machine:  key.MachinePublic{},
		DiscoKey: key.DiscoPublic{},

		Addresses:     addresses,
		AllowedIPs:    p.AllowedIPs,
		PrimaryRoutes: nil,
		Endpoints:     p.Endpoints,

		// We have no way of knowing whether the WireGuard-only peer is actually online.
		// The Android app (and maybe other clients) prevent us from setting offline
		// nodes as exit nodes so this needs to be true.
		Online:          ptrTo(true),
		IsWireGuardOnly: true,
		IsJailed:        true,

		Expired: false,
		Created: p.CreatedAt.UTC(),
	}

	if connection.IPv4MasqAddr != nil {
		node.SelfNodeV4MasqAddrForThisPeer = connection.IPv4MasqAddr
	}

	if connection.IPv6MasqAddr != nil {
		node.SelfNodeV6MasqAddrForThisPeer = connection.IPv6MasqAddr
	}

	if p.ExtraConfig != nil {
		if len(p.ExtraConfig.Tags) > 0 {
			node.Tags = p.ExtraConfig.Tags
		}

		if len(p.ExtraConfig.ExitNodeDNSResolvers) > 0 {

			node.ExitNodeDNSResolvers = make([]*dnstype.Resolver, 0, len(p.ExtraConfig.ExitNodeDNSResolvers))
			for _, resolver := range p.ExtraConfig.ExitNodeDNSResolvers {
				node.ExitNodeDNSResolvers = append(node.ExitNodeDNSResolvers, &dnstype.Resolver{
					Addr: resolver,
				})
			}
		}

		if p.ExtraConfig.SuggestExitNode != nil && *p.ExtraConfig.SuggestExitNode {
			node.CapMap = tailcfg.NodeCapMap{}
			node.CapMap[tailcfg.NodeAttrSuggestExitNode] = nil
		}

		if p.ExtraConfig.Location != nil {
			node.Hostinfo = (&tailcfg.Hostinfo{
				Hostname: p.Name,
				Location: p.ExtraConfig.Location,
			}).View()
		}
	}

	return node, nil
}

// Validate checks if the WireGuardOnlyPeer has valid configuration.
func (p *WireGuardOnlyPeer) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if p.PublicKey.IsZero() {
		return fmt.Errorf("public key cannot be empty")
	}

	if len(p.AllowedIPs) == 0 {
		return fmt.Errorf("at least one allowed IP must be specified")
	}

	if len(p.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint must be specified")
	}

	return nil
}

func prefixesToString(prefixes []netip.Prefix) []string {
	result := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		result = append(result, prefix.String())
	}
	return result
}

func addrPortsToString(addrPorts []netip.AddrPort) []string {
	result := make([]string, 0, len(addrPorts))
	for _, ap := range addrPorts {
		result = append(result, ap.String())
	}
	return result
}

func ptrTo[T any](value T) *T {
	return &value
}
