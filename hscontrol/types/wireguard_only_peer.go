package types

import (
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

// WireGuardOnlyPeer represents an external WireGuard peer that does not run
// a full Tailscale client. These peers are manually configured and statically defined.
//
// IMPORTANT: WireGuard-only peers BYPASS ACL POLICIES. They are explicitly configured
// by administrators and do not participate in the normal policy evaluation flow.
// Access control is managed solely through the KnownNodeIDs field, which determines
// which regular nodes can see this peer.
type WireGuardOnlyPeer struct {
	ID uint64 `gorm:"primary_key"`

	// Human-readable name for the peer (must be unique)
	Name string `gorm:"unique;not null"`

	UserID uint
	User   User `gorm:"constraint:OnDelete:CASCADE;"`

	// WireGuard public key of the external peer
	PublicKey key.NodePublic `gorm:"serializer:text;not null"`

	// List of node IDs that can see this WireGuard-only peer
	// Only nodes in this list will have the peer in their network map
	// This is unidirectional - the WG-only peer doesn't get map updates
	KnownNodeIDs []uint64 `gorm:"serializer:json;not null"`

	// AllowedIPs that the WireGuard-only peer is allowed to route
	// Typically includes exit routes like 0.0.0.0/0 and ::/0
	AllowedIPs []netip.Prefix `gorm:"serializer:json;not null"`

	// WireGuard endpoints where the peer can be reached
	Endpoints []netip.AddrPort `gorm:"serializer:json;not null"`

	// Source IP addresses that the WireGuard-only peer expects to see from our nodes
	// At least one of these must be set
	SelfIPv4MasqAddr *netip.Addr `gorm:"serializer:text"`
	SelfIPv6MasqAddr *netip.Addr `gorm:"serializer:text"`

	// Auto-allocated tailnet IP addresses for the peer
	// These are allocated using the same algorithm as regular nodes
	IPv4 *netip.Addr `gorm:"column:ipv4;serializer:text"`
	IPv6 *netip.Addr `gorm:"column:ipv6;serializer:text"`

	// DNS resolvers to use when this peer is used as an exit node
	ExitNodeDNSResolvers []string `gorm:"serializer:json"`

	// Whether to suggest this peer as an exit node to clients
	SuggestExitNode bool `gorm:"default:false"`

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
		Id:                p.ID,
		Name:              p.Name,
		User:              p.User.Proto(),
		PublicKey:         p.PublicKey.String(),
		KnownNodeIds:      p.KnownNodeIDs,
		AllowedIps:        prefixesToString(p.AllowedIPs),
		Endpoints:         addrPortsToString(p.Endpoints),
		SuggestExitNode:   p.SuggestExitNode,
		CreatedAt:         timestamppb.New(p.CreatedAt),
		UpdatedAt:         timestamppb.New(p.UpdatedAt),
	}

	if p.SelfIPv4MasqAddr != nil {
		peer.SelfIpv4MasqAddr = stringPtr(p.SelfIPv4MasqAddr.String())
	}

	if p.SelfIPv6MasqAddr != nil {
		peer.SelfIpv6MasqAddr = stringPtr(p.SelfIPv6MasqAddr.String())
	}

	if p.IPv4 != nil {
		peer.Ipv4 = p.IPv4.String()
	}

	if p.IPv6 != nil {
		peer.Ipv6 = p.IPv6.String()
	}

	if len(p.ExitNodeDNSResolvers) > 0 {
		peer.ExitNodeDnsResolvers = p.ExitNodeDNSResolvers
	}

	return peer
}

// ToTailcfgNode converts a WireGuardOnlyPeer to a tailcfg.Node for inclusion
// in network maps sent to regular Tailscale clients.
func (p *WireGuardOnlyPeer) ToTailcfgNode() (*tailcfg.Node, error) {
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

		Online: nil,
		IsWireGuardOnly: true,
		IsJailed:        true,

		Expired: false,
		Created: p.CreatedAt.UTC(),
	}

	if p.SelfIPv4MasqAddr != nil {
		node.SelfNodeV4MasqAddrForThisPeer = p.SelfIPv4MasqAddr
	}

	if p.SelfIPv6MasqAddr != nil {
		node.SelfNodeV6MasqAddrForThisPeer = p.SelfIPv6MasqAddr
	}

	node.CapMap = tailcfg.NodeCapMap{}

	if p.SuggestExitNode {
		node.CapMap[tailcfg.NodeAttrSuggestExitNode] = nil
	}

	if len(p.ExitNodeDNSResolvers) > 0 {
		node.ExitNodeDNSResolvers = make([]*dnstype.Resolver, 0, len(p.ExitNodeDNSResolvers))
		for _, resolver := range p.ExitNodeDNSResolvers {
			node.ExitNodeDNSResolvers = append(node.ExitNodeDNSResolvers, &dnstype.Resolver{
				Addr: resolver,
			})
		}
	}

	return node, nil
}

// Validate checks if the WireGuardOnlyPeer has valid configuration
func (p *WireGuardOnlyPeer) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("name cannot be empty")
	}

	if p.PublicKey.IsZero() {
		return fmt.Errorf("public key cannot be empty")
	}

	if len(p.KnownNodeIDs) == 0 {
		return fmt.Errorf("at least one known node ID must be specified")
	}

	if len(p.AllowedIPs) == 0 {
		return fmt.Errorf("at least one allowed IP must be specified")
	}

	if len(p.Endpoints) == 0 {
		return fmt.Errorf("at least one endpoint must be specified")
	}

	if p.SelfIPv4MasqAddr == nil && p.SelfIPv6MasqAddr == nil {
		return fmt.Errorf("at least one masquerade address (IPv4 or IPv6) must be specified")
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

func stringPtr(s string) *string {
	return &s
}
