package types

import (
	"fmt"
	"net/netip"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// WireGuardConnection represents a connection between a regular node and a WireGuard-only peer.
// This join table allows each node to have unique masquerade addresses when communicating with
// the same WireGuard peer.
type WireGuardConnection struct {
	// NodeID is the ID of the regular Tailscale node
	NodeID NodeID `gorm:"primaryKey;column:node_id"`

	// WGPeerID is the ID of the WireGuard-only peer that the ndoe above can access
	WGPeerID NodeID `gorm:"primaryKey;column:wg_peer_id"`

	// IPv4MasqAddr is the masquerade address that our node will use when communicating with this peer
	// This is the source IP the WireGuard peer expects to see
	IPv4MasqAddr *netip.Addr `gorm:"column:ipv4_masq_addr;serializer:text"`

	// IPv6MasqAddr is the IPv6 masquerade address (optional, but at least one masq addr must be set)
	IPv6MasqAddr *netip.Addr `gorm:"column:ipv6_masq_addr;serializer:text"`

	CreatedAt time.Time `gorm:"column:created_at"`
}

// WireGuardConnections is a slice of WireGuardConnection pointers.
type WireGuardConnections []*WireGuardConnection

// TableName overrides the default table name used by GORM.
func (WireGuardConnection) TableName() string {
	return "node_wg_peer_connections"
}

// Validate checks that the connection has at least one masquerade address set.
func (c *WireGuardConnection) Validate() error {
	if c.IPv4MasqAddr == nil && c.IPv6MasqAddr == nil {
		return fmt.Errorf("connection must have at least one masquerade address")
	}
	return nil
}

// ToProto converts a WireGuardConnection to its protobuf representation.
func (c *WireGuardConnection) ToProto() *v1.WireGuardConnection {
	conn := &v1.WireGuardConnection{
		NodeId:   uint64(c.NodeID),
		WgPeerId: uint64(c.WGPeerID),
	}

	if c.IPv4MasqAddr != nil {
		addrStr := c.IPv4MasqAddr.String()
		conn.Ipv4MasqAddr = &addrStr
	}

	if c.IPv6MasqAddr != nil {
		addrStr := c.IPv6MasqAddr.String()
		conn.Ipv6MasqAddr = &addrStr
	}

	conn.CreatedAt = timestamppb.New(c.CreatedAt)

	return conn
}

// ProtoToConnection converts a protobuf WireGuardConnection to the internal type.
func ProtoToConnection(proto *v1.WireGuardConnection) (*WireGuardConnection, error) {
	conn := &WireGuardConnection{
		NodeID:   NodeID(proto.NodeId),
		WGPeerID: NodeID(proto.WgPeerId),
	}

	if proto.Ipv4MasqAddr != nil && *proto.Ipv4MasqAddr != "" {
		addr, err := netip.ParseAddr(*proto.Ipv4MasqAddr)
		if err != nil {
			return nil, fmt.Errorf("parsing IPv4 masquerade address: %w", err)
		}
		conn.IPv4MasqAddr = &addr
	}

	if proto.Ipv6MasqAddr != nil && *proto.Ipv6MasqAddr != "" {
		addr, err := netip.ParseAddr(*proto.Ipv6MasqAddr)
		if err != nil {
			return nil, fmt.Errorf("parsing IPv6 masquerade address: %w", err)
		}
		conn.IPv6MasqAddr = &addr
	}

	if err := conn.Validate(); err != nil {
		return nil, err
	}

	return conn, nil
}

// WireGuardConnectionWithPeer combines a connection with its associated WireGuard-only peer.
// This type is used to atomically fetch both pieces of data from a single NodeStore snapshot,
// eliminating TOCTOU race conditions in hot paths like MapResponse generation.
type WireGuardConnectionWithPeer struct {
	Connection *WireGuardConnection
	Peer       *WireGuardOnlyPeer
}
