package types

import (
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// RegistrationData is the payload cached for a pending node registration.
// It replaces the previous practice of caching a full *[Node] and carries
// only the fields the registration callback path actually consumes when
// promoting a pending registration to a real node.
//
// Any client can open a pending registration. The bounded-LRU cache that
// holds these entries caps their number, and each entry stays small: its
// Hostinfo is bounded at decode ([BoundHostinfo]) and kept without routes.
type RegistrationData struct {
	// MachineKey is the cryptographic identity of the machine being
	// registered. Required.
	MachineKey key.MachinePublic

	// NodeKey is the cryptographic identity of the node session.
	// Required.
	NodeKey key.NodePublic

	// DiscoKey is the disco public key for peer-to-peer connections.
	DiscoKey key.DiscoPublic

	// Hostname is the resolved hostname for the registering node.
	// Already validated/normalised by EnsureHostname at producer time.
	Hostname string

	// Hostinfo is the [tailcfg.Hostinfo] from the [tailcfg.RegisterRequest]
	// without its routes, stored so that the auth callback can populate the
	// new node's initial [tailcfg.Hostinfo] (and so that observability/CLI
	// consumers see fields like OS, OSVersion, and IPNVersion before the
	// first [tailcfg.MapRequest] restores the live set, routes included).
	//
	// May be nil if the client did not send [tailcfg.Hostinfo] in the original
	// [tailcfg.RegisterRequest].
	Hostinfo *tailcfg.Hostinfo

	// Endpoints is the initial set of WireGuard endpoints the node
	// reported. The first [tailcfg.MapRequest] after registration overwrites
	// this with the live set.
	Endpoints []netip.AddrPort

	// Expiry is the optional client-requested expiry for this node.
	// May be nil if the client did not request a specific expiry.
	Expiry *time.Time
}
