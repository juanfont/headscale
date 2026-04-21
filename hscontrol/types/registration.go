package types

import (
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// RegistrationData is the payload cached for a pending node registration.
// It replaces the previous practice of caching a full *Node and carries
// only the fields the registration callback path actually consumes when
// promoting a pending registration to a real node.
//
// Combined with the bounded-LRU cache that holds these entries, this caps
// the worst-case memory footprint of unauthenticated cache-fill attempts
// at (max_entries × per_entry_size). The cache is sized so that the
// product is bounded to a few MiB even with attacker-supplied 1 MiB
// Hostinfos (the Noise body limit).
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

	// Hostinfo is the original Hostinfo from the RegisterRequest,
	// stored so that the auth callback can populate the new node's
	// initial Hostinfo (and so that observability/CLI consumers see
	// fields like OS, OSVersion, and IPNVersion before the first
	// MapRequest restores the live set).
	//
	// May be nil if the client did not send Hostinfo in the original
	// RegisterRequest.
	Hostinfo *tailcfg.Hostinfo

	// Endpoints is the initial set of WireGuard endpoints the node
	// reported. The first MapRequest after registration overwrites
	// this with the live set.
	Endpoints []netip.AddrPort

	// Expiry is the optional client-requested expiry for this node.
	// May be nil if the client did not request a specific expiry.
	Expiry *time.Time
}
