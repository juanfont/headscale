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
// holds these entries caps their number. Hostinfo retains only auth and
// confirmation metadata, bounded by [ValidateHostinfo] before caching.
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

	// Hostinfo carries hostname and requested tags for auth, and OS for the
	// confirmation page. Other fields arrive in the first MapRequest.
	// It may be nil when the registration did not include Hostinfo.
	Hostinfo *tailcfg.Hostinfo

	// Endpoints is the initial set of WireGuard endpoints the node
	// reported. The first [tailcfg.MapRequest] after registration overwrites
	// this with the live set.
	Endpoints []netip.AddrPort

	// Expiry is the optional client-requested expiry for this node.
	// May be nil if the client did not request a specific expiry.
	Expiry *time.Time
}
