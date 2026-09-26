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
// Hostinfo is a bounded projection created at admission time rather than the
// full client request, keeping the count-bounded cache within a predictable
// memory budget.
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

	// Hostinfo contains only bounded identity/display fields and RequestTags.
	// The first [tailcfg.MapRequest] restores live network and service state.
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
