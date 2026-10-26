package types

import (
	"net/netip"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// MaxRegistrationPayloadBytes limits the owned serialized registration payload
// retained by an [AuthRequest] after [AuthRequest.PrepareForCache]. It covers
// the authentication metadata and the minimal registration Hostinfo.
// It bounds retained serialized bytes, not transient encoding or decoded heap
// usage. A cache of 1024 entries retains at most 64 MiB of these payloads plus
// record overhead; a different entry limit scales that budget.
const MaxRegistrationPayloadBytes = 64 << 10

// RegistrationData is the payload cached for a pending node registration.
// It replaces the previous practice of caching a full *[Node] and carries
// only the fields the registration callback path actually consumes when
// promoting a pending registration to a real node.
//
// Any client can open a pending registration. Cache admission caps the number
// of pending entries. Hostinfo retains only auth and
// confirmation metadata, bounded by [ValidateHostinfo] before caching.
//
// [AuthRequest.PrepareForCache] retains an owned serialized representation
// bounded by [MaxRegistrationPayloadBytes], releasing this decoded payload.
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
