// Package state provides pure functions for processing [tailcfg.MapRequest] data.
// These functions are extracted from [State.UpdateNodeFromMapRequest] to improve
// testability and maintainability.

package state

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// mapRequestDelta carries the classified facts extracted from one MapRequest
// against the currently-stored node. It separates the raw wire-level peer
// change (what the client actually sent) from the broadcast/persist/policy
// decisions made from it, so that each downstream decision (broadcast, persist,
// policy refresh, relation rebuild) sees only its own input.
//
// Construction happens once per MapRequest inside the NodeStore write callback
// (so comparisons run against serialized current state); classification happens
// after the write succeeds. Splitting these avoids redoing comparisons and
// avoids having the broadcast classifier depend on incidental branch order.
type mapRequestDelta struct {
	// peerChange is the wire-level delta produced by
	// [types.Node.PeerChangeFromMapRequest] - LastSeen is always stamped.
	peerChange tailcfg.PeerChange

	// hostinfoChanged reports whether anything in Hostinfo changed apart
	// from PreferredDERP (tracked by derpChanged) and DERP latency jitter.
	// It gates storing and persisting the new Hostinfo.
	hostinfoChanged bool

	// peerHostinfoChanged reports whether a Hostinfo field that peers read
	// changed (see [peerHostinfo]). Only that forces a whole-node resend.
	peerHostinfoChanged bool

	// dnsMetadataChanged reports whether a Hostinfo field feeding the
	// node's NextDNS device metadata (Hostname, OS) changed.
	dnsMetadataChanged bool

	// routesChanged reports whether announced routes (RoutableIPs)
	// changed. Routes are policy and election inputs, so they are tracked
	// on their own.
	routesChanged bool

	// derpChanged reports whether PreferredDERP changed. oldDERP/newDERP
	// carry the values; DERP zero means "unchanged" on the wire, so
	// clearing DERP to zero cannot be sent as a patch and forces a
	// whole-peer update.
	derpChanged      bool
	oldDERP, newDERP int

	// endpointBroadcast reports whether the endpoint delta is worth fanning
	// out (i.e., a newly-added useful non-STUN endpoint). Storage still
	// happens regardless; this gates only broadcast.
	endpointBroadcast bool

	// keyChanged and discoKeyChanged report whether the node's wire keys
	// changed. Key patches already carry the resulting endpoints/expiry,
	// so a key change subsumes endpoint/DERP patches.
	keyChanged      bool
	discoKeyChanged bool

	// persistWorthy reports whether the request carries data that should
	// hit the database. LastSeen-only updates are not persist-worthy.
	persistWorthy bool
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler].
func (d mapRequestDelta) MarshalZerologObject(e *zerolog.Event) {
	e.Bool("hostinfo.changed", d.hostinfoChanged).
		Bool("hostinfo.peer_changed", d.peerHostinfoChanged).
		Bool("routes.changed", d.routesChanged).
		Bool("derp.changed", d.derpChanged).
		Int("derp.old", d.oldDERP).
		Int("derp.new", d.newDERP).
		Bool("endpoint.broadcast", d.endpointBroadcast).
		Bool("key.changed", d.keyChanged).
		Bool("disco_key.changed", d.discoKeyChanged).
		Bool("persist", d.persistWorthy)
}

// netInfoFromMapRequest determines the correct [tailcfg.NetInfo] to use.
// Returns the [tailcfg.NetInfo] that should be used for this request.
func netInfoFromMapRequest(
	nodeID types.NodeID,
	currentHostinfo *tailcfg.Hostinfo,
	reqHostinfo *tailcfg.Hostinfo,
) *tailcfg.NetInfo {
	// If request has [tailcfg.NetInfo], use it
	if reqHostinfo != nil && reqHostinfo.NetInfo != nil {
		return reqHostinfo.NetInfo
	}

	// Otherwise, use current [tailcfg.NetInfo] if available
	if currentHostinfo != nil && currentHostinfo.NetInfo != nil {
		log.Debug().
			Caller().
			Uint64(zf.NodeID, nodeID.Uint64()).
			Int(zf.DERP, currentHostinfo.NetInfo.PreferredDERP).
			Msg("using NetInfo from previous Hostinfo in MapRequest")

		return currentHostinfo.NetInfo
	}

	// No [tailcfg.NetInfo] available anywhere - log for debugging
	var hostname string
	if reqHostinfo != nil {
		hostname = reqHostinfo.Hostname
	} else if currentHostinfo != nil {
		hostname = currentHostinfo.Hostname
	}

	log.Debug().
		Caller().
		Uint64(zf.NodeID, nodeID.Uint64()).
		Str(zf.Hostname, hostname).
		Msg("node sent update but has no NetInfo in request or database")

	return nil
}

// hostinfoDERP returns the PreferredDERP value from a Hostinfo, or 0 when
// either pointer is nil. 0 is the wire "unchanged" sentinel.
func hostinfoDERP(hi *tailcfg.Hostinfo) int {
	if hi == nil || hi.NetInfo == nil {
		return 0
	}

	return hi.NetInfo.PreferredDERP
}

// hostinfoEqual reports whether two Hostinfo values are the same apart from
// PreferredDERP, which the caller tracks on its own, and DERP latency
// jitter, which [tailcfg.NetInfo.BasicallyEqual] skips.
func hostinfoEqual(oldHI, newHI *tailcfg.Hostinfo) bool {
	if oldHI == nil || newHI == nil {
		return oldHI == newHI
	}

	if !netInfoEqualIgnoringDERP(oldHI.NetInfo, newHI.NetInfo) {
		return false
	}

	// NetInfo is compared above; drop it so nil-vs-empty inside it does
	// not leak through reflect.DeepEqual.
	oldCopy := *oldHI
	oldCopy.NetInfo = nil
	newCopy := *newHI
	newCopy.NetInfo = nil

	return oldCopy.Equal(&newCopy)
}

// peerHostinfoEqual reports whether a and b agree on the Hostinfo fields
// another node's client reads from a peer: what tailscale status shows, PeerAPI
// services, SSH known hosts, exit-node location, app-connector eligibility, and
// the routes this server feeds into policy. Everything else is stored but never
// fanned out, and a peer's NetInfo is never read at all.
func peerHostinfoEqual(a, b tailcfg.HostinfoView) bool {
	if !a.Valid() || !b.Valid() {
		return a.Valid() == b.Valid()
	}

	return a.Hostname() == b.Hostname() &&
		a.OS() == b.OS() &&
		servicesEqual(a.Services(), b.Services()) &&
		views.SliceEqual(a.SSH_HostKeys(), b.SSH_HostKeys()) &&
		locationEqual(a.Location(), b.Location()) &&
		a.AppConnector() == b.AppConnector() &&
		views.SliceEqual(a.RoutableIPs(), b.RoutableIPs())
}

// servicesEqual compares field by field, as [tailcfg.Service] is
// incomparable.
func servicesEqual(a, b views.Slice[tailcfg.Service]) bool {
	if a.Len() != b.Len() {
		return false
	}

	for i := range a.Len() {
		x, y := a.At(i), b.At(i)
		if x.Proto != y.Proto || x.Port != y.Port || x.Description != y.Description {
			return false
		}
	}

	return true
}

// locationEqual compares field by field, as [tailcfg.LocationView] has no
// Equal.
func locationEqual(a, b tailcfg.LocationView) bool {
	if !a.Valid() || !b.Valid() {
		return a.Valid() == b.Valid()
	}

	return a.Country() == b.Country() &&
		a.CountryCode() == b.CountryCode() &&
		a.City() == b.City() &&
		a.CityCode() == b.CityCode() &&
		a.Latitude() == b.Latitude() &&
		a.Longitude() == b.Longitude() &&
		a.Priority() == b.Priority()
}

// netInfoEqualIgnoringDERP compares two NetInfo values via
// [tailcfg.NetInfo.BasicallyEqual] after zeroing PreferredDERP on both, so
// that DERP-only changes do not appear here (they are tracked separately).
func netInfoEqualIgnoringDERP(old, current *tailcfg.NetInfo) bool {
	if old == nil && current == nil {
		return true
	}

	if (old == nil) != (current == nil) {
		return false
	}

	oldCopy := *old
	oldCopy.PreferredDERP = 0
	currentCopy := *current
	currentCopy.PreferredDERP = 0

	return oldCopy.BasicallyEqual(&currentCopy)
}
