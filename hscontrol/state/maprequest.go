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

	// routesChanged reports whether announced routes (RoutableIPs)
	// changed. Routes are policy and election inputs, so they are tracked
	// on their own.
	routesChanged bool

	// derpChanged reports whether PreferredDERP changed. oldDERP/newDERP
	// carry the values; DERP zero means "unchanged" on the wire, so
	// clearing DERP to zero cannot be sent as a patch and forces a
	// whole-peer update.
	derpChanged      bool
	oldDERP, newDERP tailcfg.DERPRegionID

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
		Int("derp.old", int(d.oldDERP)).
		Int("derp.new", int(d.newDERP)).
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
			Int64(zf.DERP, currentHostinfo.NetInfo.PreferredDERP.Int64()).
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
func hostinfoDERP(hi *tailcfg.Hostinfo) tailcfg.DERPRegionID {
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

// peerHostinfo keeps the Hostinfo fields another node's client reads from
// a peer: what tailscale status shows, PeerAPI services, SSH known hosts,
// exit-node location, app-connector eligibility, and the routes this server
// feeds into policy. Everything else is stored but never fanned out, and a
// peer's NetInfo is never read at all.
func peerHostinfo(hi *tailcfg.Hostinfo) *tailcfg.Hostinfo {
	if hi == nil {
		return nil
	}

	return &tailcfg.Hostinfo{
		Hostname:     hi.Hostname,
		OS:           hi.OS,
		Services:     hi.Services,
		SSH_HostKeys: hi.SSH_HostKeys,
		Location:     hi.Location,
		AppConnector: hi.AppConnector,
		RoutableIPs:  hi.RoutableIPs,
	}
}

// peerHostinfoEqual reports whether the fields peers read are unchanged.
func peerHostinfoEqual(oldHI, newHI *tailcfg.Hostinfo) bool {
	return peerHostinfo(oldHI).Equal(peerHostinfo(newHI))
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
