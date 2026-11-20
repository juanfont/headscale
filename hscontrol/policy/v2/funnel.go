package v2

import (
	"slices"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tailcfg/peercap"
)

// Option configures a [PolicyManager] at construction.
type Option func(*PolicyManager)

// WithFunnelRelayTags names the tags of the funnel relay nodes. Nodes
// carrying one of them get the ingress capability towards every node the
// policy gives the funnel nodeAttr (see [Policy.withFunnelGrant]). Empty
// leaves funnel without relays.
func WithFunnelRelayTags(tags []string) Option {
	return func(pm *PolicyManager) {
		pm.funnelRelayTags = slices.Clone(tags)
		pm.funnelConfigured = true
	}
}

// withFunnelGrant returns pol with one more grant: from the funnel relay
// tags to the targets of every nodeAttrs entry holding the funnel
// attribute, carrying the [peercap.Ingress] capability. A funnel node
// accepts an ingress request on its peerapi only from a peer holding that
// capability; the grant also makes the relay and the funnel nodes peers.
//
// The grant is generated rather than written by the operator: the ingress
// capability is internal and refused in policy grants
// ([tailscaleCapAllowlist]).
//
// A policy without acls or grants allows everything; the returned policy
// keeps that by carrying the allow-all rule next to the funnel grant.
func (pol *Policy) withFunnelGrant(relayTags []string) *Policy {
	if pol == nil || len(relayTags) == 0 {
		return pol
	}

	var dsts Aliases

	for _, na := range pol.NodeAttrs {
		if slices.Contains(na.Attrs, nodecap.Funnel) {
			dsts = append(dsts, na.Targets...)
		}
	}

	if len(dsts) == 0 {
		return pol
	}

	srcs := make(Aliases, 0, len(relayTags))
	for _, t := range relayTags {
		tag := Tag(t)
		srcs = append(srcs, &tag)
	}

	out := *pol
	if out.ACLs == nil && out.Grants == nil {
		out.ACLs = allowAllPolicy().ACLs
	}

	out.Grants = append(slices.Clip(out.Grants), Grant{
		Sources:      srcs,
		Destinations: dsts,
		App:          tailcfg.PeerCapMap{peercap.Ingress: nil},
	})

	return &out
}

// hasFunnelAttr reports whether a nodeAttrs entry gives the funnel
// attribute.
func (pol *Policy) hasFunnelAttr() bool {
	if pol == nil {
		return false
	}

	return slices.ContainsFunc(pol.NodeAttrs, func(na NodeAttrGrant) bool {
		return slices.Contains(na.Attrs, nodecap.Funnel)
	})
}

// warnFunnelWithoutRelays logs, once per policy load, that the funnel
// nodeAttr has no effect while the server config does not enable funnel,
// which is the only way relay tags get set. configured is false when the
// caller, such as `headscale check`, did not pass the funnel config at all,
// so nothing is known about it.
func warnFunnelWithoutRelays(pol *Policy, configured bool, relayTags []string) {
	if !configured || len(relayTags) > 0 || !pol.hasFunnelAttr() {
		return
	}

	log.Warn().Msg("funnel nodeAttr has no effect: funnel is not enabled in the server config (funnel.enabled)")
}
