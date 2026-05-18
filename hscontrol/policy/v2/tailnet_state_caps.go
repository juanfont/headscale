package v2

// This file enumerates [tailcfg.NodeCapability] values that the
// Tailscale-hosted control plane emits where headscale has no
// equivalent concept yet. The compat test in
// tailscale_nodeattrs_compat_test.go builds the self-view CapMap via
// [types.Node.TailNode] -- the same call the mapper makes -- and
// strips these from BOTH sides before [cmp.Diff]; every other cap is
// compared in full as it lands on the wire.
//
// Each entry documents its purpose (cross-referenced to Tailscale
// source), why headscale does not emit it, and a tracking issue where
// one exists.

import (
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// PeerCapMap returns the subset of peerSelfCaps the Tailscale client
// reads from the peer view (rather than the self view) given the
// peer's state. Returns nil when no peer-consumed cap applies, matching
// the empirical wire shape where [tailcfg.Node.CapMap] is omitted for
// most peers.
//
// Caps the client reads from the peer view rather than the self view
// (suggest-exit-node, dns-subdomain-resolve — see
// ipn/ipnlocal/local.go:7534 and node_backend.go:745) are emitted only
// when the peer satisfies the cap's emission condition. This function
// encodes those conditions; the mapper calls it from
// [mapper.MapResponseBuilder.buildTailPeers] and the compat test calls
// it to compute the expected per-peer wire shape.
func PeerCapMap(peer types.NodeView, peerSelfCaps tailcfg.NodeCapMap) tailcfg.NodeCapMap {
	if len(peerSelfCaps) == 0 {
		return nil
	}

	var out tailcfg.NodeCapMap

	// suggest-exit-node — surfaced on Peer.CapMap when the peer
	// advertises exit routes AND those routes are approved. Client
	// reads at ipn/ipnlocal/local.go:7534. Approval gating prevents
	// the suggestion from following an advertised-but-not-yet-trusted
	// node.
	if peer.IsExitNode() {
		if v, ok := peerSelfCaps[tailcfg.NodeAttrSuggestExitNode]; ok {
			if out == nil {
				out = tailcfg.NodeCapMap{}
			}

			out[tailcfg.NodeAttrSuggestExitNode] = v
		}
	}

	return out
}

// unmodelledTailnetStateCaps lists [tailcfg.NodeCapability] values
// stripped on both sides of the compat diff. Order:
//
//  1. Caps gated on a user-role concept headscale does not model.
//  2. Caps gated on a tailnet feature headscale does not implement.
//  3. Caps that are tailnet-state metadata (display name, key
//     duration, etc.) where the values are not derivable from
//     headscale config in a way that round-trips through the
//     anonymized capture.
//  4. Caps that are internal magicsock or embedded-SSH tuning with no
//     headscale-side equivalent.
var unmodelledTailnetStateCaps = []tailcfg.NodeCapability{
	// --- 1. User-role gated ---

	// [tailcfg.CapabilityAdmin]: the hosted control plane stamps this
	// on nodes whose owning user has the admin role; tagged nodes
	// inherit from a tagOwner with the role. Headscale has no
	// user-role model — [types.Node.TailNode] emits it as part of
	// the always-on baseline. Stripping on both sides keeps the diff
	// from failing on every user-owned non-admin node in a capture.
	// Long-term fix is autogroup:admin support.
	tailcfg.CapabilityAdmin,

	// [tailcfg.CapabilityOwner]: same shape as is-admin, conditional
	// on the "owner" role rather than admin. Headscale does not emit
	// this cap at all. autogroup:owner support is tracked under
	// NO_USER_ROLES — see the compat skip list.
	tailcfg.CapabilityOwner,

	// --- 2. Feature not implemented ---

	// [tailcfg.CapabilityTailnetLock]: tailnet-lock signs node keys
	// with a tailnet-wide signing key so peers can detect silent
	// re-keying by the control plane. Client reads at
	// ipn/ipnlocal/local.go:1752 (b.capTailnetLock). Headscale has no
	// tailnet-lock implementation.
	tailcfg.CapabilityTailnetLock,

	// [tailcfg.NodeAttrServiceHost]: marks a node as approved to host
	// VIP services (Tailscale Services). Client reads via
	// UnmarshalNodeCapViewJSON at ipn/ipnlocal/local.go:2704.
	// Headscale does not implement Tailscale Services.
	tailcfg.NodeAttrServiceHost,

	// [tailcfg.NodeAttrStoreAppCRoutes]: tells an app-connector node
	// to persist learned routes across restarts. Client reads via
	// controlknobs:148. Headscale does not implement app connectors.
	tailcfg.NodeAttrStoreAppCRoutes,

	// [tailcfg.CapabilityWarnFunnelNoHTTPS]: deprecated in Tailscale
	// 2023-08-09. Should not appear in fresh captures — listed
	// defensively in case a stale tailnet still emits it.
	tailcfg.CapabilityWarnFunnelNoHTTPS,

	// --- 3. Tailnet-state metadata not derivable from headscale config ---

	// [tailcfg.NodeAttrTailnetDisplayName]: tailnet display name
	// surfaced in the client UI. The hosted control plane emits the
	// tailnet admin's email; headscale would have to invent a value
	// from cfg.Domain() that does not round-trip through the
	// anonymized capture string. Skip rather than diverge on a value
	// with no real-world equivalent.
	tailcfg.NodeAttrTailnetDisplayName,

	// [tailcfg.NodeAttrMaxKeyDuration]: tailnet-wide max key duration
	// value. Headscale has cfg.Node.Expiry but does not surface it
	// as a cap today; the hosted control plane emits this only when
	// a non-default value is configured.
	tailcfg.NodeAttrMaxKeyDuration,

	// [tailcfg.NodeAttrNativeIPV4]: peer-consumed cap conditional on
	// tailnet ipv4 reachability state. Out of scope for the current
	// peer-cap adoption (only suggest-exit-node is wired in this
	// PR).
	tailcfg.NodeAttrNativeIPV4,

	// --- 4. Internal tuning, no headscale equivalent ---

	// [tailcfg.NodeAttrProbeUDPLifetime]: tunes magicsock's UDP
	// path-lifetime probe behavior. Internal performance knob; not
	// policy-driven. Client reads via controlknobs:147.
	tailcfg.NodeAttrProbeUDPLifetime,

	// [tailcfg.NodeAttrSSHBehaviorV1]: configures the embedded SSH
	// server (no su, in-process SFTP). Internal tuning; the embedded
	// server picks Tailscale-vendored defaults without the cap.
	tailcfg.NodeAttrSSHBehaviorV1,

	// [tailcfg.NodeAttrSSHEnvironmentVariables]: gates SendEnv
	// forwarding in the embedded SSH server. Internal; default chosen
	// by the server.
	tailcfg.NodeAttrSSHEnvironmentVariables,
}

// strippedCapPrefixes lists URL/string prefixes for parameterized or
// pattern-named caps that should be stripped alongside
// [unmodelledTailnetStateCaps].
var strippedCapPrefixes = []string{
	// "https://tailscale.com/cap/funnel-ports?…": parameterized cap
	// (e.g. "?ports=80,443") issued when funnel is configured.
	// Funnel is not supported.
	"https://tailscale.com/cap/funnel-ports?",
}

// stripUnmodelledTailnetStateCaps returns a copy of cm with
// [unmodelledTailnetStateCaps] and [strippedCapPrefixes] removed. Used
// by the compat test on both sides before [cmp.Diff].
func stripUnmodelledTailnetStateCaps(cm tailcfg.NodeCapMap) tailcfg.NodeCapMap {
	if len(cm) == 0 {
		return nil
	}

	out := make(tailcfg.NodeCapMap, len(cm))

	for k, v := range cm {
		if isUnmodelledTailnetStateCap(k) {
			continue
		}

		out[k] = v
	}

	if len(out) == 0 {
		return nil
	}

	return out
}

func isUnmodelledTailnetStateCap(k tailcfg.NodeCapability) bool {
	if slices.Contains(unmodelledTailnetStateCaps, k) {
		return true
	}

	s := string(k)
	for _, p := range strippedCapPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}

	return false
}
