package mapper

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/multierr"
)

// MapResponseBuilder provides a fluent interface for building [tailcfg.MapResponse].
type MapResponseBuilder struct {
	resp   *tailcfg.MapResponse
	mapper *mapper
	nodeID types.NodeID
	capVer tailcfg.CapabilityVersion
	errs   []error

	debugType debugType
}

type debugType string

const (
	fullResponseDebug   debugType = "full"
	selfResponseDebug   debugType = "self"
	changeResponseDebug debugType = "change"
	policyResponseDebug debugType = "policy"
)

// NewMapResponseBuilder creates a new builder with basic fields set.
func (m *mapper) NewMapResponseBuilder(nodeID types.NodeID) *MapResponseBuilder {
	now := time.Now()

	return &MapResponseBuilder{
		resp: &tailcfg.MapResponse{
			KeepAlive:   false,
			ControlTime: &now,
		},
		mapper: m,
		nodeID: nodeID,
		errs:   nil,
	}
}

// addError adds an error to the builder's error list.
func (b *MapResponseBuilder) addError(err error) {
	if err != nil {
		b.errs = append(b.errs, err)
	}
}

// hasErrors returns true if the builder has accumulated any errors.
func (b *MapResponseBuilder) hasErrors() bool {
	return len(b.errs) > 0
}

// node looks up the requesting node, recording ErrNodeNotFoundMapper on miss.
func (b *MapResponseBuilder) node() (types.NodeView, bool) {
	nv, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(ErrNodeNotFoundMapper)
	}

	return nv, ok
}

// WithCapabilityVersion sets the capability version for the response.
func (b *MapResponseBuilder) WithCapabilityVersion(capVer tailcfg.CapabilityVersion) *MapResponseBuilder {
	b.capVer = capVer
	return b
}

// WithSelfNode adds the requesting node to the response.
func (b *MapResponseBuilder) WithSelfNode() *MapResponseBuilder {
	nv, ok := b.node()
	if !ok {
		return b
	}

	tailnode, err := nv.TailNode(
		b.capVer,
		func(types.NodeID) []netip.Prefix {
			// A router holds every route it is approved for, whatever
			// its own policy reaches.
			return nv.AllApprovedRoutes()
		},
		b.mapper.cfg,
		b.mapper.state.NodeCapMap(nv.ID()),
	)
	if err != nil {
		b.addError(err)
		return b
	}

	// PrimaryRoutes is what the router serves: the routes it is primary
	// for, under the rule its peers get them by.
	tailnode.PrimaryRoutes = slices.DeleteFunc(
		b.mapper.state.GetNodePrimaryRoutes(nv.ID()),
		func(p netip.Prefix) bool { return !b.mapper.cfg.ServesRoute(p) },
	)

	// As on Tailscale SaaS, an expired node's own entry stays authorised and
	// unmarked; the client reads its expiry from the past KeyExpiry.
	tailnode.MachineAuthorized = true
	tailnode.Expired = false

	tailnode.Hostinfo = types.SelfHostinfo(tailnode.Hostinfo)

	b.resp.Node = tailnode

	return b
}

func (b *MapResponseBuilder) WithDebugType(t debugType) *MapResponseBuilder {
	if debugDumpMapResponsePath != "" {
		b.debugType = t
	}

	return b
}

// WithDERPMap adds the DERP map to the response.
func (b *MapResponseBuilder) WithDERPMap() *MapResponseBuilder {
	b.resp.DERPMap = b.mapper.state.DERPMap().AsStruct()
	return b
}

// WithDomain adds the domain configuration.
func (b *MapResponseBuilder) WithDomain() *MapResponseBuilder {
	b.resp.Domain = b.mapper.cfg.Domain()
	return b
}

// WithCollectServicesDisabled sets the collect services flag to false.
func (b *MapResponseBuilder) WithCollectServicesDisabled() *MapResponseBuilder {
	b.resp.CollectServices.Set(false)
	return b
}

// WithDebugConfig sets [tailcfg.MapResponse.Debug] from [types.Config.TailcfgDebug].
func (b *MapResponseBuilder) WithDebugConfig() *MapResponseBuilder {
	b.resp.Debug = b.mapper.cfg.TailcfgDebug()

	return b
}

// WithSSHPolicy adds SSH policy configuration for the requesting node.
func (b *MapResponseBuilder) WithSSHPolicy() *MapResponseBuilder {
	node, ok := b.node()
	if !ok {
		return b
	}

	sshPolicy, err := b.mapper.state.SSHPolicy(node)
	if err != nil {
		// Don't fail the whole map over SSH, but fail closed: a nil
		// SSHPolicy would leave the client's previous rules in force.
		log.Error().Caller().
			Err(err).
			Uint64(zf.NodeID, node.ID().Uint64()).
			Str(zf.NodeHostname, node.Hostname()).
			Msg("building map response: compiling SSH policy failed; sending empty SSH policy")

		sshPolicy = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}
	}

	b.resp.SSHPolicy = sshPolicy

	return b
}

// WithDNSConfig adds DNS configuration for the requesting node.
func (b *MapResponseBuilder) WithDNSConfig() *MapResponseBuilder {
	node, ok := b.node()
	if !ok {
		return b
	}

	b.resp.DNSConfig = generateDNSConfig(b.mapper.cfg, node, b.mapper.state.NodeCapMap(node.ID()))

	return b
}

// WithUserProfiles adds user profiles for the requesting node and given peers.
func (b *MapResponseBuilder) WithUserProfiles(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	node, ok := b.node()
	if !ok {
		return b
	}

	b.resp.UserProfiles = generateUserProfiles(node, peers)

	return b
}

// WithPacketFilters adds packet filter rules based on policy.
//
// [State.FilterForNode] returns rules already reduced to only those relevant for this node.
// For autogroup:self policies, it returns per-node compiled rules.
// For global policies, it returns the global filter reduced for this node.
func (b *MapResponseBuilder) WithPacketFilters() *MapResponseBuilder {
	node, ok := b.node()
	if !ok {
		return b
	}

	filter, err := b.mapper.state.FilterForNode(node)
	if err != nil {
		b.addError(err)
		return b
	}

	// CapVer 81: 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
	// Currently, we do not send incremental package filters, however using the
	// new PacketFilters field and "base" allows us to send a full update when we
	// have to send an empty list, avoiding the hack in the else block.
	b.resp.PacketFilters = map[string][]tailcfg.FilterRule{
		"base": filter,
	}

	return b
}

// WithPeers adds full peer list with policy filtering (for full map response).
func (b *MapResponseBuilder) WithPeers(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	tailPeers, err := b.buildTailPeers(peers)
	if err != nil {
		b.addError(err)
		return b
	}

	b.resp.Peers = tailPeers

	return b
}

// WithPeerChanges adds changed peers with policy filtering (for incremental updates).
func (b *MapResponseBuilder) WithPeerChanges(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	tailPeers, err := b.buildTailPeers(peers)
	if err != nil {
		b.addError(err)
		return b
	}

	b.resp.PeersChanged = tailPeers

	return b
}

// buildTailPeers converts [views.Slice] of [types.NodeView] to a sorted slice of
// [tailcfg.Node]. The peers come from the NodeStore peer map, which already
// decided visibility; only each peer's routes are filtered by policy here.
func (b *MapResponseBuilder) buildTailPeers(peers views.Slice[types.NodeView]) ([]*tailcfg.Node, error) {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		return nil, ErrNodeNotFoundMapper
	}

	// [State.RoutesForPeer] needs the unreduced matchers: every rule where the
	// node is source or destination, not only the [State.FilterForNode] rules
	// where it is destination.
	matchers, err := b.mapper.state.MatchersForNode(node)
	if err != nil {
		return nil, err
	}

	// Snapshot these peers' policy caps under one policy-manager lock.
	peerCapMaps := b.mapper.state.NodeCapMapsForPeers(peers)

	// Build tail nodes with per-peer via-aware route function.
	tailPeers := make([]*tailcfg.Node, 0, peers.Len())

	for _, peer := range peers.All() {
		// Pass the peer's policy CapMap as selfPolicyCaps so per-peer
		// address-shape rules (today: disable-ipv4) apply consistently
		// in the viewer's netmap. The CapMap merge into tn.CapMap is
		// overwritten by the PeerCapMap call below; only the address
		// filtering side-effect inside TailNode survives.
		tn, err := peer.TailNode(b.capVer, func(_ types.NodeID) []netip.Prefix {
			return b.mapper.state.RoutesForPeer(node, peer, matchers)
		}, b.mapper.cfg, peerCapMaps[peer.ID()])
		if err != nil {
			// One peer with invalid data (e.g. an empty or over-long
			// GivenName that fails GetFQDN) must not blank out the map for
			// every node that can see it. Drop the offending peer, log it
			// with the identity an operator needs to fix it, and keep
			// building from the remaining valid peers.
			fix := fmt.Sprintf("headscale nodes rename %d <name>", peer.ID())
			if errors.Is(err, types.ErrExpiryOutOfRange) {
				fix = fmt.Sprintf("headscale nodes expire --identifier %d", peer.ID())
			}

			log.Warn().Caller().
				Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Uint64("map.viewer.node.id", b.nodeID.Uint64()).
				Msgf("dropping peer %d from map response: invalid node data; "+
					"fix with `%s`", peer.ID(), fix)

			continue
		}

		// [tailcfg.Node.CapMap] on a peer carries the small set of
		// caps the Tailscale client reads from the peer view rather
		// than the self view (suggest-exit-node, dns-subdomain-resolve
		// — see [tailcfg.NodeAttrSuggestExitNode] and
		// [tailcfg.NodeAttrDNSSubdomainResolve]).
		// The Tailscale-hosted control plane stamps these only when
		// the peer satisfies the cap's emission condition; every other
		// cap stays off the peer view, leaving CapMap empty for most
		// peers. [policyv2.PeerCapMap] encodes those conditions.
		tn.CapMap = policyv2.PeerCapMap(peer, peerCapMaps[peer.ID()])
		tn.Hostinfo = types.PeerHostinfo(tn.Hostinfo)

		// As on Tailscale SaaS, a connected expired peer shows online, but
		// without the endpoints and home DERP region that would reach it.
		if peer.IsExpired() {
			if peer.ActiveSessions() > 0 {
				tn.Online, tn.LastSeen = new(true), nil
			}

			tn.Endpoints, tn.HomeDERP = nil, 0
		}

		tailPeers = append(tailPeers, tn)
	}

	// Peers is always returned sorted by Node.ID.
	slices.SortStableFunc(tailPeers, func(a, b *tailcfg.Node) int {
		return cmp.Compare(a.ID, b.ID)
	})

	return tailPeers, nil
}

// WithPingRequest adds a PingRequest to the response.
func (b *MapResponseBuilder) WithPingRequest(pr *tailcfg.PingRequest) *MapResponseBuilder {
	b.resp.PingRequest = pr
	return b
}

// WithPeerChangedPatch adds peer change patches. A patch whose key expiry
// cannot be encoded is left out, as [MapResponseBuilder.buildTailPeers] leaves
// out its peer, so it cannot fail the whole response.
func (b *MapResponseBuilder) WithPeerChangedPatch(changes []*tailcfg.PeerChange) *MapResponseBuilder {
	for _, pc := range changes {
		if pc.KeyExpiry != nil {
			_, err := types.ValidateExpiry(*pc.KeyExpiry)
			if err != nil {
				continue
			}
		}

		b.resp.PeersChangedPatch = append(b.resp.PeersChangedPatch, pc)
	}

	return b
}

// WithPeersRemoved adds removed peer IDs.
func (b *MapResponseBuilder) WithPeersRemoved(removedIDs ...types.NodeID) *MapResponseBuilder {
	tailscaleIDs := make([]tailcfg.NodeID, 0, len(removedIDs))
	for _, id := range removedIDs {
		tailscaleIDs = append(tailscaleIDs, id.NodeID())
	}

	b.resp.PeersRemoved = tailscaleIDs

	return b
}

// Build finalizes the response and returns marshaled bytes.
func (b *MapResponseBuilder) Build() (*tailcfg.MapResponse, error) {
	if len(b.errs) > 0 {
		return nil, multierr.New(b.errs...)
	}

	// Dumps show the generated response; [generateMapResponse] drops it
	// if it is left empty, and an unchanged SSHPolicy is dropped later,
	// per connection, before it reaches the wire.
	if debugDumpMapResponsePath != "" {
		writeDebugMapResponse(b.resp, b.debugType, b.nodeID)
	}

	return b.resp, nil
}
