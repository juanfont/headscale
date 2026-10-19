package mapper

import (
	"cmp"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/packetfilter"
	"github.com/juanfont/headscale/hscontrol/state"
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
	view   state.MapView
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
func (m *mapper) NewMapResponseBuilder(view state.MapView) *MapResponseBuilder {
	now := time.Now()

	var nodeID types.NodeID
	if node := view.Viewer(); node.Valid() {
		nodeID = node.ID()
	}

	return &MapResponseBuilder{
		resp: &tailcfg.MapResponse{
			KeepAlive:   false,
			ControlTime: &now,
		},
		mapper: m,
		view:   view,
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
	nv := b.view.Viewer()

	ok := nv.Valid()
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

	addresses, err := b.view.NodeAddresses(nv.ID())
	if err != nil {
		b.addError(err)
		return b
	}

	tailnode, err := nv.TailNode(b.capVer, addresses, b.mapper.cfg, b.view.NodeCapMap(nv.ID()))
	if err != nil {
		b.addError(err)
		return b
	}

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
	_, ok := b.node()
	if !ok {
		return b
	}

	sshPolicy, err := b.view.SSHPolicy(b.mapper.cfg.ServerURL)
	if err != nil {
		b.addError(err)
		return b
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

	b.resp.DNSConfig = generateDNSConfig(b.mapper.cfg, node, b.view.NodeCapMap(node.ID()))

	return b
}

// WithUserProfiles adds user profiles for the requesting node and given peers.
func (b *MapResponseBuilder) WithUserProfiles(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	node, ok := b.node()
	if !ok {
		return b
	}

	if peers.Len() > 0 {
		ids := make([]types.NodeID, 0, peers.Len())
		for _, peer := range peers.All() {
			ids = append(ids, peer.ID())
		}

		peers = b.view.Peers(ids...)
	}

	b.resp.UserProfiles = generateUserProfiles(node, peers)

	return b
}

// WithPacketFilters adds packet filter rules based on policy.
//
// Rules come from the retained policy generation, already reduced for this node.
func (b *MapResponseBuilder) WithPacketFilters() *MapResponseBuilder {
	_, ok := b.node()
	if !ok {
		return b
	}

	filter, err := b.view.PacketRules()
	if err != nil {
		b.addError(err)
		return b
	}

	// CapVer 81: 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
	// Currently, we do not send incremental package filters, however using the
	// new PacketFilters field and "base" allows us to send a full update when we
	// have to send an empty list, avoiding the hack in the else block.
	b.resp.PacketFilters = map[string][]tailcfg.FilterRule{
		"base": packetfilter.ToTailcfg(filter),
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
	if peers.Len() == 0 {
		return []*tailcfg.Node{}, nil
	}

	ids := make([]types.NodeID, 0, peers.Len())
	for _, peer := range peers.All() {
		ids = append(ids, peer.ID())
	}

	peers = b.view.Peers(ids...)

	// Build tail nodes with per-peer via-aware route function.
	tailPeers := make([]*tailcfg.Node, 0, peers.Len())

	for _, peer := range peers.All() {
		addresses, err := b.view.NodeAddresses(peer.ID())
		if err != nil {
			return nil, err
		}

		tn, err := peer.TailNode(b.capVer, addresses, b.mapper.cfg, nil)
		if err != nil {
			// One peer with invalid data (e.g. an empty or over-long
			// GivenName that fails GetFQDN) must not blank out the map for
			// every node that can see it. Drop the offending peer, log it
			// with the identity an operator needs to fix it, and keep
			// building from the remaining valid peers.
			log.Warn().Caller().
				Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Uint64("map.viewer.node.id", b.nodeID.Uint64()).
				Msgf("dropping peer %d from map response: invalid node data; fix with `headscale nodes rename %d <name>`", peer.ID(), peer.ID())

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
		tn.CapMap = b.view.PeerCapMap(peer.ID())

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

// WithPeerChangedPatch adds peer change patches.
func (b *MapResponseBuilder) WithPeerChangedPatch(changes []*tailcfg.PeerChange) *MapResponseBuilder {
	b.resp.PeersChangedPatch = changes
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

	// Dumps show the generated response; an unchanged SSHPolicy is
	// dropped later, per connection, before it reaches the wire.
	if debugDumpMapResponsePath != "" {
		writeDebugMapResponse(b.resp, b.debugType, b.nodeID)
	}

	return b.resp, nil
}
