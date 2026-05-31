package mapper

import (
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
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

// WithCapabilityVersion sets the capability version for the response.
func (b *MapResponseBuilder) WithCapabilityVersion(capVer tailcfg.CapabilityVersion) *MapResponseBuilder {
	b.capVer = capVer
	return b
}

// WithSelfNode adds the requesting node to the response.
func (b *MapResponseBuilder) WithSelfNode() *MapResponseBuilder {
	nv, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(ErrNodeNotFoundMapper)
		return b
	}

	_, matchers := b.mapper.state.Filter()

	tailnode, err := nv.TailNode(
		b.capVer,
		func(id types.NodeID) []netip.Prefix {
			// Self node: include own primaries + exit routes (no via steering for self).
			primaries := policy.ReduceRoutes(nv, b.mapper.state.GetNodePrimaryRoutes(id), matchers)

			return slices.Concat(primaries, nv.ExitRoutes())
		},
		b.mapper.cfg,
		b.mapper.state.NodeCapMap(nv.ID()),
	)
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

// WithDebugConfig adds debug configuration
// It disables log tailing if the mapper's LogTail is not enabled.
func (b *MapResponseBuilder) WithDebugConfig() *MapResponseBuilder {
	b.resp.Debug = &tailcfg.Debug{
		DisableLogTail: !b.mapper.cfg.LogTail.Enabled,
	}

	return b
}

// WithSSHPolicy adds SSH policy configuration for the requesting node.
func (b *MapResponseBuilder) WithSSHPolicy() *MapResponseBuilder {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(ErrNodeNotFoundMapper)
		return b
	}

	sshPolicy, err := b.mapper.state.SSHPolicy(node)
	if err != nil {
		b.addError(err)
		return b
	}

	b.resp.SSHPolicy = sshPolicy

	return b
}

// WithDNSConfig adds DNS configuration for the requesting node.
func (b *MapResponseBuilder) WithDNSConfig() *MapResponseBuilder {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(ErrNodeNotFoundMapper)
		return b
	}

	b.resp.DNSConfig = generateDNSConfig(b.mapper.cfg, node, b.mapper.state.NodeCapMap(node.ID()))

	return b
}

// WithUserProfiles adds user profiles for the requesting node and given peers.
func (b *MapResponseBuilder) WithUserProfiles(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(ErrNodeNotFoundMapper)
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
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(ErrNodeNotFoundMapper)
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

// buildTailPeers converts [views.Slice] of [types.NodeView] to a slice of [tailcfg.Node]
// with policy filtering and sorting.
func (b *MapResponseBuilder) buildTailPeers(peers views.Slice[types.NodeView]) ([]*tailcfg.Node, error) {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		return nil, ErrNodeNotFoundMapper
	}

	// Get unreduced matchers for peer relationship determination.
	// [State.MatchersForNode] returns unreduced matchers that include all rules where the
	// node could be either source or destination. This is different from
	// [State.FilterForNode] which returns reduced rules for packet filtering (only rules
	// where node is destination).
	matchers, err := b.mapper.state.MatchersForNode(node)
	if err != nil {
		return nil, err
	}

	// If there are filter rules present, see if there are any nodes that cannot
	// access each-other at all and remove them from the peers.
	var changedViews views.Slice[types.NodeView]
	if len(matchers) > 0 {
		changedViews = policy.ReduceNodes(node, peers, matchers)
	} else {
		changedViews = peers
	}

	// Snapshot the per-node policy CapMap once per peer-list build
	// instead of locking the policy manager per peer. The per-call
	// path used to take pm.mu N times for an N-peer response.
	allCapMaps := b.mapper.state.NodeCapMaps()

	// Build tail nodes with per-peer via-aware route function.
	tailPeers := make([]*tailcfg.Node, 0, changedViews.Len())

	for _, peer := range changedViews.All() {
		// Pass the peer's policy CapMap as selfPolicyCaps so per-peer
		// address-shape rules (today: disable-ipv4) apply consistently
		// in the viewer's netmap. The CapMap merge into tn.CapMap is
		// overwritten by the PeerCapMap call below; only the address
		// filtering side-effect inside TailNode survives.
		tn, err := peer.TailNode(b.capVer, func(_ types.NodeID) []netip.Prefix {
			return b.mapper.state.RoutesForPeer(node, peer, matchers)
		}, b.mapper.cfg, allCapMaps[peer.ID()])
		if err != nil {
			return nil, err
		}

		// [tailcfg.Node.CapMap] on a peer carries the small set of
		// caps the Tailscale client reads from the peer view rather
		// than the self view (suggest-exit-node, dns-subdomain-resolve
		// — see ipn/ipnlocal/local.go:7534 and node_backend.go:745).
		// The Tailscale-hosted control plane stamps these only when
		// the peer satisfies the cap's emission condition; every other
		// cap stays off the peer view, leaving CapMap empty for most
		// peers. [policyv2.PeerCapMap] encodes those conditions.
		tn.CapMap = policyv2.PeerCapMap(peer, allCapMaps[peer.ID()])

		tailPeers = append(tailPeers, tn)
	}

	// Peers is always returned sorted by Node.ID.
	sort.SliceStable(tailPeers, func(x, y int) bool {
		return tailPeers[x].ID < tailPeers[y].ID
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

	if debugDumpMapResponsePath != "" {
		writeDebugMapResponse(b.resp, b.debugType, b.nodeID)
	}

	return b.resp, nil
}
