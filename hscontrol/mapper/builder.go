package mapper

import (
	"errors"
	"net/netip"
	"sort"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
	"tailscale.com/util/multierr"
)

// MapResponseBuilder provides a fluent interface for building tailcfg.MapResponse.
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
	patchResponseDebug  debugType = "patch"
	removeResponseDebug debugType = "remove"
	changeResponseDebug debugType = "change"
	derpResponseDebug   debugType = "derp"
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
	nodeView, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(errors.New("node not found"))
		return b
	}

	// Always use batcher's view of online status for self node
	// The batcher respects grace periods for logout scenarios
	node := nodeView.AsStruct()
	// if b.mapper.batcher != nil {
	// 	node.IsOnline = ptr.To(b.mapper.batcher.IsConnected(b.nodeID))
	// }

	_, matchers := b.mapper.state.Filter()
	tailnode, err := tailNode(
		node.View(), b.capVer, b.mapper.state,
		func(id types.NodeID) []netip.Prefix {
			return policy.ReduceRoutes(node.View(), b.mapper.state.GetNodePrimaryRoutes(id), matchers)
		},
		b.mapper.cfg)
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
		b.addError(errors.New("node not found"))
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
		b.addError(errors.New("node not found"))
		return b
	}

	b.resp.DNSConfig = generateDNSConfig(b.mapper.cfg, node)

	return b
}

// WithUserProfiles adds user profiles for the requesting node and given peers.
func (b *MapResponseBuilder) WithUserProfiles(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(errors.New("node not found"))
		return b
	}

	b.resp.UserProfiles = generateUserProfiles(node, peers)

	return b
}

// WithPacketFilters adds packet filter rules based on policy.
func (b *MapResponseBuilder) WithPacketFilters() *MapResponseBuilder {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		b.addError(errors.New("node not found"))
		return b
	}

	filter, _ := b.mapper.state.Filter()

	// CapVer 81: 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
	// Currently, we do not send incremental package filters, however using the
	// new PacketFilters field and "base" allows us to send a full update when we
	// have to send an empty list, avoiding the hack in the else block.
	b.resp.PacketFilters = map[string][]tailcfg.FilterRule{
		"base": policy.ReduceFilterRules(node, filter),
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

// buildTailPeers converts views.Slice[types.NodeView] to []tailcfg.Node with policy filtering and sorting.
func (b *MapResponseBuilder) buildTailPeers(peers views.Slice[types.NodeView]) ([]*tailcfg.Node, error) {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		return nil, errors.New("node not found")
	}

	filter, matchers := b.mapper.state.Filter()

	// If there are filter rules present, see if there are any nodes that cannot
	// access each-other at all and remove them from the peers.
	var changedViews views.Slice[types.NodeView]
	if len(filter) > 0 {
		changedViews = policy.ReduceNodes(node, peers, matchers)
	} else {
		changedViews = peers
	}

	tailPeers, err := tailNodes(
		changedViews, b.capVer, b.mapper.state,
		func(id types.NodeID) []netip.Prefix {
			return policy.ReduceRoutes(node, b.mapper.state.GetNodePrimaryRoutes(id), matchers)
		},
		b.mapper.cfg)
	if err != nil {
		return nil, err
	}

	// Peers is always returned sorted by Node.ID.
	sort.SliceStable(tailPeers, func(x, y int) bool {
		return tailPeers[x].ID < tailPeers[y].ID
	})

	return tailPeers, nil
}

// WithPeerChangedPatch adds peer change patches.
func (b *MapResponseBuilder) WithPeerChangedPatch(changes []*tailcfg.PeerChange) *MapResponseBuilder {
	b.resp.PeersChangedPatch = changes
	return b
}

// WithPeersRemoved adds removed peer IDs.
func (b *MapResponseBuilder) WithPeersRemoved(removedIDs ...types.NodeID) *MapResponseBuilder {
	var tailscaleIDs []tailcfg.NodeID
	for _, id := range removedIDs {
		tailscaleIDs = append(tailscaleIDs, id.NodeID())
	}
	b.resp.PeersRemoved = tailscaleIDs

	return b
}

// Build finalizes the response and returns marshaled bytes
func (b *MapResponseBuilder) Build() (*tailcfg.MapResponse, error) {
	if len(b.errs) > 0 {
		return nil, multierr.New(b.errs...)
	}
	if debugDumpMapResponsePath != "" {
		writeDebugMapResponse(b.resp, b.debugType, b.nodeID)
	}

	return b.resp, nil
}
