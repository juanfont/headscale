package change

import (
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// Change declares what should be included in a MapResponse.
// The mapper uses this to build the response without guessing.
type Change struct {
	// Reason is a human-readable description for logging/debugging.
	Reason string

	// TargetNode, if set, means this response should only be sent to this node.
	TargetNode types.NodeID

	// OriginNode is the node that triggered this change.
	// Used for self-update detection and filtering.
	OriginNode types.NodeID

	// Content flags - what to include in the MapResponse.
	IncludeSelf    bool
	IncludeDERPMap bool
	IncludeDNS     bool
	IncludeDomain  bool
	IncludePolicy  bool // PacketFilters and SSHPolicy - always sent together

	// Peer changes.
	PeersChanged []types.NodeID
	PeersRemoved []types.NodeID
	PeerPatches  []*tailcfg.PeerChange
	SendAllPeers bool

	// RequiresRuntimePeerComputation indicates that peer visibility
	// must be computed at runtime per-node. Used for policy changes
	// where each node may have different peer visibility.
	RequiresRuntimePeerComputation bool
}

// boolFieldNames returns all boolean field names for exhaustive testing.
// When adding a new boolean field to Change, add it here.
// Tests use reflection to verify this matches the struct.
func (r Change) boolFieldNames() []string {
	return []string{
		"IncludeSelf",
		"IncludeDERPMap",
		"IncludeDNS",
		"IncludeDomain",
		"IncludePolicy",
		"SendAllPeers",
		"RequiresRuntimePeerComputation",
	}
}

func (r Change) Merge(other Change) Change {
	merged := r

	merged.IncludeSelf = r.IncludeSelf || other.IncludeSelf
	merged.IncludeDERPMap = r.IncludeDERPMap || other.IncludeDERPMap
	merged.IncludeDNS = r.IncludeDNS || other.IncludeDNS
	merged.IncludeDomain = r.IncludeDomain || other.IncludeDomain
	merged.IncludePolicy = r.IncludePolicy || other.IncludePolicy
	merged.SendAllPeers = r.SendAllPeers || other.SendAllPeers
	merged.RequiresRuntimePeerComputation = r.RequiresRuntimePeerComputation || other.RequiresRuntimePeerComputation

	merged.PeersChanged = uniqueNodeIDs(append(r.PeersChanged, other.PeersChanged...))
	merged.PeersRemoved = uniqueNodeIDs(append(r.PeersRemoved, other.PeersRemoved...))
	merged.PeerPatches = append(r.PeerPatches, other.PeerPatches...)

	// Preserve OriginNode for self-update detection.
	// If either change has OriginNode set, keep it so the mapper
	// can detect self-updates and send the node its own changes.
	if merged.OriginNode == 0 {
		merged.OriginNode = other.OriginNode
	}

	// Preserve TargetNode for targeted responses.
	if merged.TargetNode == 0 {
		merged.TargetNode = other.TargetNode
	}

	if r.Reason != "" && other.Reason != "" && r.Reason != other.Reason {
		merged.Reason = r.Reason + "; " + other.Reason
	} else if other.Reason != "" {
		merged.Reason = other.Reason
	}

	return merged
}

func (r Change) IsEmpty() bool {
	if r.IncludeSelf || r.IncludeDERPMap || r.IncludeDNS ||
		r.IncludeDomain || r.IncludePolicy || r.SendAllPeers {
		return false
	}

	if r.RequiresRuntimePeerComputation {
		return false
	}

	return len(r.PeersChanged) == 0 &&
		len(r.PeersRemoved) == 0 &&
		len(r.PeerPatches) == 0
}

func (r Change) IsSelfOnly() bool {
	if r.TargetNode == 0 || !r.IncludeSelf {
		return false
	}

	if r.SendAllPeers || len(r.PeersChanged) > 0 || len(r.PeersRemoved) > 0 || len(r.PeerPatches) > 0 {
		return false
	}

	return true
}

// IsTargetedToNode returns true if this response should only be sent to TargetNode.
func (r Change) IsTargetedToNode() bool {
	return r.TargetNode != 0
}

// IsFull reports whether this is a full update response.
func (r Change) IsFull() bool {
	return r.SendAllPeers && r.IncludeSelf && r.IncludeDERPMap &&
		r.IncludeDNS && r.IncludeDomain && r.IncludePolicy
}

// Type returns a categorized type string for metrics.
// This provides a bounded set of values suitable for Prometheus labels,
// unlike Reason which is free-form text for logging.
func (r Change) Type() string {
	if r.IsFull() {
		return "full"
	}

	if r.IsSelfOnly() {
		return "self"
	}

	if r.RequiresRuntimePeerComputation {
		return "policy"
	}

	if len(r.PeerPatches) > 0 && len(r.PeersChanged) == 0 && len(r.PeersRemoved) == 0 && !r.SendAllPeers {
		return "patch"
	}

	if len(r.PeersChanged) > 0 || len(r.PeersRemoved) > 0 || r.SendAllPeers {
		return "peers"
	}

	if r.IncludeDERPMap || r.IncludeDNS || r.IncludeDomain || r.IncludePolicy {
		return "config"
	}

	return "unknown"
}

// ShouldSendToNode determines if this response should be sent to nodeID.
// It handles self-only targeting and filtering out self-updates for non-origin nodes.
func (r Change) ShouldSendToNode(nodeID types.NodeID) bool {
	// If targeted to a specific node, only send to that node
	if r.TargetNode != 0 {
		return r.TargetNode == nodeID
	}

	return true
}

// HasFull returns true if any response in the slice is a full update.
func HasFull(rs []Change) bool {
	for _, r := range rs {
		if r.IsFull() {
			return true
		}
	}

	return false
}

// SplitTargetedAndBroadcast separates responses into targeted (to specific node) and broadcast.
func SplitTargetedAndBroadcast(rs []Change) ([]Change, []Change) {
	var broadcast, targeted []Change

	for _, r := range rs {
		if r.IsTargetedToNode() {
			targeted = append(targeted, r)
		} else {
			broadcast = append(broadcast, r)
		}
	}

	return broadcast, targeted
}

// FilterForNode returns responses that should be sent to the given node.
func FilterForNode(nodeID types.NodeID, rs []Change) []Change {
	var result []Change

	for _, r := range rs {
		if r.ShouldSendToNode(nodeID) {
			result = append(result, r)
		}
	}

	return result
}

func uniqueNodeIDs(ids []types.NodeID) []types.NodeID {
	if len(ids) == 0 {
		return nil
	}

	slices.Sort(ids)

	return slices.Compact(ids)
}

// Constructor functions

func FullUpdate() Change {
	return Change{
		Reason:         "full update",
		IncludeSelf:    true,
		IncludeDERPMap: true,
		IncludeDNS:     true,
		IncludeDomain:  true,
		IncludePolicy:  true,
		SendAllPeers:   true,
	}
}

// FullSelf returns a full update targeted at a specific node.
func FullSelf(nodeID types.NodeID) Change {
	return Change{
		Reason:         "full self update",
		TargetNode:     nodeID,
		IncludeSelf:    true,
		IncludeDERPMap: true,
		IncludeDNS:     true,
		IncludeDomain:  true,
		IncludePolicy:  true,
		SendAllPeers:   true,
	}
}

func SelfUpdate(nodeID types.NodeID) Change {
	return Change{
		Reason:      "self update",
		TargetNode:  nodeID,
		IncludeSelf: true,
	}
}

func PolicyOnly() Change {
	return Change{
		Reason:        "policy update",
		IncludePolicy: true,
	}
}

func PolicyAndPeers(changedPeers ...types.NodeID) Change {
	return Change{
		Reason:        "policy and peers update",
		IncludePolicy: true,
		PeersChanged:  changedPeers,
	}
}

func VisibilityChange(reason string, added, removed []types.NodeID) Change {
	return Change{
		Reason:        reason,
		IncludePolicy: true,
		PeersChanged:  added,
		PeersRemoved:  removed,
	}
}

func PeersChanged(reason string, peerIDs ...types.NodeID) Change {
	return Change{
		Reason:       reason,
		PeersChanged: peerIDs,
	}
}

func PeersRemoved(peerIDs ...types.NodeID) Change {
	return Change{
		Reason:       "peers removed",
		PeersRemoved: peerIDs,
	}
}

func PeerPatched(reason string, patches ...*tailcfg.PeerChange) Change {
	return Change{
		Reason:      reason,
		PeerPatches: patches,
	}
}

func DERPMap() Change {
	return Change{
		Reason:         "DERP map update",
		IncludeDERPMap: true,
	}
}

// PolicyChange creates a response for policy changes.
// Policy changes require runtime peer visibility computation.
func PolicyChange() Change {
	return Change{
		Reason:                         "policy change",
		IncludePolicy:                  true,
		RequiresRuntimePeerComputation: true,
	}
}

// DNSConfig creates a response for DNS configuration updates.
func DNSConfig() Change {
	return Change{
		Reason:     "DNS config update",
		IncludeDNS: true,
	}
}

// NodeOnline creates a patch response for a node coming online.
func NodeOnline(nodeID types.NodeID) Change {
	return Change{
		Reason: "node online",
		PeerPatches: []*tailcfg.PeerChange{
			{
				NodeID: nodeID.NodeID(),
				Online: ptrTo(true),
			},
		},
	}
}

// NodeOffline creates a patch response for a node going offline.
func NodeOffline(nodeID types.NodeID) Change {
	return Change{
		Reason: "node offline",
		PeerPatches: []*tailcfg.PeerChange{
			{
				NodeID: nodeID.NodeID(),
				Online: ptrTo(false),
			},
		},
	}
}

// KeyExpiry creates a patch response for a node's key expiry change.
func KeyExpiry(nodeID types.NodeID, expiry *time.Time) Change {
	return Change{
		Reason: "key expiry",
		PeerPatches: []*tailcfg.PeerChange{
			{
				NodeID:    nodeID.NodeID(),
				KeyExpiry: expiry,
			},
		},
	}
}

// ptrTo returns a pointer to the given value.
func ptrTo[T any](v T) *T {
	return &v
}

// High-level change constructors

// NodeAdded returns a Change for when a node is added or updated.
// The OriginNode field enables self-update detection by the mapper.
func NodeAdded(id types.NodeID) Change {
	c := PeersChanged("node added", id)
	c.OriginNode = id

	return c
}

// NodeRemoved returns a Change for when a node is removed.
func NodeRemoved(id types.NodeID) Change {
	return PeersRemoved(id)
}

// NodeOnlineFor returns a Change for when a node comes online.
// If the node is a subnet router, a full update is sent instead of a patch.
func NodeOnlineFor(node types.NodeView) Change {
	if node.IsSubnetRouter() {
		c := FullUpdate()
		c.Reason = "subnet router online"

		return c
	}

	return NodeOnline(node.ID())
}

// NodeOfflineFor returns a Change for when a node goes offline.
// If the node is a subnet router, a full update is sent instead of a patch.
func NodeOfflineFor(node types.NodeView) Change {
	if node.IsSubnetRouter() {
		c := FullUpdate()
		c.Reason = "subnet router offline"

		return c
	}

	return NodeOffline(node.ID())
}

// KeyExpiryFor returns a Change for when a node's key expiry changes.
// The OriginNode field enables self-update detection by the mapper.
func KeyExpiryFor(id types.NodeID, expiry time.Time) Change {
	c := KeyExpiry(id, &expiry)
	c.OriginNode = id

	return c
}

// EndpointOrDERPUpdate returns a Change for when a node's endpoints or DERP region changes.
// The OriginNode field enables self-update detection by the mapper.
func EndpointOrDERPUpdate(id types.NodeID, patch *tailcfg.PeerChange) Change {
	c := PeerPatched("endpoint/DERP update", patch)
	c.OriginNode = id

	return c
}

// UserAdded returns a Change for when a user is added or updated.
// A full update is sent to refresh user profiles on all nodes.
func UserAdded() Change {
	c := FullUpdate()
	c.Reason = "user added"

	return c
}

// UserRemoved returns a Change for when a user is removed.
// A full update is sent to refresh user profiles on all nodes.
func UserRemoved() Change {
	c := FullUpdate()
	c.Reason = "user removed"

	return c
}

// ExtraRecords returns a Change for when DNS extra records change.
func ExtraRecords() Change {
	c := DNSConfig()
	c.Reason = "extra records update"

	return c
}
