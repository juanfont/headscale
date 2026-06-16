// Package change declares the [Change] type: a compact description of
// what must land in a [tailcfg.MapResponse]. The mapper reads [Change] values to
// build responses without inspecting state, and [Change.Merge] combines
// multiple pending changes for a single tick.
package change

import (
	"fmt"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// Change declares what should be included in a [tailcfg.MapResponse].
// The mapper uses this to build the response without guessing.
type Change struct {
	// Reason is a human-readable description for logging/debugging.
	Reason string

	// TargetNode, if set, means this response should only be sent to this node.
	TargetNode types.NodeID

	// OriginNode is the node that triggered this change.
	// Used for self-update detection and filtering.
	OriginNode types.NodeID

	// Content flags - what to include in the [tailcfg.MapResponse].
	IncludeSelf    bool
	IncludeDERPMap bool
	IncludeDNS     bool
	IncludeDomain  bool
	IncludePolicy  bool // [tailcfg.MapResponse.PacketFilters] and [tailcfg.MapResponse.SSHPolicy] - always sent together

	// Peer changes.
	PeersChanged []types.NodeID
	PeersRemoved []types.NodeID
	PeerPatches  []*tailcfg.PeerChange
	SendAllPeers bool

	// RequiresRuntimePeerComputation indicates that peer visibility
	// must be computed at runtime per-node. Used for policy changes
	// where each node may have different peer visibility.
	RequiresRuntimePeerComputation bool

	// PingRequest, if non-nil, is a ping request to send to the node.
	// Used by the debug ping endpoint to verify node connectivity.
	// [Change.PingRequest] is always targeted to a specific node via [Change.TargetNode].
	PingRequest *tailcfg.PingRequest
}

// boolFieldNames returns all boolean field names for exhaustive testing.
// When adding a new boolean field to [Change], add it here.
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

	merged.PeersChanged = uniqueNodeIDs(slices.Concat(r.PeersChanged, other.PeersChanged))
	merged.PeersRemoved = uniqueNodeIDs(slices.Concat(r.PeersRemoved, other.PeersRemoved))
	merged.PeerPatches = slices.Concat(r.PeerPatches, other.PeerPatches)

	// Preserve [Change.OriginNode] for self-update detection.
	// If either change has [Change.OriginNode] set, keep it so the mapper
	// can detect self-updates and send the node its own changes.
	if merged.OriginNode == 0 {
		merged.OriginNode = other.OriginNode
	}

	// Preserve [Change.TargetNode] for targeted responses.
	// Merging two changes targeted at different nodes is not supported
	// because the merged result can only have one [Change.TargetNode], which
	// would cause the other target's content to be misrouted.
	if merged.TargetNode != 0 && other.TargetNode != 0 && merged.TargetNode != other.TargetNode {
		panic(fmt.Sprintf(
			"cannot merge changes with different TargetNode: %d != %d",
			merged.TargetNode, other.TargetNode,
		))
	}

	if merged.TargetNode == 0 {
		merged.TargetNode = other.TargetNode
	}

	// Preserve [Change.PingRequest] (first wins).
	//
	// Foot-gun: if two [tailcfg.PingRequest] values to the same target merge in the
	// same tick, only the first is emitted. The client-side
	// isUniquePingRequest check then suppresses the second when it
	// eventually arrives, and the caller waits out the full
	// pingTimeout. Call sites must avoid issuing rapid successive
	// pings to one node within a single batcher tick.
	if merged.PingRequest == nil {
		merged.PingRequest = other.PingRequest
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

	if r.PingRequest != nil {
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

// IsTargetedToNode returns true if this response should only be sent to [Change.TargetNode].
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
// unlike [Change.Reason] which is free-form text for logging.
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

	if r.PingRequest != nil {
		return "ping"
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

// HasFull returns true if any response in the slice is a full update ([Change.IsFull]).
func HasFull(rs []Change) bool {
	return slices.ContainsFunc(rs, Change.IsFull)
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

// IsBroadcastPolicyChange reports whether r is a tailnet-wide policy recompute
// with no per-node payload. A recompute reads the current snapshot, so every
// such change is interchangeable and same-tick duplicates are redundant. A
// targeted or self-update ([Change.OriginNode]) recompute is per-node, so it is
// not one of these.
func (r Change) IsBroadcastPolicyChange() bool {
	return r.RequiresRuntimePeerComputation && !r.IsTargetedToNode() && r.OriginNode == 0
}

// DedupePolicyChanges keeps the first broadcast policy change in a tick and
// drops the rest: each rebuilds a node's whole netmap from the same snapshot, so
// the repeats are wasted work. Order and all other changes are preserved.
func DedupePolicyChanges(changes []Change) []Change {
	if len(changes) < 2 {
		return changes
	}

	out := make([]Change, 0, len(changes))
	seen := false

	for _, r := range changes {
		if r.IsBroadcastPolicyChange() {
			if seen {
				continue
			}

			seen = true
		}

		out = append(out, r)
	}

	return out
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
// Policy changes require runtime peer visibility computation ([Change.RequiresRuntimePeerComputation]).
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
				Online: new(true),
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
				Online: new(false),
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

// High-level change constructors

// NodeAdded returns a [Change] for when a node is added or updated.
// The [Change.OriginNode] field enables self-update detection by the mapper.
func NodeAdded(id types.NodeID) Change {
	c := PeersChanged("node added", id)
	c.OriginNode = id

	return c
}

// NodeRemoved returns a [Change] for when a node is removed.
func NodeRemoved(id types.NodeID) Change {
	return PeersRemoved(id)
}

// KeyExpiryFor returns a [Change] for when a node's key expiry changes.
// The [Change.OriginNode] field enables self-update detection by the mapper.
func KeyExpiryFor(id types.NodeID, expiry time.Time) Change {
	c := KeyExpiry(id, &expiry)
	c.OriginNode = id

	return c
}

// EndpointOrDERPUpdate returns a [Change] for when a node's endpoints or DERP region changes.
// The [Change.OriginNode] field enables self-update detection by the mapper.
func EndpointOrDERPUpdate(id types.NodeID, patch *tailcfg.PeerChange) Change {
	c := PeerPatched("endpoint/DERP update", patch)
	c.OriginNode = id

	return c
}

// NodeKeyRotated returns a [Change] for a node re-logging in: its NodeKey (and
// possibly DiscoKey, key expiry, or endpoints) changed, but nothing structural
// did. Peers only need those changed fields, so it is sent as the minimal
// incremental [tailcfg.PeerChange] patch rather than re-advertising the whole
// node — the smallest update that conveys the rotation, and the least
// disruptive for peers reconciling it.
func NodeKeyRotated(node types.NodeView) Change {
	nk := node.NodeKey()
	dk := node.DiscoKey()

	// KeyExpiry is always set: the zero value clears any prior expiry on the
	// peer (un-expire), and a non-zero value carries the new expiry.
	var expiry time.Time
	if e, ok := node.Expiry().GetOk(); ok {
		expiry = e
	}

	c := PeerPatched("node key rotated (relogin)", &tailcfg.PeerChange{
		NodeID:    tailcfg.NodeID(node.ID()), //nolint:gosec // NodeID is bounded
		Key:       &nk,
		DiscoKey:  &dk,
		KeyExpiry: &expiry,
		Endpoints: node.Endpoints().AsSlice(),
	})
	c.OriginNode = node.ID()

	return c
}

// UserAdded returns a [Change] for when a user is added or updated.
// A full update is sent to refresh user profiles on all nodes.
func UserAdded() Change {
	c := FullUpdate()
	c.Reason = "user added"

	return c
}

// UserRemoved returns a [Change] for when a user is removed.
// A full update is sent to refresh user profiles on all nodes.
func UserRemoved() Change {
	c := FullUpdate()
	c.Reason = "user removed"

	return c
}

// PingNode creates a [Change] that sends a [tailcfg.PingRequest] to a specific
// node. pr must be non-nil and nodeID must be non-zero; the node
// responds to the [tailcfg.PingRequest] URL to prove connectivity.
func PingNode(nodeID types.NodeID, pr *tailcfg.PingRequest) Change {
	return Change{
		Reason:      "ping node",
		TargetNode:  nodeID,
		PingRequest: pr,
	}
}

// ExtraRecords returns a [Change] for when DNS extra records change.
func ExtraRecords() Change {
	c := DNSConfig()
	c.Reason = "extra records update"

	return c
}
