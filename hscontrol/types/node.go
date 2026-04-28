package types

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"go4.org/netipx"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

var (
	ErrNodeAddressesInvalid = errors.New("parsing node addresses")
	ErrHostnameTooLong      = errors.New("hostname too long, cannot accept more than 255 ASCII chars")
	ErrNodeHasNoGivenName   = errors.New("node has no given name")
	ErrNodeUserHasNoName    = errors.New("node user has no name")
	ErrCannotRemoveAllTags  = errors.New("cannot remove all tags from node")
	ErrInvalidNodeView      = errors.New("cannot convert invalid NodeView to tailcfg.Node")
)

// RouteFunc is a function that takes a node ID and returns a list of
// netip.Prefixes representing the routes for that node.
type RouteFunc func(id NodeID) []netip.Prefix

// ViaRouteResult describes via grant effects for a viewer-peer pair.
// UsePrimary is always a subset of Include: it marks which included
// prefixes must additionally defer to HA primary election.
type ViaRouteResult struct {
	// Include contains prefixes this peer should serve to this viewer (via-designated).
	Include []netip.Prefix
	// Exclude contains prefixes steered to OTHER peers (suppress from global primary).
	Exclude []netip.Prefix
	// UsePrimary contains prefixes from Include where a regular
	// (non-via) grant also covers the prefix. In these cases HA
	// primary election wins — only the primary router should get
	// the route in AllowedIPs. When a prefix is NOT in UsePrimary,
	// per-viewer via steering applies.
	UsePrimary []netip.Prefix
}

type (
	NodeID  uint64
	NodeIDs []NodeID
)

func (n NodeIDs) Len() int           { return len(n) }
func (n NodeIDs) Less(i, j int) bool { return n[i] < n[j] }
func (n NodeIDs) Swap(i, j int)      { n[i], n[j] = n[j], n[i] }

func (id NodeID) StableID() tailcfg.StableNodeID {
	return tailcfg.StableNodeID(strconv.FormatUint(uint64(id), util.Base10))
}

func (id NodeID) NodeID() tailcfg.NodeID {
	return tailcfg.NodeID(id) //nolint:gosec // NodeID is bounded
}

func (id NodeID) Uint64() uint64 {
	return uint64(id)
}

func (id NodeID) String() string {
	return strconv.FormatUint(id.Uint64(), util.Base10)
}

func ParseNodeID(s string) (NodeID, error) {
	id, err := strconv.ParseUint(s, util.Base10, 64)
	return NodeID(id), err
}

func MustParseNodeID(s string) NodeID {
	id, err := ParseNodeID(s)
	if err != nil {
		panic(err)
	}

	return id
}

// Node is a Headscale client.
type Node struct {
	ID NodeID `gorm:"primary_key"`

	MachineKey key.MachinePublic `gorm:"serializer:text"`
	NodeKey    key.NodePublic    `gorm:"serializer:text"`
	DiscoKey   key.DiscoPublic   `gorm:"serializer:text"`

	Endpoints []netip.AddrPort `gorm:"serializer:json"`

	Hostinfo *tailcfg.Hostinfo `gorm:"column:host_info;serializer:json"`

	IPv4 *netip.Addr `gorm:"column:ipv4;serializer:text"`
	IPv6 *netip.Addr `gorm:"column:ipv6;serializer:text"`

	// Hostname represents the name given by the Tailscale
	// client during registration
	Hostname string

	// Givenname represents either:
	// a DNS normalized version of Hostname
	// a valid name set by the User
	//
	// GivenName is the name used in all DNS related
	// parts of headscale.
	GivenName string `gorm:"type:varchar(63);unique_index"`

	// UserID identifies the owning user for user-owned nodes.
	// Nil for tagged nodes, which are owned by their tags.
	UserID *uint
	User   *User `gorm:"constraint:OnDelete:CASCADE;"`

	RegisterMethod string

	// Tags is the definitive owner for tagged nodes.
	// When non-empty, the node is "tagged" and tags define its identity.
	// Empty for user-owned nodes.
	// Tags cannot be removed once set (one-way transition).
	Tags []string `gorm:"column:tags;serializer:json"`

	// When a node has been created with a PreAuthKey, we need to
	// prevent the preauthkey from being deleted before the node.
	// The preauthkey can define "tags" of the node so we need it
	// around.
	AuthKeyID *uint64 `sql:"DEFAULT:NULL"`
	AuthKey   *PreAuthKey

	Expiry *time.Time

	// LastSeen is when the node was last in contact with
	// headscale. It is best effort and not persisted.
	LastSeen *time.Time `gorm:"column:last_seen"`

	// ApprovedRoutes is a list of routes that the node is allowed to announce
	// as a subnet router. They are not necessarily the routes that the node
	// announces at the moment.
	// See [Node.Hostinfo]
	ApprovedRoutes []netip.Prefix `gorm:"column:approved_routes;serializer:json"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	IsOnline *bool `gorm:"-"`

	// Unhealthy excludes the node from primary route election while
	// online. Written by the HA prober. Runtime-only.
	Unhealthy bool `gorm:"-"`

	// SessionEpoch identifies a poll session. Connect bumps it; a
	// Disconnect carrying a stale value is dropped, so a deferred
	// disconnect from a previous session cannot overwrite a newer
	// Connect. Runtime-only.
	SessionEpoch uint64 `gorm:"-"`
}

type Nodes []*Node

func (ns Nodes) ViewSlice() views.Slice[NodeView] {
	vs := make([]NodeView, len(ns))
	for i, n := range ns {
		vs[i] = n.View()
	}

	return views.SliceOf(vs)
}

// IsExpired returns whether the node registration has expired.
func (node *Node) IsExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefore considered
	// to mean "not expired"
	if node.Expiry == nil || node.Expiry.IsZero() {
		return false
	}

	return time.Since(*node.Expiry) > 0
}

// IsEphemeral returns if the node is registered as an Ephemeral node.
// https://tailscale.com/docs/features/ephemeral-nodes
func (node *Node) IsEphemeral() bool {
	return node.AuthKey != nil && node.AuthKey.Ephemeral
}

// IPs returns the node's allocated Tailscale addresses. Order is
// deterministic: IPv4 (if allocated) first, IPv6 second. At most one
// of each family.
func (node *Node) IPs() []netip.Addr {
	var ret []netip.Addr

	if node.IPv4 != nil {
		ret = append(ret, *node.IPv4)
	}

	if node.IPv6 != nil {
		ret = append(ret, *node.IPv6)
	}

	return ret
}

// HasIP reports if a node has a given IP address.
func (node *Node) HasIP(i netip.Addr) bool {
	for _, ip := range node.IPs() {
		if ip.Compare(i) == 0 {
			return true
		}
	}

	return false
}

// IsTagged reports if a device is tagged and therefore should not be treated
// as a user-owned device.
// When a node has tags, the tags define its identity (not the user).
func (node *Node) IsTagged() bool {
	return len(node.Tags) > 0
}

// IsUserOwned returns true if node is owned by a user (not tagged).
// Tagged nodes may have a UserID for "created by" tracking, but the tag is the owner.
func (node *Node) IsUserOwned() bool {
	return !node.IsTagged()
}

// HasTag reports if a node has a given tag.
func (node *Node) HasTag(tag string) bool {
	return slices.Contains(node.Tags, tag)
}

// TypedUserID returns the UserID as a typed UserID type.
// Returns 0 if UserID is nil.
func (node *Node) TypedUserID() UserID {
	if node.UserID == nil {
		return 0
	}

	return UserID(*node.UserID)
}

func (node *Node) RequestTags() []string {
	if node.Hostinfo == nil {
		return []string{}
	}

	return node.Hostinfo.RequestTags
}

func (node *Node) Prefixes() []netip.Prefix {
	ips := node.IPs()
	if len(ips) == 0 {
		return nil
	}

	addrs := make([]netip.Prefix, 0, len(ips))

	for _, nodeAddress := range ips {
		ip := netip.PrefixFrom(nodeAddress, nodeAddress.BitLen())
		addrs = append(addrs, ip)
	}

	return addrs
}

// ExitRoutes returns the node's approved exit routes (0.0.0.0/0
// and/or ::/0). Consumed unconditionally by RoutesForPeer when the
// viewer uses an exit node; excluded from CanAccessRoute which only
// handles non-exit routing.
func (node *Node) ExitRoutes() []netip.Prefix {
	var routes []netip.Prefix

	for _, route := range node.AnnouncedRoutes() {
		if tsaddr.IsExitRoute(route) && slices.Contains(node.ApprovedRoutes, route) {
			routes = append(routes, route)
		}
	}

	return routes
}

// IsExitNode reports whether the node has any approved exit routes.
// Approval is required: an advertised-but-unapproved exit route does
// not make the node an exit node (fix for #3169).
func (node *Node) IsExitNode() bool {
	return len(node.ExitRoutes()) > 0
}

func (node *Node) IPsAsString() []string {
	ips := node.IPs()
	if len(ips) == 0 {
		return nil
	}

	ret := make([]string, 0, len(ips))

	for _, ip := range ips {
		ret = append(ret, ip.String())
	}

	return ret
}

func (node *Node) InIPSet(set *netipx.IPSet) bool {
	return slices.ContainsFunc(node.IPs(), set.Contains)
}

// AppendToIPSet adds all IP addresses of the node to the given
// netipx.IPSetBuilder. For identity-based aliases (tags, users,
// groups, autogroups), both IPv4 and IPv6 must be included to
// match Tailscale's behavior in the FilterRule wire format.
func (node *Node) AppendToIPSet(build *netipx.IPSetBuilder) {
	if node.IPv4 != nil {
		build.Add(*node.IPv4)
	}

	if node.IPv6 != nil {
		build.Add(*node.IPv6)
	}
}

// CanAccess reports whether node may reach node2 under the given
// matchers. A node owns two source identities for ACL purposes:
//   - its own IPs (regular peer membership)
//   - any approved subnet routes it advertises (subnet-router-as-src,
//     used for subnet-to-subnet ACLs — issue #3157)
//
// Either identity matching a rule's src — combined with the dst
// matching node2's IPs, node2's approved subnet routes, or "the
// internet" when node2 is an exit node — grants access.
func (node *Node) CanAccess(matchers []matcher.Match, node2 *Node) bool {
	src := node.IPs()
	allowedIPs := node2.IPs()
	srcRoutes := node.SubnetRoutes()
	dstRoutes := node2.SubnetRoutes()
	dstIsExit := node2.IsExitNode()

	for _, m := range matchers {
		srcMatchesIP := m.SrcsContainsIPs(src...)
		srcMatchesRoutes := len(srcRoutes) > 0 && m.SrcsOverlapsPrefixes(srcRoutes...)

		if !srcMatchesIP && !srcMatchesRoutes {
			continue
		}

		if m.DestsContainsIP(allowedIPs...) {
			return true
		}

		if len(dstRoutes) > 0 && m.DestsOverlapsPrefixes(dstRoutes...) {
			return true
		}

		if dstIsExit && m.DestsIsTheInternet() {
			return true
		}
	}

	return false
}

// CanAccessRoute determines whether a specific route prefix should be
// visible to this node based on the given matchers.
//
// Unlike CanAccess, this function intentionally does NOT check
// DestsIsTheInternet(). Exit routes (0.0.0.0/0, ::/0) are handled by
// RoutesForPeer (state.go) which adds them unconditionally from
// ExitRoutes(), not through ACL-based route filtering. The
// DestsIsTheInternet check in CanAccess exists solely for peer
// visibility determination (should two nodes see each other), which
// is a separate concern from route prefix authorization.
//
// Additionally, autogroup:internet is explicitly skipped during filter
// rule compilation (filter.go), so no matchers ever contain "the
// internet" from internet-targeted ACLs. Wildcard "*" dests produce
// matchers where DestsOverlapsPrefixes(0.0.0.0/0) already returns
// true, so the check would be redundant for that case.
func (node *Node) CanAccessRoute(matchers []matcher.Match, route netip.Prefix) bool {
	src := node.IPs()
	subnetRoutes := node.SubnetRoutes()

	for _, matcher := range matchers {
		if matcher.SrcsContainsIPs(src...) && matcher.DestsOverlapsPrefixes(route) {
			return true
		}

		if matcher.SrcsOverlapsPrefixes(route) && matcher.DestsContainsIP(src...) {
			return true
		}

		// A subnet router acts on behalf of its advertised subnets.
		// If the node's approved subnet routes overlap the source set
		// and the route overlaps the destination set, the router needs
		// this route to forward traffic from its local subnet.
		if len(subnetRoutes) > 0 {
			if matcher.SrcsOverlapsPrefixes(subnetRoutes...) &&
				matcher.DestsOverlapsPrefixes(route) {
				return true
			}

			// Reverse: traffic from the route's subnet is destined for
			// this node's subnets; the router needs the route for return
			// traffic.
			if matcher.SrcsOverlapsPrefixes(route) &&
				matcher.DestsOverlapsPrefixes(subnetRoutes...) {
				return true
			}
		}
	}

	return false
}

func (nodes Nodes) FilterByIP(ip netip.Addr) Nodes {
	var found Nodes

	for _, node := range nodes {
		if node.IPv4 != nil && ip == *node.IPv4 {
			found = append(found, node)
			continue
		}

		if node.IPv6 != nil && ip == *node.IPv6 {
			found = append(found, node)
		}
	}

	return found
}

func (nodes Nodes) ContainsNodeKey(nodeKey key.NodePublic) bool {
	for _, node := range nodes {
		if node.NodeKey == nodeKey {
			return true
		}
	}

	return false
}

func (node *Node) Proto() *v1.Node {
	nodeProto := &v1.Node{
		Id:         uint64(node.ID),
		MachineKey: node.MachineKey.String(),

		NodeKey:  node.NodeKey.String(),
		DiscoKey: node.DiscoKey.String(),

		// TODO(kradalby): replace list with v4, v6 field?
		IpAddresses: node.IPsAsString(),
		Name:        node.Hostname,
		GivenName:   node.GivenName,
		User:        nil, // Will be set below based on node type
		Tags:        node.Tags,
		Online:      node.IsOnline != nil && *node.IsOnline,

		// Only ApprovedRoutes and AvailableRoutes is set here. SubnetRoutes has
		// to be populated manually with PrimaryRoute, to ensure it includes the
		// routes that are actively served from the node.
		ApprovedRoutes:  util.PrefixesToString(node.ApprovedRoutes),
		AvailableRoutes: util.PrefixesToString(node.AnnouncedRoutes()),

		RegisterMethod: node.RegisterMethodToV1Enum(),

		CreatedAt: timestamppb.New(node.CreatedAt),
	}

	// Set User field based on node ownership
	// Note: User will be set to TaggedDevices in the gRPC layer (grpcv1.go)
	// for proper MapResponse formatting
	if node.User != nil {
		nodeProto.User = node.User.Proto()
	}

	if node.AuthKey != nil {
		nodeProto.PreAuthKey = node.AuthKey.Proto()
	}

	if node.LastSeen != nil {
		nodeProto.LastSeen = timestamppb.New(*node.LastSeen)
	}

	if node.Expiry != nil {
		nodeProto.Expiry = timestamppb.New(*node.Expiry)
	}

	return nodeProto
}

func (node *Node) GetFQDN(baseDomain string) (string, error) {
	if node.GivenName == "" {
		return "", fmt.Errorf("creating valid FQDN: %w", ErrNodeHasNoGivenName)
	}

	hostname := node.GivenName

	if baseDomain != "" {
		hostname = fmt.Sprintf(
			"%s.%s.",
			node.GivenName,
			baseDomain,
		)
	}

	if len(hostname) > MaxHostnameLength {
		return "", fmt.Errorf(
			"creating valid FQDN (%s): %w",
			hostname,
			ErrHostnameTooLong,
		)
	}

	return hostname, nil
}

// AnnouncedRoutes returns the list of routes the node announces, as
// reported by the client in Hostinfo.RoutableIPs. Announcement alone
// does not grant visibility — see SubnetRoutes for approval-gated
// access.
func (node *Node) AnnouncedRoutes() []netip.Prefix {
	if node.Hostinfo == nil {
		return nil
	}

	return node.Hostinfo.RoutableIPs
}

// SubnetRoutes returns the list of routes (excluding exit routes) that the node
// announces and are approved. Also used by CanAccess and CanAccessRoute as part
// of the subnet-router-as-source identity (issue #3157).
//
// IMPORTANT: This method is used for internal data structures and should NOT be
// used for the gRPC Proto conversion. For Proto, SubnetRoutes must be populated
// manually with PrimaryRoutes to ensure it includes only routes actively served
// by the node. See the comment in Proto() method and the implementation in
// grpcv1.go/nodesToProto.
func (node *Node) SubnetRoutes() []netip.Prefix {
	var routes []netip.Prefix

	for _, route := range node.AnnouncedRoutes() {
		if tsaddr.IsExitRoute(route) {
			continue
		}

		if slices.Contains(node.ApprovedRoutes, route) {
			routes = append(routes, route)
		}
	}

	return routes
}

// IsSubnetRouter reports if the node has any subnet routes.
func (node *Node) IsSubnetRouter() bool {
	return len(node.SubnetRoutes()) > 0
}

// AllApprovedRoutes returns the combination of SubnetRoutes and ExitRoutes.
func (node *Node) AllApprovedRoutes() []netip.Prefix {
	return append(node.SubnetRoutes(), node.ExitRoutes()...)
}

func (node *Node) String() string {
	return node.Hostname
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler for safe logging.
// This method is used with zerolog's EmbedObject() for flat field embedding
// or Object() for nested logging when multiple nodes are logged.
func (node *Node) MarshalZerologObject(e *zerolog.Event) {
	if node == nil {
		return
	}

	e.Uint64(zf.NodeID, node.ID.Uint64())
	e.Str(zf.NodeName, node.Hostname)
	e.Str(zf.MachineKey, node.MachineKey.ShortString())
	e.Str(zf.NodeKey, node.NodeKey.ShortString())
	e.Bool(zf.NodeIsTagged, node.IsTagged())
	e.Bool(zf.NodeExpired, node.IsExpired())

	if node.IsOnline != nil {
		e.Bool(zf.NodeOnline, *node.IsOnline)
	}

	if len(node.Tags) > 0 {
		e.Strs(zf.NodeTags, node.Tags)
	}

	if node.User != nil {
		e.Str(zf.UserName, node.User.Username())
	} else if node.UserID != nil {
		e.Uint(zf.UserID, *node.UserID)
	}
}

// PeerChangeFromMapRequest takes a MapRequest and compares it to the node
// to produce a PeerChange struct that can be used to updated the node and
// inform peers about smaller changes to the node.
// When a field is added to this function, remember to also add it to:
// - node.ApplyPeerChange
// - logTracePeerChange in poll.go.
func (node *Node) PeerChangeFromMapRequest(req tailcfg.MapRequest) tailcfg.PeerChange {
	ret := tailcfg.PeerChange{
		NodeID: tailcfg.NodeID(node.ID), //nolint:gosec // NodeID is bounded
	}

	if node.NodeKey.String() != req.NodeKey.String() {
		ret.Key = &req.NodeKey
	}

	if node.DiscoKey.String() != req.DiscoKey.String() {
		ret.DiscoKey = &req.DiscoKey
	}

	if node.Hostinfo != nil &&
		node.Hostinfo.NetInfo != nil &&
		req.Hostinfo != nil &&
		req.Hostinfo.NetInfo != nil &&
		node.Hostinfo.NetInfo.PreferredDERP != req.Hostinfo.NetInfo.PreferredDERP {
		ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
	}

	if req.Hostinfo != nil && req.Hostinfo.NetInfo != nil {
		// If there is no stored Hostinfo or NetInfo, use
		// the new PreferredDERP.
		if node.Hostinfo == nil {
			ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
		} else if node.Hostinfo.NetInfo == nil {
			ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
		} else if node.Hostinfo.NetInfo.PreferredDERP != req.Hostinfo.NetInfo.PreferredDERP {
			// If there is a PreferredDERP check if it has changed.
			ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
		}
	}

	// Compare endpoints using order-independent comparison
	if EndpointsChanged(node.Endpoints, req.Endpoints) {
		ret.Endpoints = req.Endpoints
	}

	now := time.Now()
	ret.LastSeen = &now

	return ret
}

// EndpointsChanged compares two endpoint slices and returns true if they differ.
// The comparison is order-independent - endpoints are sorted before comparison.
func EndpointsChanged(oldEndpoints, newEndpoints []netip.AddrPort) bool {
	if len(oldEndpoints) != len(newEndpoints) {
		return true
	}

	if len(oldEndpoints) == 0 {
		return false
	}

	// Make copies to avoid modifying the original slices
	oldCopy := slices.Clone(oldEndpoints)
	newCopy := slices.Clone(newEndpoints)

	// Sort both slices to enable order-independent comparison
	slices.SortFunc(oldCopy, netip.AddrPort.Compare)
	slices.SortFunc(newCopy, netip.AddrPort.Compare)

	return !slices.Equal(oldCopy, newCopy)
}

func (node *Node) RegisterMethodToV1Enum() v1.RegisterMethod {
	switch node.RegisterMethod {
	case "authkey":
		return v1.RegisterMethod_REGISTER_METHOD_AUTH_KEY
	case "oidc":
		return v1.RegisterMethod_REGISTER_METHOD_OIDC
	case "cli":
		return v1.RegisterMethod_REGISTER_METHOD_CLI
	default:
		return v1.RegisterMethod_REGISTER_METHOD_UNSPECIFIED
	}
}

// ApplyPeerChange takes a PeerChange struct and updates the node.
func (node *Node) ApplyPeerChange(change *tailcfg.PeerChange) {
	if change.Key != nil {
		node.NodeKey = *change.Key
	}

	if change.DiscoKey != nil {
		node.DiscoKey = *change.DiscoKey
	}

	if change.Online != nil {
		node.IsOnline = change.Online
	}

	if change.Endpoints != nil {
		node.Endpoints = change.Endpoints
	}

	// This might technically not be useful as we replace
	// the whole hostinfo blob when it has changed.
	if change.DERPRegion != 0 {
		if node.Hostinfo == nil {
			node.Hostinfo = &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{
					PreferredDERP: change.DERPRegion,
				},
			}
		} else if node.Hostinfo.NetInfo == nil {
			node.Hostinfo.NetInfo = &tailcfg.NetInfo{
				PreferredDERP: change.DERPRegion,
			}
		} else {
			node.Hostinfo.NetInfo.PreferredDERP = change.DERPRegion
		}
	}

	node.LastSeen = change.LastSeen
}

func (nodes Nodes) String() string {
	temp := make([]string, len(nodes))

	for index, node := range nodes {
		temp[index] = node.Hostname
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func (nodes Nodes) IDMap() map[NodeID]*Node {
	ret := map[NodeID]*Node{}

	for _, node := range nodes {
		ret[node.ID] = node
	}

	return ret
}

func (nodes Nodes) DebugString() string {
	var sb strings.Builder
	sb.WriteString("Nodes:\n")

	for _, node := range nodes {
		sb.WriteString(node.DebugString())
		sb.WriteString("\n")
	}

	return sb.String()
}

func (node *Node) DebugString() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s(%s):\n", node.Hostname, node.ID)

	// Show ownership status
	if node.IsTagged() {
		fmt.Fprintf(&sb, "\tTagged: %v\n", node.Tags)

		if node.User != nil {
			fmt.Fprintf(&sb, "\tCreated by: %s (%d, %q)\n", node.User.Display(), node.User.ID, node.User.Username())
		}
	} else if node.User != nil {
		fmt.Fprintf(&sb, "\tUser-owned: %s (%d, %q)\n", node.User.Display(), node.User.ID, node.User.Username())
	} else {
		fmt.Fprintf(&sb, "\tOrphaned: no user or tags\n")
	}

	fmt.Fprintf(&sb, "\tIPs: %v\n", node.IPs())
	fmt.Fprintf(&sb, "\tApprovedRoutes: %v\n", node.ApprovedRoutes)
	fmt.Fprintf(&sb, "\tAnnouncedRoutes: %v\n", node.AnnouncedRoutes())
	fmt.Fprintf(&sb, "\tSubnetRoutes: %v\n", node.SubnetRoutes())
	fmt.Fprintf(&sb, "\tExitRoutes: %v\n", node.ExitRoutes())
	sb.WriteString("\n")

	return sb.String()
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler for NodeView.
// This delegates to the underlying Node's implementation.
func (nv NodeView) MarshalZerologObject(e *zerolog.Event) {
	if !nv.Valid() {
		return
	}

	nv.ж.MarshalZerologObject(e)
}

// Owner returns the owner for display purposes.
// For tagged nodes, returns TaggedDevices. For user-owned nodes, returns the user.
// Returns an invalid UserView if the node is in an orphaned state (no tags, no user).
// Callers should check .Valid() on the result before accessing fields.
func (nv NodeView) Owner() UserView {
	if nv.IsTagged() {
		return TaggedDevices.View()
	}

	if user := nv.User(); user.Valid() {
		return user
	}

	return UserView{}
}

func (nv NodeView) IPs() []netip.Addr {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.IPs()
}

func (nv NodeView) InIPSet(set *netipx.IPSet) bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.InIPSet(set)
}

func (nv NodeView) CanAccess(matchers []matcher.Match, node2 NodeView) bool {
	if !nv.Valid() || !node2.Valid() {
		return false
	}

	return nv.ж.CanAccess(matchers, node2.ж)
}

func (nv NodeView) CanAccessRoute(matchers []matcher.Match, route netip.Prefix) bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.CanAccessRoute(matchers, route)
}

func (nv NodeView) AnnouncedRoutes() []netip.Prefix {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.AnnouncedRoutes()
}

func (nv NodeView) SubnetRoutes() []netip.Prefix {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.SubnetRoutes()
}

func (nv NodeView) IsSubnetRouter() bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.IsSubnetRouter()
}

func (nv NodeView) AllApprovedRoutes() []netip.Prefix {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.AllApprovedRoutes()
}

func (nv NodeView) AppendToIPSet(build *netipx.IPSetBuilder) {
	if !nv.Valid() {
		return
	}

	nv.ж.AppendToIPSet(build)
}

func (nv NodeView) RequestTagsSlice() views.Slice[string] {
	if !nv.Valid() || !nv.Hostinfo().Valid() {
		return views.Slice[string]{}
	}

	return nv.Hostinfo().RequestTags()
}

// IsTagged reports if a device is tagged
// and therefore should not be treated as a
// user owned device.
// Currently, this function only handles tags set
// via CLI ("forced tags" and preauthkeys).
func (nv NodeView) IsTagged() bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.IsTagged()
}

// IsExpired returns whether the node registration has expired.
func (nv NodeView) IsExpired() bool {
	if !nv.Valid() {
		return true
	}

	return nv.ж.IsExpired()
}

// IsEphemeral returns if the node is registered as an Ephemeral node.
// https://tailscale.com/docs/features/ephemeral-nodes
func (nv NodeView) IsEphemeral() bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.IsEphemeral()
}

// PeerChangeFromMapRequest takes a MapRequest and compares it to the node
// to produce a PeerChange struct that can be used to updated the node and
// inform peers about smaller changes to the node.
func (nv NodeView) PeerChangeFromMapRequest(req tailcfg.MapRequest) tailcfg.PeerChange {
	if !nv.Valid() {
		return tailcfg.PeerChange{}
	}

	return nv.ж.PeerChangeFromMapRequest(req)
}

// GetFQDN returns the fully qualified domain name for the node.
func (nv NodeView) GetFQDN(baseDomain string) (string, error) {
	if !nv.Valid() {
		return "", fmt.Errorf("creating valid FQDN: %w", ErrInvalidNodeView)
	}

	return nv.ж.GetFQDN(baseDomain)
}

// ExitRoutes returns a list of both exit routes if the
// node has any exit routes enabled.
// If none are enabled, it will return nil.
func (nv NodeView) ExitRoutes() []netip.Prefix {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.ExitRoutes()
}

func (nv NodeView) IsExitNode() bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.IsExitNode()
}

// RequestTags returns the ACL tags that the node is requesting.
func (nv NodeView) RequestTags() []string {
	if !nv.Valid() || !nv.Hostinfo().Valid() {
		return []string{}
	}

	return nv.Hostinfo().RequestTags().AsSlice()
}

// Proto converts the NodeView to a protobuf representation.
func (nv NodeView) Proto() *v1.Node {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.Proto()
}

// HasIP reports if a node has a given IP address.
func (nv NodeView) HasIP(i netip.Addr) bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.HasIP(i)
}

// HasTag reports if a node has a given tag.
func (nv NodeView) HasTag(tag string) bool {
	if !nv.Valid() {
		return false
	}

	return nv.ж.HasTag(tag)
}

// TypedUserID returns the UserID as a typed UserID type.
// Returns 0 if UserID is nil or node is invalid.
func (nv NodeView) TypedUserID() UserID {
	if !nv.Valid() {
		return 0
	}

	return nv.ж.TypedUserID()
}

// TailscaleUserID returns the user ID to use in Tailscale protocol.
// Tagged nodes always return TaggedDevices.ID, user-owned nodes return their actual UserID.
// Returns 0 for nodes in an orphaned state (no tags, no UserID).
func (nv NodeView) TailscaleUserID() tailcfg.UserID {
	if !nv.Valid() {
		return 0
	}

	if nv.IsTagged() {
		//nolint:gosec // G115: TaggedDevices.ID is a constant that fits in int64
		return tailcfg.UserID(int64(TaggedDevices.ID))
	}

	if !nv.UserID().Valid() {
		return 0
	}

	//nolint:gosec // G115: UserID values are within int64 range
	return tailcfg.UserID(int64(nv.UserID().Get()))
}

// Prefixes returns the node IPs as netip.Prefix.
func (nv NodeView) Prefixes() []netip.Prefix {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.Prefixes()
}

// IPsAsString returns the node IPs as strings.
func (nv NodeView) IPsAsString() []string {
	if !nv.Valid() {
		return nil
	}

	return nv.ж.IPsAsString()
}

// HasNetworkChanges checks if the node has network-related changes.
// Returns true if IPs, announced routes, or approved routes changed.
// This is primarily used for policy cache invalidation. Route slices
// are compared order-insensitively since clients may re-advertise the
// same routes in a different order.
func (nv NodeView) HasNetworkChanges(other NodeView) bool {
	if !slices.Equal(nv.IPs(), other.IPs()) {
		return true
	}

	if !equalPrefixesUnordered(nv.AnnouncedRoutes(), other.AnnouncedRoutes()) {
		return true
	}

	if !equalPrefixesUnordered(nv.SubnetRoutes(), other.SubnetRoutes()) {
		return true
	}

	if !equalPrefixesUnordered(nv.ExitRoutes(), other.ExitRoutes()) {
		return true
	}

	return false
}

// equalPrefixesUnordered reports whether a and b contain the same
// prefixes, order-independent. Inputs are cloned before sorting so
// callers' slices are not mutated.
func equalPrefixesUnordered(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}

	ac := slices.Clone(a)
	bc := slices.Clone(b)

	slices.SortFunc(ac, netip.Prefix.Compare)
	slices.SortFunc(bc, netip.Prefix.Compare)

	return slices.Equal(ac, bc)
}

// HasPolicyChange reports whether the node has changes that affect
// policy evaluation. Includes approved subnet routes because they act
// as source identity in CanAccess for subnet-to-subnet ACLs (#3157).
func (nv NodeView) HasPolicyChange(other NodeView) bool {
	if nv.UserID() != other.UserID() {
		return true
	}

	if !views.SliceEqual(nv.Tags(), other.Tags()) {
		return true
	}

	if !slices.Equal(nv.IPs(), other.IPs()) {
		return true
	}

	if !equalPrefixesUnordered(nv.SubnetRoutes(), other.SubnetRoutes()) {
		return true
	}

	return false
}

// TailNodes converts a slice of NodeViews into Tailscale tailcfg.Nodes.
func TailNodes(
	nodes views.Slice[NodeView],
	capVer tailcfg.CapabilityVersion,
	primaryRouteFunc RouteFunc,
	cfg *Config,
) ([]*tailcfg.Node, error) {
	tNodes := make([]*tailcfg.Node, 0, nodes.Len())

	for _, node := range nodes.All() {
		tNode, err := node.TailNode(capVer, primaryRouteFunc, cfg)
		if err != nil {
			return nil, err
		}

		tNodes = append(tNodes, tNode)
	}

	return tNodes, nil
}

// TailNode converts a NodeView into a Tailscale tailcfg.Node.
func (nv NodeView) TailNode(
	capVer tailcfg.CapabilityVersion,
	primaryRouteFunc RouteFunc,
	cfg *Config,
) (*tailcfg.Node, error) {
	if !nv.Valid() {
		return nil, ErrInvalidNodeView
	}

	hostname, err := nv.GetFQDN(cfg.BaseDomain)
	if err != nil {
		return nil, err
	}

	var derp int
	// TODO(kradalby): legacyDERP was removed in tailscale/tailscale@2fc4455e6dd9ab7f879d4e2f7cffc2be81f14077
	// and should be removed after 111 is the minimum capver.
	legacyDERP := "127.3.3.40:0" // Zero means disconnected or unknown.
	if nv.Hostinfo().Valid() && nv.Hostinfo().NetInfo().Valid() {
		legacyDERP = fmt.Sprintf("127.3.3.40:%d", nv.Hostinfo().NetInfo().PreferredDERP())
		derp = nv.Hostinfo().NetInfo().PreferredDERP()
	}

	var keyExpiry time.Time
	if nv.Expiry().Valid() {
		keyExpiry = nv.Expiry().Get()
	}

	// routeFunc returns ALL routes (subnet + exit) for this node.
	allRoutes := primaryRouteFunc(nv.ID())
	allowedIPs := slices.Concat(nv.Prefixes(), allRoutes)
	slices.SortFunc(allowedIPs, netip.Prefix.Compare)

	// PrimaryRoutes only includes non-exit subnet routes for HA tracking.
	var primaryRoutes []netip.Prefix

	for _, r := range allRoutes {
		if !tsaddr.IsExitRoute(r) {
			primaryRoutes = append(primaryRoutes, r)
		}
	}

	capMap := tailcfg.NodeCapMap{
		tailcfg.CapabilityAdmin: []tailcfg.RawMessage{},
		tailcfg.CapabilitySSH:   []tailcfg.RawMessage{},
	}
	if cfg.RandomizeClientPort {
		capMap[tailcfg.NodeAttrRandomizeClientPort] = []tailcfg.RawMessage{}
	}

	if cfg.Taildrop.Enabled {
		capMap[tailcfg.CapabilityFileSharing] = []tailcfg.RawMessage{}
	}

	// Enable Taildrive sharing and access on all nodes. The actual
	// access control is enforced by cap/drive grants in FilterRules;
	// without a matching grant these attributes alone do nothing.
	capMap[tailcfg.NodeAttrsTaildriveShare] = []tailcfg.RawMessage{}
	capMap[tailcfg.NodeAttrsTaildriveAccess] = []tailcfg.RawMessage{}

	tNode := tailcfg.Node{
		//nolint:gosec // G115: NodeID values are within int64 range
		ID:       tailcfg.NodeID(nv.ID()),
		StableID: nv.ID().StableID(),
		Name:     hostname,
		Cap:      capVer,
		CapMap:   capMap,

		User: nv.TailscaleUserID(),

		Key:       nv.NodeKey(),
		KeyExpiry: keyExpiry.UTC(),

		Machine:          nv.MachineKey(),
		DiscoKey:         nv.DiscoKey(),
		Addresses:        nv.Prefixes(),
		PrimaryRoutes:    primaryRoutes,
		AllowedIPs:       allowedIPs,
		Endpoints:        nv.Endpoints().AsSlice(),
		HomeDERP:         derp,
		LegacyDERPString: legacyDERP,
		Hostinfo:         nv.Hostinfo(),
		Created:          nv.CreatedAt().UTC(),

		Online: nv.IsOnline().Clone(),

		Tags: nv.Tags().AsSlice(),

		MachineAuthorized: !nv.IsExpired(),
		Expired:           nv.IsExpired(),
	}

	// Set LastSeen only for offline nodes to avoid confusing Tailscale clients
	// during rapid reconnection cycles. Online nodes should not have LastSeen set
	// as this can make clients interpret them as "not online" despite Online=true.
	if nv.LastSeen().Valid() && nv.IsOnline().Valid() && !nv.IsOnline().Get() {
		lastSeen := nv.LastSeen().Get()
		tNode.LastSeen = &lastSeen
	}

	return &tNode, nil
}
