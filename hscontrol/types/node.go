package types

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	ErrNodeAddressesInvalid = errors.New("failed to parse node addresses")
	ErrHostnameTooLong      = errors.New("hostname too long, cannot except 255 ASCII chars")
	ErrNodeHasNoGivenName   = errors.New("node has no given name")
	ErrNodeUserHasNoName    = errors.New("node user has no name")
)

type NodeID uint64

// type NodeConnectedMap *xsync.MapOf[NodeID, bool]

func (id NodeID) StableID() tailcfg.StableNodeID {
	return tailcfg.StableNodeID(strconv.FormatUint(uint64(id), util.Base10))
}

func (id NodeID) NodeID() tailcfg.NodeID {
	return tailcfg.NodeID(id)
}

func (id NodeID) Uint64() uint64 {
	return uint64(id)
}

func (id NodeID) String() string {
	return strconv.FormatUint(id.Uint64(), util.Base10)
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
	UserID    uint
	User      User `gorm:"constraint:OnDelete:CASCADE;"`

	RegisterMethod string

	ForcedTags []string `gorm:"serializer:json"`

	// TODO(kradalby): This seems like irrelevant information?
	AuthKeyID *uint64     `sql:"DEFAULT:NULL"`
	AuthKey   *PreAuthKey `gorm:"constraint:OnDelete:SET NULL;"`

	LastSeen *time.Time
	Expiry   *time.Time

	Routes []Route `gorm:"constraint:OnDelete:CASCADE;"`

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	IsOnline *bool `gorm:"-"`
}

type (
	Nodes []*Node
)

// GivenNameHasBeenChanged returns whether the `givenName` can be automatically changed based on the `Hostname` of the node.
func (node *Node) GivenNameHasBeenChanged() bool {
	return node.GivenName == util.ConvertWithFQDNRules(node.Hostname)
}

// IsExpired returns whether the node registration has expired.
func (node Node) IsExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefor considered
	// to mean "not expired"
	if node.Expiry == nil || node.Expiry.IsZero() {
		return false
	}

	return time.Since(*node.Expiry) > 0
}

// IsEphemeral returns if the node is registered as an Ephemeral node.
// https://tailscale.com/kb/1111/ephemeral-nodes/
func (node *Node) IsEphemeral() bool {
	return node.AuthKey != nil && node.AuthKey.Ephemeral
}

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

func (node *Node) Prefixes() []netip.Prefix {
	addrs := []netip.Prefix{}
	for _, nodeAddress := range node.IPs() {
		ip := netip.PrefixFrom(nodeAddress, nodeAddress.BitLen())
		addrs = append(addrs, ip)
	}

	return addrs
}

func (node *Node) IPsAsString() []string {
	var ret []string

	if node.IPv4 != nil {
		ret = append(ret, node.IPv4.String())
	}

	if node.IPv6 != nil {
		ret = append(ret, node.IPv6.String())
	}

	return ret
}

func (node *Node) InIPSet(set *netipx.IPSet) bool {
	for _, nodeAddr := range node.IPs() {
		if set.Contains(nodeAddr) {
			return true
		}
	}

	return false
}

// AppendToIPSet adds the individual ips in NodeAddresses to a
// given netipx.IPSetBuilder.
func (node *Node) AppendToIPSet(build *netipx.IPSetBuilder) {
	for _, ip := range node.IPs() {
		build.Add(ip)
	}
}

func (node *Node) CanAccess(filter []tailcfg.FilterRule, node2 *Node) bool {
	src := node.IPs()
	allowedIPs := node2.IPs()

	// TODO(kradalby): Regenerate this everytime the filter change, instead of
	// every time we use it.
	matchers := make([]matcher.Match, len(filter))
	for i, rule := range filter {
		matchers[i] = matcher.MatchFromFilterRule(rule)
	}

	for _, route := range node2.Routes {
		if route.Enabled {
			allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix).Addr())
		}
	}

	for _, matcher := range matchers {
		if !matcher.SrcsContainsIPs(src) {
			continue
		}

		if matcher.DestsContainsIP(allowedIPs) {
			return true
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
		User:        node.User.Proto(),
		ForcedTags:  node.ForcedTags,

		RegisterMethod: node.RegisterMethodToV1Enum(),

		CreatedAt: timestamppb.New(node.CreatedAt),
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
		return "", fmt.Errorf("failed to create valid FQDN: %w", ErrNodeHasNoGivenName)
	}

	hostname := node.GivenName

	if baseDomain != "" {
		hostname = fmt.Sprintf(
			"%s.%s",
			node.GivenName,
			baseDomain,
		)
	}

	if len(hostname) > MaxHostnameLength {
		return "", fmt.Errorf(
			"failed to create valid FQDN (%s): %w",
			hostname,
			ErrHostnameTooLong,
		)
	}

	return hostname, nil
}

// func (node *Node) String() string {
// 	return node.Hostname
// }

// PeerChangeFromMapRequest takes a MapRequest and compares it to the node
// to produce a PeerChange struct that can be used to updated the node and
// inform peers about smaller changes to the node.
// When a field is added to this function, remember to also add it to:
// - node.ApplyPeerChange
// - logTracePeerChange in poll.go.
func (node *Node) PeerChangeFromMapRequest(req tailcfg.MapRequest) tailcfg.PeerChange {
	ret := tailcfg.PeerChange{
		NodeID: tailcfg.NodeID(node.ID),
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
		} else {
			// If there is a PreferredDERP check if it has changed.
			if node.Hostinfo.NetInfo.PreferredDERP != req.Hostinfo.NetInfo.PreferredDERP {
				ret.DERPRegion = req.Hostinfo.NetInfo.PreferredDERP
			}
		}
	}

	// TODO(kradalby): Find a good way to compare updates
	ret.Endpoints = req.Endpoints

	now := time.Now()
	ret.LastSeen = &now

	return ret
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

// ApplyHostnameFromHostInfo takes a Hostinfo struct and updates the node.
func (node *Node) ApplyHostnameFromHostInfo(hostInfo *tailcfg.Hostinfo) {
	if hostInfo == nil {
		return
	}

	if node.Hostname != hostInfo.Hostname {
		if node.GivenNameHasBeenChanged() {
			node.GivenName = util.ConvertWithFQDNRules(hostInfo.Hostname)
		}

		node.Hostname = hostInfo.Hostname
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
