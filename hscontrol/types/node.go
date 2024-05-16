package types

import (
	"database/sql"
	"encoding/json"
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
	"gorm.io/gorm"
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

// Node is a Headscale client.
type Node struct {
	ID NodeID `gorm:"primary_key"`

	// MachineKeyDatabaseField is the string representation of MachineKey
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use MachineKey instead.
	MachineKeyDatabaseField string            `gorm:"column:machine_key;unique_index"`
	MachineKey              key.MachinePublic `gorm:"-"`

	// NodeKeyDatabaseField is the string representation of NodeKey
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use NodeKey instead.
	NodeKeyDatabaseField string         `gorm:"column:node_key"`
	NodeKey              key.NodePublic `gorm:"-"`

	// DiscoKeyDatabaseField is the string representation of DiscoKey
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use DiscoKey instead.
	DiscoKeyDatabaseField string          `gorm:"column:disco_key"`
	DiscoKey              key.DiscoPublic `gorm:"-"`

	// EndpointsDatabaseField is the string list representation of Endpoints
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use Endpoints instead.
	EndpointsDatabaseField StringList       `gorm:"column:endpoints"`
	Endpoints              []netip.AddrPort `gorm:"-"`

	// EndpointsDatabaseField is the string list representation of Endpoints
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use Endpoints instead.
	HostinfoDatabaseField string            `gorm:"column:host_info"`
	Hostinfo              *tailcfg.Hostinfo `gorm:"-"`

	// IPv4DatabaseField is the string representation of v4 address,
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use V4 instead.
	IPv4DatabaseField sql.NullString `gorm:"column:ipv4"`
	IPv4              *netip.Addr    `gorm:"-"`

	// IPv6DatabaseField is the string representation of v4 address,
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use V6 instead.
	IPv6DatabaseField sql.NullString `gorm:"column:ipv6"`
	IPv6              *netip.Addr    `gorm:"-"`

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

	ForcedTags StringList

	// TODO(kradalby): This seems like irrelevant information?
	AuthKeyID *uint       `sql:"DEFAULT:NULL"`
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

	for _, route := range node2.Routes {
		if route.Enabled {
			allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix).Addr())
		}
	}

	for _, rule := range filter {
		// TODO(kradalby): Cache or pregen this
		matcher := matcher.MatchFromFilterRule(rule)

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

// BeforeSave is a hook that ensures that some values that
// cannot be directly marshalled into database values are stored
// correctly in the database.
// This currently means storing the keys as strings.
func (node *Node) BeforeSave(tx *gorm.DB) error {
	node.MachineKeyDatabaseField = node.MachineKey.String()
	node.NodeKeyDatabaseField = node.NodeKey.String()
	node.DiscoKeyDatabaseField = node.DiscoKey.String()

	var endpoints StringList
	for _, addrPort := range node.Endpoints {
		endpoints = append(endpoints, addrPort.String())
	}

	node.EndpointsDatabaseField = endpoints

	hi, err := json.Marshal(node.Hostinfo)
	if err != nil {
		return fmt.Errorf("marshalling Hostinfo to store in db: %w", err)
	}
	node.HostinfoDatabaseField = string(hi)

	if node.IPv4 != nil {
		node.IPv4DatabaseField.String, node.IPv4DatabaseField.Valid = node.IPv4.String(), true
	} else {
		node.IPv4DatabaseField.String, node.IPv4DatabaseField.Valid = "", false
	}

	if node.IPv6 != nil {
		node.IPv6DatabaseField.String, node.IPv6DatabaseField.Valid = node.IPv6.String(), true
	} else {
		node.IPv6DatabaseField.String, node.IPv6DatabaseField.Valid = "", false
	}

	return nil
}

// AfterFind is a hook that ensures that Node objects fields that
// has a different type in the database is unwrapped and populated
// correctly.
// This currently unmarshals all the keys, stored as strings, into
// the proper types.
func (node *Node) AfterFind(tx *gorm.DB) error {
	var machineKey key.MachinePublic
	if err := machineKey.UnmarshalText([]byte(node.MachineKeyDatabaseField)); err != nil {
		return fmt.Errorf("unmarshalling machine key from db: %w", err)
	}
	node.MachineKey = machineKey

	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(node.NodeKeyDatabaseField)); err != nil {
		return fmt.Errorf("unmarshalling node key from db: %w", err)
	}
	node.NodeKey = nodeKey

	// DiscoKey might be empty if a node has not sent it to headscale.
	// This means that this might fail if the disco key is empty.
	if node.DiscoKeyDatabaseField != "" {
		var discoKey key.DiscoPublic
		if err := discoKey.UnmarshalText([]byte(node.DiscoKeyDatabaseField)); err != nil {
			return fmt.Errorf("unmarshalling disco key from db: %w", err)
		}
		node.DiscoKey = discoKey
	}

	endpoints := make([]netip.AddrPort, len(node.EndpointsDatabaseField))
	for idx, ep := range node.EndpointsDatabaseField {
		addrPort, err := netip.ParseAddrPort(ep)
		if err != nil {
			return fmt.Errorf("parsing endpoint from db: %w", err)
		}

		endpoints[idx] = addrPort
	}
	node.Endpoints = endpoints

	var hi tailcfg.Hostinfo
	if err := json.Unmarshal([]byte(node.HostinfoDatabaseField), &hi); err != nil {
		return fmt.Errorf("unmarshalling hostinfo from database: %w", err)
	}
	node.Hostinfo = &hi

	if node.IPv4DatabaseField.Valid {
		ip, err := netip.ParseAddr(node.IPv4DatabaseField.String)
		if err != nil {
			return fmt.Errorf("parsing IPv4 from database: %w", err)
		}

		node.IPv4 = &ip
	}

	if node.IPv6DatabaseField.Valid {
		ip, err := netip.ParseAddr(node.IPv6DatabaseField.String)
		if err != nil {
			return fmt.Errorf("parsing IPv6 from database: %w", err)
		}

		node.IPv6 = &ip
	}

	return nil
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

		// TODO(kradalby): Implement register method enum converter
		// RegisterMethod: ,

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

func (node *Node) GetFQDN(dnsConfig *tailcfg.DNSConfig, baseDomain string) (string, error) {
	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		if node.GivenName == "" {
			return "", fmt.Errorf("failed to create valid FQDN: %w", ErrNodeHasNoGivenName)
		}

		if node.User.Name == "" {
			return "", fmt.Errorf("failed to create valid FQDN: %w", ErrNodeUserHasNoName)
		}

		hostname = fmt.Sprintf(
			"%s.%s.%s",
			node.GivenName,
			node.User.Name,
			baseDomain,
		)
		if len(hostname) > MaxHostnameLength {
			return "", fmt.Errorf(
				"failed to create valid FQDN (%s): %w",
				hostname,
				ErrHostnameTooLong,
			)
		}
	} else {
		hostname = node.GivenName
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
