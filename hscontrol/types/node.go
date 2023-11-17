package types

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"go4.org/netipx"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	ErrNodeAddressesInvalid = errors.New("failed to parse node addresses")
	ErrHostnameTooLong      = errors.New("hostname too long")
)

// Node is a Headscale client.
type Node struct {
	ID uint64 `gorm:"primary_key"`

	// MachineKeyValue is the string representation of MachineKey
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use MachineKey instead.
	MachineKeyValue string `gorm:"column:machine_key;unique_index"`

	// NodeKeyValue is the string representation of NodeKey
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use NodeKey instead.
	NodeKeyValue string `gorm:"column:node_key"`

	// DiscoKeyValue is the string representation of DiscoKey
	// it is _only_ used for reading and writing the key to the
	// database and should not be used.
	// Use DiscoKey instead.
	DiscoKeyValue string `gorm:"column:disco_key"`

	MachineKey key.MachinePublic `gorm:"-"`
	NodeKey    key.NodePublic    `gorm:"-"`
	DiscoKey   key.DiscoPublic   `gorm:"-"`

	IPAddresses NodeAddresses

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
	User      User `gorm:"foreignKey:UserID"`

	RegisterMethod string

	ForcedTags StringList

	// TODO(kradalby): This seems like irrelevant information?
	AuthKeyID uint
	AuthKey   *PreAuthKey

	LastSeen *time.Time
	Expiry   *time.Time

	HostInfo  HostInfo
	Endpoints StringList

	Routes []Route

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type (
	Nodes []*Node
)

func (nodes Nodes) OnlineNodeMap() map[tailcfg.NodeID]bool {
	ret := make(map[tailcfg.NodeID]bool)

	for _, node := range nodes {
		ret[tailcfg.NodeID(node.ID)] = node.IsOnline()
	}

	return ret
}

type NodeAddresses []netip.Addr

func (na NodeAddresses) Sort() {
	sort.Slice(na, func(index1, index2 int) bool {
		if na[index1].Is4() && na[index2].Is6() {
			return true
		}
		if na[index1].Is6() && na[index2].Is4() {
			return false
		}

		return na[index1].Compare(na[index2]) < 0
	})
}

func (na NodeAddresses) StringSlice() []string {
	na.Sort()
	strSlice := make([]string, 0, len(na))
	for _, addr := range na {
		strSlice = append(strSlice, addr.String())
	}

	return strSlice
}

func (na NodeAddresses) Prefixes() []netip.Prefix {
	addrs := []netip.Prefix{}
	for _, nodeAddress := range na {
		ip := netip.PrefixFrom(nodeAddress, nodeAddress.BitLen())
		addrs = append(addrs, ip)
	}

	return addrs
}

func (na NodeAddresses) InIPSet(set *netipx.IPSet) bool {
	for _, nodeAddr := range na {
		if set.Contains(nodeAddr) {
			return true
		}
	}

	return false
}

// AppendToIPSet adds the individual ips in NodeAddresses to a
// given netipx.IPSetBuilder.
func (na NodeAddresses) AppendToIPSet(build *netipx.IPSetBuilder) {
	for _, ip := range na {
		build.Add(ip)
	}
}

func (na *NodeAddresses) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		addresses := strings.Split(value, ",")
		*na = (*na)[:0]
		for _, addr := range addresses {
			if len(addr) < 1 {
				continue
			}
			parsed, err := netip.ParseAddr(addr)
			if err != nil {
				return err
			}
			*na = append(*na, parsed)
		}

		return nil

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrNodeAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (na NodeAddresses) Value() (driver.Value, error) {
	addresses := strings.Join(na.StringSlice(), ",")

	return addresses, nil
}

// IsExpired returns whether the node registration has expired.
func (node Node) IsExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefor considered
	// to mean "not expired"
	if node.Expiry == nil || node.Expiry.IsZero() {
		return false
	}

	return time.Now().UTC().After(*node.Expiry)
}

// TODO(kradalby): Try to replace the types in the DB to be correct.
func (node *Node) EndpointsToAddrPort() ([]netip.AddrPort, error) {
	var ret []netip.AddrPort
	for _, ep := range node.Endpoints {
		addrPort, err := netip.ParseAddrPort(ep)
		if err != nil {
			return nil, err
		}

		ret = append(ret, addrPort)
	}

	return ret, nil
}

// TODO(kradalby): Try to replace the types in the DB to be correct.
func (node *Node) SetEndpointsFromAddrPorts(in []netip.AddrPort) {
	var strs StringList
	for _, addrPort := range in {
		strs = append(strs, addrPort.String())
	}

	node.Endpoints = strs
}

// IsOnline returns if the node is connected to Headscale.
// This is really a naive implementation, as we don't really see
// if there is a working connection between the client and the server.
func (node *Node) IsOnline() bool {
	if node.LastSeen == nil {
		return false
	}

	if node.IsExpired() {
		return false
	}

	return node.LastSeen.After(time.Now().Add(-KeepAliveInterval))
}

// IsEphemeral returns if the node is registered as an Ephemeral node.
// https://tailscale.com/kb/1111/ephemeral-nodes/
func (node *Node) IsEphemeral() bool {
	return node.AuthKey != nil && node.AuthKey.Ephemeral
}

func (node *Node) CanAccess(filter []tailcfg.FilterRule, node2 *Node) bool {
	for _, rule := range filter {
		// TODO(kradalby): Cache or pregen this
		matcher := matcher.MatchFromFilterRule(rule)

		if !matcher.SrcsContainsIPs([]netip.Addr(node.IPAddresses)) {
			continue
		}

		if matcher.DestsContainsIP([]netip.Addr(node2.IPAddresses)) {
			return true
		}
	}

	return false
}

func (nodes Nodes) FilterByIP(ip netip.Addr) Nodes {
	found := make(Nodes, 0)

	for _, node := range nodes {
		for _, mIP := range node.IPAddresses {
			if ip == mIP {
				found = append(found, node)
			}
		}
	}

	return found
}

// BeforeSave is a hook that ensures that some values that
// cannot be directly marshalled into database values are stored
// correctly in the database.
// This currently means storing the keys as strings.
func (n *Node) BeforeSave(tx *gorm.DB) (err error) {
	n.MachineKeyValue = n.MachineKey.String()
	n.NodeKeyValue = n.NodeKey.String()
	n.DiscoKeyValue = n.DiscoKey.String()

	return
}

// AfterFind is a hook that ensures that Node objects fields that
// has a different type in the database is unwrapped and populated
// correctly.
// This currently unmarshals all the keys, stored as strings, into
// the proper types.
func (n *Node) AfterFind(tx *gorm.DB) (err error) {
	var machineKey key.MachinePublic
	if err := machineKey.UnmarshalText([]byte(n.MachineKeyValue)); err != nil {
		return err
	}
	n.MachineKey = machineKey

	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(n.NodeKeyValue)); err != nil {
		return err
	}
	n.NodeKey = nodeKey

	var discoKey key.DiscoPublic
	if err := discoKey.UnmarshalText([]byte(n.DiscoKeyValue)); err != nil {
		return err
	}
	n.DiscoKey = discoKey

	return
}

func (node *Node) Proto() *v1.Node {
	nodeProto := &v1.Node{
		Id:         node.ID,
		MachineKey: node.MachineKey.String(),

		NodeKey:     node.NodeKey.String(),
		DiscoKey:    node.DiscoKey.String(),
		IpAddresses: node.IPAddresses.StringSlice(),
		Name:        node.Hostname,
		GivenName:   node.GivenName,
		User:        node.User.Proto(),
		ForcedTags:  node.ForcedTags,
		Online:      node.IsOnline(),

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

// GetHostInfo returns a Hostinfo struct for the node.
func (node *Node) GetHostInfo() tailcfg.Hostinfo {
	return tailcfg.Hostinfo(node.HostInfo)
}

func (node *Node) GetFQDN(dnsConfig *tailcfg.DNSConfig, baseDomain string) (string, error) {
	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf(
			"%s.%s.%s",
			node.GivenName,
			node.User.Name,
			baseDomain,
		)
		if len(hostname) > MaxHostnameLength {
			return "", fmt.Errorf(
				"hostname %q is too long it cannot except 255 ASCII chars: %w",
				hostname,
				ErrHostnameTooLong,
			)
		}
	} else {
		hostname = node.GivenName
	}

	return hostname, nil
}

func (node Node) String() string {
	return node.Hostname
}

func (nodes Nodes) String() string {
	temp := make([]string, len(nodes))

	for index, node := range nodes {
		temp[index] = node.Hostname
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func (nodes Nodes) IDMap() map[uint64]*Node {
	ret := map[uint64]*Node{}

	for _, node := range nodes {
		ret[node.ID] = node
	}

	return ret
}
