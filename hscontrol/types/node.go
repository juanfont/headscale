package types

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/rs/zerolog/log"
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

// Node is a Headscale client.
type Node struct {
	ID uint64 `gorm:"primary_key"`

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

	Routes []Route

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time

	IsOnline *bool `gorm:"-"`
}

type (
	Nodes []*Node
)

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

		var routes []netip.Addr
		for _, route := range node2.Routes {
			routes = append(routes, netip.Prefix(route.Prefix).Addr())
		} 

		if matcher.DestsContainsIP(routes) {
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
		return fmt.Errorf("failed to marshal Hostinfo to store in db: %w", err)
	}
	node.HostinfoDatabaseField = string(hi)

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
		return fmt.Errorf("failed to unmarshal machine key from db: %w", err)
	}
	node.MachineKey = machineKey

	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(node.NodeKeyDatabaseField)); err != nil {
		return fmt.Errorf("failed to unmarshal node key from db: %w", err)
	}
	node.NodeKey = nodeKey

	var discoKey key.DiscoPublic
	if err := discoKey.UnmarshalText([]byte(node.DiscoKeyDatabaseField)); err != nil {
		return fmt.Errorf("failed to unmarshal disco key from db: %w", err)
	}
	node.DiscoKey = discoKey

	endpoints := make([]netip.AddrPort, len(node.EndpointsDatabaseField))
	for idx, ep := range node.EndpointsDatabaseField {
		addrPort, err := netip.ParseAddrPort(ep)
		if err != nil {
			return fmt.Errorf("failed to parse endpoint from db: %w", err)
		}

		endpoints[idx] = addrPort
	}
	node.Endpoints = endpoints

	var hi tailcfg.Hostinfo
	if err := json.Unmarshal([]byte(node.HostinfoDatabaseField), &hi); err != nil {
		log.Trace().Err(err).Msgf("Hostinfo content: %s", node.HostinfoDatabaseField)

		return fmt.Errorf("failed to unmarshal Hostinfo from db: %w", err)
	}
	node.Hostinfo = &hi

	return nil
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

func (nodes Nodes) IDMap() map[uint64]*Node {
	ret := map[uint64]*Node{}

	for _, node := range nodes {
		ret[node.ID] = node
	}

	return ret
}
