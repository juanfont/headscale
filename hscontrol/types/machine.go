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
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	ErrMachineAddressesInvalid = errors.New("failed to parse machine addresses")
	ErrHostnameTooLong         = errors.New("hostname too long")
)

// Machine is a Headscale client.
type Machine struct {
	ID          uint64 `gorm:"primary_key"`
	MachineKey  string `gorm:"type:varchar(64);unique_index"`
	NodeKey     string
	DiscoKey    string
	IPAddresses MachineAddresses

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

	LastSeen             *time.Time
	LastSuccessfulUpdate *time.Time
	Expiry               *time.Time

	HostInfo  HostInfo
	Endpoints StringList

	Routes []Route

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type (
	Machines  []Machine
	MachinesP []*Machine
)

type MachineAddresses []netip.Addr

func (ma MachineAddresses) Sort() {
	sort.Slice(ma, func(index1, index2 int) bool {
		if ma[index1].Is4() && ma[index2].Is6() {
			return true
		}
		if ma[index1].Is6() && ma[index2].Is4() {
			return false
		}

		return ma[index1].Compare(ma[index2]) < 0
	})
}

func (ma MachineAddresses) StringSlice() []string {
	ma.Sort()
	strSlice := make([]string, 0, len(ma))
	for _, addr := range ma {
		strSlice = append(strSlice, addr.String())
	}

	return strSlice
}

func (ma MachineAddresses) Prefixes() []netip.Prefix {
	addrs := []netip.Prefix{}
	for _, machineAddress := range ma {
		ip := netip.PrefixFrom(machineAddress, machineAddress.BitLen())
		addrs = append(addrs, ip)
	}

	return addrs
}

func (ma MachineAddresses) InIPSet(set *netipx.IPSet) bool {
	for _, machineAddr := range ma {
		if set.Contains(machineAddr) {
			return true
		}
	}

	return false
}

// AppendToIPSet adds the individual ips in MachineAddresses to a
// given netipx.IPSetBuilder.
func (ma MachineAddresses) AppendToIPSet(build *netipx.IPSetBuilder) {
	for _, ip := range ma {
		build.Add(ip)
	}
}

func (ma *MachineAddresses) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		addresses := strings.Split(value, ",")
		*ma = (*ma)[:0]
		for _, addr := range addresses {
			if len(addr) < 1 {
				continue
			}
			parsed, err := netip.ParseAddr(addr)
			if err != nil {
				return err
			}
			*ma = append(*ma, parsed)
		}

		return nil

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrMachineAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (ma MachineAddresses) Value() (driver.Value, error) {
	addresses := strings.Join(ma.StringSlice(), ",")

	return addresses, nil
}

// IsExpired returns whether the machine registration has expired.
func (machine Machine) IsExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefor considered
	// to mean "not expired"
	if machine.Expiry == nil || machine.Expiry.IsZero() {
		return false
	}

	return time.Now().UTC().After(*machine.Expiry)
}

// IsOnline returns if the machine is connected to Headscale.
// This is really a naive implementation, as we don't really see
// if there is a working connection between the client and the server.
func (machine *Machine) IsOnline() bool {
	if machine.LastSeen == nil {
		return false
	}

	if machine.IsExpired() {
		return false
	}

	return machine.LastSeen.After(time.Now().Add(-KeepAliveInterval))
}

// IsEphemeral returns if the machine is registered as an Ephemeral node.
// https://tailscale.com/kb/1111/ephemeral-nodes/
func (machine *Machine) IsEphemeral() bool {
	return machine.AuthKey != nil && machine.AuthKey.Ephemeral
}

func (machine *Machine) CanAccess(filter []tailcfg.FilterRule, machine2 *Machine) bool {
	for _, rule := range filter {
		// TODO(kradalby): Cache or pregen this
		matcher := matcher.MatchFromFilterRule(rule)

		if !matcher.SrcsContainsIPs([]netip.Addr(machine.IPAddresses)) {
			continue
		}

		if matcher.DestsContainsIP([]netip.Addr(machine2.IPAddresses)) {
			return true
		}
	}

	return false
}

func (machines Machines) FilterByIP(ip netip.Addr) Machines {
	found := make(Machines, 0)

	for _, machine := range machines {
		for _, mIP := range machine.IPAddresses {
			if ip == mIP {
				found = append(found, machine)
			}
		}
	}

	return found
}

func (machine *Machine) Proto() *v1.Machine {
	machineProto := &v1.Machine{
		Id:         machine.ID,
		MachineKey: machine.MachineKey,

		NodeKey:     machine.NodeKey,
		DiscoKey:    machine.DiscoKey,
		IpAddresses: machine.IPAddresses.StringSlice(),
		Name:        machine.Hostname,
		GivenName:   machine.GivenName,
		User:        machine.User.Proto(),
		ForcedTags:  machine.ForcedTags,
		Online:      machine.IsOnline(),

		// TODO(kradalby): Implement register method enum converter
		// RegisterMethod: ,

		CreatedAt: timestamppb.New(machine.CreatedAt),
	}

	if machine.AuthKey != nil {
		machineProto.PreAuthKey = machine.AuthKey.Proto()
	}

	if machine.LastSeen != nil {
		machineProto.LastSeen = timestamppb.New(*machine.LastSeen)
	}

	if machine.LastSuccessfulUpdate != nil {
		machineProto.LastSuccessfulUpdate = timestamppb.New(
			*machine.LastSuccessfulUpdate,
		)
	}

	if machine.Expiry != nil {
		machineProto.Expiry = timestamppb.New(*machine.Expiry)
	}

	return machineProto
}

// GetHostInfo returns a Hostinfo struct for the machine.
func (machine *Machine) GetHostInfo() tailcfg.Hostinfo {
	return tailcfg.Hostinfo(machine.HostInfo)
}

func (machine *Machine) GetFQDN(dnsConfig *tailcfg.DNSConfig, baseDomain string) (string, error) {
	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf(
			"%s.%s.%s",
			machine.GivenName,
			machine.User.Name,
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
		hostname = machine.GivenName
	}

	return hostname, nil
}

func (machine *Machine) MachinePublicKey() (key.MachinePublic, error) {
	var machineKey key.MachinePublic

	if machine.MachineKey != "" {
		err := machineKey.UnmarshalText(
			[]byte(util.MachinePublicKeyEnsurePrefix(machine.MachineKey)),
		)
		if err != nil {
			return key.MachinePublic{}, fmt.Errorf("failed to parse machine public key: %w", err)
		}
	}

	return machineKey, nil
}

func (machine *Machine) DiscoPublicKey() (key.DiscoPublic, error) {
	var discoKey key.DiscoPublic
	if machine.DiscoKey != "" {
		err := discoKey.UnmarshalText(
			[]byte(util.DiscoPublicKeyEnsurePrefix(machine.DiscoKey)),
		)
		if err != nil {
			return key.DiscoPublic{}, fmt.Errorf("failed to parse disco public key: %w", err)
		}
	} else {
		discoKey = key.DiscoPublic{}
	}

	return discoKey, nil
}

func (machine *Machine) NodePublicKey() (key.NodePublic, error) {
	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText([]byte(util.NodePublicKeyEnsurePrefix(machine.NodeKey)))
	if err != nil {
		return key.NodePublic{}, fmt.Errorf("failed to parse node public key: %w", err)
	}

	return nodeKey, nil
}

func (machine Machine) String() string {
	return machine.Hostname
}

func (machines Machines) String() string {
	temp := make([]string, len(machines))

	for index, machine := range machines {
		temp[index] = machine.Hostname
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

// TODO(kradalby): Remove when we have generics...
func (machines MachinesP) String() string {
	temp := make([]string, len(machines))

	for index, machine := range machines {
		temp[index] = machine.Hostname
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}
