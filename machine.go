package headscale

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	ErrMachineNotFound                  = Error("machine not found")
	ErrMachineRouteIsNotAvailable       = Error("route is not available on machine")
	ErrMachineAddressesInvalid          = Error("failed to parse machine addresses")
	ErrMachineNotFoundRegistrationCache = Error(
		"machine not found in registration cache",
	)
	ErrCouldNotConvertMachineInterface = Error("failed to convert machine interface")
	ErrHostnameTooLong                 = Error("Hostname too long")
	ErrDifferentRegisteredNamespace    = Error(
		"machine was previously registered with a different namespace",
	)
	MachineGivenNameHashLength = 8
	MachineGivenNameTrimSize   = 2
)

const (
	maxHostnameLength = 255
)

var (
	ExitRouteV4 = netip.MustParsePrefix("0.0.0.0/0")
	ExitRouteV6 = netip.MustParsePrefix("::/0")
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
	GivenName   string `gorm:"type:varchar(63);unique_index"`
	NamespaceID uint
	Namespace   Namespace `gorm:"foreignKey:NamespaceID"`

	RegisterMethod string

	ForcedTags StringList

	// TODO(kradalby): This seems like irrelevant information?
	AuthKeyID uint
	AuthKey   *PreAuthKey

	LastSeen             *time.Time
	LastSuccessfulUpdate *time.Time
	Expiry               *time.Time

	HostInfo      HostInfo
	Endpoints     StringList
	EnabledRoutes IPPrefixes

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type (
	Machines  []Machine
	MachinesP []*Machine
)

type MachineAddresses []netip.Addr

func (ma MachineAddresses) ToStringSlice() []string {
	strSlice := make([]string, 0, len(ma))
	for _, addr := range ma {
		strSlice = append(strSlice, addr.String())
	}

	return strSlice
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
	addresses := strings.Join(ma.ToStringSlice(), ",")

	return addresses, nil
}

// isExpired returns whether the machine registration has expired.
func (machine Machine) isExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefor considered
	// to mean "not expired"
	if machine.Expiry == nil || machine.Expiry.IsZero() {
		return false
	}

	return time.Now().UTC().After(*machine.Expiry)
}

func containsAddresses(inputs []string, addrs []string) bool {
	for _, addr := range addrs {
		if contains(inputs, addr) {
			return true
		}
	}

	return false
}

// matchSourceAndDestinationWithRule.
func matchSourceAndDestinationWithRule(
	ruleSources []string,
	ruleDestinations []string,
	source []string,
	destination []string,
) bool {
	return containsAddresses(ruleSources, source) &&
		containsAddresses(ruleDestinations, destination)
}

// getFilteredByACLPeerss should return the list of peers authorized to be accessed from machine.
func getFilteredByACLPeers(
	machines []Machine,
	rules []tailcfg.FilterRule,
	machine *Machine,
) Machines {
	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msg("Finding peers filtered by ACLs")

	peers := make(map[uint64]Machine)
	// Aclfilter peers here. We are itering through machines in all namespaces and search through the computed aclRules
	// for match between rule SrcIPs and DstPorts. If the rule is a match we allow the machine to be viewable.
	for _, peer := range machines {
		if peer.ID == machine.ID {
			continue
		}
		for _, rule := range rules {
			var dst []string
			for _, d := range rule.DstPorts {
				dst = append(dst, d.IP)
			}
			if matchSourceAndDestinationWithRule(
				rule.SrcIPs,
				dst,
				machine.IPAddresses.ToStringSlice(),
				peer.IPAddresses.ToStringSlice(),
			) || // match source and destination
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					peer.IPAddresses.ToStringSlice(),
					machine.IPAddresses.ToStringSlice(),
				) || // match return path
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					machine.IPAddresses.ToStringSlice(),
					[]string{"*"},
				) || // match source and all destination
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					peer.IPAddresses.ToStringSlice(),
					[]string{"*"},
				) || // match return path for source and all destination
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					[]string{"*"},
					[]string{"*"},
				) || // match source and all destination
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					[]string{"*"},
					peer.IPAddresses.ToStringSlice(),
				) || // match source and all destination
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					[]string{"*"},
					machine.IPAddresses.ToStringSlice(),
				) { // match all sources and source
				peers[peer.ID] = peer
			}
		}
	}

	authorizedPeers := make([]Machine, 0, len(peers))
	for _, m := range peers {
		authorizedPeers = append(authorizedPeers, m)
	}
	sort.Slice(
		authorizedPeers,
		func(i, j int) bool { return authorizedPeers[i].ID < authorizedPeers[j].ID },
	)

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msgf("Found some machines: %v", machines)

	return authorizedPeers
}

func (h *Headscale) ListPeers(machine *Machine) (Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msg("Finding direct peers")

	machines := Machines{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Where("node_key <> ?",
		machine.NodeKey).Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")

		return Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msgf("Found peers: %s", machines.String())

	return machines, nil
}

func (h *Headscale) getPeers(machine *Machine) (Machines, error) {
	var peers Machines
	var err error

	// If ACLs rules are defined, filter visible host list with the ACLs
	// else use the classic namespace scope
	if h.aclPolicy != nil {
		var machines []Machine
		machines, err = h.ListMachines()
		if err != nil {
			log.Error().Err(err).Msg("Error retrieving list of machines")

			return Machines{}, err
		}
		peers = getFilteredByACLPeers(machines, h.aclRules, machine)
	} else {
		peers, err = h.ListPeers(machine)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot fetch peers")

			return Machines{}, err
		}
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msgf("Found total peers: %s", peers.String())

	return peers, nil
}

func (h *Headscale) getValidPeers(machine *Machine) (Machines, error) {
	validPeers := make(Machines, 0)

	peers, err := h.getPeers(machine)
	if err != nil {
		return Machines{}, err
	}

	for _, peer := range peers {
		if !peer.isExpired() {
			validPeers = append(validPeers, peer)
		}
	}

	return validPeers, nil
}

func (h *Headscale) ListMachines() ([]Machine, error) {
	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Find(&machines).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

func (h *Headscale) ListMachinesByGivenName(givenName string) ([]Machine, error) {
	machines := []Machine{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Find(&machines).Where("given_name = ?", givenName).Error; err != nil {
		return nil, err
	}

	return machines, nil
}

// GetMachine finds a Machine by name and namespace and returns the Machine struct.
func (h *Headscale) GetMachine(namespace string, name string) (*Machine, error) {
	machines, err := h.ListMachinesInNamespace(namespace)
	if err != nil {
		return nil, err
	}

	for _, m := range machines {
		if m.Hostname == name {
			return &m, nil
		}
	}

	return nil, ErrMachineNotFound
}

// GetMachineByGivenName finds a Machine by given name and namespace and returns the Machine struct.
func (h *Headscale) GetMachineByGivenName(namespace string, givenName string) (*Machine, error) {
	machines, err := h.ListMachinesInNamespace(namespace)
	if err != nil {
		return nil, err
	}

	for _, m := range machines {
		if m.GivenName == givenName {
			return &m, nil
		}
	}

	return nil, ErrMachineNotFound
}

// GetMachineByID finds a Machine by ID and returns the Machine struct.
func (h *Headscale) GetMachineByID(id uint64) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").Find(&Machine{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByMachineKey finds a Machine by its MachineKey and returns the Machine struct.
func (h *Headscale) GetMachineByMachineKey(
	machineKey key.MachinePublic,
) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByNodeKey finds a Machine by its current NodeKey.
func (h *Headscale) GetMachineByNodeKey(
	nodeKey key.NodePublic,
) (*Machine, error) {
	machine := Machine{}
	if result := h.db.Preload("Namespace").First(&machine, "node_key = ?",
		NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

// GetMachineByAnyNodeKey finds a Machine by its current NodeKey or the old one, and returns the Machine struct.
func (h *Headscale) GetMachineByAnyNodeKey(
	nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*Machine, error) {
	machine := Machine{}
	if result := h.db.Preload("Namespace").First(&machine, "node_key = ? OR node_key = ?",
		NodePublicKeyStripPrefix(nodeKey), NodePublicKeyStripPrefix(oldNodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &machine, nil
}

// UpdateMachineFromDatabase takes a Machine struct pointer (typically already loaded from database
// and updates it with the latest data from the database.
func (h *Headscale) UpdateMachineFromDatabase(machine *Machine) error {
	if result := h.db.Find(machine).First(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}

// SetTags takes a Machine struct pointer and update the forced tags.
func (h *Headscale) SetTags(machine *Machine, tags []string) error {
	newTags := []string{}
	for _, tag := range tags {
		if !contains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}
	machine.ForcedTags = newTags
	if err := h.UpdateACLRules(); err != nil && !errors.Is(err, errEmptyPolicy) {
		return err
	}
	h.setLastStateChangeToNow()

	if err := h.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to update tags for machine in the database: %w", err)
	}

	return nil
}

// ExpireMachine takes a Machine struct and sets the expire field to now.
func (h *Headscale) ExpireMachine(machine *Machine) error {
	now := time.Now()
	machine.Expiry = &now

	h.setLastStateChangeToNow()

	if err := h.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to expire machine in the database: %w", err)
	}

	return nil
}

// RenameMachine takes a Machine struct and a new GivenName for the machines
// and renames it.
func (h *Headscale) RenameMachine(machine *Machine, newName string) error {
	err := CheckForFQDNRules(
		newName,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "RenameMachine").
			Str("machine", machine.Hostname).
			Str("newName", newName).
			Err(err)

		return err
	}
	machine.GivenName = newName

	h.setLastStateChangeToNow()

	if err := h.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed to rename machine in the database: %w", err)
	}

	return nil
}

// RefreshMachine takes a Machine struct and sets the expire field to now.
func (h *Headscale) RefreshMachine(machine *Machine, expiry time.Time) error {
	now := time.Now()

	machine.LastSuccessfulUpdate = &now
	machine.Expiry = &expiry

	h.setLastStateChangeToNow()

	if err := h.db.Save(machine).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh machine (update expiration) in the database: %w",
			err,
		)
	}

	return nil
}

// DeleteMachine softs deletes a Machine from the database.
func (h *Headscale) DeleteMachine(machine *Machine) error {
	if err := h.db.Delete(&machine).Error; err != nil {
		return err
	}

	return nil
}

func (h *Headscale) TouchMachine(machine *Machine) error {
	return h.db.Updates(Machine{
		ID:                   machine.ID,
		LastSeen:             machine.LastSeen,
		LastSuccessfulUpdate: machine.LastSuccessfulUpdate,
	}).Error
}

// HardDeleteMachine hard deletes a Machine from the database.
func (h *Headscale) HardDeleteMachine(machine *Machine) error {
	if err := h.db.Unscoped().Delete(&machine).Error; err != nil {
		return err
	}

	return nil
}

// GetHostInfo returns a Hostinfo struct for the machine.
func (machine *Machine) GetHostInfo() tailcfg.Hostinfo {
	return tailcfg.Hostinfo(machine.HostInfo)
}

func (h *Headscale) isOutdated(machine *Machine) bool {
	if err := h.UpdateMachineFromDatabase(machine); err != nil {
		// It does not seem meaningful to propagate this error as the end result
		// will have to be that the machine has to be considered outdated.
		return true
	}

	// Get the last update from all headscale namespaces to compare with our nodes
	// last update.
	// TODO(kradalby): Only request updates from namespaces where we can talk to nodes
	// This would mostly be for a bit of performance, and can be calculated based on
	// ACLs.
	lastChange := h.getLastStateChange()
	lastUpdate := machine.CreatedAt
	if machine.LastSuccessfulUpdate != nil {
		lastUpdate = *machine.LastSuccessfulUpdate
	}
	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Time("last_successful_update", lastChange).
		Time("last_state_change", lastUpdate).
		Msgf("Checking if %s is missing updates", machine.Hostname)

	return lastUpdate.Before(lastChange)
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

func (machines Machines) toNodes(
	baseDomain string,
	dnsConfig *tailcfg.DNSConfig,
) ([]*tailcfg.Node, error) {
	nodes := make([]*tailcfg.Node, len(machines))

	for index, machine := range machines {
		node, err := machine.toNode(baseDomain, dnsConfig)
		if err != nil {
			return nil, err
		}

		nodes[index] = node
	}

	return nodes, nil
}

// toNode converts a Machine into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS.
func (machine Machine) toNode(
	baseDomain string,
	dnsConfig *tailcfg.DNSConfig,
) (*tailcfg.Node, error) {
	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText([]byte(NodePublicKeyEnsurePrefix(machine.NodeKey)))
	if err != nil {
		log.Trace().
			Caller().
			Str("node_key", machine.NodeKey).
			Msgf("Failed to parse node public key from hex")

		return nil, fmt.Errorf("failed to parse node public key: %w", err)
	}

	var machineKey key.MachinePublic
	// MachineKey is only used in the legacy protocol
	if machine.MachineKey != "" {
		err = machineKey.UnmarshalText(
			[]byte(MachinePublicKeyEnsurePrefix(machine.MachineKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse machine public key: %w", err)
		}
	}

	var discoKey key.DiscoPublic
	if machine.DiscoKey != "" {
		err := discoKey.UnmarshalText(
			[]byte(DiscoPublicKeyEnsurePrefix(machine.DiscoKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse disco public key: %w", err)
		}
	} else {
		discoKey = key.DiscoPublic{}
	}

	addrs := []netip.Prefix{}
	for _, machineAddress := range machine.IPAddresses {
		ip := netip.PrefixFrom(machineAddress, machineAddress.BitLen())
		addrs = append(addrs, ip)
	}

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	allowedIPs = append(allowedIPs, machine.EnabledRoutes...)

	// TODO(kradalby): This is kind of a hack where we say that
	// all the announced routes (except exit), is presented as primary
	// routes. This might be problematic if two nodes expose the same route.
	// This was added to address an issue where subnet routers stopped working
	// when we only populated AllowedIPs.
	primaryRoutes := []netip.Prefix{}
	if len(machine.EnabledRoutes) > 0 {
		for _, route := range machine.EnabledRoutes {
			if route == ExitRouteV4 || route == ExitRouteV6 {
				continue
			}

			primaryRoutes = append(primaryRoutes, route)
		}
	}

	var derp string
	if machine.HostInfo.NetInfo != nil {
		derp = fmt.Sprintf("127.3.3.40:%d", machine.HostInfo.NetInfo.PreferredDERP)
	} else {
		derp = "127.3.3.40:0" // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if machine.Expiry != nil {
		keyExpiry = *machine.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf(
			"%s.%s.%s",
			machine.GivenName,
			machine.Namespace.Name,
			baseDomain,
		)
		if len(hostname) > maxHostnameLength {
			return nil, fmt.Errorf(
				"hostname %q is too long it cannot except 255 ASCII chars: %w",
				hostname,
				ErrHostnameTooLong,
			)
		}
	} else {
		hostname = machine.GivenName
	}

	hostInfo := machine.GetHostInfo()

	// A node is Online if it is connected to the control server,
	// and we now we update LastSeen every keepAliveInterval duration at least.
	online := machine.LastSeen.After(time.Now().Add(-keepAliveInterval))

	node := tailcfg.Node{
		ID: tailcfg.NodeID(machine.ID), // this is the actual ID
		StableID: tailcfg.StableNodeID(
			strconv.FormatUint(machine.ID, Base10),
		), // in headscale, unlike tailcontrol server, IDs are permanent
		Name:          hostname,
		User:          tailcfg.UserID(machine.NamespaceID),
		Key:           nodeKey,
		KeyExpiry:     keyExpiry,
		Machine:       machineKey,
		DiscoKey:      discoKey,
		Addresses:     addrs,
		AllowedIPs:    allowedIPs,
		PrimaryRoutes: primaryRoutes,
		Endpoints:     machine.Endpoints,
		DERP:          derp,

		Online:   &online,
		Hostinfo: hostInfo.View(),
		Created:  machine.CreatedAt,
		LastSeen: machine.LastSeen,

		KeepAlive:         true,
		MachineAuthorized: !machine.isExpired(),
		Capabilities:      []string{tailcfg.CapabilityFileSharing},
	}

	return &node, nil
}

func (machine *Machine) toProto() *v1.Machine {
	machineProto := &v1.Machine{
		Id:         machine.ID,
		MachineKey: machine.MachineKey,

		NodeKey:     machine.NodeKey,
		DiscoKey:    machine.DiscoKey,
		IpAddresses: machine.IPAddresses.ToStringSlice(),
		Name:        machine.Hostname,
		GivenName:   machine.GivenName,
		Namespace:   machine.Namespace.toProto(),
		ForcedTags:  machine.ForcedTags,

		// TODO(kradalby): Implement register method enum converter
		// RegisterMethod: ,

		CreatedAt: timestamppb.New(machine.CreatedAt),
	}

	if machine.AuthKey != nil {
		machineProto.PreAuthKey = machine.AuthKey.toProto()
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

// getTags will return the tags of the current machine.
// Invalid tags are tags added by a user on a node, and that user doesn't have authority to add this tag.
// Valid tags are tags added by a user that is allowed in the ACL policy to add this tag.
func getTags(
	aclPolicy *ACLPolicy,
	machine Machine,
	stripEmailDomain bool,
) ([]string, []string) {
	validTags := make([]string, 0)
	invalidTags := make([]string, 0)
	if aclPolicy == nil {
		return validTags, invalidTags
	}
	validTagMap := make(map[string]bool)
	invalidTagMap := make(map[string]bool)
	for _, tag := range machine.HostInfo.RequestTags {
		owners, err := expandTagOwners(*aclPolicy, tag, stripEmailDomain)
		if errors.Is(err, errInvalidTag) {
			invalidTagMap[tag] = true

			continue
		}
		var found bool
		for _, owner := range owners {
			if machine.Namespace.Name == owner {
				found = true
			}
		}
		if found {
			validTagMap[tag] = true
		} else {
			invalidTagMap[tag] = true
		}
	}
	for tag := range invalidTagMap {
		invalidTags = append(invalidTags, tag)
	}
	for tag := range validTagMap {
		validTags = append(validTags, tag)
	}

	return validTags, invalidTags
}

func (h *Headscale) RegisterMachineFromAuthCallback(
	nodeKeyStr string,
	namespaceName string,
	registrationMethod string,
) (*Machine, error) {
	nodeKey := key.NodePublic{}
	err := nodeKey.UnmarshalText([]byte(nodeKeyStr))
	if err != nil {
		return nil, err
	}

	if machineInterface, ok := h.registrationCache.Get(NodePublicKeyStripPrefix(nodeKey)); ok {
		if registrationMachine, ok := machineInterface.(Machine); ok {
			namespace, err := h.GetNamespace(namespaceName)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to find namespace in register machine from auth callback, %w",
					err,
				)
			}

			// Registration of expired machine with different namespace
			if registrationMachine.ID != 0 &&
				registrationMachine.NamespaceID != namespace.ID {
				return nil, ErrDifferentRegisteredNamespace
			}

			registrationMachine.NamespaceID = namespace.ID
			registrationMachine.RegisterMethod = registrationMethod

			machine, err := h.RegisterMachine(
				registrationMachine,
			)

			if err == nil {
				h.registrationCache.Delete(nodeKeyStr)
			}

			return machine, err
		} else {
			return nil, ErrCouldNotConvertMachineInterface
		}
	}

	return nil, ErrMachineNotFoundRegistrationCache
}

// RegisterMachine is executed from the CLI to register a new Machine using its MachineKey.
func (h *Headscale) RegisterMachine(machine Machine,
) (*Machine, error) {
	log.Trace().
		Caller().
		Str("machine_key", machine.MachineKey).
		Msg("Registering machine")

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Msg("Attempting to register machine")

	h.ipAllocationMutex.Lock()
	defer h.ipAllocationMutex.Unlock()

	ips, err := h.getAvailableIPs()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Could not find IP for the new machine")

		return nil, err
	}

	machine.IPAddresses = ips

	if err := h.db.Save(&machine).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) machine in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Str("ip", strings.Join(ips.ToStringSlice(), ",")).
		Msg("Machine registered with the database")

	return &machine, nil
}

func (machine *Machine) GetAdvertisedRoutes() []netip.Prefix {
	return machine.HostInfo.RoutableIPs
}

func (machine *Machine) GetEnabledRoutes() []netip.Prefix {
	return machine.EnabledRoutes
}

func (machine *Machine) IsRoutesEnabled(routeStr string) bool {
	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes := machine.GetEnabledRoutes()

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

// EnableNodeRoute enables new routes based on a list of new routes. It will _replace_ the
// previous list of routes.
func (h *Headscale) EnableRoutes(machine *Machine, routeStrs ...string) error {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return err
		}

		newRoutes[index] = route
	}

	for _, newRoute := range newRoutes {
		if !contains(machine.GetAdvertisedRoutes(), newRoute) {
			return fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				machine.Hostname,
				newRoute, ErrMachineRouteIsNotAvailable,
			)
		}
	}

	machine.EnabledRoutes = newRoutes

	if err := h.db.Save(machine).Error; err != nil {
		return fmt.Errorf("failed enable routes for machine in the database: %w", err)
	}

	return nil
}

// Enabled any routes advertised by a machine that match the ACL autoApprovers policy.
func (h *Headscale) EnableAutoApprovedRoutes(machine *Machine) {
	if len(machine.IPAddresses) == 0 {
		return // This machine has no IPAddresses, so can't possibly match any autoApprovers ACLs
	}

	approvedRoutes := make([]netip.Prefix, 0, len(machine.HostInfo.RoutableIPs))
	thisMachine := []Machine{*machine}

	for _, advertisedRoute := range machine.HostInfo.RoutableIPs {
		if contains(machine.EnabledRoutes, advertisedRoute) {
			continue // Skip routes that are already enabled for the node
		}

		routeApprovers, err := h.aclPolicy.AutoApprovers.GetRouteApprovers(
			advertisedRoute,
		)
		if err != nil {
			log.Err(err).
				Str("advertisedRoute", advertisedRoute.String()).
				Uint64("machineId", machine.ID).
				Msg("Failed to resolve autoApprovers for advertised route")

			return
		}

		for _, approvedAlias := range routeApprovers {
			if approvedAlias == machine.Namespace.Name {
				approvedRoutes = append(approvedRoutes, advertisedRoute)
			} else {
				approvedIps, err := expandAlias(thisMachine, *h.aclPolicy, approvedAlias, h.cfg.OIDC.StripEmaildomain)
				if err != nil {
					log.Err(err).
						Str("alias", approvedAlias).
						Msg("Failed to expand alias when processing autoApprovers policy")

					return
				}

				// approvedIPs should contain all of machine's IPs if it matches the rule, so check for first
				if contains(approvedIps, machine.IPAddresses[0].String()) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	for _, approvedRoute := range approvedRoutes {
		if !contains(machine.EnabledRoutes, approvedRoute) {
			log.Info().
				Str("route", approvedRoute.String()).
				Uint64("client", machine.ID).
				Msg("Enabling autoApproved route for client")
			machine.EnabledRoutes = append(machine.EnabledRoutes, approvedRoute)
		}
	}
}

func (machine *Machine) RoutesToProto() *v1.Routes {
	availableRoutes := machine.GetAdvertisedRoutes()

	enabledRoutes := machine.GetEnabledRoutes()

	return &v1.Routes{
		AdvertisedRoutes: ipPrefixToString(availableRoutes),
		EnabledRoutes:    ipPrefixToString(enabledRoutes),
	}
}

func (h *Headscale) generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	normalizedHostname, err := NormalizeToFQDNRules(
		suppliedName,
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		return "", err
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := labelHostnameLength - MachineGivenNameHashLength - MachineGivenNameTrimSize
		if len(normalizedHostname) > trimmedHostnameLength {
			normalizedHostname = normalizedHostname[:trimmedHostnameLength]
		}

		suffix, err := GenerateRandomStringDNSSafe(MachineGivenNameHashLength)
		if err != nil {
			return "", err
		}

		normalizedHostname += "-" + suffix
	}

	return normalizedHostname, nil
}

func (h *Headscale) GenerateGivenName(machineKey string, suppliedName string) (string, error) {
	givenName, err := h.generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	machines, err := h.ListMachinesByGivenName(givenName)
	if err != nil {
		return "", err
	}

	for _, machine := range machines {
		if machine.MachineKey != machineKey && machine.GivenName == givenName {
			postfixedName, err := h.generateGivenName(suppliedName, true)
			if err != nil {
				return "", err
			}

			givenName = postfixedName
		}
	}

	return givenName, nil
}
