package headscale

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/set"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	errMachineNotFound                  = Error("machine not found")
	errMachineRouteIsNotAvailable       = Error("route is not available on machine")
	errMachineAddressesInvalid          = Error("failed to parse machine addresses")
	errMachineNotFoundRegistrationCache = Error(
		"machine not found in registration cache",
	)
	errCouldNotConvertMachineInterface = Error("failed to convert machine interface")
	errHostnameTooLong                 = Error("Hostname too long")
	MachineGivenNameHashLength         = 8
)

const (
	maxHostnameLength = 255
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

type MachineAddresses []netaddr.IP

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
			parsed, err := netaddr.ParseIP(addr)
			if err != nil {
				return err
			}
			*ma = append(*ma, parsed)
		}

		return nil

	default:
		return fmt.Errorf("%w: unexpected data type %T", errMachineAddressesInvalid, destination)
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
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Where("machine_key <> ?",
		machine.MachineKey).Find(&machines).Error; err != nil {
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

	return nil, errMachineNotFound
}

// GetMachineByID finds a Machine by ID and returns the Machine struct.
func (h *Headscale) GetMachineByID(id uint64) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").Find(&Machine{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetMachineByMachineKey finds a Machine by ID and returns the Machine struct.
func (h *Headscale) GetMachineByMachineKey(
	machineKey key.MachinePublic,
) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// UpdateMachine takes a Machine struct pointer (typically already loaded from database
// and updates it with the latest data from the database.
func (h *Headscale) UpdateMachine(machine *Machine) error {
	if result := h.db.Find(machine).First(&machine); result.Error != nil {
		return result.Error
	}

	return nil
}

// SetTags takes a Machine struct pointer and update the forced tags.
func (h *Headscale) SetTags(machine *Machine, tags []string) error {
	machine.ForcedTags = tags
	if err := h.UpdateACLRules(); err != nil && !errors.Is(err, errEmptyPolicy) {
		return err
	}
	h.setLastStateChangeToNow(machine.Namespace.Name)
	h.db.Save(machine)

	return nil
}

// ExpireMachine takes a Machine struct and sets the expire field to now.
func (h *Headscale) ExpireMachine(machine *Machine) {
	now := time.Now()
	machine.Expiry = &now

	h.setLastStateChangeToNow(machine.Namespace.Name)

	h.db.Save(machine)
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

	h.setLastStateChangeToNow(machine.Namespace.Name)

	h.db.Save(machine)

	return nil
}

// RefreshMachine takes a Machine struct and sets the expire field to now.
func (h *Headscale) RefreshMachine(machine *Machine, expiry time.Time) {
	now := time.Now()

	machine.LastSuccessfulUpdate = &now
	machine.Expiry = &expiry

	h.setLastStateChangeToNow(machine.Namespace.Name)

	h.db.Save(machine)
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
	if err := h.UpdateMachine(machine); err != nil {
		// It does not seem meaningful to propagate this error as the end result
		// will have to be that the machine has to be considered outdated.
		return true
	}

	namespaceSet := set.New(set.ThreadSafe)
	namespaceSet.Add(machine.Namespace.Name)

	namespaces := make([]string, namespaceSet.Size())
	for index, namespace := range namespaceSet.List() {
		if name, ok := namespace.(string); ok {
			namespaces[index] = name
		}
	}

	lastChange := h.getLastStateChange(namespaces...)
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
	includeRoutes bool,
) ([]*tailcfg.Node, error) {
	nodes := make([]*tailcfg.Node, len(machines))

	for index, machine := range machines {
		node, err := machine.toNode(baseDomain, dnsConfig, includeRoutes)
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
	includeRoutes bool,
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
	err = machineKey.UnmarshalText(
		[]byte(MachinePublicKeyEnsurePrefix(machine.MachineKey)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse machine public key: %w", err)
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

	addrs := []netaddr.IPPrefix{}
	for _, machineAddress := range machine.IPAddresses {
		ip := netaddr.IPPrefixFrom(machineAddress, machineAddress.BitLen())
		addrs = append(addrs, ip)
	}

	allowedIPs := append(
		[]netaddr.IPPrefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	// TODO(kradalby): Needs investigation, We probably dont need this condition
	// now that we dont have shared nodes
	if includeRoutes {
		allowedIPs = append(allowedIPs, machine.EnabledRoutes...)
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
				errHostnameTooLong,
			)
		}
	} else {
		hostname = machine.GivenName
	}

	hostInfo := machine.GetHostInfo()

	node := tailcfg.Node{
		ID: tailcfg.NodeID(machine.ID), // this is the actual ID
		StableID: tailcfg.StableNodeID(
			strconv.FormatUint(machine.ID, Base10),
		), // in headscale, unlike tailcontrol server, IDs are permanent
		Name:       hostname,
		User:       tailcfg.UserID(machine.NamespaceID),
		Key:        nodeKey,
		KeyExpiry:  keyExpiry,
		Machine:    machineKey,
		DiscoKey:   discoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  machine.Endpoints,
		DERP:       derp,

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
	machineKeyStr string,
	namespaceName string,
	registrationMethod string,
) (*Machine, error) {
	if machineInterface, ok := h.registrationCache.Get(machineKeyStr); ok {
		if registrationMachine, ok := machineInterface.(Machine); ok {
			namespace, err := h.GetNamespace(namespaceName)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to find namespace in register machine from auth callback, %w",
					err,
				)
			}

			registrationMachine.NamespaceID = namespace.ID
			registrationMachine.RegisterMethod = registrationMethod

			machine, err := h.RegisterMachine(
				registrationMachine,
			)

			return machine, err
		} else {
			return nil, errCouldNotConvertMachineInterface
		}
	}

	return nil, errMachineNotFoundRegistrationCache
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

	h.db.Save(&machine)

	log.Trace().
		Caller().
		Str("machine", machine.Hostname).
		Str("ip", strings.Join(ips.ToStringSlice(), ",")).
		Msg("Machine registered with the database")

	return &machine, nil
}

func (machine *Machine) GetAdvertisedRoutes() []netaddr.IPPrefix {
	return machine.HostInfo.RoutableIPs
}

func (machine *Machine) GetEnabledRoutes() []netaddr.IPPrefix {
	return machine.EnabledRoutes
}

func (machine *Machine) IsRoutesEnabled(routeStr string) bool {
	route, err := netaddr.ParseIPPrefix(routeStr)
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
	newRoutes := make([]netaddr.IPPrefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netaddr.ParseIPPrefix(routeStr)
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
				newRoute, errMachineRouteIsNotAvailable,
			)
		}
	}

	machine.EnabledRoutes = newRoutes
	h.db.Save(&machine)

	return nil
}

func (machine *Machine) RoutesToProto() *v1.Routes {
	availableRoutes := machine.GetAdvertisedRoutes()

	enabledRoutes := machine.GetEnabledRoutes()

	return &v1.Routes{
		AdvertisedRoutes: ipPrefixToString(availableRoutes),
		EnabledRoutes:    ipPrefixToString(enabledRoutes),
	}
}

func (h *Headscale) GenerateGivenName(suppliedName string) (string, error) {
	// If a hostname is or will be longer than 63 chars after adding the hash,
	// it needs to be trimmed.
	trimmedHostnameLength := labelHostnameLength - MachineGivenNameHashLength - 2

	normalizedHostname, err := NormalizeToFQDNRules(
		suppliedName,
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		return "", err
	}

	postfix, err := GenerateRandomStringDNSSafe(MachineGivenNameHashLength)
	if err != nil {
		return "", err
	}

	// Verify that that the new unique name is shorter than the maximum allowed
	// DNS segment.
	if len(normalizedHostname) <= trimmedHostnameLength {
		normalizedHostname = fmt.Sprintf("%s-%s", normalizedHostname, postfix)
	} else {
		normalizedHostname = fmt.Sprintf("%s-%s", normalizedHostname[:trimmedHostnameLength], postfix)
	}

	return normalizedHostname, nil
}
