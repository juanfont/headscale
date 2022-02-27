package headscale

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/set"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/datatypes"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	errMachineNotFound            = Error("machine not found")
	errMachineAlreadyRegistered   = Error("machine already registered")
	errMachineRouteIsNotAvailable = Error("route is not available on machine")
	errMachineAddressesInvalid    = Error("failed to parse machine addresses")
	errHostnameTooLong            = Error("Hostname too long")
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
	Name        string
	NamespaceID uint
	Namespace   Namespace `gorm:"foreignKey:NamespaceID"`

	Registered     bool // temp
	RegisterMethod string

	// TODO(kradalby): This seems like irrelevant information?
	AuthKeyID uint
	AuthKey   *PreAuthKey

	LastSeen             *time.Time
	LastSuccessfulUpdate *time.Time
	Expiry               *time.Time

	// TODO(kradalby): Figure out a way to use tailcfg datatypes
	// here and have gorm serialise them.
	HostInfo      datatypes.JSON
	Endpoints     datatypes.JSON
	EnabledRoutes datatypes.JSON

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type (
	Machines  []Machine
	MachinesP []*Machine
)

// For the time being this method is rather naive.
func (machine Machine) isRegistered() bool {
	return machine.Registered
}

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
	if machine.Expiry.IsZero() {
		return false
	}

	return time.Now().UTC().After(*machine.Expiry)
}

func containsAddresses(inputs []string, addrs []string) bool {
	for _, addr := range addrs {
		if containsString(inputs, addr) {
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
		Str("machine", machine.Name).
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
					machine.IPAddresses.ToStringSlice(),
					[]string{"*"},
				) || // match source and all destination
				matchSourceAndDestinationWithRule(
					rule.SrcIPs,
					dst,
					peer.IPAddresses.ToStringSlice(),
					machine.IPAddresses.ToStringSlice(),
				) { // match return path
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
		Str("machine", machine.Name).
		Msgf("Found some machines: %v", machines)

	return authorizedPeers
}

func (h *Headscale) ListPeers(machine *Machine) (Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msg("Finding direct peers")

	machines := Machines{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.Namespace").Preload("Namespace").Where("machine_key <> ? AND registered",
		machine.MachineKey).Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")

		return Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Name).
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
		Str("machine", machine.Name).
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
		if peer.isRegistered() && !peer.isExpired() {
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
		if m.Name == name {
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

// ExpireMachine takes a Machine struct and sets the expire field to now.
func (h *Headscale) ExpireMachine(machine *Machine) {
	now := time.Now()
	machine.Expiry = &now

	h.setLastStateChangeToNow(machine.Namespace.Name)

	h.db.Save(machine)
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
	machine.Registered = false
	h.db.Save(&machine) // we mark it as unregistered, just in case
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
func (machine *Machine) GetHostInfo() (*tailcfg.Hostinfo, error) {
	hostinfo := tailcfg.Hostinfo{}
	if len(machine.HostInfo) != 0 {
		hi, err := machine.HostInfo.MarshalJSON()
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(hi, &hostinfo)
		if err != nil {
			return nil, err
		}
	}

	return &hostinfo, nil
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
		Str("machine", machine.Name).
		Time("last_successful_update", lastChange).
		Time("last_state_change", lastUpdate).
		Msgf("Checking if %s is missing updates", machine.Name)

	return lastUpdate.Before(lastChange)
}

func (machine Machine) String() string {
	return machine.Name
}

func (machines Machines) String() string {
	temp := make([]string, len(machines))

	for index, machine := range machines {
		temp[index] = machine.Name
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

// TODO(kradalby): Remove when we have generics...
func (machines MachinesP) String() string {
	temp := make([]string, len(machines))

	for index, machine := range machines {
		temp[index] = machine.Name
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
		routesStr := []string{}
		if len(machine.EnabledRoutes) != 0 {
			allwIps, err := machine.EnabledRoutes.MarshalJSON()
			if err != nil {
				return nil, err
			}
			err = json.Unmarshal(allwIps, &routesStr)
			if err != nil {
				return nil, err
			}
		}

		for _, routeStr := range routesStr {
			ip, err := netaddr.ParseIPPrefix(routeStr)
			if err != nil {
				return nil, err
			}
			allowedIPs = append(allowedIPs, ip)
		}
	}

	endpoints := []string{}
	if len(machine.Endpoints) != 0 {
		be, err := machine.Endpoints.MarshalJSON()
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(be, &endpoints)
		if err != nil {
			return nil, err
		}
	}

	hostinfo := tailcfg.Hostinfo{}
	if len(machine.HostInfo) != 0 {
		hi, err := machine.HostInfo.MarshalJSON()
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(hi, &hostinfo)
		if err != nil {
			return nil, err
		}
	}

	var derp string
	if hostinfo.NetInfo != nil {
		derp = fmt.Sprintf("127.3.3.40:%d", hostinfo.NetInfo.PreferredDERP)
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
			machine.Name,
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
		hostname = machine.Name
	}

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
		Endpoints:  endpoints,
		DERP:       derp,

		Hostinfo: hostinfo,
		Created:  machine.CreatedAt,
		LastSeen: machine.LastSeen,

		KeepAlive:         true,
		MachineAuthorized: machine.Registered,
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
		Name:        machine.Name,
		Namespace:   machine.Namespace.toProto(),

		Registered: machine.Registered,

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

// RegisterMachine is executed from the CLI to register a new Machine using its MachineKey.
func (h *Headscale) RegisterMachine(
	machineKeyStr string,
	namespaceName string,
	registrationMethod string,

	// Optionals
	expiry *time.Time,
	authKey *PreAuthKey,
	nodePublicKey *string,
	lastSeen *time.Time,
) (*Machine, error) {
	namespace, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}

	var machineKey key.MachinePublic
	err = machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		return nil, err
	}

	log.Trace().
		Caller().
		Str("machine_key_str", machineKeyStr).
		Str("machine_key", machineKey.String()).
		Msg("Registering machine")

	machine, err := h.GetMachineByMachineKey(machineKey)
	if err != nil {
		return nil, err
	}

	if machine.isRegistered() {
		log.Trace().
			Caller().
			Str("machine", machine.Name).
			Msg("machine already registered, reauthenticating")

		h.RefreshMachine(machine, *expiry)

		return machine, nil
	}

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msg("Attempting to register machine")

	h.ipAllocationMutex.Lock()
	defer h.ipAllocationMutex.Unlock()

	ips, err := h.getAvailableIPs()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Name).
			Msg("Could not find IP for the new machine")

		return nil, err
	}

	machine.IPAddresses = ips

	if expiry != nil {
		machine.Expiry = expiry
	}

	if authKey != nil {
		machine.AuthKeyID = uint(authKey.ID)
	}

	if nodePublicKey != nil {
		machine.NodeKey = *nodePublicKey
	}

	if lastSeen != nil {
		machine.LastSeen = lastSeen
	}

	machine.NamespaceID = namespace.ID

	// TODO(kradalby): This field is uneccessary metadata,
	// move it to tags instead of having a column.
	machine.RegisterMethod = registrationMethod

	// TODO(kradalby): Registered is a very frustrating value
	// to keep up to date, and it makes is have to care if a
	// machine is registered, authenticated and expired.
	// Let us simplify the model, a machine is _only_ saved if
	// it is registered.
	machine.Registered = true
	h.db.Save(&machine)

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Str("ip", strings.Join(ips.ToStringSlice(), ",")).
		Msg("Machine registered with the database")

	return machine, nil
}

func (machine *Machine) GetAdvertisedRoutes() ([]netaddr.IPPrefix, error) {
	hostInfo, err := machine.GetHostInfo()
	if err != nil {
		return nil, err
	}

	return hostInfo.RoutableIPs, nil
}

func (machine *Machine) GetEnabledRoutes() ([]netaddr.IPPrefix, error) {
	data, err := machine.EnabledRoutes.MarshalJSON()
	if err != nil {
		return nil, err
	}

	routesStr := []string{}
	err = json.Unmarshal(data, &routesStr)
	if err != nil {
		return nil, err
	}

	routes := make([]netaddr.IPPrefix, len(routesStr))
	for index, routeStr := range routesStr {
		route, err := netaddr.ParseIPPrefix(routeStr)
		if err != nil {
			return nil, err
		}
		routes[index] = route
	}

	return routes, nil
}

func (machine *Machine) IsRoutesEnabled(routeStr string) bool {
	route, err := netaddr.ParseIPPrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := machine.GetEnabledRoutes()
	if err != nil {
		return false
	}

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

	availableRoutes, err := machine.GetAdvertisedRoutes()
	if err != nil {
		return err
	}

	for _, newRoute := range newRoutes {
		if !containsIPPrefix(availableRoutes, newRoute) {
			return fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				machine.Name,
				newRoute, errMachineRouteIsNotAvailable,
			)
		}
	}

	routes, err := json.Marshal(newRoutes)
	if err != nil {
		return err
	}

	machine.EnabledRoutes = datatypes.JSON(routes)
	h.db.Save(&machine)

	return nil
}

func (machine *Machine) RoutesToProto() (*v1.Routes, error) {
	availableRoutes, err := machine.GetAdvertisedRoutes()
	if err != nil {
		return nil, err
	}

	enabledRoutes, err := machine.GetEnabledRoutes()
	if err != nil {
		return nil, err
	}

	return &v1.Routes{
		AdvertisedRoutes: ipPrefixToString(availableRoutes),
		EnabledRoutes:    ipPrefixToString(enabledRoutes),
	}, nil
}
