package headscale

import (
	"encoding/json"
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
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

// Machine is a Headscale client.
type Machine struct {
	ID          uint64 `gorm:"primary_key"`
	MachineKey  string `gorm:"type:varchar(64);unique_index"`
	NodeKey     string
	DiscoKey    string
	IPAddress   string
	Name        string
	NamespaceID uint
	Namespace   Namespace `gorm:"foreignKey:NamespaceID"`

	Registered     bool // temp
	RegisterMethod string
	AuthKeyID      uint
	AuthKey        *PreAuthKey

	LastSeen             *time.Time
	LastSuccessfulUpdate *time.Time
	Expiry               *time.Time
	RequestedExpiry      *time.Time

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
func (machine Machine) isAlreadyRegistered() bool {
	return machine.Registered
}

// isExpired returns whether the machine registration has expired.
func (machine Machine) isExpired() bool {
	return time.Now().UTC().After(*machine.Expiry)
}

// If the Machine is expired, updateMachineExpiry updates the Machine Expiry time to the maximum allowed duration,
// or the default duration if no Expiry time was requested by the client. The expiry time here does not (yet) cause
// a client to be disconnected, however they will have to re-auth the machine if they attempt to reconnect after the
// expiry time.
func (h *Headscale) updateMachineExpiry(machine *Machine) {
	if machine.isExpired() {
		now := time.Now().UTC()
		maxExpiry := now.Add(
			h.cfg.MaxMachineRegistrationDuration,
		) // calculate the maximum expiry
		defaultExpiry := now.Add(
			h.cfg.DefaultMachineRegistrationDuration,
		) // calculate the default expiry

		// clamp the expiry time of the machine registration to the maximum allowed, or use the default if none supplied
		if maxExpiry.Before(*machine.RequestedExpiry) {
			log.Debug().
				Msgf("Clamping registration expiry time to maximum: %v (%v)", maxExpiry, h.cfg.MaxMachineRegistrationDuration)
			machine.Expiry = &maxExpiry
		} else if machine.RequestedExpiry.IsZero() {
			log.Debug().Msgf("Using default machine registration expiry time: %v (%v)", defaultExpiry, h.cfg.DefaultMachineRegistrationDuration)
			machine.Expiry = &defaultExpiry
		} else {
			log.Debug().Msgf("Using requested machine registration expiry time: %v", machine.RequestedExpiry)
			machine.Expiry = machine.RequestedExpiry
		}

		h.db.Save(&machine)
	}
}

func (h *Headscale) getDirectPeers(machine *Machine) (Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msg("Finding direct peers")

	machines := Machines{}
	if err := h.db.Preload("Namespace").Where("namespace_id = ? AND machine_key <> ? AND registered",
		machine.NamespaceID, machine.MachineKey).Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")

		return Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msgf("Found direct machines: %s", machines.String())

	return machines, nil
}

// getShared fetches machines that are shared to the `Namespace` of the machine we are getting peers for.
func (h *Headscale) getShared(machine *Machine) (Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msg("Finding shared peers")

	sharedMachines := []SharedMachine{}
	if err := h.db.Preload("Namespace").Preload("Machine").Preload("Machine.Namespace").Where("namespace_id = ?",
		machine.NamespaceID).Find(&sharedMachines).Error; err != nil {
		return Machines{}, err
	}

	peers := make(Machines, 0)
	for _, sharedMachine := range sharedMachines {
		peers = append(peers, sharedMachine.Machine)
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msgf("Found shared peers: %s", peers.String())

	return peers, nil
}

// getSharedTo fetches the machines of the namespaces this machine is shared in.
func (h *Headscale) getSharedTo(machine *Machine) (Machines, error) {
	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msg("Finding peers in namespaces this machine is shared with")

	sharedMachines := []SharedMachine{}
	if err := h.db.Preload("Namespace").Preload("Machine").Preload("Machine.Namespace").Where("machine_id = ?",
		machine.ID).Find(&sharedMachines).Error; err != nil {
		return Machines{}, err
	}

	peers := make(Machines, 0)
	for _, sharedMachine := range sharedMachines {
		namespaceMachines, err := h.ListMachinesInNamespace(
			sharedMachine.Namespace.Name,
		)
		if err != nil {
			return Machines{}, err
		}
		peers = append(peers, namespaceMachines...)
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msgf("Found peers we are shared with: %s", peers.String())

	return peers, nil
}

func (h *Headscale) getPeers(machine *Machine) (Machines, error) {
	direct, err := h.getDirectPeers(machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot fetch peers")

		return Machines{}, err
	}

	shared, err := h.getShared(machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot fetch peers")

		return Machines{}, err
	}

	sharedTo, err := h.getSharedTo(machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot fetch peers")

		return Machines{}, err
	}

	peers := append(direct, shared...)
	peers = append(peers, sharedTo...)

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msgf("Found total peers: %s", peers.String())

	return peers, nil
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

	return nil, fmt.Errorf("machine not found")
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
func (h *Headscale) GetMachineByMachineKey(machineKey string) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", machineKey); result.Error != nil {
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

// DeleteMachine softs deletes a Machine from the database.
func (h *Headscale) DeleteMachine(machine *Machine) error {
	err := h.RemoveSharedMachineFromAllNamespaces(machine)
	if err != nil && err != errorMachineNotShared {
		return err
	}

	machine.Registered = false
	namespaceID := machine.NamespaceID
	h.db.Save(&machine) // we mark it as unregistered, just in case
	if err := h.db.Delete(&machine).Error; err != nil {
		return err
	}

	return h.RequestMapUpdates(namespaceID)
}

// HardDeleteMachine hard deletes a Machine from the database.
func (h *Headscale) HardDeleteMachine(machine *Machine) error {
	err := h.RemoveSharedMachineFromAllNamespaces(machine)
	if err != nil && err != errorMachineNotShared {
		return err
	}

	namespaceID := machine.NamespaceID
	if err := h.db.Unscoped().Delete(&machine).Error; err != nil {
		return err
	}

	return h.RequestMapUpdates(namespaceID)
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

	sharedMachines, _ := h.getShared(machine)

	namespaceSet := set.New(set.ThreadSafe)
	namespaceSet.Add(machine.Namespace.Name)

	// Check if any of our shared namespaces has updates that we have
	// not propagated.
	for _, sharedMachine := range sharedMachines {
		namespaceSet.Add(sharedMachine.Namespace.Name)
	}

	namespaces := make([]string, namespaceSet.Size())
	for index, namespace := range namespaceSet.List() {
		namespaces[index] = namespace.(string)
	}

	lastChange := h.getLastStateChange(namespaces...)
	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Time("last_successful_update", *machine.LastSuccessfulUpdate).
		Time("last_state_change", lastChange).
		Msgf("Checking if %s is missing updates", machine.Name)

	return machine.LastSuccessfulUpdate.Before(lastChange)
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
	nodeKey, err := wgkey.ParseHex(machine.NodeKey)
	if err != nil {
		return nil, err
	}

	machineKey, err := wgkey.ParseHex(machine.MachineKey)
	if err != nil {
		return nil, err
	}

	var discoKey tailcfg.DiscoKey
	if machine.DiscoKey != "" {
		dKey, err := wgkey.ParseHex(machine.DiscoKey)
		if err != nil {
			return nil, err
		}
		discoKey = tailcfg.DiscoKey(dKey)
	} else {
		discoKey = tailcfg.DiscoKey{}
	}

	addrs := []netaddr.IPPrefix{}
	ip, err := netaddr.ParseIPPrefix(fmt.Sprintf("%s/32", machine.IPAddress))
	if err != nil {
		log.Trace().
			Caller().
			Str("ip", machine.IPAddress).
			Msgf("Failed to parse IP Prefix from IP: %s", machine.IPAddress)

		return nil, err
	}
	addrs = append(addrs, ip) // missing the ipv6 ?

	allowedIPs := []netaddr.IPPrefix{}
	allowedIPs = append(
		allowedIPs,
		ip,
	) // we append the node own IP, as it is required by the clients

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
	} else {
		hostname = machine.Name
	}

	n := tailcfg.Node{
		ID: tailcfg.NodeID(machine.ID), // this is the actual ID
		StableID: tailcfg.StableNodeID(
			strconv.FormatUint(machine.ID, BASE_10),
		), // in headscale, unlike tailcontrol server, IDs are permanent
		Name:       hostname,
		User:       tailcfg.UserID(machine.NamespaceID),
		Key:        tailcfg.NodeKey(nodeKey),
		KeyExpiry:  keyExpiry,
		Machine:    tailcfg.MachineKey(machineKey),
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

	return &n, nil
}

func (machine *Machine) toProto() *v1.Machine {
	machineProto := &v1.Machine{
		Id:         machine.ID,
		MachineKey: machine.MachineKey,

		NodeKey:   machine.NodeKey,
		DiscoKey:  machine.DiscoKey,
		IpAddress: machine.IPAddress,
		Name:      machine.Name,
		Namespace: machine.Namespace.toProto(),

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
	key string,
	namespaceName string,
) (*Machine, error) {
	namespace, err := h.GetNamespace(namespaceName)
	if err != nil {
		return nil, err
	}
	machineKey, err := wgkey.ParseHex(key)
	if err != nil {
		return nil, err
	}

	machine := Machine{}
	if result := h.db.First(&machine, "machine_key = ?", machineKey.HexString()); errors.Is(
		result.Error,
		gorm.ErrRecordNotFound,
	) {
		return nil, errors.New("Machine not found")
	}

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Msg("Attempting to register machine")

	if machine.isAlreadyRegistered() {
		err := errors.New("Machine already registered")
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Name).
			Msg("Attempting to register machine")

		return nil, err
	}

	ip, err := h.getAvailableIP()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Name).
			Msg("Could not find IP for the new machine")

		return nil, err
	}

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Str("ip", ip.String()).
		Msg("Found IP for host")

	machine.IPAddress = ip.String()
	machine.NamespaceID = namespace.ID
	machine.Registered = true
	machine.RegisterMethod = "cli"
	h.db.Save(&machine)

	log.Trace().
		Caller().
		Str("machine", machine.Name).
		Str("ip", ip.String()).
		Msg("Machine registered with the database")

	return &machine, nil
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
		if !containsIpPrefix(availableRoutes, newRoute) {
			return fmt.Errorf(
				"route (%s) is not available on node %s",
				machine.Name,
				newRoute,
			)
		}
	}

	routes, err := json.Marshal(newRoutes)
	if err != nil {
		return err
	}

	machine.EnabledRoutes = datatypes.JSON(routes)
	h.db.Save(&machine)

	err = h.RequestMapUpdates(machine.NamespaceID)
	if err != nil {
		return err
	}

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
