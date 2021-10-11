package headscale

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/set"
	"github.com/rs/zerolog/log"

	"gorm.io/datatypes"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/wgkey"
)

// Machine is a Headscale client
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

// For the time being this method is rather naive
func (m Machine) isAlreadyRegistered() bool {
	return m.Registered
}

func (h *Headscale) getDirectPeers(m *Machine) (Machines, error) {
	log.Trace().
		Str("func", "getDirectPeers").
		Str("machine", m.Name).
		Msg("Finding direct peers")

	machines := Machines{}
	if err := h.db.Preload("Namespace").Where("namespace_id = ? AND machine_key <> ? AND registered",
		m.NamespaceID, m.MachineKey).Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")
		return Machines{}, err
	}

	sort.Slice(machines, func(i, j int) bool { return machines[i].ID < machines[j].ID })

	log.Trace().
		Str("func", "getDirectmachines").
		Str("machine", m.Name).
		Msgf("Found direct machines: %s", machines.String())
	return machines, nil
}

func (h *Headscale) getShared(m *Machine) (Machines, error) {
	log.Trace().
		Str("func", "getShared").
		Str("machine", m.Name).
		Msg("Finding shared peers")

	// We fetch here machines that are shared to the `Namespace` of the machine we are getting peers for
	sharedMachines := []SharedMachine{}
	if err := h.db.Preload("Namespace").Preload("Machine").Where("namespace_id = ?",
		m.NamespaceID).Find(&sharedMachines).Error; err != nil {
		return Machines{}, err
	}

	peers := make(Machines, 0)
	for _, sharedMachine := range sharedMachines {
		peers = append(peers, sharedMachine.Machine)
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Str("func", "getShared").
		Str("machine", m.Name).
		Msgf("Found shared peers: %s", peers.String())
	return peers, nil
}

func (h *Headscale) getPeers(m *Machine) (Machines, error) {
	direct, err := h.getDirectPeers(m)
	if err != nil {
		log.Error().
			Str("func", "getPeers").
			Err(err).
			Msg("Cannot fetch peers")
		return Machines{}, err
	}

	shared, err := h.getShared(m)
	if err != nil {
		log.Error().
			Str("func", "getDirectPeers").
			Err(err).
			Msg("Cannot fetch peers")
		return Machines{}, err
	}

	peers := append(direct, shared...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Str("func", "getShared").
		Str("machine", m.Name).
		Msgf("Found total peers: %s", peers.String())

	return peers, nil
}

// GetMachine finds a Machine by name and namespace and returns the Machine struct
func (h *Headscale) GetMachine(namespace string, name string) (*Machine, error) {
	machines, err := h.ListMachinesInNamespace(namespace)
	if err != nil {
		return nil, err
	}

	for _, m := range *machines {
		if m.Name == name {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("machine not found")
}

// GetMachineByID finds a Machine by ID and returns the Machine struct
func (h *Headscale) GetMachineByID(id uint64) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").Find(&Machine{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}
	return &m, nil
}

// GetMachineByMachineKey finds a Machine by ID and returns the Machine struct
func (h *Headscale) GetMachineByMachineKey(mKey string) (*Machine, error) {
	m := Machine{}
	if result := h.db.Preload("Namespace").First(&m, "machine_key = ?", mKey); result.Error != nil {
		return nil, result.Error
	}
	return &m, nil
}

// UpdateMachine takes a Machine struct pointer (typically already loaded from database
// and updates it with the latest data from the database.
func (h *Headscale) UpdateMachine(m *Machine) error {
	if result := h.db.Find(m).First(&m); result.Error != nil {
		return result.Error
	}
	return nil
}

// DeleteMachine softs deletes a Machine from the database
func (h *Headscale) DeleteMachine(m *Machine) error {
	err := h.RemoveSharedMachineFromAllNamespaces(m)
	if err != nil && err != errorMachineNotShared {
		return err
	}

	m.Registered = false
	namespaceID := m.NamespaceID
	h.db.Save(&m) // we mark it as unregistered, just in case
	if err := h.db.Delete(&m).Error; err != nil {
		return err
	}

	return h.RequestMapUpdates(namespaceID)
}

// HardDeleteMachine hard deletes a Machine from the database
func (h *Headscale) HardDeleteMachine(m *Machine) error {
	err := h.RemoveSharedMachineFromAllNamespaces(m)
	if err != nil && err != errorMachineNotShared {
		return err
	}

	namespaceID := m.NamespaceID
	if err := h.db.Unscoped().Delete(&m).Error; err != nil {
		return err
	}

	return h.RequestMapUpdates(namespaceID)
}

// GetHostInfo returns a Hostinfo struct for the machine
func (m *Machine) GetHostInfo() (*tailcfg.Hostinfo, error) {
	hostinfo := tailcfg.Hostinfo{}
	if len(m.HostInfo) != 0 {
		hi, err := m.HostInfo.MarshalJSON()
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

func (h *Headscale) isOutdated(m *Machine) bool {
	err := h.UpdateMachine(m)
	if err != nil {
		// It does not seem meaningful to propagate this error as the end result
		// will have to be that the machine has to be considered outdated.
		return true
	}

	sharedMachines, _ := h.getShared(m)

	namespaceSet := set.New(set.ThreadSafe)
	namespaceSet.Add(m.Namespace.Name)

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
		Str("func", "keepAlive").
		Str("machine", m.Name).
		Time("last_successful_update", *m.LastSuccessfulUpdate).
		Time("last_state_change", lastChange).
		Msgf("Checking if %s is missing updates", m.Name)
	return m.LastSuccessfulUpdate.Before(lastChange)
}

func (m Machine) String() string {
	return m.Name
}

func (ms Machines) String() string {
	temp := make([]string, len(ms))

	for index, machine := range ms {
		temp[index] = machine.Name
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

// TODO(kradalby): Remove when we have generics...
func (ms MachinesP) String() string {
	temp := make([]string, len(ms))

	for index, machine := range ms {
		temp[index] = machine.Name
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func (ms Machines) toNodes(baseDomain string, dnsConfig *tailcfg.DNSConfig, includeRoutes bool) ([]*tailcfg.Node, error) {
	nodes := make([]*tailcfg.Node, len(ms))

	for index, machine := range ms {
		node, err := machine.toNode(baseDomain, dnsConfig, includeRoutes)
		if err != nil {
			return nil, err
		}

		nodes[index] = node
	}

	return nodes, nil
}

// toNode converts a Machine into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS
func (m Machine) toNode(baseDomain string, dnsConfig *tailcfg.DNSConfig, includeRoutes bool) (*tailcfg.Node, error) {
	nKey, err := wgkey.ParseHex(m.NodeKey)
	if err != nil {
		return nil, err
	}
	mKey, err := wgkey.ParseHex(m.MachineKey)
	if err != nil {
		return nil, err
	}

	var discoKey tailcfg.DiscoKey
	if m.DiscoKey != "" {
		dKey, err := wgkey.ParseHex(m.DiscoKey)
		if err != nil {
			return nil, err
		}
		discoKey = tailcfg.DiscoKey(dKey)
	} else {
		discoKey = tailcfg.DiscoKey{}
	}

	addrs := []netaddr.IPPrefix{}
	ip, err := netaddr.ParseIPPrefix(fmt.Sprintf("%s/32", m.IPAddress))
	if err != nil {
		log.Trace().
			Str("func", "toNode").
			Str("ip", m.IPAddress).
			Msgf("Failed to parse IP Prefix from IP: %s", m.IPAddress)
		return nil, err
	}
	addrs = append(addrs, ip) // missing the ipv6 ?

	allowedIPs := []netaddr.IPPrefix{}
	allowedIPs = append(allowedIPs, ip) // we append the node own IP, as it is required by the clients

	if includeRoutes {
		routesStr := []string{}
		if len(m.EnabledRoutes) != 0 {
			allwIps, err := m.EnabledRoutes.MarshalJSON()
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
	if len(m.Endpoints) != 0 {
		be, err := m.Endpoints.MarshalJSON()
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(be, &endpoints)
		if err != nil {
			return nil, err
		}
	}

	hostinfo := tailcfg.Hostinfo{}
	if len(m.HostInfo) != 0 {
		hi, err := m.HostInfo.MarshalJSON()
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
	if m.Expiry != nil {
		keyExpiry = *m.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf("%s.%s.%s", m.Name, m.Namespace.Name, baseDomain)
	} else {
		hostname = m.Name
	}

	n := tailcfg.Node{
		ID:         tailcfg.NodeID(m.ID),                               // this is the actual ID
		StableID:   tailcfg.StableNodeID(strconv.FormatUint(m.ID, 10)), // in headscale, unlike tailcontrol server, IDs are permanent
		Name:       hostname,
		User:       tailcfg.UserID(m.NamespaceID),
		Key:        tailcfg.NodeKey(nKey),
		KeyExpiry:  keyExpiry,
		Machine:    tailcfg.MachineKey(mKey),
		DiscoKey:   discoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  endpoints,
		DERP:       derp,

		Hostinfo: hostinfo,
		Created:  m.CreatedAt,
		LastSeen: m.LastSeen,

		KeepAlive:         true,
		MachineAuthorized: m.Registered,
		Capabilities:      []string{tailcfg.CapabilityFileSharing},
	}
	return &n, nil
}
