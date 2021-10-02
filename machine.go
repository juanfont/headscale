package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

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

// For the time being this method is rather naive
func (m Machine) isAlreadyRegistered() bool {
	return m.Registered
}

// toNode converts a Machine into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS
func (h *Headscale) toNode(m Machine, includeRoutes bool) (*tailcfg.Node, error) {
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
	if h.cfg.DNSConfig != nil && h.cfg.DNSConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf("%s.%s.%s", m.Name, m.Namespace.Name, h.cfg.BaseDomain)
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
	// TODO(juanfont): Node also has Sharer when is a shared node with info on the profile

	return &n, nil
}

func (h *Headscale) getPeers(m Machine) (*[]*tailcfg.Node, error) {
	log.Trace().
		Str("func", "getPeers").
		Str("machine", m.Name).
		Msg("Finding peers")

	machines := []Machine{}
	if err := h.db.Preload("Namespace").Where("namespace_id = ? AND machine_key <> ? AND registered",
		m.NamespaceID, m.MachineKey).Find(&machines).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")
		return nil, err
	}

	// We fetch here machines that are shared to the `Namespace` of the machine we are getting peers for
	sharedMachines := []SharedMachine{}
	if err := h.db.Preload("Namespace").Preload("Machine").Where("namespace_id = ?",
		m.NamespaceID).Find(&sharedMachines).Error; err != nil {
		return nil, err
	}

	peers := []*tailcfg.Node{}
	for _, mn := range machines {
		peer, err := h.toNode(mn, true)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	for _, sharedMachine := range sharedMachines {
		peer, err := h.toNode(sharedMachine.Machine, false) // shared nodes do not expose their routes
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Str("func", "getPeers").
		Str("machine", m.Name).
		Msgf("Found peers: %s", tailNodesToString(peers))
	return &peers, nil
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

func (h *Headscale) notifyChangesToPeers(m *Machine) {
	peers, err := h.getPeers(*m)
	if err != nil {
		log.Error().
			Str("func", "notifyChangesToPeers").
			Str("machine", m.Name).
			Msgf("Error getting peers: %s", err)
		return
	}
	for _, p := range *peers {
		log.Info().
			Str("func", "notifyChangesToPeers").
			Str("machine", m.Name).
			Str("peer", p.Name).
			Str("address", p.Addresses[0].String()).
			Msgf("Notifying peer %s (%s)", p.Name, p.Addresses[0])
		err := h.sendRequestOnUpdateChannel(p)
		if err != nil {
			log.Info().
				Str("func", "notifyChangesToPeers").
				Str("machine", m.Name).
				Str("peer", p.Name).
				Msgf("Peer %s does not appear to be polling", p.Name)
		}
		log.Trace().
			Str("func", "notifyChangesToPeers").
			Str("machine", m.Name).
			Str("peer", p.Name).
			Str("address", p.Addresses[0].String()).
			Msgf("Notified peer %s (%s)", p.Name, p.Addresses[0])
	}
}

func (h *Headscale) getOrOpenUpdateChannel(m *Machine) <-chan struct{} {
	var updateChan chan struct{}
	if storedChan, ok := h.clientsUpdateChannels.Load(m.ID); ok {
		if unwrapped, ok := storedChan.(chan struct{}); ok {
			updateChan = unwrapped
		} else {
			log.Error().
				Str("handler", "openUpdateChannel").
				Str("machine", m.Name).
				Msg("Failed to convert update channel to struct{}")
		}
	} else {
		log.Debug().
			Str("handler", "openUpdateChannel").
			Str("machine", m.Name).
			Msg("Update channel not found, creating")

		updateChan = make(chan struct{})
		h.clientsUpdateChannels.Store(m.ID, updateChan)
	}
	return updateChan
}

func (h *Headscale) closeUpdateChannel(m *Machine) {
	h.clientsUpdateChannelMutex.Lock()
	defer h.clientsUpdateChannelMutex.Unlock()

	if storedChan, ok := h.clientsUpdateChannels.Load(m.ID); ok {
		if unwrapped, ok := storedChan.(chan struct{}); ok {
			close(unwrapped)
		}
	}
	h.clientsUpdateChannels.Delete(m.ID)
}

func (h *Headscale) sendRequestOnUpdateChannel(m *tailcfg.Node) error {
	h.clientsUpdateChannelMutex.Lock()
	defer h.clientsUpdateChannelMutex.Unlock()

	pUp, ok := h.clientsUpdateChannels.Load(uint64(m.ID))
	if ok {
		log.Info().
			Str("func", "requestUpdate").
			Str("machine", m.Name).
			Msgf("Notifying peer %s", m.Name)

		if update, ok := pUp.(chan struct{}); ok {
			log.Trace().
				Str("func", "requestUpdate").
				Str("machine", m.Name).
				Msgf("Update channel is %#v", update)

			update <- struct{}{}

			log.Trace().
				Str("func", "requestUpdate").
				Str("machine", m.Name).
				Msgf("Notified machine %s", m.Name)
		}
	} else {
		log.Info().
			Str("func", "requestUpdate").
			Str("machine", m.Name).
			Msgf("Machine %s does not appear to be polling", m.Name)
		return errors.New("machine does not seem to be polling")
	}
	return nil
}

func (h *Headscale) isOutdated(m *Machine) bool {
	err := h.UpdateMachine(m)
	if err != nil {
		return true
	}

	lastChange := h.getLastStateChange(m.Namespace.Name)
	log.Trace().
		Str("func", "keepAlive").
		Str("machine", m.Name).
		Time("last_successful_update", *m.LastSuccessfulUpdate).
		Time("last_state_change", lastChange).
		Msgf("Checking if %s is missing updates", m.Name)
	return m.LastSuccessfulUpdate.Before(lastChange)
}
