package headscale

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"time"

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

	LastSeen *time.Time
	Expiry   *time.Time

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

func (m Machine) toNode() (*tailcfg.Node, error) {
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
		return nil, err
	}
	addrs = append(addrs, ip) // missing the ipv6 ?

	allowedIPs := []netaddr.IPPrefix{}
	allowedIPs = append(allowedIPs, ip) // we append the node own IP, as it is required by the clients

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

	for _, aip := range routesStr {
		ip, err := netaddr.ParseIPPrefix(aip)
		if err != nil {
			return nil, err
		}
		allowedIPs = append(allowedIPs, ip)
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

	n := tailcfg.Node{
		ID:         tailcfg.NodeID(m.ID),                               // this is the actual ID
		StableID:   tailcfg.StableNodeID(strconv.FormatUint(m.ID, 10)), // in headscale, unlike tailcontrol server, IDs are permanent
		Name:       hostinfo.Hostname,
		User:       tailcfg.UserID(m.NamespaceID),
		Key:        tailcfg.NodeKey(nKey),
		KeyExpiry:  *m.Expiry,
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
	}
	return &n, nil
}

func (h *Headscale) getPeers(m Machine) (*[]*tailcfg.Node, error) {
	machines := []Machine{}
	if err := h.db.Where("namespace_id = ? AND machine_key <> ? AND registered",
		m.NamespaceID, m.MachineKey).Find(&machines).Error; err != nil {
		log.Printf("Error accessing db: %s", err)
		return nil, err
	}

	peers := []*tailcfg.Node{}
	for _, mn := range machines {
		peer, err := mn.toNode()
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
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
	return nil, fmt.Errorf("not found")
}

// GetMachineByID finds a Machine by ID and returns the Machine struct
func (h *Headscale) GetMachineByID(id uint64) (*Machine, error) {
	m := Machine{}
	if result := h.db.Find(&Machine{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}
	return &m, nil
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
