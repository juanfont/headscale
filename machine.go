package headscale

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strconv"
	"time"

	"github.com/jinzhu/gorm/dialects/postgres"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/wgengine/wgcfg"
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
	Namespace   Namespace

	Registered bool // temp
	LastSeen   *time.Time
	Expiry     *time.Time

	HostInfo      postgres.Jsonb
	Endpoints     postgres.Jsonb
	EnabledRoutes postgres.Jsonb

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

// For the time being this method is rather naive
func (m Machine) isAlreadyRegistered() bool {
	return m.Registered
}

func (m Machine) toNode() (*tailcfg.Node, error) {
	nKey, err := wgcfg.ParseHexKey(m.NodeKey)
	if err != nil {
		return nil, err
	}
	mKey, err := wgcfg.ParseHexKey(m.MachineKey)
	if err != nil {
		return nil, err
	}

	var discoKey tailcfg.DiscoKey
	if m.DiscoKey != "" {
		dKey, err := wgcfg.ParseHexKey(m.DiscoKey)
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
	if len(m.EnabledRoutes.RawMessage) != 0 {
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
	if len(m.Endpoints.RawMessage) != 0 {
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
	if len(m.HostInfo.RawMessage) != 0 {
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
		StableID:   tailcfg.StableNodeID(strconv.FormatUint(m.ID, 10)), // in headscale, unlike tailcontrol server, IDs are permantent
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
	db, err := h.db()
	if err != nil {
		log.Printf("Cannot open DB: %s", err)
		return nil, err
	}
	defer db.Close()

	machines := []Machine{}
	if err = db.Where("namespace_id = ? AND machine_key <> ? AND registered",
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

// GetHostInfo returns a Hostinfo struct for the machine
func (m *Machine) GetHostInfo() (*tailcfg.Hostinfo, error) {
	hostinfo := tailcfg.Hostinfo{}
	if len(m.HostInfo.RawMessage) != 0 {
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
